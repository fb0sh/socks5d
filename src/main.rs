use clap::Parser;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

pub type DynError = Box<dyn std::error::Error>;
pub const SOCKS_VERSION: u8 = 0x05;
pub struct AuthCredit {
    username: String,
    password: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let bind = args.bind.clone();
    let username = args.username.clone();
    let password = args.password.clone();
    let max_connections = args.max_connections;
    let connect_timeout_secs = args.connect_timeout;
    let idle_timeout_secs = args.idle_timeout;

    let need_auth = username.is_some() && password.is_some();

    println!("[*] server auth mode: {}", need_auth);

    let listener = TcpListener::bind(&bind).await.unwrap();
    println!("[*] SOCKS5 server running on {}", bind);

    let auth_credit = Arc::new(AuthCredit {
        username: username.unwrap_or_default(),
        password: password.unwrap_or_default(),
    });

    let semaphore = Arc::new(Semaphore::new(max_connections));
    let active_connections = Arc::new(AtomicUsize::new(0));

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                let current = active_connections.fetch_add(1, Ordering::Relaxed) + 1;
                println!("[+] client connected: {} (active: {})", addr, current);

                let auth = auth_credit.clone();
                let sem = semaphore.clone();
                let connect_timeout = connect_timeout_secs;
                let idle_timeout = idle_timeout_secs;
                let active_conn = active_connections.clone();

                tokio::spawn(async move {
                    let _permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => {
                            println!("[-] failed to acquire semaphore");
                            active_conn.fetch_sub(1, Ordering::Relaxed);
                            return;
                        }
                    };

                    if let Err(e) = handle_client(socket, &auth, need_auth, connect_timeout, idle_timeout).await {
                        println!("[-] error: {:?}", e);
                    }

                    let current = active_conn.fetch_sub(1, Ordering::Relaxed) - 1;
                    println!("[-] client disconnected (active: {})", current);
                });
            }
            Err(e) => {
                println!("[-] accept error: {:?}", e);
            }
        }
    }
}

async fn handle_client(
    mut socket: TcpStream,
    auth_credit: &AuthCredit,
    need_auth: bool,
    connect_timeout: u64,
    idle_timeout: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. 协商 认证 处理认证
    handle_auth(&mut socket, auth_credit, need_auth).await?;

    // 2. 解析 请求 IP PORT
    let (dst_addr, dst_port, cmd) = handle_requests_addressing(&mut socket).await?;

    println!("[+] connect to {}:{}", &dst_addr, dst_port);

    // 3. 处理 响应，转发
    handle_replies(&mut socket, &dst_addr, dst_port, cmd, connect_timeout, idle_timeout).await?;

    Ok(())
}

async fn handle_auth(
    socket: &mut TcpStream,
    auth_credit: &AuthCredit,
    need_auth: bool,
) -> Result<(), DynError> {
    let mut buf = [0u8; 2];

    socket.read_exact(&mut buf).await?;
    // RFC 1928
    // 协商认证方法，接受客户端发送的支持的协议的列表
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
    let ver = buf[0];
    let nmethods = buf[1];

    // socks5
    if ver != SOCKS_VERSION {
        return Err(format!(
            "Client SOCKS Ver: {} != Server SOCKS Version: {}",
            ver, SOCKS_VERSION
        )
        .into());
    }

    let mut methods = vec![0u8; nmethods as usize];
    socket.read_exact(&mut methods).await?;

    // RFC 1928
    // 处理认证方式，目前使用NO AUTH
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    // o  X'00' NO AUTHENTICATION REQUIRED
    // o  X'01' GSSAPI
    // o  X'02' USERNAME/PASSWORD
    // o  X'03' to X'7F' IANA ASSIGNED
    // o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    // o  X'FF' NO ACCEPTABLE METHODS
    fn select_method(methods: &[u8]) -> u8 {
        if methods.contains(&0x00) {
            0x00
        } else if methods.contains(&0x02) {
            0x02
        } else {
            0xFF
        }
    }
    println!("[Client Auth Method]: {:?}", methods);

    // 匹配方法 并 发送确认使用的协议
    let method = if need_auth {
        if methods.contains(&0x02) { 0x02 } else { 0xFF }
    } else {
        select_method(&methods)
    };

    match method {
        0x00 => {
            // NO AUTH
            socket.write_all(&[SOCKS_VERSION, 0x00]).await?;
        }
        0x02 => {
            socket.write_all(&[SOCKS_VERSION, 0x02]).await?;
            handle_user_pass(socket, auth_credit).await?;
        }
        0xFF => {
            socket.write_all(&[SOCKS_VERSION, 0xFF]).await?;
            if need_auth {
                return Err("Pls use username/password".into());
            }
            return Err("No available auth method".into());
        }
        _ => {
            socket.write_all(&[SOCKS_VERSION, 0xFF]).await?;
            return Err("Unsupported auth method".into());
        }
    }

    async fn handle_user_pass(
        socket: &mut TcpStream,
        auth_credit: &AuthCredit,
    ) -> Result<(), DynError> {
        // 子协议 RFC1929
        // 用户名/密码认证协商
        //  +----+------+----------+------+----------+
        //  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        //  +----+------+----------+------+----------+
        //  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        //  +----+------+----------+------+----------+
        let mut buf = [0u8; 2];
        socket.read_exact(&mut buf).await?;

        // 协议版本校验
        let ver = buf[0]; // 子协议版本
        if ver != 0x01 {
            return Err(format!("Unsupported sub-protocol version :{}", ver).into());
        }

        // 获取 凭证
        let ulen = buf[1] as usize;
        if ulen == 0 {
            return Err("Username length is 0".into());
        }
        let mut uname_buf = vec![0u8; ulen];
        socket.read_exact(&mut uname_buf).await?;

        let mut plen_buf = [0u8; 1];
        socket.read_exact(&mut plen_buf).await?;

        let plen = plen_buf[0] as usize;
        if plen == 0 {
            return Err("Password length is 0".into());
        }
        let mut passwd_buf = vec![0u8; plen];
        socket.read_exact(&mut passwd_buf).await?;

        let uname = String::from_utf8(uname_buf)?;
        let passwd = String::from_utf8(passwd_buf)?;
        println!("[Client Auth]: username: {}", &uname);

        // +----+--------+
        // |VER | STATUS |
        // +----+--------+
        // | 1  | 1      |
        // +----+--------+
        // X'00 成功
        if uname == auth_credit.username && passwd == auth_credit.password {
            socket.write_all(&[0x01, 0x00]).await?;
            Ok(())
        } else {
            socket.write_all(&[0x01, 0x01]).await?;
            Err("客户端认证失败".into())
        }
    }

    Ok(())
}

async fn handle_requests_addressing(socket: &mut TcpStream) -> Result<(String, u16, u8), DynError> {
    // RFC 1928
    // 处理请求并解析 地址
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    // ATYP
    // o  X'01' IPv4
    // o  X'03' Domain
    // o  X'04' IPv6
    let mut header = [0u8; 4];
    socket.read_exact(&mut header).await?;
    let ver = header[0];
    let cmd = header[1];
    let rsv = header[2];
    let atyp = header[3];

    if ver != SOCKS_VERSION {
        return Err(format!(
            "Client SOCKS Ver: {} != Server SOCKS Version: {}",
            ver, SOCKS_VERSION
        )
        .into());
    }

    if rsv != 0x00 {
        return Err("Server does not suppport none 0x00 RSV".into());
    }

    let dst_addr = match atyp {
        0x01 => {
            // IPv4
            let mut ip = [0u8; 4];
            socket.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x03 => {
            // 域名
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            socket.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        0x04 => {
            // IPv6
            let mut ip = [0u8; 16];
            socket.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => return Err("Unsupported ATYP type".into()),
    };

    let mut port_buf = [0u8; 2];
    socket.read_exact(&mut port_buf).await?;
    let dst_port = u16::from_be_bytes(port_buf);

    Ok((dst_addr, dst_port, cmd))
}

async fn handle_replies(
    socket: &mut TcpStream,
    dst_addr: &str,
    dst_port: u16,
    cmd: u8,
    connect_timeout: u64,
    idle_timeout: u64,
) -> Result<(), DynError> {
    // RFC 1928
    // 根据 CMD 做出回复
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    // o  VER    protocol version: X'05'
    // o  REP    Reply field:
    //   o  X'00' succeeded
    //   o  X'01' general SOCKS server failure
    //   o  X'02' connection not allowed by ruleset
    //   o  X'03' Network unreachable
    //   o  X'04' Host unreachable
    //   o  X'05' Connection refused
    //   o  X'06' TTL expired
    //   o  X'07' Command not supported
    //   o  X'08' Address type not supported
    //   o  X'09' to X'FF' unassigned
    // o  RSV    RESERVED
    // o  ATYP   address type of following address
    match cmd {
        0x01 => {
            // CONNECT with timeout
            let connect_result = timeout(
                Duration::from_secs(connect_timeout),
                TcpStream::connect((dst_addr, dst_port))
            ).await;

            let mut remote: TcpStream = match connect_result {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    // Connection error
                    let rep = match e.kind() {
                        std::io::ErrorKind::ConnectionRefused => 0x05,
                        std::io::ErrorKind::NotFound => 0x04,
                        std::io::ErrorKind::AddrNotAvailable => 0x03,
                        _ => 0x01,
                    };
                    let _ = socket
                        .write_all(&[SOCKS_VERSION, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(format!("[reply] connection error: {:?}", e).into());
                }
                Err(_) => {
                    // Timeout
                    let _ = socket
                        .write_all(&[SOCKS_VERSION, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(format!("[reply] connection timeout ({}s)", connect_timeout).into());
                }
            };

            let local_addr = remote.local_addr()?;

            match local_addr {
                std::net::SocketAddr::V4(addr) => {
                    let ip = addr.ip().octets();
                    let port = addr.port().to_be_bytes();

                    socket
                        .write_all(&[
                            0x05, 0x00, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1],
                        ])
                        .await?;
                }
                std::net::SocketAddr::V6(addr) => {
                    let ip = addr.ip().octets();
                    let port = addr.port().to_be_bytes();

                    let mut resp = vec![0x05, 0x00, 0x00, 0x04];
                    resp.extend_from_slice(&ip);
                    resp.extend_from_slice(&port);

                    socket.write_all(&resp).await?;
                }
            }

            // 数据转发 with idle timeout
            let (c2s, s2c, reason) = match timeout(
                Duration::from_secs(idle_timeout),
                copy_bidirectional(socket, &mut remote)
            ).await {
                Ok(Ok((c2s, s2c))) => (c2s, s2c, "closed normally".to_string()),
                Ok(Err(e)) => {
                    println!("[-] copy error: {:?}", e);
                    (0, 0, format!("copy error: {}", e))
                }
                Err(_) => {
                    (0, 0, "idle timeout".to_string())
                }
            };

            if c2s > 0 || s2c > 0 {
                println!(
                    "[*] client->server: {} bytes, server->client: {} bytes",
                    c2s, s2c
                );
            }
            println!("[reply] connection {}", reason);
        }
        _ => {
            return Err("Server only supports CONNECT".into());
        }
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[command(name = "socks5d")]
#[command(about = "A rust SOCKS5 proxy server <fb0sh@outlook.com> github.com/fb0sh")]
struct Args {
    /// listen address
    #[arg(short, long, default_value = "0.0.0.0:1080")]
    bind: String,

    /// username for auth
    #[arg(short, long)]
    username: Option<String>,

    /// password for auth
    #[arg(short, long)]
    password: Option<String>,

    /// max concurrent connections
    #[arg(short, long, default_value = "1024")]
    max_connections: usize,

    /// connection timeout in seconds
    #[arg(short, long, default_value = "10")]
    connect_timeout: u64,

    /// idle timeout in seconds (0 = no timeout)
    #[arg(short, long, default_value = "300")]
    idle_timeout: u64,
}
