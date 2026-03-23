use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

pub type DynError = Box<dyn std::error::Error>;
pub const SOCKS_VERSION: u8 = 0x05;
pub struct AuthCredit {
    username: String,
    password: String,
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:1080").await.unwrap();
    println!("SOCKS5 server running on 0.0.0.0:1080");
    let auth_credit = Arc::new(AuthCredit {
        username: "admin".to_string(),
        password: "123456".to_string(),
    });

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                println!("[+] client connected: {}", addr);
                let auth = auth_credit.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(socket, &auth, false).await {
                        println!("[-] error: {:?}", e);
                    }
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
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. 协商 认证 处理认证
    handle_auth(&mut socket, auth_credit, need_auth).await?;

    // 2. 解析 请求 IP PORT
    let (dst_addr, dst_port, cmd) = handle_requests_addressing(&mut socket).await?;

    println!("[+] connect to {}:{}", &dst_addr, dst_port);

    // 3. 处理 响应，转发
    handle_replies(&mut socket, &dst_addr, dst_port, cmd).await?;

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
    println!("[客户端认证方法列表]: {:?}", methods);

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
                return Err("请使用用户名/密码认证".into());
            }
            return Err("没有可用的认证方法".into());
        }
        _ => {
            socket.write_all(&[SOCKS_VERSION, 0xFF]).await?;
            return Err("不支持的认证方式".into());
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
            return Err(format!("不支持的子协议版本:{}", ver).into());
        }

        // 获取 凭证
        let ulen = buf[1] as usize;
        if ulen == 0 {
            return Err("用户名长度为0".into());
        }
        let mut uname_buf = vec![0u8; ulen];
        socket.read_exact(&mut uname_buf).await?;

        let mut plen_buf = [0u8; 1];
        socket.read_exact(&mut plen_buf).await?;

        let plen = plen_buf[0] as usize;
        if plen == 0 {
            return Err("密码长度为0".into());
        }
        let mut passwd_buf = vec![0u8; plen];
        socket.read_exact(&mut passwd_buf).await?;

        let uname = String::from_utf8(uname_buf)?;
        let passwd = String::from_utf8(passwd_buf)?;
        println!("[客户端认证]: username: {}", &uname);

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
        return Err("服务器不支持非0x00的 RSV 值".into());
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
        _ => return Err("不支持的 ATYP 类型".into()),
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
            // CONNECT
            let mut remote = match TcpStream::connect((dst_addr, dst_port)).await {
                Ok(s) => s,
                Err(e) => {
                    // 返回失败
                    // 0.0.0.0 0
                    let rep = match e.kind() {
                        std::io::ErrorKind::ConnectionRefused => 0x05,
                        std::io::ErrorKind::NotFound => 0x04,
                        std::io::ErrorKind::AddrNotAvailable => 0x03,
                        _ => 0x01,
                    };
                    let _ = socket
                        .write_all(&[SOCKS_VERSION, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(format!("连接失败: {:?}", e).into());
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

            // 数据转发
            let (c2s, s2c) = copy_bidirectional(socket, &mut remote).await?;
            println!(
                "client->server: {} bytes, server->client: {} bytes",
                c2s, s2c
            );
            println!("[*] 连接关闭");
        }
        _ => {
            return Err("目前服务器只支持 CONNECT".into());
        }
    }
    Ok(())
}
