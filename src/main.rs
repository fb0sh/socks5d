use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{error, info, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub type DynError = Box<dyn std::error::Error + Send + Sync>;
pub const SOCKS_VERSION: u8 = 0x05;

pub struct AuthCredit {
    username: String,
    password: String,
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

    /// log directory
    #[arg(short, long, default_value = "logs")]
    log_dir: String,
}

fn init_tracing(log_dir: &str) -> Result<(), DynError> {
    let log_path = PathBuf::from(log_dir);
    std::fs::create_dir_all(&log_path)?;

    let file_appender = RollingFileAppender::new(Rotation::DAILY, &log_path, "socks5d.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Keep guard alive for the lifetime of the program
    std::mem::forget(guard);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true)
                .json()
        )
        .with(
            fmt::layer()
                .with_writer(std::io::stdout)
                .with_ansi(true)
                .with_target(true)
        )
        .init();

    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize logging
    if let Err(e) = init_tracing(&args.log_dir) {
        eprintln!("[-] failed to init tracing: {}", e);
        std::process::exit(1);
    }

    info!(version = env!("CARGO_PKG_VERSION"), "socks5d starting");

    let bind = args.bind.clone();
    let username = args.username.clone();
    let password = args.password.clone();
    let max_connections = args.max_connections;
    let connect_timeout_secs = args.connect_timeout;
    let idle_timeout_secs = args.idle_timeout;

    let need_auth = username.is_some() && password.is_some();
    info!(auth = need_auth, max_connections, "server config");

    let listener = TcpListener::bind(&bind).await.unwrap();
    info!(address = %bind, "SOCKS5 server running");

    let auth_credit = Arc::new(AuthCredit {
        username: username.unwrap_or_default(),
        password: password.unwrap_or_default(),
    });

    let semaphore = Arc::new(Semaphore::new(max_connections));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let total_connections = Arc::new(AtomicUsize::new(0));

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                let current = active_connections.fetch_add(1, Ordering::Relaxed) + 1;
                let total = total_connections.fetch_add(1, Ordering::Relaxed) + 1;
                info!(client = %addr, active = current, total = total, "client connected");

                let auth = auth_credit.clone();
                let sem = semaphore.clone();
                let connect_timeout = connect_timeout_secs;
                let idle_timeout = idle_timeout_secs;
                let active_conn = active_connections.clone();

                tokio::spawn(async move {
                    let _permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => {
                            error!("failed to acquire semaphore");
                            active_conn.fetch_sub(1, Ordering::Relaxed);
                            return;
                        }
                    };

                    if let Err(e) = handle_client(socket, &auth, need_auth, connect_timeout, idle_timeout).await {
                        error!(error = %e, "client handler error");
                    }

                    let current = active_conn.fetch_sub(1, Ordering::Relaxed) - 1;
                    info!(client = %addr, active = current, "client disconnected");
                });
            }
            Err(e) => {
                error!(error = %e, "accept error");
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client_addr = socket.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap());

    // 1. 协商 认证 处理认证
    handle_auth(&mut socket, auth_credit, need_auth).await?;

    // 2. 解析 请求 IP PORT
    let (target_addr, target_port, cmd) = handle_requests_addressing(&mut socket).await?;
    let dst_addr = format!("{}:{}", target_addr, target_port);

    info!(target = %dst_addr, client = %client_addr, "connecting to target");

    // 3. 处理 响应，转发
    let result = handle_replies(&mut socket, &target_addr, target_port, cmd, connect_timeout, idle_timeout).await;

    match result {
        Ok(_) => {
            info!(target = %dst_addr, client = %client_addr, "connection closed");
        }
        Err(e) => {
            warn!(target = %dst_addr, client = %client_addr, error = %e, "connection error");
            return Err(e);
        }
    }

    Ok(())
}

async fn handle_auth(
    socket: &mut TcpStream,
    auth_credit: &AuthCredit,
    need_auth: bool,
) -> Result<(), DynError> {
    let mut buf = [0u8; 2];

    socket.read_exact(&mut buf).await?;
    let ver = buf[0];
    let nmethods = buf[1];

    if ver != SOCKS_VERSION {
        return Err(format!(
            "Client SOCKS Ver: {} != Server SOCKS Version: {}",
            ver, SOCKS_VERSION
        )
        .into());
    }

    let mut methods = vec![0u8; nmethods as usize];
    socket.read_exact(&mut methods).await?;

    fn select_method(methods: &[u8]) -> u8 {
        if methods.contains(&0x00) {
            0x00
        } else if methods.contains(&0x02) {
            0x02
        } else {
            0xFF
        }
    }

    let method = if need_auth {
        if methods.contains(&0x02) { 0x02 } else { 0xFF }
    } else {
        select_method(&methods)
    };

    match method {
        0x00 => {
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

    Ok(())
}

async fn handle_user_pass(
    socket: &mut TcpStream,
    auth_credit: &AuthCredit,
) -> Result<(), DynError> {
    let mut buf = [0u8; 2];
    socket.read_exact(&mut buf).await?;

    let ver = buf[0];
    if ver != 0x01 {
        return Err(format!("Unsupported sub-protocol version :{}", ver).into());
    }

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

    if uname == auth_credit.username && passwd == auth_credit.password {
        socket.write_all(&[0x01, 0x00]).await?;
        Ok(())
    } else {
        socket.write_all(&[0x01, 0x01]).await?;
        Err("客户端认证失败".into())
    }
}

async fn handle_requests_addressing(socket: &mut TcpStream) -> Result<(String, u16, u8), DynError> {
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
            let mut ip = [0u8; 4];
            socket.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            socket.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        0x04 => {
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
                    let rep = match e.kind() {
                        std::io::ErrorKind::ConnectionRefused => 0x05,
                        std::io::ErrorKind::NotFound => 0x04,
                        std::io::ErrorKind::AddrNotAvailable => 0x03,
                        _ => 0x01,
                    };
                    let _ = socket
                        .write_all(&[SOCKS_VERSION, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(format!("connection error: {:?}", e).into());
                }
                Err(_) => {
                    let _ = socket
                        .write_all(&[SOCKS_VERSION, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(format!("connection timeout ({}s)", connect_timeout).into());
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
                    warn!(error = %e, "copy error");
                    (0, 0, format!("copy error: {}", e))
                }
                Err(_) => {
                    (0, 0, "idle timeout".to_string())
                }
            };

            if c2s > 0 || s2c > 0 {
                info!(
                    client_to_server = c2s,
                    server_to_client = s2c,
                    "connection stats"
                );
            }
            info!(reason = %reason, "connection closed");
        }
        _ => {
            return Err("Server only supports CONNECT".into());
        }
    }
    Ok(())
}