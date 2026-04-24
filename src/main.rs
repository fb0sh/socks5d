use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{error, info, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

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

    /// shutdown timeout in seconds
    #[arg(long, default_value = "30")]
    shutdown_timeout: u64,

    /// metrics HTTP server port (0 = disabled)
    #[arg(long, default_value = "9999")]
    metrics_port: u16,
}

fn init_tracing(log_dir: &str) -> Result<(), DynError> {
    let log_path = PathBuf::from(log_dir);
    std::fs::create_dir_all(&log_path)?;

    let file_appender = RollingFileAppender::new(Rotation::DAILY, &log_path, "socks5d.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Keep guard alive for the lifetime of the program
    std::mem::forget(guard);

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true)
                .json(),
        )
        .with(
            fmt::layer()
                .with_writer(std::io::stdout)
                .with_ansi(true)
                .with_target(true),
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
    let shutdown_timeout_secs = args.shutdown_timeout;
    let metrics_port = args.metrics_port;

    let need_auth = username.is_some() && password.is_some();
    info!(auth = need_auth, max_connections, "server config");

    let listener = TcpListener::bind(&bind).await.unwrap();
    info!(address = %bind, "SOCKS5 server running");

    // Graceful shutdown flag
    let shutdown = Arc::new(AtomicBool::new(false));

    // Spawn metrics server
    let active_conn_for_metrics = Arc::new(AtomicUsize::new(0));
    let total_conn_for_metrics = Arc::new(AtomicUsize::new(0));
    let error_conn_for_metrics = Arc::new(AtomicUsize::new(0));
    let bytes_for_metrics = Arc::new(AtomicUsize::new(0));

    // Clone for use in loop
    let active_conn_clone = active_conn_for_metrics.clone();
    let error_conn_clone = error_conn_for_metrics.clone();

    if metrics_port > 0 {
        let ac = active_conn_for_metrics.clone();
        let tc = total_conn_for_metrics.clone();
        let ec = error_conn_for_metrics.clone();
        let bc = bytes_for_metrics.clone();
        tokio::spawn(async move {
            start_metrics_server(metrics_port, ac, tc, ec, bc).await;
        });
    }

    // Spawn signal handler
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt()).unwrap();
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = sigint.recv() => info!("received SIGINT"),
            _ = sigterm.recv() => info!("received SIGTERM"),
        }
        info!("initiating graceful shutdown");
        shutdown_signal.store(true, Ordering::SeqCst);
    });

    let auth_credit = Arc::new(AuthCredit {
        username: username.unwrap_or_default(),
        password: password.unwrap_or_default(),
    });

    let semaphore = Arc::new(Semaphore::new(max_connections));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let total_connections = Arc::new(AtomicUsize::new(0));

    loop {
        // Check shutdown flag
        if shutdown.load(Ordering::SeqCst) {
            info!("stop accepting new connections");
            break;
        }

        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((socket, addr)) => {
                        let current = active_connections.fetch_add(1, Ordering::Relaxed) + 1;
                        let total = total_connections.fetch_add(1, Ordering::Relaxed) + 1;
                        active_conn_clone.store(current, Ordering::Relaxed);
                        total_conn_for_metrics.fetch_add(1, Ordering::Relaxed);
                        info!(client = %addr, active = current, total = total, "client connected");

                        let auth = auth_credit.clone();
                        let sem = semaphore.clone();
                        let connect_timeout = connect_timeout_secs;
                        let idle_timeout = idle_timeout_secs;
                        let active_conn = active_connections.clone();
                        let active_conn_for_spawn = active_conn_clone.clone();
                        let error_conn_for_spawn = error_conn_clone.clone();
                        let bytes = bytes_for_metrics.clone();

                        tokio::spawn(async move {
                            let _permit = match sem.acquire().await {
                                Ok(p) => p,
                                Err(_) => {
                                    error!("failed to acquire semaphore");
                                    active_conn.fetch_sub(1, Ordering::Relaxed);
                                    return;
                                }
                            };

                            if let Err(e) = handle_client(socket, &auth, need_auth, connect_timeout, idle_timeout, &bytes).await {
                                error!(error = %e, "client handler error");
                                error_conn_for_spawn.fetch_add(1, Ordering::Relaxed);
                            }

                            let current = active_conn.fetch_sub(1, Ordering::Relaxed) - 1;
                            active_conn_for_spawn.store(current, Ordering::Relaxed);
                            info!(client = %addr, active = current, "client disconnected");
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "accept error");
                    }
                }
            },
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Small delay to prevent busy looping when shutting down
            }
        }
    }

    // Wait for active connections to drain
    let timeout_dur = Duration::from_secs(shutdown_timeout_secs);
    let start = std::time::Instant::now();
    while active_connections.load(Ordering::Relaxed) > 0 {
        if start.elapsed() > timeout_dur {
            warn!(
                remaining = active_connections.load(Ordering::Relaxed),
                "shutdown timeout exceeded, force exit"
            );
            break;
        }
        info!(
            remaining = active_connections.load(Ordering::Relaxed),
            "waiting for connections to drain"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    info!("socks5d stopped");
}

async fn start_metrics_server(
    port: u16,
    active: Arc<AtomicUsize>,
    total: Arc<AtomicUsize>,
    errors: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
) {
    use std::net::SocketAddr;

    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    info!(address = %addr, "metrics server starting");

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, "failed to bind metrics port");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((mut socket, _)) => {
                let active_clone = active.clone();
                let total_clone = total.clone();
                let errors_clone = errors.clone();
                let bytes_clone = bytes.clone();

                tokio::spawn(async move {
                    // Read HTTP request (ignore path)
                    let mut buf = [0u8; 256];
                    let _ = socket.read(&mut buf).await;

                    let active_val = active_clone.load(Ordering::Relaxed) as u64;
                    let total_val = total_clone.load(Ordering::Relaxed) as u64;
                    let errors_val = errors_clone.load(Ordering::Relaxed) as u64;
                    let bytes_val = bytes_clone.load(Ordering::Relaxed) as u64;

                    let response = format!(
                        "socks5d_active_connections {}\n\
                         socks5d_total_connections {}\n\
                         socks5d_connection_errors {}\n\
                         socks5d_bytes_transferred {}\n",
                        active_val, total_val, errors_val, bytes_val
                    );

                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                        response.len(),
                        response
                    );

                    let _ = socket.write_all(resp.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
            Err(e) => {
                warn!(error = %e, "metrics accept error");
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
    bytes_transferred: &Arc<AtomicUsize>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client_addr = socket
        .peer_addr()
        .unwrap_or_else(|_| "unknown".parse().unwrap());

    // Set socket options
    if let Ok(_) = socket.set_nodelay(true) {
        // TCP_NODELAY set
    }
    // Note: SO_KEEPALIVE requires platform-specific handling, set via environment or system config

    // 1. 协商 认证 处理认证
    handle_auth(&mut socket, auth_credit, need_auth).await?;

    // 2. 解析 请求 IP PORT
    let (target_addr, target_port, cmd) = handle_requests_addressing(&mut socket).await?;
    let dst_addr = format!("{}:{}", target_addr, target_port);

    info!(target = %dst_addr, client = %client_addr, "connecting to target");

    // 3. 处理 响应，转发
    let result = handle_replies(
        &mut socket,
        &target_addr,
        target_port,
        cmd,
        connect_timeout,
        idle_timeout,
        bytes_transferred,
    )
    .await;

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
    // RFC 1928
    // 协商认证方法，接受客户端发送的支持的协议的列表
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
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
    bytes_transferred: &Arc<AtomicUsize>,
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
                TcpStream::connect((dst_addr, dst_port)),
            )
            .await;

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

            // Set socket options on remote
            let _ = remote.set_nodelay(true);

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
                copy_bidirectional(socket, &mut remote),
            )
            .await
            {
                Ok(Ok((c2s, s2c))) => (c2s, s2c, "closed normally".to_string()),
                Ok(Err(e)) => {
                    warn!(error = %e, "copy error");
                    (0, 0, format!("copy error: {}", e))
                }
                Err(_) => (0, 0, "idle timeout".to_string()),
            };

            let total_bytes = c2s + s2c;
            bytes_transferred.fetch_add(total_bytes as usize, Ordering::Relaxed);

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
