# SOCKS5 Proxy Server (Rust)

一个基于 Tokio + Rust 的异步 SOCKS5 代理服务器。

## 特性

- SOCKS5 协议（RFC1928）
- 支持 CONNECT
- IPv4 / IPv6 / 域名解析
- 用户名密码认证（RFC1929）
- 异步高并发（Tokio）
- 双向流量转发
- 连接数限制（Semaphore）
- 连接超时控制
- 空闲超时控制
- 活动连接数监控
- Structured logging（tracing + 文件日志轮转）
- 每日日志轮转

## 编译

```bash
cargo build --release

// install from crates-io
cargo install socks5d
```

## 运行

### 默认运行（无认证）

```bash
./target/release/socks5d
```

默认监听：
0.0.0.0:1080

### 指定监听地址

```bash
./target/release/socks5d --bind 127.0.0.1:1080
```

### 启用认证

```bash
./target/release/socks5d --bind 0.0.0.0:1080 --username admin --password 123456
```

### 完整参数示例

```bash
./target/release/socks5d \
  --bind 0.0.0.0:1080 \
  --username admin \
  --password 123456 \
  --max-connections 1024 \
  --connect-timeout 10 \
  --idle-timeout 300 \
  --log-dir logs
```

### 参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--bind` | `0.0.0.0:1080` | 监听地址 |
| `--username` | - | 认证用户名 |
| `--password` | - | 认证密码 |
| `--max-connections` | `1024` | 最大并发连接数 |
| `--connect-timeout` | `10` | 连接目标服务器超时（秒） |
| `--idle-timeout` | `300` | 空闲超时（秒），0=无限制 |
| `--log-dir` | `logs` | 日志目录 |

### 日志

日志输出到 stdout 和 `logs/socks5d.log.{日期}`，格式为 JSON。

## 认证机制

### 无认证

METHODS: [0x00]

服务器返回: 0x00

### 用户名密码认证

VER | ULEN | UNAME | PLEN | PASSWD

成功: 0x01 0x00
失败: 0x01 0x01

## SOCKS5 请求格式

VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT

ATYP:

- 0x01 IPv4
- 0x03 域名
- 0x04 IPv6

## 响应格式

VER | REP | RSV | ATYP | BND.ADDR | BND.PORT

## CMD

- 0x01 CONNECT

## 错误码

0x01 general failure
0x02 not allowed
0x03 network unreachable
0x04 host unreachable
0x05 connection refused
0x07 command not supported
0x08 address type not supported

## 测试

curl --socks5 127.0.0.1:1080 http://example.com

带认证:
curl --socks5-user admin:123456 --socks5 127.0.0.1:1080 http://example.com

## 注意

仅支持 TCP CONNECT
未加密，仅用于学习/测试/内网代理