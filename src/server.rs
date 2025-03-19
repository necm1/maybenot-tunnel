use crate::obfuscation::{MaybenotFramework, DUMMY_TRAFFIC_INTERVAL_MS, IDLE_THRESHOLD_MS};
use log::{error, info};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::sleep;

#[derive(Clone)]
pub struct Server {
    listener: Arc<StdMutex<TcpListener>>,
    framework: MaybenotFramework,
}

impl Server {
    pub async fn new(framework: MaybenotFramework) -> Self {
        let listener = TcpListener::bind("0.0.0.0:1080")
            .await
            .expect("🔴 Error: Port blocked!");

        info!("🧩 SOCKS5 Proxy started on port 1080...");

        Self {
            listener: Arc::new(StdMutex::new(listener)),
            framework,
        }
    }

    pub async fn run(&self) {
        loop {
            let (socket, addr) = match self.listener.lock().unwrap().accept().await {
                Ok(result) => result,
                Err(e) => {
                    error!("❌ Error accepting connection: {}", e);
                    continue;
                }
            };

            info!("🔹 Connection received from {:?}", addr);

            let server_clone = self.clone();

            tokio::spawn(async move {
                if let Err(e) = server_clone.handle_client(socket).await {
                    error!("❌ Error handling client: {}", e);
                }
            });
        }
    }

    async fn handle_client(&self, mut client: TcpStream) -> Result<(), String> {
        // SOCKS5 handshake
        let mut buf = [0u8; 1024];

        // Read authentication methods
        let n = client
            .read(&mut buf)
            .await
            .map_err(|e| format!("Failed to read: {}", e))?;
        if n < 2 || buf[0] != 0x05 {
            return Err("Not a SOCKS5 request".to_string());
        }

        // Send authentication method (no auth)
        client
            .write_all(&[0x05, 0x00])
            .await
            .map_err(|e| format!("Failed to write: {}", e))?;

        // Read connection request
        let n = client
            .read(&mut buf)
            .await
            .map_err(|e| format!("Failed to read request: {}", e))?;
        if n < 4 || buf[0] != 0x05 || buf[1] != 0x01 {
            return Err("Invalid SOCKS5 request".to_string());
        }

        // Parse address
        let target_addr = match buf[3] {
            // IPv4
            0x01 => {
                if n < 10 {
                    return Err("Invalid IPv4 address".to_string());
                }
                let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                let port = u16::from_be_bytes([buf[8], buf[9]]);
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port))
            }
            // Domain name
            0x03 => {
                let domain_len = buf[4] as usize;
                if n < 5 + domain_len + 2 {
                    return Err("Invalid domain name".to_string());
                }
                let domain = std::str::from_utf8(&buf[5..5 + domain_len])
                    .map_err(|_| "Invalid domain name encoding".to_string())?;
                let port = u16::from_be_bytes([buf[5 + domain_len], buf[6 + domain_len]]);

                info!("🌍 Domain target: {}:{}", domain, port);

                // Resolve domain to IP
                let addr = tokio::net::lookup_host((domain, port))
                    .await
                    .map_err(|e| format!("Failed to resolve domain: {}", e))?
                    .next()
                    .ok_or_else(|| "Failed to resolve domain".to_string())?;

                addr
            }
            // IPv6
            0x04 => {
                if n < 22 {
                    return Err("Invalid IPv6 address".to_string());
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&buf[4..20]);
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([buf[20], buf[21]]);
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0))
            }
            _ => return Err("Unsupported address type".to_string()),
        };

        info!("🔗 Connecting to target: {}", target_addr);

        // Connect to target
        let target = TcpStream::connect(target_addr)
            .await
            .map_err(|e| format!("Failed to connect to target: {}", e))?;

        // Send success response
        let mut response = vec![0x05, 0x00, 0x00];

        match target_addr {
            std::net::SocketAddr::V4(addr) => {
                response.push(0x01);
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(addr) => {
                response.push(0x04);
                response.extend_from_slice(&addr.ip().octets());
                response.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        client
            .write_all(&response)
            .await
            .map_err(|e| format!("Failed to send response: {}", e))?;

        // Start bidirectional proxy with Maybenot obfuscation
        self.proxy_data(client, target).await
    }

    async fn proxy_data(&self, client: TcpStream, target: TcpStream) -> Result<(), String> {
        // Set TCP_NODELAY to improve performance for interactive sessions
        if let Err(e) = client.set_nodelay(true) {
            error!("❌ Failed to set TCP_NODELAY on client socket: {}", e);
        }
        if let Err(e) = target.set_nodelay(true) {
            error!("❌ Failed to set TCP_NODELAY on target socket: {}", e);
        }

        let (mut client_read, mut client_write) = client.into_split();
        // Fix the unused mut warning
        let (mut target_read, target_write) = target.into_split();

        let framework_clone = self.framework.clone();
        let framework_clone2 = self.framework.clone();
        let framework_clone3 = self.framework.clone();

        // Create a shared last_activity variable
        let last_activity = Arc::new(StdMutex::new(Instant::now()));
        let last_activity_clone1 = last_activity.clone();
        let last_activity_clone2 = last_activity.clone();

        // We need to wrap target_write in an Arc<Mutex<>> to share it between tasks
        let target_write = Arc::new(TokioMutex::new(target_write));
        let target_write_clone = target_write.clone();

        // Add a connection state flag to track if the connection is still active
        let connection_active = Arc::new(StdMutex::new(true));
        // Create separate clones for each task to avoid the move error
        let connection_active_dummy = connection_active.clone();
        let connection_active_c2t = connection_active.clone();
        let connection_active_t2c = connection_active.clone();

        // Increase buffer sizes for better handling of large responses
        let client_buffer_size = 32768; // 32KB
        let target_buffer_size = 32768; // 32KB

        let dummy_task = tokio::spawn(async move {
            loop {
                if !*connection_active_dummy.lock().unwrap() {
                    break;
                }

                let elapsed = {
                    let guard = last_activity.lock().unwrap();
                    guard.elapsed()
                };

                if elapsed > Duration::from_millis(IDLE_THRESHOLD_MS) {
                    let dummy_data =
                        crate::obfuscation::generate_dummy_traffic(&framework_clone3).await;
                    if !dummy_data.is_empty() {
                        // Get a lock on target_write
                        if let Ok(mut write_guard) = target_write.try_lock() {
                            if let Err(e) = write_guard.write_all(&dummy_data).await {
                                // If we get a broken pipe, the connection is closed
                                if e.kind() == std::io::ErrorKind::BrokenPipe {
                                    info!("🔌 Connection closed, stopping dummy traffic");
                                    *connection_active_dummy.lock().unwrap() = false;
                                } else {
                                    error!("❌ Error while sending dummy traffic: {}", e);
                                }
                                break;
                            }
                        }
                    }

                    sleep(Duration::from_millis(DUMMY_TRAFFIC_INTERVAL_MS)).await;
                } else {
                    sleep(Duration::from_millis(100)).await;
                }
            }
        });

        let c2t = tokio::spawn(async move {
            let mut buffer = vec![0u8; client_buffer_size];

            loop {
                match client_read.read(&mut buffer).await {
                    Ok(0) => {
                        // Connection closed by client
                        info!("🔌 Connection closed by client");
                        *connection_active_c2t.lock().unwrap() = false;
                        break;
                    }
                    Ok(n) => {
                        // Update last activity time
                        {
                            let mut guard = last_activity_clone1.lock().unwrap();
                            *guard = Instant::now();
                        }

                        // Apply obfuscation to all traffic, including YouTube and Twitch
                        let data_to_send =
                            crate::obfuscation::obfuscate_data(&framework_clone, &buffer[..n])
                                .await;

                        // Get a lock on target_write_clone
                        let mut write_guard = target_write_clone.lock().await;
                        if let Err(e) = write_guard.write_all(&data_to_send).await {
                            if e.kind() == std::io::ErrorKind::BrokenPipe {
                                info!("🔌 Connection to target closed");
                                *connection_active_c2t.lock().unwrap() = false;
                            } else {
                                error!("❌ Error while writing to target: {}", e);
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        error!("❌ Error while reading from client: {}", e);
                        *connection_active_c2t.lock().unwrap() = false;
                        break;
                    }
                }
            }
        });

        let t2c = tokio::spawn(async move {
            let mut buffer = vec![0u8; target_buffer_size];
            let mut consecutive_errors = 0;
            let max_consecutive_errors = 10; // Increased tolerance for resets
            let mut backoff_ms = 50; // Start with a small backoff

            loop {
                match target_read.read(&mut buffer).await {
                    Ok(0) => {
                        // Connection closed by target
                        info!("🔌 Connection closed by target");
                        *connection_active_t2c.lock().unwrap() = false;
                        break;
                    }
                    Ok(n) => {
                        // Reset error counter on successful read
                        consecutive_errors = 0;

                        // Update last activity time
                        {
                            let mut guard = last_activity_clone2.lock().unwrap();
                            *guard = Instant::now();
                        }

                        let data_to_send =
                            crate::obfuscation::deobfuscate_data(&framework_clone2, &buffer[..n])
                                .await;

                        // Use a timeout for writing to client to avoid hanging
                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            client_write.write_all(&data_to_send),
                        )
                        .await
                        {
                            Ok(result) => {
                                if let Err(e) = result {
                                    // If we get a broken pipe, the connection is closed
                                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                                        info!("🔌 Connection to client closed");
                                        *connection_active_t2c.lock().unwrap() = false;
                                    } else {
                                        error!("❌ Error while writing to client: {}", e);
                                    }
                                    break;
                                }
                            }
                            Err(_) => {
                                error!("❌ Timeout writing to client");
                                *connection_active_t2c.lock().unwrap() = false;
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        // For connection reset errors, we'll be more tolerant
                        if e.kind() == std::io::ErrorKind::ConnectionReset
                            || e.kind() == std::io::ErrorKind::ConnectionAborted
                            || e.kind() == std::io::ErrorKind::BrokenPipe
                        {
                            consecutive_errors += 1;
                            error!(
                                "⚠️ Connection error: {} (attempt {}/{})",
                                e, consecutive_errors, max_consecutive_errors
                            );

                            // Only break after multiple consecutive errors
                            if consecutive_errors >= max_consecutive_errors {
                                error!("❌ Too many connection errors, closing connection");
                                *connection_active_t2c.lock().unwrap() = false;
                                break;
                            }

                            // Exponential backoff with a cap
                            backoff_ms = std::cmp::min(backoff_ms * 2, 1000);
                            sleep(Duration::from_millis(backoff_ms)).await;
                            continue;
                        } else {
                            error!("❌ Error while reading target: {}", e);
                            *connection_active_t2c.lock().unwrap() = false;
                            break;
                        }
                    }
                }
            }
        });

        // Wait for all tasks
        let _ = tokio::join!(c2t, t2c, dummy_task);
        Ok(())
    }
}
