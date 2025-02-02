use log::{info, warn};
use maybenot::{Framework, Machine, MachineId, TriggerAction, TriggerEvent};
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub async fn copy_stream(
    src: Arc<Mutex<TcpStream>>,
    dest: Arc<Mutex<TcpStream>>,
    is_client_to_server: bool,
    framework: Arc<Mutex<Framework<&'static [Machine], StdRng>>>,
) {
    let mut src = src.lock().await;
    let mut dest = dest.lock().await;
    let mut buf = [0; 4096];

    let mut handshake_packets = 0;
    let handshake_threshold = 3;

    loop {
        match src.read(&mut buf).await {
            Ok(0) => {
                warn!("🔴 Verbindung wurde geschlossen.");
                break;
            }
            Ok(n) => {
                info!(
                    "✅ {} → {} übertragen: {} Bytes",
                    if is_client_to_server {
                        "Client"
                    } else {
                        "Server"
                    },
                    if is_client_to_server {
                        "Server"
                    } else {
                        "Client"
                    },
                    n
                );

                if let Err(e) = dest.write_all(&buf[..n]).await {
                    warn!("⚠️ Fehler beim Senden von Daten: {}", e);
                    break;
                }

                // **Test: Server → Client Logging**
                if !is_client_to_server {
                    info!("✅ Server → Client erfolgreich gesendet: {} Bytes", n);
                }

                if handshake_packets < handshake_threshold {
                    handshake_packets += 1;
                    info!(
                        "🔹 TLS-Handshake Paket {} übertragen ({} Bytes)",
                        handshake_packets, n
                    );
                    continue;
                }
            }
            Err(e) => {
                warn!("⚠️ Fehler beim Lesen des Streams: {}", e);
                break;
            }
        }
    }

    warn!(
        "🔴 Datenübertragung zwischen {} und {} beendet.",
        if is_client_to_server {
            "Client"
        } else {
            "Server"
        },
        if is_client_to_server {
            "Server"
        } else {
            "Client"
        }
    );
}
