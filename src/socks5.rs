use log::{error, info, warn};
use maybenot::{Framework, Machine};
use rand::rngs::StdRng;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::handler::copy_stream;

pub async fn handle_client(
    mut inbound: TcpStream,
    framework: Arc<Mutex<Framework<&'static [Machine], StdRng>>>,
) {
    info!(
        "🔹 Verbindung erhalten von {:?}",
        inbound.peer_addr().unwrap()
    );

    let outbound = match socks5_connect(&mut inbound).await {
        Ok(socket) => {
            info!("✅ SOCKS5-Verbindung erfolgreich hergestellt!");
            socket
        }
        Err(err) => {
            error!("❌ SOCKS5-Fehler: {}", err);
            return;
        }
    };

    let inbound = Arc::new(Mutex::new(inbound));
    let outbound = Arc::new(Mutex::new(outbound));

    info!("🔹 Starte Datenübertragung...");

    // 🚀 **Starte beide Streams und warte auf sie**
    let t1 = tokio::spawn(copy_stream(
        inbound.clone(),
        outbound.clone(),
        true,
        Arc::clone(&framework),
    ));
    let t2 = tokio::spawn(copy_stream(
        Arc::clone(&outbound),
        Arc::clone(&inbound),
        false,
        Arc::clone(&framework),
    ));

    if let Err(e) = tokio::try_join!(t1, t2) {
        warn!("⚠️ Fehler während der Datenübertragung: {:?}", e);
    }
}

async fn socks5_connect(inbound: &mut TcpStream) -> Result<TcpStream, String> {
    let mut buf = [0; 1024];

    info!("📡 Starte SOCKS5-Handshake...");
    let bytes_read = inbound
        .read(&mut buf)
        .await
        .map_err(|e| format!("❌ Fehler beim Handshake: {}", e))?;
    info!("✅ Handshake abgeschlossen! ({} Bytes)", bytes_read);

    if buf[0] != 0x05 {
        return Err("❌ Kein gültiges SOCKS5-Protokoll".to_string());
    }

    info!("📡 Sende Authentifizierungsbestätigung...");
    inbound
        .write_all(&[0x05, 0x00])
        .await
        .map_err(|e| format!("❌ Fehler beim Senden der Auth-Bestätigung: {}", e))?;
    info!("✅ Authentifizierung abgeschlossen!");

    info!("📡 Lese Verbindungsanfrage...");
    let bytes_read = inbound
        .read(&mut buf)
        .await
        .map_err(|e| format!("❌ Fehler beim Lesen der Verbindungsanfrage: {}", e))?;
    info!("✅ Verbindungsanfrage erhalten! ({} Bytes)", bytes_read);

    if buf[1] != 0x01 {
        return Err("❌ SOCKS5 unterstützt nur CONNECT".to_string());
    }

    // 🔹 Zieladresse extrahieren (IPv4 oder Domain)
    let target_addr = match buf[3] {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port)
        }
        0x03 => {
            let domain_len = buf[4] as usize;
            let domain_bytes = &buf[5..5 + domain_len];

            let domain = match std::str::from_utf8(domain_bytes) {
                Ok(d) => d.to_string(),
                Err(_) => {
                    return Err("❌ Fehler: Domain ist keine gültige UTF-8 Zeichenkette".to_string())
                }
            };

            let port_start = 5 + domain_len;
            let port = u16::from_be_bytes([buf[port_start], buf[port_start + 1]]);

            info!("🌍 Löse Domain auf: {}:{}", domain, port);
            let target_addr = match tokio::net::lookup_host((domain.clone(), port)).await {
                Ok(mut iter) => iter
                    .next()
                    .ok_or_else(|| "❌ DNS-Auflösung fehlgeschlagen".to_string())?,
                Err(_) => return Err(format!("❌ Fehler beim Auflösen der Domain: {}", domain)),
            };

            info!(
                "✅ Domain erfolgreich aufgelöst: {} → {}",
                domain, target_addr
            );
            target_addr
        }
        _ => return Err("❌ SOCKS5 unterstützt nur IPv4 oder Domainnamen".to_string()),
    };

    // 🔗 Verbindung zum Zielserver herstellen
    info!("🔗 Versuche Verbindung zu: {}", target_addr);
    let outbound = TcpStream::connect(target_addr)
        .await
        .map_err(|e| format!("❌ Fehler bei Verbindung zu {}: {}", target_addr, e))?;
    info!("✅ Verbindung zu {} erfolgreich!", target_addr);

    // 🔹 Erfolgreiche Antwort an den Client senden
    let mut response = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

    if let std::net::SocketAddr::V4(addr) = target_addr {
        response[4..8].copy_from_slice(&addr.ip().octets());
        response[8..10].copy_from_slice(&addr.port().to_be_bytes());
    }

    inbound
        .write_all(&response)
        .await
        .map_err(|e| format!("❌ Fehler beim Senden der SOCKS5-Bestätigung: {}", e))?;
    info!("✅ SOCKS5-Bestätigung gesendet!");

    Ok(outbound)
}
