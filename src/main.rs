mod handler;
mod obfuscation;
mod socks5;

use log::{error, info};
use obfuscation::init_maybenot;
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    env_logger::init();
    info!("🧩 Maybenot SOCKS5-Proxy gestartet auf Port 1080...");

    let framework = init_maybenot();
    let listener = TcpListener::bind("127.0.0.1:1080")
        .await
        .expect("🔴 Fehler: Port blockiert!");

    while let Ok((socket, _)) = listener.accept().await {
        let framework = Arc::clone(&framework);
        tokio::spawn(socks5::handle_client(socket, framework));
    }
}
