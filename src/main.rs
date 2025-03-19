mod obfuscation;
mod server;

use log::info;
use obfuscation::init_maybenot;
use server::Server;

#[tokio::main]
async fn main() {
    env_logger::init();

    info!("🚀 Starting Maybenot SOCKS5 tunnel...");

    let framework = init_maybenot();

    let server = Server::new(framework).await;
    server.run().await;
}
