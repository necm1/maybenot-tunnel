# Maybenot Tunnel

A SOCKS5 proxy with traffic obfuscation capabilities using the [Maybenot Framework](https://github.com/maybenot-io/maybenot).

## What is Maybenot Tunnel?

**Maybenot Tunnel** is a lightweight SOCKS5 proxy that adds an extra layer of obfuscation to your internet traffic. It works by:

1. Accepting SOCKS5 connections on port `1080` (will be configurable in future releases)
2. Establishing connections to target servers
3. Applying Maybenot obfuscation to the traffic
4. Adding random padding and timing to confuse traffic analysis

The proxy is particularly useful for situations where you need to bypass basic traffic analysis or when you want to add an extra layer of privacy to your connections.

### The Power of Maybenot Obfuscation

Maybenot is based on the principles of [DAITA (Defense Against AI-guided Traffic Analysis)](https://mullvad.net/de/blog/introducing-defense-against-ai-guided-traffic-analysis-daita), a technique developed to protect against sophisticated traffic analysis attacks. Modern adversaries can use machine learning and AI to analyze encrypted traffic patterns, potentially revealing:

- What websites you're visiting
- What services you're using
- What actions you're taking online
- Communication patterns and behaviors

Even when your traffic is encrypted with HTTPS or VPN, these patterns can be analyzed through:
- Packet timing
- Packet sizes
- Traffic volume
- Connection patterns

Maybenot works by introducing carefully designed randomness to your traffic patterns:
- Adding variable-sized padding to packets
- Fragmenting data into unpredictable chunks
- Introducing timing variations that confuse pattern recognition
- Generating dummy traffic during idle periods

This makes it significantly harder for AI-based traffic analysis to identify patterns in your internet usage, enhancing your privacy beyond what standard encryption provides.

## Features

- 🔒 Full SOCKS5 proxy support (IPv4, IPv6, domain resolution)
- 🌐 Automatic TLS/SSL detection and passthrough
- 🧩 Traffic obfuscation using the [Maybenot Framework](https://github.com/maybenot-io/maybenot)
- 📊 Intelligent handling of different traffic types
- 🔄 Automatic reconnection with exponential backoff
- 📝 Detailed logging with emoji indicators

## Installation

### Prerequisites

- Rust and Cargo (1.56.0 or newer)
- Git

### Building from source

1. Clone the repository:

```bash
git clone https://github.com/necm1/maybenot-tunnel.git
cd maybenot-tunnel
```

2. Build the project:
```bash
cargo build --release
```

3. The compiled binary will be available at `target/release/maybenot-tunnel`

## Quick start
1. Run the proxy:
```bash
./target/release/maybenot-tunnel
```

2. 2. Configure your application to use the SOCKS5 proxy at `127.0.0.1:1080`

That's it! Your traffic is now being obfuscated.

## Tutorial
### Setting up a browser to use Maybenot Tunnel Firefox

Firefox
1. Open Firefox and go to Settings
2. Scroll down to "Network Settings" and click "Settings..."
3. Select "Manual proxy configuration"
4. Enter "127.0.0.1" for SOCKS Host and "1080" for Port
5. Select "SOCKS v5"
6. Check "Proxy DNS when using SOCKS v5"
7. Click "OK" to save Chrome

Chrome
1. Open Chrome and go to Settings
2. Search for "proxy" and click on "Open your computer's proxy settings"
3. On macOS:
   - Click "Advanced..." and then select the "Proxies" tab
   - Check "SOCKS Proxy" and enter "127.0.0.1" and port "1080"
   - Click "OK" and "Apply"

### Using with curl

```bash
curl --socks5 127.0.0.1:1080 https://example.com
```

### Using with SSH
```bash
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@example.com
```

## Advanced Configuration
Maybenot Tunnel can be configured by modifying the constants in `src/obfuscation.rs`:

```rust
pub const MAX_FRAGMENT_SIZE: usize = 1024;
pub const MIN_FRAGMENT_SIZE: usize = 32;
pub const MAX_PADDING_SIZE: usize = 128;
pub const IDLE_THRESHOLD_MS: u64 = 500;
pub const DUMMY_TRAFFIC_INTERVAL_MS: u64 = 2000;
```

- `MAX_FRAGMENT_SIZE`: Maximum size of data fragments
- `MIN_FRAGMENT_SIZE`: Minimum size of data fragments
- `MAX_PADDING_SIZE`: Maximum size of random padding
- `IDLE_THRESHOLD_MS`: Time before connection is considered idle
- `DUMMY_TRAFFIC_INTERVAL_MS`: Interval for sending dummy traffic

## Troubleshooting
### Connection issues

If you're experiencing connection issues:

1. Check if the target server is accessible directly
2. Ensure no firewall is blocking the connection
3. Try increasing the max_consecutive_errors value in `src/server.rs`

### SSL/TLS errors

If you see SSL/TLS errors (like `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`):

- The proxy might be interfering with the TLS handshake
- Try visiting a non-HTTPS site first, then the HTTPS site
- If issues persist, check the TLS detection logic in `src/obfuscation.rs`

## How It Works
Maybenot Tunnel uses several techniques to obfuscate traffic:

1. **Traffic fragmentation**: Splits data into smaller chunks
2. **Random padding**: Adds random-sized padding to confuse traffic analysis
3. **Timing obfuscation**: Introduces small, random delays
4. **Protocol detection**: Automatically detects and handles different protocols
5. **Dummy traffic**: Generates fake traffic during idle periods

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
-  [Maybenot Framework](https://github.com/maybenot-io/maybenot) for the obfuscation capabilities
- The Rust and Tokio communities for excellent async runtime and networking libraries