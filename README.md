### NetProxy
A high-performance, secure VPN and network proxy written in Rust. NetProxy creates a secure tunnel between a client and a server, providing encrypted traffic routing and automatic network configuration using TUN devices.

## Features
- Tunneling: Uses TUN devices for proxying.
- Encryption: Uses several cryptographic algorithms to ensure safe tunneling.
- Secure Handshake: Signature-based authentication to prevent unauthorized access.
- Zero-Config Routing: Automatically manages route config while running.

## Quick Start
### Prerequisites
Linux: Kernel support for TUN/TAP devices.
Network Packages: `iptables` and `iproute2`

### Installation
Download the binary from GitHub Releases for your device.

### Usage
1. Start the Server
`./proxy serve --port <port> --password <password>`

2. Port Forward the Server IP.
You'll have to configure your router to port forward the proxy server.

3. Connect with the Client
`./proxy connect <server_ip> --port <port> --password <password>`

### Current Limitations and Possible Improvements
- Server can only maintain one client
- Server must be restarted after the client disconnects for it to connect again (this will likely be fixed in the next update)
- Only runs on Linux

## License
MIT