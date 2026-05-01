### NetProxy
A high-performance, secure VPN and network proxy written in Rust. NetProxy creates a secure tunnel between a client and a server, providing encrypted traffic routing and automatic network configuration using TUN devices.

## Features
- Tunneling: Uses TUN devices for proxying.
- Encryption: Uses several cryptographic algorithms to ensure safe tunneling.
- Secure Handshake: Signature-based authentication to prevent unauthorized access.
- Zero-Config Routing: Automatically manages route config while running.

## Quick Start
### Prerequisites
- Linux: Kernel support for TUN/TAP devices.
- Network Packages: `iptables` and `iproute2`
- must be run with root privileges

### Installation
Download the pre-compiled binary for your architecture (x86_64 or aarch64) from the Github Release.

### Usage
1. Start the Server
`sudo ./proxy serve --port <port> --password <password>`

2. Port Forward the Server IP.
   Ensure your router is configured to forward the server's port (UDP) to the host running the proxy.

3. Connect with the Client
`sudo ./proxy connect <server_ip> --port <port> --password <password>`

### Docker Testing
A Docker Compose setup is included and can be used to test the VPN on a single device without exposing your own network. Keep in mind that it isn't fully accurate to the real use case. Problems with network devices, latency, and compatibility may arise in real use cases.

### Current Limitations and Possible Improvements
- Server can only maintain one client
- Server must be restarted after the client disconnects for it to connect again (this will likely be fixed in the next update)
- Only runs on Linux

## License
MIT