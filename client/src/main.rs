use std::io::Read;
use std::net::UdpSocket;

fn main() {
    const VPS_IP: &str = "24.55.14.254";
    const GATEWAY_IP: &str = "192.168.1.1";

    let mut config = tun::Configuration::default();
    config
        .address("10.0.0.1")
        .netmask("255.255.255.255")
        .up();

    let mut device = tun::create(&config).unwrap();

    // prevent tunnel traffic from going into itself by routing vps traffic through the router
    // also idk now how string concatenation works in rust so imma use format, sue me
    let vps_route = format!("{}/32", VPS_IP);
    std::process::Command::new("ip")
        .args(["route", "add", &vps_route, "via", GATEWAY_IP])
        .status().unwrap();

    // route all other traffic to tun0
    std::process::Command::new("ip")
        .args(["route", "add", "0.0.0.0/0", "dev", "tun0"])
        .status()
        .unwrap();

    let udp = UdpSocket::bind("0.0.0.0:0").unwrap();

    let mut buf = vec![0u8; 1500];

    let vps_addr = format!("{}:5000", VPS_IP);
    loop {
        // get size of data written to buffer
        let n = device.read(&mut buf).unwrap();

        // send data from buffer to VPS
        udp.send_to(&buf[..n], &vps_addr).unwrap();
    }
}