use std::io::{Read, Write};
use std::net::UdpSocket;
use std::sync::Arc;

fn main() {
    const VPS_IP: &str = "24.55.14.254";
    const GATEWAY_IP: &str = "192.168.1.1";

    let mut config = tun::Configuration::default();
    config
        .address("10.0.0.1")
        .netmask("255.255.255.255")
        .up();

    let device = tun::create(&config).unwrap();

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

    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").unwrap());

    let vps_addr = format!("{}:5000", VPS_IP);

    let udp_recv = Arc::clone(&udp);

    // split tun device into reader and writer for separate threads
    let (mut reader, mut writer) = device.split();

    // receive thread: receive from udp and write to device
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 1500];
        loop {
            let (n, src) = udp_recv.recv_from(&mut buf).unwrap();
            writer.write_all(&buf[..n]).unwrap();
        }
    });

    // write thread: read from device and write to udp
    let mut buf = vec![0u8; 1500];
    loop {
        let n = reader.read(&mut buf).unwrap();
        udp.send_to(&buf[..n], &vps_addr).unwrap();
    }
}