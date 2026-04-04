use std::io::{Read, Write};
use std::net::UdpSocket;
use std::sync::Arc;

struct CleanUp {
    vps_route: String,
    gateway_ip: String
}

impl CleanUp {
    fn new(vps_ip: &str, gateway_ip: &str) -> Self {
        Self {
            vps_route: format!("{}/32", vps_ip),
            gateway_ip: gateway_ip.to_string()
        }
    }
}

impl Drop for CleanUp {
    fn drop(&mut self) {
        std::process::Command::new("ip")
            .args(["route", "del", &self.vps_route, "via", &self.gateway_ip])
            .status().ok();
        std::process::Command::new("ip")
            .args(["route", "del", "0.0.0.0/0", "dev", "tun0"])
            .status().ok();
        std::process::Command::new("ip")
            .args(["route", "add", "default", "via", &self.gateway_ip])
            .status().ok();
    }
}

fn main() {
    const VPS_IP: &str = "172.20.0.10";
    const VPS_PORT: &str = "5000";
    const GATEWAY_IP: &str = "172.20.0.1";

    let mut config = tun::Configuration::default();
    config
        .address("10.0.0.1")
        .netmask("255.255.255.255")
        .destination("10.0.0.2")
        .up();

    let device = tun::create(&config).unwrap();

    // prevent tunnel traffic from going into itself by routing vps traffic through the router
    // also idk now how string concatenation works in rust so imma use format, sue me
    let vps_route = format!("{}/32", VPS_IP);
    std::process::Command::new("ip")
        .args(["route", "add", &vps_route, "via", GATEWAY_IP])
        .status().unwrap();

    std::process::Command::new("ip")
        .args(["route", "del", "default"])
        .status()
        .unwrap();

    // route all other traffic to tun0
    std::process::Command::new("ip")
        .args(["route", "add", "default", "dev", "tun0"])
        .status()
        .unwrap();

    println!("routes set");

    // cleanup Drop trait handles removing tun0 and ip routes
    let _cleanup = CleanUp::new(VPS_IP, GATEWAY_IP);

    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").unwrap());

    let vps_addr = format!("{}:{}", VPS_IP, VPS_PORT);

    let udp_recv = Arc::clone(&udp);

    // split tun device into reader and writer for separate threads
    let (mut reader, mut writer) = device.split();

    let v_ip = VPS_IP.to_string();
    let g_ip = GATEWAY_IP.to_string();
    ctrlc::set_handler(move || {
        let route = format!("{}/32", v_ip);

        std::process::Command::new("ip")
            .args(["route", "del", &route, "via", &g_ip])
            .status().ok();
        std::process::Command::new("ip")
            .args(["route", "del", "0.0.0.0/0", "dev", "tun0"])
            .status().ok();
        std::process::Command::new("ip")
            .args(["route", "add", "default", "via", &g_ip])
            .status().ok();

        std::process::exit(0);
    }).unwrap();

    // receive thread: receive from udp and write to device
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 1528];
        loop {
            let (n, src) = udp_recv.recv_from(&mut buf).unwrap();
            println!("packet returned from {}", src);

            writer.write_all(&buf[..n]).unwrap();
        }
    });

    // write thread: read from device and write to udp
    let mut buf = vec![0u8; 1528];
    loop {
        let n = reader.read(&mut buf).unwrap();
        udp.send_to(&buf[..n], &vps_addr).unwrap();
        println!("packet sent to {}", &vps_addr);
    }
}