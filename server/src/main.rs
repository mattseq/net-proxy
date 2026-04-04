use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

struct CleanUp;

impl Drop for CleanUp {
    fn drop(&mut self) {
        std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=0"])
            .status()
            .unwrap();

        std::process::Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
            .status()
            .unwrap();

        std::process::Command::new("iptables")
            .args(["-D", "FORWARD", "-i", "tun0", "-o", "eth0", "-j", "ACCEPT"])
            .status().ok();
        std::process::Command::new("iptables")
            .args(["-D", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
            .status().ok();
    }
}

fn main() {

    let mut config = tun::Configuration::default();
    config
        .address("10.0.0.2")
        .netmask("255.255.255.255")
        .destination("10.0.0.1")
        .up();

    let device = tun::create(&config).unwrap();

    // route new packets in tun0 to their destination instead of ignoring bc different destination
    std::process::Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .status()
        .unwrap();

    // packets that jump from tun0 to eth0 should have their src rewritten to this vps ip
    std::process::Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
        .status()
        .unwrap();

    // tun0 -> eth0; let packets written to tun0 jump to eth0
    std::process::Command::new("iptables")
        .args(["-A", "FORWARD", "-i", "tun0", "-o", "eth0", "-j", "ACCEPT"])
        .status().ok();

    // eth0 -> tun0; only allow packets from established connection to jump from eth0 to tun0
    std::process::Command::new("iptables")
        .args(["-A", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        .status().ok();

    println!("routes set");

    let _cleanup = CleanUp;

    ctrlc::set_handler(move || {
        std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=0"])
            .status()
            .unwrap();

        std::process::Command::new("iptables")
            .args(["-t", "nat", "-D", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
            .status()
            .unwrap();

        std::process::Command::new("iptables")
            .args(["-D", "FORWARD", "-i", "tun0", "-o", "eth0", "-j", "ACCEPT"])
            .status().ok();
        std::process::Command::new("iptables")
            .args(["-D", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
            .status().ok();

        std::process::exit(0);
    }).unwrap();

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let client_addr_write = Arc::clone(&client_addr);
    let client_addr_read = Arc::clone(&client_addr);

    let udp = Arc::new(UdpSocket::bind("0.0.0.0:5000").unwrap());
    let udp_recv = Arc::clone(&udp);

    let (mut reader, mut writer) = device.split();

    // proxy thread: receive from client through udp, modify sender ip (nat rule), and send through tun
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 1528];
        loop {
            let (n, src) = udp_recv.recv_from(&mut buf).unwrap();
            *client_addr_write.lock().unwrap() = Some(src);
            writer.write_all(&buf[..n]).unwrap();
            println!("packet forwarded (client src={})", src)
        }
    });

    // receive thread: receive from tun, modify destination ip (nat rule), send back to client through udp
    let mut buf = vec![0u8; 1528];
    loop {
        let n = reader.read(&mut buf).unwrap();
        if let Some(addr) = *client_addr_read.lock().unwrap() {
            udp.send_to(&buf[..n], addr).unwrap();
            println!("packet received, backward to og src={}", addr);
        }
    }
}