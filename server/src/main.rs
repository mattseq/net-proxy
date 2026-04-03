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
    }
}

fn main() {

    let mut config = tun::Configuration::default();
    config
        .address("10.0.0.2")
        .netmask("255.255.255.0")
        .up();

    let device = tun::create(&config).unwrap();

    std::process::Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .status()
        .unwrap();

    std::process::Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
        .status()
        .unwrap();

    let _cleanup = CleanUp;

    ctrlc::set_handler(|| std::process::exit(0)).unwrap();

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let client_addr_write = Arc::clone(&client_addr);
    let client_addr_read = Arc::clone(&client_addr);

    let udp = Arc::new(UdpSocket::bind("0.0.0.0:5000").unwrap());
    let udp_recv = Arc::clone(&udp);

    let (mut reader, mut writer) = device.split();

    // receive thread: receive from client, modify sender ip, and send through udp
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 1500];
        loop {
            let (n, src) = udp_recv.recv_from(&mut buf).unwrap();
            // src is still 192.168.x.x (local ip of sender), need to replace with LAN_IP
            *client_addr_write.lock().unwrap() = Some(src);
            writer.write_all(&buf[..n]).unwrap();
        }
    });

    // send back thread: receive from udp, modify destination ip, send back through udp
    let mut buf = vec![0u8; 1500];
    loop {
        let n = reader.read(&mut buf).unwrap();
        if let Some(addr) = *client_addr_read.lock().unwrap() {
            udp.send_to(&buf[..n], addr).unwrap();
        }
    }
}