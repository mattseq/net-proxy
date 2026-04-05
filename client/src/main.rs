use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x25519_dalek::{EphemeralSecret, PublicKey};

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
    let access_key: SigningKey = SigningKey::from(&[0u8; 32]);

    let vps_addr = format!("{}:{}", VPS_IP, VPS_PORT);

    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").unwrap());

    let udp_recv = Arc::clone(&udp);

    // gen keys
    let private = EphemeralSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&private);

    // timestamp
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let timestamp = now.to_be_bytes();

    // payload of public key and timestamp
    let mut payload = Vec::new();
    payload.extend_from_slice(public.clone().as_bytes());
    payload.extend_from_slice(&timestamp);

    // signature by signing payload with access key
    let signature = access_key.sign(&payload);

    // handshake packet with both (public key + time) and their signature
    let mut handshake_packet = payload;
    handshake_packet.extend_from_slice(&signature.to_bytes());

    udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let session_key = loop {
        println!("Sending handshake to {}", &vps_addr);

        udp.send_to(&handshake_packet, &vps_addr).expect("Failed to send handshake.");

        println!("Handshake sent. Waiting for response...");
        let mut resp_buf = [0u8; 32];

        match udp.recv_from(&mut resp_buf) {
            Ok((n, _)) => {
                if n >= 32 {
                    let server_public = PublicKey::from(resp_buf);
                    let shared = private.diffie_hellman(&server_public);

                    let mut hasher = Sha256::new();
                    Digest::update(&mut hasher, shared.to_bytes());

                    let key = hasher.finalize();

                    println!("Handshake successful");
                    break key;
                }
            }
            Err(_) => {
                println!("No response from server, retrying...");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };

    udp.set_read_timeout(None).unwrap();

    let cipher = Arc::new(ChaCha20Poly1305::new_from_slice(&session_key).unwrap());
    let mut counter: u64 = 0;
    let cipher_recv = Arc::clone(&cipher);

    let mut config = tun::Configuration::default();
    config
        .address("10.0.0.1")
        .netmask("255.255.255.255")
        .destination("10.0.0.2")
        .mtu(1400)
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

    // split tun device into reader and writer for separate threads
    let (mut reader, mut writer) = device.split();

    // cleanup Drop trait handles removing tun0 and ip routes
    let _cleanup = CleanUp::new(VPS_IP, GATEWAY_IP);

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
        let mut buf = vec![0u8; 1500];
        loop {
            let (n, src) = udp_recv.recv_from(&mut buf).unwrap();
            println!("4. packet returned from {}", src);

            // split for nonce
            let (nonce_bytes, ciphertext) = buf[..n].split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);

            // TODO: check nonce with previous nonce sent

            let decrypted = cipher_recv.decrypt(&nonce, ciphertext).unwrap();

            writer.write_all(&decrypted).unwrap();
        }
    });

    // write thread: read from device and write to udp
    let mut buf = vec![0u8; 1500];
    loop {
        let n = reader.read(&mut buf).unwrap();
        counter += 1;

        // create 12 byte nonce
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(&nonce, &buf[..n]).unwrap();

        let mut packet = nonce_bytes.to_vec();
        packet.extend_from_slice(&ciphertext);
        udp.send_to(&packet, &vps_addr).unwrap();
        println!("1. packet sent to {}", &vps_addr);
    }
}