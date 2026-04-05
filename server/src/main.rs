use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::sync::Arc;
use x25519_dalek::{EphemeralSecret, PublicKey};

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
    let access_key = SigningKey::from(&[0u8; 32]);
    let verify_key = access_key.verifying_key();

    let udp = Arc::new(UdpSocket::bind("0.0.0.0:5000").unwrap());
    let udp_recv = Arc::clone(&udp);

    let (session_key, client_addr) = loop {
        let mut buf = [0u8; 2048];

        let (n, src) = udp.recv_from(&mut buf).unwrap();

        // 32 (client public key) + 8 (timestamp) + 64 (signature)
        if n < 104 {
            continue;
        }

        // client public key byes
        let mut client_public_bytes = [0u8; 32];
        client_public_bytes.clone_from_slice(&buf[..32]);

        // timestamp bytes
        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.clone_from_slice(&buf[32..40]);

        // signature bytes
        let mut sig_bytes = [0u8; 64];
        sig_bytes.clone_from_slice(&buf[40..104]);

        let client_public = PublicKey::from(client_public_bytes);

        // TODO: check timestamp

        let signature = Signature::from_bytes(&sig_bytes);

        if verify_key.verify(&buf[..40], &signature).is_ok() {
            println!("Signature valid.");

            // gen keys
            let private = EphemeralSecret::random_from_rng(rand::thread_rng());
            let public = PublicKey::from(&private);

            // send public key
            udp.send_to(public.as_bytes(), &src).expect("Failed to send handshake.");

            let shared = private.diffie_hellman(&client_public);

            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, shared.to_bytes());

            let key = hasher.finalize();

            println!("Handshake successful with src={}", src);
            break(key, src);
        } else {
            println!("Signature invalid.");
        }
    };

    let cipher = Arc::new(ChaCha20Poly1305::new_from_slice(&session_key).unwrap());
    let mut counter: u64 = 0;
    let cipher_recv = Arc::clone(&cipher);

    let mut config = tun::Configuration::default();
    config
        .address("10.0.0.2")
        .netmask("255.255.255.255")
        .destination("10.0.0.1")
        .mtu(1400)
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

    let (mut reader, mut writer) = device.split();

    // proxy thread: receive from client through udp, modify sender ip (nat rule), and send through tun
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 1528];
        loop {
            let (n, src) = udp_recv.recv_from(&mut buf).unwrap();

            // only allow established client
            if !src.eq(&client_addr) {
                continue;
            }

            let (nonce_bytes, ciphertext) = buf[..n].split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);

            // TODO: check nonce with previous nonce sent

            let decrypted = cipher_recv.decrypt(&nonce, ciphertext).unwrap();

            writer.write_all(&decrypted).unwrap();
            println!("2. packet forwarded");
        }
    });

    // return thread: receive from tun, modify destination ip (nat rule), send back to client through udp
    let mut buf = vec![0u8; 1528];
    loop {
        let n = reader.read(&mut buf).unwrap();
        counter += 1;

        let mut nonce_bytes =[0u8; 12];
        nonce_bytes[..8].copy_from_slice(&counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(&nonce, &buf[..n]).unwrap();

        let mut packet = nonce_bytes.to_vec();
        packet.extend_from_slice(&ciphertext);
        udp.send_to(&packet, client_addr).unwrap();

        println!("3. packet received, forwarding backward");
    }
}