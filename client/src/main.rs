use common::{NetworkConfigurator, VpnEngine};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x25519_dalek::{EphemeralSecret, PublicKey};

struct ClientNetworkConfigurator {
    vps_route: String,
    gateway_ip: String
}
impl ClientNetworkConfigurator {
    fn new(vps_ip: &str, gateway_ip: &str) -> Self {
        Self {
            vps_route: format!("{}/32", vps_ip),
            gateway_ip: gateway_ip.to_string()
        }
    }
}
impl NetworkConfigurator for ClientNetworkConfigurator {
    fn setup(&self) {
        // prevent tunnel traffic from going into itself by routing vps traffic through the router
        // also idk now how string concatenation works in rust so imma use format, sue me
        std::process::Command::new("ip")
            .args(["route", "add", &self.vps_route, "via", &self.gateway_ip])
            .status().ok();

        std::process::Command::new("ip")
            .args(["route", "del", "default"])
            .status()
            .ok();

        // route all other traffic to tun0
        std::process::Command::new("ip")
            .args(["route", "add", "default", "dev", "tun0"])
            .status()
            .ok();
    }

    fn teardown(&self) {
        std::process::Command::new("ip")
            .args(["route", "del", &self.vps_route, "via", &self.gateway_ip])
            .status().ok();
        std::process::Command::new("ip")
            .args(["route", "del", "0.0.0.0/0", "dev", "tun0"])
            .status().ok();
        std::process::Command::new("ip")
            .args(["route", "add", "default", "via", &self.gateway_ip])
            .status().ok();

        println!("CLIENT TEARDOWN COMPLETE")
    }
}
impl Drop for ClientNetworkConfigurator {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn main() {
    const VPS_IP: &str = "172.20.0.10";
    const VPS_PORT: &str = "5000";
    const GATEWAY_IP: &str = "172.20.0.1";
    let access_key: SigningKey = SigningKey::from(&[0u8; 32]);

    let vps_addr: SocketAddr = format!("{}:{}", VPS_IP, VPS_PORT).parse().expect("Invalid VPS address format");

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

    let counter: u64 = 0;

    let mut config = tun::Configuration::default();
    config
        .address("10.0.0.1")
        .netmask("255.255.255.255")
        .destination("10.0.0.2")
        .mtu(1400)
        .up();

    let device = tun::create(&config).unwrap();

    let network_configurator = Arc::new(ClientNetworkConfigurator::new(&VPS_IP, GATEWAY_IP));
    network_configurator.setup();

    println!("routes set");

    // split tun device into reader and writer for separate threads
    let (reader, writer) = device.split();

    let ctrlc_config = Arc::clone(&network_configurator);
    ctrlc::set_handler(move || {
        ctrlc_config.teardown();
    }).unwrap();

    let engine_outbound = Arc::new(VpnEngine::new(&session_key));
    let engine_inbound = Arc::clone(&engine_outbound);

    // receive thread: receive from udp and write to device
    std::thread::spawn(move || {
        engine_inbound.run_inbound(writer, udp_recv, Some(vps_addr));
    });

    // write thread: read from device and write to udp
    engine_outbound.run_outbound(reader, udp, vps_addr, counter);
}