use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, ChaChaPoly1305, KeyInit, Nonce};
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use tun::{Reader, Writer};

pub struct VpnEngine {
    pub cipher: Arc<ChaCha20Poly1305>
}

impl VpnEngine {
    pub fn new(session_key: &[u8]) -> Self {
        Self {
            cipher: Arc::new(ChaChaPoly1305::new_from_slice(session_key).unwrap())
        }
    }

    pub fn run_outbound(&self, mut reader: Reader, udp: Arc<UdpSocket>, addr: SocketAddr, mut counter: u64) {
        let mut buf = vec![0u8; 1528];
        loop {
            let n = reader.read(&mut buf).unwrap();
            counter += 1;

            let mut nonce_bytes =[0u8; 12];
            nonce_bytes[..8].copy_from_slice(&counter.to_be_bytes());
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = self.cipher.encrypt(&nonce, &buf[..n]).unwrap();

            let mut packet = nonce_bytes.to_vec();
            packet.extend_from_slice(&ciphertext);
            udp.send_to(&packet, addr).unwrap();

            println!("outbound");
        }
    }

    pub fn run_inbound(&self, mut writer: Writer, udp: Arc<UdpSocket>, expected_src: Option<SocketAddr>) {
        let mut buf = vec![0u8; 1528];
        loop {
            let (n, src) = udp.recv_from(&mut buf).unwrap();

            // only allow expected_src if given
            if let Some(expected) = expected_src {
                if src != expected {
                    continue;
                }
            }

            let (nonce_bytes, ciphertext) = buf[..n].split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);

            // TODO: check nonce with previous nonce sent

            let decrypted = self.cipher.decrypt(&nonce, ciphertext).unwrap();

            writer.write_all(&decrypted).unwrap();
            println!("inbound");
        }
    }
}

pub trait NetworkConfigurator {
    fn setup(&self);
    fn teardown(&self);
}