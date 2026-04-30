use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, ChaChaPoly1305, KeyInit, Nonce};
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tun::{Reader, Writer};

pub fn password_to_key(password: String) -> SigningKey {
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, password.as_bytes());
    let hash = hasher.finalize();
    
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash);
    
    SigningKey::from_bytes(&key_bytes)
}

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
        let mut nonce_window: NonceWindow = NonceWindow::new();
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

            let mut counter_bytes = [0u8; 8];
            counter_bytes.copy_from_slice(&nonce_bytes[..8]);

            let nonce_verified = nonce_window.check(u64::from_be_bytes(counter_bytes));

            if nonce_verified {
                let decrypted = self.cipher.decrypt(&nonce, ciphertext).unwrap();

                writer.write_all(&decrypted).unwrap();
                println!("inbound");
            } else {
                println!("inbound dropped")
            }
        }
    }
}

pub trait NetworkConfigurator {
    fn setup(&self);
    fn teardown(&self);
}

pub struct NonceWindow {
    pub last_nonce: u64,
    pub bitmap: u64
}
impl NonceWindow {
    pub fn new() -> Self {
        Self {
            last_nonce: 0,
            bitmap: 0
        }
    }

    pub fn check(&mut self, new_nonce: u64) -> bool {
        // incoming nonce is newer than previuosly seen one
        if new_nonce > self.last_nonce {
            let diff = new_nonce - self.last_nonce;

            if diff >= 64 {
                // newest packet cleared the window completely, reset bitmap
                self.bitmap = 1;
                println!("FAST: Nonce cleared window. Window reset.");
            } else {
                // shift bitmap by diff
                self.bitmap <<= diff;
                // add 1 at the end for newest nonce
                self.bitmap |= 1;

                println!("NORMAL: Nonce in front of window. Window moved forward.");
            }

            self.last_nonce = new_nonce;
            return true;
        }

        // diff is difference from end of window to new nonce
        let diff = self.last_nonce - new_nonce;
        if diff < 64 {
            // mask with bit "diff" bits from the end marked as 1
            let mask = 1 << diff;

            // check if that bit is already 1 in bitmap
            if self.bitmap & mask == 0 {
                self.bitmap |= mask;
                println!("SLOW: Nonce within window and is now marked.");
                return true;
            } else {
                // bit was already 1
                println!("REPLAY: Nonce within window but was replay.");
                return false;
            }
        }

        // nonce is too old
        println!("SNAIL: Nonce was too old.");
        false
    }
}