use heapless::Vec;
use crate::crypto::aes::{Aes128, Aes256};
use crate::crypto::sha256::Sha256;
use crate::crypto::hmac::HmacSha256;
use crate::crypto::hkdf::meshtastic as mesh_kdf;
use super::channel::ChannelKey;

pub const MAX_PAYLOAD_SIZE: usize = 237;

pub const NONCE_SIZE: usize = 16;

pub const MIC_SIZE: usize = 4;

pub const MIC_SIZE_ENHANCED: usize = 8;

pub struct EncryptionContext {

    key: ChannelKey,
}

impl EncryptionContext {

    pub fn new(key: ChannelKey) -> Self {
        Self { key }
    }

    pub fn with_default_key() -> Self {
        Self::new(ChannelKey::default_key())
    }

    pub fn from_channel_name(name: &str) -> Self {
        Self::new(ChannelKey::from_channel_name(name))
    }

    pub fn from_key_bytes(key: &[u8]) -> Self {
        Self::new(ChannelKey::from_bytes(key))
    }

    pub fn is_encrypted(&self) -> bool {
        self.key.is_encrypted()
    }

    pub fn encrypt(&self, packet_id: u32, sender: u32, plaintext: &[u8]) -> Option<Vec<u8, MAX_PAYLOAD_SIZE>> {
        if !self.key.is_encrypted() {

            return Vec::from_slice(plaintext).ok();
        }

        if plaintext.len() > MAX_PAYLOAD_SIZE {
            return None;
        }

        let nonce = mesh_kdf::derive_nonce(packet_id, sender);

        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(plaintext).ok()?;

        match &self.key {
            ChannelKey::Aes128(key) => {
                let cipher = Aes128::new(key);
                cipher.encrypt_ctr(&nonce, &mut ciphertext);
            }
            ChannelKey::Aes256(key) => {
                let cipher = Aes256::new(key);
                cipher.encrypt_ctr(&nonce, &mut ciphertext);
            }
            ChannelKey::None => {}
        }

        Some(ciphertext)
    }

    pub fn decrypt(&self, packet_id: u32, sender: u32, ciphertext: &[u8]) -> Option<Vec<u8, MAX_PAYLOAD_SIZE>> {
        if !self.key.is_encrypted() {
            return Vec::from_slice(ciphertext).ok();
        }

        if ciphertext.is_empty() || ciphertext.len() > MAX_PAYLOAD_SIZE {
            return None;
        }

        let nonce = mesh_kdf::derive_nonce(packet_id, sender);

        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(ciphertext).ok()?;

        match &self.key {
            ChannelKey::Aes128(key) => {
                let cipher = Aes128::new(key);
                cipher.decrypt_ctr(&nonce, &mut plaintext);
            }
            ChannelKey::Aes256(key) => {
                let cipher = Aes256::new(key);
                cipher.decrypt_ctr(&nonce, &mut plaintext);
            }
            ChannelKey::None => {}
        }

        Some(plaintext)
    }

    pub fn key_hash(&self) -> u8 {
        let key_bytes = self.key.as_bytes();
        if key_bytes.is_empty() {
            return 0;
        }

        let mut h: u8 = 0;
        for &b in key_bytes {
            h ^= b;
        }
        h
    }
}

impl Default for EncryptionContext {
    fn default() -> Self {
        Self::with_default_key()
    }
}

pub fn compute_mic(data: &[u8]) -> [u8; MIC_SIZE] {
    let hash = Sha256::hash(data);
    let mut mic = [0u8; MIC_SIZE];
    mic.copy_from_slice(&hash[..MIC_SIZE]);
    mic
}

pub fn verify_mic(data: &[u8], expected_mic: &[u8]) -> bool {
    if expected_mic.len() != MIC_SIZE {
        return false;
    }

    let computed = compute_mic(data);
    constant_time_eq(&computed, expected_mic)
}

#[inline(never)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

pub fn compute_mic_enhanced(key: &[u8], data: &[u8]) -> [u8; MIC_SIZE_ENHANCED] {

    let mut hmac_key = [0u8; 32];
    if key.len() >= 32 {
        hmac_key.copy_from_slice(&key[..32]);
    } else {
        hmac_key[..key.len()].copy_from_slice(key);
    }

    let mac = HmacSha256::mac(&hmac_key, data);
    let mut mic = [0u8; MIC_SIZE_ENHANCED];
    mic.copy_from_slice(&mac[..MIC_SIZE_ENHANCED]);
    mic
}

pub fn verify_mic_enhanced(key: &[u8], data: &[u8], expected_mic: &[u8]) -> bool {
    if expected_mic.len() != MIC_SIZE_ENHANCED {
        return false;
    }

    let computed = compute_mic_enhanced(key, data);
    constant_time_eq(&computed, expected_mic)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MicMode {

    Standard,

    Enhanced,
}

impl Default for MicMode {
    fn default() -> Self {
        MicMode::Standard
    }
}

use crate::crypto::x25519;
use crate::crypto::chacha20::ChaCha20;
use crate::crypto::poly1305::ChaCha20Poly1305;
use crate::crypto::hkdf::Hkdf;

pub const PKI_OVERHEAD: usize = 32 + 16;

pub fn pki_encrypt(
    recipient_pubkey: &[u8; 32],
    sender_privkey: &[u8; 32],
    plaintext: &[u8],
    nonce: &[u8; 12],
) -> Option<Vec<u8, 256>> {
    if plaintext.len() + PKI_OVERHEAD > 256 {
        return None;
    }

    let mut ephemeral_seed = [0u8; 32];
    Hkdf::derive(nonce, sender_privkey, b"ephemeral", &mut ephemeral_seed);

    let ephemeral_pubkey = x25519::x25519_base(&ephemeral_seed);

    let shared_secret = x25519::x25519(&ephemeral_seed, recipient_pubkey);

    let mut key = [0u8; 32];
    Hkdf::derive(b"meshtastic-pki", &shared_secret, &ephemeral_pubkey, &mut key);

    let mut ciphertext = [0u8; 240];
    let mut tag = [0u8; 16];

    if plaintext.len() > ciphertext.len() {
        return None;
    }

    ChaCha20Poly1305::seal(&key, nonce, &[], plaintext, &mut ciphertext[..plaintext.len()], &mut tag);

    let mut output = Vec::new();
    output.extend_from_slice(&ephemeral_pubkey).ok()?;
    output.extend_from_slice(&ciphertext[..plaintext.len()]).ok()?;
    output.extend_from_slice(&tag).ok()?;

    Some(output)
}

pub fn pki_decrypt(
    recipient_privkey: &[u8; 32],
    encrypted: &[u8],
    nonce: &[u8; 12],
) -> Option<Vec<u8, 240>> {
    if encrypted.len() < PKI_OVERHEAD {
        return None;
    }

    let mut ephemeral_pubkey = [0u8; 32];
    ephemeral_pubkey.copy_from_slice(&encrypted[..32]);

    let ciphertext = &encrypted[32..encrypted.len() - 16];
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&encrypted[encrypted.len() - 16..]);

    let shared_secret = x25519::x25519(recipient_privkey, &ephemeral_pubkey);

    let mut key = [0u8; 32];
    Hkdf::derive(b"meshtastic-pki", &shared_secret, &ephemeral_pubkey, &mut key);

    let mut plaintext = [0u8; 240];
    if ciphertext.len() > plaintext.len() {
        return None;
    }

    if !ChaCha20Poly1305::open(&key, nonce, &[], ciphertext, &tag, &mut plaintext[..ciphertext.len()]) {
        return None;
    }

    let mut output = Vec::new();
    output.extend_from_slice(&plaintext[..ciphertext.len()]).ok()?;
    Some(output)
}

pub struct KeyStore {

    channel_keys: [Option<EncryptionContext>; 8],

    node_privkey: Option<[u8; 32]>,

    node_pubkey: Option<[u8; 32]>,
}

impl Drop for KeyStore {
    fn drop(&mut self) {

        if let Some(ref mut privkey) = self.node_privkey {
            crate::crypto::secure_zero(privkey);
        }

    }
}

impl KeyStore {

    pub const fn new() -> Self {
        Self {
            channel_keys: [None, None, None, None, None, None, None, None],
            node_privkey: None,
            node_pubkey: None,
        }
    }

    pub fn set_channel_key(&mut self, index: u8, key: &[u8]) {
        if (index as usize) < self.channel_keys.len() {
            self.channel_keys[index as usize] = Some(EncryptionContext::from_key_bytes(key));
        }
    }

    pub fn set_channel_name(&mut self, index: u8, name: &str) {
        if (index as usize) < self.channel_keys.len() {
            self.channel_keys[index as usize] = Some(EncryptionContext::from_channel_name(name));
        }
    }

    pub fn get_channel(&self, index: u8) -> Option<&EncryptionContext> {
        self.channel_keys.get(index as usize)?.as_ref()
    }

    pub fn set_node_keypair(&mut self, privkey: &[u8; 32]) {
        self.node_privkey = Some(*privkey);
        self.node_pubkey = Some(x25519::x25519_base(privkey));
    }

    pub fn generate_node_keypair(&mut self, entropy: &[u8; 32]) {

        let mut privkey = [0u8; 32];
        Hkdf::derive(b"meshtastic", entropy, b"node-key", &mut privkey);
        self.set_node_keypair(&privkey);
    }

    pub fn node_pubkey(&self) -> Option<&[u8; 32]> {
        self.node_pubkey.as_ref()
    }

    pub fn encrypt_for_node(
        &self,
        recipient_pubkey: &[u8; 32],
        plaintext: &[u8],
        nonce: &[u8; 12],
    ) -> Option<Vec<u8, 256>> {
        let privkey = self.node_privkey.as_ref()?;
        pki_encrypt(recipient_pubkey, privkey, plaintext, nonce)
    }

    pub fn decrypt_from_node(
        &self,
        encrypted: &[u8],
        nonce: &[u8; 12],
    ) -> Option<Vec<u8, 240>> {
        let privkey = self.node_privkey.as_ref()?;
        pki_decrypt(privkey, encrypted, nonce)
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}
