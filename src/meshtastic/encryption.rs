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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let ctx = EncryptionContext::with_default_key();
        let plaintext = b"Hello, Meshtastic!";
        let packet_id = 0x12345678;
        let sender = 0xDEADBEEF;

        let ciphertext = ctx.encrypt(packet_id, sender, plaintext).unwrap();
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = ctx.decrypt(packet_id, sender, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_encryption_with_channel_name() {
        let ctx = EncryptionContext::from_channel_name("TestChannel");
        let plaintext = b"Encrypted with channel name key";
        let packet_id = 0x11111111;
        let sender = 0x22222222;

        let ciphertext = ctx.encrypt(packet_id, sender, plaintext).unwrap();
        let decrypted = ctx.decrypt(packet_id, sender, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_different_nonces_different_ciphertext() {
        let ctx = EncryptionContext::with_default_key();
        let plaintext = b"Same plaintext";

        let ct1 = ctx.encrypt(1, 1, plaintext).unwrap();
        let ct2 = ctx.encrypt(2, 1, plaintext).unwrap();
        let ct3 = ctx.encrypt(1, 2, plaintext).unwrap();


        assert_ne!(&ct1[..], &ct2[..]);
        assert_ne!(&ct1[..], &ct3[..]);
        assert_ne!(&ct2[..], &ct3[..]);
    }

    #[test]
    fn test_mic_computation() {
        let data = b"Test data for MIC";
        let mic = compute_mic(data);
        assert_eq!(mic.len(), MIC_SIZE);


        assert!(verify_mic(data, &mic));


        assert!(!verify_mic(data, &[0, 0, 0, 0]));
    }

    #[test]
    fn test_enhanced_mic_computation() {
        let key = b"test channel key for HMAC";
        let data = b"Test data for enhanced MIC";

        let mic = compute_mic_enhanced(key, data);
        assert_eq!(mic.len(), MIC_SIZE_ENHANCED);


        assert!(verify_mic_enhanced(key, data, &mic));


        let other_key = b"different key for testing";
        let other_mic = compute_mic_enhanced(other_key, data);
        assert_ne!(mic, other_mic);
        assert!(!verify_mic_enhanced(other_key, data, &mic));


        let other_data = b"Different test data";
        let other_mic2 = compute_mic_enhanced(key, other_data);
        assert_ne!(mic, other_mic2);


        assert!(!verify_mic_enhanced(key, data, &[0, 0, 0, 0]));
    }

    #[test]
    fn test_enhanced_mic_is_keyed() {


        let data = b"Same data for both";

        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];

        let mic1 = compute_mic_enhanced(&key1, data);
        let mic2 = compute_mic_enhanced(&key2, data);


        assert_ne!(mic1, mic2);


        assert!(verify_mic_enhanced(&key1, data, &mic1));
        assert!(verify_mic_enhanced(&key2, data, &mic2));
        assert!(!verify_mic_enhanced(&key1, data, &mic2));
        assert!(!verify_mic_enhanced(&key2, data, &mic1));
    }

    #[test]
    fn test_no_encryption() {
        let ctx = EncryptionContext::new(ChannelKey::None);
        let plaintext = b"Unencrypted data";
        let packet_id = 1;
        let sender = 2;

        let output = ctx.encrypt(packet_id, sender, plaintext).unwrap();
        assert_eq!(&output[..], plaintext);
    }

    #[test]
    fn test_key_hash() {
        let ctx = EncryptionContext::from_key_bytes(&[0x01, 0x02, 0x03, 0x04]);

        assert_eq!(ctx.key_hash(), 0x04);
    }

    #[test]
    fn test_pki_encryption_roundtrip() {

        let alice_priv = [0x42u8; 32];
        let alice_pub = x25519::x25519_base(&alice_priv);

        let bob_priv = [0x24u8; 32];
        let _bob_pub = x25519::x25519_base(&bob_priv);

        let plaintext = b"Secret message for Alice";
        let nonce = [0x11u8; 12];


        let encrypted = pki_encrypt(&alice_pub, &bob_priv, plaintext, &nonce).unwrap();
        assert!(encrypted.len() > plaintext.len());


        let decrypted = pki_decrypt(&alice_priv, &encrypted, &nonce).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_key_store() {
        let mut store = KeyStore::new();


        store.set_channel_key(0, &[0x01, 0x02, 0x03, 0x04]);
        assert!(store.get_channel(0).is_some());
        assert!(store.get_channel(1).is_none());


        store.set_channel_name(1, "SecondChannel");
        assert!(store.get_channel(1).is_some());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 3, 4]));
    }
}
