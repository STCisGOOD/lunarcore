use super::hmac::HmacSha256;
use super::sha256::DIGEST_SIZE;

pub struct Hkdf;

impl Hkdf {

    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; DIGEST_SIZE] {
        let salt = if salt.is_empty() {
            &[0u8; DIGEST_SIZE][..]
        } else {
            salt
        };
        HmacSha256::mac(salt, ikm)
    }

    pub fn expand(prk: &[u8; DIGEST_SIZE], info: &[u8], okm: &mut [u8]) {
        let n = (okm.len() + DIGEST_SIZE - 1) / DIGEST_SIZE;
        assert!(n <= 255, "Output too long");

        let mut t = [0u8; DIGEST_SIZE];
        let mut offset = 0;

        for i in 1..=n {
            let mut hmac = HmacSha256::new(prk);

            if i > 1 {
                hmac.update(&t);
            }
            hmac.update(info);
            hmac.update(&[i as u8]);

            t = hmac.finalize();

            let to_copy = core::cmp::min(DIGEST_SIZE, okm.len() - offset);
            okm[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
            offset += to_copy;
        }
    }

    pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
        let prk = Self::extract(salt, ikm);
        Self::expand(&prk, info, okm);
    }

    pub fn derive_key<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; N] {
        let mut key = [0u8; N];
        Self::derive(salt, ikm, info, &mut key);
        key
    }
}

pub mod reticulum {
    use super::*;
    use crate::crypto::sha256::Sha256;

    pub const IDENTITY_HASH_SIZE: usize = 16;

    pub const FULL_HASH_SIZE: usize = 32;

    pub fn identity_hash(signing_key: &[u8; 32], encryption_key: &[u8; 32]) -> [u8; IDENTITY_HASH_SIZE] {
        let mut hasher = Sha256::new();
        hasher.update(signing_key);
        hasher.update(encryption_key);
        let full = hasher.finalize();

        let mut hash = [0u8; IDENTITY_HASH_SIZE];
        hash.copy_from_slice(&full[..IDENTITY_HASH_SIZE]);
        hash
    }

    pub fn full_identity_hash(signing_key: &[u8; 32], encryption_key: &[u8; 32]) -> [u8; FULL_HASH_SIZE] {
        let mut hasher = Sha256::new();
        hasher.update(signing_key);
        hasher.update(encryption_key);
        hasher.finalize()
    }

    pub fn derive_link_keys(
        shared_secret: &[u8; 32],
        initiator_pub: &[u8; 32],
        responder_pub: &[u8; 32],
    ) -> LinkKeys {

        let mut context = [0u8; 64];
        context[..32].copy_from_slice(initiator_pub);
        context[32..].copy_from_slice(responder_pub);

        let mut master = [0u8; 64];
        Hkdf::derive(b"reticulum", shared_secret, &context, &mut master);

        LinkKeys {
            tx_key: {
                let mut k = [0u8; 32];
                k.copy_from_slice(&master[..32]);
                k
            },
            rx_key: {
                let mut k = [0u8; 32];
                k.copy_from_slice(&master[32..]);
                k
            },
        }
    }

    pub struct LinkKeys {
        pub tx_key: [u8; 32],
        pub rx_key: [u8; 32],
    }
}

pub mod meshcore {
    use super::*;

    pub fn derive_channel_key(psk: &[u8], channel_id: u8) -> [u8; 32] {
        let info = [b'C', b'H', channel_id];
        Hkdf::derive_key(b"meshcore", psk, &info)
    }

    pub fn derive_node_key(identity: &[u8; 32], purpose: &[u8]) -> [u8; 32] {
        Hkdf::derive_key(b"meshcore-node", identity, purpose)
    }
}

pub mod meshtastic {
    use super::*;
    use crate::crypto::sha256::Sha256;

    pub const DEFAULT_KEY: [u8; 16] = [
        0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
        0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
    ];

    pub fn derive_channel_key(channel_name: &str) -> [u8; 32] {

        let hash = Sha256::hash(channel_name.as_bytes());
        hash
    }

    pub fn derive_nonce(packet_id: u32, sender: u32) -> [u8; 16] {
        let mut nonce = [0u8; 16];

        nonce[..4].copy_from_slice(&packet_id.to_le_bytes());

        nonce[8..12].copy_from_slice(&sender.to_le_bytes());

        nonce
    }
}
