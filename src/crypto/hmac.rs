use super::sha256::{Sha256, BLOCK_SIZE, DIGEST_SIZE};

pub struct HmacSha256 {

    inner: Sha256,

    outer_key: [u8; BLOCK_SIZE],
}

impl HmacSha256 {

    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; BLOCK_SIZE];

        if key.len() > BLOCK_SIZE {
            let hashed = Sha256::hash(key);
            key_block[..DIGEST_SIZE].copy_from_slice(&hashed);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut inner_key = [0u8; BLOCK_SIZE];
        let mut outer_key = [0u8; BLOCK_SIZE];

        for i in 0..BLOCK_SIZE {
            inner_key[i] = key_block[i] ^ 0x36;
            outer_key[i] = key_block[i] ^ 0x5c;
        }

        let mut inner = Sha256::new();
        inner.update(&inner_key);

        Self { inner, outer_key }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; DIGEST_SIZE] {

        let inner_hash = self.inner.finalize();

        let mut outer = Sha256::new();
        outer.update(&self.outer_key);
        outer.update(&inner_hash);
        outer.finalize()
    }

    pub fn mac(key: &[u8], data: &[u8]) -> [u8; DIGEST_SIZE] {
        let mut hmac = Self::new(key);
        hmac.update(data);
        hmac.finalize()
    }

    pub fn verify(key: &[u8], data: &[u8], expected: &[u8; DIGEST_SIZE]) -> bool {
        let computed = Self::mac(key, data);
        super::constant_time_eq(&computed, expected)
    }
}

impl Clone for HmacSha256 {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            outer_key: self.outer_key,
        }
    }
}
