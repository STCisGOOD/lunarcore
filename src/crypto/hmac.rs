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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc4231_vector1() {

        let key = [0x0b; 20];
        let data = b"Hi There";

        let mac = HmacSha256::mac(&key, data);
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        ];

        assert_eq!(mac, expected);
    }

    #[test]
    fn test_rfc4231_vector2() {

        let key = b"Jefe";
        let data = b"what do ya want for nothing?";

        let mac = HmacSha256::mac(key, data);
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
            0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
            0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        ];

        assert_eq!(mac, expected);
    }

    #[test]
    fn test_rfc4231_vector3() {

        let key = [0xaa; 20];
        let data = [0xdd; 50];

        let mac = HmacSha256::mac(&key, &data);
        let expected: [u8; 32] = [
            0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
            0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
            0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
            0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
        ];

        assert_eq!(mac, expected);
    }

    #[test]
    fn test_long_key() {

        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

        let mac = HmacSha256::mac(&key, data);
        let expected: [u8; 32] = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
            0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
            0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
            0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
        ];

        assert_eq!(mac, expected);
    }

    #[test]
    fn test_verify() {
        let key = b"secret";
        let data = b"message";
        let mac = HmacSha256::mac(key, data);

        assert!(HmacSha256::verify(key, data, &mac));


        let mut bad_mac = mac;
        bad_mac[0] ^= 1;
        assert!(!HmacSha256::verify(key, data, &bad_mac));
    }

    #[test]
    fn test_incremental() {
        let key = b"key";

        let mac1 = HmacSha256::mac(key, b"hello world");

        let mut hmac = HmacSha256::new(key);
        hmac.update(b"hello ");
        hmac.update(b"world");
        let mac2 = hmac.finalize();

        assert_eq!(mac1, mac2);
    }
}
