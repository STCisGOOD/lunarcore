const STATE_SIZE: usize = 16;


pub const BLOCK_SIZE: usize = 64;


pub const KEY_SIZE: usize = 32;


pub const NONCE_SIZE: usize = 12;


pub struct ChaCha20 {

    state: [u32; STATE_SIZE],
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {

        crate::crypto::secure_zero_u32(&mut self.state);
    }
}

impl ChaCha20 {

    const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];


    pub fn new(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> Self {
        let mut state = [0u32; STATE_SIZE];


        state[0] = Self::CONSTANTS[0];
        state[1] = Self::CONSTANTS[1];
        state[2] = Self::CONSTANTS[2];
        state[3] = Self::CONSTANTS[3];


        state[4] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        state[5] = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        state[6] = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        state[7] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
        state[8] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        state[9] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        state[10] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        state[11] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);


        state[12] = 0;


        state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

        Self { state }
    }


    pub fn new_with_counter(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], counter: u32) -> Self {
        let mut cipher = Self::new(key, nonce);
        cipher.state[12] = counter;
        cipher
    }


    fn block(&self, counter: u32) -> [u8; BLOCK_SIZE] {
        let mut state = self.state;
        state[12] = counter;

        let mut working = state;


        for _ in 0..10 {

            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);


            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }


        for i in 0..STATE_SIZE {
            working[i] = working[i].wrapping_add(state[i]);
        }


        let mut output = [0u8; BLOCK_SIZE];
        for (i, word) in working.iter().enumerate() {
            let bytes = word.to_le_bytes();
            output[i * 4] = bytes[0];
            output[i * 4 + 1] = bytes[1];
            output[i * 4 + 2] = bytes[2];
            output[i * 4 + 3] = bytes[3];
        }

        output
    }


    pub fn apply_keystream(&self, data: &mut [u8]) {
        let mut counter = self.state[12];

        for chunk in data.chunks_mut(BLOCK_SIZE) {
            let keystream = self.block(counter);
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }
            counter = counter.wrapping_add(1);
        }
    }


    pub fn encrypt(&self, data: &mut [u8]) {
        self.apply_keystream(data);
    }


    pub fn decrypt(&self, data: &mut [u8]) {
        self.apply_keystream(data);
    }


    pub fn keystream(&self, len: usize) -> heapless::Vec<u8, 1024> {
        let mut output = heapless::Vec::new();
        let mut counter = self.state[12];

        let mut remaining = len;
        while remaining > 0 {
            let block = self.block(counter);
            let to_copy = core::cmp::min(remaining, BLOCK_SIZE);
            for i in 0..to_copy {
                let _ = output.push(block[i]);
            }
            remaining -= to_copy;
            counter = counter.wrapping_add(1);
        }

        output
    }
}


#[inline]
fn quarter_round(state: &mut [u32; STATE_SIZE], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}


pub fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; 16];


    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;


    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }


    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }


    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }


    let mut output = [0u8; 32];
    for i in 0..4 {
        let bytes = state[i].to_le_bytes();
        output[i * 4] = bytes[0];
        output[i * 4 + 1] = bytes[1];
        output[i * 4 + 2] = bytes[2];
        output[i * 4 + 3] = bytes[3];
    }
    for i in 0..4 {
        let bytes = state[12 + i].to_le_bytes();
        output[16 + i * 4] = bytes[0];
        output[16 + i * 4 + 1] = bytes[1];
        output[16 + i * 4 + 2] = bytes[2];
        output[16 + i * 4 + 3] = bytes[3];
    }

    output
}


pub struct XChaCha20 {
    inner: ChaCha20,
}

impl XChaCha20 {

    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {

        let mut hnonce = [0u8; 16];
        hnonce.copy_from_slice(&nonce[..16]);
        let subkey = hchacha20(key, &hnonce);


        let mut chacha_nonce = [0u8; 12];
        chacha_nonce[4..].copy_from_slice(&nonce[16..]);

        Self {
            inner: ChaCha20::new(&subkey, &chacha_nonce),
        }
    }


    pub fn apply_keystream(&self, data: &mut [u8]) {
        self.inner.apply_keystream(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc8439_block() {

        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00,
        ];

        let cipher = ChaCha20::new_with_counter(&key, &nonce, 1);
        let block = cipher.block(1);


        let expected_start: [u8; 16] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
            0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        ];

        assert_eq!(&block[..16], &expected_start);
    }

    #[test]
    fn test_encryption_decryption() {
        let key: [u8; 32] = [0x42; 32];
        let nonce: [u8; 12] = [0x24; 12];
        let plaintext = b"Hello, ChaCha20!";

        let cipher = ChaCha20::new(&key, &nonce);

        let mut data = [0u8; 16];
        data.copy_from_slice(plaintext);


        cipher.encrypt(&mut data);
        assert_ne!(&data, plaintext);


        cipher.decrypt(&mut data);
        assert_eq!(&data, plaintext);
    }

    #[test]
    fn test_rfc8439_encryption() {

        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00,
        ];

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let cipher = ChaCha20::new_with_counter(&key, &nonce, 1);

        let mut data = [0u8; 114];
        data.copy_from_slice(plaintext);
        cipher.encrypt(&mut data);


        let expected_start: [u8; 16] = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
            0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        ];

        assert_eq!(&data[..16], &expected_start);
    }
}
