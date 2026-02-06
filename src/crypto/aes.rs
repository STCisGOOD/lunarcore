#[inline(never)]
fn sbox_ct(input: u8) -> u8 {


    let x = input;
    let x2 = gf_square(x);
    let x4 = gf_square(x2);
    let x8 = gf_square(x4);
    let x16 = gf_square(x8);
    let x32 = gf_square(x16);
    let x64 = gf_square(x32);
    let x128 = gf_square(x64);


    let inv = gf_mul_ct(x2, x4);
    let inv = gf_mul_ct(inv, x8);
    let inv = gf_mul_ct(inv, x16);
    let inv = gf_mul_ct(inv, x32);
    let inv = gf_mul_ct(inv, x64);
    let inv = gf_mul_ct(inv, x128);


    affine_transform(inv)
}


#[inline(never)]
fn inv_sbox_ct(input: u8) -> u8 {

    let x = inv_affine_transform(input);


    let x2 = gf_square(x);
    let x4 = gf_square(x2);
    let x8 = gf_square(x4);
    let x16 = gf_square(x8);
    let x32 = gf_square(x16);
    let x64 = gf_square(x32);
    let x128 = gf_square(x64);

    let inv = gf_mul_ct(x2, x4);
    let inv = gf_mul_ct(inv, x8);
    let inv = gf_mul_ct(inv, x16);
    let inv = gf_mul_ct(inv, x32);
    let inv = gf_mul_ct(inv, x64);
    gf_mul_ct(inv, x128)
}


#[inline]
fn gf_square(x: u8) -> u8 {
    gf_mul_ct(x, x)
}


#[inline]
fn gf_mul_ct(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut aa = a;


    result ^= aa & (((b & 0x01) as i8).wrapping_neg() as u8);
    let mask = ((aa >> 7) as i8).wrapping_neg() as u8;
    aa = (aa << 1) ^ (0x1b & mask);


    result ^= aa & ((((b >> 1) & 0x01) as i8).wrapping_neg() as u8);
    let mask = ((aa >> 7) as i8).wrapping_neg() as u8;
    aa = (aa << 1) ^ (0x1b & mask);


    result ^= aa & ((((b >> 2) & 0x01) as i8).wrapping_neg() as u8);
    let mask = ((aa >> 7) as i8).wrapping_neg() as u8;
    aa = (aa << 1) ^ (0x1b & mask);


    result ^= aa & ((((b >> 3) & 0x01) as i8).wrapping_neg() as u8);
    let mask = ((aa >> 7) as i8).wrapping_neg() as u8;
    aa = (aa << 1) ^ (0x1b & mask);


    result ^= aa & ((((b >> 4) & 0x01) as i8).wrapping_neg() as u8);
    let mask = ((aa >> 7) as i8).wrapping_neg() as u8;
    aa = (aa << 1) ^ (0x1b & mask);


    result ^= aa & ((((b >> 5) & 0x01) as i8).wrapping_neg() as u8);
    let mask = ((aa >> 7) as i8).wrapping_neg() as u8;
    aa = (aa << 1) ^ (0x1b & mask);


    result ^= aa & ((((b >> 6) & 0x01) as i8).wrapping_neg() as u8);
    let mask = ((aa >> 7) as i8).wrapping_neg() as u8;
    aa = (aa << 1) ^ (0x1b & mask);


    result ^= aa & ((((b >> 7) & 0x01) as i8).wrapping_neg() as u8);

    result
}


#[inline]
fn affine_transform(x: u8) -> u8 {


    let mut result = 0u8;


    result |= (parity(x & 0b11110001) ^ 1) << 0;
    result |= (parity(x & 0b11100011) ^ 1) << 1;
    result |= (parity(x & 0b11000111) ^ 0) << 2;
    result |= (parity(x & 0b10001111) ^ 0) << 3;
    result |= (parity(x & 0b00011111) ^ 0) << 4;
    result |= (parity(x & 0b00111110) ^ 1) << 5;
    result |= (parity(x & 0b01111100) ^ 1) << 6;
    result |= (parity(x & 0b11111000) ^ 0) << 7;

    result
}


#[inline]
fn inv_affine_transform(x: u8) -> u8 {

    let y = x ^ 0x63;


    let mut result = 0u8;

    result |= parity(y & 0b10100100) << 0;
    result |= parity(y & 0b01001001) << 1;
    result |= parity(y & 0b10010010) << 2;
    result |= parity(y & 0b00100101) << 3;
    result |= parity(y & 0b01001010) << 4;
    result |= parity(y & 0b10010100) << 5;
    result |= parity(y & 0b00101001) << 6;
    result |= parity(y & 0b01010010) << 7;

    result
}


#[inline]
fn parity(mut x: u8) -> u8 {
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    x & 1
}


const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];


const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];


const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];


pub const BLOCK_SIZE: usize = 16;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesMode {

    Ecb,

    Ctr,

    Cbc,
}


pub struct Aes128 {

    round_keys: [u8; 176],
}


pub struct Aes256 {

    round_keys: [u8; 240],
}

impl Drop for Aes128 {
    fn drop(&mut self) {

        crate::crypto::secure_zero(&mut self.round_keys);
    }
}

impl Aes128 {

    pub fn new(key: &[u8; 16]) -> Self {
        let mut cipher = Self {
            round_keys: [0u8; 176],
        };
        cipher.key_expansion(key);
        cipher
    }


    fn key_expansion(&mut self, key: &[u8; 16]) {

        self.round_keys[..16].copy_from_slice(key);

        let mut i = 16;
        let mut rcon_idx = 1;

        while i < 176 {

            let mut temp = [
                self.round_keys[i - 4],
                self.round_keys[i - 3],
                self.round_keys[i - 2],
                self.round_keys[i - 1],
            ];

            if i % 16 == 0 {

                temp.rotate_left(1);

                for byte in &mut temp {
                    *byte = SBOX[*byte as usize];
                }

                temp[0] ^= RCON[rcon_idx];
                rcon_idx += 1;
            }


            for j in 0..4 {
                self.round_keys[i + j] = self.round_keys[i - 16 + j] ^ temp[j];
            }
            i += 4;
        }
    }


    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut state = *block;


        Self::add_round_key(&mut state, &self.round_keys[0..16]);


        for round in 1..10 {
            Self::sub_bytes(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round * 16..(round + 1) * 16]);
        }


        Self::sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[160..176]);

        *block = state;
    }


    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let mut state = *block;


        Self::add_round_key(&mut state, &self.round_keys[160..176]);


        for round in (1..10).rev() {
            Self::inv_shift_rows(&mut state);
            Self::inv_sub_bytes(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round * 16..(round + 1) * 16]);
            Self::inv_mix_columns(&mut state);
        }


        Self::inv_shift_rows(&mut state);
        Self::inv_sub_bytes(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[0..16]);

        *block = state;
    }


    pub fn encrypt_ctr(&self, nonce: &[u8; 16], data: &mut [u8]) {
        let mut counter = *nonce;
        let mut keystream = [0u8; 16];

        for (block_idx, chunk) in data.chunks_mut(16).enumerate() {

            keystream = counter;
            self.encrypt_block(&mut keystream);


            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }


            Self::increment_counter(&mut counter);
        }
    }


    pub fn decrypt_ctr(&self, nonce: &[u8; 16], data: &mut [u8]) {
        self.encrypt_ctr(nonce, data);
    }


    pub fn encrypt_cbc(&self, iv: &[u8; 16], data: &mut [u8]) {
        assert!(data.len() % 16 == 0, "Data must be multiple of block size");

        let mut prev = *iv;

        for chunk in data.chunks_mut(16) {

            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= prev[i];
            }


            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            self.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);


            prev.copy_from_slice(chunk);
        }
    }


    pub fn decrypt_cbc(&self, iv: &[u8; 16], data: &mut [u8]) {
        assert!(data.len() % 16 == 0, "Data must be multiple of block size");

        let mut prev = *iv;

        for chunk in data.chunks_mut(16) {

            let mut saved = [0u8; 16];
            saved.copy_from_slice(chunk);


            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            self.decrypt_block(&mut block);


            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= prev[i];
            }
            chunk.copy_from_slice(&block);


            prev = saved;
        }
    }


    #[inline]
    fn sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = SBOX[*byte as usize];
        }
    }


    #[inline]
    fn inv_sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = INV_SBOX[*byte as usize];
        }
    }


    #[inline]
    fn shift_rows(state: &mut [u8; 16]) {


        let temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;


        let temp0 = state[2];
        let temp1 = state[6];
        state[2] = state[10];
        state[6] = state[14];
        state[10] = temp0;
        state[14] = temp1;


        let temp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp;
    }


    #[inline]
    fn inv_shift_rows(state: &mut [u8; 16]) {


        let temp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp;


        let temp0 = state[2];
        let temp1 = state[6];
        state[2] = state[10];
        state[6] = state[14];
        state[10] = temp0;
        state[14] = temp1;


        let temp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = temp;
    }


    #[inline]
    fn mix_columns(state: &mut [u8; 16]) {
        for col in 0..4 {
            let i = col * 4;
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];

            state[i] = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3;
            state[i + 1] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3;
            state[i + 2] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3);
            state[i + 3] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2);
        }
    }


    #[inline]
    fn inv_mix_columns(state: &mut [u8; 16]) {
        for col in 0..4 {
            let i = col * 4;
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];

            state[i] = gf_mul(s0, 0x0e) ^ gf_mul(s1, 0x0b) ^ gf_mul(s2, 0x0d) ^ gf_mul(s3, 0x09);
            state[i + 1] = gf_mul(s0, 0x09) ^ gf_mul(s1, 0x0e) ^ gf_mul(s2, 0x0b) ^ gf_mul(s3, 0x0d);
            state[i + 2] = gf_mul(s0, 0x0d) ^ gf_mul(s1, 0x09) ^ gf_mul(s2, 0x0e) ^ gf_mul(s3, 0x0b);
            state[i + 3] = gf_mul(s0, 0x0b) ^ gf_mul(s1, 0x0d) ^ gf_mul(s2, 0x09) ^ gf_mul(s3, 0x0e);
        }
    }


    #[inline]
    fn add_round_key(state: &mut [u8; 16], round_key: &[u8]) {
        for (i, byte) in state.iter_mut().enumerate() {
            *byte ^= round_key[i];
        }
    }


    #[inline]
    fn increment_counter(counter: &mut [u8; 16]) {
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }
}

impl Drop for Aes256 {
    fn drop(&mut self) {

        crate::crypto::secure_zero(&mut self.round_keys);
    }
}

impl Aes256 {

    pub fn new(key: &[u8; 32]) -> Self {
        let mut cipher = Self {
            round_keys: [0u8; 240],
        };
        cipher.key_expansion(key);
        cipher
    }


    fn key_expansion(&mut self, key: &[u8; 32]) {

        self.round_keys[..32].copy_from_slice(key);

        let mut i = 32;
        let mut rcon_idx = 1;

        while i < 240 {
            let mut temp = [
                self.round_keys[i - 4],
                self.round_keys[i - 3],
                self.round_keys[i - 2],
                self.round_keys[i - 1],
            ];

            if i % 32 == 0 {

                temp.rotate_left(1);

                for byte in &mut temp {
                    *byte = SBOX[*byte as usize];
                }

                temp[0] ^= RCON[rcon_idx];
                rcon_idx += 1;
            } else if i % 32 == 16 {

                for byte in &mut temp {
                    *byte = SBOX[*byte as usize];
                }
            }

            for j in 0..4 {
                self.round_keys[i + j] = self.round_keys[i - 32 + j] ^ temp[j];
            }
            i += 4;
        }
    }


    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut state = *block;


        add_round_key_256(&mut state, &self.round_keys[0..16]);


        for round in 1..14 {
            sub_bytes_256(&mut state);
            shift_rows_256(&mut state);
            mix_columns_256(&mut state);
            add_round_key_256(&mut state, &self.round_keys[round * 16..(round + 1) * 16]);
        }


        sub_bytes_256(&mut state);
        shift_rows_256(&mut state);
        add_round_key_256(&mut state, &self.round_keys[224..240]);

        *block = state;
    }


    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let mut state = *block;

        add_round_key_256(&mut state, &self.round_keys[224..240]);

        for round in (1..14).rev() {
            inv_shift_rows_256(&mut state);
            inv_sub_bytes_256(&mut state);
            add_round_key_256(&mut state, &self.round_keys[round * 16..(round + 1) * 16]);
            inv_mix_columns_256(&mut state);
        }

        inv_shift_rows_256(&mut state);
        inv_sub_bytes_256(&mut state);
        add_round_key_256(&mut state, &self.round_keys[0..16]);

        *block = state;
    }


    pub fn encrypt_ctr(&self, nonce: &[u8; 16], data: &mut [u8]) {
        let mut counter = *nonce;
        let mut keystream = [0u8; 16];

        for chunk in data.chunks_mut(16) {
            keystream = counter;
            self.encrypt_block(&mut keystream);

            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }

            increment_counter_256(&mut counter);
        }
    }


    pub fn decrypt_ctr(&self, nonce: &[u8; 16], data: &mut [u8]) {
        self.encrypt_ctr(nonce, data);
    }
}


#[inline]
fn sub_bytes_256(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

#[inline]
fn inv_sub_bytes_256(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = INV_SBOX[*byte as usize];
    }
}

#[inline]
fn shift_rows_256(state: &mut [u8; 16]) {
    let temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    let temp0 = state[2];
    let temp1 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = temp0;
    state[14] = temp1;

    let temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

#[inline]
fn inv_shift_rows_256(state: &mut [u8; 16]) {
    let temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    let temp0 = state[2];
    let temp1 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = temp0;
    state[14] = temp1;

    let temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

#[inline]
fn mix_columns_256(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let s0 = state[i];
        let s1 = state[i + 1];
        let s2 = state[i + 2];
        let s3 = state[i + 3];

        state[i] = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2 ^ s3;
        state[i + 1] = s0 ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3;
        state[i + 2] = s0 ^ s1 ^ gf_mul(s2, 2) ^ gf_mul(s3, 3);
        state[i + 3] = gf_mul(s0, 3) ^ s1 ^ s2 ^ gf_mul(s3, 2);
    }
}

#[inline]
fn inv_mix_columns_256(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let s0 = state[i];
        let s1 = state[i + 1];
        let s2 = state[i + 2];
        let s3 = state[i + 3];

        state[i] = gf_mul(s0, 0x0e) ^ gf_mul(s1, 0x0b) ^ gf_mul(s2, 0x0d) ^ gf_mul(s3, 0x09);
        state[i + 1] = gf_mul(s0, 0x09) ^ gf_mul(s1, 0x0e) ^ gf_mul(s2, 0x0b) ^ gf_mul(s3, 0x0d);
        state[i + 2] = gf_mul(s0, 0x0d) ^ gf_mul(s1, 0x09) ^ gf_mul(s2, 0x0e) ^ gf_mul(s3, 0x0b);
        state[i + 3] = gf_mul(s0, 0x0b) ^ gf_mul(s1, 0x0d) ^ gf_mul(s2, 0x09) ^ gf_mul(s3, 0x0e);
    }
}

#[inline]
fn add_round_key_256(state: &mut [u8; 16], round_key: &[u8]) {
    for (i, byte) in state.iter_mut().enumerate() {
        *byte ^= round_key[i];
    }
}

#[inline]
fn increment_counter_256(counter: &mut [u8; 16]) {
    for i in (0..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}


#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}


pub struct Aes128Ct {

    round_keys: [u8; 176],
}

impl Drop for Aes128Ct {
    fn drop(&mut self) {

        crate::crypto::secure_zero(&mut self.round_keys);
    }
}

impl Aes128Ct {

    pub fn new(key: &[u8; 16]) -> Self {
        let mut cipher = Self {
            round_keys: [0u8; 176],
        };
        cipher.key_expansion(key);
        cipher
    }


    fn key_expansion(&mut self, key: &[u8; 16]) {
        self.round_keys[..16].copy_from_slice(key);

        let mut i = 16;
        let mut rcon_idx = 1;

        while i < 176 {
            let mut temp = [
                self.round_keys[i - 4],
                self.round_keys[i - 3],
                self.round_keys[i - 2],
                self.round_keys[i - 1],
            ];

            if i % 16 == 0 {
                temp.rotate_left(1);

                for byte in &mut temp {
                    *byte = sbox_ct(*byte);
                }
                temp[0] ^= RCON[rcon_idx];
                rcon_idx += 1;
            }

            for j in 0..4 {
                self.round_keys[i + j] = self.round_keys[i - 16 + j] ^ temp[j];
            }
            i += 4;
        }
    }


    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut state = *block;

        Self::add_round_key(&mut state, &self.round_keys[0..16]);

        for round in 1..10 {
            Self::sub_bytes_ct(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round * 16..(round + 1) * 16]);
        }

        Self::sub_bytes_ct(&mut state);
        Self::shift_rows(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[160..176]);

        *block = state;
    }


    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let mut state = *block;

        Self::add_round_key(&mut state, &self.round_keys[160..176]);

        for round in (1..10).rev() {
            Self::inv_shift_rows(&mut state);
            Self::inv_sub_bytes_ct(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round * 16..(round + 1) * 16]);
            Self::inv_mix_columns(&mut state);
        }

        Self::inv_shift_rows(&mut state);
        Self::inv_sub_bytes_ct(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[0..16]);

        *block = state;
    }


    pub fn encrypt_ctr(&self, nonce: &[u8; 16], data: &mut [u8]) {
        let mut counter = *nonce;
        let mut keystream = [0u8; 16];

        for chunk in data.chunks_mut(16) {
            keystream = counter;
            self.encrypt_block(&mut keystream);

            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }

            Self::increment_counter(&mut counter);
        }
    }


    pub fn decrypt_ctr(&self, nonce: &[u8; 16], data: &mut [u8]) {
        self.encrypt_ctr(nonce, data);
    }


    #[inline]
    fn sub_bytes_ct(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = sbox_ct(*byte);
        }
    }

    #[inline]
    fn inv_sub_bytes_ct(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = inv_sbox_ct(*byte);
        }
    }

    #[inline]
    fn shift_rows(state: &mut [u8; 16]) {
        let temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;

        let temp0 = state[2];
        let temp1 = state[6];
        state[2] = state[10];
        state[6] = state[14];
        state[10] = temp0;
        state[14] = temp1;

        let temp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp;
    }

    #[inline]
    fn inv_shift_rows(state: &mut [u8; 16]) {
        let temp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp;

        let temp0 = state[2];
        let temp1 = state[6];
        state[2] = state[10];
        state[6] = state[14];
        state[10] = temp0;
        state[14] = temp1;

        let temp = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = temp;
    }

    #[inline]
    fn mix_columns(state: &mut [u8; 16]) {
        for col in 0..4 {
            let i = col * 4;
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];

            state[i] = gf_mul_ct(s0, 2) ^ gf_mul_ct(s1, 3) ^ s2 ^ s3;
            state[i + 1] = s0 ^ gf_mul_ct(s1, 2) ^ gf_mul_ct(s2, 3) ^ s3;
            state[i + 2] = s0 ^ s1 ^ gf_mul_ct(s2, 2) ^ gf_mul_ct(s3, 3);
            state[i + 3] = gf_mul_ct(s0, 3) ^ s1 ^ s2 ^ gf_mul_ct(s3, 2);
        }
    }

    #[inline]
    fn inv_mix_columns(state: &mut [u8; 16]) {
        for col in 0..4 {
            let i = col * 4;
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];

            state[i] = gf_mul_ct(s0, 0x0e) ^ gf_mul_ct(s1, 0x0b) ^ gf_mul_ct(s2, 0x0d) ^ gf_mul_ct(s3, 0x09);
            state[i + 1] = gf_mul_ct(s0, 0x09) ^ gf_mul_ct(s1, 0x0e) ^ gf_mul_ct(s2, 0x0b) ^ gf_mul_ct(s3, 0x0d);
            state[i + 2] = gf_mul_ct(s0, 0x0d) ^ gf_mul_ct(s1, 0x09) ^ gf_mul_ct(s2, 0x0e) ^ gf_mul_ct(s3, 0x0b);
            state[i + 3] = gf_mul_ct(s0, 0x0b) ^ gf_mul_ct(s1, 0x0d) ^ gf_mul_ct(s2, 0x09) ^ gf_mul_ct(s3, 0x0e);
        }
    }

    #[inline]
    fn add_round_key(state: &mut [u8; 16], round_key: &[u8]) {
        for (i, byte) in state.iter_mut().enumerate() {
            *byte ^= round_key[i];
        }
    }

    #[inline]
    fn increment_counter(counter: &mut [u8; 16]) {
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_ct_correctness() {

        for i in 0..=255u8 {
            let expected = SBOX[i as usize];
            let computed = sbox_ct(i);
            assert_eq!(computed, expected, "S-box mismatch at input {:#04x}: expected {:#04x}, got {:#04x}", i, expected, computed);
        }
    }

    #[test]
    fn test_inv_sbox_ct_correctness() {

        for i in 0..=255u8 {
            let expected = INV_SBOX[i as usize];
            let computed = inv_sbox_ct(i);
            assert_eq!(computed, expected, "Inv S-box mismatch at input {:#04x}: expected {:#04x}, got {:#04x}", i, expected, computed);
        }
    }

    #[test]
    fn test_sbox_inv_sbox_roundtrip() {

        for i in 0..=255u8 {
            assert_eq!(inv_sbox_ct(sbox_ct(i)), i);
            assert_eq!(sbox_ct(inv_sbox_ct(i)), i);
        }
    }

    #[test]
    fn test_gf_mul_ct_correctness() {

        assert_eq!(gf_mul_ct(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul_ct(0x02, 0x87), 0x15);
        assert_eq!(gf_mul_ct(0, 0x42), 0);
        assert_eq!(gf_mul_ct(0x42, 0), 0);
        assert_eq!(gf_mul_ct(1, 0x42), 0x42);
        assert_eq!(gf_mul_ct(0x42, 1), 0x42);
    }

    #[test]
    fn test_aes128_known_vector() {

        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];

        let cipher = Aes128::new(&key);
        let mut block = plaintext;
        cipher.encrypt_block(&mut block);

        assert_eq!(block, expected);


        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }

    #[test]
    fn test_aes128ct_known_vector() {

        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];

        let cipher = Aes128Ct::new(&key);
        let mut block = plaintext;
        cipher.encrypt_block(&mut block);

        assert_eq!(block, expected);

        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }

    #[test]
    fn test_aes128_vs_aes128ct() {

        let key: [u8; 16] = [0x42; 16];
        let plaintext: [u8; 16] = [0x24; 16];

        let cipher = Aes128::new(&key);
        let cipher_ct = Aes128Ct::new(&key);

        let mut block1 = plaintext;
        let mut block2 = plaintext;

        cipher.encrypt_block(&mut block1);
        cipher_ct.encrypt_block(&mut block2);

        assert_eq!(block1, block2);

        cipher.decrypt_block(&mut block1);
        cipher_ct.decrypt_block(&mut block2);

        assert_eq!(block1, block2);
        assert_eq!(block1, plaintext);
    }

    #[test]
    fn test_aes256_known_vector() {

        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];

        let cipher = Aes256::new(&key);
        let mut block = plaintext;
        cipher.encrypt_block(&mut block);

        assert_eq!(block, expected);

        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }

    #[test]
    fn test_ctr_mode() {
        let key: [u8; 16] = [0x2b; 16];
        let nonce: [u8; 16] = [0x00; 16];
        let plaintext = b"Hello, World! This is a test message.";

        let cipher = Aes128::new(&key);

        let mut data = [0u8; 64];
        data[..plaintext.len()].copy_from_slice(plaintext);
        let len = plaintext.len();


        cipher.encrypt_ctr(&nonce, &mut data[..len]);


        assert_ne!(&data[..len], plaintext);


        cipher.decrypt_ctr(&nonce, &mut data[..len]);


        assert_eq!(&data[..len], plaintext);
    }

    #[test]
    fn test_ctr_mode_ct() {

        let key: [u8; 16] = [0x2b; 16];
        let nonce: [u8; 16] = [0x00; 16];
        let plaintext = b"Hello, World! This is a test message.";

        let cipher = Aes128Ct::new(&key);

        let mut data = [0u8; 64];
        data[..plaintext.len()].copy_from_slice(plaintext);
        let len = plaintext.len();

        cipher.encrypt_ctr(&nonce, &mut data[..len]);
        assert_ne!(&data[..len], plaintext);

        cipher.decrypt_ctr(&nonce, &mut data[..len]);
        assert_eq!(&data[..len], plaintext);
    }

    #[test]
    fn test_gf_mul() {

        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul(0x02, 0x87), 0x15);
    }
}
