pub const TAG_SIZE: usize = 16;


pub const KEY_SIZE: usize = 32;


pub struct Poly1305 {

    r: [u32; 5],

    s: [u32; 4],

    h: [u32; 5],

    buffer: [u8; 16],

    buffer_len: usize,
}

impl Poly1305 {

    pub fn new(key: &[u8; KEY_SIZE]) -> Self {

        let r0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x0fff_fffc;
        let r1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]) & 0x0fff_fffc;
        let r2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]) & 0x0fff_fffc;
        let r3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]) & 0x0fff_fffc;


        let r = [
            r0 & 0x03ff_ffff,
            ((r0 >> 26) | (r1 << 6)) & 0x03ff_ffff,
            ((r1 >> 20) | (r2 << 12)) & 0x03ff_ffff,
            ((r2 >> 14) | (r3 << 18)) & 0x03ff_ffff,
            r3 >> 8,
        ];


        let s = [
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];

        Self {
            r,
            s,
            h: [0; 5],
            buffer: [0; 16],
            buffer_len: 0,
        }
    }


    fn process_block(&mut self, block: &[u8], final_block: bool) {

        let t0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let t1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let t2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        let t3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);

        let hibit = if final_block { 0 } else { 1 << 24 };


        self.h[0] += t0 & 0x03ff_ffff;
        self.h[1] += ((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff;
        self.h[2] += ((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff;
        self.h[3] += ((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff;
        self.h[4] += (t3 >> 8) | hibit;


        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let h0 = self.h[0] as u64;
        let h1 = self.h[1] as u64;
        let h2 = self.h[2] as u64;
        let h3 = self.h[3] as u64;
        let h4 = self.h[4] as u64;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;


        let mut c: u64;
        c = d0 >> 26;
        self.h[0] = (d0 & 0x03ff_ffff) as u32;
        let d1 = d1 + c;
        c = d1 >> 26;
        self.h[1] = (d1 & 0x03ff_ffff) as u32;
        let d2 = d2 + c;
        c = d2 >> 26;
        self.h[2] = (d2 & 0x03ff_ffff) as u32;
        let d3 = d3 + c;
        c = d3 >> 26;
        self.h[3] = (d3 & 0x03ff_ffff) as u32;
        let d4 = d4 + c;
        c = d4 >> 26;
        self.h[4] = (d4 & 0x03ff_ffff) as u32;
        self.h[0] += (c * 5) as u32;
        c = (self.h[0] >> 26) as u64;
        self.h[0] &= 0x03ff_ffff;
        self.h[1] += c as u32;
    }


    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;


        if self.buffer_len > 0 {
            let needed = 16 - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..].copy_from_slice(&data[..needed]);
                let block = self.buffer;
                self.process_block(&block, false);
                self.buffer_len = 0;
                offset = needed;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }


        while offset + 16 <= data.len() {
            self.process_block(&data[offset..offset + 16], false);
            offset += 16;
        }


        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }


    pub fn finalize(mut self) -> [u8; TAG_SIZE] {

        if self.buffer_len > 0 {

            self.buffer[self.buffer_len] = 1;
            for i in self.buffer_len + 1..16 {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            self.process_block(&block, true);
        }


        let mut c: u32;
        c = self.h[1] >> 26;
        self.h[1] &= 0x03ff_ffff;
        self.h[2] += c;
        c = self.h[2] >> 26;
        self.h[2] &= 0x03ff_ffff;
        self.h[3] += c;
        c = self.h[3] >> 26;
        self.h[3] &= 0x03ff_ffff;
        self.h[4] += c;
        c = self.h[4] >> 26;
        self.h[4] &= 0x03ff_ffff;
        self.h[0] += c * 5;
        c = self.h[0] >> 26;
        self.h[0] &= 0x03ff_ffff;
        self.h[1] += c;


        let mut g0 = self.h[0].wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x03ff_ffff;
        let mut g1 = self.h[1].wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x03ff_ffff;
        let mut g2 = self.h[2].wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x03ff_ffff;
        let mut g3 = self.h[3].wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x03ff_ffff;
        let g4 = self.h[4].wrapping_add(c).wrapping_sub(1 << 26);


        let mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let mask = !mask;
        self.h[0] = (self.h[0] & mask) | g0;
        self.h[1] = (self.h[1] & mask) | g1;
        self.h[2] = (self.h[2] & mask) | g2;
        self.h[3] = (self.h[3] & mask) | g3;


        let h0 = self.h[0] | (self.h[1] << 26);
        let h1 = (self.h[1] >> 6) | (self.h[2] << 20);
        let h2 = (self.h[2] >> 12) | (self.h[3] << 14);
        let h3 = (self.h[3] >> 18) | (self.h[4] << 8);


        let mut f: u64;
        f = h0 as u64 + self.s[0] as u64;
        let t0 = f as u32;
        f = h1 as u64 + self.s[1] as u64 + (f >> 32);
        let t1 = f as u32;
        f = h2 as u64 + self.s[2] as u64 + (f >> 32);
        let t2 = f as u32;
        f = h3 as u64 + self.s[3] as u64 + (f >> 32);
        let t3 = f as u32;


        let mut tag = [0u8; TAG_SIZE];
        tag[0..4].copy_from_slice(&t0.to_le_bytes());
        tag[4..8].copy_from_slice(&t1.to_le_bytes());
        tag[8..12].copy_from_slice(&t2.to_le_bytes());
        tag[12..16].copy_from_slice(&t3.to_le_bytes());

        tag
    }


    pub fn mac(key: &[u8; KEY_SIZE], data: &[u8]) -> [u8; TAG_SIZE] {
        let mut poly = Self::new(key);
        poly.update(data);
        poly.finalize()
    }


    pub fn verify(key: &[u8; KEY_SIZE], data: &[u8], expected: &[u8; TAG_SIZE]) -> bool {
        let computed = Self::mac(key, data);
        super::constant_time_eq(&computed, expected)
    }
}


pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {

    pub fn seal(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) {
        assert!(ciphertext.len() >= plaintext.len());


        let mut poly_key = [0u8; 32];
        let chacha = super::chacha20::ChaCha20::new(key, nonce);
        let keystream = chacha.keystream(32);
        poly_key.copy_from_slice(&keystream[..32]);


        ciphertext[..plaintext.len()].copy_from_slice(plaintext);
        let chacha = super::chacha20::ChaCha20::new_with_counter(key, nonce, 1);
        chacha.encrypt(&mut ciphertext[..plaintext.len()]);


        let mut poly = Poly1305::new(&poly_key);


        poly.update(aad);

        let aad_pad = (16 - (aad.len() % 16)) % 16;
        if aad_pad > 0 {
            poly.update(&[0u8; 16][..aad_pad]);
        }


        poly.update(&ciphertext[..plaintext.len()]);

        let ct_pad = (16 - (plaintext.len() % 16)) % 16;
        if ct_pad > 0 {
            poly.update(&[0u8; 16][..ct_pad]);
        }


        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(plaintext.len() as u64).to_le_bytes());

        *tag = poly.finalize();
    }


    pub fn open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
        plaintext: &mut [u8],
    ) -> bool {
        assert!(plaintext.len() >= ciphertext.len());


        let mut poly_key = [0u8; 32];
        let chacha = super::chacha20::ChaCha20::new(key, nonce);
        let keystream = chacha.keystream(32);
        poly_key.copy_from_slice(&keystream[..32]);


        let mut poly = Poly1305::new(&poly_key);


        poly.update(aad);
        let aad_pad = (16 - (aad.len() % 16)) % 16;
        if aad_pad > 0 {
            poly.update(&[0u8; 16][..aad_pad]);
        }


        poly.update(ciphertext);
        let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
        if ct_pad > 0 {
            poly.update(&[0u8; 16][..ct_pad]);
        }


        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(ciphertext.len() as u64).to_le_bytes());

        let computed_tag = poly.finalize();
        if !super::constant_time_eq(&computed_tag, tag) {
            return false;
        }


        plaintext[..ciphertext.len()].copy_from_slice(ciphertext);
        let chacha = super::chacha20::ChaCha20::new_with_counter(key, nonce, 1);
        chacha.decrypt(&mut plaintext[..ciphertext.len()]);

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc8439_poly1305() {

        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];

        let msg = b"Cryptographic Forum Research Group";

        let tag = Poly1305::mac(&key, msg);

        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ];

        assert_eq!(tag, expected);
    }

    #[test]
    fn test_chacha20_poly1305_aead() {

        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];

        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47,
        ];

        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7,
        ];

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let mut ciphertext = [0u8; 114];
        let mut tag = [0u8; 16];

        ChaCha20Poly1305::seal(&key, &nonce, &aad, plaintext, &mut ciphertext, &mut tag);


        let mut decrypted = [0u8; 114];
        assert!(ChaCha20Poly1305::open(&key, &nonce, &aad, &ciphertext, &tag, &mut decrypted));
        assert_eq!(&decrypted[..], &plaintext[..]);


        ciphertext[0] ^= 1;
        assert!(!ChaCha20Poly1305::open(&key, &nonce, &aad, &ciphertext, &tag, &mut decrypted));
    }
}
