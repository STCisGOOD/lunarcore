#[derive(Clone, Copy)]
struct Fe([i64; 10]);


const P: [i64; 10] = [
    0x3ffffed, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff,
    0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff,
];

impl Fe {

    const fn zero() -> Self {
        Fe([0; 10])
    }


    const fn one() -> Self {
        Fe([1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }


    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut h = [0i64; 10];

        h[0] = load_4(&bytes[0..4]) & 0x3ffffff;
        h[1] = (load_4(&bytes[3..7]) >> 2) & 0x1ffffff;
        h[2] = (load_4(&bytes[6..10]) >> 3) & 0x3ffffff;
        h[3] = (load_4(&bytes[9..13]) >> 5) & 0x1ffffff;
        h[4] = (load_4(&bytes[12..16]) >> 6) & 0x3ffffff;
        h[5] = (load_4(&bytes[16..20])) & 0x1ffffff;
        h[6] = (load_4(&bytes[19..23]) >> 1) & 0x3ffffff;
        h[7] = (load_4(&bytes[22..26]) >> 3) & 0x1ffffff;
        h[8] = (load_4(&bytes[25..29]) >> 4) & 0x3ffffff;
        h[9] = (load_3(&bytes[28..31]) >> 6) & 0x1ffffff;

        Fe(h)
    }


    fn to_bytes(&self) -> [u8; 32] {
        let mut h = self.0;


        let mut q = (19 * h[9] + (1 << 24)) >> 25;
        q = (h[0] + q) >> 26;
        q = (h[1] + q) >> 25;
        q = (h[2] + q) >> 26;
        q = (h[3] + q) >> 25;
        q = (h[4] + q) >> 26;
        q = (h[5] + q) >> 25;
        q = (h[6] + q) >> 26;
        q = (h[7] + q) >> 25;
        q = (h[8] + q) >> 26;
        q = (h[9] + q) >> 25;

        h[0] += 19 * q;

        let carry0 = h[0] >> 26;
        h[1] += carry0;
        h[0] -= carry0 << 26;
        let carry1 = h[1] >> 25;
        h[2] += carry1;
        h[1] -= carry1 << 25;
        let carry2 = h[2] >> 26;
        h[3] += carry2;
        h[2] -= carry2 << 26;
        let carry3 = h[3] >> 25;
        h[4] += carry3;
        h[3] -= carry3 << 25;
        let carry4 = h[4] >> 26;
        h[5] += carry4;
        h[4] -= carry4 << 26;
        let carry5 = h[5] >> 25;
        h[6] += carry5;
        h[5] -= carry5 << 25;
        let carry6 = h[6] >> 26;
        h[7] += carry6;
        h[6] -= carry6 << 26;
        let carry7 = h[7] >> 25;
        h[8] += carry7;
        h[7] -= carry7 << 25;
        let carry8 = h[8] >> 26;
        h[9] += carry8;
        h[8] -= carry8 << 26;
        let carry9 = h[9] >> 25;
        h[9] -= carry9 << 25;

        let mut s = [0u8; 32];
        s[0] = h[0] as u8;
        s[1] = (h[0] >> 8) as u8;
        s[2] = (h[0] >> 16) as u8;
        s[3] = ((h[0] >> 24) | (h[1] << 2)) as u8;
        s[4] = (h[1] >> 6) as u8;
        s[5] = (h[1] >> 14) as u8;
        s[6] = ((h[1] >> 22) | (h[2] << 3)) as u8;
        s[7] = (h[2] >> 5) as u8;
        s[8] = (h[2] >> 13) as u8;
        s[9] = ((h[2] >> 21) | (h[3] << 5)) as u8;
        s[10] = (h[3] >> 3) as u8;
        s[11] = (h[3] >> 11) as u8;
        s[12] = ((h[3] >> 19) | (h[4] << 6)) as u8;
        s[13] = (h[4] >> 2) as u8;
        s[14] = (h[4] >> 10) as u8;
        s[15] = (h[4] >> 18) as u8;
        s[16] = h[5] as u8;
        s[17] = (h[5] >> 8) as u8;
        s[18] = (h[5] >> 16) as u8;
        s[19] = ((h[5] >> 24) | (h[6] << 1)) as u8;
        s[20] = (h[6] >> 7) as u8;
        s[21] = (h[6] >> 15) as u8;
        s[22] = ((h[6] >> 23) | (h[7] << 3)) as u8;
        s[23] = (h[7] >> 5) as u8;
        s[24] = (h[7] >> 13) as u8;
        s[25] = ((h[7] >> 21) | (h[8] << 4)) as u8;
        s[26] = (h[8] >> 4) as u8;
        s[27] = (h[8] >> 12) as u8;
        s[28] = ((h[8] >> 20) | (h[9] << 6)) as u8;
        s[29] = (h[9] >> 2) as u8;
        s[30] = (h[9] >> 10) as u8;
        s[31] = (h[9] >> 18) as u8;

        s
    }


    fn add(&self, rhs: &Fe) -> Fe {
        Fe([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
            self.0[5] + rhs.0[5],
            self.0[6] + rhs.0[6],
            self.0[7] + rhs.0[7],
            self.0[8] + rhs.0[8],
            self.0[9] + rhs.0[9],
        ])
    }


    fn sub(&self, rhs: &Fe) -> Fe {
        Fe([
            self.0[0] - rhs.0[0],
            self.0[1] - rhs.0[1],
            self.0[2] - rhs.0[2],
            self.0[3] - rhs.0[3],
            self.0[4] - rhs.0[4],
            self.0[5] - rhs.0[5],
            self.0[6] - rhs.0[6],
            self.0[7] - rhs.0[7],
            self.0[8] - rhs.0[8],
            self.0[9] - rhs.0[9],
        ])
    }


    fn mul(&self, rhs: &Fe) -> Fe {
        let f = &self.0;
        let g = &rhs.0;

        let f0 = f[0] as i128;
        let f1 = f[1] as i128;
        let f2 = f[2] as i128;
        let f3 = f[3] as i128;
        let f4 = f[4] as i128;
        let f5 = f[5] as i128;
        let f6 = f[6] as i128;
        let f7 = f[7] as i128;
        let f8 = f[8] as i128;
        let f9 = f[9] as i128;

        let g0 = g[0] as i128;
        let g1 = g[1] as i128;
        let g2 = g[2] as i128;
        let g3 = g[3] as i128;
        let g4 = g[4] as i128;
        let g5 = g[5] as i128;
        let g6 = g[6] as i128;
        let g7 = g[7] as i128;
        let g8 = g[8] as i128;
        let g9 = g[9] as i128;

        let g1_19 = 19 * g1;
        let g2_19 = 19 * g2;
        let g3_19 = 19 * g3;
        let g4_19 = 19 * g4;
        let g5_19 = 19 * g5;
        let g6_19 = 19 * g6;
        let g7_19 = 19 * g7;
        let g8_19 = 19 * g8;
        let g9_19 = 19 * g9;

        let f1_2 = 2 * f1;
        let f3_2 = 2 * f3;
        let f5_2 = 2 * f5;
        let f7_2 = 2 * f7;
        let f9_2 = 2 * f9;

        let h0 = f0 * g0 + f1_2 * g9_19 + f2 * g8_19 + f3_2 * g7_19 + f4 * g6_19 + f5_2 * g5_19 + f6 * g4_19 + f7_2 * g3_19 + f8 * g2_19 + f9_2 * g1_19;
        let h1 = f0 * g1 + f1 * g0 + f2 * g9_19 + f3 * g8_19 + f4 * g7_19 + f5 * g6_19 + f6 * g5_19 + f7 * g4_19 + f8 * g3_19 + f9 * g2_19;
        let h2 = f0 * g2 + f1_2 * g1 + f2 * g0 + f3_2 * g9_19 + f4 * g8_19 + f5_2 * g7_19 + f6 * g6_19 + f7_2 * g5_19 + f8 * g4_19 + f9_2 * g3_19;
        let h3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + f4 * g9_19 + f5 * g8_19 + f6 * g7_19 + f7 * g6_19 + f8 * g5_19 + f9 * g4_19;
        let h4 = f0 * g4 + f1_2 * g3 + f2 * g2 + f3_2 * g1 + f4 * g0 + f5_2 * g9_19 + f6 * g8_19 + f7_2 * g7_19 + f8 * g6_19 + f9_2 * g5_19;
        let h5 = f0 * g5 + f1 * g4 + f2 * g3 + f3 * g2 + f4 * g1 + f5 * g0 + f6 * g9_19 + f7 * g8_19 + f8 * g7_19 + f9 * g6_19;
        let h6 = f0 * g6 + f1_2 * g5 + f2 * g4 + f3_2 * g3 + f4 * g2 + f5_2 * g1 + f6 * g0 + f7_2 * g9_19 + f8 * g8_19 + f9_2 * g7_19;
        let h7 = f0 * g7 + f1 * g6 + f2 * g5 + f3 * g4 + f4 * g3 + f5 * g2 + f6 * g1 + f7 * g0 + f8 * g9_19 + f9 * g8_19;
        let h8 = f0 * g8 + f1_2 * g7 + f2 * g6 + f3_2 * g5 + f4 * g4 + f5_2 * g3 + f6 * g2 + f7_2 * g1 + f8 * g0 + f9_2 * g9_19;
        let h9 = f0 * g9 + f1 * g8 + f2 * g7 + f3 * g6 + f4 * g5 + f5 * g4 + f6 * g3 + f7 * g2 + f8 * g1 + f9 * g0;

        carry_mul([h0, h1, h2, h3, h4, h5, h6, h7, h8, h9])
    }


    fn square(&self) -> Fe {
        self.mul(self)
    }


    fn mul121666(&self) -> Fe {
        let mut h = [0i128; 10];
        for i in 0..10 {
            h[i] = (self.0[i] as i128) * 121666;
        }
        carry_mul(h)
    }


    fn invert(&self) -> Fe {
        let mut t0 = self.square();
        let mut t1 = t0.square();
        t1 = t1.square();
        t1 = self.mul(&t1);
        t0 = t0.mul(&t1);
        let mut t2 = t0.square();
        t1 = t1.mul(&t2);
        t2 = t1.square();
        for _ in 1..5 {
            t2 = t2.square();
        }
        t1 = t2.mul(&t1);
        t2 = t1.square();
        for _ in 1..10 {
            t2 = t2.square();
        }
        t2 = t2.mul(&t1);
        let mut t3 = t2.square();
        for _ in 1..20 {
            t3 = t3.square();
        }
        t2 = t3.mul(&t2);
        t2 = t2.square();
        for _ in 1..10 {
            t2 = t2.square();
        }
        t1 = t2.mul(&t1);
        t2 = t1.square();
        for _ in 1..50 {
            t2 = t2.square();
        }
        t2 = t2.mul(&t1);
        t3 = t2.square();
        for _ in 1..100 {
            t3 = t3.square();
        }
        t2 = t3.mul(&t2);
        t2 = t2.square();
        for _ in 1..50 {
            t2 = t2.square();
        }
        t1 = t2.mul(&t1);
        t1 = t1.square();
        t1 = t1.square();
        t1 = t1.square();
        t1 = t1.square();
        t1 = t1.square();
        t0.mul(&t1)
    }


    fn cswap(a: &mut Fe, b: &mut Fe, swap: i64) {
        let swap = -swap;
        for i in 0..10 {
            let x = swap & (a.0[i] ^ b.0[i]);
            a.0[i] ^= x;
            b.0[i] ^= x;
        }
    }
}


fn load_4(s: &[u8]) -> i64 {
    (s[0] as i64)
        | ((s[1] as i64) << 8)
        | ((s[2] as i64) << 16)
        | ((s[3] as i64) << 24)
}


fn load_3(s: &[u8]) -> i64 {
    (s[0] as i64) | ((s[1] as i64) << 8) | ((s[2] as i64) << 16)
}


fn carry_mul(h: [i128; 10]) -> Fe {
    let mut out = [0i64; 10];

    let mut carry = (h[0] + (1 << 25)) >> 26;
    out[0] = (h[0] - (carry << 26)) as i64;
    let h1 = h[1] + carry;

    carry = (h1 + (1 << 24)) >> 25;
    out[1] = (h1 - (carry << 25)) as i64;
    let h2 = h[2] + carry;

    carry = (h2 + (1 << 25)) >> 26;
    out[2] = (h2 - (carry << 26)) as i64;
    let h3 = h[3] + carry;

    carry = (h3 + (1 << 24)) >> 25;
    out[3] = (h3 - (carry << 25)) as i64;
    let h4 = h[4] + carry;

    carry = (h4 + (1 << 25)) >> 26;
    out[4] = (h4 - (carry << 26)) as i64;
    let h5 = h[5] + carry;

    carry = (h5 + (1 << 24)) >> 25;
    out[5] = (h5 - (carry << 25)) as i64;
    let h6 = h[6] + carry;

    carry = (h6 + (1 << 25)) >> 26;
    out[6] = (h6 - (carry << 26)) as i64;
    let h7 = h[7] + carry;

    carry = (h7 + (1 << 24)) >> 25;
    out[7] = (h7 - (carry << 25)) as i64;
    let h8 = h[8] + carry;

    carry = (h8 + (1 << 25)) >> 26;
    out[8] = (h8 - (carry << 26)) as i64;
    let h9 = h[9] + carry;

    carry = (h9 + (1 << 24)) >> 25;
    out[9] = (h9 - (carry << 25)) as i64;
    out[0] += (carry * 19) as i64;

    carry = (out[0] as i128 + (1 << 25)) >> 26;
    out[0] -= (carry << 26) as i64;
    out[1] += carry as i64;

    Fe(out)
}


pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {

    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;


    let u = Fe::from_bytes(point);


    let mut x_1 = u;
    let mut x_2 = Fe::one();
    let mut z_2 = Fe::zero();
    let mut x_3 = u;
    let mut z_3 = Fe::one();

    let mut swap: i64 = 0;

    for pos in (0..255).rev() {
        let bit = ((k[pos / 8] >> (pos & 7)) & 1) as i64;
        swap ^= bit;
        Fe::cswap(&mut x_2, &mut x_3, swap);
        Fe::cswap(&mut z_2, &mut z_3, swap);
        swap = bit;

        let a = x_2.add(&z_2);
        let aa = a.square();
        let b = x_2.sub(&z_2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x_3.add(&z_3);
        let d = x_3.sub(&z_3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        let sum = da.add(&cb);
        let diff = da.sub(&cb);
        x_3 = sum.square();
        z_3 = x_1.mul(&diff.square());
        x_2 = aa.mul(&bb);
        z_2 = e.mul(&aa.add(&e.mul121666()));
    }

    Fe::cswap(&mut x_2, &mut x_3, swap);
    Fe::cswap(&mut z_2, &mut z_3, swap);


    let result = x_2.mul(&z_2.invert());
    result.to_bytes()
}


pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {

    let basepoint: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    x25519(scalar, &basepoint)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc7748_vector1() {

        let scalar: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
            0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
            0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
            0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
        ];
        let u: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
            0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
            0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
            0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
            0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
            0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
            0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
        ];

        let result = x25519(&scalar, &u);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_rfc7748_vector2() {
        let scalar: [u8; 32] = [
            0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c,
            0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d, 0x6a, 0xf5,
            0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4,
            0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d,
        ];
        let u: [u8; 32] = [
            0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3,
            0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38, 0xae, 0x2c,
            0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e,
            0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93,
        ];
        let expected: [u8; 32] = [
            0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d,
            0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8, 0x73, 0xf8,
            0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52,
            0xe6, 0xf8, 0xf7, 0x64, 0x7a, 0xac, 0x79, 0x57,
        ];

        let result = x25519(&scalar, &u);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_basepoint() {

        let scalar: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let expected: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
            0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
            0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
            0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
        ];

        let result = x25519_base(&scalar);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_key_exchange() {

        let alice_private: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_private: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];

        let alice_public = x25519_base(&alice_private);
        let bob_public = x25519_base(&bob_private);

        let alice_shared = x25519(&alice_private, &bob_public);
        let bob_shared = x25519(&bob_private, &alice_public);

        assert_eq!(alice_shared, bob_shared);
    }
}
