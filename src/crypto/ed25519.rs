use super::sha256::Sha256;

pub struct Signature(pub [u8; 64]);

pub type PublicKey = [u8; 32];

pub type PrivateKey = [u8; 32];

#[derive(Clone, Copy)]
struct Fe([i64; 10]);

#[derive(Clone, Copy)]
struct ExtendedPoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

#[derive(Clone, Copy)]
struct PrecomputedPoint {
    y_plus_x: Fe,
    y_minus_x: Fe,
    xy2d: Fe,
}

#[derive(Clone, Copy)]
struct Scalar([u8; 32]);

const BASE_Y: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

const D: Fe = Fe([
    -10913610, 13857413, -15372611, 6949391, 114729,
    -8787816, -6275908, -3247719, -18696448, -12055116,
]);

const D2: Fe = Fe([
    -21827239, -5839606, -30745221, 13898782, 229458,
    15978800, -12551817, -6495438, 29715968, 9444199,
]);

const SQRT_M1: Fe = Fe([
    -32595792, -7943725, 9377950, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482,
]);

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
        h[5] = load_4(&bytes[16..20]) & 0x1ffffff;
        h[6] = (load_4(&bytes[19..23]) >> 1) & 0x3ffffff;
        h[7] = (load_4(&bytes[22..26]) >> 3) & 0x1ffffff;
        h[8] = (load_4(&bytes[25..29]) >> 4) & 0x3ffffff;
        h[9] = (load_4(&bytes[28..32]) >> 6) & 0x1ffffff;

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

        let carry0 = h[0] >> 26; h[1] += carry0; h[0] -= carry0 << 26;
        let carry1 = h[1] >> 25; h[2] += carry1; h[1] -= carry1 << 25;
        let carry2 = h[2] >> 26; h[3] += carry2; h[2] -= carry2 << 26;
        let carry3 = h[3] >> 25; h[4] += carry3; h[3] -= carry3 << 25;
        let carry4 = h[4] >> 26; h[5] += carry4; h[4] -= carry4 << 26;
        let carry5 = h[5] >> 25; h[6] += carry5; h[5] -= carry5 << 25;
        let carry6 = h[6] >> 26; h[7] += carry6; h[6] -= carry6 << 26;
        let carry7 = h[7] >> 25; h[8] += carry7; h[7] -= carry7 << 25;
        let carry8 = h[8] >> 26; h[9] += carry8; h[8] -= carry8 << 26;
        let carry9 = h[9] >> 25; h[9] -= carry9 << 25;

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
            self.0[0] + rhs.0[0], self.0[1] + rhs.0[1], self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3], self.0[4] + rhs.0[4], self.0[5] + rhs.0[5],
            self.0[6] + rhs.0[6], self.0[7] + rhs.0[7], self.0[8] + rhs.0[8],
            self.0[9] + rhs.0[9],
        ])
    }

    fn sub(&self, rhs: &Fe) -> Fe {
        Fe([
            self.0[0] - rhs.0[0], self.0[1] - rhs.0[1], self.0[2] - rhs.0[2],
            self.0[3] - rhs.0[3], self.0[4] - rhs.0[4], self.0[5] - rhs.0[5],
            self.0[6] - rhs.0[6], self.0[7] - rhs.0[7], self.0[8] - rhs.0[8],
            self.0[9] - rhs.0[9],
        ])
    }

    fn neg(&self) -> Fe {
        Fe([
            -self.0[0], -self.0[1], -self.0[2], -self.0[3], -self.0[4],
            -self.0[5], -self.0[6], -self.0[7], -self.0[8], -self.0[9],
        ])
    }

    fn mul(&self, rhs: &Fe) -> Fe {
        let f = &self.0;
        let g = &rhs.0;

        let f0 = f[0] as i128; let f1 = f[1] as i128; let f2 = f[2] as i128;
        let f3 = f[3] as i128; let f4 = f[4] as i128; let f5 = f[5] as i128;
        let f6 = f[6] as i128; let f7 = f[7] as i128; let f8 = f[8] as i128;
        let f9 = f[9] as i128;

        let g0 = g[0] as i128; let g1 = g[1] as i128; let g2 = g[2] as i128;
        let g3 = g[3] as i128; let g4 = g[4] as i128; let g5 = g[5] as i128;
        let g6 = g[6] as i128; let g7 = g[7] as i128; let g8 = g[8] as i128;
        let g9 = g[9] as i128;

        let g1_19 = 19 * g1; let g2_19 = 19 * g2; let g3_19 = 19 * g3;
        let g4_19 = 19 * g4; let g5_19 = 19 * g5; let g6_19 = 19 * g6;
        let g7_19 = 19 * g7; let g8_19 = 19 * g8; let g9_19 = 19 * g9;

        let f1_2 = 2 * f1; let f3_2 = 2 * f3; let f5_2 = 2 * f5;
        let f7_2 = 2 * f7; let f9_2 = 2 * f9;

        let h0 = f0*g0 + f1_2*g9_19 + f2*g8_19 + f3_2*g7_19 + f4*g6_19 + f5_2*g5_19 + f6*g4_19 + f7_2*g3_19 + f8*g2_19 + f9_2*g1_19;
        let h1 = f0*g1 + f1*g0 + f2*g9_19 + f3*g8_19 + f4*g7_19 + f5*g6_19 + f6*g5_19 + f7*g4_19 + f8*g3_19 + f9*g2_19;
        let h2 = f0*g2 + f1_2*g1 + f2*g0 + f3_2*g9_19 + f4*g8_19 + f5_2*g7_19 + f6*g6_19 + f7_2*g5_19 + f8*g4_19 + f9_2*g3_19;
        let h3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g9_19 + f5*g8_19 + f6*g7_19 + f7*g6_19 + f8*g5_19 + f9*g4_19;
        let h4 = f0*g4 + f1_2*g3 + f2*g2 + f3_2*g1 + f4*g0 + f5_2*g9_19 + f6*g8_19 + f7_2*g7_19 + f8*g6_19 + f9_2*g5_19;
        let h5 = f0*g5 + f1*g4 + f2*g3 + f3*g2 + f4*g1 + f5*g0 + f6*g9_19 + f7*g8_19 + f8*g7_19 + f9*g6_19;
        let h6 = f0*g6 + f1_2*g5 + f2*g4 + f3_2*g3 + f4*g2 + f5_2*g1 + f6*g0 + f7_2*g9_19 + f8*g8_19 + f9_2*g7_19;
        let h7 = f0*g7 + f1*g6 + f2*g5 + f3*g4 + f4*g3 + f5*g2 + f6*g1 + f7*g0 + f8*g9_19 + f9*g8_19;
        let h8 = f0*g8 + f1_2*g7 + f2*g6 + f3_2*g5 + f4*g4 + f5_2*g3 + f6*g2 + f7_2*g1 + f8*g0 + f9_2*g9_19;
        let h9 = f0*g9 + f1*g8 + f2*g7 + f3*g6 + f4*g5 + f5*g4 + f6*g3 + f7*g2 + f8*g1 + f9*g0;

        carry_mul([h0, h1, h2, h3, h4, h5, h6, h7, h8, h9])
    }

    fn square(&self) -> Fe {
        self.mul(self)
    }

    fn square2(&self) -> Fe {
        let h = self.square();
        h.add(&h)
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
        for _ in 1..5 { t2 = t2.square(); }
        t1 = t2.mul(&t1);
        t2 = t1.square();
        for _ in 1..10 { t2 = t2.square(); }
        t2 = t2.mul(&t1);
        let mut t3 = t2.square();
        for _ in 1..20 { t3 = t3.square(); }
        t2 = t3.mul(&t2);
        t2 = t2.square();
        for _ in 1..10 { t2 = t2.square(); }
        t1 = t2.mul(&t1);
        t2 = t1.square();
        for _ in 1..50 { t2 = t2.square(); }
        t2 = t2.mul(&t1);
        t3 = t2.square();
        for _ in 1..100 { t3 = t3.square(); }
        t2 = t3.mul(&t2);
        t2 = t2.square();
        for _ in 1..50 { t2 = t2.square(); }
        t1 = t2.mul(&t1);
        t1 = t1.square();
        for _ in 1..5 { t1 = t1.square(); }
        t0.mul(&t1)
    }

    fn pow22523(&self) -> Fe {
        let mut t0 = self.square();
        let mut t1 = t0.square();
        t1 = t1.square();
        t1 = self.mul(&t1);
        t0 = t0.mul(&t1);
        t0 = t0.square();
        t0 = t1.mul(&t0);
        t1 = t0.square();
        for _ in 1..5 { t1 = t1.square(); }
        t0 = t1.mul(&t0);
        t1 = t0.square();
        for _ in 1..10 { t1 = t1.square(); }
        t1 = t1.mul(&t0);
        let mut t2 = t1.square();
        for _ in 1..20 { t2 = t2.square(); }
        t1 = t2.mul(&t1);
        t1 = t1.square();
        for _ in 1..10 { t1 = t1.square(); }
        t0 = t1.mul(&t0);
        t1 = t0.square();
        for _ in 1..50 { t1 = t1.square(); }
        t1 = t1.mul(&t0);
        t2 = t1.square();
        for _ in 1..100 { t2 = t2.square(); }
        t1 = t2.mul(&t1);
        t1 = t1.square();
        for _ in 1..50 { t1 = t1.square(); }
        t0 = t1.mul(&t0);
        t0 = t0.square();
        t0 = t0.square();
        self.mul(&t0)
    }

    fn is_negative(&self) -> bool {
        (self.to_bytes()[0] & 1) == 1
    }

    fn is_zero(&self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    fn abs(&self) -> Fe {
        if self.is_negative() {
            self.neg()
        } else {
            *self
        }
    }
}

fn load_4(s: &[u8]) -> i64 {
    (s[0] as i64) | ((s[1] as i64) << 8) | ((s[2] as i64) << 16) | ((s[3] as i64) << 24)
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

impl ExtendedPoint {
    fn identity() -> Self {
        ExtendedPoint {
            x: Fe::zero(),
            y: Fe::one(),
            z: Fe::one(),
            t: Fe::zero(),
        }
    }

    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let y = Fe::from_bytes(bytes);
        let z = Fe::one();
        let y2 = y.square();
        let u = y2.sub(&Fe::one());
        let v = y2.mul(&D).add(&Fe::one());
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let uv7 = u.mul(&v7);
        let mut x = uv7.pow22523().mul(&u).mul(&v3);

        let vx2 = x.square().mul(&v);
        let check = vx2.sub(&u);
        if !check.is_zero() {
            let check2 = vx2.add(&u);
            if !check2.is_zero() {
                return None;
            }
            x = x.mul(&SQRT_M1);
        }

        if x.is_negative() != ((bytes[31] >> 7) == 1) {
            x = x.neg();
        }

        let t = x.mul(&y);
        Some(ExtendedPoint { x, y, z, t })
    }

    fn to_bytes(&self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);
        let mut s = y.to_bytes();
        s[31] ^= (x.is_negative() as u8) << 7;
        s
    }

    fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square2();
        let d = a.neg();
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);
        let x3 = e.mul(&f);
        let y3 = g.mul(&h);
        let t3 = e.mul(&h);
        let z3 = f.mul(&g);
        ExtendedPoint { x: x3, y: y3, z: z3, t: t3 }
    }

    fn add(&self, other: &ExtendedPoint) -> Self {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&D2).mul(&other.t);
        let d = self.z.mul(&other.z).add(&self.z.mul(&other.z));
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        let x3 = e.mul(&f);
        let y3 = g.mul(&h);
        let t3 = e.mul(&h);
        let z3 = f.mul(&g);
        ExtendedPoint { x: x3, y: y3, z: z3, t: t3 }
    }

    fn neg(&self) -> Self {
        ExtendedPoint {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    fn scalar_mul(&self, scalar: &[u8; 32]) -> Self {

        let mut r0 = Self::identity();
        let mut r1 = *self;

        for i in (0..256).rev() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = ((scalar[byte_idx] >> bit_idx) & 1) as i64;

            ct_swap(&mut r0, &mut r1, bit);

            r1 = r0.add(&r1);
            r0 = r0.double();

            ct_swap(&mut r0, &mut r1, bit);
        }

        r0
    }

    fn ct_select(a: &Self, b: &Self, choice: i64) -> Self {

        let mask = -(choice as i64);
        ExtendedPoint {
            x: fe_ct_select(&a.x, &b.x, mask),
            y: fe_ct_select(&a.y, &b.y, mask),
            z: fe_ct_select(&a.z, &b.z, mask),
            t: fe_ct_select(&a.t, &b.t, mask),
        }
    }
}

fn ct_swap(a: &mut ExtendedPoint, b: &mut ExtendedPoint, choice: i64) {
    let mask = -(choice as i64);
    fe_ct_swap(&mut a.x, &mut b.x, mask);
    fe_ct_swap(&mut a.y, &mut b.y, mask);
    fe_ct_swap(&mut a.z, &mut b.z, mask);
    fe_ct_swap(&mut a.t, &mut b.t, mask);
}

fn fe_ct_swap(a: &mut Fe, b: &mut Fe, mask: i64) {
    for i in 0..10 {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

fn fe_ct_select(a: &Fe, b: &Fe, mask: i64) -> Fe {
    let mut result = Fe::zero();
    for i in 0..10 {
        result.0[i] = a.0[i] ^ (mask & (a.0[i] ^ b.0[i]));
    }
    result
}

fn basepoint() -> ExtendedPoint {
    ExtendedPoint::from_bytes(&BASE_Y).unwrap()
}

pub struct Ed25519;

impl Ed25519 {

    pub fn public_key(private_key: &PrivateKey) -> PublicKey {

        let h = sha512(private_key);

        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;

        let b = basepoint();
        let a = b.scalar_mul(&s);
        a.to_bytes()
    }

    pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Signature {

        let h = sha512(private_key);

        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;

        let b = basepoint();
        let a_point = b.scalar_mul(&s);
        let a = a_point.to_bytes();

        let mut hasher_r = Sha512::new();
        hasher_r.update(&h[32..]);
        hasher_r.update(message);
        let r_hash = hasher_r.finalize();
        let r = sc_reduce(&r_hash);

        let r_point = b.scalar_mul(&r);
        let r_bytes = r_point.to_bytes();

        let mut hasher_k = Sha512::new();
        hasher_k.update(&r_bytes);
        hasher_k.update(&a);
        hasher_k.update(message);
        let k_hash = hasher_k.finalize();
        let k = sc_reduce(&k_hash);

        let s_scalar = sc_muladd(&k, &s, &r);

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(&s_scalar);
        Signature(sig)
    }

    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {

        let a_point = match ExtendedPoint::from_bytes(public_key) {
            Some(p) => p,
            None => return false,
        };

        let s = &signature.0[32..];
        if !sc_is_valid(s) {
            return false;
        }

        let mut hasher = Sha512::new();
        hasher.update(&signature.0[..32]);
        hasher.update(public_key);
        hasher.update(message);
        let k_hash = hasher.finalize();
        let k = sc_reduce(&k_hash);

        let b = basepoint();
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(s);
        let sb = b.scalar_mul(&s_bytes);

        let r_point = match ExtendedPoint::from_bytes(&signature.0[..32].try_into().unwrap()) {
            Some(p) => p,
            None => return false,
        };

        let ka = a_point.scalar_mul(&k);
        let rhs = r_point.add(&ka);

        let lhs_bytes = sb.to_bytes();
        let rhs_bytes = rhs.to_bytes();

        super::constant_time_eq(&lhs_bytes, &rhs_bytes)
    }
}

const L: [i64; 12] = [
    0x1cf5d3ed, 0x009318d2, 0x1de73596, 0x1df3bd45,
    0x0000014d, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00200000,
];

fn sc_reduce(s: &[u8; 64]) -> [u8; 32] {

    let mut a = [0i64; 24];

    a[0] = 0x1fffff & load_3_i64(&s[0..3]);
    a[1] = 0x1fffff & (load_4_i64(&s[2..6]) >> 5);
    a[2] = 0x1fffff & (load_3_i64(&s[5..8]) >> 2);
    a[3] = 0x1fffff & (load_4_i64(&s[7..11]) >> 7);
    a[4] = 0x1fffff & (load_4_i64(&s[10..14]) >> 4);
    a[5] = 0x1fffff & (load_3_i64(&s[13..16]) >> 1);
    a[6] = 0x1fffff & (load_4_i64(&s[15..19]) >> 6);
    a[7] = 0x1fffff & (load_3_i64(&s[18..21]) >> 3);
    a[8] = 0x1fffff & load_3_i64(&s[21..24]);
    a[9] = 0x1fffff & (load_4_i64(&s[23..27]) >> 5);
    a[10] = 0x1fffff & (load_3_i64(&s[26..29]) >> 2);
    a[11] = 0x1fffff & (load_4_i64(&s[28..32]) >> 7);
    a[12] = 0x1fffff & (load_4_i64(&s[31..35]) >> 4);
    a[13] = 0x1fffff & (load_3_i64(&s[34..37]) >> 1);
    a[14] = 0x1fffff & (load_4_i64(&s[36..40]) >> 6);
    a[15] = 0x1fffff & (load_3_i64(&s[39..42]) >> 3);
    a[16] = 0x1fffff & load_3_i64(&s[42..45]);
    a[17] = 0x1fffff & (load_4_i64(&s[44..48]) >> 5);
    a[18] = 0x1fffff & (load_3_i64(&s[47..50]) >> 2);
    a[19] = 0x1fffff & (load_4_i64(&s[49..53]) >> 7);
    a[20] = 0x1fffff & (load_4_i64(&s[52..56]) >> 4);
    a[21] = 0x1fffff & (load_3_i64(&s[55..58]) >> 1);
    a[22] = 0x1fffff & (load_4_i64(&s[57..61]) >> 6);
    a[23] = load_4_i64(&s[60..64]) >> 3;

    sc_reduce_limbs(&mut a);

    let mut out = [0u8; 32];
    out[0] = a[0] as u8;
    out[1] = (a[0] >> 8) as u8;
    out[2] = ((a[0] >> 16) | (a[1] << 5)) as u8;
    out[3] = (a[1] >> 3) as u8;
    out[4] = (a[1] >> 11) as u8;
    out[5] = ((a[1] >> 19) | (a[2] << 2)) as u8;
    out[6] = (a[2] >> 6) as u8;
    out[7] = ((a[2] >> 14) | (a[3] << 7)) as u8;
    out[8] = (a[3] >> 1) as u8;
    out[9] = (a[3] >> 9) as u8;
    out[10] = ((a[3] >> 17) | (a[4] << 4)) as u8;
    out[11] = (a[4] >> 4) as u8;
    out[12] = (a[4] >> 12) as u8;
    out[13] = ((a[4] >> 20) | (a[5] << 1)) as u8;
    out[14] = (a[5] >> 7) as u8;
    out[15] = ((a[5] >> 15) | (a[6] << 6)) as u8;
    out[16] = (a[6] >> 2) as u8;
    out[17] = (a[6] >> 10) as u8;
    out[18] = ((a[6] >> 18) | (a[7] << 3)) as u8;
    out[19] = (a[7] >> 5) as u8;
    out[20] = (a[7] >> 13) as u8;
    out[21] = a[8] as u8;
    out[22] = (a[8] >> 8) as u8;
    out[23] = ((a[8] >> 16) | (a[9] << 5)) as u8;
    out[24] = (a[9] >> 3) as u8;
    out[25] = (a[9] >> 11) as u8;
    out[26] = ((a[9] >> 19) | (a[10] << 2)) as u8;
    out[27] = (a[10] >> 6) as u8;
    out[28] = ((a[10] >> 14) | (a[11] << 7)) as u8;
    out[29] = (a[11] >> 1) as u8;
    out[30] = (a[11] >> 9) as u8;
    out[31] = (a[11] >> 17) as u8;

    out
}

fn sc_reduce_limbs(a: &mut [i64; 24]) {

    for i in (12..24).rev() {
        let q = a[i];
        if q == 0 { continue; }

        let shift = i - 11;
        a[shift + 0] -= q * 0x1cf5d3ed;
        a[shift + 1] -= q * 0x009318d2;
        a[shift + 2] -= q * 0x1de73596;
        a[shift + 3] -= q * 0x1df3bd45;
        a[shift + 4] -= q * 0x0000014d;

        a[shift + 11] -= q * 0x00200000;
        a[i] = 0;
    }

    for _ in 0..2 {
        for i in 0..11 {
            let carry = a[i] >> 21;
            a[i] &= 0x1fffff;
            a[i + 1] += carry;
        }

        for i in 0..11 {
            if a[i] < 0 {
                a[i] += 0x200000;
                a[i + 1] -= 1;
            }
        }
    }

    let mut borrow = 0i64;
    let mut tmp = [0i64; 12];

    tmp[0] = a[0] - 0x1cf5d3ed;
    tmp[1] = a[1] - 0x009318d2;
    tmp[2] = a[2] - 0x1de73596;
    tmp[3] = a[3] - 0x1df3bd45;
    tmp[4] = a[4] - 0x0000014d;
    tmp[5] = a[5];
    tmp[6] = a[6];
    tmp[7] = a[7];
    tmp[8] = a[8];
    tmp[9] = a[9];
    tmp[10] = a[10];
    tmp[11] = a[11] - 0x00200000;

    for i in 0..11 {
        tmp[i] += borrow;
        borrow = tmp[i] >> 63;
        if tmp[i] < 0 {
            tmp[i] += 0x200000;
            borrow = -1;
        } else {
            borrow = 0;
        }
    }
    tmp[11] += borrow;

    let mask = !(tmp[11] >> 63);
    for i in 0..12 {
        a[i] = (a[i] & !mask) | (tmp[i] & mask);
    }
}

fn load_3_i64(s: &[u8]) -> i64 {
    (s[0] as i64) | ((s[1] as i64) << 8) | ((s[2] as i64) << 16)
}

fn load_4_i64(s: &[u8]) -> i64 {
    (s[0] as i64) | ((s[1] as i64) << 8) | ((s[2] as i64) << 16) | ((s[3] as i64) << 24)
}

fn sc_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {

    let a_limbs = sc_load(a);
    let b_limbs = sc_load(b);
    let c_limbs = sc_load(c);

    let mut product = [0i64; 24];
    for i in 0..12 {
        for j in 0..12 {
            product[i + j] += a_limbs[i] * b_limbs[j];
        }
    }

    for i in 0..12 {
        product[i] += c_limbs[i];
    }

    for i in 0..23 {
        let carry = product[i] >> 21;
        product[i] &= 0x1fffff;
        product[i + 1] += carry;
    }

    sc_reduce_limbs(&mut product);

    let mut out = [0u8; 32];
    out[0] = product[0] as u8;
    out[1] = (product[0] >> 8) as u8;
    out[2] = ((product[0] >> 16) | (product[1] << 5)) as u8;
    out[3] = (product[1] >> 3) as u8;
    out[4] = (product[1] >> 11) as u8;
    out[5] = ((product[1] >> 19) | (product[2] << 2)) as u8;
    out[6] = (product[2] >> 6) as u8;
    out[7] = ((product[2] >> 14) | (product[3] << 7)) as u8;
    out[8] = (product[3] >> 1) as u8;
    out[9] = (product[3] >> 9) as u8;
    out[10] = ((product[3] >> 17) | (product[4] << 4)) as u8;
    out[11] = (product[4] >> 4) as u8;
    out[12] = (product[4] >> 12) as u8;
    out[13] = ((product[4] >> 20) | (product[5] << 1)) as u8;
    out[14] = (product[5] >> 7) as u8;
    out[15] = ((product[5] >> 15) | (product[6] << 6)) as u8;
    out[16] = (product[6] >> 2) as u8;
    out[17] = (product[6] >> 10) as u8;
    out[18] = ((product[6] >> 18) | (product[7] << 3)) as u8;
    out[19] = (product[7] >> 5) as u8;
    out[20] = (product[7] >> 13) as u8;
    out[21] = product[8] as u8;
    out[22] = (product[8] >> 8) as u8;
    out[23] = ((product[8] >> 16) | (product[9] << 5)) as u8;
    out[24] = (product[9] >> 3) as u8;
    out[25] = (product[9] >> 11) as u8;
    out[26] = ((product[9] >> 19) | (product[10] << 2)) as u8;
    out[27] = (product[10] >> 6) as u8;
    out[28] = ((product[10] >> 14) | (product[11] << 7)) as u8;
    out[29] = (product[11] >> 1) as u8;
    out[30] = (product[11] >> 9) as u8;
    out[31] = (product[11] >> 17) as u8;

    out
}

fn sc_load(s: &[u8; 32]) -> [i64; 12] {
    let mut a = [0i64; 12];
    a[0] = 0x1fffff & load_3_i64(&s[0..3]);
    a[1] = 0x1fffff & (load_4_i64(&s[2..6]) >> 5);
    a[2] = 0x1fffff & (load_3_i64(&s[5..8]) >> 2);
    a[3] = 0x1fffff & (load_4_i64(&s[7..11]) >> 7);
    a[4] = 0x1fffff & (load_4_i64(&s[10..14]) >> 4);
    a[5] = 0x1fffff & (load_3_i64(&s[13..16]) >> 1);
    a[6] = 0x1fffff & (load_4_i64(&s[15..19]) >> 6);
    a[7] = 0x1fffff & (load_3_i64(&s[18..21]) >> 3);
    a[8] = 0x1fffff & load_3_i64(&s[21..24]);
    a[9] = 0x1fffff & (load_4_i64(&s[23..27]) >> 5);
    a[10] = 0x1fffff & (load_3_i64(&s[26..29]) >> 2);
    a[11] = load_4_i64(&s[28..32]) >> 7;
    a
}

fn sc_is_valid(s: &[u8]) -> bool {

    if s.len() != 32 {
        return false;
    }

    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];

    let mut borrow: i16 = 0;

    for i in 0..32 {
        let diff = (s[i] as i16) - (L[i] as i16) - borrow;

        borrow = (diff >> 15) & 1;
    }

    borrow == 1
}

struct Sha512 {
    state: [u64; 8],
    total_len: u128,
    buffer: [u8; 128],
    buffer_len: usize,
}

const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

impl Sha512 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
            ],
            total_len: 0,
            buffer: [0u8; 128],
            buffer_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        if self.buffer_len > 0 {
            let needed = 128 - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..].copy_from_slice(&data[..needed]);
                self.process_block(&self.buffer.clone());
                self.buffer_len = 0;
                offset = needed;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                self.total_len += data.len() as u128;
                return;
            }
        }

        while offset + 128 <= data.len() {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[offset..offset + 128]);
            self.process_block(&block);
            offset += 128;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }

        self.total_len += data.len() as u128;
    }

    fn finalize(mut self) -> [u8; 64] {
        let total_bits = self.total_len * 8;

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 112 {
            for i in self.buffer_len..128 {
                self.buffer[i] = 0;
            }
            self.process_block(&self.buffer.clone());
            self.buffer_len = 0;
        }

        for i in self.buffer_len..112 {
            self.buffer[i] = 0;
        }

        self.buffer[112..128].copy_from_slice(&total_bits.to_be_bytes());
        self.process_block(&self.buffer.clone());

        let mut digest = [0u8; 64];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn process_block(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];

        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                block[i * 8], block[i * 8 + 1], block[i * 8 + 2], block[i * 8 + 3],
                block[i * 8 + 4], block[i * 8 + 5], block[i * 8 + 6], block[i * 8 + 7],
            ]);
        }

        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g; g = f; f = e;
            e = d.wrapping_add(temp1);
            d = c; c = b; b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}
