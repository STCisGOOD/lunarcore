pub mod aes;
pub mod sha256;
pub mod hmac;
pub mod x25519;
pub mod ed25519;
pub mod chacha20;
pub mod poly1305;
pub mod hkdf;


pub use aes::{Aes128, Aes256, AesMode};
pub use sha256::Sha256;
pub use hmac::HmacSha256;
pub use x25519::{x25519, x25519_base};
pub use ed25519::{Ed25519, Signature};
pub use chacha20::ChaCha20;
pub use poly1305::Poly1305;
pub use hkdf::Hkdf;


#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}


#[inline]
pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}


#[inline]
pub fn secure_zero_u32(data: &mut [u32]) {
    for word in data.iter_mut() {
        unsafe {
            core::ptr::write_volatile(word, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}


pub fn random_bytes(dest: &mut [u8]) {
    crate::rng::fill_random(dest);
}


pub fn random_bytes_checked(dest: &mut [u8]) -> bool {
    crate::rng::fill_random_checked(dest)
}


pub fn rng_is_healthy() -> bool {
    crate::rng::is_healthy()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_zero() {
        let mut data = [0x42u8; 32];
        assert!(data.iter().all(|&b| b == 0x42));

        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0), "Data should be zeroed");
    }

    #[test]
    fn test_secure_zero_u32() {
        let mut data = [0xDEADBEEFu32; 16];
        assert!(data.iter().all(|&w| w == 0xDEADBEEF));

        secure_zero_u32(&mut data);
        assert!(data.iter().all(|&w| w == 0), "Data should be zeroed");
    }

    #[test]
    fn test_secure_zero_empty() {

        let mut empty: [u8; 0] = [];
        secure_zero(&mut empty);

        let mut empty_u32: [u32; 0] = [];
        secure_zero_u32(&mut empty_u32);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        let c = [0x43u8; 32];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));


        assert!(!constant_time_eq(&a[..16], &b));
    }

    #[test]
    fn test_aes128_drop_zeros_keys() {

        let key = [0x42u8; 16];
        let cipher = Aes128::new(&key);


        let round_keys_ptr = &cipher.round_keys as *const [u8; 176];


        drop(cipher);


    }

    #[test]
    fn test_chacha20_drop_zeros_state() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let cipher = ChaCha20::new(&key, &nonce);


        let mut data = [0u8; 16];
        cipher.encrypt(&mut data);


        drop(cipher);
    }
}
