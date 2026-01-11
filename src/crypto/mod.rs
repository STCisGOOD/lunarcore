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
