use crate::crypto::ed25519::{Ed25519, PublicKey, PrivateKey, Signature};
use crate::crypto::x25519::{x25519, x25519_base};
use crate::crypto::sha256::Sha256;
use crate::crypto::chacha20::{ChaCha20, KEY_SIZE, NONCE_SIZE};


pub const SEED_SIZE: usize = 32;


pub const NODE_ID_SIZE: usize = 4;


pub const SHORT_ID_SIZE: usize = 8;


const IDENTITY_FLASH_KEY: &str = "lunar_id";


const KDF_CONTEXT_IDENTITY: &[u8] = b"LunarCore Identity v1";
const KDF_CONTEXT_SIGNING: &[u8] = b"LunarCore Signing v1";
const KDF_CONTEXT_ENCRYPTION: &[u8] = b"LunarCore Encryption v1";


pub struct Identity {

    signing_key: PrivateKey,

    public_key: PublicKey,

    encryption_key: [u8; 32],

    encryption_public: [u8; 32],

    created_at: u32,
}


impl Drop for Identity {
    fn drop(&mut self) {
        crate::crypto::secure_zero(&mut self.signing_key);
        crate::crypto::secure_zero(&mut self.encryption_key);
    }
}

impl Identity {


    pub fn generate() -> Self {

        let mut seed = [0u8; SEED_SIZE];
        if !crate::rng::fill_random_checked(&mut seed) {
            panic!("RNG health check failed - cannot generate identity with weak entropy");
        }

        Self::from_seed(&seed)
    }


    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Self {

        let signing_key = Self::derive_key(seed, KDF_CONTEXT_SIGNING);
        let public_key = Ed25519::public_key(&signing_key);


        let encryption_key = Self::derive_key(seed, KDF_CONTEXT_ENCRYPTION);
        let encryption_public = x25519_base(&encryption_key);

        Self {
            signing_key,
            public_key,
            encryption_key,
            encryption_public,
            created_at: 0,
        }
    }


    fn derive_key(seed: &[u8; SEED_SIZE], context: &[u8]) -> [u8; 32] {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(seed);
        let context_len = context.len().min(32);
        input[32..32 + context_len].copy_from_slice(&context[..context_len]);
        Sha256::hash(&input)
    }


    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }


    pub fn encryption_public_key(&self) -> &[u8; 32] {
        &self.encryption_public
    }


    pub fn node_id(&self) -> u32 {
        let hash = Sha256::hash(&self.public_key);
        u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
    }


    pub fn short_id(&self) -> [u8; SHORT_ID_SIZE] {
        let hash = Sha256::hash(&self.public_key);
        let mut short = [0u8; SHORT_ID_SIZE];
        for i in 0..4 {
            let byte = hash[i];
            short[i * 2] = hex_char(byte >> 4);
            short[i * 2 + 1] = hex_char(byte & 0x0F);
        }
        short
    }


    pub fn sign(&self, message: &[u8]) -> Signature {
        Ed25519::sign(&self.signing_key, message)
    }


    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        Ed25519::verify(public_key, message, signature)
    }


    pub fn key_agree(&self, their_public: &[u8; 32]) -> [u8; 32] {
        x25519(&self.encryption_key, their_public)
    }


    pub fn encrypt_for_storage(&self, storage_key: &[u8; 32]) -> EncryptedIdentity {

        let mut plaintext = [0u8; 128];
        plaintext[0..32].copy_from_slice(&self.signing_key);
        plaintext[32..64].copy_from_slice(&self.encryption_key);
        plaintext[64..68].copy_from_slice(&self.created_at.to_le_bytes());


        let mut nonce = [0u8; NONCE_SIZE];
        if !crate::rng::fill_random_checked(&mut nonce) {
            panic!("RNG health check failed - cannot encrypt identity with weak nonce");
        }


        let cipher = ChaCha20::new(storage_key, &nonce);
        let mut ciphertext = plaintext;
        cipher.encrypt(&mut ciphertext);


        let mut tag_input = [0u8; 128 + NONCE_SIZE];
        tag_input[..128].copy_from_slice(&ciphertext);
        tag_input[128..].copy_from_slice(&nonce);
        let tag = Sha256::hash(&tag_input);

        EncryptedIdentity {
            ciphertext,
            nonce,
            tag,
        }
    }


    pub fn decrypt_from_storage(
        encrypted: &EncryptedIdentity,
        storage_key: &[u8; 32],
    ) -> Option<Self> {

        let mut tag_input = [0u8; 128 + NONCE_SIZE];
        tag_input[..128].copy_from_slice(&encrypted.ciphertext);
        tag_input[128..].copy_from_slice(&encrypted.nonce);
        let expected_tag = Sha256::hash(&tag_input);

        if !crate::crypto::constant_time_eq(&encrypted.tag, &expected_tag) {
            return None;
        }


        let cipher = ChaCha20::new(storage_key, &encrypted.nonce);
        let mut plaintext = encrypted.ciphertext;
        cipher.decrypt(&mut plaintext);


        let mut signing_key = [0u8; 32];
        let mut encryption_key = [0u8; 32];
        signing_key.copy_from_slice(&plaintext[0..32]);
        encryption_key.copy_from_slice(&plaintext[32..64]);
        let created_at = u32::from_le_bytes([
            plaintext[64], plaintext[65], plaintext[66], plaintext[67]
        ]);


        let public_key = Ed25519::public_key(&signing_key);
        let encryption_public = x25519_base(&encryption_key);


        crate::crypto::secure_zero(&mut plaintext);

        Some(Self {
            signing_key,
            public_key,
            encryption_key,
            encryption_public,
            created_at,
        })
    }


    pub fn export_seed(&self) -> [u8; SEED_SIZE] {


        self.signing_key
    }
}


pub struct EncryptedIdentity {

    pub ciphertext: [u8; 128],

    pub nonce: [u8; NONCE_SIZE],

    pub tag: [u8; 32],
}

impl EncryptedIdentity {

    pub fn to_bytes(&self) -> [u8; 128 + NONCE_SIZE + 32] {
        let mut bytes = [0u8; 128 + NONCE_SIZE + 32];
        bytes[0..128].copy_from_slice(&self.ciphertext);
        bytes[128..128 + NONCE_SIZE].copy_from_slice(&self.nonce);
        bytes[128 + NONCE_SIZE..].copy_from_slice(&self.tag);
        bytes
    }


    pub fn from_bytes(bytes: &[u8; 128 + NONCE_SIZE + 32]) -> Self {
        let mut ciphertext = [0u8; 128];
        let mut nonce = [0u8; NONCE_SIZE];
        let mut tag = [0u8; 32];

        ciphertext.copy_from_slice(&bytes[0..128]);
        nonce.copy_from_slice(&bytes[128..128 + NONCE_SIZE]);
        tag.copy_from_slice(&bytes[128 + NONCE_SIZE..]);

        Self { ciphertext, nonce, tag }
    }
}


pub struct IdentityManager {

    current: Option<Identity>,

    storage_key: [u8; 32],
}

impl Drop for IdentityManager {
    fn drop(&mut self) {
        crate::crypto::secure_zero(&mut self.storage_key);
    }
}

impl IdentityManager {


    pub fn new() -> Self {
        let storage_key = Self::derive_storage_key();
        Self {
            current: None,
            storage_key,
        }
    }


    fn derive_storage_key() -> [u8; 32] {

        let mut efuse_data = [0u8; 32];

        #[cfg(target_arch = "xtensa")]
        unsafe {

            let efuse_base = 0x6001_A000 as *const u32;
            for i in 0..8 {
                let val = core::ptr::read_volatile(efuse_base.add(i));
                efuse_data[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
            }
        }

        #[cfg(not(target_arch = "xtensa"))]
        {

            efuse_data = [0u8; 32];
        }


        let mut kdf_input = [0u8; 64];
        kdf_input[..32].copy_from_slice(&efuse_data);
        kdf_input[32..].copy_from_slice(b"LunarCore Storage Key v1\0\0\0\0\0\0\0\0");

        Sha256::hash(&kdf_input)
    }


    pub fn init(&mut self) -> &Identity {

        if let Some(identity) = self.load_from_flash() {
            self.current = Some(identity);
        } else {

            let identity = Identity::generate();
            self.save_to_flash(&identity);
            self.current = Some(identity);
        }

        self.current.as_ref().unwrap()
    }


    pub fn current(&self) -> Option<&Identity> {
        self.current.as_ref()
    }


    pub fn rotate(&mut self) -> &Identity {
        let identity = Identity::generate();
        self.save_to_flash(&identity);
        self.current = Some(identity);
        self.current.as_ref().unwrap()
    }


    pub fn import_seed(&mut self, seed: &[u8; SEED_SIZE]) -> &Identity {
        let identity = Identity::from_seed(seed);
        self.save_to_flash(&identity);
        self.current = Some(identity);
        self.current.as_ref().unwrap()
    }


    fn load_from_flash(&self) -> Option<Identity> {

        #[cfg(target_arch = "xtensa")]
        {
            use esp_idf_sys::*;

            unsafe {
                let mut handle: nvs_handle_t = 0;
                let namespace = b"lunar\0".as_ptr();

                let ret = nvs_open(namespace, nvs_open_mode_t_NVS_READONLY, &mut handle);
                if ret != 0 {
                    return None;
                }

                let key = b"identity\0".as_ptr();
                let mut size: usize = 128 + NONCE_SIZE + 32;
                let mut bytes = [0u8; 128 + NONCE_SIZE + 32];

                let ret = nvs_get_blob(handle, key, bytes.as_mut_ptr() as *mut _, &mut size);
                nvs_close(handle);

                if ret != 0 || size != bytes.len() {
                    return None;
                }

                let encrypted = EncryptedIdentity::from_bytes(&bytes);
                Identity::decrypt_from_storage(&encrypted, &self.storage_key)
            }
        }

        #[cfg(not(target_arch = "xtensa"))]
        {
            None
        }
    }


    fn save_to_flash(&self, identity: &Identity) {
        let encrypted = identity.encrypt_for_storage(&self.storage_key);
        let bytes = encrypted.to_bytes();

        #[cfg(target_arch = "xtensa")]
        unsafe {
            use esp_idf_sys::*;

            let mut handle: nvs_handle_t = 0;
            let namespace = b"lunar\0".as_ptr();

            let ret = nvs_open(namespace, nvs_open_mode_t_NVS_READWRITE, &mut handle);
            if ret != 0 {
                return;
            }

            let key = b"identity\0".as_ptr();
            nvs_set_blob(handle, key, bytes.as_ptr() as *const _, bytes.len());
            nvs_commit(handle);
            nvs_close(handle);
        }

        #[cfg(not(target_arch = "xtensa"))]
        {
            let _ = bytes;
        }
    }
}

impl Default for IdentityManager {
    fn default() -> Self {
        Self::new()
    }
}


fn hex_char(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'a' + (nibble - 10),
        _ => b'?',
    }
}


use core::sync::atomic::{AtomicBool, Ordering};

static mut IDENTITY_MANAGER: Option<IdentityManager> = None;
static IDENTITY_INIT: AtomicBool = AtomicBool::new(false);


pub fn init() {
    if !IDENTITY_INIT.swap(true, Ordering::SeqCst) {
        unsafe {
            IDENTITY_MANAGER = Some(IdentityManager::new());
            IDENTITY_MANAGER.as_mut().unwrap().init();
        }
    }
}


pub fn node_id() -> u32 {
    init();
    unsafe {
        IDENTITY_MANAGER
            .as_ref()
            .and_then(|m| m.current())
            .map(|i| i.node_id())
            .unwrap_or(0)
    }
}


pub fn public_key() -> Option<PublicKey> {
    init();
    unsafe {
        IDENTITY_MANAGER
            .as_ref()
            .and_then(|m| m.current())
            .map(|i| *i.public_key())
    }
}


pub fn encryption_public_key() -> Option<[u8; 32]> {
    init();
    unsafe {
        IDENTITY_MANAGER
            .as_ref()
            .and_then(|m| m.current())
            .map(|i| *i.encryption_public_key())
    }
}


pub fn sign(message: &[u8]) -> Option<Signature> {
    init();
    unsafe {
        IDENTITY_MANAGER
            .as_ref()
            .and_then(|m| m.current())
            .map(|i| i.sign(message))
    }
}


pub fn key_agree(their_public: &[u8; 32]) -> Option<[u8; 32]> {
    init();
    unsafe {
        IDENTITY_MANAGER
            .as_ref()
            .and_then(|m| m.current())
            .map(|i| i.key_agree(their_public))
    }
}


pub fn rotate() -> Option<u32> {
    init();
    unsafe {
        IDENTITY_MANAGER
            .as_mut()
            .map(|m| m.rotate().node_id())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let seed = [0x42u8; 32];
        let identity = Identity::from_seed(&seed);


        let node_id = identity.node_id();
        assert_ne!(node_id, 0);


        let short = identity.short_id();
        for &c in &short {
            assert!(c.is_ascii_hexdigit());
        }
    }

    #[test]
    fn test_identity_deterministic() {
        let seed = [0x42u8; 32];
        let id1 = Identity::from_seed(&seed);
        let id2 = Identity::from_seed(&seed);

        assert_eq!(id1.public_key(), id2.public_key());
        assert_eq!(id1.node_id(), id2.node_id());
    }

    #[test]
    fn test_sign_verify() {
        let seed = [0x42u8; 32];
        let identity = Identity::from_seed(&seed);

        let message = b"Hello, cypherpunk!";
        let signature = identity.sign(message);

        assert!(Identity::verify(identity.public_key(), message, &signature));
        assert!(!Identity::verify(identity.public_key(), b"wrong", &signature));
    }

    #[test]
    fn test_key_agreement() {
        let seed_alice = [0x41u8; 32];
        let seed_bob = [0x42u8; 32];

        let alice = Identity::from_seed(&seed_alice);
        let bob = Identity::from_seed(&seed_bob);

        let alice_shared = alice.key_agree(bob.encryption_public_key());
        let bob_shared = bob.key_agree(alice.encryption_public_key());

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_storage_encryption() {
        let seed = [0x42u8; 32];
        let storage_key = [0x55u8; 32];

        let identity = Identity::from_seed(&seed);
        let encrypted = identity.encrypt_for_storage(&storage_key);


        let recovered = Identity::decrypt_from_storage(&encrypted, &storage_key);
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap().public_key(), identity.public_key());


        let wrong_key = [0xAAu8; 32];
        let failed = Identity::decrypt_from_storage(&encrypted, &wrong_key);
        assert!(failed.is_none());
    }

    #[test]
    fn test_different_seeds_different_ids() {
        let id1 = Identity::from_seed(&[0x01u8; 32]);
        let id2 = Identity::from_seed(&[0x02u8; 32]);

        assert_ne!(id1.public_key(), id2.public_key());
        assert_ne!(id1.node_id(), id2.node_id());
    }
}
