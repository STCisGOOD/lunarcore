use crate::crypto::{
    x25519::{x25519, x25519_base},
    hkdf::Hkdf,
    aes::{Aes256, AesMode},
};
use heapless::Vec as HeaplessVec;
use std::collections::HashMap;


#[cfg(target_arch = "xtensa")]
fn fill_random(dest: &mut [u8]) {

    const RNG_DATA_REG: u32 = 0x3FF7_5144;

    for chunk in dest.chunks_mut(4) {

        let random_word: u32 = unsafe {
            core::ptr::read_volatile(RNG_DATA_REG as *const u32)
        };
        let bytes = random_word.to_le_bytes();
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte = bytes[i];
        }
    }
}


#[cfg(not(target_arch = "xtensa"))]
fn fill_random(dest: &mut [u8]) {


    use crate::crypto::sha256::Sha256;
    static mut COUNTER: u64 = 0;

    let mut seed = [0u8; 40];
    unsafe {
        seed[..8].copy_from_slice(&COUNTER.to_le_bytes());
        COUNTER = COUNTER.wrapping_add(1);
    }

    let stack_addr = &seed as *const _ as usize;
    seed[8..16].copy_from_slice(&stack_addr.to_le_bytes());

    let hash = Sha256::hash(&seed);
    let copy_len = core::cmp::min(dest.len(), 32);
    dest[..copy_len].copy_from_slice(&hash[..copy_len]);


    if dest.len() > 32 {
        fill_random(&mut dest[32..]);
    }
}


#[inline(never)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }


    unsafe {
        core::ptr::read_volatile(&result) == 0
    }
}


const MAX_MESSAGES_BEFORE_RATCHET: u64 = 100;

const MAX_TIME_BEFORE_RATCHET_SECS: u64 = 600;

const MAX_SKIPPED_KEYS: usize = 100;

const SESSION_HINT_INFO: &[u8] = b"session-hint-v1";

const ROOT_KEY_INFO: &[u8] = b"lunarpunk-root-key-v2";

const CHAIN_KEY_INFO: &[u8] = b"lunarpunk-chain-key-v2";

const MESSAGE_KEY_INFO: &[u8] = b"lunarpunk-message-key-v2";


#[derive(Clone)]
pub struct Session {

    root_key: [u8; 32],

    send_chain_key: [u8; 32],

    recv_chain_key: [u8; 32],

    send_ratchet_private: [u8; 32],

    send_ratchet_public: [u8; 32],

    recv_ratchet_public: [u8; 32],

    send_count: u64,

    recv_count: u64,

    prev_recv_chain: u64,

    last_ratchet_time: u64,


    skipped_keys: HashMap<([u8; 8], u64), [u8; 32]>,

    established: bool,
}


pub struct SessionParams {

    pub shared_secret: [u8; 32],

    pub our_private: [u8; 32],

    pub their_public: [u8; 32],

    pub is_initiator: bool,
}


#[derive(Debug, Clone)]
pub struct MessageHeader {

    pub dh_public: [u8; 32],

    pub prev_chain_len: u64,

    pub message_num: u64,
}

impl MessageHeader {

    pub fn encode(&self) -> [u8; 48] {
        let mut buf = [0u8; 48];
        buf[..32].copy_from_slice(&self.dh_public);
        buf[32..40].copy_from_slice(&self.prev_chain_len.to_le_bytes());
        buf[40..48].copy_from_slice(&self.message_num.to_le_bytes());
        buf
    }


    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 48 {
            return None;
        }
        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&data[..32]);

        let mut prev_bytes = [0u8; 8];
        prev_bytes.copy_from_slice(&data[32..40]);
        let prev_chain_len = u64::from_le_bytes(prev_bytes);

        let mut num_bytes = [0u8; 8];
        num_bytes.copy_from_slice(&data[40..48]);
        let message_num = u64::from_le_bytes(num_bytes);

        Some(Self {
            dh_public,
            prev_chain_len,
            message_num,
        })
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {

    NotEstablished,

    InvalidFormat,

    DecryptionFailed,

    OldChain,

    TooManySkipped,

    KeyDerivationFailed,
}

impl Session {

    pub fn new(params: SessionParams) -> Self {

        let mut root_key = [0u8; 32];
        let mut send_chain_key = [0u8; 32];
        let mut recv_chain_key = [0u8; 32];


        let salt = if params.is_initiator {
            b"initiator-salt-v1"
        } else {
            b"responder-salt-v1"
        };


        Hkdf::derive(&params.shared_secret, salt, ROOT_KEY_INFO, &mut root_key);


        let dh_output = x25519(&params.our_private, &params.their_public);


        let mut kdf_input = [0u8; 64];
        kdf_input[..32].copy_from_slice(&root_key);
        kdf_input[32..].copy_from_slice(&dh_output);

        if params.is_initiator {
            Hkdf::derive(&kdf_input, b"send", CHAIN_KEY_INFO, &mut send_chain_key);
            Hkdf::derive(&kdf_input, b"recv", CHAIN_KEY_INFO, &mut recv_chain_key);
        } else {
            Hkdf::derive(&kdf_input, b"recv", CHAIN_KEY_INFO, &mut send_chain_key);
            Hkdf::derive(&kdf_input, b"send", CHAIN_KEY_INFO, &mut recv_chain_key);
        }


        let send_ratchet_public = x25519_base(&params.our_private);

        Self {
            root_key,
            send_chain_key,
            recv_chain_key,
            send_ratchet_private: params.our_private,
            send_ratchet_public,
            recv_ratchet_public: params.their_public,
            send_count: 0,
            recv_count: 0,
            prev_recv_chain: 0,
            last_ratchet_time: 0,
            skipped_keys: HashMap::new(),
            established: true,
        }
    }


    pub fn uninitialized() -> Self {
        Self {
            root_key: [0u8; 32],
            send_chain_key: [0u8; 32],
            recv_chain_key: [0u8; 32],
            send_ratchet_private: [0u8; 32],
            send_ratchet_public: [0u8; 32],
            recv_ratchet_public: [0u8; 32],
            send_count: 0,
            recv_count: 0,
            prev_recv_chain: 0,
            last_ratchet_time: 0,
            skipped_keys: HashMap::new(),
            established: false,
        }
    }


    pub fn is_established(&self) -> bool {
        self.established
    }


    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(MessageHeader, HeaplessVec<u8, 256>), SessionError> {
        if !self.established {
            return Err(SessionError::NotEstablished);
        }


        let mut message_key = [0u8; 32];
        Hkdf::derive(&self.send_chain_key, &self.send_count.to_le_bytes(), MESSAGE_KEY_INFO, &mut message_key);


        let mut new_chain_key = [0u8; 32];
        Hkdf::derive(&self.send_chain_key, b"chain-advance", CHAIN_KEY_INFO, &mut new_chain_key);
        self.send_chain_key = new_chain_key;


        let header = MessageHeader {
            dh_public: self.send_ratchet_public,
            prev_chain_len: self.prev_recv_chain,
            message_num: self.send_count,
        };


        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&self.send_count.to_le_bytes());

        let mut ciphertext = HeaplessVec::new();
        let _ = ciphertext.extend_from_slice(plaintext);


        let aes = Aes256::new(&message_key);
        let mut keystream = [0u8; 16];
        let mut block_counter = 0u64;

        for chunk in ciphertext.chunks_mut(16) {
            keystream = nonce;
            keystream[8..].copy_from_slice(&block_counter.to_le_bytes());
            aes.encrypt_block(&mut keystream);
            for (c, k) in chunk.iter_mut().zip(keystream.iter()) {
                *c ^= k;
            }
            block_counter += 1;
        }


        let tag = Self::compute_tag(&message_key, &header.encode(), &ciphertext);
        let _ = ciphertext.extend_from_slice(&tag);

        self.send_count += 1;


        if self.should_ratchet() {
            self.advance_send_ratchet();
        }

        Ok((header, ciphertext))
    }


    pub fn decrypt(&mut self, header: &MessageHeader, ciphertext: &[u8]) -> Result<HeaplessVec<u8, 256>, SessionError> {
        if !self.established {
            return Err(SessionError::NotEstablished);
        }

        if ciphertext.len() < 16 {
            return Err(SessionError::InvalidFormat);
        }


        if header.dh_public != self.recv_ratchet_public {

            self.skip_message_keys(header.prev_chain_len)?;

            self.advance_recv_ratchet(&header.dh_public)?;
        }


        let message_key = self.get_message_key(header)?;


        let tag_start = ciphertext.len() - 16;
        let received_tag = &ciphertext[tag_start..];
        let ct_without_tag = &ciphertext[..tag_start];

        let expected_tag = Self::compute_tag(&message_key, &header.encode(), ct_without_tag);
        if !constant_time_eq(received_tag, &expected_tag) {
            return Err(SessionError::DecryptionFailed);
        }


        let mut plaintext = HeaplessVec::new();
        let _ = plaintext.extend_from_slice(ct_without_tag);

        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&header.message_num.to_le_bytes());

        let aes = Aes256::new(&message_key);
        let mut keystream = [0u8; 16];
        let mut block_counter = 0u64;

        for chunk in plaintext.chunks_mut(16) {
            keystream = nonce;
            keystream[8..].copy_from_slice(&block_counter.to_le_bytes());
            aes.encrypt_block(&mut keystream);
            for (c, k) in chunk.iter_mut().zip(keystream.iter()) {
                *c ^= k;
            }
            block_counter += 1;
        }

        Ok(plaintext)
    }


    pub fn derive_session_hint(&self, epoch: u64) -> [u8; 4] {
        let mut input = [0u8; 40];
        input[..32].copy_from_slice(&self.root_key);
        input[32..].copy_from_slice(&epoch.to_le_bytes());

        let mut hint = [0u8; 4];
        Hkdf::derive(&input, b"hint", SESSION_HINT_INFO, &mut hint);
        hint
    }


    fn should_ratchet(&self) -> bool {
        self.send_count >= MAX_MESSAGES_BEFORE_RATCHET

    }


    fn advance_send_ratchet(&mut self) {

        let mut new_private = [0u8; 32];
        fill_random(&mut new_private);


        new_private[0] &= 248;
        new_private[31] &= 127;
        new_private[31] |= 64;

        let new_public = x25519_base(&new_private);


        let dh_output = x25519(&new_private, &self.recv_ratchet_public);


        let mut kdf_input = [0u8; 64];
        kdf_input[..32].copy_from_slice(&self.root_key);
        kdf_input[32..].copy_from_slice(&dh_output);

        Hkdf::derive(&kdf_input, b"root", ROOT_KEY_INFO, &mut self.root_key);
        Hkdf::derive(&kdf_input, b"chain", CHAIN_KEY_INFO, &mut self.send_chain_key);

        self.send_ratchet_private = new_private;
        self.send_ratchet_public = new_public;
        self.prev_recv_chain = self.recv_count;
        self.send_count = 0;
    }


    fn advance_recv_ratchet(&mut self, their_new_public: &[u8; 32]) -> Result<(), SessionError> {

        let dh_output = x25519(&self.send_ratchet_private, their_new_public);


        let mut kdf_input = [0u8; 64];
        kdf_input[..32].copy_from_slice(&self.root_key);
        kdf_input[32..].copy_from_slice(&dh_output);

        Hkdf::derive(&kdf_input, b"root", ROOT_KEY_INFO, &mut self.root_key);
        Hkdf::derive(&kdf_input, b"chain", CHAIN_KEY_INFO, &mut self.recv_chain_key);

        self.recv_ratchet_public = *their_new_public;
        self.recv_count = 0;

        Ok(())
    }


    fn skip_message_keys(&mut self, until: u64) -> Result<(), SessionError> {
        let to_skip = until.saturating_sub(self.recv_count);
        if to_skip as usize > MAX_SKIPPED_KEYS {
            return Err(SessionError::TooManySkipped);
        }

        while self.recv_count < until {
            let mut message_key = [0u8; 32];
            Hkdf::derive(&self.recv_chain_key, &self.recv_count.to_le_bytes(), MESSAGE_KEY_INFO, &mut message_key);


            let mut key_prefix = [0u8; 8];
            key_prefix.copy_from_slice(&self.recv_ratchet_public[..8]);

            let _ = self.skipped_keys.insert((key_prefix, self.recv_count), message_key);


            let mut new_chain = [0u8; 32];
            Hkdf::derive(&self.recv_chain_key, b"chain-advance", CHAIN_KEY_INFO, &mut new_chain);
            self.recv_chain_key = new_chain;
            self.recv_count += 1;
        }

        Ok(())
    }


    fn get_message_key(&mut self, header: &MessageHeader) -> Result<[u8; 32], SessionError> {

        let mut key_prefix = [0u8; 8];
        key_prefix.copy_from_slice(&header.dh_public[..8]);

        if let Some(key) = self.skipped_keys.remove(&(key_prefix, header.message_num)) {
            return Ok(key);
        }


        if header.message_num > self.recv_count {
            self.skip_message_keys(header.message_num)?;
        }


        let mut message_key = [0u8; 32];
        Hkdf::derive(&self.recv_chain_key, &header.message_num.to_le_bytes(), MESSAGE_KEY_INFO, &mut message_key);


        let mut new_chain = [0u8; 32];
        Hkdf::derive(&self.recv_chain_key, b"chain-advance", CHAIN_KEY_INFO, &mut new_chain);
        self.recv_chain_key = new_chain;
        self.recv_count = header.message_num + 1;

        Ok(message_key)
    }


    fn compute_tag(key: &[u8; 32], header: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        use crate::crypto::sha256::Sha256;


        let mut inner = [0x36u8; 64];
        let mut outer = [0x5cu8; 64];

        for (i, k) in key.iter().enumerate() {
            inner[i] ^= k;
            outer[i] ^= k;
        }


        let mut hasher_data = HeaplessVec::<u8, 512>::new();
        let _ = hasher_data.extend_from_slice(&inner);
        let _ = hasher_data.extend_from_slice(header);
        let _ = hasher_data.extend_from_slice(ciphertext);
        let inner_hash = Sha256::hash(&hasher_data);


        let mut outer_data = [0u8; 96];
        outer_data[..64].copy_from_slice(&outer);
        outer_data[64..].copy_from_slice(&inner_hash);
        let full_tag = Sha256::hash(&outer_data);


        let mut tag = [0u8; 16];
        tag.copy_from_slice(&full_tag[..16]);
        tag
    }
}


pub struct SessionManager {


    sessions: HashMap<[u8; 8], Session>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }


    pub fn get_session(&mut self, peer_public: &[u8; 32]) -> Option<&mut Session> {
        let mut key = [0u8; 8];
        key.copy_from_slice(&peer_public[..8]);
        self.sessions.get_mut(&key)
    }


    pub fn create_session(&mut self, params: SessionParams) {
        let mut key = [0u8; 8];
        key.copy_from_slice(&params.their_public[..8]);

        let session = Session::new(params);
        self.sessions.insert(key, session);
    }


    pub fn remove_session(&mut self, peer_public: &[u8; 32]) {
        let mut key = [0u8; 8];
        key.copy_from_slice(&peer_public[..8]);
        self.sessions.remove(&key);
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}


const SESSION_SERIALIZED_SIZE: usize = 225;

impl Session {


    pub fn serialize(&self) -> [u8; SESSION_SERIALIZED_SIZE] {
        let mut buf = [0u8; SESSION_SERIALIZED_SIZE];
        let mut pos = 0;

        buf[pos..pos + 32].copy_from_slice(&self.root_key);
        pos += 32;
        buf[pos..pos + 32].copy_from_slice(&self.send_chain_key);
        pos += 32;
        buf[pos..pos + 32].copy_from_slice(&self.recv_chain_key);
        pos += 32;
        buf[pos..pos + 32].copy_from_slice(&self.send_ratchet_private);
        pos += 32;
        buf[pos..pos + 32].copy_from_slice(&self.send_ratchet_public);
        pos += 32;
        buf[pos..pos + 32].copy_from_slice(&self.recv_ratchet_public);
        pos += 32;
        buf[pos..pos + 8].copy_from_slice(&self.send_count.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.recv_count.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.prev_recv_chain.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.last_ratchet_time.to_le_bytes());
        pos += 8;
        buf[pos] = if self.established { 1 } else { 0 };

        buf
    }


    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < SESSION_SERIALIZED_SIZE {
            return None;
        }

        let mut pos = 0;

        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let mut send_chain_key = [0u8; 32];
        send_chain_key.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let mut recv_chain_key = [0u8; 32];
        recv_chain_key.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let mut send_ratchet_private = [0u8; 32];
        send_ratchet_private.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let mut send_ratchet_public = [0u8; 32];
        send_ratchet_public.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let mut recv_ratchet_public = [0u8; 32];
        recv_ratchet_public.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let mut u64_bytes = [0u8; 8];

        u64_bytes.copy_from_slice(&data[pos..pos + 8]);
        let send_count = u64::from_le_bytes(u64_bytes);
        pos += 8;

        u64_bytes.copy_from_slice(&data[pos..pos + 8]);
        let recv_count = u64::from_le_bytes(u64_bytes);
        pos += 8;

        u64_bytes.copy_from_slice(&data[pos..pos + 8]);
        let prev_recv_chain = u64::from_le_bytes(u64_bytes);
        pos += 8;

        u64_bytes.copy_from_slice(&data[pos..pos + 8]);
        let last_ratchet_time = u64::from_le_bytes(u64_bytes);
        pos += 8;

        let established = data[pos] != 0;

        Some(Self {
            root_key,
            send_chain_key,
            recv_chain_key,
            send_ratchet_private,
            send_ratchet_public,
            recv_ratchet_public,
            send_count,
            recv_count,
            prev_recv_chain,
            last_ratchet_time,
            skipped_keys: HashMap::new(),
            established,
        })
    }
}


const NVS_SESSION_NAMESPACE: &[u8] = b"sessions\0";

const MAX_PERSISTED_SESSIONS: usize = 32;

impl SessionManager {


    #[cfg(target_arch = "xtensa")]
    pub fn save_to_nvs(&self) -> Result<(), SessionError> {
        use esp_idf_sys::*;

        unsafe {

            let mut handle: nvs_handle_t = 0;
            let namespace = core::ffi::CStr::from_ptr(NVS_SESSION_NAMESPACE.as_ptr() as *const core::ffi::c_char);


            let mut err = nvs_open(
                namespace.as_ptr(),
                nvs_open_mode_t_NVS_READWRITE,
                &mut handle,
            );

            if err != ESP_OK {
                nvs_flash_init();
                err = nvs_open(
                    namespace.as_ptr(),
                    nvs_open_mode_t_NVS_READWRITE,
                    &mut handle,
                );
                if err != ESP_OK {
                    return Err(SessionError::KeyDerivationFailed);
                }
            }


            let count_key = core::ffi::CStr::from_ptr(b"sess_count\0".as_ptr() as *const core::ffi::c_char);
            nvs_set_u32(handle, count_key.as_ptr(), self.sessions.len() as u32);


            let mut idx = 0u32;
            for (key, session) in self.sessions.iter() {

                let mut key_name = [0u8; 16];
                let prefix = b"sess_";
                key_name[..5].copy_from_slice(prefix);

                if idx < 10 {
                    key_name[5] = b'0' + idx as u8;
                    key_name[6] = 0;
                } else {
                    key_name[5] = b'0' + (idx / 10) as u8;
                    key_name[6] = b'0' + (idx % 10) as u8;
                    key_name[7] = 0;
                }
                let key_cstr = core::ffi::CStr::from_ptr(key_name.as_ptr() as *const core::ffi::c_char);


                let mut blob = [0u8; 8 + SESSION_SERIALIZED_SIZE];
                blob[..8].copy_from_slice(key);
                blob[8..].copy_from_slice(&session.serialize());

                nvs_set_blob(
                    handle,
                    key_cstr.as_ptr(),
                    blob.as_ptr() as *const _,
                    blob.len(),
                );

                idx += 1;
            }


            nvs_commit(handle);
            nvs_close(handle);

            ::log::info!("Saved {} sessions to NVS", self.sessions.len());
        }

        Ok(())
    }


    #[cfg(target_arch = "xtensa")]
    pub fn load_from_nvs(&mut self) -> Result<usize, SessionError> {
        use esp_idf_sys::*;

        unsafe {

            let mut handle: nvs_handle_t = 0;
            let namespace = core::ffi::CStr::from_ptr(NVS_SESSION_NAMESPACE.as_ptr() as *const core::ffi::c_char);

            let err = nvs_open(
                namespace.as_ptr(),
                nvs_open_mode_t_NVS_READONLY,
                &mut handle,
            );

            if err != ESP_OK {
                return Ok(0);
            }


            let count_key = core::ffi::CStr::from_ptr(b"sess_count\0".as_ptr() as *const core::ffi::c_char);
            let mut count: u32 = 0;
            if nvs_get_u32(handle, count_key.as_ptr(), &mut count) != ESP_OK {
                nvs_close(handle);
                return Ok(0);
            }

            let count = core::cmp::min(count as usize, MAX_PERSISTED_SESSIONS);


            let mut loaded = 0;
            for idx in 0..count {

                let mut key_name = [0u8; 16];
                let prefix = b"sess_";
                key_name[..5].copy_from_slice(prefix);
                if idx < 10 {
                    key_name[5] = b'0' + idx as u8;
                    key_name[6] = 0;
                } else {
                    key_name[5] = b'0' + (idx / 10) as u8;
                    key_name[6] = b'0' + (idx % 10) as u8;
                    key_name[7] = 0;
                }
                let key_cstr = core::ffi::CStr::from_ptr(key_name.as_ptr() as *const core::ffi::c_char);


                let mut blob = [0u8; 8 + SESSION_SERIALIZED_SIZE];
                let mut blob_len = blob.len();

                if nvs_get_blob(
                    handle,
                    key_cstr.as_ptr(),
                    blob.as_mut_ptr() as *mut _,
                    &mut blob_len,
                ) == ESP_OK && blob_len == blob.len()
                {

                    let mut peer_key = [0u8; 8];
                    peer_key.copy_from_slice(&blob[..8]);


                    if let Some(session) = Session::deserialize(&blob[8..]) {
                        let _ = self.sessions.insert(peer_key, session);
                        loaded += 1;
                    }
                }
            }

            nvs_close(handle);
            ::log::info!("Loaded {} sessions from NVS", loaded);
            Ok(loaded)
        }
    }


    #[cfg(not(target_arch = "xtensa"))]
    pub fn save_to_nvs(&self) -> Result<(), SessionError> {
        Ok(())
    }

    #[cfg(not(target_arch = "xtensa"))]
    pub fn load_from_nvs(&mut self) -> Result<usize, SessionError> {
        Ok(0)
    }


    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_encrypt_decrypt() {

        let alice_private = [1u8; 32];
        let bob_private = [2u8; 32];

        let alice_public = x25519_base(&alice_private);
        let bob_public = x25519_base(&bob_private);


        let shared = x25519(&alice_private, &bob_public);

        let alice_params = SessionParams {
            shared_secret: shared,
            our_private: alice_private,
            their_public: bob_public,
            is_initiator: true,
        };

        let bob_params = SessionParams {
            shared_secret: shared,
            our_private: bob_private,
            their_public: alice_public,
            is_initiator: false,
        };

        let mut alice = Session::new(alice_params);
        let mut bob = Session::new(bob_params);


        let message = b"Hello, Bob!";
        let (header, ciphertext) = alice.encrypt(message).unwrap();


        let plaintext = bob.decrypt(&header, &ciphertext).unwrap();
        assert_eq!(&plaintext[..message.len()], message);
    }
}
