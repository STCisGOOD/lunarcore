use crate::crypto::{
    sha256::Sha256,
    ed25519::{Ed25519, Signature},
};
use heapless::Vec as HeaplessVec;

pub const CONTACT_HELLO_VERSION: u8 = 0x03;

pub const ED25519_PK_SIZE: usize = 32;

pub const X25519_PK_SIZE: usize = 32;

pub const ED25519_SIG_SIZE: usize = 64;

pub const HASH_SIZE: usize = 32;

pub const MAX_DID_LENGTH: usize = 128;

pub const MAX_NAME_LENGTH: usize = 64;

pub const DILITHIUM_PK_SIZE: usize = 1952;

pub const DILITHIUM_SIG_SIZE: usize = 2420;

#[derive(Debug, Clone)]
pub struct ContactHello {

    pub version: u8,

    pub timestamp: u64,

    pub did: HeaplessVec<u8, MAX_DID_LENGTH>,

    pub ed25519_public: [u8; ED25519_PK_SIZE],

    pub x25519_public: [u8; X25519_PK_SIZE],

    pub name: HeaplessVec<u8, MAX_NAME_LENGTH>,

    pub avatar_hash: [u8; HASH_SIZE],

    pub signature: [u8; ED25519_SIG_SIZE],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactHelloError {

    InvalidVersion,

    InvalidFormat,

    SignatureInvalid,

    BufferTooSmall,

    DidTooLong,

    NameTooLong,
}

impl ContactHello {

    pub fn new(
        timestamp: u64,
        did: &[u8],
        ed25519_public: [u8; 32],
        x25519_public: [u8; 32],
        name: &[u8],
        avatar_hash: Option<[u8; 32]>,
    ) -> Result<Self, ContactHelloError> {
        if did.len() > MAX_DID_LENGTH {
            return Err(ContactHelloError::DidTooLong);
        }
        if name.len() > MAX_NAME_LENGTH {
            return Err(ContactHelloError::NameTooLong);
        }

        let mut did_vec = HeaplessVec::new();
        did_vec.extend_from_slice(did).map_err(|_| ContactHelloError::DidTooLong)?;

        let mut name_vec = HeaplessVec::new();
        name_vec.extend_from_slice(name).map_err(|_| ContactHelloError::NameTooLong)?;

        Ok(Self {
            version: CONTACT_HELLO_VERSION,
            timestamp,
            did: did_vec,
            ed25519_public,
            x25519_public,
            name: name_vec,
            avatar_hash: avatar_hash.unwrap_or([0u8; 32]),
            signature: [0u8; 64],
        })
    }

    pub fn sign(&mut self, private_key: &[u8; 32]) {
        let data_to_sign = self.encode_for_signing();
        let sig = Ed25519::sign(private_key, &data_to_sign);
        self.signature = sig.0;
    }

    pub fn verify(&self) -> Result<bool, ContactHelloError> {
        let data = self.encode_for_signing();
        let sig = Signature(self.signature);
        Ok(Ed25519::verify(&self.ed25519_public, &data, &sig))
    }

    fn encode_for_signing(&self) -> HeaplessVec<u8, 256> {
        let mut buf = HeaplessVec::new();

        let _ = buf.push(self.version);

        let _ = buf.extend_from_slice(&self.timestamp.to_le_bytes());

        let did_len = self.did.len() as u16;
        let _ = buf.extend_from_slice(&did_len.to_le_bytes());
        let _ = buf.extend_from_slice(&self.did);

        let _ = buf.extend_from_slice(&self.ed25519_public);

        let _ = buf.extend_from_slice(&self.x25519_public);

        let _ = buf.push(self.name.len() as u8);
        let _ = buf.extend_from_slice(&self.name);

        let _ = buf.extend_from_slice(&self.avatar_hash);

        buf
    }

    pub fn encode(&self) -> HeaplessVec<u8, 512> {
        let signed_data = self.encode_for_signing();
        let mut buf = HeaplessVec::new();
        let _ = buf.extend_from_slice(&signed_data);
        let _ = buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, ContactHelloError> {
        if data.len() < 1 + 8 + 2 + 32 + 32 + 1 + 32 + 64 {
            return Err(ContactHelloError::InvalidFormat);
        }

        let mut pos = 0;

        let version = data[pos];
        if version != CONTACT_HELLO_VERSION {
            return Err(ContactHelloError::InvalidVersion);
        }
        pos += 1;

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&data[pos..pos + 8]);
        let timestamp = u64::from_le_bytes(ts_bytes);
        pos += 8;

        let mut did_len_bytes = [0u8; 2];
        did_len_bytes.copy_from_slice(&data[pos..pos + 2]);
        let did_len = u16::from_le_bytes(did_len_bytes) as usize;
        pos += 2;

        if did_len > MAX_DID_LENGTH || pos + did_len > data.len() {
            return Err(ContactHelloError::DidTooLong);
        }

        let mut did = HeaplessVec::new();
        did.extend_from_slice(&data[pos..pos + did_len])
            .map_err(|_| ContactHelloError::DidTooLong)?;
        pos += did_len;

        if pos + 32 > data.len() {
            return Err(ContactHelloError::InvalidFormat);
        }
        let mut ed25519_public = [0u8; 32];
        ed25519_public.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        if pos + 32 > data.len() {
            return Err(ContactHelloError::InvalidFormat);
        }
        let mut x25519_public = [0u8; 32];
        x25519_public.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        if pos >= data.len() {
            return Err(ContactHelloError::InvalidFormat);
        }
        let name_len = data[pos] as usize;
        pos += 1;

        if name_len > MAX_NAME_LENGTH || pos + name_len > data.len() {
            return Err(ContactHelloError::NameTooLong);
        }

        let mut name = HeaplessVec::new();
        name.extend_from_slice(&data[pos..pos + name_len])
            .map_err(|_| ContactHelloError::NameTooLong)?;
        pos += name_len;

        if pos + 32 > data.len() {
            return Err(ContactHelloError::InvalidFormat);
        }
        let mut avatar_hash = [0u8; 32];
        avatar_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        if pos + 64 > data.len() {
            return Err(ContactHelloError::InvalidFormat);
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[pos..pos + 64]);

        Ok(Self {
            version,
            timestamp,
            did,
            ed25519_public,
            x25519_public,
            name,
            avatar_hash,
            signature,
        })
    }

    pub fn to_qr_data(&self) -> HeaplessVec<u8, 512> {

        let mut buf = HeaplessVec::new();
        let _ = buf.extend_from_slice(b"YCH:");
        let _ = buf.extend_from_slice(&self.encode());
        buf
    }

    pub fn from_qr_data(data: &[u8]) -> Result<Self, ContactHelloError> {
        if data.len() < 4 || &data[..4] != b"YCH:" {
            return Err(ContactHelloError::InvalidFormat);
        }
        Self::decode(&data[4..])
    }

    pub fn fingerprint(&self) -> [u8; 8] {
        let hash = Sha256::hash(&self.ed25519_public);
        let mut fp = [0u8; 8];
        fp.copy_from_slice(&hash[..8]);
        fp
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {

    Unknown = 0,

    Seen = 1,

    Verified = 2,

    Trusted = 3,
}

#[derive(Debug, Clone)]
pub struct Contact {

    pub hello: ContactHello,

    pub trust: TrustLevel,

    pub petname: HeaplessVec<u8, MAX_NAME_LENGTH>,

    pub last_seen: u64,

    pub message_count: u32,
}

impl Contact {
    pub fn from_hello(hello: ContactHello) -> Self {
        Self {
            hello,
            trust: TrustLevel::Unknown,
            petname: HeaplessVec::new(),
            last_seen: 0,
            message_count: 0,
        }
    }

    pub fn set_petname(&mut self, name: &[u8]) {
        self.petname.clear();
        let _ = self.petname.extend_from_slice(name);
    }

    pub fn display_name(&self) -> &[u8] {
        if !self.petname.is_empty() {
            &self.petname
        } else {
            &self.hello.name
        }
    }

    pub fn serialize(&self) -> HeaplessVec<u8, 512> {
        let mut buf = HeaplessVec::new();

        let hello_encoded = self.hello.encode();
        let hello_len = hello_encoded.len() as u16;
        let _ = buf.extend_from_slice(&hello_len.to_le_bytes());
        let _ = buf.extend_from_slice(&hello_encoded);

        let _ = buf.push(self.trust as u8);

        let _ = buf.push(self.petname.len() as u8);
        let _ = buf.extend_from_slice(&self.petname);

        let _ = buf.extend_from_slice(&self.last_seen.to_le_bytes());

        let _ = buf.extend_from_slice(&self.message_count.to_le_bytes());

        buf
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        let mut pos = 0;

        let mut hello_len_bytes = [0u8; 2];
        hello_len_bytes.copy_from_slice(&data[pos..pos + 2]);
        let hello_len = u16::from_le_bytes(hello_len_bytes) as usize;
        pos += 2;

        if pos + hello_len > data.len() {
            return None;
        }

        let hello = ContactHello::decode(&data[pos..pos + hello_len]).ok()?;
        pos += hello_len;

        if pos >= data.len() {
            return None;
        }
        let trust = match data[pos] {
            0 => TrustLevel::Unknown,
            1 => TrustLevel::Seen,
            2 => TrustLevel::Verified,
            3 => TrustLevel::Trusted,
            _ => TrustLevel::Unknown,
        };
        pos += 1;

        if pos >= data.len() {
            return None;
        }
        let petname_len = data[pos] as usize;
        pos += 1;

        if pos + petname_len > data.len() {
            return None;
        }
        let mut petname = HeaplessVec::new();
        let _ = petname.extend_from_slice(&data[pos..pos + petname_len]);
        pos += petname_len;

        if pos + 8 > data.len() {
            return None;
        }
        let mut last_seen_bytes = [0u8; 8];
        last_seen_bytes.copy_from_slice(&data[pos..pos + 8]);
        let last_seen = u64::from_le_bytes(last_seen_bytes);
        pos += 8;

        if pos + 4 > data.len() {
            return None;
        }
        let mut count_bytes = [0u8; 4];
        count_bytes.copy_from_slice(&data[pos..pos + 4]);
        let message_count = u32::from_le_bytes(count_bytes);

        Some(Self {
            hello,
            trust,
            petname,
            last_seen,
            message_count,
        })
    }

    pub fn key(&self) -> [u8; 8] {
        self.hello.fingerprint()
    }
}

const NVS_CONTACT_NAMESPACE: &[u8] = b"contacts\0";

const MAX_CONTACTS: usize = 64;

pub struct ContactStore {

    contacts: heapless::FnvIndexMap<[u8; 8], Contact, MAX_CONTACTS>,
}

impl ContactStore {
    pub fn new() -> Self {
        Self {
            contacts: heapless::FnvIndexMap::new(),
        }
    }

    pub fn add(&mut self, contact: Contact) -> Result<(), ContactHelloError> {
        let key = contact.key();
        let _ = self.contacts.insert(key, contact);
        Ok(())
    }

    pub fn get(&self, fingerprint: &[u8; 8]) -> Option<&Contact> {
        self.contacts.get(fingerprint)
    }

    pub fn get_mut(&mut self, fingerprint: &[u8; 8]) -> Option<&mut Contact> {
        self.contacts.get_mut(fingerprint)
    }

    pub fn remove(&mut self, fingerprint: &[u8; 8]) -> Option<Contact> {
        self.contacts.remove(fingerprint)
    }

    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 8], &Contact)> {
        self.contacts.iter()
    }

    pub fn find_by_pubkey(&self, ed25519_public: &[u8; 32]) -> Option<&Contact> {
        self.contacts.values().find(|c| &c.hello.ed25519_public == ed25519_public)
    }

    #[cfg(target_arch = "xtensa")]
    pub fn save_to_nvs(&self) -> Result<(), ContactHelloError> {
        use esp_idf_sys::*;

        unsafe {

            let mut handle: nvs_handle_t = 0;
            let namespace = core::ffi::CStr::from_ptr(
                NVS_CONTACT_NAMESPACE.as_ptr() as *const core::ffi::c_char
            );

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
                    return Err(ContactHelloError::BufferTooSmall);
                }
            }

            let count_key = core::ffi::CStr::from_ptr(
                b"cnt_count\0".as_ptr() as *const core::ffi::c_char
            );
            nvs_set_u32(handle, count_key.as_ptr(), self.contacts.len() as u32);

            let mut idx = 0u32;
            for (_key, contact) in self.contacts.iter() {

                let mut key_name = [0u8; 16];
                let prefix = b"cnt_";
                key_name[..4].copy_from_slice(prefix);
                if idx < 10 {
                    key_name[4] = b'0' + idx as u8;
                    key_name[5] = 0;
                } else {
                    key_name[4] = b'0' + (idx / 10) as u8;
                    key_name[5] = b'0' + (idx % 10) as u8;
                    key_name[6] = 0;
                }
                let key_cstr = core::ffi::CStr::from_ptr(
                    key_name.as_ptr() as *const core::ffi::c_char
                );

                let blob = contact.serialize();

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

            ::log::info!("Saved {} contacts to NVS", self.contacts.len());
        }

        Ok(())
    }

    #[cfg(target_arch = "xtensa")]
    pub fn load_from_nvs(&mut self) -> Result<usize, ContactHelloError> {
        use esp_idf_sys::*;

        unsafe {

            let mut handle: nvs_handle_t = 0;
            let namespace = core::ffi::CStr::from_ptr(
                NVS_CONTACT_NAMESPACE.as_ptr() as *const core::ffi::c_char
            );

            let err = nvs_open(
                namespace.as_ptr(),
                nvs_open_mode_t_NVS_READONLY,
                &mut handle,
            );

            if err != ESP_OK {
                return Ok(0);
            }

            let count_key = core::ffi::CStr::from_ptr(
                b"cnt_count\0".as_ptr() as *const core::ffi::c_char
            );
            let mut count: u32 = 0;
            if nvs_get_u32(handle, count_key.as_ptr(), &mut count) != ESP_OK {
                nvs_close(handle);
                return Ok(0);
            }

            let count = core::cmp::min(count as usize, MAX_CONTACTS);

            let mut loaded = 0;
            for idx in 0..count {

                let mut key_name = [0u8; 16];
                let prefix = b"cnt_";
                key_name[..4].copy_from_slice(prefix);
                if idx < 10 {
                    key_name[4] = b'0' + idx as u8;
                    key_name[5] = 0;
                } else {
                    key_name[4] = b'0' + (idx / 10) as u8;
                    key_name[5] = b'0' + (idx % 10) as u8;
                    key_name[6] = 0;
                }
                let key_cstr = core::ffi::CStr::from_ptr(
                    key_name.as_ptr() as *const core::ffi::c_char
                );

                let mut blob = [0u8; 512];
                let mut blob_len = blob.len();

                if nvs_get_blob(
                    handle,
                    key_cstr.as_ptr(),
                    blob.as_mut_ptr() as *mut _,
                    &mut blob_len,
                ) == ESP_OK && blob_len > 0
                {

                    if let Some(contact) = Contact::deserialize(&blob[..blob_len]) {
                        let key = contact.key();
                        let _ = self.contacts.insert(key, contact);
                        loaded += 1;
                    }
                }
            }

            nvs_close(handle);
            ::log::info!("Loaded {} contacts from NVS", loaded);
            Ok(loaded)
        }
    }

    #[cfg(not(target_arch = "xtensa"))]
    pub fn save_to_nvs(&self) -> Result<(), ContactHelloError> {
        Ok(())
    }

    #[cfg(not(target_arch = "xtensa"))]
    pub fn load_from_nvs(&mut self) -> Result<usize, ContactHelloError> {
        Ok(0)
    }
}
