use crate::crypto::sha256::Sha256;
use crate::crypto::ed25519;


pub const OTA_CHUNK_SIZE: usize = 4096;


pub const MAX_FIRMWARE_SIZE: usize = 3_584_000;


pub const OTA_HEADER_MAGIC: [u8; 4] = [0x4C, 0x55, 0x4E, 0x41];


pub const OTA_HEADER_VERSION: u8 = 1;


pub const SIGNATURE_SIZE: usize = 64;


pub const PUBLIC_KEY_SIZE: usize = 32;


#[inline(never)]
fn ct_key_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}


#[inline]
fn pack_version(major: u8, minor: u8, patch: u8) -> u32 {
    ((major as u32) << 16) | ((minor as u32) << 8) | (patch as u32)
}


#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct OtaHeader {

    pub magic: [u8; 4],

    pub version: u8,

    pub header_size: u8,

    pub fw_major: u8,

    pub fw_minor: u8,

    pub fw_patch: u8,

    pub reserved: [u8; 3],

    pub firmware_size: u32,

    pub firmware_hash: [u8; 32],

    pub signature: [u8; SIGNATURE_SIZE],

    pub public_key: [u8; PUBLIC_KEY_SIZE],
}

impl OtaHeader {

    pub const SIZE: usize = 4 + 1 + 1 + 3 + 3 + 4 + 32 + 64 + 32;


    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);

        if magic != OTA_HEADER_MAGIC {
            return None;
        }

        let version = data[4];
        if version != OTA_HEADER_VERSION {
            return None;
        }

        let header_size = data[5];
        let fw_major = data[6];
        let fw_minor = data[7];
        let fw_patch = data[8];

        let mut reserved = [0u8; 3];
        reserved.copy_from_slice(&data[9..12]);

        let firmware_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

        let mut firmware_hash = [0u8; 32];
        firmware_hash.copy_from_slice(&data[16..48]);

        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&data[48..112]);

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(&data[112..144]);

        Some(Self {
            magic,
            version,
            header_size,
            fw_major,
            fw_minor,
            fw_patch,
            reserved,
            firmware_size,
            firmware_hash,
            signature,
            public_key,
        })
    }


    pub fn version_string(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        let mut idx = 0;


        idx += write_u8_to_buf(self.fw_major, &mut buf[idx..]);
        buf[idx] = b'.';
        idx += 1;


        idx += write_u8_to_buf(self.fw_minor, &mut buf[idx..]);
        buf[idx] = b'.';
        idx += 1;


        write_u8_to_buf(self.fw_patch, &mut buf[idx..]);

        buf
    }
}

fn write_u8_to_buf(val: u8, buf: &mut [u8]) -> usize {
    if val >= 100 {
        buf[0] = b'0' + val / 100;
        buf[1] = b'0' + (val / 10) % 10;
        buf[2] = b'0' + val % 10;
        3
    } else if val >= 10 {
        buf[0] = b'0' + val / 10;
        buf[1] = b'0' + val % 10;
        2
    } else {
        buf[0] = b'0' + val;
        1
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaState {

    Idle,

    ReceivingHeader,

    Receiving,

    Verifying,

    Writing,

    Complete,

    Error(OtaError),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaError {

    InvalidHeader,

    SignatureInvalid,

    HashMismatch,

    TooLarge,

    FlashError,

    PartitionError,

    Busy,

    Aborted,

    Timeout,

    RolledBack,

    DowngradeRejected,

    NoTrustedKeys,
}


pub struct OtaManager {

    state: OtaState,

    header_buf: [u8; OtaHeader::SIZE],

    header_received: usize,

    header: Option<OtaHeader>,

    bytes_received: u32,

    hasher: Sha256,

    partition_handle: i32,

    ota_handle: u32,

    trusted_keys: [[u8; PUBLIC_KEY_SIZE]; 2],

    trusted_key_count: usize,

    progress_percent: u8,


    min_version: u32,
}

impl OtaManager {

    pub fn new() -> Self {
        Self {
            state: OtaState::Idle,
            header_buf: [0u8; OtaHeader::SIZE],
            header_received: 0,
            header: None,
            bytes_received: 0,
            hasher: Sha256::new(),
            partition_handle: -1,
            ota_handle: 0,
            trusted_keys: [[0u8; PUBLIC_KEY_SIZE]; 2],
            trusted_key_count: 0,
            progress_percent: 0,
            min_version: 0,
        }
    }


    pub fn add_trusted_key(&mut self, key: &[u8; PUBLIC_KEY_SIZE]) -> bool {
        if self.trusted_key_count >= 2 {
            return false;
        }
        self.trusted_keys[self.trusted_key_count].copy_from_slice(key);
        self.trusted_key_count += 1;
        true
    }


    pub fn set_min_version(&mut self, major: u8, minor: u8, patch: u8) {
        self.min_version = pack_version(major, minor, patch);
    }


    fn is_version_allowed(&self, header: &OtaHeader) -> bool {
        let new_version = pack_version(header.fw_major, header.fw_minor, header.fw_patch);
        new_version >= self.min_version
    }


    pub fn state(&self) -> OtaState {
        self.state
    }


    pub fn progress(&self) -> u8 {
        self.progress_percent
    }


    pub fn begin(&mut self) -> Result<(), OtaError> {
        if self.state != OtaState::Idle {
            return Err(OtaError::Busy);
        }


        self.header_buf.fill(0);
        self.header_received = 0;
        self.header = None;
        self.bytes_received = 0;
        self.hasher = Sha256::new();
        self.progress_percent = 0;


        unsafe {
            let next_partition = esp_idf_sys::esp_ota_get_next_update_partition(core::ptr::null());
            if next_partition.is_null() {
                return Err(OtaError::PartitionError);
            }


            let mut handle: esp_idf_sys::esp_ota_handle_t = 0;
            let ret = esp_idf_sys::esp_ota_begin(next_partition, 0, &mut handle);
            if ret != 0 {
                return Err(OtaError::FlashError);
            }

            self.ota_handle = handle;
        }

        self.state = OtaState::ReceivingHeader;
        Ok(())
    }


    pub fn write(&mut self, data: &[u8]) -> Result<usize, OtaError> {
        match self.state {
            OtaState::Idle => Err(OtaError::Aborted),
            OtaState::Error(e) => Err(e),
            OtaState::ReceivingHeader => self.write_header(data),
            OtaState::Receiving | OtaState::Writing => self.write_firmware(data),
            _ => Ok(0),
        }
    }


    fn write_header(&mut self, data: &[u8]) -> Result<usize, OtaError> {
        let needed = OtaHeader::SIZE - self.header_received;
        let to_copy = data.len().min(needed);

        self.header_buf[self.header_received..self.header_received + to_copy]
            .copy_from_slice(&data[..to_copy]);
        self.header_received += to_copy;

        if self.header_received >= OtaHeader::SIZE {

            let header = OtaHeader::from_bytes(&self.header_buf)
                .ok_or(OtaError::InvalidHeader)?;


            if header.firmware_size as usize > MAX_FIRMWARE_SIZE {
                self.state = OtaState::Error(OtaError::TooLarge);
                return Err(OtaError::TooLarge);
            }


            if self.trusted_key_count == 0 {
                self.state = OtaState::Error(OtaError::NoTrustedKeys);
                return Err(OtaError::NoTrustedKeys);
            }


            if !self.is_version_allowed(&header) {
                self.state = OtaState::Error(OtaError::DowngradeRejected);
                return Err(OtaError::DowngradeRejected);
            }


            if !self.verify_signature(&header) {
                self.state = OtaState::Error(OtaError::SignatureInvalid);
                return Err(OtaError::SignatureInvalid);
            }

            self.header = Some(header);
            self.state = OtaState::Receiving;


            if to_copy < data.len() {
                let remaining = &data[to_copy..];
                return self.write_firmware(remaining).map(|n| to_copy + n);
            }
        }

        Ok(to_copy)
    }


    fn write_firmware(&mut self, data: &[u8]) -> Result<usize, OtaError> {
        let header = self.header.as_ref().ok_or(OtaError::InvalidHeader)?;

        let remaining = header.firmware_size - self.bytes_received;
        let to_write = (data.len() as u32).min(remaining) as usize;

        if to_write == 0 {
            return Ok(0);
        }


        self.hasher.update(&data[..to_write]);


        unsafe {
            let ret = esp_idf_sys::esp_ota_write(
                self.ota_handle,
                data.as_ptr() as *const core::ffi::c_void,
                to_write,
            );

            if ret != 0 {
                self.state = OtaState::Error(OtaError::FlashError);
                return Err(OtaError::FlashError);
            }
        }

        self.bytes_received += to_write as u32;


        self.progress_percent = ((self.bytes_received as u64 * 100) / header.firmware_size as u64) as u8;


        if self.bytes_received >= header.firmware_size {
            self.state = OtaState::Verifying;
            self.verify_and_finish()?;
        }

        Ok(to_write)
    }


    fn verify_and_finish(&mut self) -> Result<(), OtaError> {
        let header = self.header.as_ref().ok_or(OtaError::InvalidHeader)?;


        let computed_hash = self.hasher.clone().finalize();


        if computed_hash != header.firmware_hash {
            self.state = OtaState::Error(OtaError::HashMismatch);
            self.abort();
            return Err(OtaError::HashMismatch);
        }


        unsafe {
            let ret = esp_idf_sys::esp_ota_end(self.ota_handle);
            if ret != 0 {
                self.state = OtaState::Error(OtaError::FlashError);
                return Err(OtaError::FlashError);
            }

            let next_partition = esp_idf_sys::esp_ota_get_next_update_partition(core::ptr::null());
            let ret = esp_idf_sys::esp_ota_set_boot_partition(next_partition);
            if ret != 0 {
                self.state = OtaState::Error(OtaError::PartitionError);
                return Err(OtaError::PartitionError);
            }
        }

        self.state = OtaState::Complete;
        self.progress_percent = 100;
        Ok(())
    }


    fn verify_signature(&self, header: &OtaHeader) -> bool {


        if self.trusted_key_count == 0 {


            return false;
        }


        for i in 0..self.trusted_key_count {

            if ct_key_eq(&header.public_key, &self.trusted_keys[i]) {

                let signature = ed25519::Signature(header.signature);
                if ed25519::Ed25519::verify(&header.public_key, &header.firmware_hash, &signature) {
                    return true;
                }
            }
        }

        false
    }


    pub fn is_enabled(&self) -> bool {
        self.trusted_key_count > 0
    }


    pub fn trusted_key_count(&self) -> usize {
        self.trusted_key_count
    }


    pub fn abort(&mut self) {
        if self.ota_handle != 0 {
            unsafe {
                esp_idf_sys::esp_ota_abort(self.ota_handle);
            }
            self.ota_handle = 0;
        }
        self.state = OtaState::Idle;
    }


    pub fn confirm() -> Result<(), OtaError> {
        unsafe {
            let ret = esp_idf_sys::esp_ota_mark_app_valid_cancel_rollback();
            if ret != 0 {
                return Err(OtaError::PartitionError);
            }
        }
        Ok(())
    }


    pub fn rollback() -> Result<(), OtaError> {
        unsafe {
            let ret = esp_idf_sys::esp_ota_mark_app_invalid_rollback_and_reboot();
            if ret != 0 {
                return Err(OtaError::RolledBack);
            }
        }
        Ok(())
    }


    pub fn get_running_partition() -> Option<PartitionInfo> {
        unsafe {
            let partition = esp_idf_sys::esp_ota_get_running_partition();
            if partition.is_null() {
                return None;
            }

            let part = &*partition;
            let mut label = [0u8; 16];
            label[..part.label.len()].copy_from_slice(
                core::slice::from_raw_parts(part.label.as_ptr() as *const u8, part.label.len())
            );

            Some(PartitionInfo {
                address: part.address,
                size: part.size,
                label,
            })
        }
    }


    pub fn reboot() -> ! {
        unsafe {
            esp_idf_sys::esp_restart();
        }
        loop {}
    }
}

impl Default for OtaManager {
    fn default() -> Self {
        Self::new()
    }
}


#[derive(Debug, Clone)]
pub struct PartitionInfo {

    pub address: u32,

    pub size: u32,

    pub label: [u8; 16],
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OtaCommand {

    Begin = 0x01,

    Data = 0x02,

    End = 0x03,

    Abort = 0x04,

    Status = 0x05,

    Confirm = 0x06,

    Rollback = 0x07,

    Reboot = 0x08,
}

impl From<u8> for OtaCommand {
    fn from(v: u8) -> Self {
        match v {
            0x01 => OtaCommand::Begin,
            0x02 => OtaCommand::Data,
            0x03 => OtaCommand::End,
            0x04 => OtaCommand::Abort,
            0x05 => OtaCommand::Status,
            0x06 => OtaCommand::Confirm,
            0x07 => OtaCommand::Rollback,
            0x08 => OtaCommand::Reboot,
            _ => OtaCommand::Status,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OtaResponse {

    Ok = 0x00,

    Error = 0x01,

    Busy = 0x02,

    Progress = 0x03,

    Complete = 0x04,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ota_header_size() {
        assert_eq!(OtaHeader::SIZE, 144);
    }

    #[test]
    fn test_version_string() {
        let header = OtaHeader {
            magic: OTA_HEADER_MAGIC,
            version: 1,
            header_size: OtaHeader::SIZE as u8,
            fw_major: 1,
            fw_minor: 2,
            fw_patch: 3,
            reserved: [0; 3],
            firmware_size: 0,
            firmware_hash: [0; 32],
            signature: [0; 64],
            public_key: [0; 32],
        };

        let version = header.version_string();
        assert_eq!(&version[..5], b"1.2.3");
    }

    #[test]
    fn test_pack_version() {
        assert_eq!(pack_version(1, 2, 3), 0x00010203);
        assert_eq!(pack_version(0, 0, 0), 0);
        assert_eq!(pack_version(255, 255, 255), 0x00FFFFFF);

        assert!(pack_version(2, 0, 0) > pack_version(1, 255, 255));
        assert!(pack_version(1, 1, 0) > pack_version(1, 0, 255));
        assert!(pack_version(1, 0, 1) > pack_version(1, 0, 0));
    }

    #[test]
    fn test_ct_key_eq() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        let c = [0x43u8; 32];

        assert!(ct_key_eq(&a, &b));
        assert!(!ct_key_eq(&a, &c));


        let mut d = a;
        d[31] ^= 1;
        assert!(!ct_key_eq(&a, &d));
    }

    #[test]
    fn test_version_allowed() {
        let mut manager = OtaManager::new();


        let header_100 = OtaHeader {
            magic: OTA_HEADER_MAGIC,
            version: 1,
            header_size: OtaHeader::SIZE as u8,
            fw_major: 1,
            fw_minor: 0,
            fw_patch: 0,
            reserved: [0; 3],
            firmware_size: 1000,
            firmware_hash: [0; 32],
            signature: [0; 64],
            public_key: [0; 32],
        };
        assert!(manager.is_version_allowed(&header_100));


        manager.set_min_version(1, 5, 0);


        assert!(!manager.is_version_allowed(&header_100));


        let mut header_150 = header_100;
        header_150.fw_minor = 5;
        assert!(manager.is_version_allowed(&header_150));


        let mut header_200 = header_100;
        header_200.fw_major = 2;
        assert!(manager.is_version_allowed(&header_200));
    }

    #[test]
    fn test_no_trusted_keys_disables_ota() {
        let manager = OtaManager::new();
        assert!(!manager.is_enabled());
        assert_eq!(manager.trusted_key_count(), 0);
    }

    #[test]
    fn test_trusted_key_limit() {
        let mut manager = OtaManager::new();
        let key = [0x42u8; 32];

        assert!(manager.add_trusted_key(&key));
        assert!(manager.add_trusted_key(&key));

        assert!(!manager.add_trusted_key(&key));
        assert_eq!(manager.trusted_key_count(), 2);
    }
}
