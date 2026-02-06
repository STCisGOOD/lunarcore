use heapless::Vec as HeaplessVec;


pub const MAX_PACKET_SIZE: usize = 237;

pub const NODE_HINT_SIZE: usize = 2;

pub const SESSION_HINT_SIZE: usize = 4;

pub const AUTH_TAG_SIZE: usize = 16;

pub const FLAGS_SIZE: usize = 1;

pub const DATA_OVERHEAD: usize = FLAGS_SIZE + NODE_HINT_SIZE + SESSION_HINT_SIZE + AUTH_TAG_SIZE;

pub const DATA_MAX_PAYLOAD: usize = MAX_PACKET_SIZE - DATA_OVERHEAD;

pub const PADDED_MESSAGE_SIZE: usize = 200;


#[derive(Debug, Clone)]
pub struct UniversalAddress {

    pub did: HeaplessVec<u8, 128>,

    pub public_key: [u8; 32],

    pub meshcore_addr: u16,

    pub meshtastic_id: u32,

    pub reticulum_hash: [u8; 16],
}


pub struct AddressTranslator;

impl AddressTranslator {

    pub fn from_public_key(public_key: &[u8; 32]) -> UniversalAddress {
        use crate::crypto::sha256::Sha256;


        let pubkey_hash = Sha256::hash(public_key);


        let meshcore_addr = ((pubkey_hash[0] as u16) << 8) | (pubkey_hash[1] as u16);


        let meshtastic_id = ((pubkey_hash[0] as u32) << 24)
            | ((pubkey_hash[1] as u32) << 16)
            | ((pubkey_hash[2] as u32) << 8)
            | (pubkey_hash[3] as u32);


        let app_hash = Sha256::hash(b"yours.messaging");
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&app_hash);
        combined[32..].copy_from_slice(public_key);
        let reticulum_full = Sha256::hash(&combined);
        let mut reticulum_hash = [0u8; 16];
        reticulum_hash.copy_from_slice(&reticulum_full[..16]);


        let mut did = HeaplessVec::new();
        let _ = did.extend_from_slice(b"did:offgrid:z");


        UniversalAddress {
            did,
            public_key: *public_key,
            meshcore_addr,
            meshtastic_id,
            reticulum_hash,
        }
    }


    pub fn derive_meshcore_address(public_key: &[u8; 32]) -> u16 {
        use crate::crypto::sha256::Sha256;
        let hash = Sha256::hash(public_key);
        ((hash[0] as u16) << 8) | (hash[1] as u16)
    }


    pub fn derive_meshtastic_id(public_key: &[u8; 32]) -> u32 {
        use crate::crypto::sha256::Sha256;
        let hash = Sha256::hash(public_key);
        ((hash[0] as u32) << 24)
            | ((hash[1] as u32) << 16)
            | ((hash[2] as u32) << 8)
            | (hash[3] as u32)
    }


    pub fn derive_reticulum_hash(public_key: &[u8; 32], app_name: &[u8]) -> [u8; 16] {
        use crate::crypto::sha256::Sha256;
        let app_hash = Sha256::hash(app_name);
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&app_hash);
        combined[32..].copy_from_slice(public_key);
        let full_hash = Sha256::hash(&combined);
        let mut result = [0u8; 16];
        result.copy_from_slice(&full_hash[..16]);
        result
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {

    Data = 0b00,

    Handshake = 0b01,

    Control = 0b10,

    Cover = 0b11,
}

impl PacketType {
    pub fn from_flags(flags: u8) -> Self {
        match (flags >> 6) & 0b11 {
            0b00 => PacketType::Data,
            0b01 => PacketType::Handshake,
            0b10 => PacketType::Control,
            0b11 => PacketType::Cover,
            _ => unreachable!(),
        }
    }
}


#[derive(Debug, Clone)]
pub struct WirePacket {

    pub packet_type: PacketType,

    pub hop_count: u8,

    pub next_hop_hint: u16,

    pub session_hint: u32,

    pub payload: HeaplessVec<u8, 214>,
}

impl WirePacket {

    pub fn new_data(next_hop: u16, session: u32, payload: &[u8]) -> Option<Self> {
        if payload.len() > DATA_MAX_PAYLOAD {
            return None;
        }
        let mut p = HeaplessVec::new();
        p.extend_from_slice(payload).ok()?;
        Some(Self {
            packet_type: PacketType::Data,
            hop_count: 0,
            next_hop_hint: next_hop,
            session_hint: session,
            payload: p,
        })
    }


    pub fn encode(&self) -> HeaplessVec<u8, 237> {
        let mut buf = HeaplessVec::new();


        let flags = ((self.packet_type as u8) << 6) | (self.hop_count & 0x0F);
        let _ = buf.push(flags);


        let _ = buf.push((self.next_hop_hint >> 8) as u8);
        let _ = buf.push(self.next_hop_hint as u8);


        let _ = buf.push((self.session_hint >> 24) as u8);
        let _ = buf.push((self.session_hint >> 16) as u8);
        let _ = buf.push((self.session_hint >> 8) as u8);
        let _ = buf.push(self.session_hint as u8);


        let _ = buf.extend_from_slice(&self.payload);

        buf
    }


    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 7 {
            return None;
        }

        let flags = data[0];
        let packet_type = PacketType::from_flags(flags);
        let hop_count = flags & 0x0F;

        let next_hop_hint = ((data[1] as u16) << 8) | (data[2] as u16);
        let session_hint = ((data[3] as u32) << 24)
            | ((data[4] as u32) << 16)
            | ((data[5] as u32) << 8)
            | (data[6] as u32);

        let mut payload = HeaplessVec::new();
        if data.len() > 7 {
            payload.extend_from_slice(&data[7..]).ok()?;
        }

        Some(Self {
            packet_type,
            hop_count,
            next_hop_hint,
            session_hint,
            payload,
        })
    }


    pub fn increment_hop(&mut self) -> bool {
        if self.hop_count < 15 {
            self.hop_count += 1;
            true
        } else {
            false
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {

    Low = 0,

    Normal = 1,

    High = 2,

    Critical = 3,
}


#[derive(Debug, Clone)]
pub struct UniversalMessage {

    pub id: [u8; 8],

    pub recipient: UniversalAddress,

    pub payload: HeaplessVec<u8, 237>,

    pub priority: MessagePriority,

    pub timestamp: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {

    Disconnected,

    Connecting,

    Connected,

    Error,
}


#[derive(Debug, Clone, Copy)]
pub struct SignalQuality {

    pub rssi: i16,

    pub snr: i8,

    pub quality: u8,
}

impl SignalQuality {
    pub fn new(rssi: i16, snr: i8) -> Self {


        let rssi_norm = ((rssi.max(-120).min(-50) + 120) as u16 * 100 / 70) as u8;

        let snr_norm = ((snr.max(-20).min(10) + 20) as u16 * 100 / 30) as u8;

        let quality = (rssi_norm + snr_norm) / 2;

        Self { rssi, snr, quality }
    }
}


#[derive(Debug, Clone)]
pub struct MeshDeviceInfo {

    pub name: HeaplessVec<u8, 32>,

    pub firmware_version: HeaplessVec<u8, 16>,

    pub hardware_model: HeaplessVec<u8, 32>,

    pub protocols: ProtocolSupport,

    pub battery_level: u8,
}


#[derive(Debug, Clone, Copy, Default)]
pub struct ProtocolSupport {
    pub meshcore: bool,
    pub meshtastic: bool,
    pub reticulum: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {

    NotConnected,

    ConnectionFailed,

    SendFailed,

    ReceiveTimeout,

    InvalidMessage,

    BufferOverflow,

    DeviceBusy,

    ProtocolError,

    Unknown,
}


pub trait UniversalMeshTransport {

    fn connect(&mut self) -> Result<(), TransportError>;


    fn disconnect(&mut self);


    fn send_message(&mut self, message: &UniversalMessage) -> Result<[u8; 8], TransportError>;


    fn poll_message(&mut self) -> Option<UniversalMessage>;


    fn get_device_info(&self) -> Result<MeshDeviceInfo, TransportError>;


    fn connection_state(&self) -> ConnectionState;


    fn signal_quality(&self) -> SignalQuality;


    fn discover_peers(&mut self, timeout_ms: u32) -> HeaplessVec<UniversalAddress, 16>;


    fn ping_peer(&mut self, address: &UniversalAddress) -> Result<u32, TransportError>;
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    MeshCore,
    Meshtastic,
    Reticulum,
}

impl Protocol {

    pub fn magic_bytes(&self) -> [u8; 2] {
        match self {
            Protocol::MeshCore => [0xAA, 0x55],
            Protocol::Meshtastic => [0x94, 0xC3],
            Protocol::Reticulum => [0xC0, 0x00],
        }
    }


    pub fn detect(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        match (data[0], data[1]) {
            (0xAA, 0x55) => Some(Protocol::MeshCore),
            (0x94, 0xC3) => Some(Protocol::Meshtastic),
            (0xC0, _) => Some(Protocol::Reticulum),
            (b'A', b'T') => None,
            _ => None,
        }
    }
}


const MAX_KNOWN_ADDRESSES: usize = 64;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolAddress {
    MeshCore(u16),
    Meshtastic(u32),
    Reticulum([u8; 16]),
}


pub struct AddressLookupTable {

    meshcore_index: heapless::FnvIndexMap<u16, [u8; 32], MAX_KNOWN_ADDRESSES>,

    meshtastic_index: heapless::FnvIndexMap<u32, [u8; 32], MAX_KNOWN_ADDRESSES>,

    reticulum_index: heapless::FnvIndexMap<[u8; 8], [u8; 32], MAX_KNOWN_ADDRESSES>,
}

impl AddressLookupTable {
    pub fn new() -> Self {
        Self {
            meshcore_index: heapless::FnvIndexMap::new(),
            meshtastic_index: heapless::FnvIndexMap::new(),
            reticulum_index: heapless::FnvIndexMap::new(),
        }
    }


    pub fn register(&mut self, public_key: &[u8; 32]) {
        let addr = AddressTranslator::from_public_key(public_key);


        let _ = self.meshcore_index.insert(addr.meshcore_addr, *public_key);


        let _ = self.meshtastic_index.insert(addr.meshtastic_id, *public_key);


        let mut ret_key = [0u8; 8];
        ret_key.copy_from_slice(&addr.reticulum_hash[..8]);
        let _ = self.reticulum_index.insert(ret_key, *public_key);
    }


    pub fn unregister(&mut self, public_key: &[u8; 32]) {
        let addr = AddressTranslator::from_public_key(public_key);
        self.meshcore_index.remove(&addr.meshcore_addr);
        self.meshtastic_index.remove(&addr.meshtastic_id);
        let mut ret_key = [0u8; 8];
        ret_key.copy_from_slice(&addr.reticulum_hash[..8]);
        self.reticulum_index.remove(&ret_key);
    }


    pub fn lookup_meshcore(&self, addr: u16) -> Option<&[u8; 32]> {
        self.meshcore_index.get(&addr)
    }


    pub fn lookup_meshtastic(&self, id: u32) -> Option<&[u8; 32]> {
        self.meshtastic_index.get(&id)
    }


    pub fn lookup_reticulum(&self, hash: &[u8; 16]) -> Option<&[u8; 32]> {
        let mut key = [0u8; 8];
        key.copy_from_slice(&hash[..8]);
        self.reticulum_index.get(&key)
    }


    pub fn lookup(&self, addr: ProtocolAddress) -> Option<&[u8; 32]> {
        match addr {
            ProtocolAddress::MeshCore(a) => self.lookup_meshcore(a),
            ProtocolAddress::Meshtastic(id) => self.lookup_meshtastic(id),
            ProtocolAddress::Reticulum(hash) => self.lookup_reticulum(&hash),
        }
    }


    pub fn len(&self) -> usize {
        self.meshcore_index.len()
    }


    pub fn is_empty(&self) -> bool {
        self.meshcore_index.is_empty()
    }
}

impl Default for AddressLookupTable {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_derivation() {
        let pubkey = [0u8; 32];
        let addr = AddressTranslator::from_public_key(&pubkey);


        let addr2 = AddressTranslator::from_public_key(&pubkey);
        assert_eq!(addr.meshcore_addr, addr2.meshcore_addr);
        assert_eq!(addr.meshtastic_id, addr2.meshtastic_id);
        assert_eq!(addr.reticulum_hash, addr2.reticulum_hash);
    }

    #[test]
    fn test_wire_packet_roundtrip() {
        let packet = WirePacket::new_data(0x1234, 0xDEADBEEF, &[1, 2, 3, 4, 5]).unwrap();
        let encoded = packet.encode();
        let decoded = WirePacket::decode(&encoded).unwrap();

        assert_eq!(decoded.packet_type, PacketType::Data);
        assert_eq!(decoded.next_hop_hint, 0x1234);
        assert_eq!(decoded.session_hint, 0xDEADBEEF);
        assert_eq!(&decoded.payload[..], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_protocol_detection() {
        assert_eq!(Protocol::detect(&[0xAA, 0x55]), Some(Protocol::MeshCore));
        assert_eq!(Protocol::detect(&[0x94, 0xC3]), Some(Protocol::Meshtastic));
        assert_eq!(Protocol::detect(&[0xC0, 0x00]), Some(Protocol::Reticulum));
        assert_eq!(Protocol::detect(&[0x00, 0x00]), None);
    }

    #[test]
    fn test_address_lookup_table() {
        let mut table = AddressLookupTable::new();
        let pubkey1 = [1u8; 32];
        let pubkey2 = [2u8; 32];


        table.register(&pubkey1);
        table.register(&pubkey2);
        assert_eq!(table.len(), 2);


        let addr1 = AddressTranslator::from_public_key(&pubkey1);
        let addr2 = AddressTranslator::from_public_key(&pubkey2);


        assert_eq!(table.lookup_meshcore(addr1.meshcore_addr), Some(&pubkey1));
        assert_eq!(table.lookup_meshcore(addr2.meshcore_addr), Some(&pubkey2));
        assert_eq!(table.lookup_meshcore(0xFFFF), None);


        assert_eq!(table.lookup_meshtastic(addr1.meshtastic_id), Some(&pubkey1));
        assert_eq!(table.lookup_meshtastic(addr2.meshtastic_id), Some(&pubkey2));


        assert_eq!(table.lookup_reticulum(&addr1.reticulum_hash), Some(&pubkey1));


        table.unregister(&pubkey1);
        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup_meshcore(addr1.meshcore_addr), None);
    }
}
