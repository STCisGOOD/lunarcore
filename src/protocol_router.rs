use heapless::Vec;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {

    Unknown,

    MeshCore,

    Meshtastic,

    RNode,

    AtCommand,
}

impl Protocol {

    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Unknown => "Unknown",
            Protocol::MeshCore => "MeshCore",
            Protocol::Meshtastic => "Meshtastic",
            Protocol::RNode => "RNode/KISS",
            Protocol::AtCommand => "AT Command",
        }
    }
}


pub mod magic {

    pub const MESHCORE_SYNC1: u8 = 0xAA;
    pub const MESHCORE_SYNC2: u8 = 0x55;


    pub const MESHTASTIC_SYNC1: u8 = 0x94;
    pub const MESHTASTIC_SYNC2: u8 = 0xC3;


    pub const KISS_FEND: u8 = 0xC0;


    pub const AT_PREFIX: [u8; 2] = [b'A', b'T'];
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetectState {

    Idle,

    MeshCore1,

    Meshtastic1,

    At1,
}


const SYNC_TIMEOUT_BYTES: u16 = 256;


pub struct ProtocolDetector {
    state: DetectState,
    detected: Protocol,

    bytes_seen: u16,

    lock_threshold: u8,

    lock_count: u8,

    state_bytes: u16,

    last_detect_ms: u32,
}

impl Default for ProtocolDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolDetector {
    pub fn new() -> Self {
        Self {
            state: DetectState::Idle,
            detected: Protocol::Unknown,
            bytes_seen: 0,
            lock_threshold: 3,
            lock_count: 0,
            state_bytes: 0,
            last_detect_ms: 0,
        }
    }


    pub fn reset(&mut self) {
        self.state = DetectState::Idle;
        self.detected = Protocol::Unknown;
        self.bytes_seen = 0;
        self.lock_count = 0;
        self.state_bytes = 0;
    }


    pub fn soft_reset(&mut self) {
        self.state = DetectState::Idle;
        self.state_bytes = 0;
    }


    pub fn force_protocol(&mut self, protocol: Protocol) {
        self.detected = protocol;
        self.state = DetectState::Idle;

    }


    pub fn protocol(&self) -> Protocol {
        self.detected
    }


    pub fn is_locked(&self) -> bool {
        self.lock_count >= self.lock_threshold
    }


    pub fn confirm_frame(&mut self) {
        if self.lock_count < 255 {
            self.lock_count += 1;
        }
    }


    pub fn error_frame(&mut self) {
        if self.lock_count > 0 {
            self.lock_count = self.lock_count.saturating_sub(2);
        }

        if self.lock_count == 0 && self.detected != Protocol::Unknown {
            self.detected = Protocol::Unknown;
        }
    }


    fn check_timeout(&mut self) {
        if self.state != DetectState::Idle && self.state_bytes > SYNC_TIMEOUT_BYTES {

            self.state = DetectState::Idle;
            self.state_bytes = 0;
        }
    }


    pub fn feed(&mut self, byte: u8) -> Option<Protocol> {
        self.bytes_seen += 1;
        self.state_bytes += 1;


        self.check_timeout();


        if self.is_locked() {
            return Some(self.detected);
        }

        let prev_state = self.state;

        match self.state {
            DetectState::Idle => {
                match byte {
                    magic::MESHCORE_SYNC1 => {
                        self.state = DetectState::MeshCore1;
                    }
                    magic::MESHTASTIC_SYNC1 => {
                        self.state = DetectState::Meshtastic1;
                    }
                    magic::KISS_FEND => {


                        if self.detected == Protocol::Unknown || self.detected == Protocol::RNode {
                            self.detected = Protocol::RNode;
                            return Some(Protocol::RNode);
                        }
                    }
                    b'A' => {
                        self.state = DetectState::At1;
                    }
                    _ => {

                    }
                }
            }

            DetectState::MeshCore1 => {
                if byte == magic::MESHCORE_SYNC2 {
                    self.detected = Protocol::MeshCore;
                    self.state = DetectState::Idle;
                    return Some(Protocol::MeshCore);
                } else if byte == magic::MESHCORE_SYNC1 {

                } else {
                    self.state = DetectState::Idle;
                }
            }

            DetectState::Meshtastic1 => {
                if byte == magic::MESHTASTIC_SYNC2 {
                    self.detected = Protocol::Meshtastic;
                    self.state = DetectState::Idle;
                    return Some(Protocol::Meshtastic);
                } else {
                    self.state = DetectState::Idle;
                }
            }

            DetectState::At1 => {
                if byte == b'T' {
                    self.detected = Protocol::AtCommand;
                    self.state = DetectState::Idle;
                    return Some(Protocol::AtCommand);
                } else {
                    self.state = DetectState::Idle;
                }
            }
        }


        if self.state != prev_state {
            self.state_bytes = 0;
        }

        None
    }
}


pub const MAX_TRANSPORTS: usize = 3;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    UsbSerial,
    Ble,
    WiFi,
}


pub struct TransportState {
    pub transport: TransportType,
    pub detector: ProtocolDetector,
    pub active: bool,
}

impl TransportState {
    pub fn new(transport: TransportType) -> Self {
        Self {
            transport,
            detector: ProtocolDetector::new(),
            active: false,
        }
    }
}


pub struct ProtocolRouter {

    transports: [TransportState; MAX_TRANSPORTS],

    lora_protocol: Protocol,

    lora_shared: bool,

    priority_transport: Option<TransportType>,
}

impl ProtocolRouter {
    pub fn new() -> Self {
        Self {
            transports: [
                TransportState::new(TransportType::UsbSerial),
                TransportState::new(TransportType::Ble),
                TransportState::new(TransportType::WiFi),
            ],
            lora_protocol: Protocol::Unknown,
            lora_shared: true,
            priority_transport: None,
        }
    }


    pub fn transport(&mut self, t: TransportType) -> &mut TransportState {
        match t {
            TransportType::UsbSerial => &mut self.transports[0],
            TransportType::Ble => &mut self.transports[1],
            TransportType::WiFi => &mut self.transports[2],
        }
    }


    pub fn transport_ref(&self, t: TransportType) -> &TransportState {
        match t {
            TransportType::UsbSerial => &self.transports[0],
            TransportType::Ble => &self.transports[1],
            TransportType::WiFi => &self.transports[2],
        }
    }


    pub fn lora_protocol(&self) -> Protocol {
        self.lora_protocol
    }


    pub fn set_lora_protocol(&mut self, protocol: Protocol) {
        self.lora_protocol = protocol;
    }


    pub fn is_lora_shared(&self) -> bool {
        self.lora_shared
    }


    pub fn priority_transport(&self) -> Option<TransportType> {
        self.priority_transport
    }


    pub fn release_lora_control(&mut self, transport: TransportType) {
        if self.priority_transport == Some(transport) {
            self.priority_transport = None;

        }

        let state = self.transport(transport);
        state.detector.reset();
        state.active = false;
    }


    fn can_claim_lora(&self, transport: TransportType, protocol: Protocol) -> bool {

        if self.priority_transport.is_none() {
            return true;
        }


        if self.priority_transport == Some(transport) {
            return true;
        }


        if self.lora_protocol == protocol {
            return true;
        }

        false
    }


    pub fn route_incoming(&mut self, transport: TransportType, byte: u8) -> Protocol {

        let idx = match transport {
            TransportType::UsbSerial => 0,
            TransportType::Ble => 1,
            TransportType::WiFi => 2,
        };

        self.transports[idx].active = true;

        if let Some(protocol) = self.transports[idx].detector.feed(byte) {

            let can_claim = self.priority_transport.is_none()
                || self.priority_transport == Some(transport)
                || self.lora_protocol == protocol;

            if can_claim {

                if self.lora_protocol == Protocol::Unknown || self.lora_protocol == protocol {
                    self.lora_protocol = protocol;
                }


                if self.priority_transport.is_none() && self.transports[idx].detector.is_locked() {
                    self.priority_transport = Some(transport);
                }
            }
            protocol
        } else {
            self.transports[idx].detector.protocol()
        }
    }


    pub fn resolve_conflict(&mut self, transport: TransportType, new_protocol: Protocol) -> bool {

        if new_protocol == Protocol::AtCommand {
            return true;
        }


        if self.priority_transport.is_none() {
            return true;
        }


        if self.priority_transport == Some(transport) {
            return true;
        }


        if self.lora_protocol != new_protocol && self.lora_protocol != Protocol::Unknown {
            return false;
        }

        true
    }


    pub fn status(&self) -> [(TransportType, Protocol, bool); MAX_TRANSPORTS] {
        [
            (TransportType::UsbSerial, self.transports[0].detector.protocol(), self.transports[0].active),
            (TransportType::Ble, self.transports[1].detector.protocol(), self.transports[1].active),
            (TransportType::WiFi, self.transports[2].detector.protocol(), self.transports[2].active),
        ]
    }
}

impl Default for ProtocolRouter {
    fn default() -> Self {
        Self::new()
    }
}


pub struct LoRaPacket {
    pub protocol: Protocol,
    pub data: Vec<u8, 256>,
    pub rssi: i16,
    pub snr: i8,
}

impl LoRaPacket {


    pub fn detect_protocol(data: &[u8]) -> Protocol {
        if data.len() < 4 {
            return Protocol::Unknown;
        }


        if data.len() >= 20 {


            let channel_hash = data[3];

            if data.len() >= 12 {
                let flags = data[11];
                let hop_limit = flags & 0x07;
                if hop_limit >= 1 && hop_limit <= 7 && channel_hash != 0 {
                    return Protocol::Meshtastic;
                }
            }
        }


        if data.len() >= 9 {
            let flags = data[8];

            let msg_type = flags & 0x0F;

            let hop = (flags >> 4) & 0x0F;
            if msg_type <= 15 && hop <= 7 {
                return Protocol::MeshCore;
            }
        }


        if data.len() >= 18 {


            let context = data[16];
            let header_type = (context >> 6) & 0x03;
            let propagation_type = (context >> 4) & 0x03;

            if header_type <= 3 && propagation_type <= 3 {


                let zeros = data[..16].iter().filter(|&&b| b == 0).count();
                if zeros < 8 {
                    return Protocol::RNode;
                }
            }
        }

        Protocol::Unknown
    }
}


#[derive(Clone)]
pub struct UnifiedPacket {

    pub source_protocol: Protocol,

    pub dest_protocol: Protocol,

    pub payload: Vec<u8, 237>,

    pub source_addr: [u8; 32],

    pub dest_addr: [u8; 32],

    pub hops: u8,

    pub rssi: i16,

    pub snr: i8,
}

impl UnifiedPacket {
    pub fn new() -> Self {
        Self {
            source_protocol: Protocol::Unknown,
            dest_protocol: Protocol::Unknown,
            payload: Vec::new(),
            source_addr: [0; 32],
            dest_addr: [0; 32],
            hops: 0,
            rssi: 0,
            snr: 0,
        }
    }
}

impl Default for UnifiedPacket {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meshcore_detection() {
        let mut detector = ProtocolDetector::new();
        assert_eq!(detector.protocol(), Protocol::Unknown);

        detector.feed(0xAA);
        assert_eq!(detector.protocol(), Protocol::Unknown);

        let result = detector.feed(0x55);
        assert_eq!(result, Some(Protocol::MeshCore));
        assert_eq!(detector.protocol(), Protocol::MeshCore);
    }

    #[test]
    fn test_meshtastic_detection() {
        let mut detector = ProtocolDetector::new();

        detector.feed(0x94);
        let result = detector.feed(0xC3);
        assert_eq!(result, Some(Protocol::Meshtastic));
    }

    #[test]
    fn test_kiss_detection() {
        let mut detector = ProtocolDetector::new();

        let result = detector.feed(0xC0);
        assert_eq!(result, Some(Protocol::RNode));
    }

    #[test]
    fn test_at_detection() {
        let mut detector = ProtocolDetector::new();

        detector.feed(b'A');
        let result = detector.feed(b'T');
        assert_eq!(result, Some(Protocol::AtCommand));
    }
}
