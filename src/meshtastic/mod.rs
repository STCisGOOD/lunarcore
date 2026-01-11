pub mod protobuf;
pub mod channel;
pub mod packet;
pub mod encryption;

pub use protobuf::*;
pub use channel::*;
pub use packet::*;
pub use encryption::*;

use heapless::Vec;

pub const SERIAL_SYNC: [u8; 2] = [0x94, 0xC3];

pub const MAX_MESSAGE_SIZE: usize = 512;

pub const LORA_HEADER_SIZE: usize = 16;

pub const MAX_LORA_PAYLOAD: usize = 237;

pub const MIC_SIZE: usize = 4;

pub const DEFAULT_HOP_LIMIT: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PortNum {
    Unknown = 0,
    TextMessage = 1,
    RemoteHardware = 2,
    Position = 3,
    NodeInfo = 4,
    Routing = 5,
    Admin = 6,
    TextMessageCompressed = 7,
    Waypoint = 8,
    Audio = 9,
    DetectionSensor = 10,
    Reply = 32,
    IpTunnelApp = 33,
    Paxcounter = 34,
    Serial = 64,
    StoreForward = 65,
    RangeTest = 66,
    Telemetry = 67,
    Zps = 68,
    Simulator = 69,
    Traceroute = 70,
    Neighborinfo = 71,
    Atak = 72,
    Map = 73,
    Private = 256,
    AtakForwarder = 257,
    Max = 511,
}

impl From<u32> for PortNum {
    fn from(v: u32) -> Self {
        match v {
            1 => PortNum::TextMessage,
            2 => PortNum::RemoteHardware,
            3 => PortNum::Position,
            4 => PortNum::NodeInfo,
            5 => PortNum::Routing,
            6 => PortNum::Admin,
            7 => PortNum::TextMessageCompressed,
            8 => PortNum::Waypoint,
            32 => PortNum::Reply,
            33 => PortNum::IpTunnelApp,
            64 => PortNum::Serial,
            65 => PortNum::StoreForward,
            66 => PortNum::RangeTest,
            67 => PortNum::Telemetry,
            70 => PortNum::Traceroute,
            71 => PortNum::Neighborinfo,
            _ => PortNum::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MeshPacket {

    pub from: u32,

    pub to: u32,

    pub channel: u8,

    pub id: u32,

    pub hop_limit: u8,

    pub want_ack: bool,

    pub priority: Priority,

    pub rx_time: u32,

    pub rx_snr: f32,

    pub rx_rssi: i32,

    pub payload: PacketPayload,
}

#[derive(Debug, Clone)]
pub enum PacketPayload {

    Encrypted(Vec<u8, MAX_LORA_PAYLOAD>),

    Decoded(DataPayload),
}

#[derive(Debug, Clone)]
pub struct DataPayload {

    pub port: PortNum,

    pub payload: Vec<u8, MAX_LORA_PAYLOAD>,

    pub want_response: bool,

    pub dest: u32,

    pub source: u32,

    pub request_id: u32,

    pub reply_id: u32,

    pub emoji: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Priority {
    Unset = 0,
    Min = 1,
    Background = 10,
    Default = 64,
    Reliable = 70,
    Ack = 120,
    Max = 127,
}

impl From<u8> for Priority {
    fn from(v: u8) -> Self {
        match v {
            1 => Priority::Min,
            10 => Priority::Background,
            70 => Priority::Reliable,
            120 => Priority::Ack,
            127 => Priority::Max,
            _ => Priority::Default,
        }
    }
}

impl Default for MeshPacket {
    fn default() -> Self {
        Self {
            from: 0,
            to: 0xFFFFFFFF,
            channel: 0,
            id: 0,
            hop_limit: DEFAULT_HOP_LIMIT,
            want_ack: false,
            priority: Priority::Default,
            rx_time: 0,
            rx_snr: 0.0,
            rx_rssi: 0,
            payload: PacketPayload::Encrypted(Vec::new()),
        }
    }
}

impl Default for DataPayload {
    fn default() -> Self {
        Self {
            port: PortNum::Unknown,
            payload: Vec::new(),
            want_response: false,
            dest: 0,
            source: 0,
            request_id: 0,
            reply_id: 0,
            emoji: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeInfo {

    pub num: u32,

    pub user: Option<User>,

    pub position: Option<Position>,

    pub last_heard: u32,

    pub snr: f32,
}

#[derive(Debug, Clone)]
pub struct User {

    pub id: [u8; 8],

    pub long_name: Vec<u8, 40>,

    pub short_name: Vec<u8, 5>,

    pub hw_model: HardwareModel,

    pub is_licensed: bool,

    pub role: Role,
}

#[derive(Debug, Clone, Default)]
pub struct Position {

    pub latitude_i: i32,

    pub longitude_i: i32,

    pub altitude: i32,

    pub time: u32,

    pub timestamp: u32,

    pub location_source: LocationSource,

    pub altitude_source: LocationSource,

    pub pdop: u32,

    pub hdop: u32,

    pub sats_in_view: u32,

    pub ground_speed: u32,

    pub ground_track: u32,

    pub fix_quality: u32,

    pub fix_type: u32,

    pub seq_number: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum LocationSource {
    #[default]
    Unset = 0,
    Manual = 1,
    InternalGps = 2,
    ExternalGps = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HardwareModel {
    Unset = 0,
    TloraV2 = 1,
    TloraV1 = 2,
    TloraV21_1p6 = 3,
    Tbeam = 4,
    HeltecV2_0 = 5,
    TbeamV0p7 = 6,
    Techo = 7,
    TloraV1_1p3 = 8,
    Rak4631 = 9,
    HeltecV2_1 = 10,
    HeltecV1 = 11,
    LilygoTbeamS3Core = 12,
    Rak11200 = 13,
    NanoG1 = 14,
    TloraV2_1_1p8 = 15,
    TloraT3S3 = 16,
    NanoG1Explorer = 17,
    NanoG2Ultra = 18,
    LoraType = 19,
    WiPhone = 20,
    WioWm1110 = 21,
    Rak2560 = 22,
    HeltecHt62 = 23,
    Ebyte900 = 24,
    EbyteEsp32S3 = 25,
    Esp32S3Pico = 26,
    Chatter2 = 27,
    HeltecWirelessPaperV1_0 = 28,
    HeltecWirelessTrackerV1_0 = 29,
    Unphone = 30,
    Tdeck = 31,
    TWatchS3 = 32,
    PicomputerS3 = 33,
    HeltecWifiLoraV3 = 34,
    PrivateHw = 255,
}

impl Default for HardwareModel {
    fn default() -> Self {
        HardwareModel::Unset
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Client = 0,
    ClientMute = 1,
    Router = 2,
    RouterClient = 3,
    Repeater = 4,
    Tracker = 5,
    Sensor = 6,
    Tak = 7,
    ClientHidden = 8,
    LostAndFound = 9,
    TakTracker = 10,
}

impl Default for Role {
    fn default() -> Self {
        Role::Client
    }
}

pub struct MeshtasticHandler {

    pub node_id: u32,

    pub primary_channel: Channel,

    pub secondary_channels: [Option<Channel>; 7],

    pub last_packet_id: u32,

    pub rx_count: u32,

    pub tx_count: u32,

    pub position: Option<Position>,

    pub user: Option<User>,

    parser: MeshtasticParser,

    pending_responses: heapless::Deque<Vec<u8, MAX_MESSAGE_SIZE>, 16>,

    config_request_id: u32,

    config_channel_index: u8,
}

impl MeshtasticHandler {

    pub fn new(node_id: u32) -> Self {
        Self {
            node_id,
            primary_channel: Channel::default(),
            secondary_channels: [None, None, None, None, None, None, None],
            last_packet_id: 0,
            rx_count: 0,
            tx_count: 0,
            position: None,
            user: None,
            parser: MeshtasticParser::new(),
            pending_responses: heapless::Deque::new(),
            config_request_id: 0,
            config_channel_index: 0,
        }
    }

    pub fn set_channel_key(&mut self, psk: &[u8]) {
        self.primary_channel.set_key(psk);
    }

    pub fn next_packet_id(&mut self) -> u32 {
        self.last_packet_id = self.last_packet_id.wrapping_add(1);
        if self.last_packet_id == 0 {
            self.last_packet_id = 1;
        }
        self.last_packet_id
    }

    pub fn process_lora_packet(&mut self, data: &[u8], rssi: i32, snr: f32) -> Option<MeshPacket> {
        if data.len() < LORA_HEADER_SIZE + MIC_SIZE {
            return None;
        }

        let mut packet = packet::parse_lora_packet(data)?;

        packet.rx_rssi = rssi;
        packet.rx_snr = snr;

        let decrypted = self.decrypt_packet(&packet)?;

        self.rx_count += 1;

        Some(decrypted)
    }

    fn decrypt_packet(&self, packet: &MeshPacket) -> Option<MeshPacket> {
        let mut result = packet.clone();

        if let PacketPayload::Encrypted(ref encrypted) = packet.payload {

            let channel = if packet.channel == 0 {
                &self.primary_channel
            } else {
                self.secondary_channels
                    .get((packet.channel - 1) as usize)?
                    .as_ref()?
            };

            let decrypted = channel.decrypt(packet.id, packet.from, encrypted)?;

            if let Some(data) = protobuf::decode_data(&decrypted) {
                result.payload = PacketPayload::Decoded(data);
            }
        }

        Some(result)
    }

    pub fn create_packet(
        &mut self,
        to: u32,
        port: PortNum,
        payload: &[u8],
        want_ack: bool,
    ) -> Option<Vec<u8, 256>> {
        let packet_id = self.next_packet_id();

        let data = DataPayload {
            port,
            payload: Vec::from_slice(payload).ok()?,
            want_response: want_ack,
            source: self.node_id,
            dest: to,
            ..Default::default()
        };

        let encoded = protobuf::encode_data(&data)?;

        let encrypted = self.primary_channel.encrypt(packet_id, self.node_id, &encoded)?;

        let lora_packet = packet::build_lora_packet(
            self.node_id,
            to,
            packet_id,
            0,
            DEFAULT_HOP_LIMIT,
            want_ack,
            &encrypted,
        )?;

        self.tx_count += 1;

        Some(lora_packet)
    }

    pub fn create_text_message(&mut self, to: u32, text: &str) -> Option<Vec<u8, 256>> {
        self.create_packet(to, PortNum::TextMessage, text.as_bytes(), true)
    }

    pub fn create_position_packet(&mut self) -> Option<Vec<u8, 256>> {
        let position = self.position.as_ref()?;
        let encoded = protobuf::encode_position(position)?;
        self.create_packet(0xFFFFFFFF, PortNum::Position, &encoded, false)
    }

    pub fn create_node_info_packet(&mut self) -> Option<Vec<u8, 256>> {
        let user = self.user.as_ref()?;
        let encoded = protobuf::encode_user(user)?;
        self.create_packet(0xFFFFFFFF, PortNum::NodeInfo, &encoded, false)
    }

    pub fn parse_serial_frame(&self, data: &[u8]) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
        if data.len() < 4 {
            return None;
        }

        if data[0] != SERIAL_SYNC[0] || data[1] != SERIAL_SYNC[1] {
            return None;
        }

        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return None;
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&data[4..4 + len]).ok()?;
        Some(payload)
    }

    pub fn build_serial_frame(&self, payload: &[u8]) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
        let mut frame = Vec::new();
        frame.push(SERIAL_SYNC[0]).ok()?;
        frame.push(SERIAL_SYNC[1]).ok()?;
        let len_bytes = (payload.len() as u16).to_be_bytes();
        frame.push(len_bytes[0]).ok()?;
        frame.push(len_bytes[1]).ok()?;
        frame.extend_from_slice(payload).ok()?;
        Some(frame)
    }

    pub fn feed_serial(&mut self, byte: u8) -> Option<MeshtasticFrame> {
        self.parser.feed(byte)
    }

    pub fn build_lora_packet(&mut self, frame: &MeshtasticFrame) -> Option<Vec<u8, 256>> {

        if frame.payload.is_empty() {
            return None;
        }

        let payload = &frame.payload;

        if payload.len() < 2 {
            return None;
        }

        if payload[0] != 0x0A {

            return None;
        }

        let mesh_packet_len = payload[1] as usize;
        if payload.len() < 2 + mesh_packet_len {
            return None;
        }

        let mesh_packet_data = &payload[2..2 + mesh_packet_len];

        let mut to: u32 = 0xFFFFFFFF;
        let mut channel: u8 = 0;
        let mut want_ack = false;
        let mut hop_limit = DEFAULT_HOP_LIMIT;
        let mut inner_payload: Option<Vec<u8, MAX_LORA_PAYLOAD>> = None;
        let mut port = PortNum::Unknown;

        let mut idx = 0;
        while idx < mesh_packet_data.len() {
            let tag = mesh_packet_data[idx];
            idx += 1;
            if idx >= mesh_packet_data.len() {
                break;
            }

            let field_num = tag >> 3;
            let wire_type = tag & 0x07;

            match (field_num, wire_type) {

                (2, 0) => {
                    let (val, consumed) = decode_varint(&mesh_packet_data[idx..]);
                    to = val as u32;
                    idx += consumed;
                }

                (4, 0) => {
                    let (val, consumed) = decode_varint(&mesh_packet_data[idx..]);
                    channel = val as u8;
                    idx += consumed;
                }

                (6, 0) => {
                    let (val, consumed) = decode_varint(&mesh_packet_data[idx..]);
                    hop_limit = val as u8;
                    idx += consumed;
                }

                (7, 0) => {
                    let (val, consumed) = decode_varint(&mesh_packet_data[idx..]);
                    want_ack = val != 0;
                    idx += consumed;
                }

                (8, 2) => {
                    if idx >= mesh_packet_data.len() {
                        break;
                    }
                    let len = mesh_packet_data[idx] as usize;
                    idx += 1;
                    if idx + len > mesh_packet_data.len() {
                        break;
                    }
                    let data_msg = &mesh_packet_data[idx..idx + len];

                    let mut data_idx = 0;
                    while data_idx < data_msg.len() {
                        let dtag = data_msg[data_idx];
                        data_idx += 1;
                        if data_idx >= data_msg.len() {
                            break;
                        }
                        let dfield = dtag >> 3;
                        let dwire = dtag & 0x07;
                        match (dfield, dwire) {

                            (1, 0) => {
                                let (val, consumed) = decode_varint(&data_msg[data_idx..]);
                                port = PortNum::from(val as u32);
                                data_idx += consumed;
                            }

                            (2, 2) => {
                                if data_idx >= data_msg.len() {
                                    break;
                                }
                                let plen = data_msg[data_idx] as usize;
                                data_idx += 1;
                                if data_idx + plen > data_msg.len() {
                                    break;
                                }
                                let mut p = Vec::new();
                                let _ = p.extend_from_slice(&data_msg[data_idx..data_idx + plen]);
                                inner_payload = Some(p);
                                data_idx += plen;
                            }

                            (_, 0) => {
                                let (_, consumed) = decode_varint(&data_msg[data_idx..]);
                                data_idx += consumed;
                            }
                            (_, 2) => {
                                if data_idx >= data_msg.len() {
                                    break;
                                }
                                let skip_len = data_msg[data_idx] as usize;
                                data_idx += 1 + skip_len;
                            }
                            _ => break,
                        }
                    }
                    idx += len;
                }

                (_, 0) => {
                    let (_, consumed) = decode_varint(&mesh_packet_data[idx..]);
                    idx += consumed;
                }
                (_, 2) => {
                    if idx >= mesh_packet_data.len() {
                        break;
                    }
                    let skip_len = mesh_packet_data[idx] as usize;
                    idx += 1 + skip_len;
                }
                _ => break,
            }
        }

        let payload_data = inner_payload?;

        self.create_packet(to, port, &payload_data, want_ack)
    }

    pub fn reset_parser(&mut self) {
        self.parser.reset();
    }

    pub fn process_toradio(&mut self, frame: &MeshtasticFrame) -> Option<ToRadioResponse> {
        if frame.payload.is_empty() {
            return None;
        }

        let payload = &frame.payload;
        if payload.len() < 2 {
            return None;
        }

        let field_tag = payload[0];
        let field_num = field_tag >> 3;
        let wire_type = field_tag & 0x07;

        match (field_num, wire_type) {

            (1, 2) => {

                self.build_lora_packet(frame).map(ToRadioResponse::LoRaPacket)
            }

            (3, 0) => {
                let (config_id, _) = decode_varint(&payload[1..]);
                self.build_config_response(config_id as u32)
            }

            (4, 0) => {

                self.reset_parser();
                None
            }

            _ => None,
        }
    }

    fn build_config_response(&mut self, config_id: u32) -> Option<ToRadioResponse> {

        self.pending_responses.clear();
        self.config_request_id = config_id;
        self.config_channel_index = 0;

        if let Some(my_info) = self.encode_privacy_myinfo() {
            let _ = self.pending_responses.push_back(my_info);
        }

        if let Some(node_info) = self.encode_privacy_nodeinfo() {
            let _ = self.pending_responses.push_back(node_info);
        }

        if let Some(channel_config) = self.encode_channel_config(0) {
            let _ = self.pending_responses.push_back(channel_config);
        }

        for i in 0..7 {
            if self.secondary_channels[i].is_some() {
                if let Some(channel_config) = self.encode_channel_config((i + 1) as u8) {
                    let _ = self.pending_responses.push_back(channel_config);
                }
            }
        }

        if let Some(complete) = self.encode_config_complete(config_id) {
            let _ = self.pending_responses.push_back(complete);
        }

        self.pending_responses.pop_front().map(ToRadioResponse::FromRadio)
    }

    pub fn poll_pending_response(&mut self) -> Option<ToRadioResponse> {
        self.pending_responses.pop_front().map(ToRadioResponse::FromRadio)
    }

    pub fn has_pending_responses(&self) -> bool {
        !self.pending_responses.is_empty()
    }

    pub fn pending_response_count(&self) -> usize {
        self.pending_responses.len()
    }

    fn encode_privacy_myinfo(&self) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
        let mut buf: Vec<u8, MAX_MESSAGE_SIZE> = Vec::new();

        let _ = write_tag(1, WIRE_VARINT, &mut buf);
        let _ = encode_varint(0, &mut buf);

        let mut my_info: Vec<u8, 64> = Vec::new();

        let _ = write_tag(1, WIRE_VARINT, &mut my_info);
        let _ = encode_varint(self.node_id as u64, &mut my_info);

        let _ = write_tag(3, WIRE_VARINT, &mut my_info);
        let _ = encode_varint(30000, &mut my_info);

        let _ = write_tag(4, WIRE_VARINT, &mut my_info);
        let _ = encode_varint(8, &mut my_info);

        let _ = write_tag(6, WIRE_VARINT, &mut my_info);
        let _ = encode_varint(0, &mut my_info);

        let _ = write_tag(7, WIRE_VARINT, &mut my_info);
        let _ = encode_varint(1, &mut my_info);

        let _ = write_tag(4, WIRE_LEN, &mut buf);
        let _ = encode_varint(my_info.len() as u64, &mut buf);
        let _ = buf.extend_from_slice(&my_info);

        Some(buf)
    }

    fn encode_privacy_nodeinfo(&self) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
        let mut buf: Vec<u8, MAX_MESSAGE_SIZE> = Vec::new();

        let _ = write_tag(1, WIRE_VARINT, &mut buf);
        let _ = encode_varint(0, &mut buf);

        let mut node_info: Vec<u8, 128> = Vec::new();

        let _ = write_tag(1, WIRE_VARINT, &mut node_info);
        let _ = encode_varint(self.node_id as u64, &mut node_info);

        let mut user: Vec<u8, 64> = Vec::new();

        let id_str = format_node_id(self.node_id);
        let _ = write_tag(1, WIRE_LEN, &mut user);
        let _ = encode_varint(id_str.len() as u64, &mut user);
        let _ = user.extend_from_slice(id_str.as_bytes());

        if let Some(ref u) = self.user {
            let _ = write_tag(2, WIRE_LEN, &mut user);
            let _ = encode_varint(u.long_name.len() as u64, &mut user);
            let _ = user.extend_from_slice(&u.long_name);
        } else {
            let name = b"LunarNode";
            let _ = write_tag(2, WIRE_LEN, &mut user);
            let _ = encode_varint(name.len() as u64, &mut user);
            let _ = user.extend_from_slice(name);
        }

        if let Some(ref u) = self.user {
            let _ = write_tag(3, WIRE_LEN, &mut user);
            let _ = encode_varint(u.short_name.len() as u64, &mut user);
            let _ = user.extend_from_slice(&u.short_name);
        } else {
            let short = b"LNOD";
            let _ = write_tag(3, WIRE_LEN, &mut user);
            let _ = encode_varint(short.len() as u64, &mut user);
            let _ = user.extend_from_slice(short);
        }

        let _ = write_tag(5, WIRE_VARINT, &mut user);
        let _ = encode_varint(43, &mut user);

        let _ = write_tag(7, WIRE_VARINT, &mut user);
        let _ = encode_varint(4, &mut user);

        let _ = write_tag(2, WIRE_LEN, &mut node_info);
        let _ = encode_varint(user.len() as u64, &mut node_info);
        let _ = node_info.extend_from_slice(&user);

        let _ = write_tag(6, WIRE_LEN, &mut buf);
        let _ = encode_varint(node_info.len() as u64, &mut buf);
        let _ = buf.extend_from_slice(&node_info);

        Some(buf)
    }

    fn encode_channel_config(&self, index: u8) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
        let mut buf: Vec<u8, MAX_MESSAGE_SIZE> = Vec::new();

        let _ = write_tag(1, WIRE_VARINT, &mut buf);
        let _ = encode_varint(0, &mut buf);

        let mut channel: Vec<u8, 64> = Vec::new();

        let _ = write_tag(1, WIRE_VARINT, &mut channel);
        let _ = encode_varint(index as u64, &mut channel);

        let mut settings: Vec<u8, 48> = Vec::new();

        let name = self.primary_channel.name_str();
        if !name.is_empty() {
            let _ = write_tag(2, WIRE_LEN, &mut settings);
            let _ = encode_varint(name.len() as u64, &mut settings);
            let _ = settings.extend_from_slice(name.as_bytes());
        }

        let _ = write_tag(2, WIRE_LEN, &mut channel);
        let _ = encode_varint(settings.len() as u64, &mut channel);
        let _ = channel.extend_from_slice(&settings);

        let _ = write_tag(3, WIRE_VARINT, &mut channel);
        let _ = encode_varint(1, &mut channel);

        let _ = write_tag(8, WIRE_LEN, &mut buf);
        let _ = encode_varint(channel.len() as u64, &mut buf);
        let _ = buf.extend_from_slice(&channel);

        Some(buf)
    }

    fn encode_config_complete(&self, config_id: u32) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
        let mut buf: Vec<u8, MAX_MESSAGE_SIZE> = Vec::new();

        let _ = write_tag(1, WIRE_VARINT, &mut buf);
        let _ = encode_varint(0, &mut buf);

        let _ = write_tag(9, WIRE_VARINT, &mut buf);
        let _ = encode_varint(config_id as u64, &mut buf);

        Some(buf)
    }

    pub fn handle_admin_message(&mut self, payload: &[u8]) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {
        if payload.is_empty() {
            return None;
        }

        let tag = payload[0];
        let field_num = tag >> 3;

        match field_num {

            1 => self.encode_privacy_myinfo(),

            7 => self.encode_privacy_nodeinfo(),

            5 => {

                None
            }

            6 => {

                None
            }

            _ => None,
        }
    }
}

fn format_node_id(node_id: u32) -> heapless::String<16> {
    let mut s = heapless::String::new();
    let _ = s.push('!');

    for i in (0..8).rev() {
        let nibble = (node_id >> (i * 4)) & 0xF;
        let c = if nibble < 10 { b'0' + nibble as u8 } else { b'a' + (nibble - 10) as u8 };
        let _ = s.push(c as char);
    }
    s
}

pub enum ToRadioResponse {

    LoRaPacket(Vec<u8, 256>),

    FromRadio(Vec<u8, MAX_MESSAGE_SIZE>),
}

fn decode_varint(data: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut consumed = 0;

    for &byte in data {
        consumed += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            break;
        }
    }

    (result, consumed)
}

fn encode_varint<const N: usize>(value: u64, buf: &mut Vec<u8, N>) -> bool {
    let mut v = value;
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            return buf.push(byte).is_ok();
        } else {
            if buf.push(byte | 0x80).is_err() {
                return false;
            }
        }
    }
}

fn encode_sint32<const N: usize>(value: i32, buf: &mut Vec<u8, N>) -> bool {
    let encoded = ((value << 1) ^ (value >> 31)) as u32;
    encode_varint(encoded as u64, buf)
}

fn write_tag<const N: usize>(field: u32, wire_type: u8, buf: &mut Vec<u8, N>) -> bool {
    let tag = (field << 3) | (wire_type as u32);
    encode_varint(tag as u64, buf)
}

const WIRE_VARINT: u8 = 0;
const WIRE_32BIT: u8 = 5;
const WIRE_LEN: u8 = 2;

pub fn encode_fromradio_packet(packet: &MeshPacket) -> Option<Vec<u8, MAX_MESSAGE_SIZE>> {

    let mut mesh_buf: Vec<u8, 300> = Vec::new();

    if packet.from != 0 {
        if !write_tag(1, WIRE_32BIT, &mut mesh_buf) { return None; }
        if mesh_buf.extend_from_slice(&packet.from.to_le_bytes()).is_err() { return None; }
    }

    if packet.to != 0 {
        if !write_tag(2, WIRE_32BIT, &mut mesh_buf) { return None; }
        if mesh_buf.extend_from_slice(&packet.to.to_le_bytes()).is_err() { return None; }
    }

    if packet.channel != 0 {
        if !write_tag(3, WIRE_VARINT, &mut mesh_buf) { return None; }
        if !encode_varint(packet.channel as u64, &mut mesh_buf) { return None; }
    }

    match &packet.payload {
        PacketPayload::Decoded(data) => {

            let mut data_buf: Vec<u8, MAX_LORA_PAYLOAD> = Vec::new();

            if !write_tag(1, WIRE_VARINT, &mut data_buf) { return None; }
            if !encode_varint(data.port as u64, &mut data_buf) { return None; }

            if !data.payload.is_empty() {
                if !write_tag(2, WIRE_LEN, &mut data_buf) { return None; }
                if !encode_varint(data.payload.len() as u64, &mut data_buf) { return None; }
                if data_buf.extend_from_slice(&data.payload).is_err() { return None; }
            }

            if data.want_response {
                if !write_tag(3, WIRE_VARINT, &mut data_buf) { return None; }
                if data_buf.push(1).is_err() { return None; }
            }

            if data.dest != 0 {
                if !write_tag(4, WIRE_32BIT, &mut data_buf) { return None; }
                if data_buf.extend_from_slice(&data.dest.to_le_bytes()).is_err() { return None; }
            }

            if data.source != 0 {
                if !write_tag(5, WIRE_32BIT, &mut data_buf) { return None; }
                if data_buf.extend_from_slice(&data.source.to_le_bytes()).is_err() { return None; }
            }

            if data.request_id != 0 {
                if !write_tag(6, WIRE_32BIT, &mut data_buf) { return None; }
                if data_buf.extend_from_slice(&data.request_id.to_le_bytes()).is_err() { return None; }
            }

            if data.reply_id != 0 {
                if !write_tag(7, WIRE_32BIT, &mut data_buf) { return None; }
                if data_buf.extend_from_slice(&data.reply_id.to_le_bytes()).is_err() { return None; }
            }

            if data.emoji != 0 {
                if !write_tag(8, WIRE_32BIT, &mut data_buf) { return None; }
                if data_buf.extend_from_slice(&data.emoji.to_le_bytes()).is_err() { return None; }
            }

            if !data_buf.is_empty() {
                if !write_tag(4, WIRE_LEN, &mut mesh_buf) { return None; }
                if !encode_varint(data_buf.len() as u64, &mut mesh_buf) { return None; }
                if mesh_buf.extend_from_slice(&data_buf).is_err() { return None; }
            }
        }
        PacketPayload::Encrypted(encrypted) => {

            if !encrypted.is_empty() {
                if !write_tag(5, WIRE_LEN, &mut mesh_buf) { return None; }
                if !encode_varint(encrypted.len() as u64, &mut mesh_buf) { return None; }
                if mesh_buf.extend_from_slice(encrypted).is_err() { return None; }
            }
        }
    }

    if packet.id != 0 {
        if !write_tag(6, WIRE_32BIT, &mut mesh_buf) { return None; }
        if mesh_buf.extend_from_slice(&packet.id.to_le_bytes()).is_err() { return None; }
    }

    if packet.rx_time != 0 {
        if !write_tag(7, WIRE_32BIT, &mut mesh_buf) { return None; }
        if mesh_buf.extend_from_slice(&packet.rx_time.to_le_bytes()).is_err() { return None; }
    }

    if packet.rx_snr != 0.0 {
        if !write_tag(8, WIRE_32BIT, &mut mesh_buf) { return None; }
        if mesh_buf.extend_from_slice(&packet.rx_snr.to_bits().to_le_bytes()).is_err() { return None; }
    }

    if packet.hop_limit != 0 {
        if !write_tag(9, WIRE_VARINT, &mut mesh_buf) { return None; }
        if !encode_varint(packet.hop_limit as u64, &mut mesh_buf) { return None; }
    }

    if packet.want_ack {
        if !write_tag(10, WIRE_VARINT, &mut mesh_buf) { return None; }
        if mesh_buf.push(1).is_err() { return None; }
    }

    let priority_val = packet.priority as u8;
    if priority_val != 0 {
        if !write_tag(11, WIRE_VARINT, &mut mesh_buf) { return None; }
        if !encode_varint(priority_val as u64, &mut mesh_buf) { return None; }
    }

    if packet.rx_rssi != 0 {
        if !write_tag(12, WIRE_VARINT, &mut mesh_buf) { return None; }
        if !encode_sint32(packet.rx_rssi, &mut mesh_buf) { return None; }
    }

    let mut from_radio_buf: Vec<u8, MAX_MESSAGE_SIZE> = Vec::new();

    if !mesh_buf.is_empty() {
        if !write_tag(2, WIRE_LEN, &mut from_radio_buf) { return None; }
        if !encode_varint(mesh_buf.len() as u64, &mut from_radio_buf) { return None; }
        if from_radio_buf.extend_from_slice(&mesh_buf).is_err() { return None; }
    }

    Some(from_radio_buf)
}

impl Default for MeshtasticHandler {
    fn default() -> Self {
        Self::new(0)
    }
}

pub const MAX_SERIAL_PAYLOAD: usize = 512;

pub const MAX_FRAME_SIZE: usize = 4 + MAX_SERIAL_PAYLOAD;

#[derive(Debug, Clone)]
pub struct MeshtasticFrame {

    pub payload: Vec<u8, MAX_SERIAL_PAYLOAD>,
}

impl MeshtasticFrame {

    pub fn new() -> Self {
        Self {
            payload: Vec::new(),
        }
    }

    pub fn with_payload(data: &[u8]) -> Option<Self> {
        if data.len() > MAX_SERIAL_PAYLOAD {
            return None;
        }
        let mut frame = Self::new();
        for &b in data {
            let _ = frame.payload.push(b);
        }
        Some(frame)
    }

    pub fn encode(&self) -> Vec<u8, MAX_FRAME_SIZE> {
        let mut buf = Vec::new();

        let _ = buf.push(SERIAL_SYNC[0]);
        let _ = buf.push(SERIAL_SYNC[1]);

        let len = self.payload.len() as u16;
        let _ = buf.push((len >> 8) as u8);
        let _ = buf.push(len as u8);

        for &b in &self.payload {
            let _ = buf.push(b);
        }

        buf
    }
}

impl Default for MeshtasticFrame {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserState {
    WaitSync1,
    WaitSync2,
    WaitLenHigh,
    WaitLenLow,
    WaitPayload,
}

pub struct MeshtasticParser {
    state: ParserState,
    payload_len: u16,
    payload_idx: u16,
    payload: Vec<u8, MAX_SERIAL_PAYLOAD>,
}

impl Default for MeshtasticParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshtasticParser {
    pub fn new() -> Self {
        Self {
            state: ParserState::WaitSync1,
            payload_len: 0,
            payload_idx: 0,
            payload: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.state = ParserState::WaitSync1;
        self.payload.clear();
        self.payload_len = 0;
        self.payload_idx = 0;
    }

    pub fn feed(&mut self, byte: u8) -> Option<MeshtasticFrame> {
        match self.state {
            ParserState::WaitSync1 => {
                if byte == SERIAL_SYNC[0] {
                    self.state = ParserState::WaitSync2;
                }
            }

            ParserState::WaitSync2 => {
                if byte == SERIAL_SYNC[1] {
                    self.state = ParserState::WaitLenHigh;
                } else if byte == SERIAL_SYNC[0] {

                } else {
                    self.reset();
                }
            }

            ParserState::WaitLenHigh => {
                self.payload_len = (byte as u16) << 8;
                self.state = ParserState::WaitLenLow;
            }

            ParserState::WaitLenLow => {
                self.payload_len |= byte as u16;
                if self.payload_len > MAX_SERIAL_PAYLOAD as u16 {
                    self.reset();
                    return None;
                }
                self.payload.clear();
                self.payload_idx = 0;
                if self.payload_len == 0 {

                    let frame = MeshtasticFrame::new();
                    self.reset();
                    return Some(frame);
                }
                self.state = ParserState::WaitPayload;
            }

            ParserState::WaitPayload => {
                let _ = self.payload.push(byte);
                self.payload_idx += 1;
                if self.payload_idx >= self.payload_len {

                    let frame = MeshtasticFrame {
                        payload: self.payload.clone(),
                    };
                    self.reset();
                    return Some(frame);
                }
            }
        }
        None
    }
}
