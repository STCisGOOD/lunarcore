use heapless::Vec;
use crate::crypto::sha256::Sha256;

pub const FEND: u8 = 0xC0;

pub const FESC: u8 = 0xDB;

pub const TFEND: u8 = 0xDC;

pub const TFESC: u8 = 0xDD;

pub const MAX_DATA_SIZE: usize = 512;

pub const MAX_FRAME_SIZE: usize = MAX_DATA_SIZE * 2 + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KissCommand {

    DataFrame = 0x00,

    TxDelay = 0x01,

    Persistence = 0x02,

    SlotTime = 0x03,

    TxTail = 0x04,

    FullDuplex = 0x05,

    SetHardware = 0x06,

    Return = 0xFF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RNodeCommand {

    Frequency = 0x01,

    Bandwidth = 0x02,

    TxPower = 0x03,

    SpreadingFactor = 0x04,

    CodingRate = 0x05,

    RadioState = 0x06,

    RadioLock = 0x07,

    Detect = 0x08,

    Promisc = 0x0E,

    Ready = 0x0F,

    PreambleLength = 0x10,

    SymbolTimeout = 0x11,

    SyncWord = 0x12,

    CrcMode = 0x13,

    ImplicitHeader = 0x14,

    Ldro = 0x15,

    Leave = 0x0A,

    SaveConfig = 0x0B,

    ResetConfig = 0x0C,

    Bootloader = 0x0D,

    StatRx = 0x21,

    StatTx = 0x22,

    StatRssi = 0x23,

    StatSnr = 0x24,

    StatBattery = 0x25,

    StatChannel = 0x26,

    AirtimeLimit = 0x27,

    AirtimeUsage = 0x28,

    Blink = 0x30,

    LedIntensity = 0x31,

    Random = 0x40,

    FwVersion = 0x50,

    ProtocolVersion = 0x51,

    Platform = 0x48,

    Mcu = 0x49,

    Board = 0x4A,

    RomInfo = 0x4B,

    HardwareSerial = 0x55,

    Signature = 0x56,

    TcxoVoltage = 0x60,

    Error = 0x90,

    RomData = 0xA0,

    Info = 0xB0,

    DataRssi = 0xFE,
}

impl RNodeCommand {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {

            0x01 => Some(RNodeCommand::Frequency),
            0x02 => Some(RNodeCommand::Bandwidth),
            0x03 => Some(RNodeCommand::TxPower),
            0x04 => Some(RNodeCommand::SpreadingFactor),
            0x05 => Some(RNodeCommand::CodingRate),
            0x06 => Some(RNodeCommand::RadioState),
            0x07 => Some(RNodeCommand::RadioLock),
            0x08 => Some(RNodeCommand::Detect),
            0x0A => Some(RNodeCommand::Leave),
            0x0B => Some(RNodeCommand::SaveConfig),
            0x0C => Some(RNodeCommand::ResetConfig),
            0x0D => Some(RNodeCommand::Bootloader),
            0x0E => Some(RNodeCommand::Promisc),
            0x0F => Some(RNodeCommand::Ready),

            0x10 => Some(RNodeCommand::PreambleLength),
            0x11 => Some(RNodeCommand::SymbolTimeout),
            0x12 => Some(RNodeCommand::SyncWord),
            0x13 => Some(RNodeCommand::CrcMode),
            0x14 => Some(RNodeCommand::ImplicitHeader),
            0x15 => Some(RNodeCommand::Ldro),

            0x21 => Some(RNodeCommand::StatRx),
            0x22 => Some(RNodeCommand::StatTx),
            0x23 => Some(RNodeCommand::StatRssi),
            0x24 => Some(RNodeCommand::StatSnr),
            0x25 => Some(RNodeCommand::StatBattery),
            0x26 => Some(RNodeCommand::StatChannel),
            0x27 => Some(RNodeCommand::AirtimeLimit),
            0x28 => Some(RNodeCommand::AirtimeUsage),

            0x30 => Some(RNodeCommand::Blink),
            0x31 => Some(RNodeCommand::LedIntensity),
            0x40 => Some(RNodeCommand::Random),
            0x48 => Some(RNodeCommand::Platform),
            0x49 => Some(RNodeCommand::Mcu),
            0x4A => Some(RNodeCommand::Board),
            0x4B => Some(RNodeCommand::RomInfo),
            0x50 => Some(RNodeCommand::FwVersion),
            0x51 => Some(RNodeCommand::ProtocolVersion),
            0x55 => Some(RNodeCommand::HardwareSerial),
            0x56 => Some(RNodeCommand::Signature),
            0x60 => Some(RNodeCommand::TcxoVoltage),

            0x90 => Some(RNodeCommand::Error),
            0xA0 => Some(RNodeCommand::RomData),
            0xB0 => Some(RNodeCommand::Info),
            0xFE => Some(RNodeCommand::DataRssi),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KissFrame {

    pub command: u8,

    pub data: Vec<u8, MAX_DATA_SIZE>,
}

impl KissFrame {

    pub fn new(command: u8) -> Self {
        Self {
            command,
            data: Vec::new(),
        }
    }

    pub fn data_frame(data: &[u8]) -> Option<Self> {
        if data.len() > MAX_DATA_SIZE {
            return None;
        }
        let mut frame = Self::new(KissCommand::DataFrame as u8);
        for &b in data {
            let _ = frame.data.push(b);
        }
        Some(frame)
    }

    pub fn command_frame(cmd: RNodeCommand, data: &[u8]) -> Option<Self> {
        if data.len() > MAX_DATA_SIZE {
            return None;
        }
        let mut frame = Self::new(cmd as u8);
        for &b in data {
            let _ = frame.data.push(b);
        }
        Some(frame)
    }

    pub fn encode(&self) -> Vec<u8, MAX_FRAME_SIZE> {
        let mut buf = Vec::new();

        let _ = buf.push(FEND);

        escape_byte(self.command, &mut buf);

        for &b in &self.data {
            escape_byte(b, &mut buf);
        }

        let _ = buf.push(FEND);

        buf
    }

    pub fn port(&self) -> u8 {
        (self.command >> 4) & 0x0F
    }

    pub fn cmd_type(&self) -> u8 {
        self.command & 0x0F
    }
}

fn escape_byte(byte: u8, buf: &mut Vec<u8, MAX_FRAME_SIZE>) {
    match byte {
        FEND => {
            let _ = buf.push(FESC);
            let _ = buf.push(TFEND);
        }
        FESC => {
            let _ = buf.push(FESC);
            let _ = buf.push(TFESC);
        }
        _ => {
            let _ = buf.push(byte);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserState {

    WaitStart,

    WaitCommand,

    ReadData,

    Escape,
}

pub struct KissParser {
    state: ParserState,
    command: u8,
    data: Vec<u8, MAX_DATA_SIZE>,
}

impl Default for KissParser {
    fn default() -> Self {
        Self::new()
    }
}

impl KissParser {
    pub fn new() -> Self {
        Self {
            state: ParserState::WaitStart,
            command: 0,
            data: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.state = ParserState::WaitStart;
        self.command = 0;
        self.data.clear();
    }

    pub fn feed(&mut self, byte: u8) -> Option<KissFrame> {
        match self.state {
            ParserState::WaitStart => {
                if byte == FEND {
                    self.state = ParserState::WaitCommand;
                    self.data.clear();
                }
            }

            ParserState::WaitCommand => {
                match byte {
                    FEND => {

                    }
                    FESC => {

                        self.state = ParserState::Escape;
                    }
                    _ => {
                        self.command = byte;
                        self.state = ParserState::ReadData;
                    }
                }
            }

            ParserState::ReadData => {
                match byte {
                    FEND => {

                        let frame = KissFrame {
                            command: self.command,
                            data: self.data.clone(),
                        };
                        self.reset();
                        return Some(frame);
                    }
                    FESC => {
                        self.state = ParserState::Escape;
                    }
                    _ => {
                        let _ = self.data.push(byte);
                    }
                }
            }

            ParserState::Escape => {
                let unescaped = match byte {
                    TFEND => FEND,
                    TFESC => FESC,
                    _ => byte,
                };
                let _ = self.data.push(unescaped);
                self.state = ParserState::ReadData;
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RNodeState {

    Offline,

    Online,

    Transmitting,

    Receiving,
}

#[derive(Debug, Clone)]
pub struct RNodeConfig {

    pub frequency: u32,

    pub bandwidth: u32,

    pub tx_power: i8,

    pub spreading_factor: u8,

    pub coding_rate: u8,

    pub preamble_length: u16,

    pub sync_word: u8,

    pub crc_enabled: bool,

    pub implicit_header: bool,

    pub ldro: bool,
}

impl Default for RNodeConfig {
    fn default() -> Self {
        Self {
            frequency: 868_100_000,
            bandwidth: 125_000,
            tx_power: 14,
            spreading_factor: 9,
            coding_rate: 5,
            preamble_length: 8,
            sync_word: 0x12,
            crc_enabled: true,
            implicit_header: false,
            ldro: false,
        }
    }
}

impl RNodeConfig {

    pub fn eu868() -> Self {
        Self {
            frequency: 868_100_000,
            ..Default::default()
        }
    }

    pub fn us915() -> Self {
        Self {
            frequency: 915_000_000,
            ..Default::default()
        }
    }

    pub fn bandwidth_to_hz(bw_value: u8) -> u32 {
        match bw_value {
            0 => 125_000,
            1 => 250_000,
            2 => 500_000,
            _ => 125_000,
        }
    }

    pub fn hz_to_bandwidth(hz: u32) -> u8 {
        match hz {
            0..=187_500 => 0,
            187_501..=375_000 => 1,
            _ => 2,
        }
    }

    pub fn coding_rate_to_ratio(cr: u8) -> (u8, u8) {
        (4, cr)
    }

    pub fn should_enable_ldro(&self) -> bool {

        if self.bandwidth <= 125_000 {
            self.spreading_factor >= 11
        } else if self.bandwidth <= 250_000 {
            self.spreading_factor >= 12
        } else {
            false
        }
    }

    pub fn packet_airtime_ms(&self, payload_len: usize) -> u32 {
        let sf = self.spreading_factor as f32;
        let bw = self.bandwidth as f32;
        let cr = self.coding_rate as f32;
        let pl = payload_len as f32;
        let preamble = self.preamble_length as f32;

        let t_sym = (2.0_f32.powf(sf)) / bw * 1000.0;

        let t_preamble = (preamble + 4.25) * t_sym;

        let de = if self.should_enable_ldro() { 1.0 } else { 0.0 };
        let h = if self.implicit_header { 1.0 } else { 0.0 };
        let crc = if self.crc_enabled { 1.0 } else { 0.0 };

        let numerator = 8.0 * pl - 4.0 * sf + 28.0 + 16.0 * crc - 20.0 * h;
        let denominator = 4.0 * (sf - 2.0 * de);
        let n_payload = 8.0 + (numerator / denominator).ceil().max(0.0) * (cr);

        let t_payload = n_payload * t_sym;

        (t_preamble + t_payload) as u32
    }

    #[cfg(feature = "sx1262")]
    pub fn to_radio_config(&self) -> crate::sx1262::RadioConfig {
        crate::sx1262::RadioConfig {
            frequency: self.frequency,
            spreading_factor: self.spreading_factor,
            bandwidth: Self::hz_to_bandwidth(self.bandwidth),
            coding_rate: self.coding_rate.saturating_sub(4),
            tx_power: self.tx_power,
            sync_word: self.sync_word,
            preamble_length: self.preamble_length,
            crc_enabled: self.crc_enabled,
            implicit_header: self.implicit_header,
            ldro: self.should_enable_ldro(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RNodeStats {

    pub rx_count: u32,

    pub rx_bytes: u64,

    pub tx_count: u32,

    pub tx_bytes: u64,

    pub last_rssi: i16,

    pub last_snr: i8,

    pub airtime_used: u64,

    pub channel_busy: u64,
}

#[derive(Debug, Clone)]
pub struct RNodeIdentity {

    pub serial: [u8; 16],

    pub platform: &'static str,

    pub mcu: &'static str,

    pub board: &'static str,

    pub fw_version: &'static str,

    pub protocol_version: u8,

    pub hw_revision: u8,
}

impl Default for RNodeIdentity {
    fn default() -> Self {
        Self {
            serial: [0u8; 16],
            platform: "ESP32-S3",
            mcu: "ESP32-S3",
            board: "LunarNode",
            fw_version: "1.0.0-lunarcore",
            protocol_version: 1,
            hw_revision: 1,
        }
    }
}

impl RNodeIdentity {

    pub fn identity_hash(&self) -> [u8; 32] {
        let mut data = [0u8; 64];
        data[..16].copy_from_slice(&self.serial);
        data[16..24].copy_from_slice(self.platform.as_bytes().get(..8).unwrap_or(b"ESP32-S3"));
        data[24] = self.protocol_version;
        data[25] = self.hw_revision;
        Sha256::hash(&data)
    }
}

pub struct RNodeHandler {

    parser: KissParser,

    config: RNodeConfig,

    state: RNodeState,

    locked: bool,

    promiscuous: bool,

    stats: RNodeStats,

    identity: RNodeIdentity,

    random_seed: u32,

    battery_mv: u16,

    led_intensity: u8,

    airtime_limit: u32,
}

impl RNodeHandler {

    pub fn new() -> Self {
        Self {
            parser: KissParser::new(),
            config: RNodeConfig::default(),
            state: RNodeState::Offline,
            locked: false,
            promiscuous: false,
            stats: RNodeStats::default(),
            identity: RNodeIdentity::default(),
            random_seed: 0,
            battery_mv: 0,
            led_intensity: 64,
            airtime_limit: 0,
        }
    }

    pub fn with_identity(identity: RNodeIdentity) -> Self {
        Self {
            identity,
            ..Self::new()
        }
    }

    pub fn set_serial(&mut self, serial: &[u8; 16]) {
        self.identity.serial = *serial;
    }

    pub fn set_battery_voltage(&mut self, mv: u16) {
        self.battery_mv = mv;
    }

    pub fn set_random_seed(&mut self, seed: u32) {
        self.random_seed = seed;
    }

    pub fn next_random(&mut self) -> u32 {

        self.random_seed = self.random_seed.wrapping_mul(1103515245).wrapping_add(12345);
        self.random_seed
    }

    pub fn feed_serial(&mut self, byte: u8) -> Option<KissFrame> {
        self.parser.feed(byte)
    }

    pub fn process_frame(&mut self, frame: &KissFrame) -> Option<KissFrame> {

        if frame.command == KissCommand::DataFrame as u8 {
            return None;
        }

        match RNodeCommand::from_byte(frame.command) {

            Some(RNodeCommand::Frequency) => {
                if frame.data.len() >= 4 && !self.locked {
                    self.config.frequency = u32::from_be_bytes([
                        frame.data[0], frame.data[1], frame.data[2], frame.data[3]
                    ]);
                }

                KissFrame::command_frame(RNodeCommand::Frequency, &self.config.frequency.to_be_bytes())
            }

            Some(RNodeCommand::Bandwidth) => {
                if frame.data.len() >= 4 && !self.locked {
                    self.config.bandwidth = u32::from_be_bytes([
                        frame.data[0], frame.data[1], frame.data[2], frame.data[3]
                    ]);
                }
                KissFrame::command_frame(RNodeCommand::Bandwidth, &self.config.bandwidth.to_be_bytes())
            }

            Some(RNodeCommand::TxPower) => {
                if frame.data.len() >= 1 && !self.locked {

                    let power = (frame.data[0] as i8).max(-9).min(22);
                    self.config.tx_power = power;
                }
                KissFrame::command_frame(RNodeCommand::TxPower, &[self.config.tx_power as u8])
            }

            Some(RNodeCommand::SpreadingFactor) => {
                if frame.data.len() >= 1 && !self.locked {
                    let sf = frame.data[0].max(7).min(12);
                    self.config.spreading_factor = sf;

                    self.config.ldro = self.config.should_enable_ldro();
                }
                KissFrame::command_frame(RNodeCommand::SpreadingFactor, &[self.config.spreading_factor])
            }

            Some(RNodeCommand::CodingRate) => {
                if frame.data.len() >= 1 && !self.locked {
                    let cr = frame.data[0].max(5).min(8);
                    self.config.coding_rate = cr;
                }
                KissFrame::command_frame(RNodeCommand::CodingRate, &[self.config.coding_rate])
            }

            Some(RNodeCommand::PreambleLength) => {
                if frame.data.len() >= 2 && !self.locked {
                    self.config.preamble_length = u16::from_be_bytes([frame.data[0], frame.data[1]]);
                }
                KissFrame::command_frame(RNodeCommand::PreambleLength, &self.config.preamble_length.to_be_bytes())
            }

            Some(RNodeCommand::SyncWord) => {
                if frame.data.len() >= 1 && !self.locked {
                    self.config.sync_word = frame.data[0];
                }
                KissFrame::command_frame(RNodeCommand::SyncWord, &[self.config.sync_word])
            }

            Some(RNodeCommand::CrcMode) => {
                if frame.data.len() >= 1 && !self.locked {
                    self.config.crc_enabled = frame.data[0] != 0;
                }
                KissFrame::command_frame(RNodeCommand::CrcMode, &[if self.config.crc_enabled { 1 } else { 0 }])
            }

            Some(RNodeCommand::ImplicitHeader) => {
                if frame.data.len() >= 1 && !self.locked {
                    self.config.implicit_header = frame.data[0] != 0;
                }
                KissFrame::command_frame(RNodeCommand::ImplicitHeader, &[if self.config.implicit_header { 1 } else { 0 }])
            }

            Some(RNodeCommand::Ldro) => {
                if frame.data.len() >= 1 && !self.locked {
                    self.config.ldro = frame.data[0] != 0;
                }
                KissFrame::command_frame(RNodeCommand::Ldro, &[if self.config.ldro { 1 } else { 0 }])
            }

            Some(RNodeCommand::RadioState) => {
                if frame.data.len() >= 1 {
                    self.state = if frame.data[0] != 0 {
                        RNodeState::Online
                    } else {
                        RNodeState::Offline
                    };
                }
                KissFrame::command_frame(
                    RNodeCommand::RadioState,
                    &[if self.state != RNodeState::Offline { 1 } else { 0 }],
                )
            }

            Some(RNodeCommand::RadioLock) => {
                if frame.data.len() >= 1 {
                    self.locked = frame.data[0] != 0;
                }
                KissFrame::command_frame(RNodeCommand::RadioLock, &[if self.locked { 1 } else { 0 }])
            }

            Some(RNodeCommand::Promisc) => {
                if frame.data.len() >= 1 {
                    self.promiscuous = frame.data[0] != 0;
                }
                KissFrame::command_frame(RNodeCommand::Promisc, &[if self.promiscuous { 1 } else { 0 }])
            }

            Some(RNodeCommand::Detect) => {

                KissFrame::command_frame(RNodeCommand::Detect, &[0x01, self.identity.hw_revision])
            }

            Some(RNodeCommand::Ready) => {

                KissFrame::command_frame(RNodeCommand::Ready, &[0x01])
            }

            Some(RNodeCommand::FwVersion) => {
                KissFrame::command_frame(
                    RNodeCommand::FwVersion,
                    self.identity.fw_version.as_bytes(),
                )
            }

            Some(RNodeCommand::ProtocolVersion) => {
                KissFrame::command_frame(RNodeCommand::ProtocolVersion, &[self.identity.protocol_version])
            }

            Some(RNodeCommand::Platform) => {
                KissFrame::command_frame(
                    RNodeCommand::Platform,
                    self.identity.platform.as_bytes(),
                )
            }

            Some(RNodeCommand::Mcu) => {
                KissFrame::command_frame(
                    RNodeCommand::Mcu,
                    self.identity.mcu.as_bytes(),
                )
            }

            Some(RNodeCommand::Board) => {
                KissFrame::command_frame(
                    RNodeCommand::Board,
                    self.identity.board.as_bytes(),
                )
            }

            Some(RNodeCommand::HardwareSerial) => {
                KissFrame::command_frame(RNodeCommand::HardwareSerial, &self.identity.serial)
            }

            Some(RNodeCommand::Signature) => {

                let hash = self.identity.identity_hash();
                KissFrame::command_frame(RNodeCommand::Signature, &hash)
            }

            Some(RNodeCommand::StatRx) => {
                KissFrame::command_frame(RNodeCommand::StatRx, &self.stats.rx_count.to_be_bytes())
            }

            Some(RNodeCommand::StatTx) => {
                KissFrame::command_frame(RNodeCommand::StatTx, &self.stats.tx_count.to_be_bytes())
            }

            Some(RNodeCommand::StatRssi) => {
                KissFrame::command_frame(RNodeCommand::StatRssi, &self.stats.last_rssi.to_be_bytes())
            }

            Some(RNodeCommand::StatSnr) => {
                KissFrame::command_frame(RNodeCommand::StatSnr, &[self.stats.last_snr as u8])
            }

            Some(RNodeCommand::StatBattery) => {
                KissFrame::command_frame(RNodeCommand::StatBattery, &self.battery_mv.to_be_bytes())
            }

            Some(RNodeCommand::StatChannel) => {

                let util = if self.stats.channel_busy > 0 {
                    ((self.stats.airtime_used * 100) / self.stats.channel_busy).min(100) as u8
                } else {
                    0u8
                };
                KissFrame::command_frame(RNodeCommand::StatChannel, &[util])
            }

            Some(RNodeCommand::AirtimeLimit) => {
                if frame.data.len() >= 4 {
                    self.airtime_limit = u32::from_be_bytes([
                        frame.data[0], frame.data[1], frame.data[2], frame.data[3]
                    ]);
                }
                KissFrame::command_frame(RNodeCommand::AirtimeLimit, &self.airtime_limit.to_be_bytes())
            }

            Some(RNodeCommand::AirtimeUsage) => {
                let usage = (self.stats.airtime_used % (u32::MAX as u64)) as u32;
                KissFrame::command_frame(RNodeCommand::AirtimeUsage, &usage.to_be_bytes())
            }

            Some(RNodeCommand::Blink) => {

                KissFrame::command_frame(RNodeCommand::Blink, &[0x01])
            }

            Some(RNodeCommand::LedIntensity) => {
                if frame.data.len() >= 1 {
                    self.led_intensity = frame.data[0];
                }
                KissFrame::command_frame(RNodeCommand::LedIntensity, &[self.led_intensity])
            }

            Some(RNodeCommand::Random) => {

                let r = self.next_random();
                KissFrame::command_frame(RNodeCommand::Random, &r.to_be_bytes())
            }

            Some(RNodeCommand::Leave) => {

                self.state = RNodeState::Offline;
                None
            }

            Some(RNodeCommand::SaveConfig) => {

                KissFrame::command_frame(RNodeCommand::SaveConfig, &[0x01])
            }

            Some(RNodeCommand::ResetConfig) => {
                if !self.locked {
                    self.config = RNodeConfig::default();
                }
                KissFrame::command_frame(RNodeCommand::ResetConfig, &[0x01])
            }

            Some(RNodeCommand::Bootloader) => {

                KissFrame::command_frame(RNodeCommand::Bootloader, &[0x01])
            }

            Some(RNodeCommand::Error) => {

                if !frame.data.is_empty() {
                    KissFrame::command_frame(RNodeCommand::Error, &frame.data)
                } else {
                    None
                }
            }

            _ => {

                KissFrame::command_frame(RNodeCommand::Error, &[0xFF])
            }
        }
    }

    pub fn process_lora_packet(&mut self, data: &[u8], rssi: i16, snr: i8) -> KissFrame {
        self.stats.rx_count += 1;
        self.stats.rx_bytes += data.len() as u64;
        self.stats.last_rssi = rssi;
        self.stats.last_snr = snr;

        let mut frame = KissFrame::new(RNodeCommand::DataRssi as u8);
        for &b in data {
            let _ = frame.data.push(b);
        }

        let rssi_bytes = rssi.to_be_bytes();
        let _ = frame.data.push(rssi_bytes[0]);
        let _ = frame.data.push(rssi_bytes[1]);
        let _ = frame.data.push(snr as u8);

        frame
    }

    pub fn process_lora_packet_raw(&mut self, data: &[u8]) -> KissFrame {
        self.stats.rx_count += 1;
        self.stats.rx_bytes += data.len() as u64;

        let mut frame = KissFrame::new(KissCommand::DataFrame as u8);
        for &b in data {
            let _ = frame.data.push(b);
        }
        frame
    }

    pub fn get_tx_data<'a>(&mut self, frame: &'a KissFrame) -> Option<&'a [u8]> {
        if frame.command == KissCommand::DataFrame as u8 {
            self.stats.tx_count += 1;
            self.stats.tx_bytes += frame.data.len() as u64;

            let airtime = self.config.packet_airtime_ms(frame.data.len()) as u64;
            self.stats.airtime_used += airtime;
            Some(&frame.data)
        } else {
            None
        }
    }

    pub fn record_channel_busy(&mut self, ms: u64) {
        self.stats.channel_busy += ms;
    }

    pub fn config(&self) -> &RNodeConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut RNodeConfig {
        &mut self.config
    }

    pub fn state(&self) -> RNodeState {
        self.state
    }

    pub fn set_state(&mut self, state: RNodeState) {
        self.state = state;
    }

    pub fn stats(&self) -> &RNodeStats {
        &self.stats
    }

    pub fn reset_stats(&mut self) {
        self.stats = RNodeStats::default();
    }

    pub fn identity(&self) -> &RNodeIdentity {
        &self.identity
    }

    pub fn is_online(&self) -> bool {
        self.state != RNodeState::Offline
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn is_promiscuous(&self) -> bool {
        self.promiscuous
    }

    pub fn check_airtime_limit(&self, packet_len: usize) -> bool {
        if self.airtime_limit == 0 {
            return true;
        }
        let airtime = self.config.packet_airtime_ms(packet_len) as u64;

        self.stats.airtime_used + airtime <= self.airtime_limit as u64
    }
}

impl Default for RNodeHandler {
    fn default() -> Self {
        Self::new()
    }
}
