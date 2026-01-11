use heapless::Vec;

pub const SYNC: [u8; 2] = [0xAA, 0x55];

pub const END: u8 = 0x0D;

pub const MAX_DATA_SIZE: usize = 255;

pub const MAX_FRAME_SIZE: usize = 2 + 2 + 1 + 1 + MAX_DATA_SIZE + 2 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {

    Ping = 0x01,

    Pong = 0x02,

    Configure = 0x10,

    ConfigAck = 0x11,

    Transmit = 0x20,

    TxDone = 0x21,

    TxError = 0x22,

    Receive = 0x30,

    GetStats = 0x40,

    StatsResponse = 0x41,

    Cad = 0x50,

    CadResult = 0x51,

    Reset = 0xF0,

    Version = 0xF1,

    VersionResponse = 0xF2,

    Error = 0xFF,
}

impl Command {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Command::Ping),
            0x02 => Some(Command::Pong),
            0x10 => Some(Command::Configure),
            0x11 => Some(Command::ConfigAck),
            0x20 => Some(Command::Transmit),
            0x21 => Some(Command::TxDone),
            0x22 => Some(Command::TxError),
            0x30 => Some(Command::Receive),
            0x40 => Some(Command::GetStats),
            0x41 => Some(Command::StatsResponse),
            0x50 => Some(Command::Cad),
            0x51 => Some(Command::CadResult),
            0xF0 => Some(Command::Reset),
            0xF1 => Some(Command::Version),
            0xF2 => Some(Command::VersionResponse),
            0xFF => Some(Command::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub command: Command,
    pub sequence: u8,
    pub data: Vec<u8, MAX_DATA_SIZE>,
}

impl Frame {

    pub fn new(command: Command, sequence: u8) -> Self {
        Self {
            command,
            sequence,
            data: Vec::new(),
        }
    }

    pub fn with_data(command: Command, sequence: u8, data: &[u8]) -> Option<Self> {
        let mut frame = Self::new(command, sequence);
        if data.len() > MAX_DATA_SIZE {
            return None;
        }
        for &b in data {
            let _ = frame.data.push(b);
        }
        Some(frame)
    }

    pub fn encode(&self) -> Vec<u8, MAX_FRAME_SIZE> {
        let mut buf = Vec::new();

        let _ = buf.push(SYNC[0]);
        let _ = buf.push(SYNC[1]);

        let len = self.data.len() as u16;
        let _ = buf.push(len as u8);
        let _ = buf.push((len >> 8) as u8);

        let _ = buf.push(self.command as u8);
        let _ = buf.push(self.sequence);

        for &b in &self.data {
            let _ = buf.push(b);
        }

        let crc = crc16(&buf[4..]);
        let _ = buf.push(crc as u8);
        let _ = buf.push((crc >> 8) as u8);

        let _ = buf.push(END);

        buf
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserState {
    WaitSync1,
    WaitSync2,
    WaitLenLow,
    WaitLenHigh,
    WaitCommand,
    WaitSequence,
    WaitData,
    WaitCrcLow,
    WaitCrcHigh,
    WaitEnd,
}

pub struct FrameParser {
    state: ParserState,
    data_len: u16,
    data_idx: u16,
    command: u8,
    sequence: u8,
    data: Vec<u8, MAX_DATA_SIZE>,
    crc_low: u8,
}

impl Default for FrameParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameParser {
    pub fn new() -> Self {
        Self {
            state: ParserState::WaitSync1,
            data_len: 0,
            data_idx: 0,
            command: 0,
            sequence: 0,
            data: Vec::new(),
            crc_low: 0,
        }
    }

    pub fn reset(&mut self) {
        self.state = ParserState::WaitSync1;
        self.data.clear();
        self.data_len = 0;
        self.data_idx = 0;
    }

    pub fn feed(&mut self, byte: u8) -> Option<Frame> {
        match self.state {
            ParserState::WaitSync1 => {
                if byte == SYNC[0] {
                    self.state = ParserState::WaitSync2;
                }
            }
            ParserState::WaitSync2 => {
                if byte == SYNC[1] {
                    self.state = ParserState::WaitLenLow;
                } else if byte == SYNC[0] {

                } else {
                    self.reset();
                }
            }
            ParserState::WaitLenLow => {
                self.data_len = byte as u16;
                self.state = ParserState::WaitLenHigh;
            }
            ParserState::WaitLenHigh => {
                self.data_len |= (byte as u16) << 8;
                if self.data_len > MAX_DATA_SIZE as u16 {
                    self.reset();
                    return None;
                }
                self.state = ParserState::WaitCommand;
            }
            ParserState::WaitCommand => {
                self.command = byte;
                self.state = ParserState::WaitSequence;
            }
            ParserState::WaitSequence => {
                self.sequence = byte;
                self.data.clear();
                self.data_idx = 0;
                if self.data_len == 0 {
                    self.state = ParserState::WaitCrcLow;
                } else {
                    self.state = ParserState::WaitData;
                }
            }
            ParserState::WaitData => {
                let _ = self.data.push(byte);
                self.data_idx += 1;
                if self.data_idx >= self.data_len {
                    self.state = ParserState::WaitCrcLow;
                }
            }
            ParserState::WaitCrcLow => {
                self.crc_low = byte;
                self.state = ParserState::WaitCrcHigh;
            }
            ParserState::WaitCrcHigh => {
                let received_crc = (self.crc_low as u16) | ((byte as u16) << 8);

                let mut crc_data: Vec<u8, 258> = Vec::new();
                let _ = crc_data.push(self.command);
                let _ = crc_data.push(self.sequence);
                for &b in &self.data {
                    let _ = crc_data.push(b);
                }
                let calculated_crc = crc16(&crc_data);

                if received_crc == calculated_crc {
                    self.state = ParserState::WaitEnd;
                } else {
                    self.reset();
                }
            }
            ParserState::WaitEnd => {
                if byte == END {

                    if let Some(cmd) = Command::from_byte(self.command) {
                        let frame = Frame {
                            command: cmd,
                            sequence: self.sequence,
                            data: self.data.clone(),
                        };
                        self.reset();
                        return Some(frame);
                    }
                }
                self.reset();
            }
        }
        None
    }
}

#[rustfmt::skip]
const CRC16_TABLE: [u16; 256] = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0,
];

#[inline]
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        let index = ((crc >> 8) ^ (byte as u16)) as usize;
        crc = (crc << 8) ^ CRC16_TABLE[index];
    }
    crc
}

pub fn build_pong(sequence: u8) -> Frame {
    Frame::new(Command::Pong, sequence)
}

pub fn build_config_ack(sequence: u8) -> Frame {
    Frame::new(Command::ConfigAck, sequence)
}

pub fn build_tx_done(sequence: u8) -> Frame {
    Frame::new(Command::TxDone, sequence)
}

pub fn build_tx_error(sequence: u8, error_code: u8) -> Option<Frame> {
    Frame::with_data(Command::TxError, sequence, &[error_code])
}

pub fn build_receive(rssi: i16, snr: i8, data: &[u8]) -> Option<Frame> {
    if data.len() > MAX_DATA_SIZE - 4 {
        return None;
    }

    let mut frame = Frame::new(Command::Receive, 0);

    let _ = frame.data.push(rssi as u8);
    let _ = frame.data.push((rssi >> 8) as u8);

    let _ = frame.data.push(snr as u8);

    let _ = frame.data.push(0);

    for &b in data {
        let _ = frame.data.push(b);
    }

    Some(frame)
}

pub fn build_cad_result(sequence: u8, detected: bool) -> Option<Frame> {
    Frame::with_data(Command::CadResult, sequence, &[if detected { 1 } else { 0 }])
}

pub fn build_version_response(sequence: u8, version: &str) -> Option<Frame> {
    Frame::with_data(Command::VersionResponse, sequence, version.as_bytes())
}

pub fn build_error(sequence: u8, message: &str) -> Option<Frame> {
    Frame::with_data(Command::Error, sequence, message.as_bytes())
}

pub fn build_stats_response(
    sequence: u8,
    tx_packets: u32,
    rx_packets: u32,
    tx_errors: u32,
    rx_errors: u32,
) -> Option<Frame> {
    let mut data = [0u8; 16];
    data[0..4].copy_from_slice(&tx_packets.to_le_bytes());
    data[4..8].copy_from_slice(&rx_packets.to_le_bytes());
    data[8..12].copy_from_slice(&tx_errors.to_le_bytes());
    data[12..16].copy_from_slice(&rx_errors.to_le_bytes());
    Frame::with_data(Command::StatsResponse, sequence, &data)
}

pub fn parse_config(data: &[u8]) -> Option<crate::sx1262::RadioConfig> {
    if data.len() < 14 {
        return None;
    }

    let frequency = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let spreading_factor = data[4];
    let bandwidth = (u16::from_le_bytes([data[5], data[6]]) / 125) as u8;
    let coding_rate = data[7];
    let tx_power = data[8] as i8;
    let sync_word = data[9];
    let preamble_length = u16::from_le_bytes([data[10], data[11]]);
    let flags = data[12];

    Some(crate::sx1262::RadioConfig {
        frequency,
        spreading_factor,
        bandwidth: bandwidth.min(2),
        coding_rate,
        tx_power,
        sync_word,
        preamble_length,
        crc_enabled: flags & 0x01 != 0,
        implicit_header: flags & 0x02 != 0,
        ldro: flags & 0x04 != 0,
    })
}
