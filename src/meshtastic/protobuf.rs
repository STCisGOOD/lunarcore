use heapless::Vec;
use super::{DataPayload, Position, User, PortNum, HardwareModel, Role, LocationSource, MAX_LORA_PAYLOAD};


const WIRE_TYPE_VARINT: u8 = 0;

const WIRE_TYPE_64BIT: u8 = 1;

const WIRE_TYPE_LENGTH_DELIMITED: u8 = 2;

const WIRE_TYPE_32BIT: u8 = 5;


mod data_fields {
    pub const PORTNUM: u32 = 1;
    pub const PAYLOAD: u32 = 2;
    pub const WANT_RESPONSE: u32 = 3;
    pub const DEST: u32 = 4;
    pub const SOURCE: u32 = 5;
    pub const REQUEST_ID: u32 = 6;
    pub const REPLY_ID: u32 = 7;
    pub const EMOJI: u32 = 8;
}


mod position_fields {
    pub const LATITUDE_I: u32 = 1;
    pub const LONGITUDE_I: u32 = 2;
    pub const ALTITUDE: u32 = 3;
    pub const TIME: u32 = 4;
    pub const LOCATION_SOURCE: u32 = 5;
    pub const ALTITUDE_SOURCE: u32 = 6;
    pub const TIMESTAMP: u32 = 7;
    pub const TIMESTAMP_MILLIS_ADJUST: u32 = 8;
    pub const ALTITUDE_HAE: u32 = 9;
    pub const ALTITUDE_GEOIDAL_SEPARATION: u32 = 10;
    pub const PDOP: u32 = 11;
    pub const HDOP: u32 = 12;
    pub const VDOP: u32 = 13;
    pub const GPS_ACCURACY: u32 = 14;
    pub const GROUND_SPEED: u32 = 15;
    pub const GROUND_TRACK: u32 = 16;
    pub const FIX_QUALITY: u32 = 17;
    pub const FIX_TYPE: u32 = 18;
    pub const SATS_IN_VIEW: u32 = 19;
    pub const SENSOR_ID: u32 = 20;
    pub const NEXT_UPDATE: u32 = 21;
    pub const SEQ_NUMBER: u32 = 22;
}


mod user_fields {
    pub const ID: u32 = 1;
    pub const LONG_NAME: u32 = 2;
    pub const SHORT_NAME: u32 = 3;
    pub const MACADDR: u32 = 4;
    pub const HW_MODEL: u32 = 5;
    pub const IS_LICENSED: u32 = 6;
    pub const ROLE: u32 = 7;
}


pub struct ProtobufEncoder<const N: usize> {
    buffer: Vec<u8, N>,
}

impl<const N: usize> ProtobufEncoder<N> {

    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }


    pub fn finish(self) -> Vec<u8, N> {
        self.buffer
    }


    pub fn write_varint(&mut self, value: u64) -> bool {
        let mut v = value;
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                return self.buffer.push(byte).is_ok();
            } else {
                if self.buffer.push(byte | 0x80).is_err() {
                    return false;
                }
            }
        }
    }


    pub fn write_sint32(&mut self, value: i32) -> bool {
        let encoded = ((value << 1) ^ (value >> 31)) as u32;
        self.write_varint(encoded as u64)
    }


    pub fn write_sint64(&mut self, value: i64) -> bool {
        let encoded = ((value << 1) ^ (value >> 63)) as u64;
        self.write_varint(encoded)
    }


    pub fn write_tag(&mut self, field_number: u32, wire_type: u8) -> bool {
        let tag = (field_number << 3) | (wire_type as u32);
        self.write_varint(tag as u64)
    }


    pub fn write_varint_field(&mut self, field_number: u32, value: u64) -> bool {
        if value == 0 {
            return true;
        }
        self.write_tag(field_number, WIRE_TYPE_VARINT) && self.write_varint(value)
    }


    pub fn write_sint32_field(&mut self, field_number: u32, value: i32) -> bool {
        if value == 0 {
            return true;
        }
        self.write_tag(field_number, WIRE_TYPE_VARINT) && self.write_sint32(value)
    }


    pub fn write_bool_field(&mut self, field_number: u32, value: bool) -> bool {
        if !value {
            return true;
        }
        self.write_tag(field_number, WIRE_TYPE_VARINT) && self.buffer.push(1).is_ok()
    }


    pub fn write_bytes_field(&mut self, field_number: u32, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        self.write_tag(field_number, WIRE_TYPE_LENGTH_DELIMITED)
            && self.write_varint(data.len() as u64)
            && self.buffer.extend_from_slice(data).is_ok()
    }


    pub fn write_string_field(&mut self, field_number: u32, s: &str) -> bool {
        self.write_bytes_field(field_number, s.as_bytes())
    }


    pub fn write_fixed32_field(&mut self, field_number: u32, value: u32) -> bool {
        if value == 0 {
            return true;
        }
        if !self.write_tag(field_number, WIRE_TYPE_32BIT) {
            return false;
        }
        let bytes = value.to_le_bytes();
        self.buffer.extend_from_slice(&bytes).is_ok()
    }


    pub fn write_fixed64_field(&mut self, field_number: u32, value: u64) -> bool {
        if value == 0 {
            return true;
        }
        if !self.write_tag(field_number, WIRE_TYPE_64BIT) {
            return false;
        }
        let bytes = value.to_le_bytes();
        self.buffer.extend_from_slice(&bytes).is_ok()
    }


    pub fn write_message_field<F>(&mut self, field_number: u32, encode_fn: F) -> bool
    where
        F: FnOnce(&mut ProtobufEncoder<256>) -> bool,
    {
        let mut nested = ProtobufEncoder::<256>::new();
        if !encode_fn(&mut nested) {
            return false;
        }
        let nested_data = nested.finish();
        if nested_data.is_empty() {
            return true;
        }
        self.write_bytes_field(field_number, &nested_data)
    }
}

impl<const N: usize> Default for ProtobufEncoder<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ProtobufEncoder<N> {


    pub fn encode_varint_to_slice<const M: usize>(value: u64, output: &mut Vec<u8, M>) {
        let mut v = value;
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                let _ = output.push(byte);
                break;
            } else {
                let _ = output.push(byte | 0x80);
            }
        }
    }
}


pub struct ProtobufDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ProtobufDecoder<'a> {

    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }


    pub fn has_more(&self) -> bool {
        self.pos < self.data.len()
    }


    pub fn read_varint(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0;

        loop {
            if self.pos >= self.data.len() {
                return None;
            }

            let byte = self.data[self.pos];
            self.pos += 1;

            result |= ((byte & 0x7F) as u64) << shift;

            if byte & 0x80 == 0 {
                return Some(result);
            }

            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
    }


    pub fn read_sint32(&mut self) -> Option<i32> {
        let encoded = self.read_varint()? as u32;
        Some(((encoded >> 1) as i32) ^ -((encoded & 1) as i32))
    }


    pub fn read_sint64(&mut self) -> Option<i64> {
        let encoded = self.read_varint()?;
        Some(((encoded >> 1) as i64) ^ -((encoded & 1) as i64))
    }


    pub fn read_tag(&mut self) -> Option<(u32, u8)> {
        let tag = self.read_varint()? as u32;
        let field_number = tag >> 3;
        let wire_type = (tag & 0x07) as u8;
        Some((field_number, wire_type))
    }


    pub fn next_field(&mut self) -> Option<(u32, u8, &'a [u8])> {
        if !self.has_more() {
            return None;
        }

        let (field_number, wire_type) = self.read_tag()?;

        let field_data = match wire_type {
            WIRE_TYPE_VARINT => {

                let start = self.pos;
                while self.pos < self.data.len() {
                    let byte = self.data[self.pos];
                    self.pos += 1;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                &self.data[start..self.pos]
            }
            WIRE_TYPE_64BIT => {
                if self.pos + 8 > self.data.len() {
                    return None;
                }
                let result = &self.data[self.pos..self.pos + 8];
                self.pos += 8;
                result
            }
            WIRE_TYPE_LENGTH_DELIMITED => {
                let len = self.read_varint()? as usize;
                if self.pos + len > self.data.len() {
                    return None;
                }
                let result = &self.data[self.pos..self.pos + len];
                self.pos += len;
                result
            }
            WIRE_TYPE_32BIT => {
                if self.pos + 4 > self.data.len() {
                    return None;
                }
                let result = &self.data[self.pos..self.pos + 4];
                self.pos += 4;
                result
            }
            _ => return None,
        };

        Some((field_number, wire_type, field_data))
    }


    pub fn read_bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.read_varint()? as usize;
        if self.pos + len > self.data.len() {
            return None;
        }
        let result = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some(result)
    }


    pub fn read_fixed32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let result = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Some(result)
    }


    pub fn read_fixed64(&mut self) -> Option<u64> {
        if self.pos + 8 > self.data.len() {
            return None;
        }
        let result = u64::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Some(result)
    }


    pub fn skip_field(&mut self, wire_type: u8) -> bool {
        match wire_type {
            WIRE_TYPE_VARINT => self.read_varint().is_some(),
            WIRE_TYPE_64BIT => {
                if self.pos + 8 <= self.data.len() {
                    self.pos += 8;
                    true
                } else {
                    false
                }
            }
            WIRE_TYPE_LENGTH_DELIMITED => self.read_bytes().is_some(),
            WIRE_TYPE_32BIT => {
                if self.pos + 4 <= self.data.len() {
                    self.pos += 4;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }


    pub fn read_varint_from_slice(data: &[u8]) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0;

        for &byte in data.iter() {
            result |= ((byte & 0x7F) as u64) << shift;

            if byte & 0x80 == 0 {
                return Some(result);
            }

            shift += 7;
            if shift >= 64 {
                return None;
            }
        }

        None
    }


    pub fn read_varint_advancing(data: &mut &[u8]) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0;
        let mut consumed = 0;

        for (i, &byte) in data.iter().enumerate() {
            result |= ((byte & 0x7F) as u64) << shift;
            consumed = i + 1;

            if byte & 0x80 == 0 {
                *data = &data[consumed..];
                return Some(result);
            }

            shift += 7;
            if shift >= 64 {
                return None;
            }
        }

        None
    }


    pub fn read_bytes_from_slice<'b>(data: &mut &'b [u8]) -> Option<&'b [u8]> {
        let len = Self::read_varint_advancing(data)? as usize;
        if data.len() < len {
            return None;
        }
        let result = &data[..len];
        *data = &data[len..];
        Some(result)
    }


    pub fn read_tag_from_slice(data: &mut &[u8]) -> Option<(u32, u8)> {
        let tag = Self::read_varint_advancing(data)? as u32;
        let field_number = tag >> 3;
        let wire_type = (tag & 0x07) as u8;
        Some((field_number, wire_type))
    }


    pub fn skip_field_from_slice(data: &mut &[u8], wire_type: u8) -> bool {
        match wire_type {
            WIRE_TYPE_VARINT => Self::read_varint_advancing(data).is_some(),
            WIRE_TYPE_64BIT => {
                if data.len() >= 8 {
                    *data = &data[8..];
                    true
                } else {
                    false
                }
            }
            WIRE_TYPE_LENGTH_DELIMITED => Self::read_bytes_from_slice(data).is_some(),
            WIRE_TYPE_32BIT => {
                if data.len() >= 4 {
                    *data = &data[4..];
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}


pub fn encode_data(data: &DataPayload) -> Option<Vec<u8, MAX_LORA_PAYLOAD>> {
    let mut encoder = ProtobufEncoder::<MAX_LORA_PAYLOAD>::new();

    encoder.write_varint_field(data_fields::PORTNUM, data.port as u64);
    encoder.write_bytes_field(data_fields::PAYLOAD, &data.payload);
    encoder.write_bool_field(data_fields::WANT_RESPONSE, data.want_response);
    encoder.write_varint_field(data_fields::DEST, data.dest as u64);
    encoder.write_varint_field(data_fields::SOURCE, data.source as u64);
    encoder.write_varint_field(data_fields::REQUEST_ID, data.request_id as u64);
    encoder.write_varint_field(data_fields::REPLY_ID, data.reply_id as u64);
    encoder.write_varint_field(data_fields::EMOJI, data.emoji as u64);

    Some(encoder.finish())
}


pub fn encode_position(pos: &Position) -> Option<Vec<u8, MAX_LORA_PAYLOAD>> {
    let mut encoder = ProtobufEncoder::<MAX_LORA_PAYLOAD>::new();


    encoder.write_sint32_field(position_fields::LATITUDE_I, pos.latitude_i);
    encoder.write_sint32_field(position_fields::LONGITUDE_I, pos.longitude_i);
    encoder.write_sint32_field(position_fields::ALTITUDE, pos.altitude);
    encoder.write_varint_field(position_fields::TIME, pos.time as u64);
    encoder.write_varint_field(position_fields::LOCATION_SOURCE, pos.location_source as u64);
    encoder.write_varint_field(position_fields::ALTITUDE_SOURCE, pos.altitude_source as u64);
    encoder.write_varint_field(position_fields::TIMESTAMP, pos.timestamp as u64);
    encoder.write_varint_field(position_fields::PDOP, pos.pdop as u64);
    encoder.write_varint_field(position_fields::HDOP, pos.hdop as u64);
    encoder.write_varint_field(position_fields::SATS_IN_VIEW, pos.sats_in_view as u64);
    encoder.write_varint_field(position_fields::GROUND_SPEED, pos.ground_speed as u64);
    encoder.write_varint_field(position_fields::GROUND_TRACK, pos.ground_track as u64);
    encoder.write_varint_field(position_fields::FIX_QUALITY, pos.fix_quality as u64);
    encoder.write_varint_field(position_fields::FIX_TYPE, pos.fix_type as u64);
    encoder.write_varint_field(position_fields::SEQ_NUMBER, pos.seq_number as u64);

    Some(encoder.finish())
}


pub fn encode_user(user: &User) -> Option<Vec<u8, MAX_LORA_PAYLOAD>> {
    let mut encoder = ProtobufEncoder::<MAX_LORA_PAYLOAD>::new();


    let mut id_str = [0u8; 17];
    id_str[0] = b'!';
    hex_encode(&user.id, &mut id_str[1..]);
    encoder.write_bytes_field(user_fields::ID, &id_str[..17]);

    encoder.write_bytes_field(user_fields::LONG_NAME, &user.long_name);
    encoder.write_bytes_field(user_fields::SHORT_NAME, &user.short_name);
    encoder.write_bytes_field(user_fields::MACADDR, &user.id[2..]);
    encoder.write_varint_field(user_fields::HW_MODEL, user.hw_model as u64);
    encoder.write_bool_field(user_fields::IS_LICENSED, user.is_licensed);
    encoder.write_varint_field(user_fields::ROLE, user.role as u64);

    Some(encoder.finish())
}


pub fn decode_data(data: &[u8]) -> Option<DataPayload> {
    let mut decoder = ProtobufDecoder::new(data);
    let mut result = DataPayload::default();

    while decoder.has_more() {
        let (field_number, wire_type) = decoder.read_tag()?;

        match field_number {
            data_fields::PORTNUM if wire_type == WIRE_TYPE_VARINT => {
                result.port = PortNum::from(decoder.read_varint()? as u32);
            }
            data_fields::PAYLOAD if wire_type == WIRE_TYPE_LENGTH_DELIMITED => {
                let bytes = decoder.read_bytes()?;
                result.payload = Vec::from_slice(bytes).ok()?;
            }
            data_fields::WANT_RESPONSE if wire_type == WIRE_TYPE_VARINT => {
                result.want_response = decoder.read_varint()? != 0;
            }
            data_fields::DEST if wire_type == WIRE_TYPE_VARINT => {
                result.dest = decoder.read_varint()? as u32;
            }
            data_fields::SOURCE if wire_type == WIRE_TYPE_VARINT => {
                result.source = decoder.read_varint()? as u32;
            }
            data_fields::REQUEST_ID if wire_type == WIRE_TYPE_VARINT => {
                result.request_id = decoder.read_varint()? as u32;
            }
            data_fields::REPLY_ID if wire_type == WIRE_TYPE_VARINT => {
                result.reply_id = decoder.read_varint()? as u32;
            }
            data_fields::EMOJI if wire_type == WIRE_TYPE_VARINT => {
                result.emoji = decoder.read_varint()? as u32;
            }
            _ => {
                if !decoder.skip_field(wire_type) {
                    return None;
                }
            }
        }
    }

    Some(result)
}


pub fn decode_position(data: &[u8]) -> Option<Position> {
    let mut decoder = ProtobufDecoder::new(data);
    let mut result = Position::default();

    while decoder.has_more() {
        let (field_number, wire_type) = decoder.read_tag()?;

        match field_number {
            position_fields::LATITUDE_I if wire_type == WIRE_TYPE_VARINT => {
                result.latitude_i = decoder.read_sint32()?;
            }
            position_fields::LONGITUDE_I if wire_type == WIRE_TYPE_VARINT => {
                result.longitude_i = decoder.read_sint32()?;
            }
            position_fields::ALTITUDE if wire_type == WIRE_TYPE_VARINT => {
                result.altitude = decoder.read_sint32()?;
            }
            position_fields::TIME if wire_type == WIRE_TYPE_VARINT => {
                result.time = decoder.read_varint()? as u32;
            }
            position_fields::LOCATION_SOURCE if wire_type == WIRE_TYPE_VARINT => {
                result.location_source = match decoder.read_varint()? as u8 {
                    1 => LocationSource::Manual,
                    2 => LocationSource::InternalGps,
                    3 => LocationSource::ExternalGps,
                    _ => LocationSource::Unset,
                };
            }
            position_fields::ALTITUDE_SOURCE if wire_type == WIRE_TYPE_VARINT => {
                result.altitude_source = match decoder.read_varint()? as u8 {
                    1 => LocationSource::Manual,
                    2 => LocationSource::InternalGps,
                    3 => LocationSource::ExternalGps,
                    _ => LocationSource::Unset,
                };
            }
            position_fields::TIMESTAMP if wire_type == WIRE_TYPE_VARINT => {
                result.timestamp = decoder.read_varint()? as u32;
            }
            position_fields::PDOP if wire_type == WIRE_TYPE_VARINT => {
                result.pdop = decoder.read_varint()? as u32;
            }
            position_fields::HDOP if wire_type == WIRE_TYPE_VARINT => {
                result.hdop = decoder.read_varint()? as u32;
            }
            position_fields::SATS_IN_VIEW if wire_type == WIRE_TYPE_VARINT => {
                result.sats_in_view = decoder.read_varint()? as u32;
            }
            position_fields::GROUND_SPEED if wire_type == WIRE_TYPE_VARINT => {
                result.ground_speed = decoder.read_varint()? as u32;
            }
            position_fields::GROUND_TRACK if wire_type == WIRE_TYPE_VARINT => {
                result.ground_track = decoder.read_varint()? as u32;
            }
            position_fields::FIX_QUALITY if wire_type == WIRE_TYPE_VARINT => {
                result.fix_quality = decoder.read_varint()? as u32;
            }
            position_fields::FIX_TYPE if wire_type == WIRE_TYPE_VARINT => {
                result.fix_type = decoder.read_varint()? as u32;
            }
            position_fields::SEQ_NUMBER if wire_type == WIRE_TYPE_VARINT => {
                result.seq_number = decoder.read_varint()? as u32;
            }
            _ => {
                if !decoder.skip_field(wire_type) {
                    return None;
                }
            }
        }
    }

    Some(result)
}


pub fn decode_user(data: &[u8]) -> Option<User> {
    let mut decoder = ProtobufDecoder::new(data);
    let mut result = User {
        id: [0u8; 8],
        long_name: Vec::new(),
        short_name: Vec::new(),
        hw_model: HardwareModel::Unset,
        is_licensed: false,
        role: Role::Client,
    };

    while decoder.has_more() {
        let (field_number, wire_type) = decoder.read_tag()?;

        match field_number {
            user_fields::ID if wire_type == WIRE_TYPE_LENGTH_DELIMITED => {
                let bytes = decoder.read_bytes()?;

                if bytes.len() >= 17 && bytes[0] == b'!' {
                    hex_decode(&bytes[1..17], &mut result.id);
                } else if bytes.len() == 8 {
                    result.id.copy_from_slice(bytes);
                }
            }
            user_fields::LONG_NAME if wire_type == WIRE_TYPE_LENGTH_DELIMITED => {
                let bytes = decoder.read_bytes()?;
                result.long_name = Vec::from_slice(bytes).ok()?;
            }
            user_fields::SHORT_NAME if wire_type == WIRE_TYPE_LENGTH_DELIMITED => {
                let bytes = decoder.read_bytes()?;
                result.short_name = Vec::from_slice(bytes).ok()?;
            }
            user_fields::MACADDR if wire_type == WIRE_TYPE_LENGTH_DELIMITED => {
                let bytes = decoder.read_bytes()?;
                if bytes.len() == 6 {
                    result.id[2..].copy_from_slice(bytes);
                }
            }
            user_fields::HW_MODEL if wire_type == WIRE_TYPE_VARINT => {
                result.hw_model = match decoder.read_varint()? as u16 {
                    1 => HardwareModel::TloraV2,
                    2 => HardwareModel::TloraV1,
                    4 => HardwareModel::Tbeam,
                    5 => HardwareModel::HeltecV2_0,
                    9 => HardwareModel::Rak4631,
                    10 => HardwareModel::HeltecV2_1,
                    34 => HardwareModel::HeltecWifiLoraV3,
                    255 => HardwareModel::PrivateHw,
                    _ => HardwareModel::Unset,
                };
            }
            user_fields::IS_LICENSED if wire_type == WIRE_TYPE_VARINT => {
                result.is_licensed = decoder.read_varint()? != 0;
            }
            user_fields::ROLE if wire_type == WIRE_TYPE_VARINT => {
                result.role = match decoder.read_varint()? as u8 {
                    0 => Role::Client,
                    1 => Role::ClientMute,
                    2 => Role::Router,
                    3 => Role::RouterClient,
                    4 => Role::Repeater,
                    5 => Role::Tracker,
                    6 => Role::Sensor,
                    7 => Role::Tak,
                    8 => Role::ClientHidden,
                    9 => Role::LostAndFound,
                    10 => Role::TakTracker,
                    _ => Role::Client,
                };
            }
            _ => {
                if !decoder.skip_field(wire_type) {
                    return None;
                }
            }
        }
    }

    Some(result)
}


fn hex_encode(data: &[u8], output: &mut [u8]) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    for (i, &byte) in data.iter().enumerate() {
        if i * 2 + 1 < output.len() {
            output[i * 2] = HEX_CHARS[(byte >> 4) as usize];
            output[i * 2 + 1] = HEX_CHARS[(byte & 0x0F) as usize];
        }
    }
}


fn hex_decode(data: &[u8], output: &mut [u8]) {
    fn hex_val(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }

    for i in 0..output.len() {
        if i * 2 + 1 < data.len() {
            output[i] = (hex_val(data[i * 2]) << 4) | hex_val(data[i * 2 + 1]);
        }
    }
}


mod nodeinfo_fields {
    pub const NUM: u32 = 1;
    pub const USER: u32 = 2;
    pub const POSITION: u32 = 3;
    pub const SNR: u32 = 4;
    pub const LAST_HEARD: u32 = 5;
    pub const DEVICE_METRICS: u32 = 6;
}


pub fn encode_nodeinfo(
    num: u32,
    user: Option<&User>,
    position: Option<&Position>,
    snr: f32,
    last_heard: u32,
) -> Option<Vec<u8, MAX_LORA_PAYLOAD>> {
    let mut encoder = ProtobufEncoder::<MAX_LORA_PAYLOAD>::new();

    encoder.write_varint_field(nodeinfo_fields::NUM, num as u64);

    if let Some(u) = user {
        let user_data = encode_user(u)?;
        encoder.write_bytes_field(nodeinfo_fields::USER, &user_data);
    }

    if let Some(p) = position {
        let pos_data = encode_position(p)?;
        encoder.write_bytes_field(nodeinfo_fields::POSITION, &pos_data);
    }


    if snr != 0.0 {
        encoder.write_fixed32_field(nodeinfo_fields::SNR, snr.to_bits());
    }

    encoder.write_varint_field(nodeinfo_fields::LAST_HEARD, last_heard as u64);

    Some(encoder.finish())
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RoutingError {
    None = 0,
    NoRoute = 1,
    GotNak = 2,
    Timeout = 3,
    NoInterface = 4,
    MaxRetransmit = 5,
    NoChannel = 6,
    TooLarge = 7,
    NoResponse = 8,
    DutyCycleLimit = 9,
    BadRequest = 32,
    NotAuthorized = 33,
}


mod routing_fields {
    pub const ROUTE_REQUEST: u32 = 1;
    pub const ROUTE_REPLY: u32 = 2;
    pub const ERROR_REASON: u32 = 3;
}


pub fn encode_routing_error(error: RoutingError) -> Option<Vec<u8, 16>> {
    let mut encoder = ProtobufEncoder::<16>::new();
    encoder.write_varint_field(routing_fields::ERROR_REASON, error as u64);
    Some(encoder.finish())
}


pub fn decode_routing_error(data: &[u8]) -> Option<RoutingError> {
    let mut decoder = ProtobufDecoder::new(data);

    while decoder.has_more() {
        let (field_number, wire_type) = decoder.read_tag()?;

        if field_number == routing_fields::ERROR_REASON && wire_type == WIRE_TYPE_VARINT {
            return Some(match decoder.read_varint()? as u8 {
                0 => RoutingError::None,
                1 => RoutingError::NoRoute,
                2 => RoutingError::GotNak,
                3 => RoutingError::Timeout,
                4 => RoutingError::NoInterface,
                5 => RoutingError::MaxRetransmit,
                6 => RoutingError::NoChannel,
                7 => RoutingError::TooLarge,
                8 => RoutingError::NoResponse,
                9 => RoutingError::DutyCycleLimit,
                32 => RoutingError::BadRequest,
                33 => RoutingError::NotAuthorized,
                _ => RoutingError::None,
            });
        } else {
            decoder.skip_field(wire_type);
        }
    }

    None
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdminOp {
    GetChannelRequest = 1,
    GetChannelResponse = 2,
    GetOwnerRequest = 3,
    GetOwnerResponse = 4,
    GetConfigRequest = 5,
    GetConfigResponse = 6,
    GetModuleConfigRequest = 7,
    GetModuleConfigResponse = 8,
    GetCannedMessageRequest = 10,
    GetCannedMessageResponse = 11,
    GetDeviceMetadataRequest = 12,
    GetDeviceMetadataResponse = 13,
    GetRingtoneRequest = 14,
    GetRingtoneResponse = 15,
    GetDeviceConnectionStatusRequest = 16,
    GetDeviceConnectionStatusResponse = 17,
    SetOwner = 32,
    SetChannel = 33,
    SetConfig = 34,
    SetModuleConfig = 35,
    SetCannedMessageModule = 36,
    SetRingtoneMessage = 37,
    RemoveByNodenum = 38,
    SetFavoriteNode = 39,
    RemoveFavoriteNode = 40,
    BeginEditSettings = 64,
    CommitEditSettings = 65,
    RebootOtaSeconds = 95,
    ExitSimulator = 96,
    RebootSeconds = 97,
    ShutdownSeconds = 98,
    FactoryResetDevice = 99,
    NodedbReset = 100,
}


mod telemetry_fields {
    pub const TIME: u32 = 1;
    pub const DEVICE_METRICS: u32 = 2;
    pub const ENVIRONMENT_METRICS: u32 = 3;
    pub const AIR_QUALITY_METRICS: u32 = 4;
    pub const POWER_METRICS: u32 = 5;
}


mod device_metrics_fields {
    pub const BATTERY_LEVEL: u32 = 1;
    pub const VOLTAGE: u32 = 2;
    pub const CHANNEL_UTILIZATION: u32 = 3;
    pub const AIR_UTIL_TX: u32 = 4;
    pub const UPTIME_SECONDS: u32 = 5;
}


#[derive(Debug, Clone, Default)]
pub struct DeviceMetrics {

    pub battery_level: u32,

    pub voltage: u32,

    pub channel_utilization: u32,

    pub air_util_tx: u32,

    pub uptime_seconds: u32,
}


pub fn encode_device_metrics(metrics: &DeviceMetrics) -> Option<Vec<u8, 64>> {
    let mut encoder = ProtobufEncoder::<64>::new();

    encoder.write_varint_field(device_metrics_fields::BATTERY_LEVEL, metrics.battery_level as u64);
    encoder.write_varint_field(device_metrics_fields::VOLTAGE, metrics.voltage as u64);
    encoder.write_varint_field(device_metrics_fields::CHANNEL_UTILIZATION, metrics.channel_utilization as u64);
    encoder.write_varint_field(device_metrics_fields::AIR_UTIL_TX, metrics.air_util_tx as u64);
    encoder.write_varint_field(device_metrics_fields::UPTIME_SECONDS, metrics.uptime_seconds as u64);

    Some(encoder.finish())
}


pub fn encode_telemetry(time: u32, metrics: &DeviceMetrics) -> Option<Vec<u8, MAX_LORA_PAYLOAD>> {
    let mut encoder = ProtobufEncoder::<MAX_LORA_PAYLOAD>::new();

    encoder.write_varint_field(telemetry_fields::TIME, time as u64);

    let metrics_data = encode_device_metrics(metrics)?;
    encoder.write_bytes_field(telemetry_fields::DEVICE_METRICS, &metrics_data);

    Some(encoder.finish())
}


pub fn decode_device_metrics(data: &[u8]) -> Option<DeviceMetrics> {
    let mut decoder = ProtobufDecoder::new(data);
    let mut result = DeviceMetrics::default();

    while decoder.has_more() {
        let (field_number, wire_type) = decoder.read_tag()?;

        match field_number {
            device_metrics_fields::BATTERY_LEVEL if wire_type == WIRE_TYPE_VARINT => {
                result.battery_level = decoder.read_varint()? as u32;
            }
            device_metrics_fields::VOLTAGE if wire_type == WIRE_TYPE_VARINT => {
                result.voltage = decoder.read_varint()? as u32;
            }
            device_metrics_fields::CHANNEL_UTILIZATION if wire_type == WIRE_TYPE_VARINT => {
                result.channel_utilization = decoder.read_varint()? as u32;
            }
            device_metrics_fields::AIR_UTIL_TX if wire_type == WIRE_TYPE_VARINT => {
                result.air_util_tx = decoder.read_varint()? as u32;
            }
            device_metrics_fields::UPTIME_SECONDS if wire_type == WIRE_TYPE_VARINT => {
                result.uptime_seconds = decoder.read_varint()? as u32;
            }
            _ => {
                decoder.skip_field(wire_type);
            }
        }
    }

    Some(result)
}


mod to_radio_fields {
    pub const PACKET: u32 = 1;
    pub const WANT_CONFIG_ID: u32 = 3;
    pub const DISCONNECT: u32 = 4;
}


mod from_radio_fields {
    pub const ID: u32 = 1;
    pub const PACKET: u32 = 2;
    pub const MY_INFO: u32 = 3;
    pub const NODE_INFO: u32 = 4;
    pub const CONFIG: u32 = 5;
    pub const LOG_RECORD: u32 = 6;
    pub const CONFIG_COMPLETE_ID: u32 = 7;
    pub const REBOOTED: u32 = 8;
    pub const MODULE_CONFIG: u32 = 9;
    pub const CHANNEL: u32 = 10;
    pub const QUEUED_TEXT_MESSAGE_ACK: u32 = 11;
    pub const XM0DEM: u32 = 12;
    pub const METADATA: u32 = 13;
    pub const MQTTCLIENT_PROXY_MESSAGE: u32 = 14;
}


mod mesh_packet_fields {
    pub const FROM: u32 = 1;
    pub const TO: u32 = 2;
    pub const CHANNEL: u32 = 3;
    pub const ENCRYPTED: u32 = 4;
    pub const DECODED: u32 = 5;
    pub const ID: u32 = 6;
    pub const RX_TIME: u32 = 7;
    pub const RX_SNR: u32 = 8;
    pub const HOP_LIMIT: u32 = 9;
    pub const WANT_ACK: u32 = 10;
    pub const PRIORITY: u32 = 11;
    pub const RX_RSSI: u32 = 12;
    pub const DELAYED: u32 = 13;
    pub const VIA_MQTT: u32 = 14;
    pub const HOP_START: u32 = 15;
}


pub enum ToRadio {

    Packet(super::MeshPacket),

    WantConfigId(u32),

    Disconnect,
}


pub fn decode_to_radio(data: &[u8]) -> Option<ToRadio> {
    let mut decoder = ProtobufDecoder::new(data);

    while decoder.has_more() {
        let (field_number, wire_type) = decoder.read_tag()?;

        match field_number {
            to_radio_fields::PACKET if wire_type == WIRE_TYPE_LENGTH_DELIMITED => {
                let packet_data = decoder.read_bytes()?;
                let packet = decode_mesh_packet(packet_data)?;
                return Some(ToRadio::Packet(packet));
            }
            to_radio_fields::WANT_CONFIG_ID if wire_type == WIRE_TYPE_VARINT => {
                let id = decoder.read_varint()? as u32;
                return Some(ToRadio::WantConfigId(id));
            }
            to_radio_fields::DISCONNECT if wire_type == WIRE_TYPE_VARINT => {
                decoder.read_varint()?;
                return Some(ToRadio::Disconnect);
            }
            _ => {
                if !decoder.skip_field(wire_type) {
                    return None;
                }
            }
        }
    }

    None
}


pub fn decode_mesh_packet(data: &[u8]) -> Option<super::MeshPacket> {
    let mut decoder = ProtobufDecoder::new(data);
    let mut packet = super::MeshPacket::default();

    while decoder.has_more() {
        let (field_number, wire_type) = decoder.read_tag()?;

        match field_number {
            mesh_packet_fields::FROM if wire_type == WIRE_TYPE_VARINT => {
                packet.from = decoder.read_varint()? as u32;
            }
            mesh_packet_fields::TO if wire_type == WIRE_TYPE_VARINT => {
                packet.to = decoder.read_varint()? as u32;
            }
            mesh_packet_fields::CHANNEL if wire_type == WIRE_TYPE_VARINT => {
                packet.channel = decoder.read_varint()? as u8;
            }
            mesh_packet_fields::ENCRYPTED if wire_type == WIRE_TYPE_LENGTH_DELIMITED => {
                let bytes = decoder.read_bytes()?;
                packet.payload = super::PacketPayload::Encrypted(
                    heapless::Vec::from_slice(bytes).ok()?
                );
            }
            mesh_packet_fields::DECODED if wire_type == WIRE_TYPE_LENGTH_DELIMITED => {
                let decoded_data = decoder.read_bytes()?;
                if let Some(data_payload) = decode_data(decoded_data) {
                    packet.payload = super::PacketPayload::Decoded(data_payload);
                }
            }
            mesh_packet_fields::ID if wire_type == WIRE_TYPE_VARINT => {
                packet.id = decoder.read_varint()? as u32;
            }
            mesh_packet_fields::RX_TIME if wire_type == WIRE_TYPE_VARINT => {
                packet.rx_time = decoder.read_varint()? as u32;
            }
            mesh_packet_fields::RX_SNR if wire_type == WIRE_TYPE_32BIT => {
                let bits = decoder.read_fixed32()?;
                packet.rx_snr = f32::from_bits(bits);
            }
            mesh_packet_fields::HOP_LIMIT if wire_type == WIRE_TYPE_VARINT => {
                packet.hop_limit = decoder.read_varint()? as u8;
            }
            mesh_packet_fields::WANT_ACK if wire_type == WIRE_TYPE_VARINT => {
                packet.want_ack = decoder.read_varint()? != 0;
            }
            mesh_packet_fields::PRIORITY if wire_type == WIRE_TYPE_VARINT => {
                packet.priority = super::Priority::from(decoder.read_varint()? as u8);
            }
            mesh_packet_fields::RX_RSSI if wire_type == WIRE_TYPE_VARINT => {
                packet.rx_rssi = decoder.read_varint()? as i32;
            }
            _ => {
                if !decoder.skip_field(wire_type) {
                    return None;
                }
            }
        }
    }

    Some(packet)
}


pub fn encode_mesh_packet(packet: &super::MeshPacket) -> Option<heapless::Vec<u8, 256>> {
    let mut encoder = ProtobufEncoder::<256>::new();

    encoder.write_varint_field(mesh_packet_fields::FROM, packet.from as u64);
    encoder.write_varint_field(mesh_packet_fields::TO, packet.to as u64);
    encoder.write_varint_field(mesh_packet_fields::CHANNEL, packet.channel as u64);

    match &packet.payload {
        super::PacketPayload::Encrypted(data) => {
            encoder.write_bytes_field(mesh_packet_fields::ENCRYPTED, data);
        }
        super::PacketPayload::Decoded(data) => {
            let encoded = encode_data(data)?;
            encoder.write_bytes_field(mesh_packet_fields::DECODED, &encoded);
        }
    }

    encoder.write_varint_field(mesh_packet_fields::ID, packet.id as u64);
    encoder.write_varint_field(mesh_packet_fields::RX_TIME, packet.rx_time as u64);

    if packet.rx_snr != 0.0 {
        encoder.write_fixed32_field(mesh_packet_fields::RX_SNR, packet.rx_snr.to_bits());
    }

    encoder.write_varint_field(mesh_packet_fields::HOP_LIMIT, packet.hop_limit as u64);
    encoder.write_bool_field(mesh_packet_fields::WANT_ACK, packet.want_ack);
    encoder.write_varint_field(mesh_packet_fields::PRIORITY, packet.priority as u64);

    if packet.rx_rssi != 0 {

        let encoded_rssi = ((packet.rx_rssi << 1) ^ (packet.rx_rssi >> 31)) as u32;
        encoder.write_varint_field(mesh_packet_fields::RX_RSSI, encoded_rssi as u64);
    }

    Some(encoder.finish())
}


fn next_from_radio_id() -> u32 {
    use core::sync::atomic::{AtomicU32, Ordering};
    static FROM_RADIO_ID: AtomicU32 = AtomicU32::new(0);
    FROM_RADIO_ID.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
}


pub fn encode_from_radio_packet(packet: &super::MeshPacket) -> Option<heapless::Vec<u8, 512>> {
    let mut encoder = ProtobufEncoder::<512>::new();

    encoder.write_varint_field(from_radio_fields::ID, next_from_radio_id() as u64);


    let packet_data = encode_mesh_packet(packet)?;
    encoder.write_bytes_field(from_radio_fields::PACKET, &packet_data);

    Some(encoder.finish())
}


mod my_info_fields {
    pub const MY_NODE_NUM: u32 = 1;
    pub const REBOOT_COUNT: u32 = 8;
    pub const MIN_APP_VERSION: u32 = 11;
    pub const DEVICE_ID: u32 = 12;
}


pub fn encode_from_radio_my_info(
    node_num: u32,
    reboot_count: u32,
) -> Option<heapless::Vec<u8, 512>> {
    let mut encoder = ProtobufEncoder::<512>::new();

    encoder.write_varint_field(from_radio_fields::ID, next_from_radio_id() as u64);


    encoder.write_message_field(from_radio_fields::MY_INFO, |inner| {
        inner.write_varint_field(my_info_fields::MY_NODE_NUM, node_num as u64);
        inner.write_varint_field(my_info_fields::REBOOT_COUNT, reboot_count as u64);
        inner.write_varint_field(my_info_fields::MIN_APP_VERSION, 20300);
        true
    });

    Some(encoder.finish())
}


mod node_info_fields {
    pub const NUM: u32 = 1;
    pub const USER: u32 = 2;
    pub const POSITION: u32 = 3;
    pub const SNR: u32 = 4;
    pub const LAST_HEARD: u32 = 5;
    pub const DEVICE_METRICS: u32 = 6;
    pub const CHANNEL: u32 = 7;
    pub const VIA_MQTT: u32 = 8;
    pub const HOPS_AWAY: u32 = 9;
    pub const IS_FAVORITE: u32 = 10;
}


pub fn encode_from_radio_node_info(
    node_info: &super::NodeInfo,
) -> Option<heapless::Vec<u8, 512>> {
    let mut encoder = ProtobufEncoder::<512>::new();

    encoder.write_varint_field(from_radio_fields::ID, next_from_radio_id() as u64);


    encoder.write_message_field(from_radio_fields::NODE_INFO, |inner| {
        inner.write_varint_field(node_info_fields::NUM, node_info.num as u64);


        if let Some(ref user) = node_info.user {
            let user_data = encode_user(user);
            if let Some(data) = user_data {
                inner.write_bytes_field(node_info_fields::USER, &data);
            }
        }


        if let Some(ref position) = node_info.position {
            let pos_data = encode_position(position);
            if let Some(data) = pos_data {
                inner.write_bytes_field(node_info_fields::POSITION, &data);
            }
        }

        if node_info.snr != 0.0 {
            inner.write_fixed32_field(node_info_fields::SNR, node_info.snr.to_bits());
        }
        inner.write_varint_field(node_info_fields::LAST_HEARD, node_info.last_heard as u64);

        true
    });

    Some(encoder.finish())
}


mod channel_fields {
    pub const INDEX: u32 = 1;
    pub const SETTINGS: u32 = 2;
    pub const ROLE: u32 = 3;
}


mod channel_settings_fields {
    pub const CHANNEL_NUM: u32 = 1;
    pub const PSK: u32 = 2;
    pub const NAME: u32 = 3;
    pub const ID: u32 = 4;
    pub const UPLINK_ENABLED: u32 = 5;
    pub const DOWNLINK_ENABLED: u32 = 6;
    pub const MODULE_SETTINGS: u32 = 7;
}


pub fn encode_from_radio_channel(
    index: u8,
    channel: &super::Channel,
    is_primary: bool,
) -> Option<heapless::Vec<u8, 512>> {
    let mut encoder = ProtobufEncoder::<512>::new();

    encoder.write_varint_field(from_radio_fields::ID, next_from_radio_id() as u64);


    encoder.write_message_field(from_radio_fields::CHANNEL, |inner| {
        inner.write_varint_field(channel_fields::INDEX, index as u64);


        inner.write_message_field(channel_fields::SETTINGS, |settings| {
            settings.write_varint_field(channel_settings_fields::CHANNEL_NUM, index as u64);


            settings.write_string_field(channel_settings_fields::NAME, channel.name_str());
            true
        });


        let role = if is_primary { 1u64 } else { 2u64 };
        inner.write_varint_field(channel_fields::ROLE, role);

        true
    });

    Some(encoder.finish())
}


pub fn encode_from_radio_config_complete(config_id: u32) -> Option<heapless::Vec<u8, 512>> {
    let mut encoder = ProtobufEncoder::<512>::new();

    encoder.write_varint_field(from_radio_fields::ID, next_from_radio_id() as u64);
    encoder.write_varint_field(from_radio_fields::CONFIG_COMPLETE_ID, config_id as u64);

    Some(encoder.finish())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding() {
        let mut encoder = ProtobufEncoder::<16>::new();
        assert!(encoder.write_varint(300));
        let result = encoder.finish();

        assert_eq!(&result[..], &[0xAC, 0x02]);
    }

    #[test]
    fn test_varint_decoding() {
        let data = [0xAC, 0x02];
        let mut decoder = ProtobufDecoder::new(&data);
        assert_eq!(decoder.read_varint(), Some(300));
    }

    #[test]
    fn test_data_roundtrip() {
        let original = DataPayload {
            port: PortNum::TextMessage,
            payload: Vec::from_slice(b"Hello").unwrap(),
            want_response: true,
            dest: 0xFFFFFFFF,
            source: 0x12345678,
            request_id: 0,
            reply_id: 0,
            emoji: 0,
        };

        let encoded = encode_data(&original).unwrap();
        let decoded = decode_data(&encoded).unwrap();

        assert_eq!(decoded.port, original.port);
        assert_eq!(&decoded.payload[..], &original.payload[..]);
        assert_eq!(decoded.want_response, original.want_response);
        assert_eq!(decoded.source, original.source);
    }

    #[test]
    fn test_position_roundtrip() {
        let original = Position {
            latitude_i: 374220000,
            longitude_i: -1220840000,
            altitude: 100,
            time: 1700000000,
            location_source: LocationSource::InternalGps,
            ..Default::default()
        };

        let encoded = encode_position(&original).unwrap();
        let decoded = decode_position(&encoded).unwrap();

        assert_eq!(decoded.latitude_i, original.latitude_i);
        assert_eq!(decoded.longitude_i, original.longitude_i);
        assert_eq!(decoded.altitude, original.altitude);
        assert_eq!(decoded.location_source, original.location_source);
    }

    #[test]
    fn test_hex_encode() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut output = [0u8; 8];
        hex_encode(&data, &mut output);
        assert_eq!(&output, b"deadbeef");
    }

    #[test]
    fn test_hex_decode() {
        let data = b"deadbeef";
        let mut output = [0u8; 4];
        hex_decode(data, &mut output);
        assert_eq!(&output, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_sint32_encoding() {

        let mut encoder = ProtobufEncoder::<16>::new();
        encoder.write_sint32(-1);
        let result = encoder.finish();

        assert_eq!(&result[..], &[0x01]);

        let mut encoder = ProtobufEncoder::<16>::new();
        encoder.write_sint32(1);
        let result = encoder.finish();

        assert_eq!(&result[..], &[0x02]);

        let mut encoder = ProtobufEncoder::<16>::new();
        encoder.write_sint32(-2);
        let result = encoder.finish();

        assert_eq!(&result[..], &[0x03]);
    }

    #[test]
    fn test_sint32_decoding() {
        let mut decoder = ProtobufDecoder::new(&[0x01]);
        assert_eq!(decoder.read_sint32(), Some(-1));

        let mut decoder = ProtobufDecoder::new(&[0x02]);
        assert_eq!(decoder.read_sint32(), Some(1));

        let mut decoder = ProtobufDecoder::new(&[0x03]);
        assert_eq!(decoder.read_sint32(), Some(-2));
    }
}
