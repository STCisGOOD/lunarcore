use heapless::Vec;
use super::{MeshPacket, PacketPayload, Priority, LORA_HEADER_SIZE, MAX_LORA_PAYLOAD, MIC_SIZE, DEFAULT_HOP_LIMIT};
use crate::crypto::sha256::Sha256;


const OFFSET_TO: usize = 0;
const OFFSET_FROM: usize = 4;
const OFFSET_ID: usize = 8;
const OFFSET_FLAGS: usize = 12;
const OFFSET_CHANNEL_HASH: usize = 13;


const FLAG_WANT_ACK: u8 = 0x01;
const FLAG_HOP_LIMIT_MASK: u8 = 0x0E;
const FLAG_HOP_LIMIT_SHIFT: u8 = 1;
const FLAG_CHANNEL_MASK: u8 = 0xF0;
const FLAG_CHANNEL_SHIFT: u8 = 4;


pub fn parse_lora_packet(data: &[u8]) -> Option<MeshPacket> {

    if data.len() < LORA_HEADER_SIZE + MIC_SIZE {
        return None;
    }


    let to = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let from = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let id = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let flags = data[OFFSET_FLAGS];
    let channel_hash = data[OFFSET_CHANNEL_HASH];


    let want_ack = (flags & FLAG_WANT_ACK) != 0;
    let hop_limit = (flags & FLAG_HOP_LIMIT_MASK) >> FLAG_HOP_LIMIT_SHIFT;
    let channel = (flags & FLAG_CHANNEL_MASK) >> FLAG_CHANNEL_SHIFT;


    let payload_end = data.len() - MIC_SIZE;
    let payload_start = LORA_HEADER_SIZE;

    if payload_end <= payload_start {
        return None;
    }

    let mut payload_data = Vec::new();
    payload_data.extend_from_slice(&data[payload_start..payload_end]).ok()?;


    let received_mic = &data[payload_end..];
    let computed_mic = compute_mic(&data[..payload_end]);

    if !constant_time_eq(received_mic, &computed_mic) {


    }

    Some(MeshPacket {
        from,
        to,
        channel,
        id,
        hop_limit,
        want_ack,
        priority: Priority::Default,
        rx_time: 0,
        rx_snr: 0.0,
        rx_rssi: 0,
        payload: PacketPayload::Encrypted(payload_data),
    })
}


pub fn build_lora_packet(
    from: u32,
    to: u32,
    id: u32,
    channel: u8,
    hop_limit: u8,
    want_ack: bool,
    payload: &[u8],
) -> Option<Vec<u8, 256>> {
    let total_len = LORA_HEADER_SIZE + payload.len() + MIC_SIZE;
    if total_len > 256 || payload.len() > MAX_LORA_PAYLOAD {
        return None;
    }

    let mut packet = Vec::new();


    packet.extend_from_slice(&to.to_le_bytes()).ok()?;
    packet.extend_from_slice(&from.to_le_bytes()).ok()?;
    packet.extend_from_slice(&id.to_le_bytes()).ok()?;


    let flags = (if want_ack { FLAG_WANT_ACK } else { 0 })
        | ((hop_limit & 0x07) << FLAG_HOP_LIMIT_SHIFT)
        | ((channel & 0x0F) << FLAG_CHANNEL_SHIFT);
    packet.push(flags).ok()?;


    packet.push(compute_channel_hash(channel)).ok()?;


    packet.push(0).ok()?;
    packet.push(0).ok()?;


    packet.extend_from_slice(payload).ok()?;


    let mic = compute_mic(&packet);
    packet.extend_from_slice(&mic).ok()?;

    Some(packet)
}


fn compute_mic(data: &[u8]) -> [u8; MIC_SIZE] {
    let hash = Sha256::hash(data);
    let mut mic = [0u8; MIC_SIZE];
    mic.copy_from_slice(&hash[..MIC_SIZE]);
    mic
}


fn compute_channel_hash(channel: u8) -> u8 {


    let mut h = channel.wrapping_mul(0x9E).wrapping_add(0x37);
    h ^= h >> 4;
    h.wrapping_mul(0xB5)
}


fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}


pub struct PacketCache {

    entries: [(u32, u32, u32); 32],

    index: usize,
}

impl PacketCache {

    pub const fn new() -> Self {
        Self {
            entries: [(0, 0, 0); 32],
            index: 0,
        }
    }


    pub fn is_duplicate(&self, from: u32, packet_id: u32) -> bool {
        for &(f, id, _) in &self.entries {
            if f == from && id == packet_id && f != 0 {
                return true;
            }
        }
        false
    }


    pub fn add(&mut self, from: u32, packet_id: u32, timestamp: u32) {
        self.entries[self.index] = (from, packet_id, timestamp);
        self.index = (self.index + 1) % self.entries.len();
    }


    pub fn check_and_add(&mut self, from: u32, packet_id: u32, timestamp: u32) -> bool {
        if self.is_duplicate(from, packet_id) {
            return true;
        }
        self.add(from, packet_id, timestamp);
        false
    }


    pub fn clear_old(&mut self, current_time: u32, max_age: u32) {
        for entry in &mut self.entries {
            if entry.0 != 0 && current_time.saturating_sub(entry.2) > max_age {
                *entry = (0, 0, 0);
            }
        }
    }
}

impl Default for PacketCache {
    fn default() -> Self {
        Self::new()
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingDecision {

    Local,

    Forward,

    Drop,
}


pub fn route_packet(packet: &MeshPacket, our_node_id: u32, cache: &mut PacketCache, timestamp: u32) -> RoutingDecision {

    if cache.check_and_add(packet.from, packet.id, timestamp) {
        return RoutingDecision::Drop;
    }


    let is_broadcast = packet.to == 0xFFFFFFFF;
    let is_for_us = packet.to == our_node_id;

    if is_for_us || is_broadcast {

        if is_broadcast && packet.hop_limit > 0 {
            return RoutingDecision::Forward;
        }
        return RoutingDecision::Local;
    }


    if packet.hop_limit > 0 {
        RoutingDecision::Forward
    } else {
        RoutingDecision::Drop
    }
}


pub fn create_forward_packet(original: &MeshPacket, payload: &[u8]) -> Option<Vec<u8, 256>> {
    if original.hop_limit == 0 {
        return None;
    }

    build_lora_packet(
        original.from,
        original.to,
        original.id,
        original.channel,
        original.hop_limit - 1,
        original.want_ack,
        payload,
    )
}


#[derive(Debug, Default)]
pub struct PacketStats {

    pub rx_total: u32,

    pub rx_local: u32,

    pub rx_forwarded: u32,

    pub rx_dropped_dup: u32,

    pub rx_dropped_expired: u32,

    pub rx_bad: u32,

    pub tx_total: u32,

    pub tx_retransmit: u32,

    pub tx_fail: u32,
}

impl PacketStats {

    pub const fn new() -> Self {
        Self {
            rx_total: 0,
            rx_local: 0,
            rx_forwarded: 0,
            rx_dropped_dup: 0,
            rx_dropped_expired: 0,
            rx_bad: 0,
            tx_total: 0,
            tx_retransmit: 0,
            tx_fail: 0,
        }
    }


    pub fn record_rx(&mut self, decision: RoutingDecision) {
        self.rx_total += 1;
        match decision {
            RoutingDecision::Local => self.rx_local += 1,
            RoutingDecision::Forward => self.rx_forwarded += 1,
            RoutingDecision::Drop => self.rx_dropped_dup += 1,
        }
    }


    pub fn record_rx_bad(&mut self) {
        self.rx_total += 1;
        self.rx_bad += 1;
    }


    pub fn record_tx(&mut self, success: bool) {
        self.tx_total += 1;
        if !success {
            self.tx_fail += 1;
        }
    }


    pub fn record_retransmit(&mut self) {
        self.tx_retransmit += 1;
    }
}


#[derive(Clone)]
pub struct PendingAck {

    pub packet_id: u32,

    pub to: u32,

    pub packet_data: Vec<u8, 256>,

    pub tx_count: u8,

    pub max_retransmit: u8,

    pub last_tx_time: u32,

    pub retransmit_timeout: u32,
}


pub struct AckTracker {

    pending: [Option<PendingAck>; 8],
}

impl AckTracker {

    pub const fn new() -> Self {
        Self {
            pending: [None, None, None, None, None, None, None, None],
        }
    }


    pub fn add(&mut self, ack: PendingAck) -> bool {
        for slot in &mut self.pending {
            if slot.is_none() {
                *slot = Some(ack);
                return true;
            }
        }
        false
    }


    pub fn is_pending(&self, to: u32, packet_id: u32) -> bool {
        self.pending.iter().any(|p| {
            p.as_ref().map_or(false, |a| a.to == to && a.packet_id == packet_id)
        })
    }


    pub fn handle_ack(&mut self, from: u32, request_id: u32) -> bool {
        for slot in &mut self.pending {
            if let Some(ref ack) = slot {
                if ack.to == from && ack.packet_id == request_id {
                    *slot = None;
                    return true;
                }
            }
        }
        false
    }


    pub fn get_retransmit(&mut self, current_time: u32) -> Option<Vec<u8, 256>> {
        for slot in &mut self.pending {
            if let Some(ref mut ack) = slot {
                let elapsed = current_time.saturating_sub(ack.last_tx_time);
                if elapsed >= ack.retransmit_timeout {
                    if ack.tx_count < ack.max_retransmit {
                        ack.tx_count += 1;
                        ack.last_tx_time = current_time;
                        return Some(ack.packet_data.clone());
                    } else {

                        *slot = None;
                    }
                }
            }
        }
        None
    }


    pub fn clear(&mut self) {
        for slot in &mut self.pending {
            *slot = None;
        }
    }


    pub fn pending_count(&self) -> usize {
        self.pending.iter().filter(|p| p.is_some()).count()
    }
}

impl Default for AckTracker {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_build_roundtrip() {
        let from = 0x12345678;
        let to = 0xFFFFFFFF;
        let id = 0xABCDEF01;
        let channel = 0;
        let hop_limit = 3;
        let want_ack = true;
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05];

        let packet = build_lora_packet(from, to, id, channel, hop_limit, want_ack, &payload).unwrap();

        let parsed = parse_lora_packet(&packet).unwrap();
        assert_eq!(parsed.from, from);
        assert_eq!(parsed.to, to);
        assert_eq!(parsed.id, id);
        assert_eq!(parsed.channel, channel);
        assert_eq!(parsed.hop_limit, hop_limit);
        assert_eq!(parsed.want_ack, want_ack);

        if let PacketPayload::Encrypted(ref data) = parsed.payload {
            assert_eq!(&data[..], &payload);
        } else {
            panic!("Expected encrypted payload");
        }
    }

    #[test]
    fn test_packet_cache() {
        let mut cache = PacketCache::new();


        assert!(!cache.check_and_add(0x1234, 0x01, 1000));


        assert!(cache.check_and_add(0x1234, 0x01, 1001));


        assert!(!cache.check_and_add(0x5678, 0x01, 1002));


        assert!(!cache.check_and_add(0x1234, 0x02, 1003));
    }

    #[test]
    fn test_routing_decision() {
        let our_id = 0x12345678;
        let mut cache = PacketCache::new();


        let packet = MeshPacket {
            to: our_id,
            from: 0x87654321,
            id: 1,
            hop_limit: 3,
            ..Default::default()
        };
        assert_eq!(route_packet(&packet, our_id, &mut cache, 1000), RoutingDecision::Local);


        let packet = MeshPacket {
            to: 0xFFFFFFFF,
            from: 0x87654321,
            id: 2,
            hop_limit: 3,
            ..Default::default()
        };
        assert_eq!(route_packet(&packet, our_id, &mut cache, 1001), RoutingDecision::Forward);


        let packet = MeshPacket {
            to: 0x11111111,
            from: 0x87654321,
            id: 3,
            hop_limit: 2,
            ..Default::default()
        };
        assert_eq!(route_packet(&packet, our_id, &mut cache, 1002), RoutingDecision::Forward);


        let packet = MeshPacket {
            to: 0x11111111,
            from: 0x87654321,
            id: 4,
            hop_limit: 0,
            ..Default::default()
        };
        assert_eq!(route_packet(&packet, our_id, &mut cache, 1003), RoutingDecision::Drop);
    }

    #[test]
    fn test_ack_tracker() {
        let mut tracker = AckTracker::new();

        let ack = PendingAck {
            packet_id: 0x1234,
            to: 0xABCD,
            packet_data: Vec::new(),
            tx_count: 1,
            max_retransmit: 3,
            last_tx_time: 1000,
            retransmit_timeout: 500,
        };

        assert!(tracker.add(ack));
        assert!(tracker.is_pending(0xABCD, 0x1234));
        assert!(!tracker.is_pending(0xABCD, 0x5678));

        assert!(tracker.handle_ack(0xABCD, 0x1234));
        assert!(!tracker.is_pending(0xABCD, 0x1234));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
    }

    #[test]
    fn test_mic_computation() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mic = compute_mic(&data);
        assert_eq!(mic.len(), MIC_SIZE);


        let mic2 = compute_mic(&data);
        assert_eq!(mic, mic2);


        let mic3 = compute_mic(&[0x05, 0x06, 0x07, 0x08]);
        assert_ne!(mic, mic3);
    }
}
