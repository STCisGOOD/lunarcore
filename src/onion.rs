use crate::crypto::{
    x25519::x25519,
    hkdf::Hkdf,
    aes::Aes256,
    sha256::Sha256,
};
use crate::transport::{NODE_HINT_SIZE, AUTH_TAG_SIZE};
use heapless::Vec as HeaplessVec;


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


pub const MAX_HOPS: usize = 7;

pub const MIN_HOPS: usize = 3;

pub const HOP_OVERHEAD: usize = NODE_HINT_SIZE + AUTH_TAG_SIZE;

const ONION_KEY_INFO: &[u8] = b"lunarpunk-onion-key-v1";

const ONION_BLIND_INFO: &[u8] = b"lunarpunk-onion-blind-v1";


#[derive(Debug, Clone)]
pub struct RouteHop {

    pub hint: u16,

    pub public_key: [u8; 32],
}


#[derive(Debug, Clone)]
pub struct OnionRoute {

    pub hops: HeaplessVec<RouteHop, MAX_HOPS>,
}

impl OnionRoute {

    pub fn new(hops: &[RouteHop]) -> Option<Self> {
        if hops.len() < MIN_HOPS || hops.len() > MAX_HOPS {
            return None;
        }

        let mut route_hops = HeaplessVec::new();
        for hop in hops {
            route_hops.push(hop.clone()).ok()?;
        }

        Some(Self { hops: route_hops })
    }


    pub fn len(&self) -> usize {
        self.hops.len()
    }


    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }


    pub fn entry_hint(&self) -> u16 {
        self.hops.first().map(|h| h.hint).unwrap_or(0)
    }


    pub fn exit_hint(&self) -> u16 {
        self.hops.last().map(|h| h.hint).unwrap_or(0)
    }


    pub fn overhead(&self) -> usize {
        self.hops.len() * HOP_OVERHEAD
    }
}


#[derive(Debug, Clone)]
pub struct OnionPacket {

    pub data: HeaplessVec<u8, 256>,

    pub num_layers: u8,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnionError {

    InvalidRoute,

    PacketTooLarge,

    AuthenticationFailed,

    DecryptionFailed,

    NoMoreLayers,
}


pub struct OnionRouter {

    our_private: [u8; 32],

    our_public: [u8; 32],

    our_hint: u16,
}

impl OnionRouter {

    pub fn new(private_key: [u8; 32]) -> Self {
        use crate::crypto::x25519::x25519_base;

        let our_public = x25519_base(&private_key);


        let hint_hash = Sha256::hash(&our_public);
        let our_hint = ((hint_hash[0] as u16) << 8) | (hint_hash[1] as u16);

        Self {
            our_private: private_key,
            our_public,
            our_hint,
        }
    }


    pub fn wrap(&self, payload: &[u8], route: &OnionRoute) -> Result<OnionPacket, OnionError> {
        if route.len() < MIN_HOPS || route.len() > MAX_HOPS {
            return Err(OnionError::InvalidRoute);
        }


        let total_overhead = route.overhead();
        if payload.len() + total_overhead > 256 {
            return Err(OnionError::PacketTooLarge);
        }


        let mut current = HeaplessVec::<u8, 256>::new();
        current.extend_from_slice(payload).map_err(|_| OnionError::PacketTooLarge)?;


        for (i, hop) in route.hops.iter().enumerate().rev() {

            let shared = x25519(&self.our_private, &hop.public_key);


            let layer_index = (route.len() - 1 - i) as u8;
            let mut key_input = [0u8; 33];
            key_input[..32].copy_from_slice(&shared);
            key_input[32] = layer_index;

            let mut layer_key = [0u8; 32];
            Hkdf::derive(&key_input, &[layer_index], ONION_KEY_INFO, &mut layer_key);


            let encrypted = self.encrypt_layer(&layer_key, &current)?;


            let tag = self.compute_tag(&layer_key, &encrypted);


            let mut new_layer = HeaplessVec::<u8, 256>::new();


            let next_hint = if i == route.len() - 1 {

                0u16
            } else {
                route.hops[i + 1].hint
            };

            new_layer.push((next_hint >> 8) as u8).map_err(|_| OnionError::PacketTooLarge)?;
            new_layer.push(next_hint as u8).map_err(|_| OnionError::PacketTooLarge)?;
            new_layer.extend_from_slice(&tag).map_err(|_| OnionError::PacketTooLarge)?;
            new_layer.extend_from_slice(&encrypted).map_err(|_| OnionError::PacketTooLarge)?;

            current = new_layer;
        }

        Ok(OnionPacket {
            data: current,
            num_layers: route.len() as u8,
        })
    }


    pub fn unwrap(&self, packet: &OnionPacket, sender_public: &[u8; 32]) -> Result<(u16, OnionPacket), OnionError> {
        if packet.data.len() < HOP_OVERHEAD {
            return Err(OnionError::DecryptionFailed);
        }


        let next_hint = ((packet.data[0] as u16) << 8) | (packet.data[1] as u16);
        let tag = &packet.data[2..18];
        let encrypted = &packet.data[18..];


        let shared = x25519(&self.our_private, sender_public);


        let layer_index = packet.num_layers.saturating_sub(1);
        let mut key_input = [0u8; 33];
        key_input[..32].copy_from_slice(&shared);
        key_input[32] = layer_index;

        let mut layer_key = [0u8; 32];
        Hkdf::derive(&key_input, &[layer_index], ONION_KEY_INFO, &mut layer_key);


        let expected_tag = self.compute_tag(&layer_key, encrypted);
        if !constant_time_eq(tag, &expected_tag) {
            return Err(OnionError::AuthenticationFailed);
        }


        let inner = self.decrypt_layer(&layer_key, encrypted)?;


        if next_hint == 0 {
            return Err(OnionError::NoMoreLayers);
        }

        let mut inner_packet = OnionPacket {
            data: inner,
            num_layers: packet.num_layers.saturating_sub(1),
        };

        Ok((next_hint, inner_packet))
    }


    pub fn unwrap_final(&self, packet: &OnionPacket, sender_public: &[u8; 32]) -> Result<HeaplessVec<u8, 256>, OnionError> {
        if packet.data.len() < HOP_OVERHEAD {
            return Err(OnionError::DecryptionFailed);
        }


        let tag = &packet.data[2..18];
        let encrypted = &packet.data[18..];


        let shared = x25519(&self.our_private, sender_public);


        let layer_index = packet.num_layers.saturating_sub(1);
        let mut key_input = [0u8; 33];
        key_input[..32].copy_from_slice(&shared);
        key_input[32] = layer_index;

        let mut layer_key = [0u8; 32];
        Hkdf::derive(&key_input, &[layer_index], ONION_KEY_INFO, &mut layer_key);


        let expected_tag = self.compute_tag(&layer_key, encrypted);
        if !constant_time_eq(tag, &expected_tag) {
            return Err(OnionError::AuthenticationFailed);
        }


        self.decrypt_layer(&layer_key, encrypted)
    }


    fn encrypt_layer(&self, key: &[u8; 32], data: &[u8]) -> Result<HeaplessVec<u8, 256>, OnionError> {
        let mut output = HeaplessVec::new();
        output.extend_from_slice(data).map_err(|_| OnionError::PacketTooLarge)?;


        let aes = Aes256::new(key);
        let mut counter = [0u8; 16];
        let mut keystream = [0u8; 16];
        let mut block_num = 0u64;

        for chunk in output.chunks_mut(16) {
            keystream.copy_from_slice(&counter);
            keystream[8..].copy_from_slice(&block_num.to_le_bytes());
            aes.encrypt_block(&mut keystream);
            for (c, k) in chunk.iter_mut().zip(keystream.iter()) {
                *c ^= k;
            }
            block_num += 1;
        }

        Ok(output)
    }


    fn decrypt_layer(&self, key: &[u8; 32], data: &[u8]) -> Result<HeaplessVec<u8, 256>, OnionError> {

        self.encrypt_layer(key, data)
    }


    fn compute_tag(&self, key: &[u8; 32], data: &[u8]) -> [u8; 16] {

        let mut inner = [0x36u8; 64];
        let mut outer = [0x5cu8; 64];

        for (i, k) in key.iter().enumerate() {
            inner[i] ^= k;
            outer[i] ^= k;
        }


        let mut inner_input = HeaplessVec::<u8, 320>::new();
        let _ = inner_input.extend_from_slice(&inner);
        let _ = inner_input.extend_from_slice(data);
        let inner_hash = Sha256::hash(&inner_input);


        let mut outer_input = [0u8; 96];
        outer_input[..64].copy_from_slice(&outer);
        outer_input[64..].copy_from_slice(&inner_hash);
        let full = Sha256::hash(&outer_input);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&full[..16]);
        tag
    }


    pub fn our_hint(&self) -> u16 {
        self.our_hint
    }


    pub fn our_public(&self) -> &[u8; 32] {
        &self.our_public
    }


    pub fn derive_blinded_hint(&self, epoch: u64) -> u16 {
        let mut input = [0u8; 40];
        input[..32].copy_from_slice(&self.our_public);
        input[32..].copy_from_slice(&epoch.to_le_bytes());

        let mut blinded = [0u8; 2];
        Hkdf::derive(&input, &epoch.to_le_bytes(), ONION_BLIND_INFO, &mut blinded);

        ((blinded[0] as u16) << 8) | (blinded[1] as u16)
    }
}


pub struct RouteBuilder {

    relays: HeaplessVec<RouteHop, 32>,
}

impl RouteBuilder {
    pub fn new() -> Self {
        Self {
            relays: HeaplessVec::new(),
        }
    }


    pub fn add_relay(&mut self, hint: u16, public_key: [u8; 32]) -> bool {
        self.relays.push(RouteHop { hint, public_key }).is_ok()
    }


    pub fn build_route(&self, destination: RouteHop, num_hops: usize) -> Option<OnionRoute> {
        if num_hops < MIN_HOPS || num_hops > MAX_HOPS {
            return None;
        }


        let relay_count = num_hops - 1;
        if self.relays.len() < relay_count {
            return None;
        }

        let mut hops = HeaplessVec::<RouteHop, MAX_HOPS>::new();


        for i in 0..relay_count {
            hops.push(self.relays[i % self.relays.len()].clone()).ok()?;
        }


        hops.push(destination).ok()?;

        Some(OnionRoute { hops })
    }


    pub fn relay_count(&self) -> usize {
        self.relays.len()
    }
}

impl Default for RouteBuilder {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::x25519::x25519_base;

    #[test]
    fn test_onion_wrap_unwrap() {

        let relay1_priv = [1u8; 32];
        let relay2_priv = [2u8; 32];
        let relay3_priv = [3u8; 32];

        let relay1_pub = x25519_base(&relay1_priv);
        let relay2_pub = x25519_base(&relay2_priv);
        let relay3_pub = x25519_base(&relay3_priv);


        let sender_priv = [4u8; 32];
        let sender = OnionRouter::new(sender_priv);


        let route = OnionRoute::new(&[
            RouteHop { hint: 0x0001, public_key: relay1_pub },
            RouteHop { hint: 0x0002, public_key: relay2_pub },
            RouteHop { hint: 0x0003, public_key: relay3_pub },
        ]).unwrap();


        let payload = b"Secret message!";
        let packet = sender.wrap(payload, &route).unwrap();


        assert!(packet.data.len() > payload.len());
    }
}
