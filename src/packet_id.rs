const RTC_SLOW_MEM_BASE: u32 = 0x5000_0000;


const RTC_SLOT_SESSION_HI: u32 = 8;
const RTC_SLOT_SESSION_LO: u32 = 9;
const RTC_SLOT_SEQUENCE: u32 = 10;
const RTC_SLOT_BOOT_COUNT: u32 = 11;
const RTC_SLOT_MAGIC: u32 = 12;


const RTC_MAGIC: u32 = 0x4C554E42;


const MAX_SEQUENCE: u32 = 0xFFFF_FFFE;


const WAKE_SEQUENCE_SKIP: u32 = 256;


const RNG_DATA_REG: u32 = 0x6003_5110;


struct PacketIdState {

    session_id: u32,

    sequence: u32,

    boot_count: u32,
}

impl PacketIdState {

    fn new_session(&mut self) {

        let hw_random1 = hw_rng_u32();
        let hw_random2 = hw_rng_u32();
        let boot_entropy = self.boot_count.wrapping_mul(0x9E3779B9);
        let timestamp = read_rtc_time();


        let mixed = hw_random1
            ^ boot_entropy
            ^ timestamp
            ^ self.session_id.wrapping_mul(0x85EBCA6B);


        let mixed = mix32(mixed);
        let mixed = mix32(mixed ^ hw_random2);


        self.session_id = mixed;


        if self.session_id == 0 {
            self.session_id = mix32(hw_rng_u32()) | 1;
        }


        self.sequence = 0;


        self.persist();
    }


    fn persist(&self) {
        rtc_write(RTC_SLOT_SESSION_HI, self.session_id);
        rtc_write(RTC_SLOT_SEQUENCE, self.sequence);
    }


    fn to_u64(&self) -> u64 {
        ((self.session_id as u64) << 32) | (self.sequence as u64)
    }
}


#[inline]
fn rtc_read(slot: u32) -> u32 {
    unsafe {
        let addr = (RTC_SLOW_MEM_BASE + slot * 4) as *const u32;
        core::ptr::read_volatile(addr)
    }
}


#[inline]
fn rtc_write(slot: u32, value: u32) {
    unsafe {
        let addr = (RTC_SLOW_MEM_BASE + slot * 4) as *mut u32;
        core::ptr::write_volatile(addr, value);
    }
}


#[inline]
fn hw_rng_u32() -> u32 {

    crate::rng::random_u32()
}


#[inline]
#[allow(dead_code)]
fn hw_rng_raw() -> u32 {
    unsafe {
        let rng_reg = RNG_DATA_REG as *const u32;

        let r1 = core::ptr::read_volatile(rng_reg);

        for _ in 0..10 {
            core::hint::spin_loop();
        }
        let r2 = core::ptr::read_volatile(rng_reg);
        r1 ^ r2.rotate_left(13)
    }
}


fn read_rtc_time() -> u32 {

    unsafe {
        let rtc_time_low = 0x6000_8048 as *const u32;
        core::ptr::read_volatile(rtc_time_low)
    }
}


#[inline]
const fn mix32(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x85EBCA6B);
    x ^= x >> 13;
    x = x.wrapping_mul(0xC2B2AE35);
    x ^= x >> 16;
    x
}


use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};


static PACKET_ID_SESSION: AtomicU32 = AtomicU32::new(0);
static PACKET_ID_SEQUENCE: AtomicU32 = AtomicU32::new(0);


static BOOT_COUNT: AtomicU32 = AtomicU32::new(0);


static INITIALIZED: AtomicBool = AtomicBool::new(false);


pub fn init() {

    if INITIALIZED.load(Ordering::Acquire) {
        return;
    }


    if INITIALIZED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {

        while !INITIALIZED.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        return;
    }


    let magic = rtc_read(RTC_SLOT_MAGIC);

    let (session_id, sequence, boot_count) = if magic == RTC_MAGIC {

        let stored_session = rtc_read(RTC_SLOT_SESSION_HI);
        let stored_sequence = rtc_read(RTC_SLOT_SEQUENCE);
        let stored_boot_count = rtc_read(RTC_SLOT_BOOT_COUNT);

        let boot_count = stored_boot_count.wrapping_add(1);


        if stored_sequence >= MAX_SEQUENCE {

            let new_session = generate_session_id(stored_session, boot_count);
            (new_session, 0u32, boot_count)
        } else {

            let new_sequence = stored_sequence.saturating_add(WAKE_SEQUENCE_SKIP);
            (stored_session, new_sequence, boot_count)
        }
    } else {

        let new_session = generate_session_id(0, 0);
        rtc_write(RTC_SLOT_MAGIC, RTC_MAGIC);
        (new_session, 0u32, 0u32)
    };


    BOOT_COUNT.store(boot_count, Ordering::SeqCst);
    rtc_write(RTC_SLOT_BOOT_COUNT, boot_count);


    PACKET_ID_SESSION.store(session_id, Ordering::SeqCst);
    PACKET_ID_SEQUENCE.store(sequence, Ordering::SeqCst);


    rtc_write(RTC_SLOT_SESSION_HI, session_id);
    rtc_write(RTC_SLOT_SEQUENCE, sequence);
}


fn generate_session_id(previous: u32, boot_count: u32) -> u32 {
    let hw_random1 = hw_rng_u32();
    let hw_random2 = hw_rng_u32();
    let boot_entropy = boot_count.wrapping_mul(0x9E3779B9);
    let timestamp = read_rtc_time();

    let mixed = hw_random1
        ^ boot_entropy
        ^ timestamp
        ^ previous.wrapping_mul(0x85EBCA6B);

    let mixed = mix32(mixed);
    let mixed = mix32(mixed ^ hw_random2);


    if mixed == 0 { mix32(hw_rng_u32()) | 1 } else { mixed }
}


pub fn next_packet_id() -> u32 {
    init();


    let sequence = PACKET_ID_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    let session_id = PACKET_ID_SESSION.load(Ordering::SeqCst);


    if sequence >= MAX_SEQUENCE {

        rotate_session_internal();
    }


    if sequence & 0xFF == 0 {
        rtc_write(RTC_SLOT_SESSION_HI, session_id);
        rtc_write(RTC_SLOT_SEQUENCE, sequence);
    }


    mix32(session_id ^ sequence.wrapping_mul(0x85EBCA6B))
}


fn rotate_session_internal() {

    let boot_count = BOOT_COUNT.load(Ordering::SeqCst);
    let old_session = PACKET_ID_SESSION.load(Ordering::SeqCst);

    let new_session = generate_session_id(old_session, boot_count);


    PACKET_ID_SESSION.store(new_session, Ordering::SeqCst);
    PACKET_ID_SEQUENCE.store(0, Ordering::SeqCst);


    rtc_write(RTC_SLOT_SESSION_HI, new_session);
    rtc_write(RTC_SLOT_SEQUENCE, 0);
}


pub fn rotate_session() {
    init();
    rotate_session_internal();
}


pub fn session_info() -> (u32, u32, u32) {
    init();
    let session_id = PACKET_ID_SESSION.load(Ordering::SeqCst);
    let sequence = PACKET_ID_SEQUENCE.load(Ordering::SeqCst);
    let boot_count = BOOT_COUNT.load(Ordering::SeqCst);
    (session_id, sequence, boot_count)
}


pub fn next_packet_id_64() -> u64 {
    init();
    let sequence = PACKET_ID_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    let session_id = PACKET_ID_SESSION.load(Ordering::SeqCst);


    if sequence >= MAX_SEQUENCE {
        rotate_session_internal();
    }

    ((session_id as u64) << 32) | (sequence as u64)
}


pub fn invalidate_rtc() {
    rtc_write(RTC_SLOT_MAGIC, 0);
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mix32() {

        let a = mix32(0);
        let b = mix32(1);
        let c = mix32(2);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn test_mix32_bijective() {

        let mut outputs = [0u32; 1000];
        for i in 0..1000 {
            outputs[i] = mix32(i as u32);
        }


        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                assert_ne!(outputs[i], outputs[j], "Collision at {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_packet_id_state() {
        let mut state = PacketIdState {
            session_id: 0xABCD_1234,
            sequence: 0x5678_9ABC,
            boot_count: 0,
        };

        let nonce = state.to_u64();
        assert_eq!(nonce >> 32, 0xABCD_1234);
        assert_eq!(nonce as u32, 0x5678_9ABC);
    }

    #[test]
    fn test_generate_session_id_nonzero() {

        for _ in 0..100 {
            let session = generate_session_id(0, 0);
            assert_ne!(session, 0, "Session ID must not be zero");
        }
    }

    #[test]
    fn test_uniqueness_atomic() {

        PACKET_ID_SESSION.store(0x1234_0000, Ordering::SeqCst);
        PACKET_ID_SEQUENCE.store(0, Ordering::SeqCst);
        INITIALIZED.store(true, Ordering::SeqCst);

        let mut ids = [0u32; 100];
        for id in &mut ids {

            let sequence = PACKET_ID_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let session = PACKET_ID_SESSION.load(Ordering::SeqCst);
            *id = mix32(session ^ sequence.wrapping_mul(0x85EBCA6B));
        }


        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "Duplicate ID at {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_64bit_nonce_uniqueness() {

        PACKET_ID_SESSION.store(0x1234, Ordering::SeqCst);
        PACKET_ID_SEQUENCE.store(0, Ordering::SeqCst);
        INITIALIZED.store(true, Ordering::SeqCst);

        let mut prev = 0u64;
        for _ in 0..1000 {
            let sequence = PACKET_ID_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let session = PACKET_ID_SESSION.load(Ordering::SeqCst);
            let nonce = ((session as u64) << 32) | (sequence as u64);
            assert!(nonce > prev || prev == 0, "Nonces must be strictly monotonic");
            prev = nonce;
        }
    }

    #[test]
    fn test_session_info() {
        PACKET_ID_SESSION.store(0xDEAD_BEEF, Ordering::SeqCst);
        PACKET_ID_SEQUENCE.store(0xCAFE_BABE, Ordering::SeqCst);
        BOOT_COUNT.store(42, Ordering::SeqCst);
        INITIALIZED.store(true, Ordering::SeqCst);

        let (session, sequence, boot) = session_info();
        assert_eq!(session, 0xDEAD_BEEF);
        assert_eq!(sequence, 0xCAFE_BABE);
        assert_eq!(boot, 42);
    }
}
