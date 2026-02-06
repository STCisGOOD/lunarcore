use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};


const RNG_DATA_REG: u32 = 0x6003_5110;


const WIFI_MAC_TIME_REG: u32 = 0x6003_3010;


const MAX_REPETITION_COUNT: u32 = 8;


const APT_WINDOW_SIZE: u32 = 512;


const APT_CUTOFF: u32 = 20;


const MIN_SAMPLES_FOR_HEALTH: u32 = 64;


const MIN_ENTROPY_SCALED: u32 = 24;


static RNG_HEALTHY: AtomicBool = AtomicBool::new(false);


static SAMPLE_COUNT: AtomicU32 = AtomicU32::new(0);


static REPETITION_COUNT: AtomicU32 = AtomicU32::new(0);


static LAST_VALUE: AtomicU32 = AtomicU32::new(0);


static FAILURE_COUNT: AtomicU32 = AtomicU32::new(0);


static BIT_COUNTS: [AtomicU32; 32] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];


static INITIALIZED: AtomicBool = AtomicBool::new(false);


pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }


    SAMPLE_COUNT.store(0, Ordering::SeqCst);
    REPETITION_COUNT.store(0, Ordering::SeqCst);
    FAILURE_COUNT.store(0, Ordering::SeqCst);


    for _ in 0..MIN_SAMPLES_FOR_HEALTH {
        let _ = raw_random_u32_with_health();
    }


    let failures = FAILURE_COUNT.load(Ordering::SeqCst);
    let healthy = failures == 0 && estimate_entropy() >= MIN_ENTROPY_SCALED;
    RNG_HEALTHY.store(healthy, Ordering::SeqCst);

    if !healthy {
        log_rng_warning("RNG health check failed during initialization");
    }
}


static RNG_WARNING_COUNT: AtomicU32 = AtomicU32::new(0);


#[inline]
fn log_rng_warning(_msg: &str) {
    RNG_WARNING_COUNT.fetch_add(1, Ordering::SeqCst);


}


pub fn warning_count() -> u32 {
    RNG_WARNING_COUNT.load(Ordering::SeqCst)
}


#[inline]
fn hw_rng_raw() -> u32 {
    unsafe {
        let reg = RNG_DATA_REG as *const u32;
        core::ptr::read_volatile(reg)
    }
}


fn raw_random_u32_with_health() -> u32 {
    let value = hw_rng_raw();
    update_health_state(value);
    value
}


fn update_health_state(value: u32) {
    let count = SAMPLE_COUNT.fetch_add(1, Ordering::SeqCst);


    let last = LAST_VALUE.swap(value, Ordering::SeqCst);
    if value == last {
        let rep = REPETITION_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
        if rep >= MAX_REPETITION_COUNT {
            FAILURE_COUNT.fetch_add(1, Ordering::SeqCst);
            RNG_HEALTHY.store(false, Ordering::SeqCst);
            log_rng_warning("RNG repetition count exceeded");
        }
    } else {
        REPETITION_COUNT.store(0, Ordering::SeqCst);
    }


    for i in 0..32 {
        if (value >> i) & 1 == 1 {
            BIT_COUNTS[i].fetch_add(1, Ordering::Relaxed);
        }
    }


    if count > 0 && count % APT_WINDOW_SIZE == 0 {
        reassess_health();
    }
}


fn reassess_health() {
    let failures = FAILURE_COUNT.load(Ordering::SeqCst);
    let entropy = estimate_entropy();


    if failures == 0 && entropy >= MIN_ENTROPY_SCALED {
        RNG_HEALTHY.store(true, Ordering::SeqCst);
    } else if entropy < MIN_ENTROPY_SCALED {
        RNG_HEALTHY.store(false, Ordering::SeqCst);
        log_rng_warning("RNG entropy below threshold");
    }


    if failures > 0 {

        let _ = FAILURE_COUNT.compare_exchange(
            failures,
            failures - 1,
            Ordering::SeqCst,
            Ordering::Relaxed
        );

    }


    if SAMPLE_COUNT.load(Ordering::SeqCst) % (APT_WINDOW_SIZE * 4) == 0 {
        for bc in &BIT_COUNTS {
            bc.store(0, Ordering::Relaxed);
        }
    }
}


fn estimate_entropy() -> u32 {
    let samples = SAMPLE_COUNT.load(Ordering::SeqCst);
    if samples < MIN_SAMPLES_FOR_HEALTH {
        return 0;
    }

    let mut total_entropy: u32 = 0;

    for bc in &BIT_COUNTS {
        let ones = bc.load(Ordering::Relaxed);


        let expected = samples / 2;
        let diff = if ones > expected { ones - expected } else { expected - ones };


        let scaled_entropy = if diff >= expected {
            0
        } else {

            8u32.saturating_sub((8 * diff) / expected.max(1))
        };

        total_entropy += scaled_entropy;
    }


    total_entropy / 32
}


#[inline]
pub fn is_healthy() -> bool {
    RNG_HEALTHY.load(Ordering::SeqCst)
}


pub fn health_stats() -> RngHealthStats {
    RngHealthStats {
        healthy: RNG_HEALTHY.load(Ordering::SeqCst),
        sample_count: SAMPLE_COUNT.load(Ordering::SeqCst),
        failure_count: FAILURE_COUNT.load(Ordering::SeqCst),
        estimated_entropy: estimate_entropy(),
    }
}


#[derive(Debug, Clone, Copy)]
pub struct RngHealthStats {

    pub healthy: bool,

    pub sample_count: u32,

    pub failure_count: u32,

    pub estimated_entropy: u32,
}


pub fn random_u32() -> u32 {
    if !INITIALIZED.load(Ordering::SeqCst) {
        init();
    }

    let healthy = RNG_HEALTHY.load(Ordering::SeqCst);


    let r1 = raw_random_u32_with_health();


    for _ in 0..5 {
        core::hint::spin_loop();
    }

    let r2 = raw_random_u32_with_health();


    let time_entropy = read_timer_entropy();


    let mut result = mix_entropy(r1, r2, time_entropy);


    if !healthy {
        log_rng_warning("RNG unhealthy - applying compensating entropy mixing");


        for i in 0..4 {
            for _ in 0..10 {
                core::hint::spin_loop();
            }
            let extra = raw_random_u32_with_health();
            let time = read_timer_entropy();
            result = mix_entropy(result, extra, time.wrapping_add(i));
        }
    }

    result
}


pub fn random_u32_checked() -> Option<u32> {
    if !is_healthy() {
        return None;
    }
    Some(random_u32())
}


pub fn fill_random(dest: &mut [u8]) {
    if !INITIALIZED.load(Ordering::SeqCst) {
        init();
    }

    let mut offset = 0;
    while offset < dest.len() {
        let random = random_u32();
        let bytes = random.to_le_bytes();

        let remaining = dest.len() - offset;
        let to_copy = remaining.min(4);

        dest[offset..offset + to_copy].copy_from_slice(&bytes[..to_copy]);
        offset += to_copy;
    }
}


pub fn fill_random_checked(dest: &mut [u8]) -> bool {
    if !is_healthy() {
        return false;
    }
    fill_random(dest);
    true
}


pub fn recheck_health() {

    FAILURE_COUNT.store(0, Ordering::SeqCst);


    for _ in 0..MIN_SAMPLES_FOR_HEALTH {
        let _ = raw_random_u32_with_health();
    }


    reassess_health();
}


fn read_timer_entropy() -> u32 {
    unsafe {

        let timer = core::ptr::read_volatile(WIFI_MAC_TIME_REG as *const u32);
        timer
    }
}


#[inline]
fn mix_entropy(a: u32, b: u32, c: u32) -> u32 {
    let mut h = a;
    h ^= b.rotate_left(13);
    h = h.wrapping_mul(0x85EBCA6B);
    h ^= c.rotate_right(7);
    h = h.wrapping_mul(0xC2B2AE35);
    h ^= h >> 16;
    h
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mix_entropy() {

        let a = mix_entropy(1, 2, 3);
        let b = mix_entropy(1, 2, 4);
        let c = mix_entropy(2, 2, 3);

        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn test_entropy_estimation() {

        SAMPLE_COUNT.store(100, Ordering::SeqCst);


        for bc in &BIT_COUNTS {
            bc.store(50, Ordering::Relaxed);
        }

        let entropy = estimate_entropy();
        assert!(entropy >= 7, "Perfect distribution should have high entropy");
    }

    #[test]
    fn test_entropy_estimation_biased() {

        SAMPLE_COUNT.store(100, Ordering::SeqCst);


        for bc in &BIT_COUNTS {
            bc.store(95, Ordering::Relaxed);
        }

        let entropy = estimate_entropy();
        assert!(entropy < 4, "Biased distribution should have low entropy");
    }

    #[test]
    fn test_health_stats() {
        let stats = health_stats();

        let _ = stats.healthy;
        let _ = stats.sample_count;
        let _ = stats.failure_count;
        let _ = stats.estimated_entropy;
    }
}
