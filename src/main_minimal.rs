mod rng;
mod crypto;
mod protocol;
mod protocol_router;
mod sx1262;
mod display;
mod meshtastic;
mod rnode;
mod session;
mod onion;
mod transport;
mod ble;

use esp_idf_hal::delay::FreeRtos;
use esp_idf_sys as _;

fn main() -> ! {

    esp_idf_sys::link_patches();


    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("=== Incremental Test: crypto + protocol + sx1262 ===");


    let test_data = b"hello";
    let hash = crypto::sha256::Sha256::hash(test_data);
    log::info!("SHA256 test: {:02x}{:02x}{:02x}{:02x}...", hash[0], hash[1], hash[2], hash[3]);


    let mut parser = protocol::FrameParser::new();
    log::info!("Protocol parser created");


    let router = protocol_router::ProtocolRouter::new();
    log::info!("Protocol router created");

    log::info!("All tested modules loaded successfully");

    let mut counter = 0u32;
    loop {
        log::info!("Loop iteration: {}", counter);
        counter = counter.wrapping_add(1);
        FreeRtos::delay_ms(1000);
    }
}
