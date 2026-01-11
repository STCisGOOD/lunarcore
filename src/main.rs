mod crypto;
mod rng;
mod sx1262;
mod protocol;
mod protocol_router;
mod meshtastic;
mod rnode;
mod ble;
mod display;
mod transport;
mod session;
mod onion;

use esp_idf_hal::delay::FreeRtos;
use esp_idf_sys as _;

use esp_idf_hal::prelude::*;
use esp_idf_hal::gpio::*;
use esp_idf_hal::spi::{SpiDeviceDriver, SpiDriverConfig};
use esp_idf_hal::i2c::{I2cConfig, I2cDriver};
use esp_idf_hal::uart::UartDriver;
use esp_idf_hal::adc::attenuation::DB_11;
use esp_idf_hal::adc::oneshot::config::AdcChannelConfig;
use esp_idf_hal::adc::oneshot::{AdcDriver, AdcChannelDriver};
use display::StatusDisplay;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crypto::sha256::Sha256;
use heapless::Vec;

use sx1262::{Sx1262, RadioConfig, RadioState, RadioError};
use protocol::{Frame, FrameParser, Command, MAX_FRAME_SIZE};
use protocol_router::{Protocol, ProtocolRouter, ProtocolDetector, TransportType};
use meshtastic::{MeshtasticParser, MeshtasticFrame, MeshtasticHandler};
use rnode::{KissParser, KissFrame, RNodeHandler, KissCommand};
use ble::{BleManager, ServiceType};
use session::{SessionManager, Session, SessionParams, SessionError, MessageHeader};
use onion::{OnionRouter, OnionRoute, RouteHop, OnionPacket, OnionError, RouteBuilder};
use transport::{WirePacket, AddressTranslator, UniversalAddress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {

    SessionError,

    EncryptionFailed,

    DecryptionFailed,

    NoSession,

    OnionError,

    InvalidFormat,

    BufferOverflow,
}

pub enum DecryptResult {

    Plaintext(heapless::Vec<u8, 256>),

    Forward {
        next_hop: u16,
        data: heapless::Vec<u8, 237>,
    },
}

const FIRMWARE_VERSION: &str = "LunarCore v1.0.0";

const BAUD_RATE: u32 = 115200;

const RX_BUFFER_SIZE: usize = 512;

const DEFAULT_FREQUENCY: u32 = 915_000_000;

const BATTERY_DIVIDER_RATIO: f32 = 4.9;

const ADC_VREF_MV: u32 = 3300;

const ADC_MAX_VALUE: u32 = 4095;

const BATTERY_LOW_MV: u32 = 3400;

const BATTERY_CRITICAL_MV: u32 = 3200;

const WATCHDOG_TIMEOUT_SEC: u32 = 30;

const LED_BLINK_IDLE: u32 = 2000;
const LED_BLINK_ACTIVE: u32 = 500;
const LED_BLINK_ERROR: u32 = 100;

const PIN_SPI_MOSI: i32 = 10;
const PIN_SPI_MISO: i32 = 11;
const PIN_SPI_SCK: i32 = 9;

const PIN_LORA_NSS: i32 = 8;
const PIN_LORA_RST: i32 = 12;
const PIN_LORA_BUSY: i32 = 13;
const PIN_LORA_DIO1: i32 = 14;

const PIN_LED: i32 = 35;
const PIN_VEXT: i32 = 36;

const PIN_BATTERY_ADC: i32 = 1;

const PIN_I2C_SDA: i32 = 17;
const PIN_I2C_SCL: i32 = 18;
const PIN_OLED_RST: i32 = 21;

static DIO1_TRIGGERED: AtomicBool = AtomicBool::new(false);

static PACKET_PENDING: AtomicBool = AtomicBool::new(false);

static TX_COMPLETE: AtomicBool = AtomicBool::new(false);

static SYSTEM_TICKS: AtomicU32 = AtomicU32::new(0);

static LAST_ACTIVITY: AtomicU32 = AtomicU32::new(0);

static ERROR_COUNT: AtomicU32 = AtomicU32::new(0);

#[derive(Clone)]
struct NodeIdentity {

    node_id: u32,

    mac_address: [u8; 6],

    hardware_serial: [u8; 8],

    public_key: [u8; 32],

    private_key: [u8; 32],
}

const NVS_NAMESPACE: &str = "lunarcore";
const NVS_KEY_NODE_ID: &str = "node_id";
const NVS_KEY_PRIVATE_KEY: &str = "priv_key";

impl NodeIdentity {

    fn from_hardware() -> Self {

        let mac_address = Self::read_mac_address();

        let hardware_serial = Self::read_hardware_serial();

        let (node_id, private_key) = Self::load_or_create_identity(&hardware_serial);

        let public_key = crypto::ed25519::Ed25519::public_key(&private_key);

        Self {
            node_id,
            mac_address,
            hardware_serial,
            public_key,
            private_key,
        }
    }

    fn load_or_create_identity(hardware_serial: &[u8; 8]) -> (u32, [u8; 32]) {

        let nvs_result = unsafe {
            let mut handle: esp_idf_sys::nvs_handle_t = 0;
            let namespace = core::ffi::CStr::from_bytes_with_nul(b"lunarcore\0").unwrap();
            let err = esp_idf_sys::nvs_open(
                namespace.as_ptr(),
                esp_idf_sys::nvs_open_mode_t_NVS_READWRITE,
                &mut handle,
            );
            if err == esp_idf_sys::ESP_OK {
                Some(handle)
            } else {

                esp_idf_sys::nvs_flash_init();
                let err = esp_idf_sys::nvs_open(
                    namespace.as_ptr(),
                    esp_idf_sys::nvs_open_mode_t_NVS_READWRITE,
                    &mut handle,
                );
                if err == esp_idf_sys::ESP_OK {
                    Some(handle)
                } else {
                    None
                }
            }
        };

        if let Some(handle) = nvs_result {

            let mut node_id: u32 = 0;
            let mut private_key = [0u8; 32];
            let mut key_len: usize = 32;

            let node_id_key = core::ffi::CStr::from_bytes_with_nul(b"node_id\0").unwrap();
            let priv_key_key = core::ffi::CStr::from_bytes_with_nul(b"priv_key\0").unwrap();

            let has_node_id = unsafe {
                esp_idf_sys::nvs_get_u32(handle, node_id_key.as_ptr(), &mut node_id) == esp_idf_sys::ESP_OK
            };

            let has_private_key = unsafe {
                esp_idf_sys::nvs_get_blob(
                    handle,
                    priv_key_key.as_ptr(),
                    private_key.as_mut_ptr() as *mut _,
                    &mut key_len,
                ) == esp_idf_sys::ESP_OK && key_len == 32
            };

            if has_node_id && has_private_key {

                log::info!("Loaded existing node identity from NVS");
                unsafe { esp_idf_sys::nvs_close(handle); }
                return (node_id, private_key);
            }

            log::info!("Creating new random node identity (privacy-first)");

            node_id = Self::generate_random_node_id();

            private_key = Self::generate_random_private_key(hardware_serial);

            unsafe {
                esp_idf_sys::nvs_set_u32(handle, node_id_key.as_ptr(), node_id);
                esp_idf_sys::nvs_set_blob(
                    handle,
                    priv_key_key.as_ptr(),
                    private_key.as_ptr() as *const _,
                    32,
                );
                esp_idf_sys::nvs_commit(handle);
                esp_idf_sys::nvs_close(handle);
            }

            log::info!("Stored new identity in NVS");
            (node_id, private_key)
        } else {

            log::warn!("NVS not available, using ephemeral identity");
            let node_id = Self::generate_random_node_id();
            let private_key = Self::generate_random_private_key(hardware_serial);
            (node_id, private_key)
        }
    }

    fn generate_random_node_id() -> u32 {
        let mut random_bytes = [0u8; 4];
        unsafe {
            esp_idf_sys::esp_fill_random(random_bytes.as_mut_ptr() as *mut _, 4);
        }

        let id = u32::from_le_bytes(random_bytes);
        id | 0x80000000
    }

    fn generate_random_private_key(hardware_serial: &[u8; 8]) -> [u8; 32] {
        let mut random_bytes = [0u8; 32];
        unsafe {
            esp_idf_sys::esp_fill_random(random_bytes.as_mut_ptr() as *mut _, 32);
        }

        let mut seed_input = [0u8; 40];
        seed_input[0..32].copy_from_slice(&random_bytes);
        seed_input[32..40].copy_from_slice(hardware_serial);

        let mut private_key = Sha256::hash(&seed_input);

        private_key[0] &= 248;
        private_key[31] &= 127;
        private_key[31] |= 64;

        private_key
    }

    #[allow(dead_code)]
    fn factory_reset() -> Option<Self> {

        unsafe {
            let namespace = core::ffi::CStr::from_bytes_with_nul(b"lunarcore\0").unwrap();
            esp_idf_sys::nvs_flash_erase_partition(namespace.as_ptr());
        }

        log::info!("Factory reset: erased old identity, generating new one");

        Some(Self::from_hardware())
    }

    fn read_mac_address() -> [u8; 6] {
        let mut mac = [0u8; 6];

        unsafe {

            esp_idf_sys::esp_efuse_mac_get_default(mac.as_mut_ptr());
        }

        mac
    }

    fn read_hardware_serial() -> [u8; 8] {
        let mut serial = [0u8; 8];

        unsafe {

            let efuse_base: *const u32 = 0x6001A044 as *const u32;
            let word0 = core::ptr::read_volatile(efuse_base);
            let word1 = core::ptr::read_volatile(efuse_base.add(1));

            serial[0..4].copy_from_slice(&word0.to_le_bytes());
            serial[4..8].copy_from_slice(&word1.to_le_bytes());
        }

        serial
    }

    fn x25519_pubkey(&self) -> [u8; 32] {
        use crypto::x25519;
        x25519::x25519_base(&self.private_key)
    }
}

struct BatteryState {

    voltage_mv: u32,

    percentage: u8,

    is_charging: bool,

    is_low: bool,

    is_critical: bool,
}

impl BatteryState {
    fn new() -> Self {
        Self {
            voltage_mv: 0,
            percentage: 0,
            is_charging: false,
            is_low: false,
            is_critical: false,
        }
    }

    fn update(&mut self, adc_value: u32) {

        let vadc_mv = (adc_value * ADC_VREF_MV) / ADC_MAX_VALUE;
        self.voltage_mv = ((vadc_mv as f32) * BATTERY_DIVIDER_RATIO) as u32;

        self.percentage = Self::voltage_to_percentage(self.voltage_mv);

        self.is_low = self.voltage_mv < BATTERY_LOW_MV;
        self.is_critical = self.voltage_mv < BATTERY_CRITICAL_MV;

        self.is_charging = self.voltage_mv > 4200;
    }

    fn voltage_to_percentage(mv: u32) -> u8 {

        const CURVE: [(u32, u8); 11] = [
            (4200, 100),
            (4100, 90),
            (4000, 80),
            (3900, 70),
            (3800, 60),
            (3700, 50),
            (3600, 40),
            (3500, 30),
            (3400, 20),
            (3300, 10),
            (3000, 0),
        ];

        if mv >= CURVE[0].0 {
            return 100;
        }
        if mv <= CURVE[10].0 {
            return 0;
        }

        for i in 0..10 {
            if mv >= CURVE[i + 1].0 && mv <= CURVE[i].0 {
                let v_range = CURVE[i].0 - CURVE[i + 1].0;
                let p_range = CURVE[i].1 - CURVE[i + 1].1;
                let v_offset = mv - CURVE[i + 1].0;

                return CURVE[i + 1].1 + ((v_offset * p_range as u32) / v_range) as u8;
            }
        }

        50
    }
}

struct Stats {

    tx_packets: u32,

    rx_packets: u32,

    tx_errors: u32,

    rx_errors: u32,

    protocol_switches: u32,

    tx_bytes: u64,

    rx_bytes: u64,

    uptime_seconds: u32,

    last_rssi: i16,

    last_snr: i8,

    airtime_ms: u64,
}

impl Stats {
    fn new() -> Self {
        Self {
            tx_packets: 0,
            rx_packets: 0,
            tx_errors: 0,
            rx_errors: 0,
            protocol_switches: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            uptime_seconds: 0,
            last_rssi: 0,
            last_snr: 0,
            airtime_ms: 0,
        }
    }

    fn record_rx(&mut self, len: usize, rssi: i16, snr: i8) {
        self.rx_packets += 1;
        self.rx_bytes += len as u64;
        self.last_rssi = rssi;
        self.last_snr = snr;
    }

    fn record_tx(&mut self, len: usize, airtime_ms: u32) {
        self.tx_packets += 1;
        self.tx_bytes += len as u64;
        self.airtime_ms += airtime_ms as u64;
    }
}

struct LedController {

    is_on: bool,

    last_toggle: u32,

    interval_ms: u32,

    blink_count: u8,

    remaining: u8,
}

impl LedController {
    fn new() -> Self {
        Self {
            is_on: false,
            last_toggle: 0,
            interval_ms: LED_BLINK_IDLE,
            blink_count: 0,
            remaining: 0,
        }
    }

    fn set_idle(&mut self) {
        self.interval_ms = LED_BLINK_IDLE;
        self.blink_count = 0;
    }

    fn set_active(&mut self) {
        self.interval_ms = LED_BLINK_ACTIVE;
        self.blink_count = 0;
    }

    fn set_error(&mut self) {
        self.interval_ms = LED_BLINK_ERROR;
        self.blink_count = 0;
    }

    fn flash(&mut self, count: u8) {
        self.blink_count = count;
        self.remaining = count * 2;
        self.interval_ms = 100;
    }

    fn update(&mut self, current_time: u32) -> bool {
        if current_time.wrapping_sub(self.last_toggle) >= self.interval_ms {
            self.last_toggle = current_time;

            if self.blink_count > 0 {
                if self.remaining > 0 {
                    self.remaining -= 1;
                    self.is_on = !self.is_on;
                    return true;
                } else {

                    self.set_idle();
                }
            } else {
                self.is_on = !self.is_on;
                return true;
            }
        }
        false
    }
}

struct LunarCore<SPI, NSS, RESET, BUSY, DIO1> {

    radio: Sx1262<SPI, NSS, RESET, BUSY, DIO1>,

    router: ProtocolRouter,

    meshcore_parser: FrameParser,

    meshtastic: MeshtasticHandler,

    rnode: RNodeHandler,

    ble: BleManager,

    stats: Stats,

    identity: NodeIdentity,

    battery: BatteryState,

    led: LedController,

    rx_active: bool,

    serial_protocol: Protocol,

    vext_enabled: bool,

    last_battery_check: u32,

    at_buffer: Vec<u8, 128>,

    session_manager: SessionManager,

    onion_router: OnionRouter,

    route_builder: RouteBuilder,

    our_address: UniversalAddress,
}

impl<SPI, NSS, RESET, BUSY, DIO1, E> LunarCore<SPI, NSS, RESET, BUSY, DIO1>
where
    SPI: embedded_hal::spi::SpiDevice<Error = E>,
    NSS: embedded_hal::digital::OutputPin,
    RESET: embedded_hal::digital::OutputPin,
    BUSY: embedded_hal::digital::InputPin,
    DIO1: embedded_hal::digital::InputPin,
{
    fn new(radio: Sx1262<SPI, NSS, RESET, BUSY, DIO1>, identity: NodeIdentity) -> Self {
        let node_id = identity.node_id;

        let x25519_private = {
            let mut key = identity.private_key;

            key[0] &= 248;
            key[31] &= 127;
            key[31] |= 64;
            key
        };

        let onion_router = OnionRouter::new(x25519_private);

        let our_address = AddressTranslator::from_public_key(&identity.public_key);

        Self {
            radio,
            router: ProtocolRouter::new(),
            meshcore_parser: FrameParser::new(),
            meshtastic: MeshtasticHandler::new(node_id),
            rnode: RNodeHandler::new(),
            ble: BleManager::new(),
            stats: Stats::new(),
            identity,
            battery: BatteryState::new(),
            led: LedController::new(),
            rx_active: false,
            serial_protocol: Protocol::Unknown,
            vext_enabled: true,
            last_battery_check: 0,
            at_buffer: Vec::new(),

            session_manager: SessionManager::new(),
            onion_router,
            route_builder: RouteBuilder::new(),
            our_address,
        }
    }

    fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    fn update_battery(&mut self, adc_value: u32) {
        self.battery.update(adc_value);

        if self.battery.is_critical {
            self.led.set_error();
            log::warn!("Battery critical: {}mV", self.battery.voltage_mv);
        } else if self.battery.is_low {
            log::info!("Battery low: {}mV ({}%)", self.battery.voltage_mv, self.battery.percentage);
        }
    }

    fn handle_dio1_interrupt(&mut self) {

        DIO1_TRIGGERED.store(false, Ordering::Relaxed);

        if let Ok(irq_status) = self.radio.get_irq_status() {
            if irq_status & 0x01 != 0 {

                TX_COMPLETE.store(true, Ordering::Release);
                LAST_ACTIVITY.store(SYSTEM_TICKS.load(Ordering::Relaxed), Ordering::Relaxed);
            }
            if irq_status & 0x02 != 0 {

                PACKET_PENDING.store(true, Ordering::Release);
                LAST_ACTIVITY.store(SYSTEM_TICKS.load(Ordering::Relaxed), Ordering::Relaxed);
            }
            if irq_status & 0x04 != 0 {

            }
            if irq_status & 0x40 != 0 {

                self.stats.rx_errors += 1;
                ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
            }

            let _ = self.radio.clear_irq(irq_status);
        }
    }

    fn process_radio_events(&mut self) {

        if TX_COMPLETE.swap(false, Ordering::Acquire) {

            if self.radio.start_rx(0).is_ok() {
                self.rx_active = true;
            }
            self.led.flash(1);
        }

        if PACKET_PENDING.swap(false, Ordering::Acquire) {
            self.led.flash(2);
        }
    }

    fn process_at_command(&mut self, uart: &UartDriver) {

        let mut cmd_upper = [0u8; 128];
        let len = self.at_buffer.len().min(128);
        for i in 0..len {
            cmd_upper[i] = self.at_buffer[i].to_ascii_uppercase();
        }
        let cmd = &cmd_upper[..len];

        let _ = uart.write(b"\r\n");

        if cmd.starts_with(b"AT+VERSION") || cmd.starts_with(b"ATI") {

            let _ = uart.write(b"LunarCore v1.0.0\r\n");
            let _ = uart.write(b"Unified Mesh Bridge Firmware\r\n");
            let _ = uart.write(b"Protocols: MeshCore, Meshtastic, RNode/KISS\r\n");
            let _ = uart.write(b"OK\r\n");
        } else if cmd.starts_with(b"AT+STATUS") {

            let _ = uart.write(b"Status: ");
            if self.rx_active {
                let _ = uart.write(b"RX Active\r\n");
            } else {
                let _ = uart.write(b"Idle\r\n");
            }

            let mut buf = [0u8; 32];
            let s = format_battery(&self.battery, &mut buf);
            let _ = uart.write(s.as_bytes());
            let _ = uart.write(b"\r\n");

            let _ = uart.write(b"TX: ");
            write_u32(uart, self.stats.tx_packets);
            let _ = uart.write(b" RX: ");
            write_u32(uart, self.stats.rx_packets);
            let _ = uart.write(b"\r\n");

            let _ = uart.write(b"OK\r\n");
        } else if cmd.starts_with(b"AT+NODEID") {

            let _ = uart.write(b"Node ID: ");
            write_hex32(uart, self.identity.node_id);
            let _ = uart.write(b"\r\n");
            let _ = uart.write(b"OK\r\n");
        } else if cmd.starts_with(b"AT+MAC") {

            let _ = uart.write(b"MAC: ");
            for (i, &b) in self.identity.mac_address.iter().enumerate() {
                write_hex8(uart, b);
                if i < 5 {
                    let _ = uart.write(b":");
                }
            }
            let _ = uart.write(b"\r\n");
            let _ = uart.write(b"OK\r\n");
        } else if cmd.starts_with(b"AT+FREQ=") {

            if let Some(freq) = parse_u32_from_cmd(&cmd[8..]) {
                log::info!("Setting frequency to {} Hz", freq);
                let mut config = self.radio.config.clone();
                config.frequency = freq;
                if self.radio.configure(&config).is_ok() {
                    let _ = uart.write(b"OK\r\n");
                } else {
                    let _ = uart.write(b"ERROR\r\n");
                }
            } else {
                let _ = uart.write(b"ERROR: Invalid frequency\r\n");
            }
        } else if cmd.starts_with(b"AT+SF=") {

            if let Some(sf) = parse_u32_from_cmd(&cmd[6..]) {
                if sf >= 7 && sf <= 12 {
                    log::info!("Setting SF to {}", sf);
                    let mut config = self.radio.config.clone();
                    config.spreading_factor = sf as u8;
                    if self.radio.configure(&config).is_ok() {
                        let _ = uart.write(b"OK\r\n");
                    } else {
                        let _ = uart.write(b"ERROR\r\n");
                    }
                } else {
                    let _ = uart.write(b"ERROR: SF must be 7-12\r\n");
                }
            } else {
                let _ = uart.write(b"ERROR: Invalid SF\r\n");
            }
        } else if cmd.starts_with(b"AT+TXPOWER=") {

            if let Some(power) = parse_i8_from_cmd(&cmd[11..]) {
                if power >= -9 && power <= 22 {
                    log::info!("Setting TX power to {} dBm", power);
                    let mut config = self.radio.config.clone();
                    config.tx_power = power;
                    if self.radio.configure(&config).is_ok() {
                        let _ = uart.write(b"OK\r\n");
                    } else {
                        let _ = uart.write(b"ERROR\r\n");
                    }
                } else {
                    let _ = uart.write(b"ERROR: Power must be -9 to +22\r\n");
                }
            } else {
                let _ = uart.write(b"ERROR: Invalid power\r\n");
            }
        } else if cmd.starts_with(b"AT+RESET") {

            if self.radio.init().is_ok() {
                let _ = uart.write(b"OK\r\n");
            } else {
                let _ = uart.write(b"ERROR\r\n");
            }
        } else if cmd.starts_with(b"AT+RX") {

            if self.radio.start_rx(0).is_ok() {
                self.rx_active = true;
                let _ = uart.write(b"OK\r\n");
            } else {
                let _ = uart.write(b"ERROR\r\n");
            }
        } else if cmd.starts_with(b"AT+RSSI") {

            if let Ok(rssi) = self.radio.get_rssi() {
                let _ = uart.write(b"RSSI: ");
                write_i16(uart, rssi);
                let _ = uart.write(b" dBm\r\n");
                let _ = uart.write(b"OK\r\n");
            } else {
                let _ = uart.write(b"ERROR\r\n");
            }
        } else if cmd == b"AT" {

            let _ = uart.write(b"OK\r\n");
        } else if cmd.starts_with(b"AT+HELP") || cmd.starts_with(b"AT?") {

            let _ = uart.write(b"Available commands:\r\n");
            let _ = uart.write(b"  AT          - Test\r\n");
            let _ = uart.write(b"  ATI         - Version info\r\n");
            let _ = uart.write(b"  AT+STATUS   - System status\r\n");
            let _ = uart.write(b"  AT+NODEID   - Node ID\r\n");
            let _ = uart.write(b"  AT+MAC      - MAC address\r\n");
            let _ = uart.write(b"  AT+FREQ=Hz  - Set frequency\r\n");
            let _ = uart.write(b"  AT+SF=n     - Set spreading factor\r\n");
            let _ = uart.write(b"  AT+TXPOWER=n - Set TX power\r\n");
            let _ = uart.write(b"  AT+RX       - Start RX mode\r\n");
            let _ = uart.write(b"  AT+RSSI     - Get RSSI\r\n");
            let _ = uart.write(b"  AT+RESET    - Reset radio\r\n");
            let _ = uart.write(b"OK\r\n");
        } else {
            let _ = uart.write(b"ERROR: Unknown command\r\n");
        }
    }

    fn process_serial_byte(&mut self, byte: u8, uart: &UartDriver) {

        if self.serial_protocol == Protocol::Unknown {
            if let Some(protocol) = self.router.transport(TransportType::UsbSerial)
                .detector.feed(byte)
            {
                self.serial_protocol = protocol;
                self.stats.protocol_switches += 1;
                log::info!("Protocol detected: {}", protocol.name());

                self.configure_radio_for_protocol(protocol);
            }
        }

        match self.serial_protocol {
            Protocol::MeshCore => {
                if let Some(frame) = self.meshcore_parser.feed(byte) {
                    self.handle_meshcore_frame(&frame, uart);
                    self.router.transport(TransportType::UsbSerial)
                        .detector.confirm_frame();
                }
            }

            Protocol::Meshtastic => {
                if let Some(frame) = self.meshtastic.feed_serial(byte) {
                    self.handle_meshtastic_frame(&frame, uart);
                    self.router.transport(TransportType::UsbSerial)
                        .detector.confirm_frame();
                }
            }

            Protocol::RNode => {
                if let Some(frame) = self.rnode.feed_serial(byte) {
                    self.handle_rnode_frame(&frame, uart);
                    self.router.transport(TransportType::UsbSerial)
                        .detector.confirm_frame();
                }
            }

            Protocol::AtCommand => {

                if byte == b'\r' || byte == b'\n' {
                    if !self.at_buffer.is_empty() {
                        self.process_at_command(uart);
                        self.at_buffer.clear();
                    }
                } else if byte >= 0x20 && byte < 0x7F {

                    let _ = self.at_buffer.push(byte);
                }
            }

            Protocol::Unknown => {

            }
        }
    }

    fn configure_radio_for_protocol(&mut self, protocol: Protocol) {
        let config = match protocol {
            Protocol::MeshCore => RadioConfig {
                frequency: 915_000_000,
                spreading_factor: 9,
                bandwidth: 0,
                coding_rate: 1,
                tx_power: 14,
                sync_word: 0x12,
                preamble_length: 8,
                crc_enabled: true,
                implicit_header: false,
                ldro: false,
            },
            Protocol::Meshtastic => RadioConfig {
                frequency: 906_875_000,
                spreading_factor: 11,
                bandwidth: 0,
                coding_rate: 1,
                tx_power: 17,
                sync_word: 0x2B,
                preamble_length: 16,
                crc_enabled: true,
                implicit_header: false,
                ldro: true,
            },
            Protocol::RNode => {

                let cfg = self.rnode.config();
                RadioConfig {
                    frequency: cfg.frequency,
                    spreading_factor: cfg.spreading_factor,
                    bandwidth: match cfg.bandwidth {
                        125_000 => 0,
                        250_000 => 1,
                        500_000 => 2,
                        _ => 0,
                    },
                    coding_rate: cfg.coding_rate.saturating_sub(4),
                    tx_power: cfg.tx_power,
                    sync_word: 0x12,
                    preamble_length: 8,
                    crc_enabled: true,
                    implicit_header: false,
                    ldro: cfg.spreading_factor >= 11,
                }
            }
            _ => return,
        };

        if let Err(e) = self.radio.configure(&config) {
            log::error!("Failed to configure radio: {:?}", e);
        }

        self.router.set_lora_protocol(protocol);
    }

    fn handle_meshcore_frame(&mut self, frame: &Frame, uart: &UartDriver) {
        match frame.command {
            Command::Ping => {
                let response = protocol::build_pong(frame.sequence);
                self.send_frame(uart, &response);
            }

            Command::Configure => {
                if let Some(config) = protocol::parse_config(&frame.data) {
                    match self.radio.configure(&config) {
                        Ok(()) => {
                            let response = protocol::build_config_ack(frame.sequence);
                            self.send_frame(uart, &response);
                        }
                        Err(_) => {
                            if let Some(response) = protocol::build_error(frame.sequence, "Config failed") {
                                self.send_frame(uart, &response);
                            }
                        }
                    }
                }
            }

            Command::Transmit => {
                self.rx_active = false;
                match self.radio.transmit(&frame.data) {
                    Ok(()) => {
                        self.stats.tx_packets += 1;
                        let response = protocol::build_tx_done(frame.sequence);
                        self.send_frame(uart, &response);
                        let _ = self.radio.start_rx(0);
                        self.rx_active = true;
                    }
                    Err(e) => {
                        self.stats.tx_errors += 1;
                        let code = match e {
                            RadioError::TxTimeout => 1,
                            RadioError::BusyTimeout => 2,
                            _ => 255,
                        };
                        if let Some(response) = protocol::build_tx_error(frame.sequence, code) {
                            self.send_frame(uart, &response);
                        }
                    }
                }
            }

            Command::Version => {
                if let Some(response) = protocol::build_version_response(
                    frame.sequence,
                    FIRMWARE_VERSION,
                ) {
                    self.send_frame(uart, &response);
                }
            }

            Command::GetStats => {
                if let Some(response) = protocol::build_stats_response(
                    frame.sequence,
                    self.stats.tx_packets,
                    self.stats.rx_packets,
                    self.stats.tx_errors,
                    self.stats.rx_errors,
                ) {
                    self.send_frame(uart, &response);
                }
            }

            Command::Reset => {
                let _ = self.radio.init();
                self.rx_active = false;
                let response = protocol::build_pong(frame.sequence);
                self.send_frame(uart, &response);
            }

            _ => {
                if let Some(response) = protocol::build_error(frame.sequence, "Unknown command") {
                    self.send_frame(uart, &response);
                }
            }
        }

        if !self.rx_active && self.radio.state() == RadioState::Standby {
            if self.radio.start_rx(0).is_ok() {
                self.rx_active = true;
            }
        }
    }

    fn handle_meshtastic_frame(&mut self, frame: &MeshtasticFrame, uart: &UartDriver) {

        match self.meshtastic.process_toradio(frame) {
            Some(meshtastic::ToRadioResponse::LoRaPacket(tx_data)) => {

                self.rx_active = false;
                match self.radio.transmit(&tx_data) {
                    Ok(()) => {
                        self.stats.tx_packets += 1;
                        let _ = self.radio.start_rx(0);
                        self.rx_active = true;
                    }
                    Err(_) => {
                        self.stats.tx_errors += 1;
                    }
                }
            }

            Some(meshtastic::ToRadioResponse::FromRadio(response)) => {

                self.send_meshtastic_response(&response, uart);

                self.flush_meshtastic_responses(uart);
            }

            None => {

            }
        }

        if !self.rx_active {
            if self.radio.start_rx(0).is_ok() {
                self.rx_active = true;
            }
        }
    }

    fn send_meshtastic_response(&mut self, response: &[u8], uart: &UartDriver) {

        if let Some(serial_frame) = self.meshtastic.build_serial_frame(response) {
            let _ = uart.write(&serial_frame);
        }

        let _ = self.ble.queue_from_radio(response);

        self.meshtastic.rx_count = self.meshtastic.rx_count.wrapping_add(1);
        let _ = self.ble.notify_from_num(self.meshtastic.rx_count);
    }

    fn flush_meshtastic_responses(&mut self, uart: &UartDriver) {

        while let Some(meshtastic::ToRadioResponse::FromRadio(response)) =
            self.meshtastic.poll_pending_response()
        {
            self.send_meshtastic_response(&response, uart);

            FreeRtos::delay_ms(10);
        }
    }

    fn handle_rnode_frame(&mut self, frame: &KissFrame, uart: &UartDriver) {

        if let Some(response) = self.rnode.process_frame(frame) {

            let encoded = response.encode();
            let _ = uart.write(&encoded);
        }

        if frame.command == KissCommand::DataFrame as u8 {
            if let Some(tx_data) = self.rnode.get_tx_data(frame) {
                self.rx_active = false;
                match self.radio.transmit(tx_data) {
                    Ok(()) => {
                        self.stats.tx_packets += 1;
                        let _ = self.radio.start_rx(0);
                        self.rx_active = true;
                    }
                    Err(_) => {
                        self.stats.tx_errors += 1;
                    }
                }
            }
        }

        if self.rnode.is_online() && !self.rx_active {
            if self.radio.start_rx(0).is_ok() {
                self.rx_active = true;
            }
        }
    }

    fn check_rx(&mut self, uart: &UartDriver) {
        if !self.rx_active {
            return;
        }

        match self.radio.check_rx() {
            Ok(Some((data, rssi, snr))) => {
                self.stats.rx_packets += 1;
                self.route_rx_packet(&data, rssi, snr, uart);
            }
            Ok(None) => {

            }
            Err(RadioError::RxTimeout) => {
                let _ = self.radio.start_rx(0);
            }
            Err(RadioError::CrcError) => {
                self.stats.rx_errors += 1;
                let _ = self.radio.start_rx(0);
            }
            Err(_) => {
                self.stats.rx_errors += 1;
            }
        }
    }

    fn route_rx_packet(&mut self, data: &[u8], rssi: i16, snr: i8, uart: &UartDriver) {
        match self.serial_protocol {
            Protocol::MeshCore => {
                if let Some(frame) = protocol::build_receive(rssi, snr, data) {
                    self.send_frame(uart, &frame);
                }
            }

            Protocol::Meshtastic => {
                if let Some(packet) = self.meshtastic.process_lora_packet(data, rssi as i32, snr as f32) {
                    if let Some(from_radio) = meshtastic::encode_fromradio_packet(&packet) {

                        if let Some(serial_frame) = self.meshtastic.build_serial_frame(&from_radio) {
                            let _ = uart.write(&serial_frame);
                        }

                        let _ = self.ble.notify_from_num(self.meshtastic.rx_count);
                    }
                }
            }

            Protocol::RNode => {
                let frame = self.rnode.process_lora_packet(data, rssi, snr);
                let encoded = frame.encode();
                let _ = uart.write(&encoded);
            }

            _ => {

            }
        }
    }

    fn send_frame(&self, uart: &UartDriver, frame: &Frame) {
        let encoded = frame.encode();
        let _ = uart.write(&encoded);
    }

    fn encrypt_for_tx(
        &mut self,
        plaintext: &[u8],
        recipient_public: &[u8; 32],
        use_onion: bool,
    ) -> Result<Vec<u8, 237>, CryptoError> {

        let session = match self.session_manager.get_session(recipient_public) {
            Some(s) => s,
            None => {

                let our_x25519 = crypto::x25519::x25519_base(&self.identity.private_key);
                let shared = crypto::x25519::x25519(&self.identity.private_key, recipient_public);

                let params = SessionParams {
                    shared_secret: shared,
                    our_private: self.identity.private_key,
                    their_public: *recipient_public,
                    is_initiator: true,
                };

                self.session_manager.create_session(params);

                self.session_manager.get_session(recipient_public)
                    .ok_or(CryptoError::SessionError)?
            }
        };

        let (header, ciphertext) = session.encrypt(plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut session_encrypted = Vec::<u8, 256>::new();
        session_encrypted.extend_from_slice(&header.encode())
            .map_err(|_| CryptoError::BufferOverflow)?;
        session_encrypted.extend_from_slice(&ciphertext)
            .map_err(|_| CryptoError::BufferOverflow)?;

        let payload_for_wire = if use_onion && self.route_builder.relay_count() >= 3 {

            let dest_hint = AddressTranslator::from_public_key(recipient_public);
            let dest_hop = RouteHop {
                hint: dest_hint.meshcore_addr,
                public_key: *recipient_public,
            };

            if let Some(route) = self.route_builder.build_route(dest_hop, 3) {
                match self.onion_router.wrap(&session_encrypted, &route) {
                    Ok(onion_packet) => onion_packet.data,
                    Err(_) => session_encrypted,
                }
            } else {
                session_encrypted
            }
        } else {
            session_encrypted
        };

        let dest_address = AddressTranslator::from_public_key(recipient_public);
        let epoch = (millis() / 1000) as u64;
        let session_hint_bytes = session.derive_session_hint(epoch);

        let session_hint_u32 = ((session_hint_bytes[0] as u32) << 24)
            | ((session_hint_bytes[1] as u32) << 16)
            | ((session_hint_bytes[2] as u32) << 8)
            | (session_hint_bytes[3] as u32);

        let mut payload_truncated = Vec::<u8, 214>::new();
        let copy_len = core::cmp::min(payload_for_wire.len(), 214);
        let _ = payload_truncated.extend_from_slice(&payload_for_wire[..copy_len]);

        let wire_packet = WirePacket::new_data(
            dest_address.meshcore_addr,
            session_hint_u32,
            &payload_truncated,
        ).ok_or(CryptoError::BufferOverflow)?;

        let mut output = Vec::<u8, 237>::new();
        output.extend_from_slice(&wire_packet.encode())
            .map_err(|_| CryptoError::BufferOverflow)?;

        Ok(output)
    }

    fn decrypt_from_rx(
        &mut self,
        wire_data: &[u8],
        sender_public: &[u8; 32],
    ) -> Result<DecryptResult, CryptoError> {

        let wire_packet = WirePacket::decode(wire_data)
            .ok_or(CryptoError::InvalidFormat)?;

        let is_for_us = wire_packet.next_hop_hint == self.our_address.meshcore_addr;

        if !is_for_us {

            let mut expanded_payload = heapless::Vec::<u8, 256>::new();
            let _ = expanded_payload.extend_from_slice(&wire_packet.payload);

            let onion_packet = OnionPacket {
                data: expanded_payload,
                num_layers: (wire_data.len() / 18).min(7) as u8,
            };

            match self.onion_router.unwrap(&onion_packet, sender_public) {
                Ok((next_hint, inner_packet)) => {

                    let mut truncated = heapless::Vec::<u8, 214>::new();
                    let copy_len = core::cmp::min(inner_packet.data.len(), 214);
                    let _ = truncated.extend_from_slice(&inner_packet.data[..copy_len]);

                    if let Some(forward_packet) = WirePacket::new_data(
                        next_hint,
                        wire_packet.session_hint,
                        &truncated,
                    ) {
                        let mut encoded = Vec::<u8, 237>::new();
                        let _ = encoded.extend_from_slice(&forward_packet.encode());

                        return Ok(DecryptResult::Forward {
                            next_hop: next_hint,
                            data: encoded,
                        });
                    }
                    return Err(CryptoError::BufferOverflow);
                }
                Err(OnionError::NoMoreLayers) => {

                }
                Err(_) => {
                    return Err(CryptoError::OnionError);
                }
            }
        }

        let mut session_encrypted = heapless::Vec::<u8, 256>::new();
        let _ = session_encrypted.extend_from_slice(&wire_packet.payload);

        if session_encrypted.len() < 48 {
            return Err(CryptoError::InvalidFormat);
        }

        let header = MessageHeader::decode(&session_encrypted[..48])
            .ok_or(CryptoError::InvalidFormat)?;
        let ciphertext = &session_encrypted[48..];

        let session = self.session_manager.get_session(sender_public)
            .ok_or(CryptoError::NoSession)?;

        let plaintext = session.decrypt(&header, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(DecryptResult::Plaintext(plaintext))
    }

    fn add_relay(&mut self, hint: u16, public_key: [u8; 32]) {
        self.route_builder.add_relay(hint, public_key);
    }

    fn relay_count(&self) -> usize {
        self.route_builder.relay_count()
    }
}

fn dio1_isr() {
    DIO1_TRIGGERED.store(true, Ordering::Release);
}

fn timer_tick_isr() {
    SYSTEM_TICKS.fetch_add(1, Ordering::Relaxed);
}

fn millis() -> u32 {
    SYSTEM_TICKS.load(Ordering::Relaxed)
}

fn init_watchdog() {
    unsafe {

        let config = esp_idf_sys::esp_task_wdt_config_t {
            timeout_ms: WATCHDOG_TIMEOUT_SEC * 1000,
            idle_core_mask: 0,
            trigger_panic: true,
        };
        esp_idf_sys::esp_task_wdt_init(&config);
        esp_idf_sys::esp_task_wdt_add(core::ptr::null_mut());
    }
}

fn feed_watchdog() {
    unsafe {
        esp_idf_sys::esp_task_wdt_reset();
    }
}

fn format_battery<'a>(battery: &BatteryState, buf: &'a mut [u8; 32]) -> &'a str {
    let mut idx = 0;

    let prefix = b"Battery: ";
    buf[idx..idx + prefix.len()].copy_from_slice(prefix);
    idx += prefix.len();

    idx += write_u32_to_buf(battery.voltage_mv, &mut buf[idx..]);

    let suffix = b"mV (";
    buf[idx..idx + suffix.len()].copy_from_slice(suffix);
    idx += suffix.len();

    idx += write_u32_to_buf(battery.percentage as u32, &mut buf[idx..]);

    let end = b"%)";
    buf[idx..idx + end.len()].copy_from_slice(end);
    idx += end.len();

    core::str::from_utf8(&buf[..idx]).unwrap_or("Battery: ???")
}

fn write_u32_to_buf(val: u32, buf: &mut [u8]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut v = val;
    let mut digits = [0u8; 10];
    let mut count = 0;

    while v > 0 {
        digits[count] = b'0' + (v % 10) as u8;
        v /= 10;
        count += 1;
    }

    for i in 0..count {
        buf[i] = digits[count - 1 - i];
    }

    count
}

fn write_u32(uart: &UartDriver, val: u32) {
    let mut buf = [0u8; 10];
    let len = write_u32_to_buf(val, &mut buf);
    let _ = uart.write(&buf[..len]);
}

fn write_i16(uart: &UartDriver, val: i16) {
    if val < 0 {
        let _ = uart.write(b"-");
        write_u32(uart, (-val) as u32);
    } else {
        write_u32(uart, val as u32);
    }
}

fn write_hex8(uart: &UartDriver, val: u8) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let buf = [HEX[(val >> 4) as usize], HEX[(val & 0xF) as usize]];
    let _ = uart.write(&buf);
}

fn write_hex32(uart: &UartDriver, val: u32) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut buf = [0u8; 8];
    for i in 0..8 {
        buf[7 - i] = HEX[((val >> (i * 4)) & 0xF) as usize];
    }
    let _ = uart.write(&buf);
}

fn parse_u32_from_cmd(bytes: &[u8]) -> Option<u32> {
    let mut result: u32 = 0;
    let mut found_digit = false;

    for &b in bytes {
        if b >= b'0' && b <= b'9' {
            result = result.checked_mul(10)?.checked_add((b - b'0') as u32)?;
            found_digit = true;
        } else if found_digit {
            break;
        }
    }

    if found_digit { Some(result) } else { None }
}

fn parse_i8_from_cmd(bytes: &[u8]) -> Option<i8> {
    let mut result: i32 = 0;
    let mut negative = false;
    let mut found_digit = false;
    let mut started = false;

    for &b in bytes {
        if b == b'-' && !started {
            negative = true;
            started = true;
        } else if b >= b'0' && b <= b'9' {
            result = result.checked_mul(10)?.checked_add((b - b'0') as i32)?;
            found_digit = true;
            started = true;
        } else if found_digit {
            break;
        }
    }

    if found_digit {
        let val = if negative { -result } else { result };
        if val >= -128 && val <= 127 {
            Some(val as i8)
        } else {
            None
        }
    } else {
        None
    }
}

fn main() -> ! {

    esp_idf_sys::link_patches();

    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("========================================");
    log::info!("  LunarCore Mesh Firmware v1.0.0");
    log::info!("  Pure Rust Cryptography Stack");
    log::info!("  Cypherpunk / Lunarpunk Design");
    log::info!("========================================");

    run_lunarcore();
}

fn run_lunarcore() -> ! {

    let identity = NodeIdentity::from_hardware();
    log::info!("[INIT] Node ID: {:08X}", identity.node_id);

    let peripherals = Peripherals::take().unwrap();

    let mut led_pin = PinDriver::output(peripherals.pins.gpio35).unwrap();
    led_pin.set_low().unwrap();
    let mut vext_pin = PinDriver::output(peripherals.pins.gpio36).unwrap();
    vext_pin.set_low().unwrap();
    drop(vext_pin);
    log::info!("[INIT] GPIO OK");

    let mut oled_rst = PinDriver::output(peripherals.pins.gpio21).unwrap();
    oled_rst.set_low().unwrap();
    FreeRtos::delay_ms(10);
    oled_rst.set_high().unwrap();
    FreeRtos::delay_ms(10);
    let i2c_config = I2cConfig::new().baudrate(Hertz(400_000));
    let i2c = I2cDriver::new(
        peripherals.i2c0,
        peripherals.pins.gpio17,
        peripherals.pins.gpio18,
        &i2c_config,
    ).unwrap();
    let mut status_display = StatusDisplay::new(i2c);
    let _ = status_display.init();
    log::info!("[INIT] OLED OK");

    let _ = status_display.boot_animation(&mut |ms| FreeRtos::delay_ms(ms));

    let spi_config = esp_idf_hal::spi::config::Config::new()
        .baudrate(Hertz(8_000_000))
        .data_mode(embedded_hal::spi::MODE_0);
    let spi = SpiDeviceDriver::new_single(
        peripherals.spi2,
        peripherals.pins.gpio9,
        peripherals.pins.gpio10,
        Some(peripherals.pins.gpio11),
        Option::<Gpio0>::None,
        &SpiDriverConfig::default(),
        &spi_config,
    ).unwrap();
    let nss = PinDriver::output(peripherals.pins.gpio8).unwrap();
    let reset = PinDriver::output(peripherals.pins.gpio12).unwrap();
    let busy = PinDriver::input(peripherals.pins.gpio13).unwrap();
    let mut dio1 = PinDriver::input(peripherals.pins.gpio14).unwrap();
    dio1.set_pull(Pull::Down).unwrap();
    log::info!("[INIT] SPI OK");

    unsafe {
        dio1.subscribe(dio1_isr).unwrap();
    }
    dio1.enable_interrupt().unwrap();

    let mut radio = Sx1262::new(spi, nss, reset, busy, dio1);
    match radio.init() {
        Ok(()) => log::info!("[INIT] SX1262 OK"),
        Err(e) => log::error!("[INIT] SX1262 FAILED: {:?}", e),
    }

    let mut lunarcore = LunarCore::new(radio, identity);
    log::info!("[INIT] LunarCore OK");

    match lunarcore.ble.init("LunarCore") {
        Ok(()) => {
            log::info!("[INIT] BLE OK");
            let _ = lunarcore.ble.start_advertising();
        }
        Err(e) => log::error!("[INIT] BLE FAILED: {:?}", e),
    }

    let uart_config = esp_idf_hal::uart::config::Config::default()
        .baudrate(Hertz(BAUD_RATE));
    let uart = UartDriver::new(
        peripherals.uart0,
        peripherals.pins.gpio43,
        peripherals.pins.gpio44,
        Option::<Gpio0>::None,
        Option::<Gpio0>::None,
        &uart_config,
    ).unwrap();
    log::info!("[INIT] UART OK");

    init_watchdog();

    let adc1 = AdcDriver::new(peripherals.adc1).unwrap();
    let adc_config = AdcChannelConfig {
        attenuation: DB_11,
        ..Default::default()
    };
    let mut battery_channel = AdcChannelDriver::new(&adc1, peripherals.pins.gpio1, &adc_config).unwrap();
    log::info!("[INIT] ADC OK");

    log::info!("========================================");
    log::info!("  Protocols: MeshCore, Meshtastic, KISS");
    log::info!("  Waiting for protocol detection...");
    log::info!("========================================");

    let mut last_second = 0u32;
    let mut battery_check_interval = 0u32;

    loop {
        let now = millis();

        feed_watchdog();

        if DIO1_TRIGGERED.load(Ordering::Acquire) {
            lunarcore.handle_dio1_interrupt();
        }

        lunarcore.process_radio_events();

        let mut byte = [0u8; 1];
        while uart.read(&mut byte, 0).unwrap_or(0) > 0 {
            lunarcore.process_serial_byte(byte[0], &uart);
            LAST_ACTIVITY.store(now, Ordering::Relaxed);
        }

        lunarcore.check_rx(&uart);

        if lunarcore.led.update(now) {
            if lunarcore.led.is_on {
                let _ = led_pin.set_high();
            } else {
                let _ = led_pin.set_low();
            }
        }

        if now.wrapping_sub(battery_check_interval) >= 10_000 {
            battery_check_interval = now;
            if let Ok(adc_value) = adc1.read(&mut battery_channel) {
                lunarcore.update_battery(adc_value as u32);
            }
        }

        let current_second = now / 1000;
        if current_second > last_second {
            last_second = current_second;
            lunarcore.stats.uptime_seconds = current_second;

            if current_second % 60 == 0 {
                log::info!("Uptime: {}s, RX: {}, TX: {}",
                    current_second,
                    lunarcore.stats.rx_packets,
                    lunarcore.stats.tx_packets);
            }
        }

        FreeRtos::delay_ms(1);
    }
}
