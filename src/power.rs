pub const MIN_DEEP_SLEEP_US: u64 = 1_000;

pub const MAX_DEEP_SLEEP_US: u64 = 86_400_000_000;

pub const DEFAULT_LIGHT_SLEEP_MS: u32 = 100;

pub const LOW_BATTERY_THRESHOLD_MV: u32 = 3400;

pub const CRITICAL_BATTERY_THRESHOLD_MV: u32 = 3200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerMode {

    Performance,

    Balanced,

    LowPower,

    UltraLow,
}

impl Default for PowerMode {
    fn default() -> Self {
        PowerMode::Balanced
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeSources(pub u32);

impl WakeSources {

    pub const NONE: Self = Self(0);

    pub const TIMER: Self = Self(1 << 0);

    pub const GPIO: Self = Self(1 << 1);

    pub const UART: Self = Self(1 << 2);

    pub const TOUCH: Self = Self(1 << 3);

    pub const ULP: Self = Self(1 << 4);

    pub const BLE: Self = Self(1 << 5);

    pub const WIFI: Self = Self(1 << 6);

    pub const EXT0: Self = Self(1 << 7);

    pub const EXT1: Self = Self(1 << 8);

    pub const ALL: Self = Self(0x1FF);

    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn has(self, source: Self) -> bool {
        (self.0 & source.0) != 0
    }
}

impl core::ops::BitOr for WakeSources {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeCause {

    PowerOn,

    Timer,

    Gpio(u8),

    Uart,

    Touch,

    Ulp,

    Ble,

    Wifi,

    Ext0,

    Ext1,

    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub struct GpioWakeConfig {

    pub pin: u8,

    pub level_high: bool,
}

pub struct PowerManager {

    mode: PowerMode,

    light_sleep_wake: WakeSources,

    deep_sleep_wake: WakeSources,

    gpio_wake_pins: [Option<GpioWakeConfig>; 8],

    cpu_freq_mhz: u32,

    last_wake_cause: WakeCause,

    total_sleep_us: u64,

    sleep_count: u32,
}

impl PowerManager {

    pub const fn new() -> Self {
        Self {
            mode: PowerMode::Balanced,
            light_sleep_wake: WakeSources::TIMER.or(WakeSources::GPIO).or(WakeSources::UART),
            deep_sleep_wake: WakeSources::TIMER.or(WakeSources::GPIO),
            gpio_wake_pins: [None; 8],
            cpu_freq_mhz: 240,
            last_wake_cause: WakeCause::PowerOn,
            total_sleep_us: 0,
            sleep_count: 0,
        }
    }

    pub fn init(&mut self) -> Result<(), PowerError> {

        self.last_wake_cause = self.read_wake_cause();

        self.apply_mode()?;

        Ok(())
    }

    pub fn set_mode(&mut self, mode: PowerMode) -> Result<(), PowerError> {
        self.mode = mode;
        self.apply_mode()
    }

    fn apply_mode(&mut self) -> Result<(), PowerError> {
        let (cpu_freq, wifi_ps, bt_power) = match self.mode {
            PowerMode::Performance => (240, false, true),
            PowerMode::Balanced => (160, true, true),
            PowerMode::LowPower => (80, true, false),
            PowerMode::UltraLow => (40, true, false),
        };

        self.set_cpu_frequency(cpu_freq)?;

        if wifi_ps {
            self.enable_wifi_power_save();
        } else {
            self.disable_wifi_power_save();
        }

        Ok(())
    }

    pub fn set_cpu_frequency(&mut self, mhz: u32) -> Result<(), PowerError> {

        match mhz {
            240 | 160 | 80 | 40 | 20 | 10 => {},
            _ => return Err(PowerError::InvalidFrequency),
        };

        unsafe {
            let pm_config = esp_idf_sys::esp_pm_config_esp32s3_t {
                max_freq_mhz: mhz as i32,
                min_freq_mhz: 10,
                light_sleep_enable: false,
            };

            let ret = esp_idf_sys::esp_pm_configure(&pm_config as *const _ as *const core::ffi::c_void);
            if ret != 0 {
                return Err(PowerError::ConfigFailed);
            }
        }

        self.cpu_freq_mhz = mhz;
        Ok(())
    }

    pub fn configure_gpio_wake(&mut self, config: GpioWakeConfig) -> Result<(), PowerError> {

        for slot in &mut self.gpio_wake_pins {
            if slot.is_none() || slot.as_ref().map(|c| c.pin) == Some(config.pin) {
                *slot = Some(config);
                return Ok(());
            }
        }
        Err(PowerError::TooManyWakePins)
    }

    pub fn light_sleep(&mut self, duration_ms: u32) -> Result<WakeCause, PowerError> {
        if duration_ms == 0 {
            return Err(PowerError::InvalidDuration);
        }

        let duration_us = duration_ms as u64 * 1000;

        unsafe {

            if self.light_sleep_wake.has(WakeSources::TIMER) {
                esp_idf_sys::esp_sleep_enable_timer_wakeup(duration_us);
            }

            if self.light_sleep_wake.has(WakeSources::UART) {

                esp_idf_sys::esp_sleep_enable_uart_wakeup(0);
            }

            if self.light_sleep_wake.has(WakeSources::GPIO) {
                self.configure_gpio_wake_internal()?;
            }

            let ret = esp_idf_sys::esp_light_sleep_start();
            if ret != 0 {
                return Err(PowerError::SleepFailed);
            }
        }

        self.sleep_count += 1;
        self.total_sleep_us += duration_us;

        let cause = self.read_wake_cause();
        self.last_wake_cause = cause;
        Ok(cause)
    }

    pub fn deep_sleep(&mut self, duration_us: u64) -> ! {
        if duration_us < MIN_DEEP_SLEEP_US {

            unsafe {
                esp_idf_sys::esp_sleep_enable_timer_wakeup(MIN_DEEP_SLEEP_US);
            }
        } else if duration_us > MAX_DEEP_SLEEP_US {
            unsafe {
                esp_idf_sys::esp_sleep_enable_timer_wakeup(MAX_DEEP_SLEEP_US);
            }
        } else {
            unsafe {
                esp_idf_sys::esp_sleep_enable_timer_wakeup(duration_us);
            }
        }

        if self.deep_sleep_wake.has(WakeSources::GPIO) {
            let _ = self.configure_gpio_wake_internal();
        }

        unsafe {
            esp_idf_sys::esp_deep_sleep_start();
        }

        loop {
            core::hint::spin_loop();
        }
    }

    fn configure_gpio_wake_internal(&self) -> Result<(), PowerError> {
        unsafe {
            let mut mask: u64 = 0;
            let mut mode = esp_idf_sys::esp_sleep_ext1_wakeup_mode_t_ESP_EXT1_WAKEUP_ANY_HIGH;

            for config in &self.gpio_wake_pins {
                if let Some(cfg) = config {
                    if cfg.pin < 64 {
                        mask |= 1u64 << cfg.pin;
                        if !cfg.level_high {
                            mode = esp_idf_sys::esp_sleep_ext1_wakeup_mode_t_ESP_EXT1_WAKEUP_ALL_LOW;
                        }
                    }
                }
            }

            if mask != 0 {
                esp_idf_sys::esp_sleep_enable_ext1_wakeup(mask, mode);
            }
        }
        Ok(())
    }

    fn read_wake_cause(&self) -> WakeCause {
        unsafe {
            let cause = esp_idf_sys::esp_sleep_get_wakeup_cause();
            match cause {
                esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UNDEFINED => WakeCause::PowerOn,
                esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_TIMER => WakeCause::Timer,
                esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT0 => WakeCause::Ext0,
                esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT1 => {

                    let gpio_mask = esp_idf_sys::esp_sleep_get_ext1_wakeup_status();
                    let gpio = gpio_mask.trailing_zeros() as u8;
                    WakeCause::Gpio(gpio)
                }
                esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_TOUCHPAD => WakeCause::Touch,
                esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_ULP => WakeCause::Ulp,
                esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_GPIO => {
                    WakeCause::Gpio(0)
                }
                esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UART => WakeCause::Uart,
                esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_WIFI => WakeCause::Wifi,
                esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_BT => WakeCause::Ble,
                _ => WakeCause::Unknown,
            }
        }
    }

    fn enable_wifi_power_save(&self) {
        unsafe {
            esp_idf_sys::esp_wifi_set_ps(esp_idf_sys::wifi_ps_type_t_WIFI_PS_MIN_MODEM);
        }
    }

    fn disable_wifi_power_save(&self) {
        unsafe {
            esp_idf_sys::esp_wifi_set_ps(esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE);
        }
    }

    pub fn mode(&self) -> PowerMode {
        self.mode
    }

    pub fn last_wake_cause(&self) -> WakeCause {
        self.last_wake_cause
    }

    pub fn total_sleep_us(&self) -> u64 {
        self.total_sleep_us
    }

    pub fn sleep_count(&self) -> u32 {
        self.sleep_count
    }

    pub fn cpu_freq_mhz(&self) -> u32 {
        self.cpu_freq_mhz
    }

    pub fn is_battery_low(voltage_mv: u32) -> bool {
        voltage_mv < LOW_BATTERY_THRESHOLD_MV
    }

    pub fn is_battery_critical(voltage_mv: u32) -> bool {
        voltage_mv < CRITICAL_BATTERY_THRESHOLD_MV
    }

    pub fn set_rtc_data(&self, slot: u8, value: u32) {
        if slot >= 8 {
            return;
        }
        unsafe {

            let rtc_mem = (0x50000000 + slot as u32 * 4) as *mut u32;
            core::ptr::write_volatile(rtc_mem, value);
        }
    }

    pub fn get_rtc_data(&self, slot: u8) -> u32 {
        if slot >= 8 {
            return 0;
        }
        unsafe {
            let rtc_mem = (0x50000000 + slot as u32 * 4) as *const u32;
            core::ptr::read_volatile(rtc_mem)
        }
    }
}

impl Default for PowerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerError {

    InvalidFrequency,

    ConfigFailed,

    InvalidDuration,

    SleepFailed,

    TooManyWakePins,
}
