use embedded_hal::spi::SpiDevice;
use embedded_hal::digital::{InputPin, OutputPin};
use esp_idf_hal::delay::FreeRtos;


#[allow(dead_code)]
mod opcode {

    pub const SET_SLEEP: u8 = 0x84;
    pub const SET_STANDBY: u8 = 0x80;
    pub const SET_FS: u8 = 0xC1;
    pub const SET_TX: u8 = 0x83;
    pub const SET_RX: u8 = 0x82;
    pub const STOP_TIMER_ON_PREAMBLE: u8 = 0x9F;
    pub const SET_RX_DUTY_CYCLE: u8 = 0x94;
    pub const SET_CAD: u8 = 0xC5;
    pub const SET_TX_CONTINUOUS_WAVE: u8 = 0xD1;
    pub const SET_TX_INFINITE_PREAMBLE: u8 = 0xD2;
    pub const SET_REGULATOR_MODE: u8 = 0x96;
    pub const CALIBRATE: u8 = 0x89;
    pub const CALIBRATE_IMAGE: u8 = 0x98;
    pub const SET_PA_CONFIG: u8 = 0x95;
    pub const SET_RX_TX_FALLBACK_MODE: u8 = 0x93;


    pub const WRITE_REGISTER: u8 = 0x0D;
    pub const READ_REGISTER: u8 = 0x1D;
    pub const WRITE_BUFFER: u8 = 0x0E;
    pub const READ_BUFFER: u8 = 0x1E;


    pub const SET_DIO_IRQ_PARAMS: u8 = 0x08;
    pub const GET_IRQ_STATUS: u8 = 0x12;
    pub const CLEAR_IRQ_STATUS: u8 = 0x02;
    pub const SET_DIO2_AS_RF_SWITCH_CTRL: u8 = 0x9D;
    pub const SET_DIO3_AS_TCXO_CTRL: u8 = 0x97;


    pub const SET_RF_FREQUENCY: u8 = 0x86;
    pub const SET_PACKET_TYPE: u8 = 0x8A;
    pub const GET_PACKET_TYPE: u8 = 0x11;
    pub const SET_TX_PARAMS: u8 = 0x8E;
    pub const SET_MODULATION_PARAMS: u8 = 0x8B;
    pub const SET_PACKET_PARAMS: u8 = 0x8C;
    pub const SET_CAD_PARAMS: u8 = 0x88;
    pub const SET_BUFFER_BASE_ADDRESS: u8 = 0x8F;
    pub const SET_LORA_SYMB_NUM_TIMEOUT: u8 = 0xA0;


    pub const GET_STATUS: u8 = 0xC0;
    pub const GET_RX_BUFFER_STATUS: u8 = 0x13;
    pub const GET_PACKET_STATUS: u8 = 0x14;
    pub const GET_RSSI_INST: u8 = 0x15;
    pub const GET_STATS: u8 = 0x10;
    pub const RESET_STATS: u8 = 0x00;
    pub const GET_DEVICE_ERRORS: u8 = 0x17;
    pub const CLEAR_DEVICE_ERRORS: u8 = 0x07;
}


#[allow(dead_code)]
mod register {
    pub const WHITENING_INITIAL_MSB: u16 = 0x06B8;
    pub const WHITENING_INITIAL_LSB: u16 = 0x06B9;
    pub const CRC_INITIAL_MSB: u16 = 0x06BC;
    pub const CRC_INITIAL_LSB: u16 = 0x06BD;
    pub const CRC_POLYNOMIAL_MSB: u16 = 0x06BE;
    pub const CRC_POLYNOMIAL_LSB: u16 = 0x06BF;
    pub const SYNC_WORD_0: u16 = 0x06C0;
    pub const SYNC_WORD_1: u16 = 0x06C1;
    pub const NODE_ADDRESS: u16 = 0x06CD;
    pub const BROADCAST_ADDRESS: u16 = 0x06CE;
    pub const LORA_SYNC_WORD_MSB: u16 = 0x0740;
    pub const LORA_SYNC_WORD_LSB: u16 = 0x0741;
    pub const RANDOM_NUMBER_0: u16 = 0x0819;
    pub const RANDOM_NUMBER_1: u16 = 0x081A;
    pub const RANDOM_NUMBER_2: u16 = 0x081B;
    pub const RANDOM_NUMBER_3: u16 = 0x081C;
    pub const RX_GAIN: u16 = 0x08AC;
    pub const OCP_CONFIGURATION: u16 = 0x08E7;
    pub const XTA_TRIM: u16 = 0x0911;
    pub const XTB_TRIM: u16 = 0x0912;
}


#[allow(dead_code)]
pub mod irq {
    pub const TX_DONE: u16 = 1 << 0;
    pub const RX_DONE: u16 = 1 << 1;
    pub const PREAMBLE_DETECTED: u16 = 1 << 2;
    pub const SYNC_WORD_VALID: u16 = 1 << 3;
    pub const HEADER_VALID: u16 = 1 << 4;
    pub const HEADER_ERR: u16 = 1 << 5;
    pub const CRC_ERR: u16 = 1 << 6;
    pub const CAD_DONE: u16 = 1 << 7;
    pub const CAD_DETECTED: u16 = 1 << 8;
    pub const TIMEOUT: u16 = 1 << 9;
    pub const ALL: u16 = 0x03FF;
}


#[derive(Debug, Clone)]
pub struct RadioConfig {

    pub frequency: u32,

    pub spreading_factor: u8,

    pub bandwidth: u8,

    pub coding_rate: u8,

    pub tx_power: i8,

    pub sync_word: u8,

    pub preamble_length: u16,

    pub crc_enabled: bool,

    pub implicit_header: bool,

    pub ldro: bool,
}

impl Default for RadioConfig {
    fn default() -> Self {
        Self {
            frequency: 915_000_000,
            spreading_factor: 9,
            bandwidth: 0x04,
            coding_rate: 1,
            tx_power: 14,
            sync_word: 0x12,
            preamble_length: 8,
            crc_enabled: true,
            implicit_header: false,
            ldro: false,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioState {
    Sleep,
    Standby,
    Tx,
    Rx,
    Cad,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioError {

    Spi,

    BusyTimeout,

    InvalidConfig,

    TxTimeout,

    RxTimeout,

    CrcError,

    BufferOverflow,
}


pub struct Sx1262<SPI, NSS, RESET, BUSY, DIO1> {
    spi: SPI,
    nss: NSS,
    reset: RESET,
    busy: BUSY,
    dio1: DIO1,

    pub config: RadioConfig,
    state: RadioState,
}

impl<SPI, NSS, RESET, BUSY, DIO1, E> Sx1262<SPI, NSS, RESET, BUSY, DIO1>
where
    SPI: SpiDevice<Error = E>,
    NSS: OutputPin,
    RESET: OutputPin,
    BUSY: InputPin,
    DIO1: InputPin,
{

    pub fn new(spi: SPI, nss: NSS, reset: RESET, busy: BUSY, dio1: DIO1) -> Self {
        Self {
            spi,
            nss,
            reset,
            busy,
            dio1,
            config: RadioConfig::default(),
            state: RadioState::Sleep,
        }
    }


    pub fn init(&mut self) -> Result<(), RadioError> {

        self.reset()?;


        self.wait_busy_extended()?;


        self.write_command(&[
            opcode::SET_DIO3_AS_TCXO_CTRL,
            0x02,
            0x00,
            0x01,
            0x40,
        ])?;


        self.delay_ms(10);
        self.wait_busy_extended()?;


        self.write_command(&[opcode::SET_STANDBY, 0x01])?;
        self.state = RadioState::Standby;
        self.wait_busy()?;


        self.write_command(&[opcode::SET_REGULATOR_MODE, 0x01])?;
        self.wait_busy()?;


        self.write_command(&[opcode::CALIBRATE, 0x7F])?;
        self.wait_busy_extended()?;


        self.clear_errors()?;


        self.write_command(&[
            opcode::CALIBRATE_IMAGE,
            0xE1,
            0xE9,
        ])?;
        self.wait_busy()?;


        self.write_command(&[opcode::SET_DIO2_AS_RF_SWITCH_CTRL, 0x01])?;


        self.write_command(&[opcode::SET_PACKET_TYPE, 0x01])?;


        self.configure(&self.config.clone())?;

        Ok(())
    }


    pub fn reset(&mut self) -> Result<(), RadioError> {

        let _ = self.reset.set_low();

        FreeRtos::delay_ms(1);

        let _ = self.reset.set_high();

        FreeRtos::delay_ms(10);
        Ok(())
    }


    fn wait_busy(&mut self) -> Result<(), RadioError> {

        for _ in 0..100 {

            match self.busy.is_high() {
                Ok(false) => return Ok(()),
                Ok(true) => {},
                Err(_) => {},
            }

            FreeRtos::delay_ms(1);
        }
        Err(RadioError::BusyTimeout)
    }


    fn wait_busy_extended(&mut self) -> Result<(), RadioError> {


        for _ in 0..500 {
            match self.busy.is_high() {
                Ok(false) => return Ok(()),
                Ok(true) => {},
                Err(_) => {},
            }

            FreeRtos::delay_ms(1);
        }
        Err(RadioError::BusyTimeout)
    }


    fn delay_ms(&self, ms: u32) {
        FreeRtos::delay_ms(ms);
    }


    fn write_command(&mut self, data: &[u8]) -> Result<(), RadioError> {
        self.wait_busy()?;
        let _ = self.nss.set_low();
        let result = self.spi.write(data);
        let _ = self.nss.set_high();
        result.map_err(|_| RadioError::Spi)
    }


    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), RadioError> {
        self.wait_busy()?;
        let _ = self.nss.set_low();
        let result = self.spi.transfer(rx, tx);
        let _ = self.nss.set_high();
        result.map_err(|_| RadioError::Spi)
    }


    pub fn set_standby(&mut self) -> Result<(), RadioError> {
        self.write_command(&[opcode::SET_STANDBY, 0x01])?;
        self.state = RadioState::Standby;
        Ok(())
    }


    pub fn configure(&mut self, config: &RadioConfig) -> Result<(), RadioError> {

        log::info!("[SX1262] ========== RADIO CONFIG ==========");
        log::info!("[SX1262] Freq: {} Hz, SF: {}, BW: {}, CR: {}",
            config.frequency, config.spreading_factor, config.bandwidth, config.coding_rate);
        log::info!("[SX1262] TX Power: {}, Sync: 0x{:02X}, Preamble: {}",
            config.tx_power, config.sync_word, config.preamble_length);
        log::info!("[SX1262] CRC: {}, ImplicitHdr: {}, LDRO: {}",
            config.crc_enabled, config.implicit_header, config.ldro);
        log::info!("[SX1262] ===================================");


        if config.spreading_factor < 7 || config.spreading_factor > 12 {
            return Err(RadioError::InvalidConfig);
        }
        if config.bandwidth > 6 {
            return Err(RadioError::InvalidConfig);
        }


        let freq_reg = ((config.frequency as u64 * (1 << 25)) / 32_000_000) as u32;
        self.write_command(&[
            opcode::SET_RF_FREQUENCY,
            (freq_reg >> 24) as u8,
            (freq_reg >> 16) as u8,
            (freq_reg >> 8) as u8,
            freq_reg as u8,
        ])?;


        self.write_command(&[
            opcode::SET_PA_CONFIG,
            0x04,
            0x07,
            0x00,
            0x01,
        ])?;


        let power = config.tx_power.max(-9).min(22) as u8;
        self.write_command(&[
            opcode::SET_TX_PARAMS,
            power.wrapping_add(9),
            0x04,
        ])?;


        let bw_hz: u32 = match config.bandwidth {
            0x00 => 7_810,
            0x01 => 15_630,
            0x02 => 31_250,
            0x03 => 62_500,
            0x04 => 125_000,
            0x05 => 250_000,
            0x06 => 500_000,
            _ => 125_000,
        };
        let symbol_time_us = ((1u32 << config.spreading_factor) * 1_000_000) / bw_hz;
        let ldro_required = symbol_time_us > 16380;
        let ldro = if config.ldro || ldro_required { 0x01 } else { 0x00 };
        self.write_command(&[
            opcode::SET_MODULATION_PARAMS,
            config.spreading_factor,
            config.bandwidth,
            config.coding_rate,
            ldro,
        ])?;


        let header_type = if config.implicit_header { 0x01 } else { 0x00 };
        let crc_type = if config.crc_enabled { 0x01 } else { 0x00 };
        self.write_command(&[
            opcode::SET_PACKET_PARAMS,
            (config.preamble_length >> 8) as u8,
            config.preamble_length as u8,
            header_type,
            255,
            crc_type,
            0x00,
        ])?;


        let mut iq_config = self.read_register(0x0736)?;
        iq_config |= 0x04;
        self.write_register(0x0736, iq_config)?;


        let sync_msb = (config.sync_word & 0xF0) | 0x04;
        let sync_lsb = ((config.sync_word & 0x0F) << 4) | 0x04;
        log::info!("[SX1262] Sync word: input=0x{:02X} -> MSB=0x{:02X}, LSB=0x{:02X}",
            config.sync_word, sync_msb, sync_lsb);
        self.write_register(register::LORA_SYNC_WORD_MSB, sync_msb)?;
        self.write_register(register::LORA_SYNC_WORD_LSB, sync_lsb)?;


        self.write_command(&[opcode::SET_BUFFER_BASE_ADDRESS, 0x00, 0x00])?;


        self.write_command(&[
            opcode::SET_DIO_IRQ_PARAMS,
            (irq::ALL >> 8) as u8,
            irq::ALL as u8,
            (irq::ALL >> 8) as u8,
            irq::ALL as u8,
            0x00, 0x00,
            0x00, 0x00,
        ])?;


        self.write_register(register::RX_GAIN, 0x96)?;

        self.config = config.clone();
        Ok(())
    }


    fn write_register(&mut self, addr: u16, value: u8) -> Result<(), RadioError> {
        self.write_command(&[
            opcode::WRITE_REGISTER,
            (addr >> 8) as u8,
            addr as u8,
            value,
        ])
    }


    fn read_register(&mut self, addr: u16) -> Result<u8, RadioError> {
        let mut rx = [0u8; 5];
        self.transfer(
            &[
                opcode::READ_REGISTER,
                (addr >> 8) as u8,
                addr as u8,
                0x00,
            ],
            &mut rx,
        )?;
        Ok(rx[4])
    }


    pub fn transmit(&mut self, data: &[u8]) -> Result<(), RadioError> {
        if data.len() > 255 {
            return Err(RadioError::BufferOverflow);
        }


        self.set_standby()?;


        let mut cmd = heapless::Vec::<u8, 258>::new();
        let _ = cmd.push(opcode::WRITE_BUFFER);
        let _ = cmd.push(0x00);
        for &b in data {
            let _ = cmd.push(b);
        }
        self.write_command(&cmd)?;


        let header_type = if self.config.implicit_header { 0x01 } else { 0x00 };
        let crc_type = if self.config.crc_enabled { 0x01 } else { 0x00 };
        self.write_command(&[
            opcode::SET_PACKET_PARAMS,
            (self.config.preamble_length >> 8) as u8,
            self.config.preamble_length as u8,
            header_type,
            data.len() as u8,
            crc_type,
            0x00,
        ])?;


        self.write_command(&[opcode::CLEAR_IRQ_STATUS, 0x03, 0xFF])?;


        self.write_command(&[opcode::SET_TX, 0x00, 0x00, 0x00])?;
        self.state = RadioState::Tx;


        self.wait_tx_done()?;

        self.state = RadioState::Standby;
        Ok(())
    }


    fn wait_tx_done(&mut self) -> Result<(), RadioError> {

        for _ in 0..10000 {

            if self.dio1.is_high().unwrap_or(false) {
                let irq = self.get_irq_status()?;
                if irq & irq::TX_DONE != 0 {
                    self.write_command(&[opcode::CLEAR_IRQ_STATUS, 0x03, 0xFF])?;


                    self.start_rx(0)?;
                    return Ok(());
                }
            }

            FreeRtos::delay_ms(1);
        }
        self.set_standby()?;
        Err(RadioError::TxTimeout)
    }


    pub fn get_irq_status(&mut self) -> Result<u16, RadioError> {
        let mut rx = [0u8; 4];
        self.transfer(&[opcode::GET_IRQ_STATUS, 0, 0, 0], &mut rx)?;
        Ok(((rx[2] as u16) << 8) | (rx[3] as u16))
    }


    pub fn get_status(&mut self) -> Result<(u8, u8), RadioError> {
        let mut rx = [0u8; 2];
        self.transfer(&[opcode::GET_STATUS, 0], &mut rx)?;

        let status = rx[1];
        let chip_mode = (status >> 4) & 0x07;
        let cmd_status = (status >> 1) & 0x07;
        Ok((chip_mode, cmd_status))
    }


    pub fn get_errors(&mut self) -> Result<u16, RadioError> {
        let mut rx = [0u8; 4];
        self.transfer(&[opcode::GET_DEVICE_ERRORS, 0, 0, 0], &mut rx)?;
        Ok(((rx[2] as u16) << 8) | (rx[3] as u16))
    }


    pub fn clear_errors(&mut self) -> Result<(), RadioError> {
        self.write_command(&[opcode::CLEAR_DEVICE_ERRORS, 0x00, 0x00])
    }


    pub fn clear_irq(&mut self, flags: u16) -> Result<(), RadioError> {
        self.write_command(&[
            opcode::CLEAR_IRQ_STATUS,
            (flags >> 8) as u8,
            flags as u8,
        ])
    }


    pub fn start_rx(&mut self, timeout_ms: u32) -> Result<(), RadioError> {
        self.set_standby()?;


        self.write_command(&[opcode::CLEAR_IRQ_STATUS, 0x03, 0xFF])?;


        let timeout_ticks = if timeout_ms == 0 {
            0xFFFFFF
        } else {
            ((timeout_ms as u64 * 64) / 1000).min(0xFFFFFF) as u32
        };


        self.write_command(&[
            opcode::SET_RX,
            (timeout_ticks >> 16) as u8,
            (timeout_ticks >> 8) as u8,
            timeout_ticks as u8,
        ])?;

        self.state = RadioState::Rx;
        Ok(())
    }


    pub fn read_packet(&mut self) -> Result<(heapless::Vec<u8, 256>, i16, i8), RadioError> {

        let mut buf_status = [0u8; 4];
        self.transfer(&[opcode::GET_RX_BUFFER_STATUS, 0, 0, 0], &mut buf_status)?;
        let payload_len = buf_status[2];
        let start_offset = buf_status[3];

        if payload_len == 0 {
            return Err(RadioError::RxTimeout);
        }


        let mut pkt_status = [0u8; 5];
        self.transfer(&[opcode::GET_PACKET_STATUS, 0, 0, 0, 0], &mut pkt_status)?;
        let rssi = -(pkt_status[2] as i16 / 2);
        let snr = pkt_status[3] as i8 / 4;


        let mut data = heapless::Vec::<u8, 256>::new();
        let mut read_cmd = [0u8; 258];
        read_cmd[0] = opcode::READ_BUFFER;
        read_cmd[1] = start_offset;
        read_cmd[2] = 0;

        let len = payload_len as usize + 3;
        let mut rx_buf = [0u8; 258];
        self.transfer(&read_cmd[..len], &mut rx_buf[..len])?;

        for i in 0..payload_len as usize {
            let _ = data.push(rx_buf[3 + i]);
        }

        Ok((data, rssi, snr))
    }


    pub fn check_rx(&mut self) -> Result<Option<(heapless::Vec<u8, 256>, i16, i8)>, RadioError> {

        if !self.dio1.is_high().unwrap_or(false) {
            return Ok(None);
        }

        let irq = self.get_irq_status()?;

        if irq & irq::CRC_ERR != 0 {
            self.write_command(&[opcode::CLEAR_IRQ_STATUS, 0x03, 0xFF])?;
            return Err(RadioError::CrcError);
        }

        if irq & irq::TIMEOUT != 0 {
            self.write_command(&[opcode::CLEAR_IRQ_STATUS, 0x03, 0xFF])?;
            return Err(RadioError::RxTimeout);
        }

        if irq & irq::RX_DONE != 0 {

            let mut buf_status = [0u8; 4];
            self.transfer(&[opcode::GET_RX_BUFFER_STATUS, 0, 0, 0], &mut buf_status)?;
            let payload_len = buf_status[2];
            let start_offset = buf_status[3];


            let mut pkt_status = [0u8; 5];
            self.transfer(&[opcode::GET_PACKET_STATUS, 0, 0, 0, 0], &mut pkt_status)?;
            let rssi = -(pkt_status[2] as i16 / 2);
            let snr = pkt_status[3] as i8 / 4;


            let mut data = heapless::Vec::<u8, 256>::new();
            let mut read_cmd = [0u8; 258];
            read_cmd[0] = opcode::READ_BUFFER;
            read_cmd[1] = start_offset;
            read_cmd[2] = 0;

            let len = payload_len as usize + 3;
            let mut rx_buf = [0u8; 258];
            self.transfer(&read_cmd[..len], &mut rx_buf[..len])?;

            for i in 0..payload_len as usize {
                let _ = data.push(rx_buf[3 + i]);
            }


            self.write_command(&[opcode::CLEAR_IRQ_STATUS, 0x03, 0xFF])?;

            return Ok(Some((data, rssi, snr)));
        }

        Ok(None)
    }


    pub fn cad(&mut self) -> Result<bool, RadioError> {
        self.set_standby()?;


        self.write_command(&[
            opcode::SET_CAD_PARAMS,
            0x04,
            24,
            10,
            0x00,
            0x00, 0x00, 0x00,
        ])?;


        self.write_command(&[opcode::CLEAR_IRQ_STATUS, 0x03, 0xFF])?;


        self.write_command(&[opcode::SET_CAD])?;
        self.state = RadioState::Cad;


        for _ in 0..1000 {
            if self.dio1.is_high().unwrap_or(false) {
                let irq = self.get_irq_status()?;
                if irq & irq::CAD_DONE != 0 {
                    let detected = irq & irq::CAD_DETECTED != 0;
                    self.write_command(&[opcode::CLEAR_IRQ_STATUS, 0x03, 0xFF])?;
                    self.state = RadioState::Standby;
                    return Ok(detected);
                }
            }

            FreeRtos::delay_ms(1);
        }
        self.set_standby()?;
        Err(RadioError::BusyTimeout)
    }


    pub fn state(&self) -> RadioState {
        self.state
    }


    pub fn get_rssi(&mut self) -> Result<i16, RadioError> {
        let mut rx = [0u8; 3];
        self.transfer(&[opcode::GET_RSSI_INST, 0, 0], &mut rx)?;
        Ok(-(rx[2] as i16 / 2))
    }


    pub fn random(&mut self) -> Result<u32, RadioError> {

        self.start_rx(0)?;

        FreeRtos::delay_ms(10);
        self.set_standby()?;


        let mut random = 0u32;
        let mut rx = [0u8; 3];

        for (i, addr) in [
            register::RANDOM_NUMBER_0,
            register::RANDOM_NUMBER_1,
            register::RANDOM_NUMBER_2,
            register::RANDOM_NUMBER_3,
        ].iter().enumerate() {
            self.transfer(&[
                opcode::READ_REGISTER,
                (*addr >> 8) as u8,
                *addr as u8,
            ], &mut rx)?;
            random |= (rx[2] as u32) << (i * 8);
        }

        Ok(random)
    }
}
