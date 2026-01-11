use heapless::String;

pub const SSD1306_ADDR: u8 = 0x3C;

pub const DISPLAY_WIDTH: usize = 128;
pub const DISPLAY_HEIGHT: usize = 64;

pub const DISPLAY_PAGES: usize = DISPLAY_HEIGHT / 8;

pub const FRAMEBUFFER_SIZE: usize = DISPLAY_WIDTH * DISPLAY_PAGES;

const CMD_SET_CONTRAST: u8 = 0x81;
const CMD_DISPLAY_ALL_ON_RESUME: u8 = 0xA4;
const CMD_DISPLAY_ALL_ON: u8 = 0xA5;
const CMD_NORMAL_DISPLAY: u8 = 0xA6;
const CMD_INVERT_DISPLAY: u8 = 0xA7;
const CMD_DISPLAY_OFF: u8 = 0xAE;
const CMD_DISPLAY_ON: u8 = 0xAF;
const CMD_SET_DISPLAY_OFFSET: u8 = 0xD3;
const CMD_SET_COM_PINS: u8 = 0xDA;
const CMD_SET_VCOM_DETECT: u8 = 0xDB;
const CMD_SET_DISPLAY_CLOCK_DIV: u8 = 0xD5;
const CMD_SET_PRECHARGE: u8 = 0xD9;
const CMD_SET_MULTIPLEX: u8 = 0xA8;
const CMD_SET_LOW_COLUMN: u8 = 0x00;
const CMD_SET_HIGH_COLUMN: u8 = 0x10;
const CMD_SET_START_LINE: u8 = 0x40;
const CMD_MEMORY_MODE: u8 = 0x20;
const CMD_COLUMN_ADDR: u8 = 0x21;
const CMD_PAGE_ADDR: u8 = 0x22;
const CMD_COM_SCAN_INC: u8 = 0xC0;
const CMD_COM_SCAN_DEC: u8 = 0xC8;
const CMD_SEG_REMAP: u8 = 0xA0;
const CMD_CHARGE_PUMP: u8 = 0x8D;
const CMD_DEACTIVATE_SCROLL: u8 = 0x2E;

const CONTROL_CMD_SINGLE: u8 = 0x80;
const CONTROL_CMD_STREAM: u8 = 0x00;
const CONTROL_DATA_STREAM: u8 = 0x40;

static FONT_5X7: [u8; 320] = [

    0x00, 0x00, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x5F, 0x00, 0x00,

    0x00, 0x07, 0x00, 0x07, 0x00,

    0x14, 0x7F, 0x14, 0x7F, 0x14,

    0x24, 0x2A, 0x7F, 0x2A, 0x12,

    0x23, 0x13, 0x08, 0x64, 0x62,

    0x36, 0x49, 0x55, 0x22, 0x50,

    0x00, 0x05, 0x03, 0x00, 0x00,

    0x00, 0x1C, 0x22, 0x41, 0x00,

    0x00, 0x41, 0x22, 0x1C, 0x00,

    0x08, 0x2A, 0x1C, 0x2A, 0x08,

    0x08, 0x08, 0x3E, 0x08, 0x08,

    0x00, 0x50, 0x30, 0x00, 0x00,

    0x08, 0x08, 0x08, 0x08, 0x08,

    0x00, 0x60, 0x60, 0x00, 0x00,

    0x20, 0x10, 0x08, 0x04, 0x02,

    0x3E, 0x51, 0x49, 0x45, 0x3E,

    0x00, 0x42, 0x7F, 0x40, 0x00,

    0x42, 0x61, 0x51, 0x49, 0x46,

    0x21, 0x41, 0x45, 0x4B, 0x31,

    0x18, 0x14, 0x12, 0x7F, 0x10,

    0x27, 0x45, 0x45, 0x45, 0x39,

    0x3C, 0x4A, 0x49, 0x49, 0x30,

    0x01, 0x71, 0x09, 0x05, 0x03,

    0x36, 0x49, 0x49, 0x49, 0x36,

    0x06, 0x49, 0x49, 0x29, 0x1E,

    0x00, 0x36, 0x36, 0x00, 0x00,

    0x00, 0x56, 0x36, 0x00, 0x00,

    0x00, 0x08, 0x14, 0x22, 0x41,

    0x14, 0x14, 0x14, 0x14, 0x14,

    0x41, 0x22, 0x14, 0x08, 0x00,

    0x02, 0x01, 0x51, 0x09, 0x06,

    0x32, 0x49, 0x79, 0x41, 0x3E,

    0x7E, 0x11, 0x11, 0x11, 0x7E,

    0x7F, 0x49, 0x49, 0x49, 0x36,

    0x3E, 0x41, 0x41, 0x41, 0x22,

    0x7F, 0x41, 0x41, 0x22, 0x1C,

    0x7F, 0x49, 0x49, 0x49, 0x41,

    0x7F, 0x09, 0x09, 0x01, 0x01,

    0x3E, 0x41, 0x41, 0x51, 0x32,

    0x7F, 0x08, 0x08, 0x08, 0x7F,

    0x00, 0x41, 0x7F, 0x41, 0x00,

    0x20, 0x40, 0x41, 0x3F, 0x01,

    0x7F, 0x08, 0x14, 0x22, 0x41,

    0x7F, 0x40, 0x40, 0x40, 0x40,

    0x7F, 0x02, 0x04, 0x02, 0x7F,

    0x7F, 0x04, 0x08, 0x10, 0x7F,

    0x3E, 0x41, 0x41, 0x41, 0x3E,

    0x7F, 0x09, 0x09, 0x09, 0x06,

    0x3E, 0x41, 0x51, 0x21, 0x5E,

    0x7F, 0x09, 0x19, 0x29, 0x46,

    0x46, 0x49, 0x49, 0x49, 0x31,

    0x01, 0x01, 0x7F, 0x01, 0x01,

    0x3F, 0x40, 0x40, 0x40, 0x3F,

    0x1F, 0x20, 0x40, 0x20, 0x1F,

    0x7F, 0x20, 0x18, 0x20, 0x7F,

    0x63, 0x14, 0x08, 0x14, 0x63,

    0x03, 0x04, 0x78, 0x04, 0x03,

    0x61, 0x51, 0x49, 0x45, 0x43,

    0x00, 0x00, 0x7F, 0x41, 0x41,

    0x02, 0x04, 0x08, 0x10, 0x20,

    0x41, 0x41, 0x7F, 0x00, 0x00,

    0x04, 0x02, 0x01, 0x02, 0x04,

    0x40, 0x40, 0x40, 0x40, 0x40,
];

pub struct Display<I2C> {

    i2c: I2C,

    framebuffer: [u8; FRAMEBUFFER_SIZE],

    power_on: bool,

    inverted: bool,

    contrast: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayError {

    I2cError,

    InvalidCoordinates,

    BufferOverflow,
}

impl<I2C, E> Display<I2C>
where
    I2C: embedded_hal::i2c::I2c<Error = E>,
{

    pub fn new(i2c: I2C) -> Self {
        Self {
            i2c,
            framebuffer: [0u8; FRAMEBUFFER_SIZE],
            power_on: false,
            inverted: false,
            contrast: 0x7F,
        }
    }

    pub fn init(&mut self) -> Result<(), DisplayError> {

        let init_cmds: [u8; 26] = [
            CMD_DISPLAY_OFF,
            CMD_SET_DISPLAY_CLOCK_DIV, 0x80,
            CMD_SET_MULTIPLEX, 0x3F,
            CMD_SET_DISPLAY_OFFSET, 0x00,
            CMD_SET_START_LINE | 0x00,
            CMD_CHARGE_PUMP, 0x14,
            CMD_MEMORY_MODE, 0x00,
            CMD_SEG_REMAP | 0x01,
            CMD_COM_SCAN_DEC,
            CMD_SET_COM_PINS, 0x12,
            CMD_SET_CONTRAST, self.contrast,
            CMD_SET_PRECHARGE, 0xF1,
            CMD_SET_VCOM_DETECT, 0x40,
            CMD_DISPLAY_ALL_ON_RESUME,
            CMD_NORMAL_DISPLAY,
            CMD_DEACTIVATE_SCROLL,
            CMD_DISPLAY_ON,
        ];

        for cmd in init_cmds {
            self.write_command(cmd)?;
        }

        self.power_on = true;
        self.clear();
        self.flush()?;

        Ok(())
    }

    fn write_command(&mut self, cmd: u8) -> Result<(), DisplayError> {
        let buf = [CONTROL_CMD_SINGLE, cmd];
        self.i2c.write(SSD1306_ADDR, &buf).map_err(|_| DisplayError::I2cError)
    }

    fn write_commands(&mut self, cmds: &[u8]) -> Result<(), DisplayError> {
        for &cmd in cmds {
            self.write_command(cmd)?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), DisplayError> {

        self.write_commands(&[CMD_COLUMN_ADDR, 0, (DISPLAY_WIDTH - 1) as u8])?;

        self.write_commands(&[CMD_PAGE_ADDR, 0, (DISPLAY_PAGES - 1) as u8])?;

        const CHUNK_SIZE: usize = 128;
        for chunk in self.framebuffer.chunks(CHUNK_SIZE) {
            let mut buf = [0u8; CHUNK_SIZE + 1];
            buf[0] = CONTROL_DATA_STREAM;
            buf[1..1 + chunk.len()].copy_from_slice(chunk);
            self.i2c.write(SSD1306_ADDR, &buf[..1 + chunk.len()])
                .map_err(|_| DisplayError::I2cError)?;
        }

        Ok(())
    }

    pub fn clear(&mut self) {
        self.framebuffer.fill(0);
    }

    pub fn fill(&mut self) {
        self.framebuffer.fill(0xFF);
    }

    pub fn set_pixel(&mut self, x: usize, y: usize, on: bool) {
        if x >= DISPLAY_WIDTH || y >= DISPLAY_HEIGHT {
            return;
        }

        let page = y / 8;
        let bit = y % 8;
        let idx = page * DISPLAY_WIDTH + x;

        if on {
            self.framebuffer[idx] |= 1 << bit;
        } else {
            self.framebuffer[idx] &= !(1 << bit);
        }
    }

    pub fn get_pixel(&self, x: usize, y: usize) -> bool {
        if x >= DISPLAY_WIDTH || y >= DISPLAY_HEIGHT {
            return false;
        }

        let page = y / 8;
        let bit = y % 8;
        let idx = page * DISPLAY_WIDTH + x;

        (self.framebuffer[idx] >> bit) & 1 != 0
    }

    pub fn draw_hline(&mut self, x: usize, y: usize, width: usize, on: bool) {
        for dx in 0..width {
            self.set_pixel(x + dx, y, on);
        }
    }

    pub fn draw_vline(&mut self, x: usize, y: usize, height: usize, on: bool) {
        for dy in 0..height {
            self.set_pixel(x, y + dy, on);
        }
    }

    pub fn draw_rect(&mut self, x: usize, y: usize, width: usize, height: usize, on: bool) {
        self.draw_hline(x, y, width, on);
        self.draw_hline(x, y + height - 1, width, on);
        self.draw_vline(x, y, height, on);
        self.draw_vline(x + width - 1, y, height, on);
    }

    pub fn fill_rect(&mut self, x: usize, y: usize, width: usize, height: usize, on: bool) {
        for dy in 0..height {
            self.draw_hline(x, y + dy, width, on);
        }
    }

    pub fn draw_char(&mut self, x: usize, y: usize, c: char) -> usize {
        let c = c as u8;
        if c < 32 || c > 95 + 32 {
            return 0;
        }

        let idx = ((c - 32) as usize) * 5;
        if idx + 5 > FONT_5X7.len() {
            return 0;
        }

        for col in 0..5 {
            let bits = FONT_5X7[idx + col];
            for row in 0..7 {
                let on = (bits >> row) & 1 != 0;
                self.set_pixel(x + col, y + row, on);
            }
        }

        6
    }

    pub fn draw_text(&mut self, x: usize, y: usize, text: &str) {
        let mut cx = x;
        for c in text.chars() {
            if cx >= DISPLAY_WIDTH {
                break;
            }
            cx += self.draw_char(cx, y, c);
        }
    }

    pub fn draw_text_centered(&mut self, y: usize, text: &str) {
        let width = text.len() * 6;
        let x = if width < DISPLAY_WIDTH {
            (DISPLAY_WIDTH - width) / 2
        } else {
            0
        };
        self.draw_text(x, y, text);
    }

    pub fn set_contrast(&mut self, contrast: u8) -> Result<(), DisplayError> {
        self.contrast = contrast;
        self.write_commands(&[CMD_SET_CONTRAST, contrast])
    }

    pub fn power_on(&mut self) -> Result<(), DisplayError> {
        self.write_command(CMD_DISPLAY_ON)?;
        self.power_on = true;
        Ok(())
    }

    pub fn power_off(&mut self) -> Result<(), DisplayError> {
        self.write_command(CMD_DISPLAY_OFF)?;
        self.power_on = false;
        Ok(())
    }

    pub fn invert(&mut self, invert: bool) -> Result<(), DisplayError> {
        self.inverted = invert;
        if invert {
            self.write_command(CMD_INVERT_DISPLAY)
        } else {
            self.write_command(CMD_NORMAL_DISPLAY)
        }
    }

    pub fn is_on(&self) -> bool {
        self.power_on
    }

    pub fn framebuffer(&self) -> &[u8; FRAMEBUFFER_SIZE] {
        &self.framebuffer
    }

    pub fn framebuffer_mut(&mut self) -> &mut [u8; FRAMEBUFFER_SIZE] {
        &mut self.framebuffer
    }
}

pub struct StatusDisplay<I2C> {
    display: Display<I2C>,
}

pub struct StatusContent {

    pub protocol: &'static str,

    pub node_id: u32,

    pub battery_pct: u8,

    pub rx_count: u32,

    pub tx_count: u32,

    pub rssi: i16,

    pub connected: bool,
}

impl<I2C, E> StatusDisplay<I2C>
where
    I2C: embedded_hal::i2c::I2c<Error = E>,
{

    pub fn new(i2c: I2C) -> Self {
        Self {
            display: Display::new(i2c),
        }
    }

    pub fn init(&mut self) -> Result<(), DisplayError> {
        self.display.init()
    }

    pub fn show_splash(&mut self) -> Result<(), DisplayError> {
        self.display.clear();

        self.display.draw_rect(0, 0, DISPLAY_WIDTH, DISPLAY_HEIGHT, true);

        self.display.draw_text_centered(8, "LunarCore");
        self.display.draw_text_centered(18, "v1.0.0");

        self.display.draw_text_centered(32, "Unified Mesh");
        self.display.draw_text_centered(42, "Bridge Firmware");

        self.display.draw_text_centered(54, "MC | MT | RN");

        self.display.flush()
    }

    pub fn show_status(&mut self, status: &StatusContent) -> Result<(), DisplayError> {
        self.display.clear();

        self.display.draw_text(0, 0, status.protocol);

        let batt_str = format_battery(status.battery_pct);
        self.display.draw_text(DISPLAY_WIDTH - 24, 0, &batt_str);

        self.display.draw_hline(0, 9, DISPLAY_WIDTH, true);

        self.display.draw_text(0, 12, "ID:");
        let id_str = format_hex32(status.node_id);
        self.display.draw_text(24, 12, &id_str);

        self.display.draw_text(0, 22, "RX:");
        let rx_str = format_u32(status.rx_count);
        self.display.draw_text(24, 22, &rx_str);

        self.display.draw_text(64, 22, "TX:");
        let tx_str = format_u32(status.tx_count);
        self.display.draw_text(88, 22, &tx_str);

        self.display.draw_text(0, 32, "RSSI:");
        let rssi_str = format_i16(status.rssi);
        self.display.draw_text(36, 32, &rssi_str);
        self.display.draw_text(72, 32, "dBm");

        self.display.draw_text(0, 44, "Status:");
        if status.connected {
            self.display.draw_text(48, 44, "CONNECTED");
        } else {
            self.display.draw_text(48, 44, "WAITING");
        }

        self.display.draw_hline(0, 54, DISPLAY_WIDTH, true);

        self.display.draw_text_centered(56, "github.com/yours");

        self.display.flush()
    }

    pub fn show_error(&mut self, msg: &str) -> Result<(), DisplayError> {
        self.display.clear();

        self.display.draw_text_centered(20, "ERROR");
        self.display.draw_hline(20, 30, DISPLAY_WIDTH - 40, true);
        self.display.draw_text_centered(36, msg);

        self.display.flush()
    }

    pub fn show_message(&mut self, line1: &str, line2: &str) -> Result<(), DisplayError> {
        self.display.clear();

        self.display.draw_text_centered(24, line1);
        self.display.draw_text_centered(36, line2);

        self.display.flush()
    }

    pub fn power_off(&mut self) -> Result<(), DisplayError> {
        self.display.power_off()
    }

    pub fn power_on(&mut self) -> Result<(), DisplayError> {
        self.display.power_on()
    }

    pub fn display(&mut self) -> &mut Display<I2C> {
        &mut self.display
    }
}

fn format_battery(pct: u8) -> String<4> {
    let mut s = String::new();
    if pct >= 100 {
        let _ = s.push_str("100");
    } else if pct >= 10 {
        let _ = s.push((b'0' + pct / 10) as char);
        let _ = s.push((b'0' + pct % 10) as char);
    } else {
        let _ = s.push((b'0' + pct) as char);
    }
    let _ = s.push('%');
    s
}

fn format_hex32(val: u32) -> String<8> {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut s = String::new();
    for i in (0..8).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        let _ = s.push(HEX[nibble] as char);
    }
    s
}

fn format_u32(val: u32) -> String<10> {
    let mut s = String::new();
    if val == 0 {
        let _ = s.push('0');
        return s;
    }

    let mut v = val;
    let mut digits = [0u8; 10];
    let mut count = 0;

    while v > 0 {
        digits[count] = (v % 10) as u8;
        v /= 10;
        count += 1;
    }

    for i in (0..count).rev() {
        let _ = s.push((b'0' + digits[i]) as char);
    }
    s
}

fn format_i16(val: i16) -> String<6> {
    let mut s = String::new();
    if val < 0 {
        let _ = s.push('-');
        let abs = (-(val as i32)) as u32;
        let formatted = format_u32(abs);
        let _ = s.push_str(&formatted);
    } else {
        let formatted = format_u32(val as u32);
        let _ = s.push_str(&formatted);
    }
    s
}

static MOON_PHASES: [[u8; 72]; 8] = [

    [
        0x00,0x00,0x00,0x00,0x00,0xE0,0xF0,0x38,0x1C,0x0C,0x06,0x06,
        0x06,0x06,0x0C,0x1C,0x38,0xF0,0xE0,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x1F,0x7F,0xE0,0x80,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x80,0xE0,0x7F,0x1F,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x07,0x0F,0x1C,0x38,0x30,0x60,0x60,
        0x60,0x60,0x30,0x38,0x1C,0x0F,0x07,0x00,0x00,0x00,0x00,0x00,
    ],

    [
        0x00,0x00,0x00,0x00,0x00,0xE0,0xF0,0x38,0x1C,0x0C,0x06,0x06,
        0x06,0x06,0x0C,0x1C,0x38,0xF0,0xE0,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x1F,0x7F,0xFF,0xFF,0xFE,0xFC,0xF8,0xF0,0xE0,
        0xC0,0x80,0x00,0x00,0x00,0x80,0xE0,0x7F,0x1F,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x07,0x0F,0x1C,0x38,0x31,0x63,0x63,
        0x63,0x63,0x31,0x38,0x1C,0x0F,0x07,0x00,0x00,0x00,0x00,0x00,
    ],

    [
        0x00,0x00,0x00,0x00,0x00,0xE0,0xF0,0x38,0x1C,0x0C,0x06,0x06,
        0xFE,0xFE,0xFC,0xFC,0xF8,0xF0,0xE0,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x1F,0x7F,0xFF,0xFF,0xFE,0xFC,0xF8,0xF0,0xE0,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F,0x1F,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x07,0x0F,0x1C,0x38,0x30,0x60,0x60,
        0x7F,0x7F,0x3F,0x3F,0x1F,0x0F,0x07,0x00,0x00,0x00,0x00,0x00,
    ],

    [
        0x00,0x00,0x00,0x00,0x00,0xE0,0xF0,0xF8,0xFC,0xFC,0xFE,0xFE,
        0xFE,0xFE,0xFC,0xFC,0xF8,0xF0,0xE0,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x1F,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F,0x1F,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x07,0x0F,0x1F,0x3F,0x3F,0x7F,0x7F,
        0x7F,0x7F,0x3F,0x3F,0x1F,0x0F,0x07,0x00,0x00,0x00,0x00,0x00,
    ],

    [
        0x00,0x00,0x00,0x00,0x00,0xE0,0xF0,0xF8,0xFC,0xFC,0xFE,0xFE,
        0xFE,0xFE,0xFC,0xFC,0xF8,0xF0,0xE0,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x1F,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F,0x1F,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x07,0x0F,0x1F,0x3F,0x3F,0x7F,0x7F,
        0x7F,0x7F,0x3F,0x3F,0x1F,0x0F,0x07,0x00,0x00,0x00,0x00,0x00,
    ],

    [
        0x00,0x00,0x00,0x00,0x00,0xE0,0xF0,0xF8,0xFC,0xFC,0xFE,0xFE,
        0xFE,0xFE,0xFC,0xFC,0xF8,0xF0,0xE0,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x1F,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F,0x1F,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x07,0x0F,0x1F,0x3F,0x3F,0x7F,0x7F,
        0x7F,0x7F,0x3F,0x3F,0x1F,0x0F,0x07,0x00,0x00,0x00,0x00,0x00,
    ],

    [
        0x00,0x00,0x00,0x00,0x00,0xE0,0xF0,0xF8,0xFC,0xFC,0xFE,0xFE,
        0x06,0x06,0x0C,0x1C,0x38,0xF0,0xE0,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x1F,0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x00,0x00,0x00,0x00,0x00,0x80,0xE0,0x7F,0x1F,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x07,0x0F,0x1F,0x3F,0x3F,0x7F,0x7F,
        0x60,0x60,0x30,0x38,0x1C,0x0F,0x07,0x00,0x00,0x00,0x00,0x00,
    ],

    [
        0x00,0x00,0x00,0x00,0x00,0xE0,0xF0,0xF8,0xFC,0xFC,0xFE,0xFE,
        0x06,0x06,0x0C,0x1C,0x38,0xF0,0xE0,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x1F,0x7F,0xFF,0xFF,0x07,0x03,0x01,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x80,0xE0,0x7F,0x1F,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x07,0x0F,0x1F,0x3F,0x3F,0x7F,0x7F,
        0x60,0x60,0x30,0x38,0x1C,0x0F,0x07,0x00,0x00,0x00,0x00,0x00,
    ],
];

static YOURS_FACE: [u8; 128] = [
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0xE0,0xF0,0xF8,0xF8,0xF8,0xFC,0xFC,0xFC,0xFC,0xFC,0xFC,0xF8,0xF8,0xF0,0xF0,0xE0,0xE0,0xE0,0xC0,0x80,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0xFF,0xFF,0xFF,0xFF,0xFF,0xEF,0xE7,0xE7,0xE7,0xC7,0xC7,0xC7,0xC7,0xC7,0xFF,0xFF,0xFF,0xFF,0x0F,0x07,0x03,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x0F,0x0F,0x7F,0xFF,0xFD,0xF9,0xC1,0xC1,0xDE,0xFE,0xF0,0xFF,0xFF,0xFF,0xFF,0x7F,0x1F,0x07,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x03,0x07,0x0F,0x1F,0x1F,0x1D,0x1D,0x0F,0x0F,0x03,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
];

impl<I2C, E> Display<I2C>
where
    I2C: embedded_hal::i2c::I2c<Error = E>,
{

    pub fn draw_bitmap_24x24(&mut self, x: usize, y: usize, bitmap: &[u8; 72]) {
        for col in 0..24 {
            for page in 0..3 {
                let byte = bitmap[page * 24 + col];
                for bit in 0..8 {
                    let px_y = y + page * 8 + bit;
                    let px_x = x + col;
                    if px_x < DISPLAY_WIDTH && px_y < DISPLAY_HEIGHT {
                        self.set_pixel(px_x, px_y, (byte >> bit) & 1 != 0);
                    }
                }
            }
        }
    }

    pub fn draw_bitmap_32x32(&mut self, x: usize, y: usize, bitmap: &[u8; 128]) {
        for col in 0..32 {
            for page in 0..4 {
                let byte = bitmap[page * 32 + col];
                for bit in 0..8 {
                    let px_y = y + page * 8 + bit;
                    let px_x = x + col;
                    if px_x < DISPLAY_WIDTH && px_y < DISPLAY_HEIGHT {
                        self.set_pixel(px_x, px_y, (byte >> bit) & 1 != 0);
                    }
                }
            }
        }
    }
}

impl<I2C, E> StatusDisplay<I2C>
where
    I2C: embedded_hal::i2c::I2c<Error = E>,
{

    pub fn boot_animation(&mut self, delay_fn: &mut dyn FnMut(u32)) -> Result<(), DisplayError> {

        for cycle in 0..2 {
            for phase in 0..8 {
                self.display.clear();

                let moon_x = (DISPLAY_WIDTH - 24) / 2;
                let moon_y = 8;
                self.display.draw_bitmap_24x24(moon_x, moon_y, &MOON_PHASES[phase]);

                self.display.draw_text_centered(40, "LUNARCORE");

                let dots_x = (DISPLAY_WIDTH - 8 * 4) / 2;
                for i in 0..8 {
                    let on = i <= phase;
                    self.display.fill_rect(dots_x + i * 4, 54, 2, 2, on);
                }

                self.display.flush()?;

                let delay = if cycle == 1 { 120 } else { 80 };
                delay_fn(delay);
            }
        }

        self.show_branding()?;
        delay_fn(1500);

        Ok(())
    }

    pub fn show_branding(&mut self) -> Result<(), DisplayError> {
        self.display.clear();

        let logo_x = (DISPLAY_WIDTH - 32) / 2;
        let logo_y = 4;
        self.display.draw_bitmap_32x32(logo_x, logo_y, &YOURS_FACE);

        self.display.draw_text_centered(42, "[ YOURS ]");
        self.display.draw_text_centered(52, "x [ LUNARCORE ]");

        self.display.flush()
    }

    pub fn show_init_progress(&mut self, step: &str, progress: u8) -> Result<(), DisplayError> {
        self.display.clear();

        self.display.draw_text_centered(8, "INITIALIZING");

        self.display.draw_text_centered(24, step);

        let bar_width = 100;
        let bar_x = (DISPLAY_WIDTH - bar_width) / 2;
        let bar_y = 40;
        let filled = (bar_width as u32 * progress as u32 / 100) as usize;

        self.display.draw_rect(bar_x, bar_y, bar_width, 8, true);
        self.display.fill_rect(bar_x + 1, bar_y + 1, filled.saturating_sub(2), 6, true);

        let pct_str = format_battery(progress);
        self.display.draw_text_centered(52, &pct_str);

        self.display.flush()
    }
}
