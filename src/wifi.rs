use heapless::{String, Vec};
use crate::crypto::chacha20::ChaCha20;
use crate::crypto::sha256::Sha256;
use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

pub const DEFAULT_TCP_PORT: u16 = 4000;

pub const MAX_TCP_CLIENTS: usize = 4;

pub const TCP_RX_BUFFER_SIZE: usize = 512;

pub const TCP_TX_BUFFER_SIZE: usize = 512;

pub const WIFI_CONNECT_TIMEOUT_SEC: u32 = 30;

pub const DEFAULT_AP_SSID: &str = "LunarCore";

pub const DEFAULT_AP_PASSWORD: &str = "lunarpunk";

pub const MAX_SSID_LEN: usize = 32;

pub const MAX_PASSWORD_LEN: usize = 64;

pub const AUTH_CHALLENGE_SIZE: usize = 32;

pub const AUTH_RESPONSE_SIZE: usize = 32;

pub const SESSION_KEY_SIZE: usize = 32;

pub const SESSION_NONCE_SIZE: usize = 12;

pub const AUTH_TIMEOUT_SEC: u32 = 10;

pub const MAX_AUTH_FAILURES: u8 = 3;

pub const AUTH_LOCKOUT_SEC: u32 = 300;

pub const CONN_RATE_LIMIT: u8 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiMode {

    Off,

    Ap,

    Sta,

    ApSta,
}

impl Default for WifiMode {
    fn default() -> Self {
        WifiMode::Off
    }
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {

    pub require_auth: bool,

    pub psk: [u8; 32],

    pub encrypt_traffic: bool,

    pub rate_limiting: bool,

    pub allow_external: bool,
}

impl Drop for SecurityConfig {
    fn drop(&mut self) {

        crate::crypto::secure_zero(&mut self.psk);
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_auth: true,
            psk: [0u8; 32],
            encrypt_traffic: true,
            rate_limiting: true,
            allow_external: false,
        }
    }
}

impl SecurityConfig {

    pub fn with_psk(psk: &[u8; 32]) -> Self {
        Self {
            require_auth: true,
            psk: *psk,
            encrypt_traffic: true,
            rate_limiting: true,
            allow_external: false,
        }
    }

    pub fn insecure() -> Self {
        Self {
            require_auth: false,
            psk: [0u8; 32],
            encrypt_traffic: false,
            rate_limiting: false,
            allow_external: true,
        }
    }

    pub fn is_psk_set(&self) -> bool {
        self.psk.iter().any(|&b| b != 0)
    }
}

#[derive(Debug, Clone)]
pub struct WifiConfig {

    pub mode: WifiMode,

    pub ap_ssid: String<MAX_SSID_LEN>,

    pub ap_password: String<MAX_PASSWORD_LEN>,

    pub ap_channel: u8,

    pub sta_ssid: String<MAX_SSID_LEN>,

    pub sta_password: String<MAX_PASSWORD_LEN>,

    pub tcp_port: u16,

    pub mdns_enabled: bool,

    pub mdns_hostname: String<32>,

    pub security: SecurityConfig,
}

impl Default for WifiConfig {
    fn default() -> Self {
        let mut ap_ssid = String::new();
        let _ = ap_ssid.push_str(DEFAULT_AP_SSID);

        let mut ap_password = String::new();
        let _ = ap_password.push_str(DEFAULT_AP_PASSWORD);

        let mut mdns_hostname = String::new();
        let _ = mdns_hostname.push_str("lunarcore");

        Self {
            mode: WifiMode::Off,
            ap_ssid,
            ap_password,
            ap_channel: 1,
            sta_ssid: String::new(),
            sta_password: String::new(),
            tcp_port: DEFAULT_TCP_PORT,
            mdns_enabled: true,
            mdns_hostname,
            security: SecurityConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkStatus {

    pub mode: WifiMode,

    pub sta_connected: bool,

    pub sta_ip: Option<Ipv4Addr>,

    pub ap_active: bool,

    pub ap_ip: Option<Ipv4Addr>,

    pub ap_client_count: u8,

    pub tcp_client_count: u8,

    pub rssi: i8,
}

impl Default for NetworkStatus {
    fn default() -> Self {
        Self {
            mode: WifiMode::Off,
            sta_connected: false,
            sta_ip: None,
            ap_active: false,
            ap_ip: None,
            ap_client_count: 0,
            tcp_client_count: 0,
            rssi: 0,
        }
    }
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {

    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;
    const BLOCK_SIZE: usize = 64;

    let mut k_pad = [0u8; BLOCK_SIZE];
    k_pad[..32].copy_from_slice(key);

    let mut inner_hasher = Sha256::new();
    let mut inner_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key[i] = k_pad[i] ^ IPAD;
    }
    inner_hasher.update(&inner_key);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    let mut outer_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_key[i] = k_pad[i] ^ OPAD;
    }
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

#[inline(never)]
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {

    None,

    ChallengeSent,

    Authenticated,

    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpClientState {

    Disconnected,

    Authenticating,

    Detecting,

    Connected,
}

pub struct SessionCrypto {

    pub key: [u8; SESSION_KEY_SIZE],

    pub nonce: [u8; SESSION_NONCE_SIZE],

    pub counter: u32,

    pub enabled: bool,
}

impl Drop for SessionCrypto {
    fn drop(&mut self) {

        self.clear();
    }
}

impl SessionCrypto {

    pub const fn new() -> Self {
        Self {
            key: [0u8; SESSION_KEY_SIZE],
            nonce: [0u8; SESSION_NONCE_SIZE],
            counter: 0,
            enabled: false,
        }
    }

    pub fn init(&mut self, key: &[u8; SESSION_KEY_SIZE], nonce: &[u8; SESSION_NONCE_SIZE]) {
        self.key.copy_from_slice(key);
        self.nonce.copy_from_slice(nonce);
        self.counter = 0;
        self.enabled = true;
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        if !self.enabled {
            return;
        }

        let counter_bytes = self.counter.to_le_bytes();
        self.nonce[0..4].copy_from_slice(&counter_bytes);

        let cipher = ChaCha20::new(&self.key, &self.nonce);
        cipher.encrypt(data);

        self.counter = self.counter.wrapping_add(1);
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {

        self.encrypt(data);
    }

    pub fn clear(&mut self) {

        for b in &mut self.key {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in &mut self.nonce {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        self.counter = 0;
        self.enabled = false;
    }
}

pub struct TcpClient {

    pub fd: i32,

    pub addr: SocketAddrV4,

    pub state: TcpClientState,

    pub auth_state: AuthState,

    pub auth_challenge: [u8; AUTH_CHALLENGE_SIZE],

    pub auth_failures: u8,

    pub auth_started: u32,

    pub session: SessionCrypto,

    pub protocol: u8,

    pub rx_buffer: Vec<u8, TCP_RX_BUFFER_SIZE>,

    pub tx_buffer: Vec<u8, TCP_TX_BUFFER_SIZE>,

    pub last_activity: u32,
}

impl TcpClient {

    pub const fn empty() -> Self {
        Self {
            fd: -1,
            addr: SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0),
            state: TcpClientState::Disconnected,
            auth_state: AuthState::None,
            auth_challenge: [0u8; AUTH_CHALLENGE_SIZE],
            auth_failures: 0,
            auth_started: 0,
            session: SessionCrypto::new(),
            protocol: 0,
            rx_buffer: Vec::new(),
            tx_buffer: Vec::new(),
            last_activity: 0,
        }
    }

    pub fn is_available(&self) -> bool {
        self.state == TcpClientState::Disconnected
    }

    pub fn is_authenticated(&self) -> bool {
        self.auth_state == AuthState::Authenticated || self.auth_state == AuthState::None
    }

    pub fn reset(&mut self) {
        self.fd = -1;
        self.state = TcpClientState::Disconnected;
        self.auth_state = AuthState::None;
        self.auth_challenge.fill(0);
        self.auth_failures = 0;
        self.auth_started = 0;
        self.session.clear();
        self.protocol = 0;
        self.rx_buffer.clear();
        self.tx_buffer.clear();
    }
}

pub struct WifiManager {

    pub config: WifiConfig,

    pub status: NetworkStatus,

    server_fd: i32,

    clients: [TcpClient; MAX_TCP_CLIENTS],

    initialized: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiError {

    NotInitialized,

    AlreadyInitialized,

    ConfigError,

    ConnectionFailed,

    Timeout,

    SocketError,

    NoClientSlots,

    BufferFull,

    AuthenticationFailed,

    NoPskConfigured,

    NotAuthenticated,

    RateLimited,
}

impl WifiManager {

    pub const fn new() -> Self {
        Self {
            config: WifiConfig {
                mode: WifiMode::Off,
                ap_ssid: String::new(),
                ap_password: String::new(),
                ap_channel: 1,
                sta_ssid: String::new(),
                sta_password: String::new(),
                tcp_port: DEFAULT_TCP_PORT,
                mdns_enabled: true,
                mdns_hostname: String::new(),
                security: SecurityConfig {
                    require_auth: true,
                    psk: [0u8; 32],
                    encrypt_traffic: true,
                    rate_limiting: true,
                    allow_external: false,
                },
            },
            status: NetworkStatus {
                mode: WifiMode::Off,
                sta_connected: false,
                sta_ip: None,
                ap_active: false,
                ap_ip: None,
                ap_client_count: 0,
                tcp_client_count: 0,
                rssi: 0,
            },
            server_fd: -1,
            clients: [
                TcpClient::empty(),
                TcpClient::empty(),
                TcpClient::empty(),
                TcpClient::empty(),
            ],
            initialized: false,
        }
    }

    pub fn set_psk(&mut self, psk: &[u8; 32]) {
        self.config.security.psk.copy_from_slice(psk);
    }

    pub fn is_auth_configured(&self) -> bool {
        !self.config.security.require_auth || self.config.security.is_psk_set()
    }

    pub fn init(&mut self, config: WifiConfig) -> Result<(), WifiError> {
        if self.initialized {
            return Err(WifiError::AlreadyInitialized);
        }

        self.config = config;

        unsafe {

            let ret = esp_idf_sys::nvs_flash_init();
            if ret != 0 && ret != esp_idf_sys::ESP_ERR_NVS_NO_FREE_PAGES as i32 {

                esp_idf_sys::nvs_flash_erase();
                esp_idf_sys::nvs_flash_init();
            }

            esp_idf_sys::esp_netif_init();

            esp_idf_sys::esp_event_loop_create_default();

            match self.config.mode {
                WifiMode::Off => {}
                WifiMode::Ap => {
                    esp_idf_sys::esp_netif_create_default_wifi_ap();
                }
                WifiMode::Sta => {
                    esp_idf_sys::esp_netif_create_default_wifi_sta();
                }
                WifiMode::ApSta => {
                    esp_idf_sys::esp_netif_create_default_wifi_ap();
                    esp_idf_sys::esp_netif_create_default_wifi_sta();
                }
            }

            let mut wifi_init_config = esp_idf_sys::wifi_init_config_t::default();
            esp_idf_sys::esp_wifi_init(&wifi_init_config);

            esp_idf_sys::esp_wifi_set_storage(esp_idf_sys::wifi_storage_t_WIFI_STORAGE_RAM);
        }

        self.initialized = true;
        Ok(())
    }

    pub fn start(&mut self) -> Result<(), WifiError> {
        if !self.initialized {
            return Err(WifiError::NotInitialized);
        }

        unsafe {
            match self.config.mode {
                WifiMode::Off => {
                    esp_idf_sys::esp_wifi_stop();
                }
                WifiMode::Ap => {
                    self.configure_ap()?;
                    esp_idf_sys::esp_wifi_set_mode(esp_idf_sys::wifi_mode_t_WIFI_MODE_AP);
                    esp_idf_sys::esp_wifi_start();
                    self.status.ap_active = true;
                    self.status.ap_ip = Some(Ipv4Addr::new(192, 168, 4, 1));
                }
                WifiMode::Sta => {
                    self.configure_sta()?;
                    esp_idf_sys::esp_wifi_set_mode(esp_idf_sys::wifi_mode_t_WIFI_MODE_STA);
                    esp_idf_sys::esp_wifi_start();
                    esp_idf_sys::esp_wifi_connect();
                }
                WifiMode::ApSta => {
                    self.configure_ap()?;
                    self.configure_sta()?;
                    esp_idf_sys::esp_wifi_set_mode(esp_idf_sys::wifi_mode_t_WIFI_MODE_APSTA);
                    esp_idf_sys::esp_wifi_start();
                    esp_idf_sys::esp_wifi_connect();
                    self.status.ap_active = true;
                    self.status.ap_ip = Some(Ipv4Addr::new(192, 168, 4, 1));
                }
            }
        }

        self.status.mode = self.config.mode;
        Ok(())
    }

    fn configure_ap(&self) -> Result<(), WifiError> {
        unsafe {
            let mut ap_config: esp_idf_sys::wifi_config_t = core::mem::zeroed();

            let ssid_bytes = self.config.ap_ssid.as_bytes();
            let ssid_len = ssid_bytes.len().min(32);
            ap_config.ap.ssid[..ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);
            ap_config.ap.ssid_len = ssid_len as u8;

            let pass_bytes = self.config.ap_password.as_bytes();
            let pass_len = pass_bytes.len().min(64);
            ap_config.ap.password[..pass_len].copy_from_slice(&pass_bytes[..pass_len]);

            ap_config.ap.channel = self.config.ap_channel;
            ap_config.ap.max_connection = MAX_TCP_CLIENTS as u8;

            if pass_len > 0 {
                ap_config.ap.authmode = esp_idf_sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK;
            } else {
                ap_config.ap.authmode = esp_idf_sys::wifi_auth_mode_t_WIFI_AUTH_OPEN;
            }

            let ret = esp_idf_sys::esp_wifi_set_config(
                esp_idf_sys::wifi_interface_t_WIFI_IF_AP,
                &mut ap_config,
            );

            if ret != 0 {
                return Err(WifiError::ConfigError);
            }
        }
        Ok(())
    }

    fn configure_sta(&self) -> Result<(), WifiError> {
        unsafe {
            let mut sta_config: esp_idf_sys::wifi_config_t = core::mem::zeroed();

            let ssid_bytes = self.config.sta_ssid.as_bytes();
            let ssid_len = ssid_bytes.len().min(32);
            sta_config.sta.ssid[..ssid_len].copy_from_slice(&ssid_bytes[..ssid_len]);

            let pass_bytes = self.config.sta_password.as_bytes();
            let pass_len = pass_bytes.len().min(64);
            sta_config.sta.password[..pass_len].copy_from_slice(&pass_bytes[..pass_len]);

            let ret = esp_idf_sys::esp_wifi_set_config(
                esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
                &mut sta_config,
            );

            if ret != 0 {
                return Err(WifiError::ConfigError);
            }
        }
        Ok(())
    }

    pub fn start_tcp_server(&mut self) -> Result<(), WifiError> {
        if !self.initialized {
            return Err(WifiError::NotInitialized);
        }

        unsafe {

            let fd = esp_idf_sys::lwip_socket(
                esp_idf_sys::AF_INET as i32,
                esp_idf_sys::SOCK_STREAM as i32,
                esp_idf_sys::IPPROTO_TCP as i32,
            );

            if fd < 0 {
                return Err(WifiError::SocketError);
            }

            let opt: i32 = 1;
            esp_idf_sys::lwip_setsockopt(
                fd,
                esp_idf_sys::SOL_SOCKET as i32,
                esp_idf_sys::SO_REUSEADDR as i32,
                &opt as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<i32>() as u32,
            );

            let mut addr: esp_idf_sys::sockaddr_in = core::mem::zeroed();
            addr.sin_family = esp_idf_sys::AF_INET as u8;
            addr.sin_port = self.config.tcp_port.to_be();
            addr.sin_addr.s_addr = 0;

            let ret = esp_idf_sys::lwip_bind(
                fd,
                &addr as *const _ as *const esp_idf_sys::sockaddr,
                core::mem::size_of::<esp_idf_sys::sockaddr_in>() as u32,
            );

            if ret < 0 {
                esp_idf_sys::lwip_close(fd);
                return Err(WifiError::SocketError);
            }

            let ret = esp_idf_sys::lwip_listen(fd, MAX_TCP_CLIENTS as i32);
            if ret < 0 {
                esp_idf_sys::lwip_close(fd);
                return Err(WifiError::SocketError);
            }

            let flags = esp_idf_sys::lwip_fcntl(fd, esp_idf_sys::F_GETFL as i32, 0);
            esp_idf_sys::lwip_fcntl(fd, esp_idf_sys::F_SETFL as i32, flags | esp_idf_sys::O_NONBLOCK as i32);

            self.server_fd = fd;
        }

        Ok(())
    }

    pub fn stop_tcp_server(&mut self) {
        if self.server_fd >= 0 {
            unsafe {
                esp_idf_sys::lwip_close(self.server_fd);
            }
            self.server_fd = -1;
        }

        for client in &mut self.clients {
            if client.fd >= 0 {
                unsafe {
                    esp_idf_sys::lwip_close(client.fd);
                }
                client.reset();
            }
        }
    }

    pub fn poll(&mut self) -> Option<(usize, Vec<u8, TCP_RX_BUFFER_SIZE>)> {
        if self.server_fd < 0 {
            return None;
        }

        self.accept_connections();

        for i in 0..MAX_TCP_CLIENTS {
            if self.clients[i].fd >= 0 {
                if let Some(data) = self.read_client(i) {
                    return Some((i, data));
                }
            }
        }

        None
    }

    fn accept_connections(&mut self) {
        unsafe {
            let mut client_addr: esp_idf_sys::sockaddr_in = core::mem::zeroed();
            let mut addr_len: u32 = core::mem::size_of::<esp_idf_sys::sockaddr_in>() as u32;

            let client_fd = esp_idf_sys::lwip_accept(
                self.server_fd,
                &mut client_addr as *mut _ as *mut esp_idf_sys::sockaddr,
                &mut addr_len,
            );

            if client_fd >= 0 {

                for client in &mut self.clients {
                    if client.is_available() {

                        let flags = esp_idf_sys::lwip_fcntl(client_fd, esp_idf_sys::F_GETFL as i32, 0);
                        esp_idf_sys::lwip_fcntl(client_fd, esp_idf_sys::F_SETFL as i32, flags | esp_idf_sys::O_NONBLOCK as i32);

                        client.fd = client_fd;
                        client.state = TcpClientState::Detecting;

                        let ip_bytes = client_addr.sin_addr.s_addr.to_le_bytes();
                        let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                        let port = u16::from_be(client_addr.sin_port);
                        client.addr = SocketAddrV4::new(ip, port);

                        self.status.tcp_client_count += 1;
                        return;
                    }
                }

                esp_idf_sys::lwip_close(client_fd);
            }
        }
    }

    fn read_client(&mut self, idx: usize) -> Option<Vec<u8, TCP_RX_BUFFER_SIZE>> {
        let client = &mut self.clients[idx];
        if client.fd < 0 {
            return None;
        }

        let mut buf = [0u8; TCP_RX_BUFFER_SIZE];

        unsafe {
            let n = esp_idf_sys::lwip_recv(
                client.fd,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                buf.len(),
                0,
            );

            if n > 0 {
                let mut data = Vec::new();
                for &b in &buf[..n as usize] {
                    let _ = data.push(b);
                }
                return Some(data);
            } else if n == 0 {

                self.disconnect_client(idx);
            }

        }

        None
    }

    pub fn send_to_client(&mut self, idx: usize, data: &[u8]) -> Result<usize, WifiError> {
        if idx >= MAX_TCP_CLIENTS {
            return Err(WifiError::SocketError);
        }

        let client = &mut self.clients[idx];
        if client.fd < 0 {
            return Err(WifiError::SocketError);
        }

        unsafe {
            let n = esp_idf_sys::lwip_send(
                client.fd,
                data.as_ptr() as *const core::ffi::c_void,
                data.len(),
                0,
            );

            if n < 0 {
                self.disconnect_client(idx);
                return Err(WifiError::SocketError);
            }

            Ok(n as usize)
        }
    }

    pub fn broadcast(&mut self, data: &[u8]) {
        for i in 0..MAX_TCP_CLIENTS {
            if self.clients[i].fd >= 0 {
                let _ = self.send_to_client(i, data);
            }
        }
    }

    pub fn disconnect_client(&mut self, idx: usize) {
        if idx >= MAX_TCP_CLIENTS {
            return;
        }

        let client = &mut self.clients[idx];
        if client.fd >= 0 {
            unsafe {
                esp_idf_sys::lwip_close(client.fd);
            }
            client.reset();
            if self.status.tcp_client_count > 0 {
                self.status.tcp_client_count -= 1;
            }
        }
    }

    pub fn get_client(&self, idx: usize) -> Option<&TcpClient> {
        if idx < MAX_TCP_CLIENTS && self.clients[idx].fd >= 0 {
            Some(&self.clients[idx])
        } else {
            None
        }
    }

    pub fn get_client_mut(&mut self, idx: usize) -> Option<&mut TcpClient> {
        if idx < MAX_TCP_CLIENTS && self.clients[idx].fd >= 0 {
            Some(&mut self.clients[idx])
        } else {
            None
        }
    }

    pub fn stop(&mut self) {
        self.stop_tcp_server();

        unsafe {
            esp_idf_sys::esp_wifi_stop();
        }

        self.status.mode = WifiMode::Off;
        self.status.sta_connected = false;
        self.status.ap_active = false;
    }

    pub fn status(&self) -> &NetworkStatus {
        &self.status
    }

    pub fn update_status(&mut self) {
        unsafe {

            let mut ap_info: esp_idf_sys::wifi_ap_record_t = core::mem::zeroed();
            if esp_idf_sys::esp_wifi_sta_get_ap_info(&mut ap_info) == 0 {
                self.status.sta_connected = true;
                self.status.rssi = ap_info.rssi;
            } else {
                self.status.sta_connected = false;
            }

        }
    }

    pub fn scan(&mut self) -> Result<Vec<NetworkInfo, 16>, WifiError> {
        if !self.initialized {
            return Err(WifiError::NotInitialized);
        }

        let mut networks = Vec::new();

        unsafe {

            let scan_config: esp_idf_sys::wifi_scan_config_t = core::mem::zeroed();
            let ret = esp_idf_sys::esp_wifi_scan_start(&scan_config, true);
            if ret != 0 {
                return Err(WifiError::ConfigError);
            }

            let mut ap_count: u16 = 0;
            esp_idf_sys::esp_wifi_scan_get_ap_num(&mut ap_count);

            let count = ap_count.min(16) as usize;
            let mut ap_records: [esp_idf_sys::wifi_ap_record_t; 16] = core::mem::zeroed();
            let mut actual_count = count as u16;

            esp_idf_sys::esp_wifi_scan_get_ap_records(&mut actual_count, ap_records.as_mut_ptr());

            for i in 0..actual_count as usize {
                let ap = &ap_records[i];
                let mut ssid = String::new();
                for &b in &ap.ssid {
                    if b == 0 {
                        break;
                    }
                    let _ = ssid.push(b as char);
                }

                let info = NetworkInfo {
                    ssid,
                    rssi: ap.rssi,
                    channel: ap.primary,
                    auth: ap.authmode as u8,
                };
                let _ = networks.push(info);
            }
        }

        Ok(networks)
    }
}

impl Default for WifiManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct NetworkInfo {

    pub ssid: String<MAX_SSID_LEN>,

    pub rssi: i8,

    pub channel: u8,

    pub auth: u8,
}

impl NetworkInfo {

    pub fn is_open(&self) -> bool {
        self.auth == 0
    }
}
