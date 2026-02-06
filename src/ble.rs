use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use critical_section::Mutex;
use heapless::{Vec, Deque};


pub const MAX_CONNECTIONS: usize = 3;


pub const MAX_MTU: usize = 512;


pub const MAX_ADV_DATA: usize = 31;


pub const MAX_SCAN_RSP: usize = 31;


pub const TX_QUEUE_DEPTH: usize = 8;


pub const RX_BUFFER_SIZE: usize = 512;


pub mod nus {

    pub const SERVICE: [u8; 16] = [
        0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0,
        0x93, 0xf3, 0xa3, 0xb5, 0x01, 0x00, 0x40, 0x6e,
    ];

    pub const RX: [u8; 16] = [
        0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0,
        0x93, 0xf3, 0xa3, 0xb5, 0x02, 0x00, 0x40, 0x6e,
    ];

    pub const TX: [u8; 16] = [
        0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0,
        0x93, 0xf3, 0xa3, 0xb5, 0x03, 0x00, 0x40, 0x6e,
    ];
}


pub mod meshtastic {

    pub const SERVICE: [u8; 16] = [
        0xfd, 0xea, 0x73, 0xe2, 0xca, 0x5d, 0xa8, 0x9f,
        0x1f, 0x46, 0xa8, 0x15, 0x18, 0xb2, 0xa1, 0x6b,
    ];

    pub const FROM_RADIO: [u8; 16] = [
        0x02, 0x00, 0x12, 0xac, 0x42, 0x02, 0x78, 0xb8,
        0xed, 0x11, 0x93, 0x49, 0x9e, 0xe6, 0x55, 0x2c,
    ];

    pub const TO_RADIO: [u8; 16] = [
        0xe7, 0x01, 0x44, 0x12, 0x66, 0x78, 0xdd, 0xa1,
        0xad, 0x4d, 0x9e, 0x12, 0xd2, 0x76, 0x5c, 0xf7,
    ];

    pub const FROM_NUM: [u8; 16] = [
        0x53, 0x44, 0xe3, 0x47, 0x75, 0xaa, 0x70, 0xa6,
        0x66, 0x4f, 0x00, 0xa8, 0x8c, 0xa1, 0x9d, 0xed,
    ];
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connected,
    Subscribed,
    Encrypted,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    Nus,
    Meshtastic,
    Unknown,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleError {
    NotInitialized,
    AlreadyInitialized,
    MaxConnections,
    NotConnected,
    NotSubscribed,
    MtuExceeded,
    QueueFull,
    InvalidHandle,
    StackError(i32),
    Timeout,
    InvalidParameter,
}


#[derive(Debug, Clone)]
pub enum BleEvent {
    Connected { conn_handle: u16 },
    Disconnected { conn_handle: u16, reason: u8 },
    MtuExchange { conn_handle: u16, mtu: u16 },
    Subscribed { conn_handle: u16, service: ServiceType },
    Unsubscribed { conn_handle: u16, service: ServiceType },
    DataReceived { conn_handle: u16, service: ServiceType, data: Vec<u8, RX_BUFFER_SIZE> },
    TxComplete { conn_handle: u16 },
    EncryptionChanged { conn_handle: u16, encrypted: bool },
}


#[derive(Debug, Clone)]
pub struct BleDataPacket {

    pub conn_handle: u16,

    pub service: ServiceType,

    pub data: Vec<u8, RX_BUFFER_SIZE>,
}


pub struct BleConnection {

    handle: u16,

    state: ConnectionState,

    service: ServiceType,

    mtu: u16,

    tx_queue: Deque<Vec<u8, MAX_MTU>, TX_QUEUE_DEPTH>,

    rx_buffer: Vec<u8, RX_BUFFER_SIZE>,

    nus_tx_notify: bool,

    mesh_from_radio_notify: bool,

    mesh_from_num_notify: bool,

    encrypted: bool,

    peer_addr: [u8; 6],

    conn_interval: u16,

    conn_latency: u16,

    supervision_timeout: u16,
}

impl BleConnection {
    pub fn new(handle: u16, peer_addr: [u8; 6]) -> Self {
        Self {
            handle,
            state: ConnectionState::Connected,
            service: ServiceType::Unknown,
            mtu: 23,
            tx_queue: Deque::new(),
            rx_buffer: Vec::new(),
            nus_tx_notify: false,
            mesh_from_radio_notify: false,
            mesh_from_num_notify: false,
            encrypted: false,
            peer_addr,
            conn_interval: 0,
            conn_latency: 0,
            supervision_timeout: 0,
        }
    }


    pub fn is_subscribed(&self) -> bool {
        match self.service {
            ServiceType::Nus => self.nus_tx_notify,
            ServiceType::Meshtastic => self.mesh_from_radio_notify,
            ServiceType::Unknown => false,
        }
    }


    pub fn max_payload(&self) -> usize {
        (self.mtu as usize).saturating_sub(3)
    }


    pub fn queue_tx(&mut self, data: &[u8]) -> Result<(), BleError> {
        if data.len() > self.max_payload() {
            return Err(BleError::MtuExceeded);
        }

        let mut vec = Vec::new();
        vec.extend_from_slice(data).map_err(|_| BleError::MtuExceeded)?;

        self.tx_queue.push_back(vec).map_err(|_| BleError::QueueFull)?;
        Ok(())
    }
}


static BLE_STATE: Mutex<RefCell<Option<BleState>>> = Mutex::new(RefCell::new(None));


static EVENT_QUEUE: Mutex<RefCell<Deque<BleEvent, 16>>> = Mutex::new(RefCell::new(Deque::new()));


static ADVERTISING: AtomicBool = AtomicBool::new(false);


static CONNECTION_COUNT: AtomicU16 = AtomicU16::new(0);

struct BleState {
    connections: [Option<BleConnection>; MAX_CONNECTIONS],
    device_name: [u8; 32],
    device_name_len: usize,

    nus_rx_handle: u16,
    nus_tx_handle: u16,
    mesh_to_radio_handle: u16,
    mesh_from_radio_handle: u16,
    mesh_from_num_handle: u16,


    from_radio_queue: Deque<Vec<u8, MAX_MTU>, 16>,
}

impl BleState {
    fn new(name: &str) -> Self {
        let mut device_name = [0u8; 32];
        let name_bytes = name.as_bytes();
        let len = core::cmp::min(name_bytes.len(), 32);
        device_name[..len].copy_from_slice(&name_bytes[..len]);

        Self {
            connections: [None, None, None],
            device_name,
            device_name_len: len,
            nus_rx_handle: 0,
            nus_tx_handle: 0,
            mesh_to_radio_handle: 0,
            mesh_from_radio_handle: 0,
            mesh_from_num_handle: 0,
            from_radio_queue: Deque::new(),
        }
    }

    fn find_connection(&mut self, handle: u16) -> Option<&mut BleConnection> {
        for slot in &mut self.connections {
            if let Some(conn) = slot {
                if conn.handle == handle {
                    return Some(conn);
                }
            }
        }
        None
    }

    fn add_connection(&mut self, handle: u16, peer_addr: [u8; 6]) -> Result<(), BleError> {
        for slot in &mut self.connections {
            if slot.is_none() {
                *slot = Some(BleConnection::new(handle, peer_addr));
                CONNECTION_COUNT.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
        }
        Err(BleError::MaxConnections)
    }

    fn remove_connection(&mut self, handle: u16) {
        for slot in &mut self.connections {
            if let Some(conn) = slot {
                if conn.handle == handle {
                    *slot = None;
                    CONNECTION_COUNT.fetch_sub(1, Ordering::SeqCst);
                    return;
                }
            }
        }
    }
}


pub struct BleManager {
    initialized: bool,
}

impl BleManager {

    pub const fn new() -> Self {
        Self { initialized: false }
    }


    pub fn init(&mut self, device_name: &str) -> Result<(), BleError> {
        if self.initialized {
            return Err(BleError::AlreadyInitialized);
        }


        critical_section::with(|cs| {
            BLE_STATE.borrow(cs).replace(Some(BleState::new(device_name)));
        });


        unsafe {
            self.init_nimble()?;
            self.register_services()?;
        }

        self.initialized = true;
        Ok(())
    }


    unsafe fn init_nimble(&self) -> Result<(), BleError> {


        #[cfg(target_arch = "xtensa")]
        {
            extern "C" {
                fn nimble_port_init() -> i32;
                fn nimble_port_freertos_init(task: extern "C" fn(*mut core::ffi::c_void)) -> i32;
            }


            let rc = nimble_port_init();
            if rc != 0 {
                return Err(BleError::StackError(rc));
            }


            esp_idf_sys::ble_hs_cfg.sync_cb = Some(on_sync);
            esp_idf_sys::ble_hs_cfg.reset_cb = Some(on_reset);


            let rc = nimble_port_freertos_init(nimble_host_task);
            if rc != 0 {
                return Err(BleError::StackError(rc));
            }
        }


        #[cfg(not(target_arch = "xtensa"))]
        {

        }

        Ok(())
    }


    unsafe fn register_services(&self) -> Result<(), BleError> {
        #[cfg(target_arch = "xtensa")]
        {

            static NUS_SERVICE: GattService = GattService {
                uuid: &nus::SERVICE,
                characteristics: &[
                    GattCharacteristic {
                        uuid: &nus::RX,
                        flags: CHR_FLAG_WRITE | CHR_FLAG_WRITE_NO_RSP,
                        callback: Some(nus_rx_callback),
                    },
                    GattCharacteristic {
                        uuid: &nus::TX,
                        flags: CHR_FLAG_NOTIFY,
                        callback: None,
                    },
                ],
            };


            static MESH_SERVICE: GattService = GattService {
                uuid: &meshtastic::SERVICE,
                characteristics: &[
                    GattCharacteristic {
                        uuid: &meshtastic::TO_RADIO,
                        flags: CHR_FLAG_WRITE | CHR_FLAG_WRITE_NO_RSP,
                        callback: Some(mesh_to_radio_callback),
                    },
                    GattCharacteristic {
                        uuid: &meshtastic::FROM_RADIO,
                        flags: CHR_FLAG_READ | CHR_FLAG_NOTIFY,
                        callback: Some(mesh_from_radio_callback),
                    },
                    GattCharacteristic {
                        uuid: &meshtastic::FROM_NUM,
                        flags: CHR_FLAG_NOTIFY,
                        callback: None,
                    },
                ],
            };

            extern "C" {
                fn ble_gatts_count_cfg(svcs: *const GattService) -> i32;
                fn ble_gatts_add_svcs(svcs: *const GattService) -> i32;
            }


            let services = [NUS_SERVICE, MESH_SERVICE];

            let rc = ble_gatts_count_cfg(services.as_ptr());
            if rc != 0 {
                return Err(BleError::StackError(rc));
            }

            let rc = ble_gatts_add_svcs(services.as_ptr());
            if rc != 0 {
                return Err(BleError::StackError(rc));
            }
        }

        Ok(())
    }


    pub fn start_advertising(&mut self) -> Result<(), BleError> {
        if !self.initialized {
            return Err(BleError::NotInitialized);
        }

        #[cfg(target_arch = "xtensa")]
        unsafe {
            let mut adv_params = ble_gap_adv_params {
                conn_mode: BLE_GAP_CONN_MODE_UND,
                disc_mode: BLE_GAP_DISC_MODE_GEN,
                itvl_min: 160,
                itvl_max: 320,
                channel_map: 0x07,
                filter_policy: 0,
                high_duty_cycle: 0,
            };

            extern "C" {
                fn ble_gap_adv_start(
                    own_addr_type: u8,
                    direct_addr: *const u8,
                    duration_ms: i32,
                    params: *const ble_gap_adv_params,
                    cb: extern "C" fn(*mut ble_gap_event, *mut core::ffi::c_void) -> i32,
                    arg: *mut core::ffi::c_void,
                ) -> i32;
            }

            let rc = ble_gap_adv_start(
                BLE_OWN_ADDR_PUBLIC,
                core::ptr::null(),
                BLE_HS_FOREVER,
                &adv_params,
                gap_event_callback,
                core::ptr::null_mut(),
            );

            if rc != 0 {
                return Err(BleError::StackError(rc));
            }
        }

        ADVERTISING.store(true, Ordering::SeqCst);
        Ok(())
    }


    pub fn stop_advertising(&mut self) -> Result<(), BleError> {
        if !self.initialized {
            return Err(BleError::NotInitialized);
        }

        #[cfg(target_arch = "xtensa")]
        unsafe {
            extern "C" {
                fn ble_gap_adv_stop() -> i32;
            }

            let rc = ble_gap_adv_stop();
            if rc != 0 && rc != BLE_HS_EALREADY {
                return Err(BleError::StackError(rc));
            }
        }

        ADVERTISING.store(false, Ordering::SeqCst);
        Ok(())
    }


    pub fn is_advertising(&self) -> bool {
        ADVERTISING.load(Ordering::SeqCst)
    }


    pub fn connection_count(&self) -> u16 {
        CONNECTION_COUNT.load(Ordering::SeqCst)
    }


    pub fn send(&self, conn_handle: u16, data: &[u8]) -> Result<(), BleError> {
        if !self.initialized {
            return Err(BleError::NotInitialized);
        }

        critical_section::with(|cs| {
            let mut state = BLE_STATE.borrow(cs).borrow_mut();
            let state = state.as_mut().ok_or(BleError::NotInitialized)?;

            let conn = state.find_connection(conn_handle).ok_or(BleError::NotConnected)?;

            if !conn.is_subscribed() {
                return Err(BleError::NotSubscribed);
            }

            if data.len() > conn.max_payload() {
                return Err(BleError::MtuExceeded);
            }

            conn.queue_tx(data)?;


            let char_handle = match conn.service {
                ServiceType::Nus => state.nus_tx_handle,
                ServiceType::Meshtastic => state.mesh_from_radio_handle,
                ServiceType::Unknown => return Err(BleError::InvalidHandle),
            };

            #[cfg(target_arch = "xtensa")]
            unsafe {
                self.send_notification(conn_handle, char_handle, data)?;
            }

            Ok(())
        })
    }


    #[cfg(target_arch = "xtensa")]
    unsafe fn send_notification(&self, conn_handle: u16, char_handle: u16, data: &[u8]) -> Result<(), BleError> {
        extern "C" {
            fn ble_gatts_notify_custom(
                conn_handle: u16,
                chr_val_handle: u16,
                om: *mut os_mbuf,
            ) -> i32;
            fn os_mbuf_get_pkthdr(pool: *mut core::ffi::c_void, user_hdr_len: u16) -> *mut os_mbuf;
            fn os_mbuf_append(om: *mut os_mbuf, data: *const u8, len: u16) -> i32;
            fn os_mbuf_free_chain(om: *mut os_mbuf) -> i32;
            fn ble_hs_mbuf_att_pkt() -> *mut os_mbuf;
        }

        let om = ble_hs_mbuf_att_pkt();
        if om.is_null() {
            return Err(BleError::StackError(-1));
        }

        let rc = os_mbuf_append(om, data.as_ptr(), data.len() as u16);
        if rc != 0 {
            os_mbuf_free_chain(om);
            return Err(BleError::StackError(rc));
        }

        let rc = ble_gatts_notify_custom(conn_handle, char_handle, om);
        if rc != 0 {
            return Err(BleError::StackError(rc));
        }

        Ok(())
    }


    pub fn broadcast(&self, service: ServiceType, data: &[u8]) -> Result<usize, BleError> {
        if !self.initialized {
            return Err(BleError::NotInitialized);
        }

        let mut sent = 0;

        critical_section::with(|cs| {
            let mut state = BLE_STATE.borrow(cs).borrow_mut();
            let state = state.as_mut().ok_or(BleError::NotInitialized)?;

            for slot in &mut state.connections {
                if let Some(conn) = slot {
                    if conn.service == service && conn.is_subscribed() {
                        if data.len() <= conn.max_payload() {
                            if conn.queue_tx(data).is_ok() {
                                sent += 1;
                            }
                        }
                    }
                }
            }
            Ok(sent)
        })
    }


    pub fn notify_from_num(&self, counter: u32) -> Result<usize, BleError> {
        if !self.initialized {
            return Err(BleError::NotInitialized);
        }

        let counter_bytes = counter.to_le_bytes();
        let mut sent = 0;

        critical_section::with(|cs| {
            let mut state = BLE_STATE.borrow(cs).borrow_mut();
            let state = state.as_mut().ok_or(BleError::NotInitialized)?;

            let from_num_handle = state.mesh_from_num_handle;

            for slot in &mut state.connections {
                if let Some(conn) = slot {

                    if conn.mesh_from_num_notify {
                        #[cfg(target_arch = "xtensa")]
                        unsafe {
                            if self.send_notification(conn.handle, from_num_handle, &counter_bytes).is_ok() {
                                sent += 1;
                            }
                        }

                        #[cfg(not(target_arch = "xtensa"))]
                        {
                            sent += 1;
                        }
                    }
                }
            }
            Ok(sent)
        })
    }


    pub fn queue_from_radio(&self, data: &[u8]) -> Result<(), BleError> {
        if !self.initialized {
            return Err(BleError::NotInitialized);
        }

        if data.len() > MAX_MTU {
            return Err(BleError::MtuExceeded);
        }

        critical_section::with(|cs| {
            let mut state = BLE_STATE.borrow(cs).borrow_mut();
            let state = state.as_mut().ok_or(BleError::NotInitialized)?;


            let mut vec: Vec<u8, MAX_MTU> = Vec::new();
            vec.extend_from_slice(data).map_err(|_| BleError::MtuExceeded)?;


            state.from_radio_queue.push_back(vec).map_err(|_| BleError::QueueFull)?;

            Ok(())
        })
    }


    pub fn dequeue_from_radio(&self) -> Option<Vec<u8, MAX_MTU>> {
        if !self.initialized {
            return None;
        }

        critical_section::with(|cs| {
            let mut state = BLE_STATE.borrow(cs).borrow_mut();
            state.as_mut()?.from_radio_queue.pop_front()
        })
    }


    pub fn has_from_radio_data(&self) -> bool {
        if !self.initialized {
            return false;
        }

        critical_section::with(|cs| {
            let state = BLE_STATE.borrow(cs).borrow();
            state.as_ref().map_or(false, |s| !s.from_radio_queue.is_empty())
        })
    }


    pub fn poll_event(&self) -> Option<BleEvent> {
        critical_section::with(|cs| {
            EVENT_QUEUE.borrow(cs).borrow_mut().pop_front()
        })
    }


    pub fn read(&self) -> Option<Vec<u8, RX_BUFFER_SIZE>> {
        self.read_with_service().map(|packet| packet.data)
    }


    pub fn read_with_service(&self) -> Option<BleDataPacket> {
        if !self.initialized {
            return None;
        }


        critical_section::with(|cs| {
            let mut queue = EVENT_QUEUE.borrow(cs).borrow_mut();


            let mut found_idx = None;
            for (idx, event) in queue.iter().enumerate() {
                if matches!(event, BleEvent::DataReceived { .. }) {
                    found_idx = Some(idx);
                    break;
                }
            }

            if found_idx.is_some() {


                let mut temp: Deque<BleEvent, 16> = Deque::new();
                let mut result = None;

                while let Some(event) = queue.pop_front() {
                    if result.is_none() {
                        if let BleEvent::DataReceived { conn_handle, service, data } = event {
                            result = Some(BleDataPacket {
                                conn_handle,
                                service,
                                data,
                            });
                            continue;
                        }
                    }
                    let _ = temp.push_back(event);
                }


                while let Some(event) = temp.pop_front() {
                    let _ = queue.push_back(event);
                }

                result
            } else {
                None
            }
        })
    }


    pub fn process_tx(&self) -> Result<(), BleError> {
        if !self.initialized {
            return Err(BleError::NotInitialized);
        }

        critical_section::with(|cs| {
            let mut state = BLE_STATE.borrow(cs).borrow_mut();
            let state = state.as_mut().ok_or(BleError::NotInitialized)?;

            for slot in &mut state.connections {
                if let Some(conn) = slot {
                    if conn.is_subscribed() {
                        while let Some(data) = conn.tx_queue.pop_front() {
                            let char_handle = match conn.service {
                                ServiceType::Nus => state.nus_tx_handle,
                                ServiceType::Meshtastic => state.mesh_from_radio_handle,
                                ServiceType::Unknown => continue,
                            };

                            #[cfg(target_arch = "xtensa")]
                            unsafe {

                                let _ = self.send_notification(conn.handle, char_handle, &data);
                            }


                        }
                    }
                }
            }
            Ok(())
        })
    }


    pub fn disconnect(&self, conn_handle: u16) -> Result<(), BleError> {
        if !self.initialized {
            return Err(BleError::NotInitialized);
        }

        #[cfg(target_arch = "xtensa")]
        unsafe {
            extern "C" {
                fn ble_gap_terminate(conn_handle: u16, reason: u8) -> i32;
            }

            let rc = ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            if rc != 0 {
                return Err(BleError::StackError(rc));
            }
        }

        Ok(())
    }


    pub fn update_conn_params(
        &self,
        conn_handle: u16,
        min_interval: u16,
        max_interval: u16,
        latency: u16,
        timeout: u16,
    ) -> Result<(), BleError> {
        if !self.initialized {
            return Err(BleError::NotInitialized);
        }

        #[cfg(target_arch = "xtensa")]
        unsafe {
            extern "C" {
                fn ble_gap_update_params(
                    conn_handle: u16,
                    params: *const ble_gap_upd_params,
                ) -> i32;
            }

            let params = ble_gap_upd_params {
                itvl_min: min_interval,
                itvl_max: max_interval,
                latency,
                supervision_timeout: timeout,
                min_ce_len: 0,
                max_ce_len: 0,
            };

            let rc = ble_gap_update_params(conn_handle, &params);
            if rc != 0 {
                return Err(BleError::StackError(rc));
            }
        }

        Ok(())
    }
}

impl Default for BleManager {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(target_arch = "xtensa")]
extern "C" fn gap_event_callback(event: *mut ble_gap_event, _arg: *mut core::ffi::c_void) -> i32 {
    unsafe {
        let event = &*event;

        match event.event_type {
            BLE_GAP_EVENT_CONNECT => {
                let connect = &event.event_data.connect;
                if connect.status == 0 {
                    let conn_handle = connect.conn_handle;
                    let peer_addr = connect.peer_addr;

                    critical_section::with(|cs| {
                        if let Some(state) = BLE_STATE.borrow(cs).borrow_mut().as_mut() {
                            let _ = state.add_connection(conn_handle, peer_addr);
                        }

                        let _ = EVENT_QUEUE.borrow(cs).borrow_mut().push_back(
                            BleEvent::Connected { conn_handle }
                        );
                    });
                }
            }

            BLE_GAP_EVENT_DISCONNECT => {
                let disconnect = &event.event_data.disconnect;
                let conn_handle = disconnect.conn_handle;
                let reason = disconnect.reason as u8;

                critical_section::with(|cs| {
                    if let Some(state) = BLE_STATE.borrow(cs).borrow_mut().as_mut() {
                        state.remove_connection(conn_handle);
                    }

                    let _ = EVENT_QUEUE.borrow(cs).borrow_mut().push_back(
                        BleEvent::Disconnected { conn_handle, reason }
                    );
                });


                if CONNECTION_COUNT.load(Ordering::SeqCst) < MAX_CONNECTIONS as u16 {

                }
            }

            BLE_GAP_EVENT_MTU => {
                let mtu_event = &event.event_data.mtu;
                let conn_handle = mtu_event.conn_handle;
                let mtu = mtu_event.value;

                critical_section::with(|cs| {
                    if let Some(state) = BLE_STATE.borrow(cs).borrow_mut().as_mut() {
                        if let Some(conn) = state.find_connection(conn_handle) {
                            conn.mtu = mtu;
                        }
                    }

                    let _ = EVENT_QUEUE.borrow(cs).borrow_mut().push_back(
                        BleEvent::MtuExchange { conn_handle, mtu }
                    );
                });
            }

            BLE_GAP_EVENT_SUBSCRIBE => {
                let subscribe = &event.event_data.subscribe;
                let conn_handle = subscribe.conn_handle;
                let attr_handle = subscribe.attr_handle;
                let notify = subscribe.cur_notify != 0;

                critical_section::with(|cs| {
                    if let Some(state) = BLE_STATE.borrow(cs).borrow_mut().as_mut() {

                        let nus_tx_handle = state.nus_tx_handle;
                        let mesh_from_radio_handle = state.mesh_from_radio_handle;
                        let mesh_from_num_handle = state.mesh_from_num_handle;

                        if let Some(conn) = state.find_connection(conn_handle) {
                            let service = if attr_handle == nus_tx_handle {
                                conn.nus_tx_notify = notify;
                                conn.service = ServiceType::Nus;
                                ServiceType::Nus
                            } else if attr_handle == mesh_from_radio_handle {
                                conn.mesh_from_radio_notify = notify;
                                conn.service = ServiceType::Meshtastic;
                                ServiceType::Meshtastic
                            } else if attr_handle == mesh_from_num_handle {
                                conn.mesh_from_num_notify = notify;
                                conn.service = ServiceType::Meshtastic;
                                ServiceType::Meshtastic
                            } else {
                                ServiceType::Unknown
                            };

                            if notify {
                                conn.state = ConnectionState::Subscribed;
                                let _ = EVENT_QUEUE.borrow(cs).borrow_mut().push_back(
                                    BleEvent::Subscribed { conn_handle, service }
                                );
                            } else {
                                let _ = EVENT_QUEUE.borrow(cs).borrow_mut().push_back(
                                    BleEvent::Unsubscribed { conn_handle, service }
                                );
                            }
                        }
                    }
                });
            }

            BLE_GAP_EVENT_ENC_CHANGE => {
                let enc_change = &event.event_data.enc_change;
                let conn_handle = enc_change.conn_handle;
                let status = enc_change.status;

                critical_section::with(|cs| {
                    if let Some(state) = BLE_STATE.borrow(cs).borrow_mut().as_mut() {
                        if let Some(conn) = state.find_connection(conn_handle) {
                            conn.encrypted = status == 0;
                            if conn.encrypted {
                                conn.state = ConnectionState::Encrypted;
                            }
                        }
                    }

                    let _ = EVENT_QUEUE.borrow(cs).borrow_mut().push_back(
                        BleEvent::EncryptionChanged {
                            conn_handle,
                            encrypted: status == 0,
                        }
                    );
                });
            }

            _ => {}
        }
    }

    0
}


#[cfg(target_arch = "xtensa")]
extern "C" fn nus_rx_callback(
    conn_handle: u16,
    _attr_handle: u16,
    ctxt: *mut ble_gatt_access_ctxt,
    _arg: *mut core::ffi::c_void,
) -> i32 {
    unsafe {
        let ctxt = &*ctxt;
        if ctxt.op == BLE_GATT_ACCESS_OP_WRITE_CHR {
            let om = ctxt.om;
            let mut data: Vec<u8, RX_BUFFER_SIZE> = Vec::new();


            let mut current = om;
            while !current.is_null() {
                let mbuf = &*current;
                let slice = core::slice::from_raw_parts(mbuf.data, mbuf.len as usize);
                let _ = data.extend_from_slice(slice);
                current = mbuf.next;
            }

            critical_section::with(|cs| {
                let _ = EVENT_QUEUE.borrow(cs).borrow_mut().push_back(
                    BleEvent::DataReceived {
                        conn_handle,
                        service: ServiceType::Nus,
                        data,
                    }
                );
            });
        }
    }

    0
}


#[cfg(target_arch = "xtensa")]
extern "C" fn mesh_to_radio_callback(
    conn_handle: u16,
    _attr_handle: u16,
    ctxt: *mut ble_gatt_access_ctxt,
    _arg: *mut core::ffi::c_void,
) -> i32 {
    unsafe {
        let ctxt = &*ctxt;
        if ctxt.op == BLE_GATT_ACCESS_OP_WRITE_CHR {
            let om = ctxt.om;
            let mut data: Vec<u8, RX_BUFFER_SIZE> = Vec::new();

            let mut current = om;
            while !current.is_null() {
                let mbuf = &*current;
                let slice = core::slice::from_raw_parts(mbuf.data, mbuf.len as usize);
                let _ = data.extend_from_slice(slice);
                current = mbuf.next;
            }

            critical_section::with(|cs| {
                let _ = EVENT_QUEUE.borrow(cs).borrow_mut().push_back(
                    BleEvent::DataReceived {
                        conn_handle,
                        service: ServiceType::Meshtastic,
                        data,
                    }
                );
            });
        }
    }

    0
}


#[cfg(target_arch = "xtensa")]
extern "C" fn mesh_from_radio_callback(
    _conn_handle: u16,
    _attr_handle: u16,
    ctxt: *mut ble_gatt_access_ctxt,
    _arg: *mut core::ffi::c_void,
) -> i32 {
    unsafe {
        let ctxt = &*ctxt;
        if ctxt.op == BLE_GATT_ACCESS_OP_READ_CHR {

            critical_section::with(|cs| {
                if let Some(state) = BLE_STATE.borrow(cs).borrow_mut().as_mut() {

                    if let Some(data) = state.from_radio_queue.pop_front() {
                        extern "C" {
                            fn os_mbuf_append(om: *mut os_mbuf, data: *const u8, len: u16) -> i32;
                        }
                        let _ = os_mbuf_append(ctxt.om, data.as_ptr(), data.len() as u16);
                    }
                }
            });
        }
    }

    0
}


#[cfg(target_arch = "xtensa")]
extern "C" fn on_sync() {

    ADVERTISING.store(false, Ordering::SeqCst);
}


#[cfg(target_arch = "xtensa")]
extern "C" fn on_reset(reason: i32) {

    log::warn!("NimBLE reset: {}", reason);
    ADVERTISING.store(false, Ordering::SeqCst);
    CONNECTION_COUNT.store(0, Ordering::SeqCst);
}


#[cfg(target_arch = "xtensa")]
extern "C" fn nimble_host_task(_arg: *mut core::ffi::c_void) {
    extern "C" {
        fn nimble_port_run() -> !;
    }
    unsafe {
        nimble_port_run();
    }
}


#[cfg(target_arch = "xtensa")]
#[repr(C)]
struct ble_gap_event {
    event_type: u8,
    _padding: [u8; 3],
    event_data: ble_gap_event_union,
}


#[cfg(target_arch = "xtensa")]
#[repr(C)]
union ble_gap_event_union {
    connect: ble_gap_event_connect,
    disconnect: ble_gap_event_disconnect,
    mtu: ble_gap_event_mtu,
    subscribe: ble_gap_event_subscribe,
    enc_change: ble_gap_event_enc_change,
    _raw: [u8; 64],
}

#[cfg(target_arch = "xtensa")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ble_gap_event_connect {
    status: i32,
    conn_handle: u16,
    _padding: [u8; 2],
    peer_addr: [u8; 6],
}

#[cfg(target_arch = "xtensa")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ble_gap_event_disconnect {
    reason: i32,
    conn_handle: u16,
}

#[cfg(target_arch = "xtensa")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ble_gap_event_mtu {
    conn_handle: u16,
    channel_id: u16,
    value: u16,
}

#[cfg(target_arch = "xtensa")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ble_gap_event_subscribe {
    conn_handle: u16,
    attr_handle: u16,
    reason: u8,
    prev_notify: u8,
    cur_notify: u8,
    prev_indicate: u8,
    cur_indicate: u8,
}

#[cfg(target_arch = "xtensa")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ble_gap_event_enc_change {
    status: i32,
    conn_handle: u16,
}

#[cfg(target_arch = "xtensa")]
#[repr(C)]
struct ble_gap_adv_params {
    conn_mode: u8,
    disc_mode: u8,
    itvl_min: u16,
    itvl_max: u16,
    channel_map: u8,
    filter_policy: u8,
    high_duty_cycle: u8,
}

#[cfg(target_arch = "xtensa")]
#[repr(C)]
struct ble_gap_upd_params {
    itvl_min: u16,
    itvl_max: u16,
    latency: u16,
    supervision_timeout: u16,
    min_ce_len: u16,
    max_ce_len: u16,
}

#[cfg(target_arch = "xtensa")]
#[repr(C)]
struct ble_gatt_access_ctxt {
    op: u8,
    om: *mut os_mbuf,
}

#[cfg(target_arch = "xtensa")]
#[repr(C)]
struct os_mbuf {
    data: *const u8,
    len: u16,
    next: *mut os_mbuf,
}


#[cfg(target_arch = "xtensa")]
#[repr(C)]
#[derive(Clone, Copy)]
struct GattService {
    uuid: *const [u8; 16],
    characteristics: *const [GattCharacteristic],
}


#[cfg(target_arch = "xtensa")]
#[repr(C)]
#[derive(Clone, Copy)]
struct GattCharacteristic {
    uuid: *const [u8; 16],
    flags: u16,
    callback: Option<extern "C" fn(u16, u16, *mut ble_gatt_access_ctxt, *mut core::ffi::c_void) -> i32>,
}


#[cfg(target_arch = "xtensa")]
unsafe impl Sync for GattService {}
#[cfg(target_arch = "xtensa")]
unsafe impl Send for GattService {}
#[cfg(target_arch = "xtensa")]
unsafe impl Sync for GattCharacteristic {}
#[cfg(target_arch = "xtensa")]
unsafe impl Send for GattCharacteristic {}


#[cfg(target_arch = "xtensa")]
const BLE_GAP_CONN_MODE_UND: u8 = 0;
#[cfg(target_arch = "xtensa")]
const BLE_GAP_DISC_MODE_GEN: u8 = 2;
#[cfg(target_arch = "xtensa")]
const BLE_OWN_ADDR_PUBLIC: u8 = 0;
#[cfg(target_arch = "xtensa")]
const BLE_HS_FOREVER: i32 = i32::MAX;
#[cfg(target_arch = "xtensa")]
const BLE_HS_EALREADY: i32 = 2;
#[cfg(target_arch = "xtensa")]
const BLE_ERR_REM_USER_CONN_TERM: u8 = 0x13;
#[cfg(target_arch = "xtensa")]
const BLE_GAP_EVENT_CONNECT: u8 = 0;
#[cfg(target_arch = "xtensa")]
const BLE_GAP_EVENT_DISCONNECT: u8 = 1;
#[cfg(target_arch = "xtensa")]
const BLE_GAP_EVENT_MTU: u8 = 15;
#[cfg(target_arch = "xtensa")]
const BLE_GAP_EVENT_SUBSCRIBE: u8 = 14;
#[cfg(target_arch = "xtensa")]
const BLE_GAP_EVENT_ENC_CHANGE: u8 = 10;
#[cfg(target_arch = "xtensa")]
const BLE_GATT_ACCESS_OP_READ_CHR: u8 = 0;
#[cfg(target_arch = "xtensa")]
const BLE_GATT_ACCESS_OP_WRITE_CHR: u8 = 1;
#[cfg(target_arch = "xtensa")]
const CHR_FLAG_WRITE: u16 = 0x0008;
#[cfg(target_arch = "xtensa")]
const CHR_FLAG_WRITE_NO_RSP: u16 = 0x0004;
#[cfg(target_arch = "xtensa")]
const CHR_FLAG_NOTIFY: u16 = 0x0010;
#[cfg(target_arch = "xtensa")]
const CHR_FLAG_READ: u16 = 0x0002;


pub fn build_adv_data(name: &str, include_nus: bool, include_meshtastic: bool) -> Vec<u8, MAX_ADV_DATA> {
    let mut data: Vec<u8, MAX_ADV_DATA> = Vec::new();


    let _ = data.push(0x02);
    let _ = data.push(0x01);
    let _ = data.push(0x06);


    let _ = data.push(0x02);
    let _ = data.push(0x0A);
    let _ = data.push(0x00);


    let name_bytes = name.as_bytes();
    let max_name = MAX_ADV_DATA - data.len() - 2;
    let name_len = core::cmp::min(name_bytes.len(), max_name);
    if name_len > 0 {
        let _ = data.push((name_len + 1) as u8);
        if name_len == name_bytes.len() {
            let _ = data.push(0x09);
        } else {
            let _ = data.push(0x08);
        }
        for i in 0..name_len {
            let _ = data.push(name_bytes[i]);
        }
    }

    data
}


pub fn build_scan_rsp(include_nus: bool, include_meshtastic: bool) -> Vec<u8, MAX_SCAN_RSP> {
    let mut data: Vec<u8, MAX_SCAN_RSP> = Vec::new();


    if include_nus && data.len() + 18 <= MAX_SCAN_RSP {
        let _ = data.push(17);
        let _ = data.push(0x07);
        for &b in &nus::SERVICE {
            let _ = data.push(b);
        }
    }

    if include_meshtastic && data.len() + 18 <= MAX_SCAN_RSP {
        let _ = data.push(17);
        let _ = data.push(0x06);
        for &b in &meshtastic::SERVICE {
            let _ = data.push(b);
        }
    }

    data
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nus_uuids() {

        assert_eq!(nus::SERVICE[12], 0x01);
        assert_eq!(nus::RX[12], 0x02);
        assert_eq!(nus::TX[12], 0x03);
    }

    #[test]
    fn test_adv_data_builder() {
        let data = build_adv_data("LunarCore", true, false);
        assert!(data.len() <= MAX_ADV_DATA);


        assert_eq!(data[0], 0x02);
        assert_eq!(data[1], 0x01);
        assert_eq!(data[2], 0x06);
    }

    #[test]
    fn test_connection() {
        let conn = BleConnection::new(1, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(conn.handle, 1);
        assert_eq!(conn.state, ConnectionState::Connected);
        assert_eq!(conn.mtu, 23);
        assert_eq!(conn.max_payload(), 20);
    }

    #[test]
    fn test_ble_manager_init() {

        let manager = BleManager::new();
        assert!(!manager.initialized);
    }
}
