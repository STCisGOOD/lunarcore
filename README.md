# LunarCore

Multi-protocol mesh firmware for ESP32-S3 LoRa devices.

## Protocols

- MeshCore
- Meshtastic
- RNode/KISS (Reticulum)

Protocol is auto-detected from the first bytes over serial or BLE.

## Hardware

Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262)

## Flash (prebuilt)

Download `lunarcore-esp32s3.bin` from [Releases](../../releases).

```bash
pip install esptool
esptool.py --chip esp32s3 -p PORT write_flash 0x0 lunarcore-esp32s3.bin
```

## Build from source

```bash
espup install
. ~/export-esp.sh
cargo build --release
espflash flash target/xtensa-esp32s3-espidf/release/lunarcore --monitor
```

## Repeater

Enabled by default. Relays MeshCore packets when no app is connected. Disable with `AT+REPEATER=0`.

## License

MIT
