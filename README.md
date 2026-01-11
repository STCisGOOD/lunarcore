# LunarCore

Multi-protocol mesh firmware for ESP32-S3 LoRa devices.

## Protocols

- MeshCore
- Meshtastic
- RNode/KISS (Reticulum)

## Hardware

Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262)

## Build

```bash
espup install
cargo build --release
espflash flash target/xtensa-esp32s3-espidf/release/lunarcore --monitor
```

## License

MIT
