# NLTP v1.6.0 — Arduino & PlatformIO C99 SDK

**Loss-Healing X25519 Forward-Secret UDP & ESP-NOW v1/v2 Transport (`4.76 KB` TX-Only MCU Profile)**

- **Live Browser Wire Lab & Docs:** https://indian-aman.github.io/necklink/nltp/
- **Python Gateway SDK (`pynltp`):** `pip install pynltp`
- **Source Monorepo:** https://github.com/indian-aman/necklink/tree/main/packages/nltp

## Key Capabilities
- **Systematic `GF(2^8)` Cauchy Erasure Coding:** Heals `10–35%` random RF packet loss in-flight with zero retransmit stall (`100%` SHA-256 verified on physical `ESP32 + ESP8266` hardware).
- **`X25519` Forward Secrecy + `ChaCha20-Poly1305` AEAD:** `512`-packet anti-replay window (`160/160` forged/replayed frames dropped pre-FEC).
- **Built-in Zero-Dependency `LZ4` Block Compression:** Shrinks repetitive JSON/CSV telemetry `6.1×–6.9×` before encryption and FEC slicing (`FLAG_LZ4 = 0x40`).
- **Confirmed `0 ms` HOL Out-of-Line Reflex Channel:** Sub-millisecond emergency actuator commands bypass bulk file transfer queues.
- **`4,760`-Byte `#define NLTP_TX_ONLY` Sensor Mode:** Fits comfortably inside `ESP8266`, `ATmega`, and `STM32` SRAM budgets with `0` `malloc` calls and `0` floats.
