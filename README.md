# NLTP v1.6.0 — Arduino, PlatformIO & ESP-IDF C99 SDK

[![Tier-1 Compliance CI](https://github.com/indian-aman/NLTP-Arduino/actions/workflows/tier1-compliance.yml/badge.svg)](https://github.com/indian-aman/NLTP-Arduino/actions/workflows/tier1-compliance.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16811/badge)](https://www.bestpractices.dev/projects/16811)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/indian-aman/NLTP-Arduino/badge)](https://scorecard.dev/viewer/?uri=github.com/indian-aman/NLTP-Arduino)
[![IETF Datatracker](https://img.shields.io/badge/IETF%20Datatracker-draft--bains--nltp--00-005A9C.svg)](https://datatracker.ietf.org/doc/draft-bains-nltp/)
[![ESP Component Registry](https://components.espressif.com/components/indian-aman/nltp/badge.svg)](https://components.espressif.com/components/indian-aman/nltp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

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

---

## Standards, Security & Verification (Tier 1)

Every commit is continuously verified against formal IETF/NIST cryptographic vectors, memory sanitizers, adversarial fuzzing, static safety rules, and supply-chain provenance:

| Artifact / Assurance Gate | Specification & Verification Scope |
| :--- | :--- |
| **Formal IETF Internet-Draft** | [`datatracker.ietf.org/doc/draft-bains-nltp/`](https://datatracker.ietf.org/doc/draft-bains-nltp/) ([TXT](spec/draft-bains-nltp-00.txt) · [XML](spec/draft-bains-nltp-00.xml) · [HTML](spec/draft-bains-nltp-00.html)) — active IETF Individual Internet-Draft specifying wire headers, handshake, Cauchy FEC, and LZ4 |
| **NIST & IETF Cryptographic KATs** | [`tests/test_kat_vectors.c`](tests/test_kat_vectors.c) — `1,668` checks covering **RFC 7748** (X25519 + low-order point rejection), **RFC 8439** (ChaCha20-Poly1305 AEAD), **RFC 4231** (HMAC-SHA256), **NIST FIPS 180-4** (SHA-256), **RFC 6479** (`512`-bit anti-replay), and `30%`-loss encrypted loopback under `ASan`/`UBSan` |
| **Continuous `libFuzzer` Harness** | [`fuzz/fuzz_nltp_rx.c`](fuzz/fuzz_nltp_rx.c) — `500,000` mutated frames per CI run (`clang -fsanitize=fuzzer,address,undefined`) across plaintext/encrypted parsers & in-place LZ4 decompression |
| **MISRA C:2012 Compliance** | [`docs/MISRA_C_2012_COMPLIANCE.md`](docs/MISRA_C_2012_COMPLIANCE.md) — strict ISO C99 (`-Wpedantic -Werror`), zero heap (`-DNLTP_NO_MALLOC`), zero floats, acyclic call graph, `cppcheck` + MISRA C:2012 CI audit |
| **Security & Disclosure Policy** | [`SECURITY.md`](SECURITY.md) & [`CONTRIBUTING.md`](CONTRIBUTING.md) — coordinated disclosure SLA, authenticate-before-decrypt architecture, and contributor gates |
| **Supply-Chain SBOM & Provenance** | [`sbom.spdx.json`](sbom.spdx.json) (SPDX 2.3) · [`sbom.cdx.json`](sbom.cdx.json) (CycloneDX 1.5) + GitHub SLSA Build Provenance attestations & [OpenSSF Scorecard](.github/workflows/scorecard.yml) |

---

## Installation (`Arduino`, `PlatformIO`, `ESP-IDF`, `CMake`)

### 1. Espressif ESP-IDF Component Manager (`v5.0+`)
Published on the official [ESP Component Registry (`indian-aman/nltp`)](https://components.espressif.com/components/indian-aman/nltp):
```bash
idf.py add-dependency "indian-aman/nltp^1.6.0"
```
Or reference this repository directly in `idf_component.yml`:
```yaml
dependencies:
  nltp:
    git: https://github.com/indian-aman/NLTP-Arduino.git
    version: "1.6.0"
```

### 2. PlatformIO (`platformio.ini`)
```ini
lib_deps =
    https://github.com/indian-aman/NLTP-Arduino.git#v1.6.0
```

### 3. Standalone CMake (`Linux` / `macOS` / `Windows` / Embedded)
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```
