# Contributing to NLTP-Arduino

Thank you for contributing to **NLTP** (*NeckLink Transport Protocol*). Because NLTP runs directly on safety- and resource-constrained microcontrollers (`ESP32`, `ESP8266`, `STM32`, `RP2040`) over untrusted wireless and Internet links, all contributions must adhere to strict portability, memory-safety, and wire-interoperability standards.

---

## Repository Structure

| Path | Description |
| :--- | :--- |
| `src/nltp_wire.h` | Pure ANSI C99 wire framing, IEEE 802.3 CRC32, `GF(2^8)` Cauchy FEC, X25519, ChaCha20-Poly1305 AEAD, RFC 6479 anti-replay, and zero-heap LZ4 raw block codec |
| `src/nltp_core.h`, `src/nltp_core.c` | Portable C99 NLTP endpoint state machine (handshake, sender, receiver, BBR-style integer rate pacer, reliable reflex lane) |
| `src/nltp_sha256.h`, `src/nltp_sha256.c` | FIPS 180-4 SHA-256 and RFC 2104 HMAC-SHA256 |
| `src/nltp_net.h`, `src/nltp_net.c` | Zero-knowledge CGNAT relay framing (`"NR"`) and RFC 5389 STUN client helpers |
| `src/nltp_espnow.h` | Zero-wrapper ESP-NOW v1/v2 L2 transport for ESP-IDF v5.x / Arduino-ESP32 v3.x |
| `src/NLTP.h` | Arduino IDE & PlatformIO C++ wrapper (`NLTPWiFiNode`, `NLTPESPNowNode`) |
| `tests/test_kat_vectors.c` | Official NIST / IETF cryptographic Known-Answer Tests (KAT) & lossy encrypted loopback suite |
| `fuzz/fuzz_nltp_rx.c` | `libFuzzer` + `ASan`/`UBSan` adversarial frame and LZ4 decompression harness |
| `spec/draft-bains-nltp-00.xml` | Formal IETF Internet-Draft wire specification (RFCXML v3) |
| `docs/MISRA_C_2012_COMPLIANCE.md` | MISRA C:2012 static compliance matrix & justified deviation register |

---

## Mandatory Engineering & Coding Standards

1. **Strict ISO C99 (`-std=c99 -Wpedantic -Werror`):**
   - All core files (`src/nltp_*.c`, `src/nltp_*.h` except ESP-IDF-specific `nltp_espnow.h`) must compile cleanly with zero warnings under `gcc` and `clang` using `-std=c99 -Wall -Wextra -Wpedantic -Werror` with GNU extensions disabled (`-DCMAKE_C_EXTENSIONS=OFF`).
2. **Zero Dynamic Memory Allocation:**
   - Core protocol and cryptographic paths must not call `malloc`, `calloc`, `realloc`, or `free` (enforced under `-DNLTP_NO_MALLOC`). All state resides inside caller-owned structs (`nltp_endpoint_t`).
3. **Zero Floating-Point Arithmetic:**
   - Do **not** introduce `float` or `double` types, literals, or `<math.h>` calls anywhere in `src/`. All pacing, RTT estimation, and loss calculations use deterministic integer arithmetic.
4. **Constant-Time Cryptographic Discipline:**
   - Secret-dependent branches and table lookups are forbidden in X25519, ChaCha20, Poly1305, and MAC verification. Sensitive stack buffers must be scrubbed with `nltp_wipe_bytes()`.
5. **Unaligned-Safe Serialization:**
   - Never cast byte pointers (`uint8_t *`) directly to multi-byte integer pointers (`uint16_t *`, `uint32_t *`, `uint64_t *`). Always use `nltp_read_u32_le` / `nltp_write_u32_le` and related helpers in `src/nltp_wire.h`.
6. **Byte-Level Wire Compatibility:**
   - Do not alter wire headers, packet type IDs (`0x01`..`0x0D`), handshake transcripts, or FEC Cauchy coefficients (`x_r = 64 + (parity_offset % 192)`, `y_c = c & 0x3F`) without a coordinated protocol version bump and matching updates to `spec/draft-bains-nltp-00.xml` and `tests/test_kat_vectors.c`.

---

## Local Pre-PR Verification Checklist

Before opening a pull request, run the full Tier-1 verification suite locally:

```bash
# 1. Strict C99 + ASan/UBSan Cryptographic KAT & Protocol Loopback Suite
gcc -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 -g -fsanitize=address,undefined \
    -DNLTP_NO_MALLOC -Isrc \
    tests/test_kat_vectors.c src/nltp_core.c src/nltp_net.c src/nltp_sha256.c \
    -o test_kat_vectors
./test_kat_vectors

# 2. Ultra-Light 4.76 KB MCU Sensor Profile (NLTP_TX_ONLY=1) Verification
gcc -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 -g -fsanitize=address,undefined \
    -DNLTP_TX_ONLY=1 -DNLTP_NO_MALLOC -Isrc \
    tests/test_kat_vectors.c src/nltp_core.c src/nltp_net.c src/nltp_sha256.c \
    -o test_kat_txonly
./test_kat_txonly

# 3. CMake + CTest Build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure

# 4. libFuzzer + ASan/UBSan Adversarial Fuzzing (500,000 inputs)
clang -O2 -g -fsanitize=fuzzer,address,undefined -DNLTP_NO_MALLOC -Isrc \
    fuzz/fuzz_nltp_rx.c src/nltp_core.c src/nltp_net.c src/nltp_sha256.c \
    -o fuzz_nltp_rx
./fuzz_nltp_rx -runs=500000 -max_len=1400

# 5. Cppcheck + MISRA C:2012 Audit
cppcheck --std=c99 --enable=warning,style,performance,portability --error-exitcode=1 -Isrc src/

# 6. ESP-IDF Component Packaging Check
compote component pack --name nltp
```

---

## Security Issues

If you discover a security or memory-safety bug, please follow [SECURITY.md](SECURITY.md) rather than opening a public issue or pull request.

## License

By contributing to `NLTP-Arduino`, you agree that your contributions will be licensed under the [MIT License](LICENSE).
