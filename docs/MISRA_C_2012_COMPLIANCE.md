# MISRA C:2012 Static Analysis & Compliance Statement

**Component:** NeckLink Transport Protocol (`NLTP`) Portable ANSI C99 Core (`v1.6.0`)  
**Audited Scope:** `src/nltp_wire.h`, `src/nltp_core.h`, `src/nltp_core.c`, `src/nltp_sha256.h`, `src/nltp_sha256.c`, `src/nltp_net.h`, `src/nltp_net.c`  
**Out-of-Scope HAL Wrappers:** `src/NLTP.h` (Arduino C++ class wrapper) and `src/nltp_espnow.h` (ESP-IDF v5.x FreeRTOS / Wi-Fi vendor-frame HAL)  
**CI Enforcement:** `.github/workflows/tier1-compliance.yml` (`cppcheck` + `misra.py` addon + `gcc -std=c99 -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined`)

---

## 1. Safety-Critical Architectural Guarantees

NLTP's core C99 implementation is designed from the ground up for deterministic execution on bare-metal and RTOS microcontrollers (`ESP32`, `ESP8266`, `STM32`, `ARM Cortex-M`, `RP2040`):

| Property | MISRA C:2012 Reference | Implementation Status |
| :--- | :--- | :--- |
| **Strict ISO/IEC 9899:1999 C99** | Dir 1.1, Rule 1.1, Rule 1.2 | **Compliant.** Zero GNU/compiler extensions in core files (`-std=c99 -Wpedantic -Werror`, `CMAKE_C_EXTENSIONS=OFF`). |
| **Zero Dynamic Heap Allocation** | Dir 4.12, Rule 21.3 | **Compliant (`-DNLTP_NO_MALLOC`).** All state resides inside statically sizably `nltp_endpoint_t` (`4,760 B` when `NLTP_TX_ONLY=1`). LZ4 decompression executes in-place (`nltp_lz4_decompress_inplace`) with zero heap. |
| **Zero Floating-Point Operations** | Dir 1.1, Rule 10.1–10.8 | **Compliant.** Zero `float` or `double` types, casts, or operations across the entire codebase; all BBR rate control, RTT smoothing, and loss EMAs use bounded integer arithmetic. |
| **Zero Recursion (Acyclic Call Graph)** | Rule 17.2 | **Compliant.** `0` recursive or mutually recursive functions; maximum stack frame usage is statically bounded at compile time. |
| **Bounded Loop Termination** | Rule 14.2 | **Compliant.** Every loop is bounded by compile-time constants (`NLTP_GEN_K = 8`, `NLTP_REPLAY_WORDS = 8`, `255` Montgomery ladder steps, `64` SHA-256 rounds, `10` ChaCha20 double-rounds) or validated datagram length (`len <= NLTP_PKT_MAX + 64`). |
| **Unaligned-Safe Memory Access** | Rule 11.3 | **Compliant.** Network/wire integers are exclusively loaded and stored byte-by-byte via `nltp_read_u32_le`, `nltp_read_u64_le`, `nltp_write_u16_le`, `nltp_write_u32_le`, and `nltp_write_u64_le`. |
| **Defensive Input Bounds Checking** | Dir 4.1, Dir 4.14 | **Compliant.** All external radio/UDP inputs (`nltp_on_datagram`, `nltp_unpack_encrypted_frame_v`, `nltp_lz4_decompress_inplace`, `nltp_stun_parse_response`) validate frame length, cryptographic MAC, replay window, and cursor invariants prior to state mutation. |
| **Dead-Store-Safe Key Zeroization** | Dir 4.1 | **Compliant.** Ephemeral X25519 private keys (`sk_i`, `sk_r`), shared secrets (`dh`), and HKDF-style `prk` buffers are zeroized through `volatile uint8_t *` (`nltp_wipe_bytes`). |

---

## 2. Dynamic Memory Profile (`Dir 4.12` / `Rule 21.3`)

- In `src/nltp_wire.h`, `src/nltp_sha256.c`, and `src/nltp_net.c`: **zero** calls to `<stdlib.h>` allocation functions exist unconditionally.
- In `src/nltp_core.c`:
  - Primary LZ4 receive finalization (`rx_try_finalize`) uses zero-heap overlap-safe `nltp_lz4_decompress_inplace()` whenever the caller's receive buffer includes `NLTP_LZ4_INPLACE_MARGIN(comp_len)` (`(comp_len >> 8) + 32` bytes).
  - A host-convenience fallback (`malloc`/`free`) exists solely for tight host buffers lacking the in-place margin and is completely compiled out when `-DNLTP_NO_MALLOC` is defined (the default in `tier1-compliance.yml` KAT and fuzzing builds).
  - For safety-critical or MISRA-strict firmware builds, always pass `-DNLTP_NO_MALLOC` (and `-DNLTP_NO_DEFAULT_RANDOM` on bare-metal MCUs supplying `nltp_set_random()`).

---

## 3. Formal Deviation Register

In accordance with **MISRA C:2012 Section 5.4 (Deviations)**, the following deliberate engineering deviations are documented and justified for cryptographic and network-parser clarity:

### DEV-001: Early-Return Guard Clauses in Packet Parsers & Verifiers
- **MISRA Rule:** Rule 15.5 (*Advisory* — *"A function should have a single point of exit at the end"*)
- **Locations:** `nltp_unpack_encrypted_frame_v`, `nltp_lz4_decompress`, `nltp_lz4_decompress_inplace`, `nltp_replay_would_accept`, `nltp_replay_accept`, `nltp_on_datagram`, `rx_on_shard`, `sess_on_hello`, `sess_on_ack`, `nltp_stun_parse_response`.
- **Technical Justification:** Security-critical parsers processing untrusted network datagrams are significantly less error-prone when invalid lengths, bad magic bytes, replay rejections, and AEAD tag mismatches return `0` immediately at the point of check. Rewriting 10+ sequential validation gates into deeply nested `if (...) { if (...) { ... } }` pyramids or `goto cleanup` chains increases cyclomatic complexity and risks accidental fall-through past failed authentication checks. All functions with early returns hold no dynamically allocated resources (ephemeral secrets on `sess_on_hello`/`sess_on_ack` error paths are explicitly scrubbed with `nltp_wipe_bytes` prior to return).

### DEV-002: Bounded Pointer Indexing & Increment over Byte Buffers
- **MISRA Rule:** Rule 18.4 (*Advisory* — *"The `+`, `-`, `+=` and `-=` operators should not be applied to an expression of pointer type"*)
- **Locations:** Serialization offsets (`out_pkt + NLTP_ENC_HEADER_BYTES`, `raw + 4`, `buf + off`) across `src/nltp_wire.h`, `src/nltp_core.c`, and `src/nltp_net.c`.
- **Technical Justification:** Byte-offset addressing (`pkt + CONST_OFFSET`) is standard C99 idiom for fixed-offset wire headers (`20 B` AEAD header, `16 B` CRC header, `12 B` shard header) and avoids introducing superfluous slice structs. Every variable offset (`sp`, `dp`, `pos`) is verified against `len` / `buf_cap` / `expected_raw_len` before dereference and continuously verified under `ASan`/`UBSan` + `500,000`-iteration `libFuzzer` runs.

### DEV-003: `void *` Opaque Callback Context & `volatile uint8_t *` Zeroization Cast
- **MISRA Rule:** Rule 11.5 (*Advisory* — *"A conversion should not be performed from pointer to void into pointer to object"*)
- **Locations:** `nltp_wipe_bytes(void *buf, size_t n)` (`src/nltp_wire.h`) and user transport callbacks (`void *user`).
- **Technical Justification:** `nltp_wipe_bytes` converts `void *` to `volatile uint8_t *` (character type, permitted to alias any object representation under ISO C99 §6.5/7) to guarantee compiler optimization passes cannot elide secret-key zeroization. Opaque `void *user` context pointers allow zero-global reentrant transport integration without coupling `nltp_core.c` to BSD sockets, lwIP, or ESP-NOW headers.

### DEV-004: Bounded `snprintf` for `STREAM_META` JSON Serialization
- **MISRA Rule:** Rule 21.6 (*Required* — *"The Standard Library input/output functions shall not be used"*)
- **Locations:** `tx_start_common` and `json_find` in `src/nltp_core.c` (plus POSIX-only `/dev/urandom` reader guarded out on embedded targets).
- **Technical Justification:** `snprintf` formats strictly bounded integer fields (`%lu`) and sanitized ASCII filenames (`safe_name` restricts characters to `[A-Za-z0-9._-]`) into fixed-size stack/struct arrays (`uint8_t meta[352]`, `char pat[40]`), checking the return count `(n > 0 && (size_t)n < sizeof(tx->meta))`. No unbounded `sprintf`, `scanf`, or console `printf` calls exist anywhere in `src/`.

---

## 4. Reproducing the Static Analysis Audit

```bash
# Run Cppcheck general static analysis (strict zero-warning gate)
cppcheck --std=c99 --enable=warning,style,performance,portability \
         --inline-suppr --error-exitcode=1 \
         -DNLTP_NO_MALLOC -Isrc \
         src/nltp_core.c src/nltp_net.c src/nltp_sha256.c

# Run Cppcheck MISRA C:2012 rule checker addon
cppcheck --std=c99 --addon=misra -DNLTP_NO_MALLOC -Isrc \
         src/nltp_core.c src/nltp_net.c src/nltp_sha256.c
```
