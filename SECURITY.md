# Security Policy

## Supported Versions

Security updates and cryptographic patches are actively maintained for the latest minor release series of `NLTP-Arduino` (and the underlying portable ANSI C99 `nltp` core):

| Version | Wire Protocol | Forward Secrecy (X25519+PSK) | Bounded Zero-Heap LZ4 | Supported |
| :--- | :--- | :---: | :---: | :---: |
| **1.6.x** | NLTP v1 / Session v2 | Yes | Yes | **Supported** |
| **1.5.x** | NLTP v1 / Session v2 | Yes | No | Security fixes only |
| **< 1.5.0** | Legacy Session v1 | Static PSK / early HKDF | No | Unsupported (upgrade to `1.6.0+`) |

## Reporting a Vulnerability

**Please do NOT report undisclosed security vulnerabilities through public GitHub issues, pull requests, or discussions.**

Instead, report suspected vulnerabilities privately through either of the following channels:

1. **GitHub Private Vulnerability Reporting (Preferred):**
   Submit a confidential advisory directly at:
   https://github.com/indian-aman/NLTP-Arduino/security/advisories/new
2. **Direct Maintainer Email:**
   Send a detailed report to **Amandeep Singh Bains** (`indianaman1.10.97@gmail.com`) with the subject line `[SECURITY][NLTP-Arduino] <brief summary>`.

### What to Include

To help reproduce and triage the issue rapidly, please include:
- Affected file(s), function name(s), and version / commit SHA.
- Target environment (e.g., `ESP32` / `ESP8266` / `STM32` / POSIX host, `NLTP_TX_ONLY=0` or `1`, encrypted vs. plaintext mode).
- Minimal proof-of-concept C snippet or hex datagram input (such as a `libFuzzer` crash reproducer for `fuzz/fuzz_nltp_rx.c`).
- Impact assessment (e.g., out-of-bounds read/write, nonce reuse, replay bypass, DoS / state exhaustion).

### Coordinated Disclosure & Response SLA

| Milestone | Target SLA |
| :--- | :--- |
| **Initial acknowledgment** | Within **48 hours** |
| **Triage, reproduction & CVSS v3.1 severity rating** | Within **5 business days** |
| **Patch release & regression test (`tests/test_kat_vectors.c`)** | Within **7 days** (Critical/High) / **30 days** (Medium/Low) |
| **Coordinated public GHSA disclosure** | Upon patch availability (or mutually agreed embargo up to 90 days) |

Reporters who follow coordinated disclosure will be credited in the GitHub Security Advisory and release notes unless anonymity is requested.

---

## Cryptographic & Memory-Safety Architecture

NLTP is engineered for untrusted RF links (`ESP-NOW v1/v2`, long-range 802.11 LR) and Internet/CGNAT UDP paths:

1. **1-RTT Forward-Secret Handshake (`NLTP_SESSION_VERSION = 2`):**
   - Mutual authentication and ephemeral key agreement combine **RFC 7748 X25519** with a 256-bit pre-shared key (`K`) and fresh 128-bit initiator/responder nonces (`n_i`, `n_r`), bound to both endpoints' 32-bit connection IDs (`cid_i`, `cid_r`):
     - `prk = HMAC-SHA256(K, "NLTP-1.5-X25519" || dh || n_i || n_r || LE32(cid_i) || LE32(cid_r))`
     - `k_i2r = HMAC-SHA256(prk, "i2r")`, `k_r2i = HMAC-SHA256(prk, "r2i")`
   - All low-order Curve25519 points resulting in an all-zero shared secret (`dh == 0^32`) are rejected per **RFC 7748 Section 6.1**.
   - Ephemeral private scalars (`sk_i`, `sk_r`), raw Diffie-Hellman output (`dh`), and intermediate `prk` material are scrubbed immediately via `volatile` byte zeroization (`nltp_wipe_bytes`).

2. **Authenticate-Before-Decrypt AEAD & Anti-Replay:**
   - Every encrypted frame carries a 20-byte cleartext AAD header (`"NL"`, `version_type`, `flags`, `conn_id`, `seq64`, `ts_ms`) authenticated by a 128-bit **RFC 8439 ChaCha20-Poly1305** tag under deterministic 96-bit nonce `LE32(conn_id) || LE64(seq64)`.
   - `nltp_unpack_encrypted_frame_v()` checks the **RFC 6479 512-packet sliding anti-replay window** non-destructively (`nltp_replay_would_accept`), verifies the 16-byte Poly1305 MAC in constant time (`diff |= calc_tag[i] ^ rx_tag[i]`), and commits the sequence bit (`nltp_replay_accept`) **before** ChaCha20 decryption ever touches the output plaintext buffer.
   - Legacy version-1 encrypted frames (`(version_type >> 4) != 2`) and unauthenticated plaintext frames are strictly dropped (`auth_drops++`) whenever a key is configured.

3. **DoS & Session-Hijack Mitigations:**
   - **Peer Address Pinning:** UDP and ESP-NOW wrappers update peer IP/port/MAC state only when `ep->valid_rx` increments (requiring valid AEAD authentication in encrypted mode).
   - **Candidate Session Staging (`sess[1]`):** While an active session (`sess[0]`) has received traffic within `SESS_TAKEOVER_MS` (`1000 ms`), a newly arriving `PT_HELLO` is staged in `sess[1]` and cannot displace `sess[0]` until subsequent session-authenticated traffic arrives.
   - **Rate-Limited Restart Hints (`PT_NO_SESSION`):** Unauthenticated restart hints are throttled to `HINT_INTERVAL_MS` (`250 ms`) and accepted only if the echoed `conn_id` matches the local endpoint and `0 < echoed_seq <= tx_seq`.
   - **Post-AEAD Bounded LZ4 & SHA-256:** `nltp_lz4_decompress_inplace()` enforces strict input/output bounds and read-before-write cursor invariants (`dp + match_len <= sp`), followed by full-payload **NIST FIPS 180-4 SHA-256** verification before `sha_ok` is asserted.

## Continuous Security Verification

Every push and pull request in `.github/workflows/tier1-compliance.yml` executes:
- **Official Cryptographic KATs (`tests/test_kat_vectors.c`):** RFC 7748, RFC 8439, RFC 4231, NIST FIPS 180-4, RFC 6479 anti-replay boundaries, and 30%-loss encrypted loopback under `AddressSanitizer` (`ASan`) and `UndefinedBehaviorSanitizer` (`UBSan`).
- **Continuous Fuzzing (`fuzz/fuzz_nltp_rx.c`):** `500,000` mutated adversarial frames per CI run via `clang -fsanitize=fuzzer,address,undefined`.
- **MISRA C:2012 Static Analysis:** `cppcheck` + MISRA C:2012 rule checking (`docs/MISRA_C_2012_COMPLIANCE.md`).
- **Supply-Chain Attestation:** SPDX 2.3 (`sbom.spdx.json`), CycloneDX 1.5 (`sbom.cdx.json`), OpenSSF Scorecard, and GitHub SLSA Build Provenance (`actions/attest-build-provenance`).
