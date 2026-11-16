/*
 * test_kat_vectors.c — Official NIST & IETF Cryptographic Known-Answer Tests (KAT)
 *                      and Lossy Encrypted Protocol Verification Suite for NLTP v1.6.0
 *
 * Standards verified:
 *   1. NIST FIPS 180-4   : SHA-256 (empty, "abc", 448-bit multi-block, 1,000,000 'a')
 *   2. IETF RFC 4231     : HMAC-SHA256 Test Cases 1, 2, 3, 6 & NLTP 1.5 X25519+PSK KDF
 *   3. IETF RFC 7748     : X25519 s5.2 scalar mult vectors, s6.1 DH & low-order point rejection
 *   4. IETF RFC 8439     : ChaCha20 s2.3.2/s2.4.2, Poly1305 s2.5.2, AEAD s2.8.2 & forgery rejection
 *   5. IETF RFC 6479     : 512-packet sliding anti-replay window boundaries & poisoning resistance
 *   6. IEEE 802.3 / FEC  : CRC32 check value & GF(2^8) Cauchy matrix invertibility over 0x11D
 *   7. LZ4 Raw Block     : Zero-heap compression, overlap-safe in-place decompression & bounds guards
 *   8. End-to-End NLTP   : X25519+PSK + ChaCha20-Poly1305 + Cauchy FEC under 30% packet loss + Reflex
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "nltp_wire.h"
#include "nltp_sha256.h"
#include "nltp_core.h"
#include "nltp_net.h"

static int g_checks_run = 0;
static int g_checks_failed = 0;

#define CHECK(cond, msg) do { \
    g_checks_run++; \
    if (!(cond)) { \
        fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        g_checks_failed++; \
    } \
} while (0)

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t from_hex(const char *hex, uint8_t *out, size_t max_len) {
    size_t n = 0;
    while (*hex && *(hex + 1) && n < max_len) {
        int hi = hex_nibble(hex[0]);
        int lo = hex_nibble(hex[1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

static int eq_hex(const uint8_t *buf, size_t len, const char *expected_hex) {
    uint8_t exp[256];
    size_t n;
    if (len > sizeof(exp)) return 0;
    n = from_hex(expected_hex, exp, sizeof(exp));
    return (n == len) && (memcmp(buf, exp, len) == 0);
}

/* -------------------------------------------------------------------------
 * 1. NIST FIPS 180-4 SHA-256 Known-Answer Vectors
 * ------------------------------------------------------------------------- */
static void test_nist_fips180_sha256(void) {
    char hex[65];
    nltp_sha256_t ctx;
    uint8_t digest[32];
    uint8_t chunk[137];
    size_t rem;

    /* Vector 1: Empty string "" */
    nltp_sha256_hex((const uint8_t *)"", 0u, hex);
    CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
          "FIPS 180-4 SHA-256 empty string");

    /* Vector 2: "abc" */
    nltp_sha256_hex((const uint8_t *)"abc", 3u, hex);
    CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
          "FIPS 180-4 SHA-256 'abc'");

    /* Vector 3: 448-bit two-block message */
    nltp_sha256_hex((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56u, hex);
    CHECK(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
          "FIPS 180-4 SHA-256 448-bit multi-block");

    /* Vector 4: 1,000,000 repetitions of 'a' fed in prime-sized 137-byte chunks */
    memset(chunk, 'a', sizeof(chunk));
    nltp_sha256_init(&ctx);
    rem = 1000000u;
    while (rem > 0u) {
        size_t take = rem < sizeof(chunk) ? rem : sizeof(chunk);
        nltp_sha256_update(&ctx, chunk, take);
        rem -= take;
    }
    nltp_sha256_final(&ctx, digest);
    CHECK(eq_hex(digest, 32u, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
          "FIPS 180-4 SHA-256 1,000,000 'a'");
}

/* -------------------------------------------------------------------------
 * 2. RFC 4231 HMAC-SHA256 & NLTP 1.5 Session KDF Vectors
 * ------------------------------------------------------------------------- */
static void test_rfc4231_hmac_and_kdf(void) {
    uint8_t key[131], data[64], mac[32];
    uint8_t psk[32], dh[32], n_i[16], n_r[16], kdf_msg[87], prk[32], k_i2r[32], k_r2i[32];
    uint8_t b64_key[32], pass_key[32];
    size_t i;

    /* RFC 4231 Test Case 1 */
    memset(key, 0x0bu, 20u);
    nltp_hmac_sha256(key, 20u, (const uint8_t *)"Hi There", 8u, mac);
    CHECK(eq_hex(mac, 32u, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
          "RFC 4231 HMAC-SHA256 Test Case 1");

    /* RFC 4231 Test Case 2 */
    nltp_hmac_sha256((const uint8_t *)"Jefe", 4u,
                     (const uint8_t *)"what do ya want for nothing?", 28u, mac);
    CHECK(eq_hex(mac, 32u, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
          "RFC 4231 HMAC-SHA256 Test Case 2");

    /* RFC 4231 Test Case 3 */
    memset(key, 0xaau, 20u);
    memset(data, 0xddu, 50u);
    nltp_hmac_sha256(key, 20u, data, 50u, mac);
    CHECK(eq_hex(mac, 32u, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
          "RFC 4231 HMAC-SHA256 Test Case 3");

    /* RFC 4231 Test Case 6 (131-byte key > 64-byte block size) */
    memset(key, 0xaau, 131u);
    nltp_hmac_sha256(key, 131u,
                     (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54u, mac);
    CHECK(eq_hex(mac, 32u, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
          "RFC 4231 HMAC-SHA256 Test Case 6 (key > 64B)");

    /* NLTP 1.5 X25519+PSK Session Key Derivation Determinism */
    for (i = 0; i < 32u; ++i) psk[i] = (uint8_t)(0x10u + i);
    from_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", dh, 32u);
    for (i = 0; i < 16u; ++i) {
        n_i[i] = (uint8_t)(0x01u + i);
        n_r[i] = (uint8_t)(0x21u + i);
    }
    memcpy(kdf_msg, "NLTP-1.5-X25519", 15u);
    memcpy(kdf_msg + 15, dh, 32u);
    memcpy(kdf_msg + 47, n_i, 16u);
    memcpy(kdf_msg + 63, n_r, 16u);
    nltp_write_u32_le(kdf_msg + 79, 0x11223345u);
    nltp_write_u32_le(kdf_msg + 83, 0x55667789u);
    nltp_hmac_sha256(psk, 32u, kdf_msg, sizeof(kdf_msg), prk);
    nltp_hmac_sha256(prk, 32u, (const uint8_t *)"i2r", 3u, k_i2r);
    nltp_hmac_sha256(prk, 32u, (const uint8_t *)"r2i", 3u, k_r2i);

    CHECK(eq_hex(prk, 32u, "6306595ae52f5df950e3ebdaa2d464fe047051fa0e38b54075e378f83c7c17e2"),
          "NLTP 1.5 KDF PRK vector");
    CHECK(eq_hex(k_i2r, 32u, "9b2408a16c17371feff864059f2c4f556d85d56f88592e61fe23f906e45f91fa"),
          "NLTP 1.5 KDF k_i2r vector");
    CHECK(eq_hex(k_r2i, 32u, "99494825a27dd99ddb4f57a236d4b62085656f0beedd06ec3255837b35f625ec"),
          "NLTP 1.5 KDF k_r2i vector");

    /* URL-safe base64 32-byte key vs passphrase derivation */
    nltp_key_from_psk("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", b64_key);
    for (i = 0; i < 32u; ++i) {
        if (b64_key[i] != (uint8_t)i) break;
    }
    CHECK(i == 32u, "nltp_key_from_psk URL-safe base64 decode");

    nltp_key_from_psk("  buoy-alpha-secret  ", pass_key);
    nltp_key_from_psk("buoy-alpha-secret", b64_key);
    CHECK(memcmp(pass_key, b64_key, 32u) == 0, "nltp_key_from_psk whitespace trim determinism");
}

/* -------------------------------------------------------------------------
 * 3. RFC 7748 X25519 Known-Answer Vectors & Low-Order Point Rejection
 * ------------------------------------------------------------------------- */
static void test_rfc7748_x25519(void) {
    uint8_t scalar[32], u[32], out[32];
    uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32], k_ab[32], k_ba[32];
    static const char *low_order_hex[7] = {
        /* u = 0 (order 2) */
        "0000000000000000000000000000000000000000000000000000000000000000",
        /* u = 1 (order 4) */
        "0100000000000000000000000000000000000000000000000000000000000000",
        /* order 8 point #1 */
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        /* order 8 point #2 */
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        /* u = p - 1 (order 2) */
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        /* u = p (non-canonical 0, order 2) */
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        /* u = p + 1 (non-canonical 1, order 4) */
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    };
    size_t i;

    /* RFC 7748 Section 5.2 Vector 1 */
    from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar, 32u);
    from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, 32u);
    CHECK(nltp_x25519_scalarmult(out, scalar, u) == 1, "RFC 7748 s5.2 Vector 1 return code");
    CHECK(eq_hex(out, 32u, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
          "RFC 7748 s5.2 Vector 1 output");

    /* RFC 7748 Section 5.2 Vector 2 */
    from_hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", scalar, 32u);
    from_hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u, 32u);
    CHECK(nltp_x25519_scalarmult(out, scalar, u) == 1, "RFC 7748 s5.2 Vector 2 return code");
    CHECK(eq_hex(out, 32u, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
          "RFC 7748 s5.2 Vector 2 output");

    /* RFC 7748 Section 6.1 Alice / Bob Ephemeral Diffie-Hellman */
    from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a_priv, 32u);
    from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b_priv, 32u);
    nltp_x25519_public_key(a_pub, a_priv);
    nltp_x25519_public_key(b_pub, b_priv);
    CHECK(eq_hex(a_pub, 32u, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
          "RFC 7748 s6.1 Alice public key");
    CHECK(eq_hex(b_pub, 32u, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
          "RFC 7748 s6.1 Bob public key");
    CHECK(nltp_x25519_scalarmult(k_ab, a_priv, b_pub) == 1, "RFC 7748 s6.1 Alice DH ok");
    CHECK(nltp_x25519_scalarmult(k_ba, b_priv, a_pub) == 1, "RFC 7748 s6.1 Bob DH ok");
    CHECK(memcmp(k_ab, k_ba, 32u) == 0, "RFC 7748 s6.1 DH symmetry");
    CHECK(eq_hex(k_ab, 32u, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
          "RFC 7748 s6.1 shared secret");

    /* RFC 7748 Section 6.1 Low-Order Points (orders 1, 2, 4, 8 + non-canonical) MUST return 0 */
    for (i = 0; i < 7u; ++i) {
        from_hex(low_order_hex[i], u, 32u);
        CHECK(nltp_x25519_scalarmult(out, a_priv, u) == 0,
              "RFC 7748 s6.1 low-order point rejected");
        CHECK(eq_hex(out, 32u, "0000000000000000000000000000000000000000000000000000000000000000"),
              "RFC 7748 s6.1 low-order point yields zero shared secret");
    }
}

/* -------------------------------------------------------------------------
 * 4. RFC 8439 ChaCha20, Poly1305 & AEAD Seal/Open + Forgery Rejection
 * ------------------------------------------------------------------------- */
static void poly1305_raw_rfc8439(const uint8_t otk32[32], const uint8_t *msg, size_t len, uint8_t tag16[16]) {
    nltp_poly1305_t ctx;
    size_t off = 0u;
    nltp_poly1305_init(&ctx, otk32);
    while (off + 16u <= len) {
        nltp_poly1305_block16(&ctx, msg + off);
        off += 16u;
    }
    if (off < len) {
        uint8_t tail[16];
        size_t i, rem = len - off;
        uint32_t r0 = ctx.r[0], r1 = ctx.r[1], r2 = ctx.r[2], r3 = ctx.r[3], r4 = ctx.r[4];
        uint32_t s1 = r1 * 5u, s2 = r2 * 5u, s3 = r3 * 5u, s4 = r4 * 5u;
        uint32_t h0, h1, h2, h3, h4, c;
        uint64_t d0, d1, d2, d3, d4;
        for (i = 0u; i < rem; ++i) tail[i] = msg[off + i];
        tail[rem] = 1u;
        for (i = rem + 1u; i < 16u; ++i) tail[i] = 0u;
        h0 = ctx.h[0] + ((nltp_read_u32_le(tail +  0)     ) & 0x3FFFFFFu);
        h1 = ctx.h[1] + ((nltp_read_u32_le(tail +  3) >> 2) & 0x3FFFFFFu);
        h2 = ctx.h[2] + ((nltp_read_u32_le(tail +  6) >> 4) & 0x3FFFFFFu);
        h3 = ctx.h[3] + ((nltp_read_u32_le(tail +  9) >> 6) & 0x3FFFFFFu);
        h4 = ctx.h[4] + ((nltp_read_u32_le(tail + 12) >> 8));
        d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3FFFFFFu; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3FFFFFFu; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3FFFFFFu; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3FFFFFFu; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3FFFFFFu; h0 += c * 5u;
        c = h0 >> 26;             h0 &= 0x3FFFFFFu;               h1 += c;
        ctx.h[0] = h0; ctx.h[1] = h1; ctx.h[2] = h2; ctx.h[3] = h3; ctx.h[4] = h4;
    }
    nltp_poly1305_finish(&ctx, tag16);
}

static void test_rfc8439_chacha20_poly1305(void) {
    static const char *sunscreen =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it.";
    uint8_t key[32], nonce[12], block64[64], ct[128], dec[128], aad[12], otk[32], tag[16];
    uint8_t pkt[64], out_pt[32], canary[32];
    nltp_replay_window_t rw;
    uint8_t pkt_type = 0, flags = 0;
    uint32_t cid = 0, ts = 0;
    size_t pt_len = 0, wire_len, i;

    /* RFC 8439 Section 2.3.2: ChaCha20 Block Function */
    for (i = 0; i < 32u; ++i) key[i] = (uint8_t)i;
    from_hex("000000090000004a00000000", nonce, 12u);
    nltp_chacha20_block(key, 1u, nonce, block64);
    CHECK(eq_hex(block64, 64u,
                 "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                 "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"),
          "RFC 8439 s2.3.2 ChaCha20 block");

    /* RFC 8439 Section 2.4.2: ChaCha20 Stream Encryption */
    from_hex("000000000000004a00000000", nonce, 12u);
    nltp_chacha20_xor(key, 1u, nonce, (const uint8_t *)sunscreen, ct, 114u);
    CHECK(eq_hex(ct, 114u,
                 "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                 "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                 "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                 "5af90bbf74a35be6b40b8eedf2785e42874d"),
          "RFC 8439 s2.4.2 ChaCha20 encryption");
    nltp_chacha20_xor(key, 1u, nonce, ct, dec, 114u);
    CHECK(memcmp(dec, sunscreen, 114u) == 0, "RFC 8439 s2.4.2 ChaCha20 round-trip");

    /* RFC 8439 Section 2.5.2: Poly1305 One-Time MAC */
    from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", otk, 32u);
    poly1305_raw_rfc8439(otk, (const uint8_t *)"Cryptographic Forum Research Group", 34u, tag);
    CHECK(eq_hex(tag, 16u, "a8061dc1305136c6c22b8baf0c0127a9"),
          "RFC 8439 s2.5.2 Poly1305 tag");

    /* RFC 8439 Section 2.8.2: AEAD_CHACHA20_POLY1305 */
    for (i = 0; i < 32u; ++i) key[i] = (uint8_t)(0x80u + i);
    from_hex("070000004041424344454647", nonce, 12u);
    from_hex("50515253c0c1c2c3c4c5c6c7", aad, 12u);
    nltp_chacha20_xor(key, 1u, nonce, (const uint8_t *)sunscreen, ct, 114u);
    nltp_aead_compute_tag(key, nonce, aad, 12u, ct, 114u, tag);
    CHECK(eq_hex(ct, 114u,
                 "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                 "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                 "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                 "3ff4def08e4b7a9de576d26586cec64b6116"),
          "RFC 8439 s2.8.2 AEAD ciphertext");
    CHECK(eq_hex(tag, 16u, "1ae10b594f09e26a7e902ecbd0600691"),
          "RFC 8439 s2.8.2 AEAD Poly1305 tag");

    /* NLTP v2 Encrypted Frame Vector & Authenticate-Before-Decrypt Checks */
    from_hex("9b2408a16c17371feff864059f2c4f556d85d56f88592e61fe23f906e45f91fa", key, 32u);
    nltp_write_u32_le(dec, 1000u);
    wire_len = nltp_pack_encrypted_frame_v(pkt, key, NLTP_SESSION_VERSION, NLTP_PT_PING, 0u,
                                           0x11223345u, 1u, 1000u, dec, 4u);
    CHECK(wire_len == 40u, "NLTP v2 encrypted PING wire length == 40B");
    CHECK(eq_hex(pkt, 40u,
                 "4e4c2880453322110100000000000000e80300009dc0f8334ee50dfbb2a72a3476367815995fb029"),
          "NLTP v2 encrypted PING wire vector");

    /* Forged ciphertext bit-flip MUST be rejected without modifying out_pt or replay_win */
    nltp_replay_init(&rw);
    memset(out_pt, 0xA5, sizeof(out_pt));
    memset(canary, 0xA5, sizeof(canary));
    pkt[21] ^= 0x01u;
    CHECK(nltp_unpack_encrypted_frame_v(pkt, 40u, key, NLTP_SESSION_VERSION, &rw,
                                        &pkt_type, &flags, &cid, &ts, out_pt, &pt_len) == 0,
          "Forged ciphertext rejected");
    CHECK(memcmp(out_pt, canary, sizeof(out_pt)) == 0,
          "Authenticate-before-decrypt: out_pt untouched on forged ciphertext");
    CHECK(rw.highest_seq == 0u,
          "Replay window unpoisoned on forged ciphertext");
    pkt[21] ^= 0x01u;

    /* Forged AAD header bit-flip (timestamp byte) MUST be rejected */
    pkt[16] ^= 0x01u;
    CHECK(nltp_unpack_encrypted_frame_v(pkt, 40u, key, NLTP_SESSION_VERSION, &rw,
                                        &pkt_type, &flags, &cid, &ts, out_pt, &pt_len) == 0,
          "Forged AAD header rejected");
    pkt[16] ^= 0x01u;

    /* Version downgrade (expecting v2, given v1) MUST be rejected */
    CHECK(nltp_unpack_encrypted_frame_v(pkt, 40u, key, NLTP_VERSION, &rw,
                                        &pkt_type, &flags, &cid, &ts, out_pt, &pt_len) == 0,
          "Version mismatch rejected");

    /* Authentic frame accepted once, exact replay rejected */
    CHECK(nltp_unpack_encrypted_frame_v(pkt, 40u, key, NLTP_SESSION_VERSION, &rw,
                                        &pkt_type, &flags, &cid, &ts, out_pt, &pt_len) == 1,
          "Authentic NLTP v2 encrypted frame accepted");
    CHECK(pkt_type == NLTP_PT_PING && cid == 0x11223345u && ts == 1000u && pt_len == 4u &&
          nltp_read_u32_le(out_pt) == 1000u,
          "Unpacked NLTP v2 fields match");
    CHECK(nltp_unpack_encrypted_frame_v(pkt, 40u, key, NLTP_SESSION_VERSION, &rw,
                                        &pkt_type, &flags, &cid, &ts, out_pt, &pt_len) == 0,
          "Replayed NLTP v2 encrypted frame rejected");
}

/* -------------------------------------------------------------------------
 * 5. RFC 6479 512-Packet Sliding Anti-Replay Window Boundary Tests
 * ------------------------------------------------------------------------- */
static void test_rfc6479_replay_window(void) {
    nltp_replay_window_t w;
    uint64_t probe_diffs[8] = {0u, 1u, 63u, 64u, 65u, 255u, 510u, 511u};
    size_t i;

    nltp_replay_init(&w);
    CHECK(nltp_replay_accept(&w, 0u) == 0, "RFC 6479 seq=0 always rejected");
    CHECK(nltp_replay_accept(&w, 1u) == 1, "RFC 6479 seq=1 accepted");
    CHECK(nltp_replay_accept(&w, 1u) == 0, "RFC 6479 seq=1 duplicate rejected");

    /* Advance window to 600: valid window is [89 .. 600], seq=88 (diff=512) must fail */
    CHECK(nltp_replay_accept(&w, 600u) == 1, "RFC 6479 advance to seq=600");
    CHECK(nltp_replay_accept(&w, 88u) == 0, "RFC 6479 seq=88 (diff=512) outside 512-bit window");

    for (i = 0; i < 8u; ++i) {
        uint64_t seq = 600u - probe_diffs[i];
        if (seq == 600u) {
            CHECK(nltp_replay_accept(&w, seq) == 0, "RFC 6479 seq=600 duplicate rejected");
        } else {
            CHECK(nltp_replay_accept(&w, seq) == 1, "RFC 6479 in-window out-of-order seq accepted");
            CHECK(nltp_replay_accept(&w, seq) == 0, "RFC 6479 in-window duplicate seq rejected");
        }
    }

    /* Jump >= 512 bits ahead (from 600 to 2048) */
    CHECK(nltp_replay_accept(&w, 2048u) == 1, "RFC 6479 jump >= 512 accepted");
    CHECK(nltp_replay_accept(&w, 600u) == 0, "RFC 6479 old seq=600 rejected after jump");
    CHECK(nltp_replay_accept(&w, 2048u - 511u) == 1, "RFC 6479 new window lower edge accepted");
    CHECK(nltp_replay_accept(&w, 2048u - 512u) == 0, "RFC 6479 new window outside edge rejected");
}

/* -------------------------------------------------------------------------
 * 6. IEEE 802.3 CRC32 & GF(2^8) Algebraic Cauchy FEC Axioms
 * ------------------------------------------------------------------------- */
static void test_crc32_and_gf256_cauchy(void) {
    uint8_t hdr[NLTP_HEADER_BYTES];
    uint8_t coeff0[8], coeff1[8];
    unsigned a, b, c;

    /* IEEE 802.3 standard check value on "123456789" */
    CHECK(nltp_crc32_ieee((const uint8_t *)"123456789", 9u, 0u) == 0xCBF43926u,
          "IEEE 802.3 CRC32('123456789') == 0xCBF43926");

    /* Plaintext NLTP PING header deterministic vector */
    {
        uint8_t pl[4];
        nltp_write_u32_le(pl, 1000u);
        nltp_pack_header(hdr, NLTP_PT_PING, 0u, 0x11223345u, 1000u, pl, 4u);
        CHECK(hdr[0] == 0x4Eu && hdr[1] == 0x4Cu && hdr[2] == 0x18u && hdr[3] == 0x00u,
              "NLTP v1 plaintext PING header framing");
    }

    /* GF(2^8) multiplicative inverse & distributivity over 0x11D */
    CHECK(nltp_gf256_inv(0u) == 0u, "GF(2^8) inv(0) == 0");
    for (a = 1u; a < 256u; ++a) {
        uint8_t inv = nltp_gf256_inv((uint8_t)a);
        CHECK(nltp_gf256_mul((uint8_t)a, inv) == 1u, "GF(2^8) a * inv(a) == 1");
    }
    for (a = 0u; a < 256u; a += 17u) {
        for (b = 0u; b < 256u; b += 29u) {
            for (c = 0u; c < 256u; c += 31u) {
                uint8_t lhs = nltp_gf256_mul((uint8_t)a, (uint8_t)(b ^ c));
                uint8_t rhs = (uint8_t)(nltp_gf256_mul((uint8_t)a, (uint8_t)b) ^
                                        nltp_gf256_mul((uint8_t)a, (uint8_t)c));
                CHECK(lhs == rhs, "GF(2^8) distributivity");
            }
        }
    }

    /* Cauchy row generation for parity_offset = 0 and 1 */
    nltp_cauchy_row(0u, 8u, coeff0);
    nltp_cauchy_row(1u, 8u, coeff1);
    CHECK(eq_hex(coeff0, 8u, "365ff8d5924ea604"), "Cauchy FEC row parity_offset=0 vector");
    CHECK(eq_hex(coeff1, 8u, "5f36d5f84e9204a6"), "Cauchy FEC row parity_offset=1 vector");
    for (c = 0u; c < 8u; ++c) {
        CHECK(coeff0[c] != 0u && coeff1[c] != 0u && coeff0[c] != coeff1[c],
              "Cauchy FEC rows non-zero and distinct");
    }
}

/* -------------------------------------------------------------------------
 * 7. Zero-Heap LZ4 Compression, In-Place Decompression & Adversarial Bounds
 * ------------------------------------------------------------------------- */
static void test_lz4_codec_and_bounds(void) {
    uint8_t raw[4096], comp[4200], out[4096], inplace[4096 + 128];
    uint32_t htab[1024];
    size_t i, comp_len;

    for (i = 0; i < sizeof(raw); ++i) {
        static const char pat[] = "{\"sensor\":\"buoy-01\",\"temp_mc\":24150,\"wave_mm\":312}\n";
        raw[i] = (uint8_t)pat[i % (sizeof(pat) - 1u)];
    }
    comp_len = nltp_lz4_compress(raw, sizeof(raw), comp, sizeof(comp), htab, 10u);
    CHECK(comp_len > 0u && comp_len < sizeof(raw) / 4u,
          "LZ4 compresses repetitive JSON telemetry >4x");

    CHECK(nltp_lz4_decompress(comp, comp_len, out, sizeof(raw)) == 1,
          "LZ4 standard decompression succeeds");
    CHECK(memcmp(raw, out, sizeof(raw)) == 0,
          "LZ4 standard decompression byte-exact match");

    memcpy(inplace, comp, comp_len);
    CHECK(nltp_lz4_decompress_inplace(inplace, sizeof(inplace), comp_len, sizeof(raw)) == 1,
          "LZ4 zero-heap in-place decompression succeeds");
    CHECK(memcmp(raw, inplace, sizeof(raw)) == 0,
          "LZ4 zero-heap in-place byte-exact match");

    /* Adversarial / malformed LZ4 streams MUST safely return 0 */
    {
        uint8_t bad_zero_off[6] = {0x10u, 'A', 0x00u, 0x00u, 0x10u, 'B'};
        uint8_t bad_oob_off[6]  = {0x10u, 'A', 0x05u, 0x00u, 0x10u, 'B'};
        uint8_t bad_trunc[4]    = {0xF0u, 255u, 255u, 255u};
        uint8_t bad_expand[8]   = {0x1Fu, 'A', 0x01u, 0x00u, 255u, 255u, 255u, 255u};
        uint8_t dst[64];

        CHECK(nltp_lz4_decompress(bad_zero_off, sizeof(bad_zero_off), dst, 16u) == 0,
              "LZ4 rejects offset == 0");
        CHECK(nltp_lz4_decompress(bad_oob_off, sizeof(bad_oob_off), dst, 16u) == 0,
              "LZ4 rejects offset > dp");
        CHECK(nltp_lz4_decompress(bad_trunc, sizeof(bad_trunc), dst, 64u) == 0,
              "LZ4 rejects truncated literal length");
        CHECK(nltp_lz4_decompress(bad_expand, sizeof(bad_expand), dst, 32u) == 0,
              "LZ4 rejects match length overflow");

        memcpy(dst, bad_expand, sizeof(bad_expand));
        CHECK(nltp_lz4_decompress_inplace(dst, sizeof(dst), sizeof(bad_expand), 32u) == 0,
              "LZ4 in-place rejects cursor overtake / expansion bomb");
    }
}

/* -------------------------------------------------------------------------
 * 8. Relay / STUN Helpers (`nltp_net.c`)
 * ------------------------------------------------------------------------- */
static void test_relay_and_stun(void) {
    uint8_t tag[16], wrapped[64], stun_req[20], stun_resp[32], tid[12];
    uint8_t cmd = 0;
    const uint8_t *inner = 0;
    size_t inner_len = 0, wn, i;
    uint32_t ip_be = 0;
    uint16_t port_be = 0;

    nltp_room_tag("ocean-buoy-7", tag);
    wn = nltp_relay_wrap(wrapped, sizeof(wrapped), tag, NLTP_RELAY_CMD_DATA,
                         (const uint8_t *)"NLTEST", 6u);
    CHECK(wn == NLTP_RELAY_HDR_BYTES + 6u, "Relay wrap length");
    CHECK(nltp_relay_unwrap(wrapped, wn, tag, &cmd, &inner, &inner_len) == 1 &&
          cmd == NLTP_RELAY_CMD_DATA && inner_len == 6u && memcmp(inner, "NLTEST", 6u) == 0,
          "Relay unwrap round-trip");

    for (i = 0; i < 12u; ++i) tid[i] = (uint8_t)(0x40u + i);
    nltp_stun_build_request(stun_req, tid);
    CHECK(nltp_is_stun(stun_req, sizeof(stun_req)) == 1, "STUN Binding Request recognized");

    /* Craft RFC 5389 Binding Success Response with XOR-MAPPED-ADDRESS for 203.0.113.42:54321 */
    memset(stun_resp, 0, sizeof(stun_resp));
    stun_resp[0] = 0x01u; stun_resp[1] = 0x01u; /* Binding Success */
    stun_resp[2] = 0x00u; stun_resp[3] = 0x0Cu; /* attr len = 12 */
    stun_resp[4] = 0x21u; stun_resp[5] = 0x12u; stun_resp[6] = 0xA4u; stun_resp[7] = 0x42u;
    memcpy(stun_resp + 8, tid, 12u);
    stun_resp[20] = 0x00u; stun_resp[21] = 0x20u; /* XOR-MAPPED-ADDRESS */
    stun_resp[22] = 0x00u; stun_resp[23] = 0x08u; /* len = 8 */
    stun_resp[24] = 0x00u; stun_resp[25] = 0x01u; /* IPv4 */
    {
        uint16_t xport = (uint16_t)(54321u ^ 0x2112u);
        uint32_t xip = 0xCB00712Au ^ 0x2112A442u;
        stun_resp[26] = (uint8_t)(xport >> 8);
        stun_resp[27] = (uint8_t)xport;
        stun_resp[28] = (uint8_t)(xip >> 24);
        stun_resp[29] = (uint8_t)(xip >> 16);
        stun_resp[30] = (uint8_t)(xip >> 8);
        stun_resp[31] = (uint8_t)xip;
    }
    CHECK(nltp_stun_parse_response(stun_resp, sizeof(stun_resp), tid, &ip_be, &port_be) == 1,
          "STUN XOR-MAPPED-ADDRESS parsed");
    {
        const uint8_t *ipp = (const uint8_t *)&ip_be;
        const uint8_t *pp = (const uint8_t *)&port_be;
        CHECK(ipp[0] == 203u && ipp[1] == 0u && ipp[2] == 113u && ipp[3] == 42u &&
              ((uint16_t)((pp[0] << 8) | pp[1])) == 54321u,
              "STUN decoded IPv4 203.0.113.42:54321");
    }
}

/* -------------------------------------------------------------------------
 * 9. Simulated Lossy Wire + Encrypted NLTP Loopback (30% Packet Loss)
 * ------------------------------------------------------------------------- */
#define WIRE_Q_CAP 256u

typedef struct {
    uint8_t data[NLTP_PKT_MAX + 96u];
    size_t len;
    int dst; /* 0 = ep_a, 1 = ep_b */
} wire_pkt_t;

typedef struct {
    uint32_t clock_ms;
    uint32_t prng;
    uint32_t drop_pct; /* 0..100, applied to DATA_SHARD & CRYPTIC_PARITY */
    uint32_t dropped_pkts;
    uint32_t delivered_pkts;
    wire_pkt_t q[WIRE_Q_CAP];
    size_t head, count;
} sim_bus_t;

typedef struct {
    sim_bus_t *bus;
    int peer_dst;
    uint32_t rng_ctr;
} node_ctx_t;

static uint32_t sim_rand32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static uint32_t sim_now_ms(void *user) {
    const node_ctx_t *nc = (const node_ctx_t *)user;
    return nc->bus->clock_ms;
}

static void sim_rng_bytes(void *user, uint8_t *out, size_t len) {
    node_ctx_t *nc = (node_ctx_t *)user;
    size_t i;
    for (i = 0; i < len; ++i) {
        nc->rng_ctr += 0x9E3779B9u;
        out[i] = (uint8_t)((sim_rand32(&nc->bus->prng) ^ nc->rng_ctr) & 0xFFu);
    }
}

static void sim_send_cb(void *user, const uint8_t *pkt, size_t len) {
    node_ctx_t *nc = (node_ctx_t *)user;
    sim_bus_t *bus = nc->bus;
    uint8_t ptype = (len >= 3u) ? (uint8_t)(pkt[2] & 0x0Fu) : 0u;

    if (bus->drop_pct > 0u &&
        (ptype == NLTP_PT_DATA_SHARD || ptype == NLTP_PT_CRYPTIC_PARITY)) {
        if ((sim_rand32(&bus->prng) % 100u) < bus->drop_pct) {
            bus->dropped_pkts++;
            return;
        }
    }
    if (bus->count < WIRE_Q_CAP && len <= sizeof(bus->q[0].data)) {
        size_t tail = (bus->head + bus->count) % WIRE_Q_CAP;
        memcpy(bus->q[tail].data, pkt, len);
        bus->q[tail].len = len;
        bus->q[tail].dst = nc->peer_dst;
        bus->count++;
    }
}

static void sim_pump(sim_bus_t *bus, nltp_endpoint_t *ep_a, nltp_endpoint_t *ep_b) {
    while (bus->count > 0u) {
        wire_pkt_t item = bus->q[bus->head];
        bus->head = (bus->head + 1u) % WIRE_Q_CAP;
        bus->count--;
        bus->delivered_pkts++;
        if (item.dst == 0) {
            nltp_on_datagram(ep_a, item.data, item.len);
        } else {
            nltp_on_datagram(ep_b, item.data, item.len);
        }
    }
}

#if NLTP_TX_ONLY
static void test_tx_only_profile_and_handshake(void) {
    static sim_bus_t bus;
    static nltp_endpoint_t ep_a, ep_b;
    node_ctx_t ctx_a, ctx_b;
    uint8_t key32[32], rbuf[64];
    uint16_t rlen = 0;
    uint32_t rcid = 0, rseq, step;

    printf("  [INFO] NLTP_TX_ONLY=1 sizeof(nltp_endpoint_t) = %lu bytes (sizeof(void*)=%lu)\n",
           (unsigned long)sizeof(nltp_endpoint_t), (unsigned long)sizeof(void *));
    /* 4,760 B on 64-bit LP64 hosts; <= 4,760 B on 32-bit ESP32/ESP8266/Cortex-M */
    if (sizeof(void *) == 8u) {
        CHECK(sizeof(nltp_endpoint_t) == 4760u, "NLTP_TX_ONLY=1 exact 4,760-byte static footprint");
    } else {
        CHECK(sizeof(nltp_endpoint_t) <= 4760u, "NLTP_TX_ONLY=1 <= 4,760-byte 32-bit MCU footprint");
    }

    memset(&bus, 0, sizeof(bus));
    bus.prng = 0xC0FFEE11u;
    ctx_a.bus = &bus; ctx_a.peer_dst = 1; ctx_a.rng_ctr = 0x1111u;
    ctx_b.bus = &bus; ctx_b.peer_dst = 0; ctx_b.rng_ctr = 0x2222u;

    nltp_key_from_psk("txonly-kat-psk-2026", key32);
    nltp_init(&ep_a, 0x1001u, 0u, sim_send_cb, sim_now_ms, &ctx_a);
    nltp_init(&ep_b, 0x2001u, 0u, sim_send_cb, sim_now_ms, &ctx_b);
    nltp_set_random(&ep_a, sim_rng_bytes);
    nltp_set_random(&ep_b, sim_rng_bytes);
    nltp_set_key(&ep_a, key32);
    nltp_set_key(&ep_b, key32);

    rseq = nltp_send_reflex(&ep_a, (const uint8_t *)"VALVE_SHUTOFF", 13u);
    CHECK(rseq == 1u, "TX_ONLY reflex queued and triggers X25519+PSK handshake");

    for (step = 0; step < 50u; ++step) {
        bus.clock_ms += 10u;
        nltp_poll(&ep_a);
        nltp_poll(&ep_b);
        sim_pump(&bus, &ep_a, &ep_b);
        if (nltp_reflex_acked(&ep_a, rseq)) break;
    }
    CHECK(ep_a.sessions_up >= 1u && ep_b.sessions_up >= 1u, "TX_ONLY X25519+PSK session established");
    CHECK(nltp_reflex_acked(&ep_a, rseq) == 1, "TX_ONLY reflex ACKed");
    CHECK(nltp_pop_reflex(&ep_b, rbuf, sizeof(rbuf), &rlen, &rcid) == 1 &&
          rlen == 13u && memcmp(rbuf, "VALVE_SHUTOFF", 13u) == 0,
          "TX_ONLY peer received authenticated reflex payload");
}
#else
static void test_encrypted_lossy_loopback(void) {
    static sim_bus_t bus;
    static nltp_endpoint_t tx_ep, rx_ep;
    static uint8_t tx_payload[24576];
    static uint8_t lz4_payload[16384];
    static uint8_t lz4_scratch[17000];
    static uint8_t rx_buf[24576 + 256];
    node_ctx_t ctx_tx, ctx_rx;
    uint8_t key32[32], low_hello[84], hello_pt[48], reflex_out[64];
    uint16_t reflex_len = 0;
    uint32_t reflex_cid = 0, rseq, sid, step;
    size_t i;

    printf("  [INFO] Full TX+RX sizeof(nltp_endpoint_t) = %lu bytes\n",
           (unsigned long)sizeof(nltp_endpoint_t));

    memset(&bus, 0, sizeof(bus));
    bus.prng = 0xBADC0DE5u;
    bus.drop_pct = 30u; /* 30% simulated random packet loss on shards & parity! */

    ctx_tx.bus = &bus; ctx_tx.peer_dst = 1; ctx_tx.rng_ctr = 0x13579BDFu;
    ctx_rx.bus = &bus; ctx_rx.peer_dst = 0; ctx_rx.rng_ctr = 0x2468ACE0u;

    for (i = 0; i < sizeof(tx_payload); ++i) {
        tx_payload[i] = (uint8_t)((i * 73u + (i >> 5) * 19u + 0x5Au) & 0xFFu);
    }
    for (i = 0; i < sizeof(lz4_payload); ++i) {
        static const char line[] = "ts=1763318400,ax=102,ay=-44,az=981,batt_mv=4120\n";
        lz4_payload[i] = (uint8_t)line[i % (sizeof(line) - 1u)];
    }

    nltp_key_from_psk("tier1-compliance-psk-secret", key32);
    nltp_init(&tx_ep, 0xAAAA0001u, 20000u, sim_send_cb, sim_now_ms, &ctx_tx);
    nltp_init(&rx_ep, 0xBBBB0001u, 20000u, sim_send_cb, sim_now_ms, &ctx_rx);
    nltp_set_random(&tx_ep, sim_rng_bytes);
    nltp_set_random(&rx_ep, sim_rng_bytes);
    nltp_set_key(&tx_ep, key32);
    nltp_set_key(&rx_ep, key32);
    nltp_set_rx_buffer(&rx_ep, rx_buf, sizeof(rx_buf));

    /* Verify endpoint rejects a PT_HELLO carrying an all-zero low-order X25519 public key */
    memset(hello_pt, 0x42, 16u);
    memset(hello_pt + 16, 0x00, 32u); /* pk_i = 0^32 low-order point */
    nltp_pack_encrypted_frame_v(low_hello, key32, NLTP_SESSION_VERSION, NLTP_PT_HELLO, 0u,
                                0xDEAD0001u, 99u, 10u, hello_pt, sizeof(hello_pt));
    nltp_on_datagram(&rx_ep, low_hello, sizeof(low_hello));
    CHECK(rx_ep.sessions_up == 0u, "Endpoint rejects PT_HELLO with low-order X25519 pk_i");

    /* Transfer #1: 24 KB raw binary stream + concurrent reflex emergency command under 30% loss */
    sid = nltp_send_buffer(&tx_ep, tx_payload, sizeof(tx_payload), "firmware.bin");
    CHECK(sid == 1u, "24 KB encrypted stream started");
    rseq = nltp_send_reflex(&tx_ep, (const uint8_t *)"EMERGENCY_BRAKE_NOW", 19u);
    CHECK(rseq == 1u, "Out-of-line reflex command queued alongside bulk transfer");

    for (step = 0; step < 2500u; ++step) {
        bus.clock_ms += 5u;
        nltp_poll(&tx_ep);
        nltp_poll(&rx_ep);
        sim_pump(&bus, &tx_ep, &rx_ep);
        if (nltp_tx_done(&tx_ep) && nltp_rx_done(&rx_ep) && nltp_reflex_acked(&tx_ep, rseq)) {
            break;
        }
    }

    printf("  [INFO] 30%% loss loopback #1: steps=%lu dropped=%lu delivered=%lu sessions=%lu\n",
           (unsigned long)step, (unsigned long)bus.dropped_pkts,
           (unsigned long)bus.delivered_pkts, (unsigned long)rx_ep.sessions_up);

    CHECK(bus.dropped_pkts > 0u, "Simulated 30% RF loss actually dropped shards");
    CHECK(nltp_rx_done(&rx_ep) == 1 && nltp_rx_sha_ok(&rx_ep) == 1,
          "Receiver reconstructed 24 KB stream with verified SHA-256 under 30% packet loss");
    CHECK(nltp_rx_len(&rx_ep) == sizeof(tx_payload) &&
          memcmp(rx_buf, tx_payload, sizeof(tx_payload)) == 0,
          "Reconstructed 24 KB payload matches byte-for-byte");
    CHECK(nltp_tx_verified(&tx_ep) == 1, "Sender received STREAM_FIN_ACK sha_ok=1");
    CHECK(nltp_reflex_acked(&tx_ep, rseq) == 1, "Out-of-line reflex command ACKed under 30% loss");
    CHECK(nltp_pop_reflex(&rx_ep, reflex_out, sizeof(reflex_out), &reflex_len, &reflex_cid) == 1 &&
          reflex_len == 19u && memcmp(reflex_out, "EMERGENCY_BRAKE_NOW", 19u) == 0,
          "Out-of-line reflex command delivered intact");

    /* Transfer #2: 16 KB LZ4-compressed telemetry stream under 30% packet loss (zero-heap in-place finalize) */
    memset(rx_buf, 0, sizeof(rx_buf));
    sid = nltp_send_buffer_lz4(&tx_ep, lz4_payload, sizeof(lz4_payload),
                               lz4_scratch, sizeof(lz4_scratch), "telemetry.csv");
    CHECK(sid == 2u, "16 KB LZ4 encrypted stream started");

    for (step = 0; step < 2500u; ++step) {
        bus.clock_ms += 5u;
        nltp_poll(&tx_ep);
        nltp_poll(&rx_ep);
        sim_pump(&bus, &tx_ep, &rx_ep);
        if (nltp_tx_done(&tx_ep) && nltp_rx_done(&rx_ep) && rx_ep.rx.stream_id == sid) {
            break;
        }
    }

    CHECK(nltp_rx_done(&rx_ep) == 1 && nltp_rx_sha_ok(&rx_ep) == 1,
          "Receiver reconstructed & in-place LZ4-decompressed 16 KB stream under 30% loss");
    CHECK(nltp_rx_len(&rx_ep) == sizeof(lz4_payload) &&
          memcmp(rx_buf, lz4_payload, sizeof(lz4_payload)) == 0,
          "Decompressed 16 KB LZ4 payload matches byte-for-byte");
}
#endif

int main(void) {
    printf("=== NLTP v1.6.0 Cryptographic KAT & Protocol Compliance Suite ===\n");
    test_nist_fips180_sha256();
    test_rfc4231_hmac_and_kdf();
    test_rfc7748_x25519();
    test_rfc8439_chacha20_poly1305();
    test_rfc6479_replay_window();
    test_crc32_and_gf256_cauchy();
    test_lz4_codec_and_bounds();
    test_relay_and_stun();
#if NLTP_TX_ONLY
    test_tx_only_profile_and_handshake();
#else
    test_encrypted_lossy_loopback();
#endif

    printf("=== Summary: %d/%d checks passed (%d failed) ===\n",
           g_checks_run - g_checks_failed, g_checks_run, g_checks_failed);
    return g_checks_failed == 0 ? 0 : 1;
}
