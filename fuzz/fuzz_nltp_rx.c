/*
 * fuzz_nltp_rx.c — Continuous libFuzzer + ASan/UBSan Harness for NLTP v1.6.0
 *
 * Feeds mutated adversarial inputs into:
 *   1. Plaintext `nltp_on_datagram` endpoint (including valid-CRC synthesized framing so deep
 *      shard/FEC/STREAM_META/ACK/REFLEX parsers are exercised, not just rejected at CRC32!)
 *   2. Encrypted `nltp_on_datagram` endpoint (both raw mutated wire frames AND pre-established
 *      session-sealed mutated plaintexts so post-AEAD state machines are fuzzed!)
 *   3. `nltp_unpack_encrypted_frame_v` + RFC 6479 512-bit anti-replay window
 *   4. `nltp_lz4_decompress` and `nltp_lz4_decompress_inplace` (malicious expansion & corrupt offsets)
 *   5. `nltp_relay_unwrap` and `nltp_stun_parse_response`
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "nltp_wire.h"
#include "nltp_core.h"
#include "nltp_net.h"

typedef struct {
    uint32_t now_ms;
    uint32_t rng_state;
} fuzz_env_t;

static void fuzz_noop_send(void *user, const uint8_t *pkt, size_t len) {
    (void)user;
    (void)pkt;
    (void)len;
}

static uint32_t fuzz_now_ms(void *user) {
    fuzz_env_t *env = (fuzz_env_t *)user;
    env->now_ms += 3u;
    return env->now_ms;
}

static void fuzz_rng(void *user, uint8_t *out, size_t len) {
    fuzz_env_t *env = (fuzz_env_t *)user;
    size_t i;
    for (i = 0; i < len; ++i) {
        env->rng_state = env->rng_state * 1664525u + 1013904223u;
        out[i] = (uint8_t)(env->rng_state >> 24);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const uint8_t k_psk[32] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    static const uint8_t k_sess[32] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
    };
    static nltp_endpoint_t ep_plain;
    static nltp_endpoint_t ep_enc;
    static uint8_t rx_buf_plain[4096];
    static uint8_t rx_buf_enc[4096];
    static uint8_t synth[1460];
    static uint8_t lz4_out[1024];
    static uint8_t lz4_inplace[1024];
    fuzz_env_t env;

    if (!data || size == 0u || size > 1400u) return 0;

    env.now_ms = 1000u;
    env.rng_state = 0x12345678u ^ (uint32_t)size;

    /* 1. Plaintext endpoint: raw mutated frame + CRC-fixed frame for deep parser coverage */
    nltp_init(&ep_plain, 0x1111u, 10000u, fuzz_noop_send, fuzz_now_ms, &env);
    nltp_set_rx_buffer(&ep_plain, rx_buf_plain, sizeof(rx_buf_plain));
    nltp_on_datagram(&ep_plain, data, size);

    if (size >= 3u && size <= 1400u) {
        uint8_t ptype = (uint8_t)(data[0] & 0x0Fu);
        uint8_t flags = (uint8_t)(data[1] & 0x7Fu);
        size_t pl_len = size - 2u;
        nltp_pack_header(synth, ptype, flags, 0x2222u, 1020u, data + 2, pl_len);
        if (pl_len > 0u) memcpy(synth + NLTP_HEADER_BYTES, data + 2, pl_len);
        nltp_on_datagram(&ep_plain, synth, NLTP_HEADER_BYTES + pl_len);
        nltp_poll(&ep_plain);
    }

    /* 2. Encrypted endpoint: raw mutated wire frame + authenticated session-sealed mutated payload */
    nltp_init(&ep_enc, 0x3333u, 10000u, fuzz_noop_send, fuzz_now_ms, &env);
    nltp_set_random(&ep_enc, fuzz_rng);
    nltp_set_key(&ep_enc, k_psk);
    nltp_set_rx_buffer(&ep_enc, rx_buf_enc, sizeof(rx_buf_enc));
    nltp_on_datagram(&ep_enc, data, size);

    /* Install live session key to fuzz post-AEAD encrypted dispatch & anti-replay */
    ep_enc.sess[0].used = 1u;
    ep_enc.sess[0].role = 'r';
    ep_enc.sess[0].peer_cid = 0x4444u;
    memcpy(ep_enc.sess[0].k_rx, k_sess, 32u);
    memcpy(ep_enc.sess[0].k_tx, k_sess, 32u);
    nltp_replay_init(&ep_enc.sess[0].replay);

    if (size >= 3u && size <= 1040u) {
        uint8_t ptype = (uint8_t)(data[0] & 0x0Fu);
        uint8_t flags = (uint8_t)(data[1] & 0x7Fu);
        uint64_t seq = (uint64_t)data[2] + 1u;
        size_t pl_len = size - 3u;
        size_t n = nltp_pack_encrypted_frame_v(synth, k_sess, NLTP_SESSION_VERSION, ptype, flags,
                                               0x4444u, seq, 1050u, data + 3, pl_len);
        nltp_on_datagram(&ep_enc, synth, n);
        nltp_poll(&ep_enc);
    }

    /* 3. Direct AEAD unpacker + RFC 6479 replay window */
    {
        nltp_replay_window_t rw;
        uint8_t ptype = 0, flags = 0;
        uint32_t cid = 0, ts = 0;
        size_t pt_len = 0;
        nltp_replay_init(&rw);
        (void)nltp_unpack_encrypted_frame_v(data, size, k_sess, NLTP_SESSION_VERSION, &rw,
                                            &ptype, &flags, &cid, &ts, synth, &pt_len);
    }

    /* 4. Zero-heap LZ4 standard & in-place decompression under arbitrary malicious expansion */
    if (size >= 2u) {
        size_t target_raw = ((size_t)data[0] << 2) | 1u; /* 1..1021 bytes */
        size_t comp_len = size - 1u;
        if (target_raw > sizeof(lz4_out)) target_raw = sizeof(lz4_out);
        (void)nltp_lz4_decompress(data + 1, comp_len, lz4_out, target_raw);

        if (comp_len <= sizeof(lz4_inplace)) {
            size_t cap = sizeof(lz4_inplace);
            if (data[0] & 1u) {
                /* Also test tight / insufficient buffer capacities */
                cap = comp_len + (data[0] >> 2);
                if (cap > sizeof(lz4_inplace)) cap = sizeof(lz4_inplace);
            }
            memcpy(lz4_inplace, data + 1, comp_len);
            (void)nltp_lz4_decompress_inplace(lz4_inplace, cap, comp_len, target_raw);
        }
    }

    /* 5. Relay & STUN parsers */
    {
        static const uint8_t room_tag[16] = {0};
        static const uint8_t tid[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        uint8_t cmd = 0;
        const uint8_t *inner = 0;
        size_t inner_len = 0;
        uint32_t ip_be = 0;
        uint16_t port_be = 0;
        (void)nltp_relay_unwrap(data, size, room_tag, &cmd, &inner, &inner_len);
        (void)nltp_stun_parse_response(data, size, tid, &ip_be, &port_be);
    }

    return 0;
}
