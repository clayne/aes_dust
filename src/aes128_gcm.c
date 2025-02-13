/**
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

#include <aes128_gcm.h>

#ifndef BIT
#define BIT(x) (1U << (x))
#endif

/* --- Utility functions for Big-Endian conversions --- */
static inline u32 GET_BE32(const u8 *a) {
    return ((u32)a[0] << 24) | ((u32)a[1] << 16) | ((u32)a[2] << 8) | ((u32)a[3]);
}

static inline void PUT_BE32(u8 *a, u32 val) {
    a[0] = (u8)((val >> 24) & 0xff);
    a[1] = (u8)((val >> 16) & 0xff);
    a[2] = (u8)((val >> 8) & 0xff);
    a[3] = (u8)(val & 0xff);
}

static inline u64 GET_BE64(const u8 *a) {
    return (((u64)a[0]) << 56) | (((u64)a[1]) << 48) |
           (((u64)a[2]) << 40) | (((u64)a[3]) << 32) |
           (((u64)a[4]) << 24) | (((u64)a[5]) << 16) |
           (((u64)a[6]) << 8)  | ((u64)a[7]);
}

static inline void PUT_BE64(u8 *a, u64 val) {
    for (int i = 7; i >= 0; --i) {
        a[i] = (u8)(val & 0xff);
        val >>= 8;
    }
}

/* --- GCM Helper Functions --- */

/* Increment the last 32 bits (big-endian) of a 16-byte block. */
static void inc32(u8 *block) {
    u32 val = GET_BE32(block + 12);
    val++;
    PUT_BE32(block + 12, val);
}

/* XOR two 16-byte blocks (dst ^= src). */
static void xor_block(u8 *dst, const u8 *src) {
    for (int i = 0; i < AES_BLK_LEN; i++) {
        dst[i] ^= src[i];
    }
}

/* Shift a 16-byte block right by one bit.
 * This function treats the block as four 32-bit big-endian words.
 */
static void shift_right_block(u8 *v) {
    u32 val;
    for (int i = 12; i >= 0; i -= 4) {
        val = GET_BE32(v + i);
        val >>= 1;
        if (i > 0 && (v[i - 1] & 0x01))
            val |= 0x80000000;
        PUT_BE32(v + i, val);
    }
}

/* Multiply two 128-bit values (x and y) in GF(2^128) as used in GCM.
 * z = x * y.
 */
static void gf_mult(const u8 *x, const u8 *y, u8 *z) {
    u8 v[16];
    int i, j;
    memset(z, 0, AES_BLK_LEN);
    memcpy(v, y, AES_BLK_LEN);

    for (i = 0; i < AES_BLK_LEN; i++) {
        for (j = 0; j < 8; j++) {
            if (x[i] & BIT(7 - j)) {
                xor_block(z, v);
            }
            if (v[15] & 0x01) {
                shift_right_block(v);
                v[0] ^= 0xe1;
            } else {
                shift_right_block(v);
            }
        }
    }
}

/* Initialize a GHASH accumulator to zero. */
static void ghash_start(u8 *y) {
    memset(y, 0, AES_BLK_LEN);
}

/* Compute GHASH(H, X) where X is xlen bytes.
 * The result is accumulated in y.
 */
static void ghash(const u8 *h, const u8 *x, u32 xlen, u8 *y) {
    u32 m = xlen / AES_BLK_LEN;
    const u8 *xpos = x;
    u8 tmp[AES_BLK_LEN];

    for (u32 i = 0; i < m; i++) {
        xor_block(y, xpos);
        xpos += AES_BLK_LEN;
        gf_mult(y, h, tmp);
        memcpy(y, tmp, AES_BLK_LEN);
    }

    /* Process any remaining partial block */
    if ((x + xlen) > xpos) {
        size_t last = (x + xlen) - xpos;
        memcpy(tmp, xpos, last);
        memset(tmp + last, 0, AES_BLK_LEN - last);
        xor_block(y, tmp);
        gf_mult(y, h, tmp);
        memcpy(y, tmp, AES_BLK_LEN);
    }
}

/* GCTR function as specified in GCM.
 * Given an initial counter block (icb), encrypt x (of length xlen bytes)
 * to produce output y.
 */
static void aes_gctr(void *ctx, const u8 *icb, const u8 *x, u32 xlen, u8 *y) {
    u32 n = xlen / AES_BLK_LEN;
    u32 last = xlen % AES_BLK_LEN;
    u8 cb[AES_BLK_LEN], tmp[AES_BLK_LEN];
    const u8 *xpos = x;
    u8 *ypos = y;

    if (xlen == 0)
        return;

    memcpy(cb, icb, AES_BLK_LEN);

    for (u32 i = 0; i < n; i++) {
        memcpy(ypos, cb, AES_BLK_LEN);
        aes128_ecb_encrypt(ctx, ypos);
        xor_block(ypos, xpos);
        xpos += AES_BLK_LEN;
        ypos += AES_BLK_LEN;
        inc32(cb);
    }

    if (last) {
        memcpy(tmp, cb, AES_BLK_LEN);
        aes128_ecb_encrypt(ctx, tmp);
        for (u32 i = 0; i < last; i++) {
            ypos[i] = xpos[i] ^ tmp[i];
        }
    }
}

/* --- Initialization Helpers --- */

/* Initialize the AES context with the given key. */
static void aes_encrypt_init(aes128_ctx *ctx, const u8 *key, u32 key_len) {
    aes128_init_ctx(ctx);
    aes128_set_key(ctx, (void *)key);
}

/* Initialize the hash subkey H for GCM.
 * H = AES-128(0^128)
 */
static void aes_gcm_init_hash_subkey(aes128_ctx *ctx, const u8 *key, u32 key_len, u8 *H) {
    aes_encrypt_init(ctx, key, key_len);
    memset(H, 0, AES_BLK_LEN);
    aes128_ecb_encrypt(ctx, H);
}

/* Prepare the pre-counter block J0.
 * If IV is 12 bytes, then J0 = IV || 0x00000001.
 * Otherwise, J0 = GHASH(H, IV || padding || [0^64 || (IV_bit_length)]).
 */
static void aes_gcm_prepare_j0(const u8 *iv, u32 iv_len, const u8 *H, u8 *J0) {
    u8 len_buf[AES_BLK_LEN];

    if (iv_len == 12) {
        memcpy(J0, iv, iv_len);
        memset(J0 + iv_len, 0, AES_BLK_LEN - iv_len);
        J0[AES_BLK_LEN - 1] = 0x01;
    } else {
        ghash_start(J0);
        ghash(H, iv, iv_len, J0);
        PUT_BE64(len_buf, 0);
        PUT_BE64(len_buf + 8, iv_len * 8);
        ghash(H, len_buf, AES_BLK_LEN, J0);
    }
}

/* A helper that increments J0 and then calls GCTR.
 */
static void aes_gcm_gctr(void *aes, const u8 *J0, const u8 *in, u32 len, u8 *out) {
    u8 J0inc[AES_BLK_LEN];

    if (len == 0)
        return;

    memcpy(J0inc, J0, AES_BLK_LEN);
    inc32(J0inc);
    aes_gctr(aes, J0inc, in, len, out);
}

/* Compute GHASH over AAD and ciphertext.
 * S = GHASH(H, AAD || C || [bit lengths])
 */
static void aes_gcm_ghash(const u8 *H, const u8 *aad, u32 aad_len,
                          const u8 *crypt, u32 crypt_len, u8 *S) {
    u8 len_buf[AES_BLK_LEN];

    ghash_start(S);
    ghash(H, aad, aad_len, S);
    ghash(H, crypt, crypt_len, S);
    PUT_BE64(len_buf, aad_len * 8);
    PUT_BE64(len_buf + 8, crypt_len * 8);
    ghash(H, len_buf, AES_BLK_LEN, S);
}

/* --- GCM Public Functions --- */

/* AES-128 GCM Encryption.
 * Inputs:
 *   key, key_len: AES key.
 *   iv, iv_len: Initialization vector.
 *   plain, plain_len: Plaintext.
 *   aad, aad_len: Additional authenticated data.
 * Outputs:
 *   crypt: Ciphertext (same length as plaintext).
 *   tag: Authentication tag (16 bytes).
 * Returns 0 on success.
 */
int aes128_gcm_encrypt(const u8 *key, u32 key_len, const u8 *iv, u32 iv_len,
                       const u8 *plain, u32 plain_len, const u8 *aad, u32 aad_len,
                       u8 *crypt, u8 *tag) {
    u8 H[AES_BLK_LEN], J0[AES_BLK_LEN], S[AES_BLK_LEN];
    aes128_ctx ctx;

    aes_gcm_init_hash_subkey(&ctx, key, key_len, H);
    aes_gcm_prepare_j0(iv, iv_len, H, J0);
    aes_gcm_gctr(&ctx, J0, plain, plain_len, crypt);
    aes_gcm_ghash(H, aad, aad_len, crypt, plain_len, S);
    aes_gctr(&ctx, J0, S, AES_BLK_LEN, tag);

    return 0;
}

/* AES-128 GCM Decryption.
 * Inputs:
 *   key, key_len: AES key.
 *   iv, iv_len: Initialization vector.
 *   crypt, crypt_len: Ciphertext.
 *   aad, aad_len: Additional authenticated data.
 *   tag: Authentication tag (16 bytes).
 * Outputs:
 *   plain: Decrypted plaintext (same length as ciphertext).
 * Returns 0 if authentication succeeds, -1 if authentication fails.
 */
int aes128_gcm_decrypt(const u8 *key, u32 key_len, const u8 *iv, u32 iv_len,
                       const u8 *crypt, u32 crypt_len, const u8 *aad, u32 aad_len,
                       const u8 *tag, u8 *plain) {
    u8 H[AES_BLK_LEN], J0[AES_BLK_LEN], S[AES_BLK_LEN], T[AES_BLK_LEN];
    aes128_ctx ctx;

    aes_gcm_init_hash_subkey(&ctx, key, key_len, H);
    aes_gcm_prepare_j0(iv, iv_len, H, J0);
    aes_gcm_gctr(&ctx, J0, crypt, crypt_len, plain);
    aes_gcm_ghash(H, aad, aad_len, crypt, crypt_len, S);
    aes_gctr(&ctx, J0, S, AES_BLK_LEN, T);

    return (memcmp(tag, T, AES_BLK_LEN) != 0) ? -1 : 0;
}
