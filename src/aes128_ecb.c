/**
  This is free and unencumbered software released into the public domain.
  
  Anyone is free to copy, modify, publish, use, compile, sell, or
  distribute this software, either in source code form or as a compiled
  binary, for any purpose, commercial or non-commercial, and by any
  means.
  
  In jurisdictions that recognize copyright laws, the author or authors
  of this software dedicate any and all copyright interest in the
  software to the public domain. We make this dedication for the benefit
  of the public at large and to the detriment of our heirs and
  successors. We intend this dedication to be an overt act of
  relinquishment in perpetuity of all present and future rights to this
  software under copyright law.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
  OTHER DEALINGS IN THE SOFTWARE.
  
  For more information, please refer to <http://unlicense.org/>
 */

#include <aes128_ecb.h>

/* Multiply each byte of x by 2 in GF(2^8) across the four bytes */
u32 M(u32 x) {
    u32 t = x & 0x80808080;
    return ((x ^ t) << 1) ^ ((t >> 7) * 0x1b);
}

/**
 * Initializes the AES context.
 * This function builds the S-box (c->sbox) for encryption and its inverse (c->sbox_inv)
 * for decryption. It only needs to be called once per context.
 */
void aes128_init_ctx(aes128_ctx* c) {
    u32 x = 1, i;
    u8 gf_exp[256];

    /* Build the GF(2^8) exponentiation lookup table */
    for (i = 0; i < 256; i++) {
        gf_exp[i] = (u8)x;
        x ^= M(x);
    }

    /* Generate the S-box */
    c->sbox[0] = 99;
    
    for (i = 0; i < 255; i++) {
        x = gf_exp[255 - i];
        x |= x << 8;
        x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7);
        c->sbox[gf_exp[i]] = (u8)((x ^ 99) & 0xFF);
    }
    
    /* Compute the inverse S-box */
    for (i = 0; i < 256; i++) {
        c->sbox_inv[c->sbox[i]] = (u8)i;
    }
}

void aes128_set_iv(aes128_ctx* c, void* iv) {
    memcpy(c->iv, iv, AES_IV_LEN);
}


/**
 * Creates round keys for AES-128 encryption.
 * This should be called after aes128_init_ctx() and before any encryption.
 */
void aes128_set_key(aes128_ctx* c, void* mk) {
    u32 i, w, k[4];
    u32 *rk = (u32*)c->rkeys;
    
    /* Copy master key (16 bytes = 4 words) into local buffer */
    for (i = 0; i < 4; i++) {
        k[i] = ((u32*)mk)[i];
    }
    
    /* Generate the round keys.
       The loop continues until the round constant (rc) equals 216.
       This should produce the 11 round keys (44 words) required for AES-128.
    */
    for (u32 rc = 1; rc != 216; rc = M(rc)) {
        /* Save the current key words as the next round key */
        for (i = 0; i < 4; i++) {
            rk[i] = k[i];
        }
        /* Expand the key:
           - Rotate the last word and substitute its bytes using the S-box.
           - Rotate the result and XOR with the round constant.
           - XOR the result into each of the key words.
         */
        w = k[3];
        
        for (i = 0; i < 4; i++) {
            w = (w & -256) | c->sbox[w & 255];
            w = R(w, 8);
        }
        w = R(w, 8) ^ rc;
        
        for (i = 0; i < 4; i++) {
            w = k[i] ^= w;
        }
        rk += 4;
    }
}

/**
 * Encrypts a single 16-byte block in-place using AES-128 in ECB mode.
 */
void aes128_ecb_encrypt(aes128_ctx* c, void* data) {
    u32 nr = 0, i, w;
    u32 x[4], *s = (u32*)data;
    u32 *rk = (u32*)c->rkeys;
    
    /* Copy input block into local state */
    for (i = 0; i < 4; i++) {
        x[i] = s[i];
    }

    /* Perform the rounds */
    for (;;) {
        /* AddRoundKey: XOR state with current round key */
        for (i = 0; i < 4; i++) {
            s[i] = x[i] ^ rk[i];
        }
        
        rk += 4;
        
        if (nr++ == 10)
            break;

        /* Combined SubBytes and ShiftRows:
           Process each byte in the 16-byte block. The index 'w' is updated
           using a cyclic shift (w = (w - 3) & 15) to achieve the ShiftRows effect.
        */
        for (w = i = 0; i < 16; i++) {
            ((u8*)x)[w] = c->sbox[((u8*)s)[i]];
            w = (w - 3) & 15;
        }
        if (nr != 10) {
            /* MixColumns transformation */
            for (i = 0; i < 4; i++) {
                w = x[i];
                x[i] = R(w, 8) ^ R(w, 16) ^ R(w, 24) ^ M(R(w, 8) ^ w);
            }
        }
    }
}

/**
 * Decrypts a single 16-byte block in-place using AES-128 in ECB mode.
 */
void aes128_ecb_decrypt(aes128_ctx* c, void* data) {
    u32 nr = 10, i, w;
    u32 x[4], *s = (u32*)data;
    /* Get pointer to the final round key.
       For AES-128 there are 11 round keys (each 4 words); the final round key starts at index 40.
    */
    u32 *rk = ((u32*)c->rkeys) + 40;

    /* Initial round: XOR ciphertext with final round key */
    for (i = 0; i < 4; i++) {
        s[i] ^= rk[i];
    }

    /* Perform 10 rounds of decryption */
    for (;;) {
        rk -= 4;
        /* Combined Inverse ShiftRows and Inverse SubBytes:
           Process the block in reverse order; 'w' is updated as (w + 3) & 15.
        */
        for (w = 0, i = 15; (int)i >= 0; i--) {
            w = (w + 3) & 15;
            ((u8*)x)[i] = c->sbox_inv[((u8*)s)[w]];
        }
        /* AddRoundKey */
        for (i = 0; i < 4; i++) {
            s[i] = x[i] ^ rk[i];
        }
        if (--nr == 0)
            break;
        /* Inverse MixColumns transformation */
        for (i = 0; i < 4; i++) {
            w = s[i];
            w ^= M(M(R(w, 16) ^ w));
            s[i] = R(w, 8) ^ R(w, 16) ^ R(w, 24) ^ M(R(w, 8) ^ w);
        }
    }
}
