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

  For more information, please refer to <http://unlicense.org/> */

#include <aes128_ctr.h>

#include <string.h>

/**
 * Sets the nonce for AES-128 CTR mode.
 */
void aes128_ctr_set(aes128_ctx* c, const void* nonce) {
    memset(c->ctr, 0, AES_BLK_LEN); // Clear the counter array
    memcpy(c->ctr, nonce, 12);      // Copy the 12-byte nonce to the counter
}

/**
 * Encrypts data using AES-128 in CTR mode.
 */
int aes128_ctr_encrypt(aes128_ctx* c, void* data, u32 len) {
    u8 i, r, t[AES_BLK_LEN], *p = (u8*)data;

    while (len) {
        // Copy counter+nonce to local buffer
        for (i = 0; i < AES_BLK_LEN; i++) t[i] = c->ctr[i];

        // Encrypt the counter using AES-128 ECB mode
        aes128_ecb_encrypt(c, t);

        // XOR plaintext with keystream block
        r = len > AES_BLK_LEN ? AES_BLK_LEN : len;
        for (i = 0; i < r; i++) p[i] ^= t[i];

        // Update length and data pointer
        len -= r;
        p += r;

        // Increment the counter
        for (i = AES_BLK_LEN; i != 0; i--) {
            if (++c->ctr[i - 1]) break;
            if (i == 1) return 0; // Counter overflow
        }
    }

    return 1;
}

/**
 * Decrypts data using AES-128 in CTR mode.
 */
int aes128_ctr_decrypt(aes128_ctx* c, void* data, u32 len) {
    return aes128_ctr_encrypt(c, data, len); // Same as encryption
}
