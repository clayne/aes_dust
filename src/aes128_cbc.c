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

#include <aes128_cbc.h>

/**
 * Encrypts data in-place using AES-128 in CBC mode.
 *
 * @param c     Pointer to the AES-128 context (must hold a valid IV in c->iv).
 * @param data  Pointer to the data buffer (plaintext) to encrypt.
 * @param len   Length in bytes of the data buffer (must be a multiple of AES_BLK_LEN).
 */
void aes128_cbc_encrypt(aes128_ctx* c, void* data, u32 len) {
    u8 *buf = (u8*)data;
    u8 *iv  = c->iv;

    while (len >= AES_BLK_LEN) {
        // XOR the current plaintext block with the IV (or previous ciphertext)
        for (u32 i = 0; i < AES_BLK_LEN; i++) {
            buf[i] ^= iv[i];
        }
        // Encrypt the block in-place using AES-128 ECB
        aes128_ecb_encrypt(c, buf);

        // Update IV to the ciphertext block just produced
        iv = buf;
        buf += AES_BLK_LEN;
        len -= AES_BLK_LEN;
    }

    // Update the IV in the AES context
    for (u32 i=0; i<AES_BLK_LEN; i++) c->iv[i] = iv[i];
}


/**
 * Decrypts data in-place using AES-128 in CBC mode.
 *
 * @param c     Pointer to the AES-128 context (must hold a valid IV in c->iv).
 * @param data  Pointer to the data buffer (ciphertext) to decrypt.
 * @param len   Length in bytes of the data buffer (must be a multiple of AES_BLK_LEN).
 */
void aes128_cbc_decrypt(aes128_ctx* c, void* data, u32 len) {
    u8 *buf = (u8*)data;
    u8 prev_iv[AES_BLK_LEN]; // to hold the previous ciphertext block
    u32 i;

    // Copy the original IV from the context
    for (i = 0; i < AES_BLK_LEN; i++) {
        prev_iv[i] = c->iv[i];
    }

    while (len >= AES_BLK_LEN) {
        u8 cur_cipher[AES_BLK_LEN];
        // Save current ciphertext block into cur_cipher
        for (i = 0; i < AES_BLK_LEN; i++) {
            cur_cipher[i] = buf[i];
        }

        // Decrypt the block in-place (ECB decryption)
        aes128_ecb_decrypt(c, buf);

        // XOR decrypted block with the previous ciphertext (or IV for the first block)
        for (i = 0; i < AES_BLK_LEN; i++) {
            buf[i] ^= prev_iv[i];
        }

        // Update prev_iv to current ciphertext block for next iteration
        for (i = 0; i < AES_BLK_LEN; i++) {
            prev_iv[i] = cur_cipher[i];
        }

        buf += AES_BLK_LEN;
        len -= AES_BLK_LEN;
    }

    // Update the IV in the AES context with the last processed ciphertext block
    for (i = 0; i < AES_BLK_LEN; i++) {
        c->iv[i] = prev_iv[i];
    }
}


