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

#ifndef AES128_ECB_H
#define AES128_ECB_H

#include <string.h>

#define AES_KEY_LEN 16
#define AES_BLK_LEN 16 
#define AES_IV_LEN  16
#define AES_CTR_LEN 16

#define R(v,n)(((v)>>(n))|((v)<<(32-(n))))

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef struct _aes128_ctx {
    u8 sbox[256];
    u8 sbox_inv[256];
    
    u8 ctr[AES_CTR_LEN];
    u8 iv[AES_IV_LEN];
    u8 rkeys[11][AES_KEY_LEN];
} aes128_ctx;

#ifdef __cplusplus
extern "C" {
#endif

void
aes128_init_ctx(aes128_ctx*);

void
aes128_set_iv(aes128_ctx*, void*);

void
aes128_set_key(aes128_ctx*, void*);

void 
aes128_ecb_encrypt(aes128_ctx*, void*);

void 
aes128_ecb_decrypt(aes128_ctx*, void*);

#ifdef __cplusplus
}
#endif

#endif

