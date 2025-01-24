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

#ifndef AES128_GCM_H
#define AES128_GCM_H

#include "aes128_ecb.h"

#ifdef __cplusplus
extern "C" {
#endif

int aes128_gcm_encrypt(const u8 *key, u32 key_len, const u8 *iv, u32 iv_len,
	       const u8 *plain, u32 plain_len,
	       const u8 *aad, u32 aad_len, u8 *crypt, u8 *tag);
           
int aes128_gcm_decrypt(const u8 *key, u32 key_len, const u8 *iv, u32 iv_len,
	       const u8 *crypt, u32 crypt_len,
	       const u8 *aad, u32 aad_len, const u8 *tag, u8 *plain);
           
#ifdef __cplusplus
}
#endif

#endif
