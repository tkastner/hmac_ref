// Copyright (C) 2012 IAIK, Graz University of Technology
// Authors: Paul Wiegele <wiegele@student.tugraz.at>
//          Johannes Winter <johannes.winter@iaik.tugraz.at>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
// FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
#include "sha.h"

#include <string.h>

/// Output padding
static uint8_t g_k_opad[64];

//----------------------------------------------------------------------
void hmac_init(const void* key, size_t key_len)
{
  memset(g_k_opad, 0, sizeof(g_k_opad));

  // Key scheduling
  if (key_len > sizeof(g_k_opad)) {
    // Hash the key
    hash_init();
    hash_update(key, key_len);
    hash_final(g_k_opad);

  } else {
    // Copy the key
    memcpy(g_k_opad, key, key_len);
  }

  // Start the inner hash thread
  hash_init();

  // Inner padding (ipad)
  for (size_t n = 0; n < sizeof(g_k_opad); ++n) {
    g_k_opad[n] ^= 0x36;
  }

  hash_update(g_k_opad, sizeof(g_k_opad));
}

//----------------------------------------------------------------------
void hmac_update(const uint8_t *msg, size_t len)
{
  hash_update(msg, len);
}

//----------------------------------------------------------------------
void hmac_final(uint8_t hmac[HASH_DIGEST_SIZE])
{
  // Finish inner hash
  hash_final(hmac);

  // Outer hash
  hash_init();

  // Outer padding (opad) from inner padding
  for (size_t n = 0; n < sizeof(g_k_opad); ++n) {
    g_k_opad[n] ^= (0x36 ^ 0x5C);
  }

  // Finish HMAC
  hash_update(hmac, HASH_DIGEST_SIZE);
  hash_final(hmac);

  // Cleanup
  memset(g_k_opad, 0, sizeof(g_k_opad));
}
