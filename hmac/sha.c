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

# include <string.h>

typedef struct {
    uint32_t H[5];
    uint32_t A, B, C, D, E;
    uint32_t W[16];
    uint8_t msg[64];
    uint8_t msg_idx;
    uint32_t len_upper;
    uint32_t len_lower;
} SHACtx;

// Global hash instance
static SHACtx g_sha1;

//----------------------------------------------------------------------
static inline uint32_t cshift(uint32_t x, uint32_t n)
{
  return (((x) << (n)) | ((x) >> (32-(n))));
}

//----------------------------------------------------------------------
static uint32_t sha1_f(uint8_t t, uint32_t B, uint32_t C, uint32_t D)
{
  if (t <= 19) {
    return (B & C) | (~B & D);
  } else if (t <= 39) {
    return B ^ C ^ D;
  } else if (t <= 59) {
    return (B & C) | (B & D) | (C & D);
  } else { /* if( (40 <= t) && ( t <= 79) ) */
    return B ^ C ^ D;
  }
}

//----------------------------------------------------------------------
static uint32_t sha1_K(uint8_t t)
{
  if(t <= 19) {
    return 0x5A827999;
  } else if (t <= 39) {
    return 0x6ED9EBA1;
  } else if (t <= 59) {
    return 0x8F1BBCDC;
  } else { /* if( (40 <= t) && ( t <= 79) ) */
    return 0xCA62C1D6;
  }
}

//----------------------------------------------------------------------
static int sha1_process(void)
{
  //lower nibble of t
  //uint8_t helper = 0;

  //a. reorder msg into W array
  uint8_t *src = g_sha1.msg;

  for (uint8_t t = 0; t < 16; t++) {
      uint32_t temp = (uint32_t)(*src++) << 24;
      temp |= (uint32_t)(*src++) << 16;
      temp |= (uint32_t)(*src++) << 8;
      temp |= (uint32_t)(*src++);
      g_sha1.W[t] = temp;
  }

  //b. copy H[0...4] to A...E
  g_sha1.A = g_sha1.H[0];
  g_sha1.B = g_sha1.H[1];
  g_sha1.C = g_sha1.H[2];
  g_sha1.D = g_sha1.H[3];
  g_sha1.E = g_sha1.H[4];

  for (uint8_t t = 0; t < 80; t++) {
    uint8_t s = t & 0xF;
    if(t >= 16) {
        g_sha1.W[s] = cshift( g_sha1.W[ (s+13) & 0xF ] ^
                              g_sha1.W[ (s+ 8) & 0xF ] ^
                              g_sha1.W[ (s+ 2) & 0xF ] ^
                              g_sha1.W[ s ], 1);
    }

    uint32_t temp = cshift(g_sha1.A, 5) +
        sha1_f(t, g_sha1.B, g_sha1.C, g_sha1.D) +
        g_sha1.E +
        g_sha1.W[s] +
        sha1_K(t);

    // E=D, D=C, C=S^30(B), B=A, A=TEMP
    g_sha1.E = g_sha1.D;
    g_sha1.D = g_sha1.C;
    g_sha1.C = cshift(g_sha1.B, 30);
    g_sha1.B = g_sha1.A;
    g_sha1.A = temp;
 }

  // H[0..4] = H[0..4] + {A, B, C, D, E}
  g_sha1.H[0] += g_sha1.A;
  g_sha1.H[1] += g_sha1.B;
  g_sha1.H[2] += g_sha1.C;
  g_sha1.H[3] += g_sha1.D;
  g_sha1.H[4] += g_sha1.E;
  g_sha1.msg_idx = 0;
  return 1;
}

//----------------------------------------------------------------------
static void sha1_input( const uint8_t *msg, unsigned int len)
{
    // Store msg within SHA context
    while (len--) {
        g_sha1.msg[g_sha1.msg_idx++] = *msg++;

        // keep track of all the bits we allready processed
        g_sha1.len_lower += 8;
        if(g_sha1.len_lower == 0) { //if we encounter a overflow
            g_sha1.len_upper += 8;
        }

        // We have filled the entire block
        if(g_sha1.msg_idx == 64) {
            sha1_process();
        }
    }
}

//----------------------------------------------------------------------
static void sha1_padding(void)
{
  uint8_t temp;

  // check of padding fits the current msg block
  // msg + 0x80 + overall_length
  if(g_sha1.msg_idx + 1 + 8 < 64 ) {
      g_sha1.msg[g_sha1.msg_idx++] = 0x80;
      //fill in zeros
      while(g_sha1.msg_idx <= 55) {
          g_sha1.msg[g_sha1.msg_idx++] = 0x00;
      }

  } else {
      //if we are not able to fit the padding in this
      //we have to create a new one

      //what happens here if msg_idx is allready 63?
      g_sha1.msg[g_sha1.msg_idx++] = 0x80;

      //fill current block with zeros
      while(g_sha1.msg_idx <= 63) {
          g_sha1.msg[g_sha1.msg_idx++] = 0x00;
      }

      sha1_process();

      //fill the new block with zeros
      while(g_sha1.msg_idx <= 55) {
          g_sha1.msg[g_sha1.msg_idx++] = 0x00;
      }
  }

  // write len_upper byte-wise to msg array
  temp = 4;
  do {
      temp--;
      g_sha1.msg[g_sha1.msg_idx++] = (g_sha1.len_upper >> 8*temp) & 0xFF;
  } while(temp != 0 );

  // write len_lower byte-wise to msg array
  temp = 4;
  do {
      temp--;
      g_sha1.msg[g_sha1.msg_idx++] = (g_sha1.len_lower >> 8*temp) & 0xFF;
  } while (temp != 0 );
}

//----------------------------------------------------------------------
void hash_init(void)
{
    memset(&g_sha1, 0, sizeof(g_sha1));
    g_sha1.H[0] = 0x67452301;
    g_sha1.H[1] = 0xEFCDAB89;
    g_sha1.H[2] = 0x98BADCFE;
    g_sha1.H[3] = 0x10325476;
    g_sha1.H[4] = 0xC3D2E1F0;
}

//----------------------------------------------------------------------
void hash_update(const uint8_t *msg, size_t len)
{
    do {
        size_t block_len = (len > 64)? 64 : len;
        sha1_input(msg, block_len);
        msg += block_len;
        len -= block_len;
    } while (len > 0);
}

//----------------------------------------------------------------------
void hash_final(uint8_t digest[HASH_DIGEST_SIZE])
{
    // Pad and process the final block
    sha1_padding();
    sha1_process();

    // Write the hash in proper endianess
    uint8_t *dst = digest;
    for (uint8_t i = 0; i < 5; i++) {
        *dst++ = g_sha1.H[i] >> 24;
        *dst++ = g_sha1.H[i] >> 16;
        *dst++ = g_sha1.H[i] >> 8;
        *dst++ = g_sha1.H[i];
    }

    memset(&g_sha1, 0, sizeof(g_sha1));
}
