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
#ifndef HASH_H_INCLUDED
#define HASH_H_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define HASH_DIGEST_SIZE 20

void hash_init(void);
void hash_update(const uint8_t *msg, size_t len);
void hash_final(uint8_t digest[HASH_DIGEST_SIZE]);

void h_init(const void* key, size_t key_len);
void h_update(const unsigned char *msg, size_t len);
void h_final(unsigned char hmac[HASH_DIGEST_SIZE]);

void pgm_hash_update(const void *pgm_ptr, size_t len);
void eep_hash_update(const void* eep_ptr, size_t len);

#endif // HASH_H_INCLUDED
