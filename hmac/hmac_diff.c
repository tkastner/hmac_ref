/*
 * hmac.c
 *
 *  Created on: Oct 19, 2013
 *      Author: thms
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "sha.h"

#define HASH_DIGEST_SIZE 20

/// Output padding
static unsigned char g_k_opad[64];

int main() {

	unsigned char ordinal[4] = { 0x00, 0x00, 0x00, 0x17 };

	HMAC_CTX hmac;

	unsigned char shared_secret[20] = { 0x42, 0xAC ,0xAF, 0xF1, 0xD4 ,0x99, 0x3C, 0xCA, 0xC9, 0x00, 0x3C, 0xCA, 0xC8, 0x00, 0x3C, 0xCA, 0xC8, 0x00, 0x3C, 0xCA };
	unsigned char hashDigest[20] = { 0x6F, 0x02, 0x98, 0x86, 0x25, 0x8C, 0xAF, 0x9F, 0xC2, 0x4A, 0x70, 0x6B, 0xBD, 0x44, 0xBC, 0x5E, 0x57, 0xD8, 0x32, 0xA1 };
	unsigned char even[20] = { 0x76, 0xF4, 0x26, 0x85, 0xF4, 0x8E, 0x33, 0x3B, 0x9B, 0x8B, 0xBA, 0xCF, 0x8D, 0x12, 0x42, 0x39, 0x7F, 0x8A, 0xC3, 0x23 };
	unsigned char odd[20] = { 0xFE, 0x26, 0x68, 0x4C, 0x27, 0xB6, 0x50, 0x2A, 0xEC, 0x90, 0x85, 0xAA, 0xD9, 0x80, 0x38, 0x13, 0x9C, 0xD6, 0xE5, 0xBF };
	//unsigned char h[20] = { 0x6B, 0xB0, 0x85, 0x4C, 0xA0, 0x9C, 0xAF, 0x9C, 0x3C, 0xCC, 0xA5, 0x57, 0x30, 0x85, 0xB9, 0x5F, 0x7B, 0x85, 0xE9, 0xCB };
	unsigned char new_h[20] = { 0x00 };
	unsigned char new_h2[20] = { 0x00 };
	unsigned char xor_key[20] = { 0x00 };
	unsigned char encrypted_secret[20] = { 0x00 };
	unsigned char secret_key[20] = { 0x00 };
	unsigned char shared[20] = { 0x00 };
	unsigned char cont = 0x00;

	unsigned char osapEven[20] = { 0x03 ,0xF0 ,0x02 ,0xB6, 0xA9 ,0x2C ,0x48 ,0xAE, 0x3E ,0x0E ,0xEA ,0xA1, 0x47 ,0x5C ,0x3D ,0x21, 0xE8 ,0x06 ,0x38 ,0xD6 };

	unsigned char osapOdd[20]  = { 0x67, 0x04, 0x00, 0x4E, 0x36, 0x0C, 0x6E, 0x4A, 0xCB, 0xDB, 0xBB, 0xE6, 0xDD, 0xE2, 0xF1, 0x46, 0x2C, 0xF0, 0x77, 0x01 };

	hmac_init(secret_key, 20);
	hmac_update(osapEven, 20);
	hmac_update(osapOdd, 20);
	hmac_final(shared);

	int i;
	printf("ENC AUTH:\n");
	for(i=0;i<20;i++)
		printf("%02X ", shared[i]);

	printf("\n");

	unsigned char pcrInfoSize[4] = { 0x00, 0x00, 0x00, 0x2C };

	unsigned char pcrInfo[44] = { 0x00 };

	unsigned char data[20] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x57, 0x6f, 0x72, 0x6c, 0x64,
							  0x21, 0x54, 0x68, 0x69, 0x73, 0x49, 0x73, 0x4d, 0x65, 0x0A };

	unsigned char data_len[4] = { 0x00, 0x00, 0x00, 0x14 };

	pcrInfo[1] = 0x02;
	pcrInfo[2] = 0x00;

	unsigned int hmac_len = 20;

	hash_init();
	hash_update(even, 20);
	hash_update(shared_secret, 20);
	hash_final(xor_key);

	for(i=0;i<20;i++)
		encrypted_secret[i] = xor_key[i] ^ secret_key[i];

	printf("ENC AUTH:\n");
	for(i=0;i<20;i++)
		printf("%02X ", encrypted_secret[i]);

	printf("\n");

	hash_init();
	hash_update(ordinal, 4);
	hash_update(encrypted_secret, 20);
	hash_update(pcrInfoSize, 4);
	hash_update(pcrInfo, 44);
	hash_update(data_len, 4);
	hash_update(data, 20);
	hash_final(hashDigest);

	printf("HASH DIGEST:\n");
	for(i=0;i<20;i++)
		printf("%02X ", hashDigest[i]);

	printf("\n");

	HMAC_CTX_init(&hmac);
	HMAC_Init(&hmac, shared_secret, 20, EVP_sha1());
	HMAC_Update(&hmac, hashDigest, 20);
	HMAC_Update(&hmac, even, 20);
	HMAC_Update(&hmac, odd, 20);
	HMAC_Update(&hmac, &cont, 1);
	HMAC_Final(&hmac, new_h, &hmac_len);

	printf("OPENSSL HMAC:\n");
	for(i=0;i<20;i++)
		printf("%02X ", new_h[i]);

	printf("\n");

	h_init(shared_secret, 20);
	h_update(hashDigest, 20);
	h_update(even, 20);
	h_update(odd, 20);
	h_update(&cont, 1);
	h_final(new_h2);

	printf("IAIK HMAC:\n");
	i=0;
	for(;i<20;i++)
		printf("%02X ", new_h2[i]);
	printf("\n");

	return 0;
}

//----------------------------------------------------------------------
void h_init(const void* key, size_t key_len)
{
  memset(g_k_opad, 0, sizeof(g_k_opad));

  // Key scheduling
  if (key_len > sizeof(g_k_opad)) {
	printf("Hashing the key\n");
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
void h_update(const unsigned char *msg, size_t len)
{
  hash_update(msg, len);
}

//----------------------------------------------------------------------
void h_final(unsigned char hmac[HASH_DIGEST_SIZE])
{
  // Finish inner hash
	hash_final(hmac);

  // Outer hash
  hash_init();

  // Outer padding (opad) from inner padding
  for (size_t n = 0; n < sizeof(g_k_opad); ++n) {
    g_k_opad[n] ^= (0x36 ^ 0x5C);
  }
  hash_update(g_k_opad, sizeof(g_k_opad));
  // Finish HMAC
  hash_update(hmac, HASH_DIGEST_SIZE);
  hash_final(hmac);

  // Cleanup
  memset(g_k_opad, 0, sizeof(g_k_opad));
}
