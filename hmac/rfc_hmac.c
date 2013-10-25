
/*
** Function: hmac_sha1
*/
#include <stdio.h>
#include <strings.h>
#include "sha.h"

void hmac_sha1(text, text_len, key, key_len, digest)
unsigned char*  text;                /* pointer to data stream */
int             text_len;            /* length of data stream */
unsigned char*  key;                 /* pointer to authentication key */
int             key_len;             /* length of authentication key */
unsigned char*  digest;              /* caller digest to be filled in */

{

        unsigned char k_ipad[65];    /* inner padding -
                                      * key XORd with ipad
                                      */
        unsigned char k_opad[65];    /* outer padding -
                                      * key XORd with opad
                                      */
        int i;
        /*
         * the HMAC_MD5 transform looks like:
         *
         * MD5(K XOR opad, MD5(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
         * opad is the byte 0x5c repeated 64 times
         * and text is the data being protected
         */

        /* start out by storing key in pads */
        bzero( k_ipad, sizeof k_ipad);
        bzero( k_opad, sizeof k_opad);
        bcopy( key, k_ipad, key_len);
        bcopy( key, k_opad, key_len);

        for(i=0;i<64;i++)
        	printf("%X ", k_ipad[i]);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner MD5
         */
        hash_init();
        hash_update(k_ipad,64);
        hash_update(text,text_len);
        hash_final(digest);
        /*
         * perform outer MD5
         */
        hash_init();
        hash_update(k_opad,64);
        hash_update(digest, 16);
        hash_final(digest);

        printf("\n");
        int j=0;
        for(;j<20;j++)
        	printf("%02X ", digest[j]);
}
