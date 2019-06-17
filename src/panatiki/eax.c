/*
  A really stupid, brain-dead implementation of EAX mode (hardcoded to use AES
  with 128 bit keys). The idea is that it's easy to verify the code is correct.
  It is not fast. At all. It generates random keys and messages, and dumps
  various things to stdout - the intent of this code is to generate test
  vectors.

  There is a fast EAX implementation in Botan (http://botan.randombit.net)

  Requires OpenSSL 0.9.7 (for the AES support)

     (C) 2003 Jack Lloyd (lloyd@randombit.net)
        This program is free software; you can redistribute it and/or modify it
        under the terms of the GNU General Public License version 2 as
        published by the Free Software Foundation. This program is distributed
        in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
        even the implied warranty of MERCHANTABILITY or FITNESS FOR A
        PARTICULAR PURPOSE.


   Modified by:

   Copyright (c) 2012, Pedro Moreno Sánchez
	All rights reserved.

	Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

	1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

	3. Neither the name of the University of Murcia nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */
 

#include "include.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "eax.h"
#include "aes.h"

#ifdef __cplusplus
}
#endif


void do_omac(const unsigned char key[16], const unsigned char data[], int length,
             unsigned char mac[16]);

void do_omac_n(const unsigned char key[16], const unsigned char data[], int length,
             unsigned char mac[16], unsigned char tag);

void do_ctr(const unsigned char key[16], const unsigned char nonce[16],
            unsigned char data[], int length);

void do_eax(const unsigned char key[16], const unsigned char nonce[16],
            const unsigned char data[], int length,
            const unsigned char header[], int h_length,
            unsigned char message_ciphered[],
            unsigned char tag_buf[], int tag_length);

/*void dump(const char* name, const unsigned char data[], int length, int always)
   {
   int j;

   if(!always && !DUMP_INTER)
      return;

   printf("%s: ", name);
   for(j = strlen(name); j < 8; j++)
      printf(" ");
   for(j = 0; j != length; j++)
      printf("%02X", data[j]);
   printf("\n");
   }*/



/* The overall EAX transform */
void do_eax(const unsigned char key[16], const unsigned char nonce[16],
            const unsigned char data[], int length,
            const unsigned char header[], int h_length,
            unsigned char data_ciphered[],
            unsigned char tag_buf[], int tag_length)
   {
   unsigned char mac_nonce[16], mac_data[16], mac_header[16];
   int j;

   /* this copy will be encrypted in CTR mode */
   //unsigned char* data_copy = (unsigned char*)malloc(length);
   unsigned char data_copy [length];
   memcpy(data_copy, data, length);

   do_omac_n(key, nonce, 16, mac_nonce, 0);
   do_omac_n(key, header, h_length, mac_header, 1);
   do_ctr(key, mac_nonce, data_copy, length);
   /* MAC the ciphertext, not the plaintext */
   do_omac_n(key, data_copy, length, mac_data, 2);



   for(j = 0; j != length; j++){
	  data_ciphered[j] = data_copy[j];
   }
   for(j = 0; j != TAG_SIZE; j++){
	  tag_buf[j] = mac_nonce[j] ^ mac_data[j] ^ mac_header[j];
   }
   /*dump("MAC(H)", mac_header, 16, 0);
   dump("MAC(N)", mac_nonce, 16, 0);
   dump("MAC(C)", mac_data, 16, 0);*/

   /*printf("MAC(H)    ");
   for(j = 0; j != 16; j++)
      printf("%02X", mac_header[j]);
   printf("\n");

   printf("MAC(N)    ");
   for(j = 0; j != 16; j++)
      printf("%02X", mac_nonce[j]);
   printf("\n");

   printf("MAC(C)    ");
   for(j = 0; j != 16; j++)
      printf("%02X", mac_data[j]);
   printf("\n");
	
   printf("CIPHER:   ");
   for(j = 0; j != length; j++){
      printf("%02X", data_copy[j]);
	  data_ciphered[j] = data_copy[j];
  }
   for(j = 0; j != TAG_SIZE; j++){
      printf("%02X", mac_nonce[j] ^ mac_data[j] ^ mac_header[j]);
	  tag_bug[j] = mac_nonce[j] ^ mac_data[j] ^ mac_header[j];
  }
   printf("\n");*/
   }

/* I copied this part from my 'real' OMAC source, so it's possible they are
   both wrong - this needs to be checked carefully.
*/
void poly_double(const unsigned char in[16], unsigned char out[16])
   {
   const int do_xor = (in[0] & 0x80) ? 1 : 0;
   int j;
   unsigned char carry = 0;

   memcpy(out, in, 16);

   for(j = 16; j != 0; j--)
      {
      unsigned char temp = out[j-1];
      out[j-1] = (temp << 1) | carry;
      carry = (temp >> 7);
      }

   if(do_xor)
      out[15] ^= 0x87; /* fixed polynomial for n=128, binary=10000111 */
   }

/* The OMAC parameterized PRF function */
void do_omac_n(const unsigned char key[16], const unsigned char data[], int length,
               unsigned char mac[16], unsigned char tag)
   {
   //unsigned char* data_copy = (unsigned char*)malloc(length + 16);
   unsigned char data_copy [length + 16];

   memset(data_copy, 0, length + 16);
   data_copy[15] = tag;
   memcpy(data_copy + 16, data, length);

   do_omac(key, data_copy, length + 16, mac);
   }

/* The OMAC / pad functions */
void do_omac(const unsigned char key[16], const unsigned char data[], int length,
             unsigned char mac[16])
   {
   //Init AES ctx and key
   //AES_KEY aes_key;
   //char aes_key [16];
   //AesCtx ctx;
   //AesCtxIni(&ctx, NULL, key, KEY128, CBC);
   aes_context ctx;


   
   unsigned char L[16] = { 0 }, P[16] = { 0 }, B[16] = { 0 };
   int j;
   int total_len = 0;
   //unsigned char* data_padded = 0;
   //unsigned char data_padded [64];
   unsigned char data_padded [150];
   const unsigned char* xor_pad;

   //AES_set_encrypt_key(key, 128, &aes_key);
   aes_set_key(key, 16, &ctx);
   //cc2420_aes_set_key(key, 0);

   //AES_encrypt(L, L, &aes_key); /* create L */
   //aes_encrypt( L, L, &ctx);
   //bACI_ECBencodeStripe(key, TRUE, L, L);
   //AesEncrypt(&ctx, L, L, sizeof(L));
   //cc2420_aes_cipher(L, 16, 0);
   aesencrypt(L, L, &ctx);

   poly_double(L, B); /* B = 2L */
   poly_double(B, P); /* P = 2B = 2(2L) = 4L */

   /*dump("L", L, 16, 0);
   dump("B", B, 16, 0);
   dump("P", P, 16, 0);*/

   if(length && length % 16 == 0) /* if of size n, 2n, 3n... */
      total_len = length; /* no padding */
   else
      total_len = length + (16 - length % 16); /* round up to next 16 unsigned chars */

   //data_padded = (unsigned char*)malloc(total_len);
   memset(data_padded, 0, total_len);
   memcpy(data_padded, data, length);

   if(total_len != length) /* if add padding */
      data_padded[length] = 0x80;

   //dump("OMAC_IN", data, length, 0);
   //dump("PADDED", data_padded, total_len, 0);

   /* If no padding, XOR in B, otherwise XOR in P */
   xor_pad = (total_len == length) ? B : P;

   for(j = total_len - 16; j != total_len; j++)
      {
      data_padded[j] ^= *xor_pad;
      xor_pad++;
      }

   //dump("POSTXOR", data_padded, total_len, 0);

   //assert(total_len % 16 == 0); /* sanity check */
   memset(mac, 0, 16);

   for(j = 0; j != total_len; j += 16)
      {
      int k;
      for(k = 0; k != 16; k++) mac[k] ^= data_padded[j+k];
      //dump("C_i", mac, 16, 0);
      //AES_encrypt(mac, mac, &aes_key);
      //aes_encrypt(mac, mac, &ctx);
      //bACI_ECBencodeStripe(NULL,FALSE, mac, mac);
      //AesEncrypt(&ctx, mac, mac, sizeof(mac));
	  //cc2420_aes_cipher(mac, 16, 0);
	  aesencrypt(mac, mac, &ctx);
      }

   //dump("C_m", mac, 16, 0);
   }

/* CTR encryption */
void do_ctr(const unsigned char key[16], const unsigned char nonce[16],
            unsigned char data[], int length)
   {
   //char aes_key [16];
   //AesCtx ctx;
   //AesCtxIni(&ctx, NULL, key, KEY128, CBC);
   aes_context ctx;

   unsigned char state[16]; /* the actual counter */
   unsigned char buffer[16]; /* encrypted counter */
   int j;

   memcpy(state, nonce, 16);

   //AES_set_encrypt_key(key, 128, &aes_key);
   aes_set_key(key, 16, &ctx);
   // cc2420_aes_set_key(key, 0);
   
   /* Initial encryption of the counter */
   //AES_encrypt(state, buffer, &aes_key);
   //aes_encrypt(state, buffer, &ctx);
   //bACI_ECBencodeStripe(key, TRUE, state, buffer);
   //AesEncrypt(&ctx, state, buffer, sizeof(state));
   //cc2420_aes_cipher(state, 16, 0);
   //memcpy(buffer, state, 16);
   aesencrypt(state, buffer, &ctx);

   while(length)
      {
      int to_xor = (length < 16) ? length : 16;

      for(j = 0; j != to_xor; j++)
         data[j] ^= buffer[j];
      data += to_xor;
      length -= to_xor;

      /* Compute E(counter++) */
      for(j = 15; j >= 0; j--)
         if(++state[j])
            break;
      //AES_encrypt(state, buffer, &aes_key);
      //aes_encrypt(state, buffer, &ctx);
      //bACI_ECBencodeStripe(NULL, FALSE, state, buffer);
      //AesEncrypt(&ctx, state, buffer, sizeof(state));
		//cc2420_aes_cipher(state, 16, 0);
		//memcpy(buffer, state, 16);
	  aesencrypt(state, buffer, &ctx);
      }
   }
