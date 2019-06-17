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

#ifndef _EAX_H
#define _EAX_H

#include "include.h"

/* PARAMETERS: Play with as desired */
#define MSG_MIN 0 /* anything */
#define MSG_MAX 0  /* anything >= MSG_MIN */
#define NONCE_SIZE 16 /* anything, will tend to be == blocksize of cipher */
#define HEADER_SIZE 8 /* anything */
#define TAG_SIZE 16 /* between 0 and 16 */

#define VECTORS 1 /* how many vectors to print at once */
#define DUMP_INTER 0 /* dump intermediate values */


void do_eax(const unsigned char key[16], const unsigned char nonce[16],
            const unsigned char data[], int length,
            const unsigned char header[], int h_length,
            unsigned char data_ciphered[],
            unsigned char tag_buf[], int tag_length);

void do_omac(const unsigned char key[16], const unsigned char data[], int length,
             unsigned char mac[16]);

#endif
