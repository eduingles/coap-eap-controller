/* Copyright (c) 2012, Pedro Moreno Sánchez
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the University of Murcia nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#ifndef __EAP_PSK
#define __EAP_PSK

#ifdef __cplusplus
extern "C" {
#endif

#include "eap-peer.h"
//#include "ahi_aes.h"
#include "aes.h"
#include "eax.h"

#ifdef __cplusplus
}
#endif

#define ID_P_LENGTH 6


unsigned char check(const unsigned char * eapReqData);
void process(const unsigned char * eapReqData, unsigned char * methodState, unsigned char * decision);
void buildResp( unsigned char * eapRespData, unsigned char reqId);
void initMethodEap();


static unsigned char tek_key [16];

static unsigned char ak [16];
static unsigned char kdk [16];
static unsigned char step;
static unsigned char rand_s[16];
static unsigned char rand_p[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
								   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static unsigned char id_s[16];
static unsigned short id_s_length;
static unsigned char ct[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

//Nonce defined in the RFC EAP-PSK for the protected-channel computing
static unsigned char nonce [16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};


static unsigned char psk[16]={'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};


static unsigned char data_ciphered [16];
static unsigned char tag_bug[16];
static unsigned char header [22];
static unsigned char msg[1] = {0x80};


#endif
