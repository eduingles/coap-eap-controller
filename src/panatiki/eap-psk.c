/* Copyright (c) 2012, Pedro Moreno Sánchez
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

#include "eap-psk.h"
#include "aes.h"

#ifdef __cplusplus
}
#endif

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>


//static unsigned char psk[16]={'1', '2', '3', '4', '5', '6', '7', '8', '1', '2', '3', '4', '5', '6', '7', '8'};
//static unsigned char psk[16]={'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

#define reqId ((struct eap_msg *)eapReqData)->id
#define reqMethod ((struct eap_msg *)eapReqData)->method
#define reqCode ((struct eap_msg *)eapReqData)->code
#define reqLength ((struct eap_msg *)eapReqData)->length

unsigned char output [16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};//Auxiliar AES register
unsigned char it;
unsigned int aux;
static unsigned char data [64];

void initMethodEap(){
	
	
	//AesCtx ctx; //Aes context
	aes_context ctx;


	//Init variables
	//psk_key_available = FALSE; //In the beginning there is no key
	step = 0; //In the beginning there is no eap-psk message

	//Init the Aes ctx with the psk
	//AesCtxIni(&ctx, NULL, psk, KEY128, CBC);
	//cc2420_aes_set_key(psk, 0);
	//aes_set_key(psk, 16, &ctx);
	aes_set_key(psk, 16, &ctx);

	//Init the rand_p
	srand(time(NULL));
	for (it=0; it<16; it=it+2){
		aux = rand();
		memcpy(rand_p+it, &aux, sizeof(unsigned short)); //2 unsigned chars
	}
	
	///////AK and KDK derivation

	//Init constant as ct0
	memset(ct, 0, sizeof(ct));

	/////AES-128(PSK,ct0)
	//bACI_ECBencodeStripe(psk, TRUE, ct, output);
	//AesEncrypt(&ctx, ct, output, sizeof(ct));
	//cc2420_aes_cipher(ct, 16, 0);
	//memcpy(output, ct, 16);
	aesencrypt(ct, output, &ctx);

	//Init constant as ct1
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x01;
	
	/////XOR (ct1, AES-128(PSK, ct0))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	////AK = AES-128(PSK, XOR (ct1, AES-128(PSK, ct0)))
	//bACI_ECBencodeStripe(psk, TRUE, ct, ak); //The psk is not set because it is just set
	//AesEncrypt(&ctx, ct, ak, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(ak, ct, sizeof(ct));
	aesencrypt(ct, ak, &ctx);

	//Init constant as ct2
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x02;
	
	/////XOR (ct2, AES-128(PSK, ct0))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	////KDK = AES-128 (PSK, XOR (ct2, AES-128(PSK, ct0)) )
	//bACI_ECBencodeStripe(psk, TRUE, ct, kdk); //The psk is not set because it is just set
	//AesEncrypt(&ctx, ct, kdk, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(kdk, ct, sizeof(ct));
	aesencrypt(ct, kdk, &ctx);


	///Generating tek, msk and emsk
	//AES-128(KDK, RAND_P)
	//bACI_ECBencodeStripe(kdk, TRUE, rand_p, output);
	//cc2420_aes_set_key(kdk, 0);
	aes_set_key(kdk, 16, &ctx);

	//AesCtxIni(&ctx, NULL, kdk, KEY128, CBC);
	//AesEncrypt(&ctx, rand_p, output, sizeof(rand_p));
	//cc2420_aes_cipher(rand_p, sizeof(rand_p), 0);
	//memcpy(output, rand_p, sizeof(rand_p));
	aesencrypt(rand_p, output, &ctx);

	//Init constant as ct1
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x01;
	
	//XOR (ct1, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//TEK = AES-128(KDK, XOR (ct1, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, tek_key); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, tek_key, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(tek_key, ct, sizeof(ct));
	aesencrypt(ct, tek_key, &ctx);

	//Init constant as ct2
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x02;
	
	//XOR (ct2, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//MSK 1/4 = AES-128(KDK, XOR (ct2, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, msk_key); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, msk_key, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(msk_key, ct, sizeof(ct));
	aesencrypt(ct, msk_key, &ctx);

/*
	//Init constant as ct3
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x03;
	
	//XOR (ct3, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//MSK 2/4 = AES-128(KDK, XOR (ct3, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, msk_key+16); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, msk_key+16, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(msk_key+16, ct, sizeof(ct));
	aesencrypt(ct, msk_key+16, &ctx);

	//Init constant as ct4
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x04;
	
	//XOR (ct4, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//MSK 3/4 = AES-128(KDK, XOR (ct4, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, msk_key+32); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, msk_key+32, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(msk_key+32, ct, sizeof(ct));
	aesencrypt(ct, msk_key+32, &ctx);

	//Init constant as ct5
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x05;
	
	//XOR (ct5, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//MSK 4/4 = AES-128(KDK, XOR (ct5, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, msk_key+48); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, msk_key+48, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(msk_key+48, ct, sizeof(ct));	
	aesencrypt(ct, msk_key+48, &ctx);
*/
	//Init constant as ct6 
/*	memset(ct, 0, sizeof(ct));
	ct[15] = 0x06;
	
	//XOR (ct6, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//EMSK 1/4 = AES-128(KDK, XOR (ct6, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, emsk_key); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, emsk_key, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(emsk_key, ct, sizeof(ct));	
	aesencrypt(ct, emsk_key, &ctx);

	//Init constant as ct7
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x07;
	
	//XOR (ct7, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//EMSK 2/4 = AES-128(KDK, XOR (ct7, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, emsk_key+16); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, emsk_key+16, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(emsk_key+16, ct, sizeof(ct));	
	aesencrypt(ct, emsk_key+16, &ctx);

	//Init constant as ct8
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x08;
	
	//XOR (ct8, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//EMSK 3/4 = AES-128(KDK, XOR (ct8, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, emsk_key+32); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, emsk_key+32, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(emsk_key+32, ct, sizeof(ct));		
	aesencrypt(ct, emsk_key+32, &ctx);

	//Init constant as ct9
	memset(ct, 0, sizeof(ct));
	ct[15] = 0x09;
	
	//XOR (ct9, AES-128(KDK, RAND_P))
	for (it=0; it<16; it++){
		ct[it] = ct[it]^output[it];
	}

	//EMSK 4/4 = AES-128(KDK, XOR (ct9, AES-128(KDK, RAND_P)))
	//bACI_ECBencodeStripe(NULL, FALSE, ct, emsk_key+48); //The kdk is not set because it is just set
	//AesEncrypt(&ctx, ct, emsk_key+48, sizeof(ct));
	//cc2420_aes_cipher(ct, sizeof(ct), 0);
	//memcpy(emsk_key+48, ct, sizeof(ct));
	aesencrypt(ct, emsk_key+48, &ctx);  */
}

//Check de EAP_PSK Request message
unsigned char check(const unsigned char * eapReqData){

	if (reqMethod == EAP_PSK)
		return TRUE;

	return FALSE;
}

//Process the EAP-PSK Request message. The results are obtained in the
// methodState and decision variables.
void process(const unsigned char * eapReqData, unsigned char * methodState, unsigned char * decision){
	if (reqMethod==EAP_PSK && reqCode==REQUEST_CODE ){ //Type EAP-PSK && Code=1
		step++;
		
		//if (step==1){ //EAP-PSK first message
		if (eapReqData[5]==0x00){ //EAP-PSK first message
			step=2; //The next step is EAP-PSK 2
			memcpy(rand_s, eapReqData+6, 16);
			
			id_s_length = NTOHS(reqLength) -22;
			
			memcpy(id_s, eapReqData+22, id_s_length);

			
			*(methodState)= MAY_CONT;
			*(decision)=COND_SUCC;

		}
		//else if (step==3){ //EAP-PSK third message
		else if (eapReqData[5]==0x80){ //EAP-PSK third message
			step=4; //The next step is EAP-PSK 2
			//Checking rand_s
			
			for (it=0; it<16; it++) {
				if (eapReqData[6+it] != rand_s [it]){
					*(methodState)= MAY_CONT;
					*(decision)=FAIL;
					return;
				}
			}

			//checking MAC_S = CMAC-AES-128 (AK, ID_S||RAND_P)
			memcpy(data, id_s, id_s_length);
			memcpy(data+id_s_length, rand_p, 16);

            do_omac(ak, data, id_s_length+16, output); //output == mac_s


			for (it=0; it<16; it++){
				if (eapReqData[22+it] != output[it]){ //output == mac_s
					*(methodState)= MAY_CONT;
					*(decision)=FAIL;
					return;
				}
			}
			
			*(methodState)= MAY_CONT;
			*(decision)=COND_SUCC;
			eapKeyAvailable = TRUE;
		}	
	}
}

//Build the EAP-PSK Response message depending on the step variable value
void buildResp(unsigned char * eapRespData, const unsigned char identifier){
	//Building EAP-PSK message
	
	if (step==2){ //EAP-PSK second message
		((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
		((struct eap_msg *)eapRespData)->id = identifier;
		((struct eap_msg *)eapRespData)->length = HTONS(54+ID_P_LENGTH);
		((struct eap_msg *)eapRespData)->method = EAP_PSK;
		eapRespData[5] = 0x40; //T=1 in flags field
		
		memcpy((eapRespData+6), rand_s, 16);
		memcpy((eapRespData+22), rand_p, 16);

		//Calculating MAC_P = CMAC-AES-128(AK, ID_P||ID_S||RAND_S||RAND_P)
		//memcpy(data, id_p, ID_P_LENGTH);
		
#ifdef __cplusplus
		sprintf((char *)data, "%s", "client");
#else
		sprintf(data, "%s", "client");
#endif
		

		memcpy(data+ID_P_LENGTH, id_s, id_s_length);
		memcpy(data+ID_P_LENGTH+id_s_length, rand_s, 16);
		memcpy(data+ID_P_LENGTH+id_s_length+16, rand_p, 16);

       	do_omac(ak, data, ID_P_LENGTH+id_s_length+16+16, output); //output == mac_p
			
		memcpy(eapRespData+38, output, 16); //output == mac_p

#ifdef __cplusplus
		sprintf((char *)eapRespData+54, "%s", "client");
#else
		sprintf(eapRespData+54, "%s", "client");
#endif
	}
	else if (step==4){ //EAP-PSK fourth message
		((struct eap_msg *)eapRespData)->code = RESPONSE_CODE;
		((struct eap_msg *)eapRespData)->id = identifier;
		((struct eap_msg *)eapRespData)->length = HTONS(43);
		((struct eap_msg *)eapRespData)->method = EAP_PSK;
		eapRespData[5] = 0xc0; //T=3 Flags

		memcpy(eapRespData+6, rand_s, 16);
		memcpy(eapRespData+22, nonce+12, 4); //Only the last four digits are used.

		//Set the values to calculate the tag
		memcpy(header, eapRespData, 22);
		do_eax(tek_key, nonce,
		msg, 1,
		header, 22,
		data_ciphered,
		tag_bug, 16);

		memcpy(eapRespData+26, tag_bug, 16);
		memcpy(eapRespData+42, data_ciphered, 1);

		//psk_key_available = TRUE;
		eapKeyAvailable = TRUE;
	} 
	
}

