/* Copyright (c) 2012, Pedro Moreno Sánchez
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the University of Murcia nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include "eap-peer.h"
#ifdef __cplusplus
}
#endif


#define reqId ((struct eap_msg *)msg)->id
#define reqMethod ((struct eap_msg *)msg)->method

void printf_hex_eap(unsigned char *hex, unsigned int l)
{
	int i;
	if (hex){	
	for (i=0; i < l; i++)
		printf("%02x",hex[i]);

	printf("\n");
	}
}


//Build the Identity message
static void buildIdentity(const unsigned char id){

	printf("Building Identity\n");
	
	((struct eap_msg*) eapRespData)->code = RESPONSE_CODE;
	((struct eap_msg*) eapRespData)->id = id;
	((struct eap_msg*) eapRespData)->length = HTONS((sizeof(struct eap_msg) + strlen(USER)));
	((struct eap_msg*) eapRespData)->method = IDENTITY;
	sprintf(eapRespData + sizeof(struct eap_msg), "%s", (char *)USER);

	printf_hex_eap(eapRespData,sizeof(struct eap_msg) + strlen(USER));
	printf("\n");
}

//EAP peer state machine step function
void eap_peer_sm_step(const unsigned char* msg){
	//INITIALIZE STATE
	if (eapRestart){
		
		selectedMethod = NONE;
		methodState = NONE;
		decision = FAIL;
		lastId = NONE;
		eapSuccess = FALSE;
		eapFail = FALSE;
		eapKeyAvailable = FALSE;

		//Initialition out of standard
		eapReq = FALSE;
		eapResp = FALSE;
		eapNoResp = FALSE;
		memset (eapRespData, 0, EAP_MSG_LEN);
		initMethodEap();

		eapRestart=FALSE;
		return;
	}

	//IDLE STATE
	if (!msg){
		return;
	}

	//RECEIVED STATE
	if (eapReq){
		//parseEapReq(msg);
		
		//if ((type_received == RxSUCCESS) && (reqId == lastId) && (decision!=FAIL)){
		if ( ( ((struct eap_msg *)msg)->code == SUCCESS_CODE) && (reqId == lastId) && (decision!=FAIL)){
			goto _SUCCESS;
		}
		
		//else if (methodState!=CONT && ( ((type_received == RxFAILURE) && decision != UNCOND_SUCC) || (type_received == RxSUCCESS && decision==FAIL) ) && (reqId == lastId) ){
		else if (methodState!=CONT && ( (( ((struct eap_msg *)msg)->code == FAILURE_CODE) && decision != UNCOND_SUCC) || (( ((struct eap_msg *)msg)->code == SUCCESS_CODE) && decision==FAIL) ) && (reqId == lastId) ){
			goto _FAILURE;
		}

		//else if (type_received == RxREQ && reqId == lastId){
		else if (( ((struct eap_msg *)msg)->code == REQUEST_CODE) && reqId == lastId){
			//RETRANSMIT STATE
			goto _SEND_RESPONSE;
		}

		//else if ((type_received == RxREQ) && (reqId!=lastId) && (selectedMethod == NONE) && (reqMethod==IDENTITY)){
		else if (( ((struct eap_msg *)msg)->code == REQUEST_CODE) && (reqId!=lastId) && (selectedMethod == NONE) && (reqMethod==IDENTITY)){
			//processIdentity(msg); //TODO: Deploy this. It can be avoided?
			printf("EStoy en EAP resp id\n");
			buildIdentity( reqId );
			goto _SEND_RESPONSE;
		}
		
		//else if ((type_received == RxREQ) && (reqId!=lastId) && (selectedMethod == NONE) && (reqMethod != IDENTITY) ){
		else if (( ((struct eap_msg *)msg)->code == REQUEST_CODE) && (reqId!=lastId) && (selectedMethod == NONE) && (reqMethod != IDENTITY) ){
			//GET_METHOD STATE
			//if (allowMethod(reqMethod)){
			if (reqMethod == EAP_PSK){ //We can do this because only EAP-PSK is supported
				selectedMethod = reqMethod;
				methodState = INIT;
			}
			else{
				//TODO: It is necessary build a Nak message here
			}
			if (selectedMethod == reqMethod) goto _METHOD;
			else goto _SEND_RESPONSE;
		}
	
		//else if ((type_received == RxREQ) && (reqId!=lastId) && (reqMethod==selectedMethod) && (methodState != DONE)){
		else if (( ((struct eap_msg *)msg)->code == REQUEST_CODE) && (reqId!=lastId) && (reqMethod==selectedMethod) && (methodState != DONE)){
			goto _METHOD;
		}

		
		else goto _DISCARD;

	
	}
	else if ((altAccept && decision != FAIL)) goto _SUCCESS;

	else if (altReject || (altAccept && methodState != CONT && decision == FAIL)) goto _FAILURE;
	
	else goto _DISCARD;

_FAILURE:
	//FAILURE STATE
	eapFail = TRUE;
	return;

_SUCCESS:
	//SUCCESS STATE
	eapSuccess = TRUE;
	return;

_METHOD:
	//METHOD STATE
	if(check(msg)){
		process(msg, &methodState, &decision);
		printf("Estoy construyendo EAP resp-id\n");
		buildResp((struct eap_msg *)eapRespData, reqId);
		/*if (isKeyAvailable()){
			eapKeyAvailable = TRUE;
		}*/
		//eapKeyAvailable is directly set in EAP-PSK method
		goto _SEND_RESPONSE;
	}
	else goto _DISCARD;

	
_SEND_RESPONSE:
	//SEND_RESPONSE STATE
	lastId = reqId;
	eapReq = FALSE;
	eapResp = TRUE;
	return;

_DISCARD:
	//DISCARD STATE
	eapReq = FALSE;
	eapNoResp = TRUE;
	return;
}
