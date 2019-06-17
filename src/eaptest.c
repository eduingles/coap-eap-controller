/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in draft-ietf-core-coap
 *
 * Copyright (C) 2010--2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use. 
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>

#include "panatiki/include.h"
#include "panatiki/eap-peer.h"
#include "panatiki/eap-psk.h"



void printf_hex(unsigned char *hex, unsigned int l)
{
	int i;
	if (hex != NULL){	
	for (i=0; i < l; i++)
		printf("%02x",hex[i]);

	printf("\n");
	}
}


int main(int argc, char **argv) {
	
	memset(&msk_key,0, MSK_LENGTH);
	eapRestart=TRUE;
	eap_peer_sm_step(NULL);

	unsigned char firstEAP[5] = {0x01,0x88,0x00,0x05,0x01};
	int len;	
	
	printf_hex(&firstEAP,5);

	eapReq=TRUE;
	eap_peer_sm_step((unsigned char*)&firstEAP);

	if (eapResp){
		printf("Hay EAP response %d\n",ntohs( ((struct eap_msg*) eapRespData)->length));
		printf_hex(eapRespData,len = ntohs( ((struct eap_msg*) eapRespData)->length));
	}else{
		printf("NO HAY EAP RESPONSE\n");
	}



  return 0;
}
