/// Server example for cantcoap that responds to the ETSI IoT CoAP Plugtests.
/**
 * This example waits for CoAP packets and responds accordingly.It is designed to work with 
 * the ETSI IoT CoAP Plugtests (http://www.etsi.org/plugtests/coap/coap.htm). Put this on
 * A public IP somewhere, and use the website http://coap.me to drive the tests.
 *
 * Note, the tests on coap.me are a bit odd.
 */

#define __USE_POSIX 1

// for mbed compatibility
#define failGracefully exit

// buffers for UDP and URIs
#define BUF_LEN 500
#define URI_BUF_LEN 32


#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>


#include "cantcoap-master/nethelper.h"
#include "_cantcoap.h"
#include "uthash.h"

#include "panatiki/include.h"
#include "panatiki/eap-peer.h"
#include "panatiki/eap-psk.h"



// Global Variables
int nonce_c;
int nonce_s;
int location_path;
unsigned char auth_key[16] = {0};
unsigned char sequence[12] = {0};
uint8_t authKeyAvailable;
short isTime = 0;

// Retransmission variables
uint8_t *lastReceivedMessage;
uint8_t *lastSentMessage;
int lastSentMessage_len;
int lastReceivedMessage_len;

// Retransmissions funtions

void storeLastSentMessageInSession(CoapPDU *pdu){

    if(lastSentMessage != NULL)
    {
        free((void *) lastSentMessage);
        lastSentMessage = NULL;
    }

    lastSentMessage = (uint8_t *)malloc((size_t)getPDULength(pdu));
    memcpy(lastSentMessage,getPDUPointer(pdu) ,(size_t)getPDULength(pdu));
    lastSentMessage_len = getPDULength(pdu);
}

void storeLastReceivedMessageInSession(CoapPDU *pdu){

    if(lastReceivedMessage != NULL)
    {
        free((void *)lastReceivedMessage);
        lastReceivedMessage = NULL;
    }

    printf("Storing Last Received Message of length %d \n",getPDULength(pdu));

    lastReceivedMessage = (uint8_t *)malloc((size_t)getPDULength(pdu));
    memcpy(lastReceivedMessage,getPDUPointer(pdu) ,(size_t)getPDULength(pdu));
    lastReceivedMessage_len = getPDULength(pdu);

}

void sendLastMessage(int sockfd, struct sockaddr_storage *recvFrom){

    CoapPDU *toSendPDU = _CoapPDU_buf2(lastSentMessage, BUF_LEN, BUF_LEN);
    setPDULength(toSendPDU,lastSentMessage_len);
    if(validate(toSendPDU) != 1){
        INFO("ERROR: Non valid PDU");
    }


    socklen_t addrLen = sizeof(struct sockaddr_in);
    if(recvFrom->ss_family==AF_INET6) {
        addrLen = sizeof(struct sockaddr_in6);
    }
    ssize_t sent = sendto(
            sockfd,
            getPDUPointer(toSendPDU),
            (size_t)getPDULength(toSendPDU),
            0,
            (struct sockaddr*)recvFrom,
            addrLen
    );
    if(sent<0) {
        DBG("Error sending packet: %ld.",sent);
        perror(NULL);

    } else {
        DBG("Sent: %ld",sent);
    }


}


// Aux Functions
void printf_hex(unsigned char *hex, unsigned int l)
{
	int i;
	if (hex != NULL){	
		for (i=0; i < l; i++)
			printf("%02x",hex[i]);

		printf("\n");
	}
}



typedef int (*ResourceCallback)(CoapPDU *pdu, int sockfd, struct sockaddr_storage *recvFrom);

// using uthash for the URI hash table. Each entry contains a callback handler.
struct URIHashEntry {
	const char *uri; 
	ResourceCallback callback;
	int id;
	UT_hash_handle hh;
};

// callback functions defined here
int gTestCallback(CoapPDU *request, int sockfd, struct sockaddr_storage *recvFrom) {

	unsigned char *payload, *ptr;//, *auth;//, *token

	unsigned int len;
	uint8_t mac[16] ={0};
	uint8_t mac2check[16] ={0};
	uint8_t zero[16] ={0};

	socklen_t addrLen = sizeof(struct sockaddr_in);
	if(recvFrom->ss_family==AF_INET6) {
		addrLen = sizeof(struct sockaddr_in6);
	}
	DBG("gTestCallback function called");

	//  prepare appropriate response
	CoapPDU *response = _CoapPDU();
	setVersion(response,1);
	setMessageID(response,getMessageID(request));
	setToken(response,getTokenPointer(request),(uint8_t)getTokenLength(request));
	_setURI(response,(char*)"auth",4);
        addOption(response,COAP_OPTION_LOCATION_PATH, 1,(uint8_t *)&location_path);


	// respond differently, depending on method code
	switch(getCode(request)) {
		case COAP_EMPTY:
			// makes no sense, send RST
			break;


		case COAP_POST:

			nonce_s = rand();
            // Setting location Path to a number from 0..9

            	setCode(response, COAP_CREATED);
            	setPayload(response, (uint8_t *)&nonce_s, getPayloadLength(request));
		memcpy(&nonce_c, getPayloadPointer(request),(size_t)getPayloadLength(request));


			ptr = (unsigned char*)&sequence;

			memcpy(ptr,getTokenPointer(request),(size_t)getTokenLength(request));
			ptr += 4;

			memcpy(ptr, &(nonce_c),sizeof(unsigned int));
			ptr += 4;

			memcpy(ptr, &(nonce_s),sizeof(unsigned int));

    		// EAP Restart
			memset(&msk_key,0, MSK_LENGTH);
			eapRestart=TRUE;
			eap_peer_sm_step(NULL);

			break;

		case COAP_PUT:
			setCode(response,COAP_CHANGED);

			if(!eapKeyAvailable){ // EAP EXCHANGE FINISHED
				printf("---------------\nEAP EXCHANGE IN COURSE \n");

				eapReq=TRUE;
				payload = getPayloadPointer(request);

				eap_peer_sm_step(payload);

				if (eapResp){
                    			len = ntohs( ((struct eap_msg*) eapRespData)->length);
                    			setPayload(response,eapRespData, len);
				}
			}
			else{ 	

				/*	Verificamos la mac del mensaje recibido
				 * */

				// EAP EXCHANGE FINISHED
				printf("EAP EXCHANGE FINISHED\n");

				do_omac(msk_key, sequence,
						12, auth_key);
				authKeyAvailable=TRUE;

				memcpy(getPDUPointer(request)+getPDULength(request)-21,&zero,16);

				do_omac(auth_key, getPDUPointer(request),
						getPDULength(request), mac2check);

				addOption(response,COAP_OPTION_AUTH,16,(uint8_t *)&zero);


				isTime = 1;

			}

			break;

		default: 
			break;
	}

	// type
	switch(getType(request)) {

		case COAP_CONFIRMABLE:
			setType(response,COAP_ACKNOWLEDGEMENT);
			break;

		case COAP_NON_CONFIRMABLE:
			setType(response,COAP_ACKNOWLEDGEMENT);

			break;

        default:
          break;
	};


	if(eapKeyAvailable && isTime){
		do_omac(auth_key, getPDUPointer(response),
				getPDULength(response), mac);

		memcpy(getPDUPointer(response)+getPDULength(response)-16,&mac,16);

	}

	// send the packet
	ssize_t sent = sendto(
			sockfd,
			getPDUPointer(response),
            	(size_t)getPDULength(response),
			0,
			(struct sockaddr*)recvFrom,
			addrLen
			);
	if(sent<0) {
		DBG("Error sending packet: %ld.",sent);
		perror(NULL);
		return 1;
	} else {
		DBG("Sent: %ld",sent);
	}

    storeLastSentMessageInSession(response);


        return 0;
}

// resource URIs here
char const gURIA[] = "/auth";

const char *gURIList[] = {
	gURIA,
};

// URIs mapped to callback functions here
const ResourceCallback gCallbacks[] = {
	gTestCallback	
};

const int gNumResources = 1;

///////////// End Resource Stuff //////////////


int startAuth(int sockfd, struct addrinfo *remoteAddress)
{
	fd_set mreadset; /*master read set*/
	struct timeval  tval;
	int msecWait=2000;
	int maxRetr=3;
	//int state=0;
	//int last_length=0;
	ssize_t ret = 0;
	CoapPDU *request,*response;
	//bool valid = 0;

	/*********Preparing GET Auth**************/
	request = _CoapPDU();
	printf("pdu: ");
	printf_hex(getPDUPointer(request),(size_t)getPDULength(request));

	//setVersion(request,1);
	//printf("pdu: ");
	//printf_hex(getPDUPointer(request),(size_t)getPDULength(request));

	setType(request,COAP_CONFIRMABLE);
	printf("pdu: ");
	printf_hex(getPDUPointer(request),(size_t)getPDULength(request));

	setCode(request,COAP_GET);
	printf("pdu: ");
	printf_hex(getPDUPointer(request),(size_t)getPDULength(request));

	int token=1;
	setToken(request,(uint8_t*)&token,4);
	printf("pdu: ");
	printf_hex(getPDUPointer(request),(size_t)getPDULength(request));

	setMessageID(request,htons(0x0000));
	printf("pdu: ");
	printf_hex(getPDUPointer(request),(size_t)getPDULength(request));

	_setURI(request,(char*)"auth",4);
	printf("pdu: ");
	printf_hex(getPDUPointer(request),(size_t)getPDULength(request));

	/*****************************************/

	do {
		ret = sendto(sockfd,getPDUPointer(request),(size_t)getPDULength(request),0,remoteAddress->ai_addr,remoteAddress->ai_addrlen);

		if(ret != getPDULength(request)) {
			printf("Error sending packet.\n");
			perror(NULL);
			return -1;
		}

		printf("GET request sent\n");
		printHuman(request);
		printHex(request);

		FD_ZERO(&mreadset);
		FD_SET(sockfd, &mreadset);
		tval.tv_sec  = msecWait / 1000;
		tval.tv_usec = (msecWait % 1000) * 1000; 

		ret=select(sockfd+1, &mreadset, NULL, NULL, &tval);


		if (ret)
		{
			if (FD_ISSET(sockfd,&mreadset))
			{			
				//receive packet

				char buffer[500];
				struct sockaddr_in6 remote_addr6;
				socklen_t addr_size=sizeof(remote_addr6);
				bzero(&remote_addr6,sizeof(remote_addr6));

				ret = recvfrom(sockfd,&buffer,500,0,(struct sockaddr *) &(remote_addr6),&(addr_size));
				if(ret != -1) 
				{
					// validate packet
					response = _CoapPDU_buf((uint8_t*)buffer,(int)ret);
					if ((validate(response)==1) && (getMessageID(response) == getMessageID(request)) && 
							(getType(response) == COAP_ACKNOWLEDGEMENT)) 
					{	
						//valid = 1;
						printf("Valid ACK CoAP PDU received\n");
						printHuman(response);
						printHex(response);
						deallocCoapPDU(&response);					
						return 1;
					}
					else maxRetr--;

					deallocCoapPDU(&response);					

				} else maxRetr--;
			}
		} 
		else maxRetr--;

	} while (maxRetr != 0);

	return -1;
}






int main(int argc, char **argv) {


	// parse options	
	if(argc!=5) {
		printf("USAGE\r\n   %s listenAddress listenPort remoteAddress remotePort\r\n",argv[0]);
		return 0;
	}

	char *listenAddressString = argv[1];
	char *listenPortString    = argv[2];
	char *remoteAddressString = argv[3];
	char *remotePortString    = argv[4];

	struct addrinfo bindAddr;
	struct addrinfo *local,*remoteAddress;

	memset(&bindAddr, 0, sizeof(struct addrinfo));
	bindAddr.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
	bindAddr.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
	bindAddr.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

	int s = getaddrinfo(listenAddressString, listenPortString, &bindAddr, &local);

	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		return NULL;
	}

	// setup bind address
	INFO("Setting up bind address");
	printAddressStructures(&bindAddr);

	// setup socket
	int sockfd = socket(local->ai_family,local->ai_socktype,0);

	// call bind
	printf("Binding socket. %d\n",sockfd);
	if(bind(sockfd,local->ai_addr,local->ai_addrlen)!=0) {
		printf("Error binding socket");
		perror(NULL);
		failGracefully(5);
	}

	//
	printAddress(local);

	memset(&bindAddr, 0, sizeof(struct addrinfo));
	bindAddr.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
	bindAddr.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
	bindAddr.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

	//s =
    getaddrinfo(remoteAddressString, remotePortString, &bindAddr, &remoteAddress);
	printAddress(remoteAddress);

	startAuth(sockfd,remoteAddress);

	// setup URI callbacks using uthash hash table
	struct URIHashEntry *entry = NULL, *directory = NULL, *hash = NULL;
	for(int i=0; i<gNumResources; i++) {
		// create new hash structure to bind URI and callback
		entry = (struct URIHashEntry*)malloc(sizeof(struct URIHashEntry));
		entry->uri = gURIList[i];
		entry->callback = gCallbacks[i];
		// add hash structure to hash table, note that key is the URI
		HASH_ADD_KEYPTR(hh, directory, entry->uri, strlen(entry->uri), entry);
	}


	char buffer[BUF_LEN];
	char uriBuffer[URI_BUF_LEN];
	int recvURILen = 0;

	// storage for handling receive address
	struct sockaddr_storage recvAddr;
	socklen_t recvAddrLen = sizeof(struct sockaddr_storage);
	struct sockaddr_in *v4Addr;
	struct sockaddr_in6 *v6Addr;
	char straddr[INET6_ADDRSTRLEN];

    location_path = (rand()%9)+1;


    lastReceivedMessage = NULL;
    lastSentMessage = NULL;

	// reuse the same PDU
	CoapPDU *recvPDU = _CoapPDU_buf2((uint8_t*)buffer,BUF_LEN,BUF_LEN);

	// just block and handle one packet at a time in a single thread
	// you're not going to use this code for a production system are you ;)
	while(1) {
		// receive packet
		ssize_t ret = recvfrom(sockfd,&buffer,BUF_LEN,0,(struct sockaddr*)&recvAddr,&recvAddrLen);
		if(ret==-1) {
			INFO("Error receiving data");
			return -1;
		}

		// print src address
		switch(recvAddr.ss_family) {
			case AF_INET:
				v4Addr = (struct sockaddr_in*)&recvAddr;
				INFO("Got packet from %s:%d",inet_ntoa(v4Addr->sin_addr),ntohs(v4Addr->sin_port));
				break;

			case AF_INET6:
				v6Addr = (struct sockaddr_in6*)&recvAddr;
				INFO("Got packet from %s:%d",inet_ntop(AF_INET6,&v6Addr->sin6_addr,straddr,sizeof(straddr)),ntohs(v6Addr->sin6_port));
				break;
		    default:
                INFO("IP VERSION not recognized");
                break;
        }

		// validate packet
		if(ret>BUF_LEN) {
			INFO("PDU too large to fit in pre-allocated buffer");
			continue;
		}
		setPDULength(recvPDU,(int)ret);
		if(validate(recvPDU)!=1) {
			INFO("Malformed CoAP packet");
			continue;
		}
		INFO("Valid CoAP PDU received");
		printHuman(recvPDU);
		printHex(recvPDU);

		// depending on what this is, maybe call callback function
		if(getURI(recvPDU,uriBuffer,URI_BUF_LEN,&recvURILen)!=0) {
			INFO("Error retrieving URI");
			continue;
		}
		if(recvURILen==0) {
			INFO("There is no URI associated with this Coap PDU");
		} else {
            // Determine if the received message is duplicated
            if(lastReceivedMessage != NULL &&
               lastReceivedMessage_len == getPDULength(recvPDU) &&
                    memcmp(lastReceivedMessage, getPDUPointer(recvPDU), (size_t)lastReceivedMessage_len) == 0){
                INFO("Duplicated message");

                //sendLastMessage(sockfd,&recvAddr);
                //continue;
            }
            //else {
                HASH_FIND_STR(directory, uriBuffer, hash);
                if (hash) {
                    DBG("Hash id is %d.", hash->id);

                    storeLastReceivedMessageInSession(recvPDU);

                    hash->callback(recvPDU, sockfd, &recvAddr);
                    continue;
                } else {
                    DBG("Hash not found.");
                    continue;
                }
            //}
		}

		// no URI, handle cases

		// code==0, no payload, this is a ping request, send RST
		if(getPDULength(recvPDU)==0&&getCode(recvPDU)==0) {
			INFO("CoAP ping request");
		}

	}
	return 0;
}
