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
#define TIME_WAKE_UP 1000000


#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>


#include "cantcoap-master/nethelper.h"
#include "cantcoap-master/cantcoap.h"
#include "cantcoap-master/uthash.h"
#include "panautils.h"
#include "panatiki/include.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "panatiki/include.h"
#include "panatiki/eap-peer.h"
//#include "lalarm.h"


#ifdef __cplusplus
}
#endif


// Global Variables
int nonce_c;
int nonce_s;
int location_path;
unsigned char auth_key[16] = {0};
unsigned char sequence[12] = {0};
uint8_t authKeyAvailable;
bool isTime = false;

// Retransmission variables
uint8_t *lastReceivedMessage;
uint8_t *lastSentMessage;
int lastSentMessage_len;
int lastReceivedMessage_len;

/*
struct lalarm_coap* list_alarms_coap_eap = NULL;
float RT;
float RT_INIT;


// Retransmissions funtions
#define DEBUG 1
void print_list_alarms(){
#ifdef DEBUG
    struct lalarm_coap* ptr = list_alarms_coap_eap;

    while (ptr != NULL) {
        pana_debug("Showing session alarm id: %#X", ptr->coap_eap_session->session_id);
        pana_debug("Showing alarm type: %#X", ptr->id);
        ptr = ptr->sig;
    }
#endif
}
*/



void storeLastSentMessageInSession(CoapPDU *pdu){

    if(lastSentMessage != NULL)
    {
        free((void *) lastSentMessage);
        lastSentMessage = NULL;
    }

    lastSentMessage = (uint8_t *)malloc((size_t)pdu->getPDULength());
    memcpy(lastSentMessage,pdu->getPDUPointer() ,(size_t)pdu->getPDULength());
    lastSentMessage_len = pdu->getPDULength();
}

void storeLastReceivedMessageInSession(CoapPDU *pdu){

    if(lastReceivedMessage != NULL)
    {
        free((void *)lastReceivedMessage);
        lastReceivedMessage = NULL;
    }

    printf("Storing Last Received Message of length %d \n",pdu->getPDULength());

    lastReceivedMessage = (uint8_t *)malloc((size_t)pdu->getPDULength());
    memcpy(lastReceivedMessage,pdu->getPDUPointer() ,(size_t)pdu->getPDULength());
    lastReceivedMessage_len = pdu->getPDULength();

}

void sendLastMessage(int sockfd, struct sockaddr_storage *recvFrom){

    CoapPDU *toSendPDU = new CoapPDU(lastSentMessage, BUF_LEN, BUF_LEN);
    toSendPDU->setPDULength(lastSentMessage_len);
    if(toSendPDU->validate() != 1){
        INFO("ERROR: Non valid PDU");
    }


    socklen_t addrLen = sizeof(struct sockaddr_in);
    if(recvFrom->ss_family==AF_INET6) {
        addrLen = sizeof(struct sockaddr_in6);
    }
    ssize_t sent = sendto(
            sockfd,
            toSendPDU->getPDUPointer(),
            (size_t)toSendPDU->getPDULength(),
            0,
            (sockaddr*)recvFrom,
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
	CoapPDU *response = new CoapPDU();
	response->setVersion(1);
	response->setMessageID(request->getMessageID());
	response->setToken(request->getTokenPointer(),(uint8_t)request->getTokenLength());
	response->setURI((char*)"auth",4);
    response->addOption(CoapPDU::COAP_OPTION_LOCATION_PATH, 1,(uint8_t *)&location_path);


	// respond differently, depending on method code
	switch(request->getCode()) {
		case CoapPDU::COAP_EMPTY:
			// makes no sense, send RST
			break;


		case CoapPDU::COAP_POST:

			nonce_s = rand();
            // Setting location Path to a number from 0..9

            response->setCode(CoapPDU::COAP_CREATED);
            response->setPayload(  (uint8_t *)&nonce_s, request->getPayloadLength());
			memcpy(&nonce_c, request->getPayloadPointer(),(size_t)request->getPayloadLength());


			ptr = (unsigned char*)&sequence;

			memcpy(ptr,request->getTokenPointer(),(size_t) request->getTokenLength());
			ptr += 4;

			memcpy(ptr, &(nonce_c),sizeof(unsigned int));
			ptr += 4;

			memcpy(ptr, &(nonce_s),sizeof(unsigned int));

    		// EAP Restart
			memset(&msk_key,0, MSK_LENGTH);
			eapRestart=TRUE;
			eap_peer_sm_step(NULL);

			break;

		case CoapPDU::COAP_PUT:
			response->setCode(CoapPDU::COAP_CHANGED);

			if(!eapKeyAvailable){ // EAP EXCHANGE FINISHED
				printf("---------------\nEAP EXCHANGE IN COURSE \n");

				eapReq=TRUE;
				payload = request->getPayloadPointer();

				eap_peer_sm_step(payload);

				if (eapResp){
                    len = ntohs( ((struct eap_msg*) eapRespData)->length);
                    response->setPayload(eapRespData, len);
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

				memcpy(request->getPDUPointer()+request->getPDULength()-21,&zero,16);

				do_omac(auth_key, request->getPDUPointer(),
						request->getPDULength(), mac2check);

				response->addOption(CoapPDU::COAP_OPTION_AUTH,16,(uint8_t *)&zero);


				isTime = true;

			}

			break;

		default: 
			break;
	}

	// type
	switch(request->getType()) {

		case CoapPDU::COAP_CONFIRMABLE:
			response->setType(CoapPDU::COAP_ACKNOWLEDGEMENT);
			break;

		case CoapPDU::COAP_NON_CONFIRMABLE:
			response->setType(CoapPDU::COAP_ACKNOWLEDGEMENT);

			break;

        default:
          break;
	};


	if(eapKeyAvailable && isTime){
		do_omac(auth_key, response->getPDUPointer(),
				response->getPDULength(), mac);

		memcpy(response->getPDUPointer()+response->getPDULength()-16,&mac,16);

	}

	// send the packet
	ssize_t sent = sendto(
			sockfd,
			response->getPDUPointer(),
            (size_t)response->getPDULength(),
			0,
			(sockaddr*)recvFrom,
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
/*
    RT = RT_INIT;
    add_alarm_coap_eap(&(list_alarms_coap_eap),NULL,RT,POST_ALARM);
*/
    return 0;
}

// resource URIs here
const char *gURIA = "/auth";

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
	request = new CoapPDU();
	request->setVersion(1);
	request->setType(CoapPDU::COAP_CONFIRMABLE);
	request->setCode(CoapPDU::COAP_GET);
	int token=1;
	request->setToken((uint8_t*)&token,4);
	request->setMessageID(htons(0x0000));
	request->setURI((char*)"auth",4);
	/*****************************************/

	do {
		ret = sendto(sockfd,request->getPDUPointer(),(size_t)request->getPDULength(),0,remoteAddress->ai_addr,remoteAddress->ai_addrlen);

		if(ret != request->getPDULength()) {
			printf("Error sending packet.\n");
			perror(NULL);
			return -1;
		}

		printf("GET request sent\n");
		request->printHuman();
		request->printHex();

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
					response = new CoapPDU((uint8_t*)buffer,(int)ret);
					if ((response->validate()==1) && (response->getMessageID() == request->getMessageID()) && 
							(response->getType() == CoapPDU::COAP_ACKNOWLEDGEMENT)) 
					{	
						//valid = 1;
						printf("Valid ACK CoAP PDU received\n");
						response->printHuman();
						response->printHex();
						delete response;					
						return 1;
					}
					else maxRetr--;

					delete response;

				} else maxRetr--;
			}
		} 
		else maxRetr--;

	} while (maxRetr != 0);

	return -1;
}



/*
void * handle_alarm_coap_management() {

    printf("Enter handle_alarm_coap_management\n");

    while (TRUE){ // Do it while the PAA is activated.

        print_list_alarms();

        //struct retr_coap_func_parameter retrans_params;
        // Get the actual timestamp.
        double time = getTime();
        //printf("time: %d\n",time);

        struct lalarm_coap* alarm = NULL;
        while ((alarm=get_next_alarm_coap_eap(&list_alarms_coap_eap, time)) != NULL)
        {
            printf("Looking for alarms\n");

           // retrans_params.session = (coap_eap_ctx *)alarm->coap_eap_session;
           // retrans_params.id = 0;

            if (alarm->id == POST_ALARM)
            {
                printf("A POST_AUTH alarm ocurred\n");
             //   retrans_params.id = POST_ALARM;
             //   add_task(process_retr_coap_eap, &retrans_params);
            }
            else { // An unknown alarm is activated.
                printf("\nAn UNKNOWN alarm ocurred\n");
            }
        }
        waitusec(TIME_WAKE_UP);
    }
    return NULL;
}

*/

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
	CoapPDU *recvPDU = new CoapPDU((uint8_t*)buffer,BUF_LEN,BUF_LEN);

	// just block and handle one packet at a time in a single thread
	// you're not going to use this code for a production system are you ;)
	while(1) {
		// receive packet
		ssize_t ret = recvfrom(sockfd,&buffer,BUF_LEN,0,(sockaddr*)&recvAddr,&recvAddrLen);
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
		recvPDU->setPDULength((int)ret);
		if(recvPDU->validate()!=1) {
			INFO("Malformed CoAP packet");
			continue;
		}
		INFO("Valid CoAP PDU received");
		recvPDU->printHuman();
		recvPDU->printHex();

		// depending on what this is, maybe call callback function
		if(recvPDU->getURI(uriBuffer,URI_BUF_LEN,&recvURILen)!=0) {
			INFO("Error retrieving URI");
			continue;
		}
		if(recvURILen==0) {
			INFO("There is no URI associated with this Coap PDU");
		} else {
            // Determine if the received message is duplicated
            if(lastReceivedMessage != NULL &&
               lastReceivedMessage_len == recvPDU->getPDULength() &&
                    memcmp(lastReceivedMessage, recvPDU->getPDUPointer(), (size_t)lastReceivedMessage_len) == 0){
                INFO("Duplicated message");

                sendLastMessage(sockfd,&recvAddr);
                continue;
            }
            else {
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
            }
		}

		// no URI, handle cases

		// code==0, no payload, this is a ping request, send RST
		if(recvPDU->getPDULength()==0&&recvPDU->getCode()==0) {
			INFO("CoAP ping request");
		}

	}
	return 0;
}
