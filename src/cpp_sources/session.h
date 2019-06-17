#ifndef SESSION_H
#define SESSION_H

#define __USE_POSIX 1
#include <sys/time.h>
#include <math.h>


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
#include <pthread.h>
/*
#include "panatiki/include.h"
#include "panatiki/eap-peer.h"
#include "panatiki/eap-psk.h"
#include "cantcoap-master/nethelper.h"
#include "cantcoap-master/cantcoap.h"
#include "cantcoap-master/uthash.h"
*/

class Session{

	private:
	Session(){
		pthread_mutex_init(&mutex, NULL);
	}
	public:

//	 coap_context_t  *ctx;
	 pthread_mutex_t mutex;

	 uint32_t session_id;
	 uint16_t CURRENT_STATE;
	 //Contains MSK key value when generated.
	 uint8_t *msk_key;
	 uint8_t *auth_key; //It will have 16 bytes
	 //MSK key length.
	 uint16_t key_len;

	   
	     // This event variable is set to TRUE when the retransmission timer
	     // is expired.
	     
	    bool RTX_TIMEOUT;
	    bool ISSET;
	    
	     // This variable contains the current number of retransmissions of
	     // the outstanding PANA message.
	     
	    uint16_t RTX_COUNTER;

	    
	     // Configurable maximum for how many retransmissions should be
	     // attempted before aborting.
	     
	    int RTX_MAX_NUM;

	    float RT;
	    float RT_INIT;
	
	    unsigned int nonce_c;
	    unsigned int nonce_s;

	    // Alarm list
//	    struct lalarm_coap** list_of_alarms; 
	    /*char token[20];
	    int token_length;*/ 
//	    char uri_str[100];
//	    unsigned char uri_opt_str[40];
//	    int uri_opt_str_n;
//	    unsigned char location[8];
//	    coap_address_t remote;	/**< remote address */  


		void setMSK(uint8_t *msk, uint16_t len);
		void setAuthKey(uint8_t *authKey, uint16_t len);


};


#endif

















