/**
 * @file coap_eap_session.h
 * @brief Headers of functions to manage PANA sessions.
 **/
/*
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 2010.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *  
 *  
 *  https://sourceforge.net/projects/openpana/
 */

#ifndef COAP_EAP_SESSION_H
#define COAP_EAP_SESSION_H

#include "../include.h"

#ifdef __cplusplus
extern "C"{
#endif

#include "../loadconfig.h"
#include "../libeapstack/eap_auth_interface.h"
#include "../wpa_supplicant/src/utils/common.h"
#include "../include.h"

#ifdef __cplusplus
}
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <stdlib.h>


#define MAX_WAIT_SECONDS 90
#define BUF_LEN 500





typedef struct
{

  uint8_t * lastSentMessage;
  int lastSentMessage_len;
  
  
  uint8_t * lastReceivedMessage;
  int lastReceivedMessage_len;
  
  struct sockaddr_storage recvAddr;

  uint16_t message_id;

 pthread_mutex_t mutex;
 struct eap_auth_ctx eap_ctx;
 uint32_t session_id;
 uint16_t CURRENT_STATE;
 /**Contains MSK key value when generated.*/
    u8 *msk_key;
    u8 *auth_key; //It will have 16 bytes
 /**MSK key length.*/
    uint16_t key_len;

   /**
     * This event variable is set to TRUE when the retransmission timer
     * is expired.
     */
    bool RTX_TIMEOUT;
    bool ISSET;
    /**
     * This variable contains the current number of retransmissions of
     * the outstanding PANA message.
     */
    uint16_t RTX_COUNTER;
    int RTX_COUNTER_AAA;/**< Number of retransmission to AAA*/

    /**
     * Configurable maximum for how many retransmissions should be
     * attempted before aborting.
     */
    int RTX_MAX_NUM;
/*
    float RT;
    float RT_INIT;
*/
    double RT;
    double RT_INIT;

    unsigned int nonce_c;
    unsigned int nonce_s;
    char userID[45];


   /**Alarm list.*/
    struct lalarm_coap** list_of_alarms; 
    /*char token[20];
    int token_length;*/ 
    char uri_str[100];
    unsigned char uri_opt_str[40];
    int uri_opt_str_n;
//    unsigned char location[8];
     char *location;
	int eap_workarround;
    //coap_address_t remote;	/**< remote address */  

} coap_eap_ctx;

/** Initializes the pana_ctx structure refered to a new PANA session.
 *
 * @param *pana_session Session that gonna be initialized*/

void rand_str(char *dest, size_t length);
void init_CoAP_EAP_Session(coap_eap_ctx* coap_eap_session);

#endif


