/**
 * @file coap_eap_statemachine.c
 * @brief  State machine's common functions implementation.
 **/
/*
 *  Copyright (C) Pedro Moreno Sánchez & Francisco Vidal Meca on 2011.
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
#ifdef __cplusplus
extern "C" {
#endif

#include "coap_eap_statemachine.h"
#include "coap_eap_session.h"
#include "../lalarm.h"

#ifdef __cplusplus
}
#endif

int order_opts(void *a, void *b) {
  if (!a || !b)
    return a < b ? -1 : 1;

  if (COAP_OPTION_KEY(*(coap_option *)a) < COAP_OPTION_KEY(*(coap_option * )b))
    return -1;

  return COAP_OPTION_KEY(*(coap_option * )a)
    == COAP_OPTION_KEY(*(coap_option * )b);
}

coap_list_t *
new_option_node(unsigned short key, unsigned int length, unsigned char *data) {
  coap_option *option;
  coap_list_t *node;

  option = coap_malloc(sizeof(coap_option) + length);
  if (!option)
    goto error;

  COAP_OPTION_KEY(*option) = key;
  COAP_OPTION_LENGTH(*option) = length;
  memcpy(COAP_OPTION_DATA(*option), data, length);

  /* we can pass NULL here as delete function since option is released automatically  */
  node = coap_new_listnode(option, NULL);

  if (node)
    return node;

error: perror("new_option_node: malloc");
       coap_free(option);
       return NULL;
}

void cmdline_uri(char *arg,coap_uri_t *uri,coap_list_t **optlist) {
  unsigned char portbuf[2];
#define BUFSIZE 40
  unsigned char _buf[BUFSIZE];
  unsigned char *buf = _buf;
  size_t buflen;
  int res;
  str proxy = { 0, NULL };

  if (proxy.length) { /* create Proxy-Uri from argument */
    size_t len = strlen(arg);
    while (len > 270) {
      coap_insert(optlist,
          new_option_node(COAP_OPTION_PROXY_URI, 270,
            (unsigned char *) arg), order_opts);
      len -= 270;
      arg += 270;
    }

    coap_insert(optlist,
        new_option_node(COAP_OPTION_PROXY_URI, len,
          (unsigned char *) arg), order_opts);
  } else { /* split arg into Uri-* options */
    coap_split_uri((unsigned char *) arg, strlen(arg), uri);

    if (uri->port != COAP_DEFAULT_PORT) {
      coap_insert(optlist,
          new_option_node(COAP_OPTION_URI_PORT,
            coap_encode_var_bytes(portbuf, uri->port), portbuf),
          order_opts);
    }

    if (uri->path.length) {
      buflen = BUFSIZE;
      res = coap_split_path(uri->path.s, uri->path.length, buf, &buflen);

      while (res--) {
        coap_insert(optlist,
            new_option_node(COAP_OPTION_URI_PATH,
              COAP_OPT_LENGTH(buf), COAP_OPT_VALUE(buf)),
            order_opts);

        buf += COAP_OPT_SIZE(buf);
      }
    }

    if (uri->query.length) {
      buflen = BUFSIZE;
      buf = _buf;
      res = coap_split_query(uri->query.s, uri->query.length, buf, &buflen);

      while (res--) {
        coap_insert(optlist,
            new_option_node(COAP_OPTION_URI_QUERY,
              COAP_OPT_LENGTH(buf), COAP_OPT_VALUE(buf)),
            order_opts);

        buf += COAP_OPT_SIZE(buf);
      }
    }
  }
}

int resolve_address(const str *server, struct sockaddr *dst) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error, len = -1;

  memset(addrstr, 0, sizeof(addrstr));
  if (server->length)
    memcpy(addrstr, server->s, server->length);
  else
    memcpy(addrstr, "localhost", 9);

  memset((char *) &hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, "", &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
    switch (ainfo->ai_family) {
      case AF_INET6:
      case AF_INET:
        len = ainfo->ai_addrlen;
        memcpy(dst, ainfo->ai_addr, len);
        goto finish;
      default:
        ;
    }
  }

finish: freeaddrinfo(res);
        return len;
}

void rand_str(char *dest, size_t length) {
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
}


coap_pdu_t *
coap_new_request(coap_context_t *ctx, method_t m, coap_list_t *options) {
  coap_pdu_t *pdu;
  coap_list_t *opt;

  if (!(pdu = coap_new_pdu()))
    return NULL;

  pdu->hdr->type = COAP_MESSAGE_CON;
  pdu->hdr->id = coap_new_message_id(ctx);
  pdu->hdr->code = m;

  printf("\n ******** ENVIO PRIMER POST ******** \n");

  char mitoken[8];
  rand_str(&mitoken,8);
  printf("Envio Token: %s\n", mitoken);
unsigned char _token_data[8] = "12345678";
str the_token = { 0, _token_data };
  strncpy((char *)the_token.s, mitoken, min(sizeof(_token_data), strlen(mitoken)));
  the_token.length = strlen(mitoken);



  pdu->hdr->token_length = the_token.length;
  if (!coap_add_token(pdu, the_token.length, the_token.s)) {
    debug("cannot add token to request\n");
  }

  // Pillamos opciones como uri-path
  for (opt = options; opt; opt = opt->next) {
    coap_add_option(pdu, COAP_OPTION_KEY(*(coap_option * )opt->data),
        COAP_OPTION_LENGTH(*(coap_option * )opt->data),
        COAP_OPTION_DATA(*(coap_option * )opt->data));
  }
  /* Mandamos primer post vacio */
  coap_add_data(pdu, 0, "");

  printf("Envio Paquete: \n");
  coap_show_pdu(pdu);

  return pdu;
}


// Init the state machine table's positions
void _initTable() {
    table [INITIAL][RECV_GET_AUTH] = handler_get_auth;

    table [WAIT_ACK_POST][RECV_ACK_POST] = handler_ack_post;

    table [WAIT_ACK_PUT][RECV_ACK_PUT] = handler_ack_put;
 
    table [WAIT_ACK_AUTH_PUT][RECV_ACK_AUTH_PUT] = handler_ack_auth_put;

    table [AUTH][RECV_GET_AUTH] = allEventClosedState ;

    table [AUTH][RECV_ACK_POST] =allEventClosedState; 

    table [AUTH][RECV_ACK_PUT] =  allEventClosedState ;
    table [AUTH][RECV_ACK_AUTH_PUT] = allEventClosedState ;

    table [AUTH][TIMEOUT_AUTH] = deleteState;
    
    table [INITIAL][RETRANSMISSION] = retransmission;

    table [WAIT_ACK_POST][RETRANSMISSION] = retransmission;

    table [WAIT_ACK_PUT][RETRANSMISSION] = retransmission;
 
    table [WAIT_ACK_AUTH_PUT][RETRANSMISSION] = retransmission;

    table [AUTH][RETRANSMISSION] = allEventClosedState ;

}

coap_pdu_t *
coap_new_request(coap_context_t *ctx, method_t m, coap_list_t *options) {
  coap_pdu_t *pdu;
  coap_list_t *opt;

  if (!(pdu = coap_new_pdu()))
    return NULL;

  pdu->hdr->type = COAP_MESSAGE_CON;
  pdu->hdr->id = coap_new_message_id(ctx);
  pdu->hdr->code = m;

  printf("\n ******** ENVIO PRIMER POST ******** \n");

  char mitoken[8];
  rand_str(&mitoken,8);
  printf("Envio Token: %s\n", mitoken);
  strncpy((char *)the_token.s, mitoken, min(sizeof(_token_data), strlen(mitoken)));
  the_token.length = strlen(mitoken);



  pdu->hdr->token_length = the_token.length;
  if (!coap_add_token(pdu, the_token.length, the_token.s)) {
    debug("cannot add token to request\n");
  }

  // Pillamos opciones como uri-path
  for (opt = options; opt; opt = opt->next) {
    coap_add_option(pdu, COAP_OPTION_KEY(*(coap_option * )opt->data),
        COAP_OPTION_LENGTH(*(coap_option * )opt->data),
        COAP_OPTION_DATA(*(coap_option * )opt->data));
  }
  /* Mandamos primer post vacio */
  coap_add_data(pdu, 0, "");

  printf("Envio Paquete: \n");
  coap_show_pdu(pdu);

  return pdu;
}

coap_pdu_t *
coap_new_request2(coap_context_t *ctx, method_t m, coap_list_t *options,
    unsigned char *datos, int longituddatos) {
  coap_pdu_t *pdu;
  int len =longituddatos;
  coap_list_t *opt;
  unsigned char *datos2 = NULL;
  unsigned char buf[3];
  int longitt = 0;
  nput++;

  printf("\n ******** PUT NUMERO %d ******** \n",nput);

  if (!(pdu = coap_new_pdu()))
    return NULL;

  pdu->hdr->type = msgtype;
  pdu->hdr->id = coap_new_message_id(ctx);
  pdu->hdr->code = m;

  char mitoken[8];
  rand_str(&mitoken,8);
  printf("Envio Token: %s\n", mitoken);

  strncpy((char *)the_token.s, mitoken, min(sizeof(_token_data), strlen(mitoken)));
  the_token.length = strlen(mitoken);

  pdu->hdr->token_length = the_token.length;
  if (!coap_add_token(pdu, the_token.length, the_token.s)) {
    debug("cannot add token to request\n");
  }

if (location) {
    printf("LOCATION_PATH: %s\n",location);
    coap_add_option(pdu, COAP_OPTION_LOCATION_PATH,8,location);
  } 

  for (opt = options; opt; opt = opt->next) {
    coap_add_option(pdu, COAP_OPTION_KEY(*(coap_option * )opt->data),
        COAP_OPTION_LENGTH(*(coap_option * )opt->data),
        COAP_OPTION_DATA(*(coap_option * )opt->data));
    break;
  }

  // Initialize eap_server
  if (initeap){
    eap_coap_server_init();
    initeap = 0;
  }

  eap_coap_server_step(datos, &datos2, &len, &key);
  coap_add_option(pdu, COAP_OPTION_CONTENT_TYPE,
      coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_OCTET_STREAM), buf);
  if (key) {
    coap_add_option(pdu, COAP_OPTION_AUTH,16,0);
  }
  coap_add_data(pdu, len, (const unsigned char *) datos2);

  if (key) {
    printf("\n ** TENEMOS CLAVE: ");
    for(longitt=0;longitt<16;longitt++){
      printf("%02x",key[longitt]);
    }
    printf("\n");
    unsigned char mac[16] = {0};
    override_auth_option_pdu(key, &mac, pdu);
  }
  printf("Envio Paquete: ");
  coap_show_pdu(pdu);

  return pdu;
}





int handler_get_auth()
{
        coap_list_t *optlist = NULL;
        coap_uri_t uri;

        cmdline_uri("coap://[::1]/auth",&uri,&optlist);
        str server = uri.host;
        unsigned short port = uri.port;

	printf("process_receive_coap_get_auth uri.port %d\n", uri.port);

       coap_address_t dst;
       /* resolve destination address where server should be sent */
       int res = resolve_address(&server, &dst.addr.sa);

       if (res < 0) {
            printf("failed to resolve address\n");
            return NULL;
       }

       dst.size = res;
       dst.addr.sin.sin_port = htons(8000);
       /*Sending a POST*/
       coap_pdu_t *pdu;
       coap_tid_t tid = COAP_INVALID_TID;
       unsigned int method = 2;
       if (!(pdu = coap_new_request(coap_eap_session->ctx, method, optlist)))
         return -1;
     
      if (pdu->hdr->type == COAP_MESSAGE_CON)
      {
          printf("Sending message\n");
          tid = coap_send_confirmed(coap_eap_session->ctx, &dst, pdu);
      }
      else
          tid = coap_send(coap_eap_session->ctx, &dst, pdu);

      if (pdu->hdr->type != COAP_MESSAGE_CON || tid == COAP_INVALID_TID)
         coap_delete_pdu(pdu);

      add_alarm_coap_eap(&(list_alarms_coap_eap),coap_eap_session,50,POST_ALARM);

      printf("Saliendo de process_receive_coap_get_auth\n");
   _rtxTimerStart();

   return WAIT_ACK_POST;
}


int handler_ack_post()
{
   coap_read(current_session->ctx); /* read received data */
   eapRestart();

}


int handler_ack_put()
{
	 unsigned char *datosdelack = NULL;
         size_t *longituddatosack = NULL;
         int longg = 0;

         coap_read(current_session->ctx); /* read received data */
         coap_get_data(ctx->recvqueue->pdu, &longituddatosack, &datosdelack);
         coap_dispatch(current_session->ctx);

         eap_auth_set_eapResp(&(current_session->eap_ctx), TRUE);
         eap_auth_set_eapRespData(&(current_session->eap_ctx), datosdelack, longituddatosack);
         eap_auth_step(&(current_session->eap_ctx));
    
         add_alarma(current_session->list_of_alarms, current_session, 1, RETR_AAA); //FIXME: El tiempo de retransmsiones de EAP
																		      	       pana_debug("Finished txEAP function\n");
}

int transition_coap_eap(coap_eap_ctx *coap_eap_session) 
{
    if (coap_eap_session == NULL || coap_eap_session->CURRENT_STATE > NUM_STATES) 
    {
        return ERROR;
    }

    current_session = coap_eap_session;
     
    pana_debug("Trying a transition..");
    pana_debug("Session ID: %d, current state: %s", current_session->session_id, state_name[current_session->CURRENT_STATE + 1]);

    int i; // Events' iterator
    int rs = ERROR; // result state
    for (i = 0; i < NUM_EVENTS && rs == ERROR; i++) {
        if (table[current_session->CURRENT_STATE][i] != NULL) {
            rs = table[current_session->CURRENT_STATE][i]();
        }
    }

	if (rs == ERROR)
		return ERROR;
		
	printf("COAP_EAP: Entering state: %s (Session ID: %s).\n", state_name[rs + 1], current_session->session_id);
	if (rs != NO_CHANGE) {
		coap_eap_session->CURRENT_STATE = rs;
    }
    
    return 0;
  
}

// Common Procedures

void disconnect() {

}

int authorize() {

	 return 1; 
    
}

void retransmit() {

        coap_queue_t *nextpdu;
	pana_debug("Message to retransmit:");
        
        nextpdu = coap_peek_next(current_session->ctx);

        current_session->RTX_TIMEOUT = 0;
        
        coap_retransmit(current_session->ctx, coap_pop_next( current_session->ctx ));

        current_session->RTX_COUNTER += 1;
        
        current_session->RT = MAX_WAIT_SECONDS;
        add_alarma(current_session->list_of_alarms, current_session, current_session->RT, RETR_ALARM);

}

void _rtxTimerStart() {
	pana_debug("rtxTimerStart function");

    current_session->RTX_COUNTER = 0; // Reset retransmission's counter
    //current_session->RTX_MAX_NUM; //This value is updated in the session's initialization

    current_session->RT = MAX_WAIT_SECONDS;

    add_alarma(current_session->list_of_alarms, current_session, current_session->RT, RETR_ALARM);

}

void _rtxTimerStop() {
	pana_debug("rtxTimerStop  function");

    if (current_session == NULL) {
		pana_debug("There isn't any session associated");
        return;
    }
    coap_eap_ctx *session = get_alarm_coap_eap_session(current_session->list_of_alarms, current_session->session_id, RETR_ALARM);
}

void _sessionTimerReStart(int timeout) {
	pana_debug("sessionTimerReStart function. Timeout: %d", timeout); 
	//Get the alarm of this session
        coap_eap_ctx * session = get_alarm_coap_eap_session(current_session->list_of_alarms, current_session->session_id, SESS_ALARM);
	
	//Add the alarm with the new expiration time
	add_alarma(current_session->list_of_alarms, current_session, timeout, SESS_ALARM);
}

void _eapRestart() {
	pana_debug("eapRestart function");

	//It is necesary reset the session's variables used to generate the pana auth key
	// due to the eap conversation will be reinited
	
	//FIXME: Hay que liberar la msk_key?
	current_session->msk_key = NULL;
	current_session->key_len = 0;
	//FIXME: Hay que liberar la estructura current_session->avp_data?

	/*if (current_session->avp_data!=NULL){
		//XFREE(current_session->avp_data[AUTH_AVP]);
		current_session->avp_data[AUTH_AVP] = NULL;
	}*/
	
        eap_auth_set_eapRestart(&(current_session->eap_ctx), TRUE);
        eap_auth_step(&(current_session->eap_ctx));
        pana_debug("eapReStart: EAP has been properly restarted.\n");
}

void _txEAP() {
	
    pana_debug("txEAP function");

    //The Response value of EAPsession must be set to true   
    //only for PANA servers
    eap_auth_set_eapResp(&(current_session->eap_ctx), TRUE);
    printf("Rafa: Aquí va el paquete EAP recibido de la mota\n");	
    //eap_auth_set_eapRespData(&(current_session->eap_ctx), elmntvalue, ntohs(elmnt->length));
    eap_auth_step(&(current_session->eap_ctx));
    
    add_alarma(current_session->list_of_alarms, current_session, 1, RETR_AAA); //FIXME: El tiempo de retransmsiones de EAP
																		      	  pana_debug("Finished _txEAP function\n");
}

void _sessionTimerStop() {

	pana_debug("sessionTimerStop function");
	//Get the alarm of this session
	coap_eap_ctx * session = get_alarm_coap_eap_session(current_session->list_of_alarms, current_session->session_id,SESS_ALARM);
	pana_debug("sessionTimerStop finished");
}

int _generatePanaSa() { // See RFC 5609 Page 8
	pana_debug("generatePanaSa function");
    //TODO: Falta la implementación
    //If the EAP method does not generate a key (MSK)
    // return FALSE;
    
    #ifdef ISCLIENT
	/* Check if the PaC can match the PRF and Integrity algorithm AVPs
	 * advertised by the PAA in PAR[S] message */
	 // If the algorithms cannot be matched, return false.
    #endif
    
    #ifdef ISSERVER
    /* Indicate whether a PRF and Integrity algorithm AVPs will be sent
     * in the PAR[S]. If a non-generating algorithm is used, return false.
     * */
    #endif
    
    return TRUE;
}

int _keyAvailable() {
		//Variable to store if there's an EAP key available
	int eapKeyAvailable = FALSE; 
	eapKeyAvailable = eap_auth_get_eapKeyAvailable(&(current_session->eap_ctx));
		//Tries to retrieve a Master Session Key (MSK) from the EAP entity
		if (eapKeyAvailable == TRUE) {
			pana_debug("EAP lower-layer Key Available");
			unsigned int key_len;
			u8* key = NULL;
			key = eap_auth_get_eapKeyData(&(current_session->eap_ctx), &key_len);
			//The key and its length must be copied into the pana context
			coap_eap_ctx * session = current_session;
			session->key_len = key_len;
			if(session->msk_key != NULL){
				XFREE(session->msk_key);
				session->msk_key = NULL;
			}
			session->msk_key = XCALLOC(u8, key_len);
			memcpy(session->msk_key, key, key_len);

			//We generate the AUTH_OPTION
			u8 * new_auth_key = NULL;
			//new_auth_key = generateAUTH(current_session);
			if(new_auth_key != NULL){
				XFREE(current_session->avp_data[AUTH_AVP]);
				current_session->avp_data[AUTH_AVP] = new_auth_key;
			}
			else{
				pana_debug("KeyAvailable - Generated AUTH key is NULL!");
			}
			//If !=NULL the key generation was successful
			return current_session->avp_data[AUTH_AVP]!=NULL;
		}
		else //If an MSK isn't retrieved
			return FALSE;
}

// Common functions

int _retransmission() {
    if ((current_session->RTX_TIMEOUT && (current_session->RTX_COUNTER < current_session->RTX_MAX_NUM))) {
        retransmit();
        return NO_CHANGE;
    } else
        return ERROR;
}

int _reachMaxNumRt() {
    if ((current_session->RTX_TIMEOUT && current_session->RTX_COUNTER >= current_session->RTX_MAX_NUM) || current_session->SESS_TIMEOUT) {
        disconnect();
        return CLOSED;
    } else
        return ERROR;
}


int _allEventClosedState() {
    return CLOSED;
}

