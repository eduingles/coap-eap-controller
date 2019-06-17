/**
 * @file coap_eap_session.c
 * @brief Functions to manage PANA sessions.
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

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/timeb.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "coap_eap_session.h"
#include <math.h>
#include <sys/time.h>

#ifdef __cplusplus
}
#endif

int
coap_prng_impl(unsigned char *buf, size_t len) {
  time_t t;
  srand((unsigned) time(&t));
    while (len--)
        *buf++ = rand() & 0xFF;
    return 1;
}


void init_CoAP_EAP_Session(coap_eap_ctx* coap_eap_session){
	
	    struct timeval start, end;
 
		long mtime, seconds, useconds;   
 
		gettimeofday(&end, NULL);
	 
	    seconds  = end.tv_sec;
	    useconds = end.tv_usec;
	 
	    mtime = seconds + useconds;
	 
		srand(mtime);
	 
	 coap_eap_session->session_id 		= rand();
	 printf("New session_id %X\n",htons(coap_eap_session->session_id));
	 
	 coap_eap_session->message_id 			= 1;
	 coap_eap_session->CURRENT_STATE		= 0;
	 coap_eap_session->RTX_COUNTER 			= 0;
	 coap_eap_session->ISSET 			= 0;
	 coap_eap_session->lastSentMessage 		= NULL;
	 coap_eap_session->lastReceivedMessage 	= NULL;
	 coap_eap_session->location 			= strdup("/b");

	 coap_eap_session->eap_workarround = 0;
	 memset(coap_eap_session->userID,0,40);
    printf("coap_eap_session->RTX_COUNTER %d\n", coap_eap_session->RTX_COUNTER);

    unsigned char rand_value;
    coap_prng_impl(&rand_value, 1);//prng(&rand_value,1);

    printf("rand_value %d\n", rand_value);
    coap_eap_session->RT = (((double)rand_value/(double)255)) + (double)2;
    //coap_eap_session->RT = (rand()/255)%10 + (float)2;

     printf("The  RT is %lf\n", coap_eap_session->RT);
	 coap_eap_session->RT_INIT = coap_eap_session->RT;
	 printf("\nfirst RT %lf\n", coap_eap_session->RT_INIT);

	 coap_eap_session->auth_key = NULL;
	 coap_eap_session->msk_key = NULL;
	 coap_eap_session->key_len = 0;
	
	
	 //coap_eap_session->recvAddr = XMALLOC(struct sockaddr_storage,1);
          
	 /*Rafa: We create a session id based on the token*/
	 pthread_mutex_init(&(coap_eap_session->mutex), NULL);
	 load_config_server();
	 // Init EAP authenticator.
	 eap_auth_init(&(coap_eap_session->eap_ctx), coap_eap_session, CA_CERT, SERVER_CERT, SERVER_KEY);

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

/* reverse:  reverse string s in place */
 void reverse(char s[])
 {
     int i, j;
     char c;
 
     for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
         c = s[i];
         s[i] = s[j];
         s[j] = c;
     }
 }

void itoa(int n, char s[])
 {
     int i, sign;
 
     if ((sign = n) < 0)  /* record sign */
         n = -n;          /* make n positive */
     i = 0;
     do {       /* generate digits in reverse order */
         s[i++] = n % 10 + '0';   /* get next digit */
     } while ((n /= 10) > 0);     /* delete it */
     if (sign < 0)
         s[i++] = '-';
     s[i] = '\0';
     reverse(s);
 }


