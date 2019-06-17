#include "session.h"
/*
Session::Session(){
	session_id = 0;
	pthread_mutex_init(&mutex, NULL);
	CURRENT_STATE = 0;
	msk_key = NULL;
	auth_key = NULL;
	key_len = 0;
	RTX_TIMEOUT = false;
	ISSET = false;
	RTX_COUNTER = 0;
	RTX_MAX_NUM;
	RT = 0.0;
	RT_INIT = 0.0;
	nonce_c = 0;
	nonce_s = 0;
	
};
*/
void Session::setMSK(uint8_t *msk, uint16_t len){
	memcpy(&msk_key,&msk,len);
	key_len = len;	
}

void Session::setAuthKey(uint8_t *authKey, uint16_t len){
	memcpy(&auth_key,&authKey,16);
}

