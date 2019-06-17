// File:   prf_plus.h
// Author: Fernando Bernal Hidalgo
//

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/hmac.h>
#include "common.h"
#include <string.h>

#ifdef __cplusplus
}
#endif


void PRF( u8 * key, u16 key_length, u8 * sequence, u16 sequence_length, u8 * result );
void PRF_plus( u8 iter, u8 * key, u16 key_length, u8 * sequence, u16 sequence_length, u8 * result);
