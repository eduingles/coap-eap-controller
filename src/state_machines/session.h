/**
 * @file session.h
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
#ifndef SESSION_H
#define SESSION_H
#include "../include.h"

#define ISSERVER 1

/**
 * Declaration of common configurable variables
 */

#ifdef ISCLIENT //Include session variables only for PANA clients

#ifdef __cplusplus
extern "C" {
#endif

#include "sessionclient.h"
#include "../libeapstack/eap_peer_interface.h"

#ifdef __cplusplus
}
#endif

/**
 * Declaration of client configurable variables
 * */
int IP_VERSION;		// Version of IP protocol used in PANA communication
int PRF_SUITE;   //PRF algorithm negociated in handshake
int AUTH_SUITE;   // Integrity algorithm negociated in handshake
int FAILED_SESS_TIMEOUT_CONFIG; // Timeout used in the PANA session saved in PaC
short SRCPORT;  // Source port used in messages sent to PAA
short DSTPORT;  // Destination port used in messages sent to PAA
char* DESTIP;   // Destination ip used in messages sent to PAA
char* LOCALIP;  // Source IP used in messages sent to PAA

char* USER;     // User's name used in the authentication phase
char* PASSWORD; // Password used in the authentication phase
char* CA_CERT;  // Name of CA's cert
char* CLIENT_CERT; // Name of client's cert
char* CLIENT_KEY;  // Name of client key's cert
char* PRIVATE_KEY; // Key used by the client in the certificates.
int FRAG_SIZE;     // Size of eap's fragments.
int PING_TIME;	   // Time to wait for test channel status in the access phase.
int NUMBER_PING;   // Number of ping messages to be exchanged.
int NUMBER_PING_AUX;   // Number of ping messages to be exchanged (auxiliar variable).
bool EAP_PIGGYBACK;    // Indicates if eap piggyback is activated.
#endif

#ifdef ISSERVER //Include session variables only for PANA servers

#ifdef __cplusplus
extern "C" {
#endif

#include "../libeapstack/eap_auth_interface.h"

#ifdef __cplusplus
}
#endif

/**
 * Declaration of server configurable variables
 * */
int IP_VERSION;		// Version of IP protocol used in PANA communication
int PRF_SUITE;  //PRF algorithm negociated in handshake
int AUTH_SUITE; // Integrity algorithm negociated ni handshake
int SRCPORT;			// Source port used in messages sent to PaC
int LIFETIME_SESSION_TIMEOUT_CONFIG;  // Timeout used in the PANA session saved in PAA
int LIFETIME_SESSION_CLIENT_TIMEOUT_CONFIG; // Timeout to send to PaC
int TIME_PCI;			// Timeout without a PANA-Answer for the first PANA-Request message.
int NUM_WORKERS;		// Number of threads running as "workers"

char* CA_CERT;          // Name of CA's cert
char* SERVER_CERT;      // Name of AAA server's cert
char* SERVER_KEY;       // Name of AAA server's key cert
int IP_VERSION_AUTH;	// Version of IP protocol used in AAA comunication
char* AS_IP;		    // AAA server's IP
short AS_PORT;          // AAA server's port
char* AS_SECRET;        // Shared secret between AAA client and server
int PING_TIME;	   // Time to wait for test channel status in the access phase.
int NUMBER_PING;   // Number of ping messages to be exchanged.
int NUMBER_PING_AUX;   // Number of ping messages to be exchanged (auxiliar variable).
int MODE;
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "../panamessages.h"
#include "../loadconfig.h"

#ifdef __cplusplus
}
#endif


/** Max Request retry attempts. See rfc 3315*/
#define REQ_MAX_RC	10 

/** Max Request timeout value. See rfc 3315*/
#define REQ_MAX_RT	30 





#endif
