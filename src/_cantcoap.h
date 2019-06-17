#include <sys/types.h>
#include <sys/socket.h>
#define __USE_POSIX 1
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <math.h>
#include "uthash.h"

#undef DEBUG

#define DBG_NEWLINE "\n"

#define INFO(...) printf(__VA_ARGS__); printf(DBG_NEWLINE);
#define INFOX(...); printf(__VA_ARGS__);
#define ERR(...) printf(__VA_ARGS__); printf(DBG_NEWLINE);

#ifdef DEBUG
        #define DBG(...) fprintf(stderr,"%s:%d ",__FILE__,__LINE__); fprintf(stderr,__VA_ARGS__); fprintf(stderr,"\r\n");
        #define DBGX(...) fprintf(stderr,__VA_ARGS__);
        #define DBGLX(...) fprintf(stderr,"%s:%d ",__FILE__,__LINE__); fprintf(stderr,__VA_ARGS__);
        #define DBG_PDU() printBin();
#else
        #define DBG(...) {};
        #define DBGX(...) {};
        #define DBGLX(...) {};
        #define DBG_PDU() {};
#endif

#define COAP_HDR_SIZE 4
#define COAP_OPTION_HDR_BYTE 1

// CoAP PDU format

//   0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Ver| T |  TKL  |      Code     |          Message ID           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Token (if any, TKL bytes) ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Options (if any) ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |1 1 1 1 1 1 1 1|    Payload (if any) ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


typedef enum type {
	COAP_CONFIRMABLE=0x00,
	COAP_NON_CONFIRMABLE=0x10,
	COAP_ACKNOWLEDGEMENT=0x20,
	COAP_RESET=0x30
} Type;
		
		// CoAP response codes.
typedef enum code {
	COAP_EMPTY=0x00,
	COAP_GET,
	COAP_POST,
	COAP_PUT,
	COAP_DELETE,
	COAP_CREATED=0x41,
	COAP_DELETED,
	COAP_VALID,
	COAP_CHANGED,
	COAP_CONTENT,
	COAP_BAD_REQUEST=0x80,
	COAP_UNAUTHORIZED,
	COAP_BAD_OPTION,
	COAP_FORBIDDEN,
	COAP_NOT_FOUND,
	COAP_METHOD_NOT_ALLOWED,
	COAP_NOT_ACCEPTABLE,
	COAP_PRECONDITION_FAILED=0x8C,
	COAP_REQUEST_ENTITY_TOO_LARGE=0x8D,
	COAP_UNSUPPORTED_CONTENT_FORMAT=0x8F,
	COAP_INTERNAL_SERVER_ERROR=0xA0,
	COAP_NOT_IMPLEMENTED,
	COAP_BAD_GATEWAY,
	COAP_SERVICE_UNAVAILABLE,
	COAP_GATEWAY_TIMEOUT,
	COAP_PROXYING_NOT_SUPPORTED,
	COAP_UNDEFINED_CODE=0xFF
} Code;

		/// CoAP option numbers.
		typedef enum option {
			COAP_OPTION_IF_MATCH=1,
			COAP_OPTION_URI_HOST=3,
			COAP_OPTION_ETAG,
			COAP_OPTION_IF_NONE_MATCH,
			COAP_OPTION_OBSERVE,
			COAP_OPTION_URI_PORT,
			COAP_OPTION_LOCATION_PATH,
			COAP_OPTION_URI_PATH=11,
			COAP_OPTION_CONTENT_FORMAT,
			COAP_OPTION_MAX_AGE=14,
			COAP_OPTION_URI_QUERY,
			COAP_OPTION_ACCEPT=17,
			COAP_OPTION_LOCATION_QUERY=20,
			COAP_OPTION_BLOCK2=23,
			COAP_OPTION_BLOCK1=27,
			COAP_OPTION_SIZE2,
			COAP_OPTION_PROXY_URI=35,
			COAP_OPTION_PROXY_SCHEME=39,
			COAP_OPTION_SIZE1=60,
			COAP_OPTION_AUTH = 92
		} Option;

		/// CoAP content-formats.
		typedef enum contentFormat {
			COAP_CONTENT_FORMAT_TEXT_PLAIN = 0,
			COAP_CONTENT_FORMAT_APP_LINK  = 40,
			COAP_CONTENT_FORMAT_APP_XML,
			COAP_CONTENT_FORMAT_APP_OCTET,
			COAP_CONTENT_FORMAT_APP_EXI   = 47,
			COAP_CONTENT_FORMAT_APP_JSON  = 50
		} ContentFormat;

		/// Sequence of these is returned by CoapPDU::getOptions()
		typedef struct CoapOption {
			uint16_t optionDelta;
			uint16_t optionNumber;
			uint16_t optionValueLength;
			int totalLength;
			uint8_t *optionPointer;
			uint8_t *optionValuePointer;
		} CoapOption;

		// construction and destruction
typedef struct CoapPDU
{	
		// variables
		uint8_t *_pdu;
		int _pduLength;

		int _constructedFromBuffer;
		int _bufferLength;

		uint8_t *_payloadPointer;
		int _payloadLength;

		int _numOptions;
		uint16_t _maxAddedOptionNumber;
} CoapPDU;
		

CoapPDU * _CoapPDU();
CoapPDU * _CoapPDU_buf(uint8_t *pdu, int pduLength);
CoapPDU * _CoapPDU_buf2(uint8_t *buffer, int bufferLength, int pduLength);
int reset(CoapPDU *coap_pdu);
int validate(CoapPDU *coap_pdu);
void deallocCoapPDU(CoapPDU **pcoap_pdu);
uint8_t* getPDUPointer(CoapPDU *coap_pdu);
void setPDULength(CoapPDU *coap_pdu, int len);
int setURI(CoapPDU *coap_pdu,char *uri);
int _setURI(CoapPDU *coap_pdu, char *uri, int urilen);
int addURIQuery(CoapPDU *coap_pdu, char *query);
int getURI(CoapPDU *coap_pdu,char *dst, int dstlen, int *outLen);
int setVersion(CoapPDU *coap_pdu, uint8_t version);
uint8_t getVersion(CoapPDU *coap_pdu);
void setType(CoapPDU *coap_pdu, Type mt);
Type getType(CoapPDU *coap_pdu);
int setTokenLength(CoapPDU *coap_pdu, uint8_t tokenLength);
int getTokenLength(CoapPDU *coap_pdu);
uint8_t* getTokenPointer(CoapPDU *coap_pdu);
int setToken(CoapPDU *coap_pdu, uint8_t *token, uint8_t tokenLength);
void setCode(CoapPDU *coap_pdu, Code code);
Code getCode(CoapPDU *coap_pdu);
Code httpStatusToCode(int httpStatus);
int setMessageID(CoapPDU *coap_pdu, uint16_t messageID);
uint16_t getMessageID(CoapPDU *coap_pdu);
int getPDULength(CoapPDU *coap_pdu);
int getNumOptions(CoapPDU *coap_pdu);
CoapOption* getOptions(CoapPDU *coap_pdu);
int addOption(CoapPDU *coap_pdu,uint16_t insertedOptionNumber, uint16_t optionValueLength, uint8_t *optionValue);
uint8_t* mallocPayload(CoapPDU *coap_pdu,int len);
int setPayload(CoapPDU *coap_pdu,uint8_t *payload, int len);
uint8_t* getPayloadPointer(CoapPDU *coap_pdu);
int getPayloadLength(CoapPDU *coap_pdu);
uint8_t* getPayloadCopy(CoapPDU *coap_pdu);
int setContentFormat(CoapPDU *coap_pdu, ContentFormat format);
void shiftPDUUp(CoapPDU *coap_pdu, int shiftOffset, int shiftAmount);
void shiftPDUDown(CoapPDU *coap_pdu, int startLocation, int shiftOffset, int shiftAmount);
uint16_t getOptionValueLength(CoapPDU *coap_pdu, uint8_t *option);
uint16_t getOptionDelta(CoapPDU *coap_pdu, uint8_t *option);
int findInsertionPosition(CoapPDU *coap_pdu, uint16_t optionNumber, uint16_t *prevOptionNumber);
int computeExtraBytes(CoapPDU *coap_pdu, uint16_t n);
void setOptionDelta(CoapPDU *coap_pdu, int optionPosition, uint16_t optionDelta);
int insertOption(CoapPDU *coap_pdu,
	int insertionPosition,
	uint16_t optionDelta, 
	uint16_t optionValueLength,
	uint8_t *optionValue);
void printHuman(CoapPDU *coap_pdu);
void printPDUAsCArray(CoapPDU *coap_pdu);
void printOptionHuman(CoapPDU *coap_pdu,uint8_t *option);
void printHex(CoapPDU *coap_pdu);
void _printBinary(uint8_t b);
void print(CoapPDU *coap_pdu);
