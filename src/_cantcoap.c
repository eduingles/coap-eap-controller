#include "_cantcoap.h"


CoapPDU * _CoapPDU() {
	
	CoapPDU *coap_pdu = (CoapPDU *)calloc(1, sizeof(CoapPDU));
	// pdu
	coap_pdu->_pdu = (uint8_t*)calloc(4,sizeof(uint8_t));
	coap_pdu->_pduLength = 4;
	coap_pdu->_bufferLength = coap_pdu->_pduLength;

	//options
	coap_pdu->_numOptions = 0;
	coap_pdu->_maxAddedOptionNumber = 0;

	// payload
	coap_pdu->_payloadPointer = NULL;
	coap_pdu->_payloadLength = 0;

	coap_pdu->_constructedFromBuffer = 0;

	setVersion(coap_pdu,1);
	return coap_pdu;
}

/// Construct object from external buffer that may be larger than actual PDU.
/**
 * This differs from CoapPDU::CoapPDU(uint8_t *pdu, int pduLength) in that the buffer may be larger
 * than the actual CoAP PDU contained int the buffer. This is typically used when a large buffer is reused
 * multiple times. Note that \b pduLength can be 0.
 * 
 * If an actual CoAP PDU is passed in the buffer, \b pduLength should match its length. CoapPDU::validate() must
 * be called to initiate the object before member functions can be used.
 *
 * A PDU constructed in this manner must be validated with CoapPDU::validate() before the member variables will be accessible.
 *
 * \warning The validation call parses the PDU structure to set some internal parameters. If you do
 * not validate the PDU, then the behaviour of member access functions will be undefined.
 * 
 * The buffer can be reused by issuing a CoapPDU::reset() but the class will not change the size of the buffer. If the
 * newly constructed PDU exceeds the size of the buffer, the function called (for example CoapPDU::addOption) will fail.
 *
 * Deleting this object will only delete the Object container and will not delete the PDU buffer.
 *
 * \param buffer A buffer which either contains a CoAP PDU or is intended to be used to construct one.
 * \param bufferLength The length of the buffer
 * \param pduLength If the buffer contains a CoAP PDU, this specifies the length of the PDU within the buffer.
 *
 * \sa CoapPDU::CoapPDU(), CoapPDU::CoapPDU(uint8_t *pdu, int pduLength)
 */
CoapPDU * _CoapPDU_buf2(uint8_t *buffer, int bufferLength, int pduLength) {
	// sanity
	if(pduLength<4&&pduLength!=0) {
		DBG("PDU cannot have a length less than 4");
	}

	// pdu
	CoapPDU *coap_pdu = (CoapPDU *)calloc(1, sizeof(CoapPDU));	
	coap_pdu->_pdu = buffer;
	coap_pdu->_bufferLength = bufferLength;
	if(pduLength==0) {
		// this is actually a fresh pdu, header always exists
		coap_pdu->_pduLength = 4;
		// make sure header is zeroed
		coap_pdu->_pdu[0] = 0x00; coap_pdu->_pdu[1] = 0x00; coap_pdu->_pdu[2] = 0x00; coap_pdu->_pdu[3] = 0x00;
		setVersion(coap_pdu,1);
	} else {
		coap_pdu->_pduLength = pduLength;
	}

	coap_pdu->_constructedFromBuffer = 1;

	// options
	coap_pdu->_numOptions = 0;
	coap_pdu->_maxAddedOptionNumber = 0;

	// payload
	coap_pdu->_payloadPointer = NULL;
	coap_pdu->_payloadLength = 0;

	return coap_pdu;
}


/// Construct a PDU using an external buffer. No copy of the buffer is made.
/**
 * This constructor is normally used where a PDU has been received over the network, and it's length is known.
 * In this case the CoapPDU object is probably going to be used as a temporary container to access member values.
 *
 * It is assumed that \b pduLength is the length of the actual CoAP PDU, and consequently the buffer will also be this size,
 * contrast this with CoapPDU::CoapPDU(uint8_t *buffer, int bufferLength, int pduLength) which allows the buffer to 
 * be larger than the PDU.
 *
 * A PDU constructed in this manner must be validated with CoapPDU::validate() before the member variables will be accessible.
 *
 * \warning The validation call parses the PDU structure to set some internal parameters. If you do
 * not validate the PDU, then the behaviour of member access functions will be undefined.
 * 
 * The buffer can be reused by issuing a CoapPDU::reset() but the class will not change the size of the buffer. If the
 * newly constructed PDU exceeds the size of the buffer, the function called (for example CoapPDU::addOption) will fail.
 *
 * Deleting this object will only delete the Object container and will not delete the PDU buffer.
 *
 * @param pdu A pointer to an array of bytes which comprise the CoAP PDU
 * @param pduLength The length of the CoAP PDU pointed to by \b pdu

 * \sa CoapPDU::CoapPDU(), CoapPDU::CoapPDU(uint8_t *buffer, int bufferLength, int pduLength)
 */
CoapPDU * _CoapPDU_buf(uint8_t *pdu, int pduLength)
{
	return _CoapPDU_buf2(pdu,pduLength,pduLength);
}


/// Reset CoapPDU container so it can be reused to build a new PDU.
/**
 * This resets the CoapPDU container, setting the pdu length, option count, etc back to zero. The
 * PDU can then be populated as if it were newly constructed.
 *
 * Note that the space available will depend on how the CoapPDU was originally constructed:
 * -# CoapPDU::CoapPDU()
 *
 * 	Available space initially be \b _pduLength. But further space will be allocated as needed on demand, 
 *    limited only by the OS/environment.
 *
 * -# CoapPDU::CoapPDU(uint8_t *pdu, int pduLength)
 *
 *		Space is limited by the variable \b pduLength. The PDU cannot exceed \b pduLength bytes.
 *		 
 * -# CoapPDU::CoapPDU(uint8_t *buffer, int bufferLength, int pduLength)
 *
 *		Space is limited by the variable \b bufferLength. The PDU cannot exceed \b bufferLength bytes.
 *
 * \return 0 on success, 1 on failure.
 */
int reset(CoapPDU *coap_pdu) {
	// pdu
	memset(coap_pdu->_pdu,0x00,coap_pdu->_bufferLength);
	// packet always has at least a header
	coap_pdu->_pduLength = 4;

	// options
	coap_pdu->_numOptions = 0;
	coap_pdu->_maxAddedOptionNumber = 0;
	// payload
	coap_pdu->_payloadPointer = NULL;
	coap_pdu->_payloadLength = 0;
	return 0;
}

/// Validates a PDU constructed using an external buffer.
/**
 * When a CoapPDU is constructed using an external buffer, the programmer must call this function to
 * check that the received PDU is a valid CoAP PDU.
 *
 * \warning The validation call parses the PDU structure to set some internal parameters. If you do
 * not validate the PDU, then the behaviour of member access functions will be undefined.
 *
 * \return 1 if the PDU validates correctly, 0 if not. XXX maybe add some error codes
 */
int validate(CoapPDU *coap_pdu) {
	if(coap_pdu->_pduLength<4) {
		DBG("PDU has to be a minimum of 4 bytes. This: %d bytes",coap_pdu->_pduLength);
		return 0;
	}

	// check header
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

	DBG("Version: %d",getVersion(coap_pdu));
	DBG("Type: %d",getType(coap_pdu));

	// token length must be between 0 and 8
	int tokenLength = getTokenLength(coap_pdu);
	if(tokenLength<0||tokenLength>8) {
		DBG("Invalid token length: %d",tokenLength);
		return 0;
	}
	DBG("Token length: %d",tokenLength);
	// check total length
	if((COAP_HDR_SIZE+tokenLength)>coap_pdu->_pduLength) {
		DBG("Token length would make pdu longer than actual length.");
		return 0;
	}

	// check that code is valid
	Code code = getCode(coap_pdu);	
	if(code<COAP_EMPTY ||
		(code>COAP_DELETE&&code<COAP_CREATED) ||
		(code>COAP_CONTENT&&code<COAP_BAD_REQUEST) ||
		(code>COAP_NOT_ACCEPTABLE&&code<COAP_PRECONDITION_FAILED) ||
		(code==0x8E) ||
		(code>COAP_UNSUPPORTED_CONTENT_FORMAT&&code<COAP_INTERNAL_SERVER_ERROR) ||
		(code>COAP_PROXYING_NOT_SUPPORTED) ) {
		DBG("Invalid CoAP code: %d",code);
		return 0;
	}
	DBG("CoAP code: %d",code);

	// token can be anything so nothing to check

	// check that options all make sense
	uint16_t optionDelta =0, optionNumber = 0, optionValueLength = 0;
	int totalLength = 0;

	// first option occurs after token
	int optionPos = COAP_HDR_SIZE + getTokenLength(coap_pdu);

	// may be 0 options
	if(optionPos==coap_pdu->_pduLength) {
		DBG("No options. No payload.");
		coap_pdu->_numOptions = 0;
		coap_pdu->_payloadLength = 0;
		return 1;
	}

	int bytesRemaining = (coap_pdu->_pduLength)-optionPos;
	int numOptions = 0;
	uint8_t upperNibble = 0x00, lowerNibble = 0x00;

	// walk over options and record information
	while(1) {
		// check for payload marker
		if(bytesRemaining>0) {
			uint8_t optionHeader = coap_pdu->_pdu[optionPos];
			if(optionHeader==0xFF) {
				// payload
				if(bytesRemaining>1) {
					coap_pdu->_payloadPointer = &(coap_pdu->_pdu[optionPos+1]);
					coap_pdu->_payloadLength = (bytesRemaining-1);
					coap_pdu->_numOptions = numOptions;
					DBG("Payload found, length: %d",coap_pdu->_payloadLength);
					return 1;
				}
				// payload marker but no payload
				coap_pdu->_payloadPointer = NULL;
				coap_pdu->_payloadLength = 0;
				DBG("Payload marker but no payload.");
				return 0;
			}

			// check that option delta and option length are valid values
			upperNibble = (optionHeader & 0xF0) >> 4;
			lowerNibble = (optionHeader & 0x0F);
			if(upperNibble==0x0F||lowerNibble==0x0F) {
				DBG("Expected option header or payload marker, got: 0x%x%x",upperNibble,lowerNibble);
				return 0;
			}
			DBG("Option header byte appears sane: 0x%x%x",upperNibble,lowerNibble);
		} else {
			DBG("No more data. No payload.");
			coap_pdu->_payloadPointer = NULL;
			coap_pdu->_payloadLength = 0;
			coap_pdu->_numOptions = numOptions;
			return 1;
		}

		// skip over option header byte
		bytesRemaining--;

		// check that there is enough space for the extended delta and length bytes (if any)
		int headerBytesNeeded = computeExtraBytes(coap_pdu,upperNibble);
		DBG("%d extra bytes needed for extended delta",headerBytesNeeded);
		if(headerBytesNeeded>bytesRemaining) {
			DBG("Not enough space for extended option delta, needed %d, have %d.",headerBytesNeeded,bytesRemaining);
			return 0;
		}
		headerBytesNeeded += computeExtraBytes(coap_pdu,lowerNibble);
		if(headerBytesNeeded>bytesRemaining) {
			DBG("Not enough space for extended option length, needed %d, have %d.",
				(headerBytesNeeded-computeExtraBytes(coap_pdu,upperNibble)),bytesRemaining);
			return 0;
		}
		DBG("Enough space for extended delta and length: %d, continuing.",headerBytesNeeded);

		// extract option details
		optionDelta = getOptionDelta(coap_pdu,&(coap_pdu->_pdu[optionPos]));
		optionNumber += optionDelta;
		optionValueLength = getOptionValueLength(coap_pdu,&(coap_pdu->_pdu[optionPos]));
		DBG("Got option: %d with length %d",optionNumber,optionValueLength);
		// compute total length
		totalLength = 1; // mandatory header
		totalLength += computeExtraBytes(coap_pdu,optionDelta);
		totalLength += computeExtraBytes(coap_pdu,optionValueLength);
		totalLength += optionValueLength;
		// check there is enough space
		if(optionPos+totalLength>coap_pdu->_pduLength) {
			DBG("Not enough space for option payload, needed %d, have %d.",(totalLength-headerBytesNeeded-1),(coap_pdu->_pduLength)-optionPos);
			return 0;
		}
		DBG("Enough space for option payload: %d %d",optionValueLength,(totalLength-headerBytesNeeded-1));

		// recompute bytesRemaining
		bytesRemaining -= totalLength;
		bytesRemaining++; // correct for previous --

		// move to next option
		optionPos += totalLength; 

		// inc number of options XXX
		numOptions++;
	}

	return 1;
}

/// Destructor. Does not free buffer if constructor passed an external buffer.
/**
 * The destructor acts differently, depending on how the object was initially constructed (from buffer or not):
 *
 * -# CoapPDU::CoapPDU()
 *
 * 	Complete object is destroyed.
 *
 * -# CoapPDU::CoapPDU(uint8_t *pdu, int pduLength)
 *
 *		Only object container is destroyed. \b pdu is left intact.
 *		 
 * -# CoapPDU::CoapPDU(uint8_t *buffer, int bufferLength, int pduLength)
 *
 *		Only object container is destroyed. \b pdu is left intact.
 *
 */
void deallocCoapPDU(CoapPDU **pcoap_pdu) {
	if(!(*pcoap_pdu)->_constructedFromBuffer) {
		free((*pcoap_pdu)->_pdu);
	}
	free(*pcoap_pdu);
	*pcoap_pdu=NULL;
}

/// Returns a pointer to the internal buffer.
uint8_t* getPDUPointer(CoapPDU *coap_pdu) {
	return coap_pdu->_pdu;
}

/// Set the PDU length to the length specified.
/**
 * This is used when re-using a PDU container before calling CoapPDU::validate() as it
 * is not possible to deduce the length of a PDU since the payload has no length marker.
 * \param len The length of the PDU
 */
void setPDULength(CoapPDU *coap_pdu, int len) {
	coap_pdu->_pduLength = len;
}

/// Shorthand function for setting a resource URI.
/**
 * Calls CoapPDU::setURI(uri,strlen(uri).
 */
int setURI(CoapPDU *coap_pdu,char *uri) {
	return _setURI(coap_pdu,uri,strlen(uri));
}

/// Shorthand function for setting a resource URI.
/**
 * This will parse the supplied \b uri and construct enough URI_PATH and URI_QUERY options to encode it.
 * The options are added to the PDU.
 * 
 * At present only simple URI formatting is handled, only '/','?', and '&' separators, and no port or protocol specificaiton.
 *
 * The function will split on '/' and create URI_PATH elements until it either reaches the end of the string
 * in which case it will stop or if it reaches '?' it will start splitting on '&' and create URI_QUERY elements
 * until it reaches the end of the string.
 *
 * Here is an example:
 *
 * /a/b/c/d?x=1&y=2&z=3
 *
 * Will be broken into four URI_PATH elements "a", "b", "c", "d", and three URI_QUERY elements "x=1", "y=2", "z=3"
 *
 * TODO: Add protocol extraction, port extraction, and some malformity checking.
 *
 * \param uri The uri to parse.
 * \param urilen The length of the uri to parse.
 *
 * \return 1 on success, 0 on failure.
 */
int _setURI(CoapPDU *coap_pdu, char *uri, int urilen) {
	// only '/', '?', '&' and ascii chars allowed

	// sanitation
	if(urilen<=0||uri==NULL) {
		DBG("Null or zero-length uri passed.");
		return 1;
	}

	// single character URI path (including '/' case)
	if(urilen==1) {
		addOption(coap_pdu, COAP_OPTION_URI_PATH,1,(uint8_t*)uri);
		return 0;
	}

	// TODO, queries
	// extract ? to mark where to stop processing path components
	// and then process the query params

	// local vars
	char *startP=uri,*endP=NULL;
	int oLen = 0;
	char splitChar = '/';
	int queryStageTriggered = 0;
	uint16_t optionType = COAP_OPTION_URI_PATH;
	while(1) {
		// stop at end of string or query
		if(*startP==0x00||*(startP+1)==0x00) {
			break;
		}

		// ignore leading slash
		if(*startP==splitChar) {
			DBG("Skipping leading slash");
			startP++;
		}

		// find next split point
		endP = strchr(startP,splitChar);

		// might not be another slash
		if(endP==NULL) {
			DBG("Ending out of slash");
			// check if there is a ?
			endP = strchr(startP,'?');
			// done if no queries
			if(endP==NULL) {
				endP = uri+urilen;
			} else {
				queryStageTriggered = 1;
			}
		}

		// get length of segment
		oLen = endP-startP;

		#ifdef DEBUG
		char *b = (char*)malloc(oLen+1);
		memcpy(b,startP,oLen);
		b[oLen] = 0x00;
		DBG("Adding URI_PATH %s",b);
		free(b);
		#endif

		// add option
		if(addOption(coap_pdu, optionType,oLen,(uint8_t*)startP)!=0) {
			DBG("Error adding option");
			return 1;
		}
		startP = endP;

		if(queryStageTriggered) {
			splitChar = '&';
			optionType = COAP_OPTION_URI_QUERY;
			startP++;
			queryStageTriggered = 0;
		}
	}

	return 0;
}

/// Shorthand for adding a URI QUERY to the option list.
/**
 * Adds a new option to the CoAP PDU that encodes a URI_QUERY.
 *
 * \param query The uri query to encode.
 * \return 0 on success, 1 on failure.
 */
int addURIQuery(CoapPDU *coap_pdu, char *query) {
	return addOption(coap_pdu, COAP_OPTION_URI_QUERY,strlen(query),(uint8_t*)query);
}

/// Concatenates any URI_PATH elements and URI_QUERY elements into a single string.
/**
 * Parses the PDU options and extracts all URI_PATH and URI_QUERY elements, 
 * concatenating them into a single string with slash and amphersand separators accordingly.
 * 
 * The produced string will be NULL terminated.
 * 
 * \param dst Buffer into which to copy the concatenated path elements.
 * \param dstlen Length of buffer.
 * \param outLen Pointer to integer, into which URI length will be placed.
 *
 * \return 0 on success, 1 on failure. \b outLen will contain the length of the concatenated elements.
 */
int getURI(CoapPDU *coap_pdu,char *dst, int dstlen, int *outLen) {
	if(outLen==NULL) {
		DBG("Output length pointer is NULL");
		return 1;
	}

	if(dst==NULL) {
		DBG("NULL destination buffer");
		*outLen = 0;
		return 1;
	}

	// check destination space
	if(dstlen<=0) {
		*dst = 0x00;
		*outLen = 0;
		DBG("Destination buffer too small (0)!");
		return 1;
	}
	// check option count
	if(coap_pdu->_numOptions==0) {
		*dst = 0x00;
		*outLen = 0;
		return 0;
	}
	// get options
	CoapOption *options = getOptions(coap_pdu);
	if(options==NULL) {
		*dst = 0x00;
		*outLen = 0;
		return 0;
	}
	// iterate over options to construct URI
	CoapOption *o = NULL;
	int bytesLeft = dstlen-1; // space for 0x00
	int oLen = 0;
	// add slash at beggining
	if(bytesLeft>=1) {
		*dst = '/';
		dst++;
		bytesLeft--;
	} else {
		DBG("No space for initial slash needed 1, got %d",bytesLeft);
		return 1;
	}

	char separator = '/';
	int firstQuery = 1;

	for(int i=0; i<coap_pdu->_numOptions; i++) {
		o = &options[i];
		oLen = o->optionValueLength;
		if(o->optionNumber==COAP_OPTION_URI_PATH||o->optionNumber==COAP_OPTION_URI_QUERY) {
			// if the option is a query, change the separator to &
			if(o->optionNumber==COAP_OPTION_URI_QUERY) {
				if(firstQuery) {
					// change previous '/' to a '?'
					*(dst-1) = '?';
					firstQuery = 0;
				}
				separator = '&';
			}

			// check space
			if(oLen>bytesLeft) {
				DBG("Destination buffer too small, needed %d, got %d",oLen,bytesLeft);
				return 1;
			}

			// case where single '/' exists
			if(oLen==1&&o->optionValuePointer[0]=='/') {
				*dst = 0x00;
				*outLen = 1;
				return 0;
			}

			// copy URI path or query component
			memcpy(dst,o->optionValuePointer,oLen);

			// adjust counters
			dst += oLen;
			bytesLeft -= oLen;

			// add separator following (don't know at this point if another option is coming)
			if(bytesLeft>=1) {
				*dst = separator;
				dst++;
				bytesLeft--;
			} else {
				DBG("Ran out of space after processing option");
				return 1;
			}
		}
	}

	// remove terminating separator
	dst--;
	bytesLeft++;
	// add null terminating byte (always space since reserved)
	*dst = 0x00;
	*outLen = (dstlen-1)-bytesLeft;
	return 0;
}

/// Sets the CoAP version.
/**
 * \param version CoAP version between 0 and 3.
 * \return 0 on success, 1 on failure.
 */
int setVersion(CoapPDU *coap_pdu, uint8_t version) {
	uint8_t *_pdu = coap_pdu->_pdu;	
	if(version>3) {
		return 0;
	}

	_pdu[0] &= 0x3F;
	_pdu[0] |= (version << 6);
	return 1;
}
		
/**
 * Gets the CoAP Version.
 * @return The CoAP version between 0 and 3.
 */
uint8_t getVersion(CoapPDU *coap_pdu) {
	uint8_t *_pdu = coap_pdu->_pdu;
	return (_pdu[0]&0xC0)>>6;
}

/**
 * Sets the type of this CoAP PDU. 
 * \param mt The type, one of: 
 * - COAP_CONFIRMABLE
 * - COAP_NON_CONFIRMABLE
 * - COAP_ACKNOWLEDGEMENT
 * - COAP_RESET.
 */
void setType(CoapPDU *coap_pdu, Type mt) {
	uint8_t *_pdu = coap_pdu->_pdu;
	_pdu[0] &= 0xCF;
	_pdu[0] |= mt;
}

/// Returns the type of the PDU.
Type getType(CoapPDU *coap_pdu) {
	uint8_t *_pdu = coap_pdu->_pdu;	
	return (Type)(_pdu[0]&0x30);
}


/// Set the token length.
/**
 * \param tokenLength The length of the token in bytes, between 0 and 8.
 * \return 0 on success, 1 on failure.
 */
int setTokenLength(CoapPDU *coap_pdu, uint8_t tokenLength) {
	uint8_t *_pdu = coap_pdu->_pdu;
	
	if(tokenLength>8)
		return 1;

	_pdu[0] &= 0xF0;
	_pdu[0] |= tokenLength;
	return 0;
}

/// Returns the token length.
int getTokenLength(CoapPDU *coap_pdu) {
	uint8_t *_pdu = coap_pdu->_pdu;
	return _pdu[0] & 0x0F;
}

/// Returns a pointer to the PDU token.
uint8_t* getTokenPointer(CoapPDU *coap_pdu) {
	
	if(getTokenLength(coap_pdu)==0) {
		return NULL;
	}
	uint8_t *_pdu = coap_pdu->_pdu;	
		
	return &_pdu[4];
}

/// Set the PDU token to the supplied byte sequence.
/**
 * This sets the PDU token to \b token and sets the token length to \b tokenLength.
 * \param token A sequence of bytes representing the token.
 * \param tokenLength The length of the byte sequence.
 * \return 0 on success, 1 on failure.
 */
int setToken(CoapPDU *coap_pdu, uint8_t *token, uint8_t tokenLength) {
	DBG("Setting token");
	if(token==NULL) {
		DBG("NULL pointer passed as token reference");
		return 1;
	}

	if(tokenLength==0) {
		DBG("Token has zero length");
		return 1;
	}

	// if tokenLength has not changed, just copy the new value
	uint8_t oldTokenLength = getTokenLength(coap_pdu);
	uint8_t *_pdu = coap_pdu->_pdu;
	if(tokenLength==oldTokenLength) {
		memcpy((void*)&_pdu[4],token,tokenLength);
		return 0;
	}

	// otherwise compute new length of PDU
	uint8_t oldPDULength = coap_pdu->_pduLength;
	coap_pdu->_pduLength -= oldTokenLength;
	coap_pdu->_pduLength += tokenLength;

	// now, have to shift old memory around, but shift direction depends
	// whether pdu is now bigger or smaller
	if(coap_pdu->_pduLength>oldPDULength) {
		// new PDU is bigger, need to allocate space for new PDU
		if(!coap_pdu->_constructedFromBuffer) {
			uint8_t *newMemory = (uint8_t*)realloc(coap_pdu->_pdu,coap_pdu->_pduLength);
			if(newMemory==NULL) {
				// malloc failed
				DBG("Failed to allocate memory for token");
				coap_pdu->_pduLength = oldPDULength;
				return 1;
			}
			coap_pdu->_pdu = newMemory;
			coap_pdu->_bufferLength = coap_pdu->_pduLength;
		} else {
			// constructed from buffer, check space
			if(coap_pdu->_pduLength>coap_pdu->_bufferLength) {
				DBG("Buffer too small to contain token, needed %d, got %d.",coap_pdu->_pduLength-oldPDULength,coap_pdu->_bufferLength-oldPDULength);
				coap_pdu->_pduLength = oldPDULength;
				return 1;
			}
		}

		// and then shift everything after token up to end of new PDU
		// memory overlaps so do this manually so to avoid additional mallocs
		int shiftOffset = coap_pdu->_pduLength-oldPDULength;
		int shiftAmount = coap_pdu->_pduLength-tokenLength-COAP_HDR_SIZE; // everything after token
		shiftPDUUp(coap_pdu, shiftOffset,shiftAmount);

		// now copy the token into the new space and set official token length
		memcpy((void*)&_pdu[4],token,tokenLength);
		setTokenLength(coap_pdu,tokenLength);

		// and return success
		return 0;
	}

	// new PDU is smaller, copy the new token value over the old one
	memcpy((void*)&_pdu[4],token,tokenLength);
	// and shift everything after the new token down
	int startLocation = COAP_HDR_SIZE+tokenLength;
	int shiftOffset = oldPDULength-coap_pdu->_pduLength;
	int shiftAmount = oldPDULength-oldTokenLength-COAP_HDR_SIZE;
	shiftPDUDown(coap_pdu, startLocation,shiftOffset,shiftAmount);
	// then reduce size of buffer
	if(!coap_pdu->_constructedFromBuffer) {
		uint8_t *newMemory = (uint8_t*)realloc(coap_pdu->_pdu,coap_pdu->_pduLength);
		if(newMemory==NULL) {
			// malloc failed, PDU in inconsistent state
			DBG("Failed to shrink PDU for new token. PDU probably broken");
			return 1;
		}
		coap_pdu->_pdu = newMemory;
		coap_pdu->_bufferLength = coap_pdu->_pduLength;
	}

	// and officially set the new tokenLength
	setTokenLength(coap_pdu,tokenLength);
	return 0;
}

/// Sets the CoAP response code
void setCode(CoapPDU *coap_pdu, Code code) {

	uint8_t *_pdu = coap_pdu->_pdu;
	_pdu[1] = code;
	// there is a limited set of response codes
}

/// Gets the CoAP response code
Code getCode(CoapPDU *coap_pdu) {

	uint8_t *_pdu = coap_pdu->_pdu;
	return (Code)_pdu[1];
}


/// Converts a http status code as an integer, to a CoAP code.
/**
 * \param httpStatus the HTTP status code as an integer (e.g 200)
 * \return The correct corresponding CoapPDU::Code on success,
 * CoapPDU::COAP_UNDEFINED_CODE on failure.
 */
Code httpStatusToCode(int httpStatus) {
	switch(httpStatus) {
		case 1:
			return COAP_GET;
		case 2:
			return COAP_POST;
		case 3:
			return COAP_PUT;
		case 4:
			return COAP_DELETE;
		case 201:
			return COAP_CREATED;
		case 202:
			return COAP_DELETED;
		case 203:
			return COAP_VALID;
		case 204:
			return COAP_CHANGED;
		case 205:
			return COAP_CONTENT;
		case 400:
			return COAP_BAD_REQUEST;
		case 401:
			return COAP_UNAUTHORIZED;
		case 402:
			return COAP_BAD_OPTION;
		case 403:
			return COAP_FORBIDDEN;
		case 404:
			return COAP_NOT_FOUND;
		case 405:
			return COAP_METHOD_NOT_ALLOWED;
		case 406:
			return COAP_NOT_ACCEPTABLE;
		case 412:
			return COAP_PRECONDITION_FAILED;
		case 413:
			return COAP_REQUEST_ENTITY_TOO_LARGE;
		case 415:
			return COAP_UNSUPPORTED_CONTENT_FORMAT;
		case 500:
			return COAP_INTERNAL_SERVER_ERROR;
		case 501:
			return COAP_NOT_IMPLEMENTED;
		case 502:
			return COAP_BAD_GATEWAY;
		case 503:
			return COAP_SERVICE_UNAVAILABLE;
		case 504:
			return COAP_GATEWAY_TIMEOUT;
		case 505:
			return COAP_PROXYING_NOT_SUPPORTED;
		default:
			return COAP_UNDEFINED_CODE;
	}
}

/// Set messageID to the supplied value.
/**
 * \param messageID A 16bit message id.
 * \return 0 on success, 1 on failure.
 */
int setMessageID(CoapPDU *coap_pdu, uint16_t messageID) {
	// message ID is stored in network byte order
	uint16_t networkOrder = htons(messageID);
	uint8_t *_pdu = coap_pdu->_pdu;
	// bytes 2 and 3 hold the ID
	_pdu[2] &= 0x00;
	_pdu[2] |= (networkOrder >> 8);    // MSB
	_pdu[3] &= 0x00;
	_pdu[3] |= (networkOrder & 0x00FF); // LSB
	return 0;
}

/// Returns the 16 bit message ID of the PDU.
uint16_t getMessageID(CoapPDU *coap_pdu) {
	// mesasge ID is stored in network byteorder
	uint8_t *_pdu = coap_pdu->_pdu;	
	uint16_t networkOrder = 0x0000;
	networkOrder |= _pdu[2];
	networkOrder <<= 8;
	networkOrder |= _pdu[3];
	return ntohs(networkOrder);
}

/// Returns the length of the PDU.
int getPDULength(CoapPDU *coap_pdu) {
	return coap_pdu->_pduLength;
}

/// Return the number of options that the PDU has.
int getNumOptions(CoapPDU *coap_pdu) {
	return coap_pdu->_numOptions;
}


/**
 * This returns the options as a sequence of structs.
 */
CoapOption* getOptions(CoapPDU *coap_pdu) {
	DBG("getOptions() called, %d options.",coap_pdu->_numOptions);

	uint16_t optionDelta =0, optionNumber = 0, optionValueLength = 0;
	int totalLength = 0;

	if(coap_pdu->_numOptions==0) {
		return NULL;
	}

	// malloc space for options
	CoapOption *options = (CoapOption*)malloc(coap_pdu->_numOptions*sizeof(CoapOption));

	// first option occurs after token
	int optionPos = COAP_HDR_SIZE + getTokenLength(coap_pdu);
	uint8_t *_pdu = coap_pdu->_pdu;	
	
	// walk over options and record information
	for(int i=0; i< coap_pdu->_numOptions; i++) {
		// extract option details
		optionDelta = getOptionDelta(coap_pdu, &_pdu[optionPos]);
		optionNumber += optionDelta;
		optionValueLength = getOptionValueLength(coap_pdu, &_pdu[optionPos]);
		// compute total length
		totalLength = 1; // mandatory header
		totalLength += computeExtraBytes(coap_pdu, optionDelta);
		totalLength += computeExtraBytes(coap_pdu, optionValueLength);
		totalLength += optionValueLength;
		// record option details
		options[i].optionNumber = optionNumber;
		options[i].optionDelta = optionDelta;
		options[i].optionValueLength = optionValueLength;
		options[i].totalLength = totalLength;
		options[i].optionPointer = &_pdu[optionPos];
		options[i].optionValuePointer = &_pdu[optionPos+totalLength-optionValueLength];
		// move to next option
		optionPos += totalLength; 
	}

	return options;
}

/// Add an option to the PDU.
/**
 * Unlike other implementations, options can be added in any order, and in-memory manipulation will be
 * performed to ensure the correct ordering of options (they use a delta encoding of option numbers).
 * Re-ordering memory like this incurs a small performance cost, so if you care about this, then you
 * might want to add options in ascending order of option number.
 * \param optionNumber The number of the option, see the enum CoapPDU::Option for shorthand notations.
 * \param optionLength The length of the option payload in bytes.
 * \param optionValue A pointer to the byte sequence that is the option payload (bytes will be copied).
 * \return 0 on success, 1 on failure.
 */
int addOption(CoapPDU *coap_pdu,uint16_t insertedOptionNumber, uint16_t optionValueLength, uint8_t *optionValue) {
	// this inserts the option in memory, and re-computes the deltas accordingly
	// prevOption <-- insertionPosition
	// nextOption

	// find insertion location and previous option number
	uint16_t prevOptionNumber = 0; // option number of option before insertion point
	int insertionPosition = findInsertionPosition(coap_pdu,insertedOptionNumber,&prevOptionNumber);
	DBG("inserting option at position %d, after option with number: %hu",insertionPosition,prevOptionNumber);

	// compute option delta length
	uint16_t optionDelta = insertedOptionNumber-prevOptionNumber;
	uint8_t extraDeltaBytes = computeExtraBytes(coap_pdu,optionDelta);

	// compute option length length
	uint16_t extraLengthBytes = computeExtraBytes(coap_pdu,optionValueLength);

	// compute total length of option
	uint16_t optionLength = COAP_OPTION_HDR_BYTE + extraDeltaBytes + extraLengthBytes + optionValueLength;

	// if this is at the end of the PDU, job is done, just malloc and insert
	if(insertionPosition==coap_pdu->_pduLength) {
		DBG("Inserting at end of PDU");
		// optionNumber must be biggest added
		coap_pdu->_maxAddedOptionNumber = insertedOptionNumber;

		// set new PDU length and allocate space for extra option
		int oldPDULength = coap_pdu->_pduLength;
		coap_pdu->_pduLength += optionLength;
		if(!coap_pdu->_constructedFromBuffer) {
			uint8_t *newMemory = (uint8_t*)realloc(coap_pdu->_pdu,coap_pdu->_pduLength);
			if(newMemory==NULL) {
				DBG("Failed to allocate memory for option.");
				coap_pdu->_pduLength = oldPDULength;
				// malloc failed
				return 1;
			}
			coap_pdu->_pdu = newMemory;
			coap_pdu->_bufferLength = coap_pdu->_pduLength;
		} else {
			// constructed from buffer, check space
			if(coap_pdu->_pduLength>coap_pdu->_bufferLength) {
				DBG("Buffer too small for new option: needed %d, got %d.",coap_pdu->_pduLength-oldPDULength,coap_pdu->_bufferLength-oldPDULength);
				coap_pdu->_pduLength = oldPDULength;
				return 1;
			}
		}
		
		// insert option at position
		insertOption(coap_pdu,insertionPosition,optionDelta,optionValueLength,optionValue);
		coap_pdu->_numOptions++;
		return 0;
	}
	// XXX could do 0xFF pdu payload case for changing of dynamically allocated application space SDUs < yeah, if you're insane

	// the next option might (probably) needs it's delta changing
	// I want to take this into account when allocating space for the new
	// option, to avoid having to do two mallocs, first get info about this option
	uint8_t *_pdu = coap_pdu->_pdu;

	int nextOptionDelta = getOptionDelta(coap_pdu, &_pdu[insertionPosition]);
	int nextOptionNumber = prevOptionNumber + nextOptionDelta;
	int nextOptionDeltaBytes = computeExtraBytes(coap_pdu,nextOptionDelta);
	// recompute option delta, relative to inserted option
	int newNextOptionDelta = nextOptionNumber-insertedOptionNumber;
	int newNextOptionDeltaBytes = computeExtraBytes(coap_pdu,newNextOptionDelta);
	// determine adjustment
	int optionDeltaAdjustment = newNextOptionDeltaBytes-nextOptionDeltaBytes;

	// create space for new option, including adjustment space for option delta
	DBG_PDU();
	DBG("Creating space");
	int mallocLength = optionLength+optionDeltaAdjustment;
	int oldPDULength = coap_pdu->_pduLength;
	coap_pdu->_pduLength += mallocLength;

	if(!coap_pdu->_constructedFromBuffer) {
		uint8_t *newMemory = (uint8_t*)realloc(coap_pdu->_pdu,coap_pdu->_pduLength);
		if(newMemory==NULL) {
			DBG("Failed to allocate memory for option");
			coap_pdu->_pduLength = oldPDULength;
			return 1; 
		}
		coap_pdu->_pdu = newMemory;
		coap_pdu->_bufferLength = coap_pdu->_pduLength;
	} else {
		// constructed from buffer, check space
		if(coap_pdu->_pduLength>coap_pdu->_bufferLength) {
			DBG("Buffer too small to contain option, needed %d, got %d.",coap_pdu->_pduLength-oldPDULength,coap_pdu->_bufferLength-oldPDULength);
			coap_pdu->_pduLength = oldPDULength;
			return 1;
		}
	}

	// move remainder of PDU data up to create hole for new option
	DBG_PDU();
	DBG("Shifting PDU.");
	shiftPDUUp(coap_pdu, mallocLength,coap_pdu->_pduLength-(insertionPosition+mallocLength));
	DBG_PDU();

	// adjust option delta bytes of following option
	// move the option header to the correct position
	int nextHeaderPos = insertionPosition+mallocLength;
	_pdu[nextHeaderPos-optionDeltaAdjustment] = _pdu[nextHeaderPos];
	nextHeaderPos -= optionDeltaAdjustment;
	// and set the new value
	setOptionDelta(coap_pdu, nextHeaderPos, newNextOptionDelta);

	// new option shorter
	// p p n n x x x x x
	// p p n n x x x x x -
	// p p - n n x x x x x
	// p p - - n x x x x x
	// p p o o n x x x x x

	// new option longer
	// p p n n x x x x x
	// p p n n x x x x x - - -
	// p p - - - n n x x x x x
	// p p - - n n n x x x x x
	// p p o o n n n x x x x x

	// note, it can only ever be shorter or the same since if an option was inserted the delta got smaller
	// but I'll leave that little comment in, just to show that it would work even if the delta got bigger

	// now insert the new option into the gap
	DBGLX("Inserting new option...");
	insertOption(coap_pdu, insertionPosition,optionDelta,optionValueLength,optionValue);
	DBGX("done\r\n");
	DBG_PDU();

	// done, mark it with B! 
	return 0;
}

/// Allocate space for a payload.
/**
 * For dynamically constructed PDUs, this will allocate space for a payload in the object
 * and return a pointer to it. If the PDU was constructed from a buffer, this doesn't
 * malloc anything, it just changes the _pduLength and returns the payload pointer.
 *
 * \note The pointer returned points into the PDU buffer.
 * \param len The length of the payload buffer to allocate.
 * \return Either a pointer to the payload buffer, or NULL if there wasn't enough space / allocation failed.
 */
uint8_t* mallocPayload(CoapPDU *coap_pdu,int len) {
	DBG("Entering mallocPayload");
	// sanity checks
	if(len==0) {
		DBG("Cannot allocate a zero length payload");
		return NULL;
	}

	// further sanity
	if(len==coap_pdu->_payloadLength) {
		DBG("Space for payload of specified length already exists");
		if(coap_pdu->_payloadPointer==NULL) {
			DBG("Garbage PDU. Payload length is %d, but existing _payloadPointer NULL",coap_pdu->_payloadLength);
			return NULL;
		}
		return coap_pdu->_payloadPointer;
	}

	DBG("_bufferLength: %d, _pduLength: %d, _payloadLength: %d",coap_pdu->_bufferLength,coap_pdu->_pduLength,coap_pdu->_payloadLength);

	// might be making payload bigger (including bigger than 0) or smaller
	int markerSpace = 1;
	int payloadSpace = len;
	// is this a resizing?
	if(coap_pdu->_payloadLength!=0) {
		// marker already exists
		markerSpace = 0;
		// compute new payload length (can be negative if shrinking payload)
		payloadSpace = len-coap_pdu->_payloadLength;
	}

	// make space for payload (and payload marker if necessary)
	int newLen = coap_pdu->_pduLength+payloadSpace+markerSpace;
	if(!coap_pdu->_constructedFromBuffer) {
		uint8_t* newPDU = (uint8_t*)realloc(coap_pdu->_pdu,newLen);
		if(newPDU==NULL) {
			DBG("Cannot allocate (or shrink) space for payload");
			return NULL;
		}
		coap_pdu->_pdu = newPDU;
		coap_pdu->_bufferLength = newLen;
	} else {
		// constructed from buffer, check space
		DBG("newLen: %d, _bufferLength: %d",newLen,coap_pdu->_bufferLength);
		if(newLen>coap_pdu->_bufferLength) {
			DBG("Buffer too small to contain desired payload, needed %d, got %d.",newLen-coap_pdu->_pduLength,coap_pdu->_bufferLength-coap_pdu->_pduLength);
			return NULL;
		}
	}

	// deal with fresh allocation case separately
	if(coap_pdu->_payloadPointer==NULL) {
		// set payload marker
		uint8_t *_pdu = coap_pdu->_pdu;
		_pdu[coap_pdu->_pduLength] = 0xFF;
		// payload at end of old PDU
		coap_pdu->_payloadPointer = &_pdu[coap_pdu->_pduLength+1];
		coap_pdu->_pduLength = newLen;
		coap_pdu->_payloadLength = len;
		return coap_pdu->_payloadPointer;
	}

	// otherwise, just adjust length of PDU
	coap_pdu->_pduLength = newLen;
	coap_pdu->_payloadLength = len;
	DBG("Leaving mallocPayload");
	return coap_pdu->_payloadPointer;
}

/// Set the payload to the byte sequence specified. Allocates memory in dynamic PDU if necessary.
/**
 * This will set the payload to \b payload. It will allocate memory in the case where the PDU was
 * constructed without an external buffer.
 *
 * This will fail either if the fixed buffer isn't big enough, or if memory could not be allocated
 * in the non-external-buffer case.
 * 
 * \param payload Pointer to payload byte sequence.
 * \param len Length of payload byte sequence.
 * \return 0 on success, 1 on failure.
 */
int setPayload(CoapPDU *coap_pdu,uint8_t *payload, int len) {
	if(payload==NULL) {
		DBG("NULL payload pointer.");
		return 1;
	}

	uint8_t *payloadPointer = mallocPayload(coap_pdu,len);
	if(payloadPointer==NULL) {
		DBG("Allocation of payload failed");
		return 1;
	}

	// copy payload contents
	memcpy(payloadPointer,payload,len);

	return 0;
}

/// Returns a pointer to the payload buffer.
uint8_t* getPayloadPointer(CoapPDU *coap_pdu) {
	return coap_pdu->_payloadPointer;
}

/// Gets the length of the payload buffer.
int getPayloadLength(CoapPDU *coap_pdu) {
	return coap_pdu->_payloadLength;
}

/// Returns a pointer to a buffer which is a copy of the payload buffer (dynamically allocated).
uint8_t* getPayloadCopy(CoapPDU *coap_pdu) {
	if(coap_pdu->_payloadLength==0) {
		return NULL;
	}

	// malloc space for copy
	uint8_t *payload = (uint8_t*)malloc(coap_pdu->_payloadLength);
	if(payload==NULL) {
		DBG("Unable to allocate memory for payload");
		return NULL;
	}

	// copy and return
	memcpy(payload,coap_pdu->_payloadPointer,coap_pdu->_payloadLength);
	return payload;
}

/// Shorthand for setting the content-format option.
/**
 * Sets the content-format to the specified value (adds an option). 
 * \param format The content format, one of:
 *
 * - COAP_CONTENT_FORMAT_TEXT_PLAIN
 * - COAP_CONTENT_FORMAT_APP_LINK
 * - COAP_CONTENT_FORMAT_APP_XML
 * - COAP_CONTENT_FORMAT_APP_OCTET
 * - COAP_CONTENT_FORMAT_APP_EXI
 * - COAP_CONTENT_FORMAT_APP_JSON
 *
 * \return 0 on success, 1 on failure.
 */
int setContentFormat(CoapPDU *coap_pdu, ContentFormat format) {
	if(format==0) {
		// minimal representation means null option value
		if(addOption(coap_pdu, COAP_OPTION_CONTENT_FORMAT,0,NULL)!=0) {
			DBG("Error setting content format");
			return 1;
		}
		return 0;
	}

	uint8_t c[2];

	// just use 1 byte if can do it
	if(format<256) {
		c[0] = format;
		if(addOption(coap_pdu,COAP_OPTION_CONTENT_FORMAT,1,c)!=0) {
			DBG("Error setting content format");
			return 1;
		}
		return 0;
	}

	uint16_t networkOrder = htons(format);
	c[0] &= 0x00;
	c[0] |= (networkOrder >> 8);     // MSB
	c[1] &= 0x00;
	c[1] |= (networkOrder & 0x00FF); // LSB
	if(addOption(coap_pdu,COAP_OPTION_CONTENT_FORMAT,2,c)!=0) {
		DBG("Error setting content format");
		return 1;
	}
	return 0;
}

/// PRIVATE PRIVATE PRIVATE PRIVATE PRIVATE PRIVATE PRIVATE
/// PRIVATE PRIVATE PRIVATE PRIVATE PRIVATE PRIVATE PRIVATE

/// Moves a block of bytes to end of PDU from given offset.
/**
 * This moves the block of bytes _pdu[_pduLength-1-shiftOffset-shiftAmount] ... _pdu[_pduLength-1-shiftOffset]
 * to the end of the PDU.
 * \param shiftOffset End of block to move, relative to end of PDU (-1).
 * \param shiftAmount Length of block to move.
 */
void shiftPDUUp(CoapPDU *coap_pdu, int shiftOffset, int shiftAmount) {
	DBG("shiftOffset: %d, shiftAmount: %d",shiftOffset,shiftAmount);
	int destPointer = coap_pdu->_pduLength-1;
	int srcPointer  = destPointer-shiftOffset;
	uint8_t *_pdu = coap_pdu->_pdu;
	while(shiftAmount--) {
		_pdu[destPointer] = _pdu[srcPointer];
		destPointer--;
		srcPointer--;
	}
}

/// Moves a block of bytes down a specified number of steps. 
/**
 * Moves the block of bytes _pdu[startLocation+shiftOffset] ... _pdu[startLocation+shiftOffset+shiftAmount]
 * down to \b startLocation.
 * \param startLocation Index where to shift the block to.
 * \param shiftOffset Where the block starts, relative to start index.
 * \param shiftAmount Length of block to shift.
 */
void shiftPDUDown(CoapPDU *coap_pdu, int startLocation, int shiftOffset, int shiftAmount) {
	DBG("startLocation: %d, shiftOffset: %d, shiftAmount: %d",startLocation,shiftOffset,shiftAmount);
	int srcPointer = startLocation+shiftOffset;
	uint8_t *_pdu = coap_pdu->_pdu;
	while(shiftAmount--) {
		_pdu[startLocation] = _pdu[srcPointer];
		startLocation++;
		srcPointer++;
	}
}

/// Gets the payload length of an option.
/**
 * \param option Pointer to location of option in PDU.
 * \return The 16 bit option-payload length.
 */
uint16_t getOptionValueLength(CoapPDU *coap_pdu, uint8_t *option) {
	uint16_t delta = (option[0] & 0xF0) >> 4;
	uint16_t length = (option[0] & 0x0F);
	// no extra bytes
	if(length<13) {
		return length;
	}
	
	// extra bytes skip header
	int offset = 1;
	// skip extra option delta bytes
	if(delta==13) {
		offset++;
	} else if(delta==14) {
		offset+=2;
	}

	// process length
	if(length==13) {
		return (option[offset]+13);
	} else {
		// need to convert to host order
		uint16_t networkOrder = 0x0000;
		networkOrder |= option[offset++];
		networkOrder <<= 8;
		networkOrder |= option[offset];
		uint16_t hostOrder = ntohs(networkOrder);
		return hostOrder+269;
	}

}

/// Gets the delta of an option.
/**
 * \param option Pointer to location of option in PDU.
 * \return The 16 bit delta.
 */
uint16_t getOptionDelta(CoapPDU *coap_pdu, uint8_t *option) {
	uint16_t delta = (option[0] & 0xF0) >> 4;
	if(delta<13) {
		return delta;
	} else if(delta==13) {
		// single byte option delta
		return (option[1]+13);
	} else if(delta==14) {
		// double byte option delta
		// need to convert to host order
		uint16_t networkOrder = 0x0000;
		networkOrder |= option[1];
		networkOrder <<= 8;
		networkOrder |= option[2];
		uint16_t hostOrder = ntohs(networkOrder);
		return hostOrder+269;
	} else {
		// should only ever occur in payload marker
		return delta;
	}
}

/// Finds the insertion position in the current list of options for the specified option.
/**
 * \param optionNumber The option's number.
 * \param prevOptionNumber A pointer to a uint16_t which will store the option number of the option previous
 * to the insertion point.
 * \return 0 on success, 1 on failure. \b prevOptionNumber will contain the option number of the option
 * before the insertion position (for example 0 if no options have been inserted).
 */
int findInsertionPosition(CoapPDU *coap_pdu, uint16_t optionNumber, uint16_t *prevOptionNumber) {
	// zero this for safety
	*prevOptionNumber = 0x00;

	DBG("_pduLength: %d",coap_pdu->_pduLength);

	// if option is bigger than any currently stored, it goes at the end
	// this includes the case that no option has yet been added
	if( (optionNumber >= coap_pdu->_maxAddedOptionNumber) || (coap_pdu->_pduLength == (COAP_HDR_SIZE+getTokenLength(coap_pdu))) ) {
		*prevOptionNumber = coap_pdu->_maxAddedOptionNumber;
		return coap_pdu->_pduLength;
	}

	// otherwise walk over the options
	int optionPos = COAP_HDR_SIZE + getTokenLength(coap_pdu);
	uint16_t optionDelta = 0, optionValueLength = 0;
	uint16_t currentOptionNumber = 0;
	uint8_t *_pdu = coap_pdu->_pdu;
	while(optionPos<(coap_pdu->_pduLength) && _pdu[optionPos]!=0xFF) {
		optionDelta =getOptionDelta(coap_pdu,&_pdu[optionPos]);
		currentOptionNumber += optionDelta;
		optionValueLength = getOptionValueLength(coap_pdu, &_pdu[optionPos]);
		// test if this is insertion position
		if(currentOptionNumber>optionNumber) {
			return optionPos;
		}
		// keep track of the last valid option number
		*prevOptionNumber = currentOptionNumber;
		// move onto next option
		optionPos += computeExtraBytes(coap_pdu, optionDelta);
		optionPos += computeExtraBytes(coap_pdu, optionValueLength);
		optionPos += optionValueLength;
		optionPos++; // (for mandatory option header byte)
	}
	return optionPos;

}

/// CoAP uses a minimal-byte representation for length fields. This returns the number of bytes needed to represent a given length.
int computeExtraBytes(CoapPDU *coap_pdu, uint16_t n) {
	if(n<13) {
		return 0;
	}

	if(n<269) { 
		return 1;
	}
	
	return 2;
}

/// Set the option delta to the specified value.
/** 
 * This assumes space has been made for the option delta.
 * \param optionPosition The index of the option in the PDU.
 * \param optionDelta The option delta value to set.
 */
void setOptionDelta(CoapPDU *coap_pdu, int optionPosition, uint16_t optionDelta) {
	int headerStart = optionPosition;
	uint8_t *_pdu = coap_pdu->_pdu;	
	// clear the old option delta bytes
	_pdu[headerStart] &= 0x0F;

	// set the option delta bytes
	if(optionDelta<13) {
		_pdu[headerStart] |= (optionDelta << 4);
	} else if(optionDelta<269) {
	   // 1 extra byte
		_pdu[headerStart] |= 0xD0; // 13 in first nibble
		_pdu[++optionPosition] &= 0x00;
		_pdu[optionPosition] |= (optionDelta-13);
	} else {
		// 2 extra bytes, network byte order uint16_t
		_pdu[headerStart] |= 0xE0; // 14 in first nibble
		optionDelta = htons(optionDelta-269);
		_pdu[++optionPosition] &= 0x00;
		_pdu[optionPosition] |= (optionDelta >> 8);     // MSB
		_pdu[++optionPosition] &= 0x00;
		_pdu[optionPosition] |= (optionDelta & 0x00FF); // LSB
	}
}

/// Insert an option in-memory at the specified location.
/**
 * This assumes that there is enough space at the location specified.
 * \param insertionPosition Position in the PDU where the option should be placed.
 * \param optionDelta The delta value for the option.
 * \param optionValueLength The length of the option value.
 * \param optionValue A pointer to the sequence of bytes representing the option value.
 * \return 0 on success, 1 on failure.
 */
int insertOption(CoapPDU *coap_pdu,
	int insertionPosition,
	uint16_t optionDelta, 
	uint16_t optionValueLength,
	uint8_t *optionValue) {

	int headerStart = insertionPosition;
	uint8_t *_pdu = coap_pdu->_pdu;	
	
	// clear old option header start
	_pdu[headerStart] &= 0x00;

	// set the option delta bytes
	if(optionDelta<13) {
		_pdu[headerStart] |= (optionDelta << 4);
	} else if(optionDelta<269) {
	   // 1 extra byte
		_pdu[headerStart] |= 0xD0; // 13 in first nibble
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (optionDelta-13);
	} else {
		// 2 extra bytes, network byte order uint16_t
		_pdu[headerStart] |= 0xE0; // 14 in first nibble
		optionDelta = htons(optionDelta-269);
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (optionDelta >> 8);     // MSB
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (optionDelta & 0x00FF); // LSB
	}

	// set the option value length bytes
	if(optionValueLength<13) {
		_pdu[headerStart] |= (optionValueLength & 0x000F);
	} else if(optionValueLength<269) {
		_pdu[headerStart] |= 0x0D; // 13 in second nibble
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (optionValueLength-13);
	} else {
		_pdu[headerStart] |= 0x0E; // 14 in second nibble
		// this is in network byte order
		DBG("optionValueLength: %u",optionValueLength);
		uint16_t networkOrder = htons(optionValueLength-269);
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (networkOrder >> 8);     // MSB
		_pdu[++insertionPosition] &= 0x00;
		_pdu[insertionPosition] |= (networkOrder & 0x00FF); // LSB
	}

	// and finally copy the option value itself
	memcpy(&_pdu[++insertionPosition],optionValue,optionValueLength);

	return 0;
}

// DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG
// DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG

/// Prints the PDU in human-readable format.
void printHuman(CoapPDU *coap_pdu) {
	INFO("__________________");
	if(coap_pdu->_constructedFromBuffer) {
		INFO("PDU was constructed from buffer of %d bytes",coap_pdu->_bufferLength);
	}
	INFO("PDU is %d bytes long",coap_pdu->_pduLength);
	INFO("CoAP Version: %d",getVersion(coap_pdu));
	INFOX("Message Type: ");
	switch(getType(coap_pdu)) {
		case COAP_CONFIRMABLE:
			INFO("Confirmable");
		break;

		case COAP_NON_CONFIRMABLE:
			INFO("Non-Confirmable");
		break;

		case COAP_ACKNOWLEDGEMENT:
			INFO("Acknowledgement");
		break;

		case COAP_RESET:
			INFO("Reset");
		break;
	}
	INFO("Token length: %d",getTokenLength(coap_pdu));
	INFOX("Code: ");
	switch(getCode(coap_pdu)) {
		case COAP_EMPTY:
			INFO("0.00 Empty");
		break;
		case COAP_GET:
			INFO("0.01 GET");
		break;
		case COAP_POST:
			INFO("0.02 POST");
		break;
		case COAP_PUT:
			INFO("0.03 PUT");
		break;
		case COAP_DELETE:
			INFO("0.04 DELETE");
		break;
		case COAP_CREATED:
			INFO("2.01 Created");
		break;
		case COAP_DELETED:
			INFO("2.02 Deleted");
		break;
		case COAP_VALID:
			INFO("2.03 Valid");
		break;
		case COAP_CHANGED:
			INFO("2.04 Changed");
		break;
		case COAP_CONTENT:
			INFO("2.05 Content");
		break;
		case COAP_BAD_REQUEST:
			INFO("4.00 Bad Request");
		break;
		case COAP_UNAUTHORIZED:
			INFO("4.01 Unauthorized");
		break;
		case COAP_BAD_OPTION:
			INFO("4.02 Bad Option");
		break;
		case COAP_FORBIDDEN:
			INFO("4.03 Forbidden");
		break;
		case COAP_NOT_FOUND:
			INFO("4.04 Not Found");
		break;
		case COAP_METHOD_NOT_ALLOWED:
			INFO("4.05 Method Not Allowed");
		break;
		case COAP_NOT_ACCEPTABLE:
			INFO("4.06 Not Acceptable");
		break;
		case COAP_PRECONDITION_FAILED:
			INFO("4.12 Precondition Failed");
		break;
		case COAP_REQUEST_ENTITY_TOO_LARGE:
			INFO("4.13 Request Entity Too Large");
		break;
		case COAP_UNSUPPORTED_CONTENT_FORMAT:
			INFO("4.15 Unsupported Content-Format");
		break;
		case COAP_INTERNAL_SERVER_ERROR:
			INFO("5.00 Internal Server Error");
		break;
		case COAP_NOT_IMPLEMENTED:
			INFO("5.01 Not Implemented");
		break;
		case COAP_BAD_GATEWAY:
			INFO("5.02 Bad Gateway");
		break;
		case COAP_SERVICE_UNAVAILABLE:
			INFO("5.03 Service Unavailable");
		break;
		case COAP_GATEWAY_TIMEOUT:
			INFO("5.04 Gateway Timeout");
		break;
		case COAP_PROXYING_NOT_SUPPORTED:
			INFO("5.05 Proxying Not Supported");
		break;
		case COAP_UNDEFINED_CODE:
			INFO("Undefined Code");
		break;
	}

	// print message ID
	INFO("Message ID: %u",getMessageID(coap_pdu));

	// print token value
	int tokenLength = getTokenLength(coap_pdu);
	uint8_t *tokenPointer = getPDUPointer(coap_pdu)+COAP_HDR_SIZE;
	if(tokenLength==0) {
		INFO("No token.");
	} else {
		INFO("Token of %d bytes.",tokenLength);
		INFOX("   Value: 0x");
		for(int j=0; j<tokenLength; j++) {
			INFOX("%.2x",tokenPointer[j]);
		}
		INFO(" ");
	}

	// print options
	CoapOption* options = getOptions(coap_pdu);
	INFO("%d options:",coap_pdu->_numOptions);
	for(int i=0; i<coap_pdu->_numOptions; i++) {
		INFO("OPTION (%d/%d)",i + 1,coap_pdu->_numOptions);
		INFO("   Option number (delta): %hu (%hu)",options[i].optionNumber,options[i].optionDelta);
		INFOX("   Name: ");
		switch(options[i].optionNumber) {
			case COAP_OPTION_IF_MATCH:
				INFO("IF_MATCH");
			break;
			case COAP_OPTION_URI_HOST:
				INFO("URI_HOST");
			break;
			case COAP_OPTION_ETAG:
				INFO("ETAG");
			break;
			case COAP_OPTION_IF_NONE_MATCH:
				INFO("IF_NONE_MATCH");
			break;
			case COAP_OPTION_OBSERVE:
				INFO("OBSERVE");
			break;
			case COAP_OPTION_URI_PORT:
				INFO("URI_PORT");
			break;
			case COAP_OPTION_LOCATION_PATH:
				INFO("LOCATION_PATH");
			break;
			case COAP_OPTION_URI_PATH:
				INFO("URI_PATH");
			break;
			case COAP_OPTION_CONTENT_FORMAT:
				INFO("CONTENT_FORMAT");
			break;
			case COAP_OPTION_MAX_AGE:
				INFO("MAX_AGE");
			break;
			case COAP_OPTION_URI_QUERY:
				INFO("URI_QUERY");
			break;
			case COAP_OPTION_ACCEPT:
				INFO("ACCEPT");
			break;
			case COAP_OPTION_LOCATION_QUERY:
				INFO("LOCATION_QUERY");
			break;
			case COAP_OPTION_PROXY_URI:
				INFO("PROXY_URI");
			break;
			case COAP_OPTION_PROXY_SCHEME:
				INFO("PROXY_SCHEME");
			break;
			case COAP_OPTION_BLOCK1:
				INFO("BLOCK1");
			break;
			case COAP_OPTION_BLOCK2:
				INFO("BLOCK2");
			break;
			case COAP_OPTION_SIZE1:
				INFO("SIZE1");
			break;
			case COAP_OPTION_SIZE2:
				INFO("SIZE2");
			break;
			default:
				INFO("Unknown option");
			break;
		}
		INFO("   Value length: %u",options[i].optionValueLength);
		INFOX("   Value: \"");
		for(int j=0; j<options[i].optionValueLength; j++) {
			char c = options[i].optionValuePointer[j];
			if((c>='!'&&c<='~')||c==' ') {
				INFOX("%c",c);
			} else {
				INFOX("\\%.2d",c);
			}
		}
		INFO("\"");
	}
	
	// print payload
	if(coap_pdu->_payloadLength==0) {
		INFO("No payload.");
	} else {
		INFO("Payload of %d bytes",coap_pdu->_payloadLength);
		INFOX("   Value: \"");
		for(int j=0; j<coap_pdu->_payloadLength; j++) {
			char c = coap_pdu->_payloadPointer[j];
			if((c>='!'&&c<='~')||c==' ') {
				INFOX("%c",c);
			} else {
				INFOX("\\%.2x",c);
			}
		}
		INFO("\"");
	}
	INFO("__________________");
}

/// Prints the PDU as a c array (useful for debugging or hardcoding PDUs)
void printPDUAsCArray(CoapPDU *coap_pdu) {
	printf("const uint8_t array[] = {\r\n   ");
	for(int i=0; i<coap_pdu->_pduLength; i++) {
		printf("0x%.2x, ",coap_pdu->_pdu[i]);
	}
	printf("\r\n};\r\n");
}

/// A routine for printing an option in human-readable format.
/**
 * \param option This is a pointer to where the option begins in the PDU.
 */
void printOptionHuman(CoapPDU *coap_pdu,uint8_t *option) {
	// compute some useful stuff
	uint16_t optionDelta = getOptionDelta(coap_pdu,option);
	uint16_t optionValueLength = getOptionValueLength(coap_pdu, option);
	int extraDeltaBytes = computeExtraBytes(coap_pdu,optionDelta);
	int extraValueLengthBytes = computeExtraBytes(coap_pdu,optionValueLength);
	int totalLength = 1+extraDeltaBytes+extraValueLengthBytes+optionValueLength;

	if(totalLength>coap_pdu->_pduLength) {
		uint8_t *_pdu=coap_pdu->_pdu;
		totalLength = &_pdu[(coap_pdu->_pduLength)-1]-option;
		DBG("New length: %u",totalLength);
	}

	// print summary
	DBG("~~~~~~ Option ~~~~~~");
	DBG("Delta: %u, Value length: %u",optionDelta,optionValueLength);

	// print all bytes
	DBG("All bytes (%d):",totalLength);
	for(int i=0; i<totalLength; i++) {
		if(i%4==0) {
			DBG(" ");
			DBGX("   %.2d ",i);
		}
		_printBinary(option[i]); DBGX(" ");
	}
	DBG(" "); DBG(" ");

	// print header byte
	DBG("Header byte:");
	DBGX("   ");
	_printBinary(*option++);
	DBG(" "); DBG(" ");

	// print extended delta bytes
	if(extraDeltaBytes) {
		DBG("Extended delta bytes (%d) in network order: ",extraDeltaBytes);
		DBGX("   ");
		while(extraDeltaBytes--) {
			_printBinary(*option++); DBGX(" ");
		}
	} else {
		DBG("No extended delta bytes");
	}
	DBG(" "); DBG(" ");

	// print extended value length bytes
	if(extraValueLengthBytes) {
		DBG("Extended value length bytes (%d) in network order: ",extraValueLengthBytes);
		DBGX("   ");
		while(extraValueLengthBytes--) {
			_printBinary(*option++); DBGX(" ");
		}
	} else {
		DBG("No extended value length bytes");
	}
	DBG(" ");

	// print option value
	DBG("Option value bytes:");
	for(int i=0; i<optionValueLength; i++) {
		if(i%4==0) {
			DBG(" ");
			DBGX("   %.2d ",i);
		}
		_printBinary(*option++);
		DBGX(" ");
	}
	DBG(" ");
}

/// Dumps the PDU header in hex.
void printHex(CoapPDU *coap_pdu) {
	printf("Hexdump dump of PDU\r\n");
	uint8_t *_pdu = coap_pdu->_pdu;
	printf("%.2x %.2x %.2x %.2x",_pdu[0],_pdu[1],_pdu[2],_pdu[3]);
}

/// Dumps the entire PDU in binary.
void printBin(CoapPDU *coap_pdu) {
	uint8_t *_pdu = coap_pdu->_pdu;
	for(int i=0; i<coap_pdu->_pduLength; i++) {
		if(i%4==0) {
			printf("\r\n");
			printf("%.2d ",i);
		} 
		_printBinary(_pdu[i]); printf(" ");
	}
	printf("\r\n");
}

/// Prints a single byte in binary.
void _printBinary(uint8_t b) {
	printf("%d%d%d%d%d%d%d%d",
		(b&0x80)&&0x01,
		(b&0x40)&&0x01,
		(b&0x20)&&0x01,
		(b&0x10)&&0x01,
		(b&0x08)&&0x01,
		(b&0x04)&&0x01,
		(b&0x02)&&0x01,
		(b&0x01)&&0x01);
}

/// Dumps the PDU as a byte sequence to stdout.
void print(CoapPDU *coap_pdu) {
	fwrite(coap_pdu->_pdu,1,coap_pdu->_pduLength,stdout);
}

