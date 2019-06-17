/* 
 *  Copyright (C) Pedro Moreno Sánchez on 25/04/12.
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

#ifndef _EAX_H
#define _EAX_H

#include "include.h"

/* PARAMETERS: Play with as desired */
#define MSG_MIN 0 /* anything */
#define MSG_MAX 0  /* anything >= MSG_MIN */
#define NONCE_SIZE 16 /* anything, will tend to be == blocksize of cipher */
#define HEADER_SIZE 8 /* anything */
#define TAG_SIZE 16 /* between 0 and 16 */

#define VECTORS 1 /* how many vectors to print at once */
#define DUMP_INTER 0 /* dump intermediate values */


void do_eax(const uint8_t key[16], const uint8_t nonce[16],
            const uint8_t data[], int length,
            const uint8_t header[], int h_length,
            uint8_t data_ciphered[],
            uint8_t tag_buf[], int tag_length);

void do_omac(const uint8_t key[16], const uint8_t data[], int length,
             uint8_t mac[16]);

#endif
