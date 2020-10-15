/* Copyright (C) 2020 Shahar Paz <shaharps [at] tau [dot] ac [dot] il>
 *
 * This file is part of the CRISP code.
 * See <https://github.com/shapaz/CRISP>.
 *
 * This file may be used under the terms of the GNU General Public License
 * version 3 as published by the Free Software Foundation and appearing in
 * the file LICENSE.GPL included in the packaging of this file.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef UTILS_H
#define UTILS_H

#include <sodium.h>
#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

#define MAX_ID_BYTES				16

#define MAX(x,y)					( (x) > (y) ? (x) : (y) )

#define ARRAY_COUNT(a)				( sizeof(a) / sizeof(a[0]) )

#define DSI(tag)					DSI_(PROTOCOL, tag)
#define DSI_(protocol,tag)			( (const BYTE*) #protocol "-" #tag )
#define DSI_SIZE(tag)				( sizeof( DSI(tag) ) - 1 )

#define MEASURE_NONE				0
#define MEASURE_MAIN				1
#define MEASURE_ALL					2

#ifndef MEASURE
#define MEASURE						MEASURE_MAIN
#endif

#define SODIUM( func, ... )											 \
{																	 \
	int sodium_result = crypto_ ## func ( __VA_ARGS__ );			 \
	if ( sodium_result != 0 )										 \
	{																 \
		error( 1, 0, "crypto_" #func " returned %d", sodium_result );\
	}																 \
}

#define SEND( sock, ... )											\
{																	\
	struct iovec parts[] =											\
	{																\
		{ NULL, 0 },	/* Place holder for header */				\
		__VA_ARGS__													\
	};																\
	vsend( sock, parts, ARRAY_COUNT(parts) );						\
}

#define RECV( sock, ... )											\
{																	\
	struct iovec parts[] =											\
	{																\
		{ NULL, 0 },	/* Place holder for header */				\
		__VA_ARGS__													\
	};																\
	vrecv( sock, parts, ARRAY_COUNT(parts) );						\
}

#define TAGGED_HASH( hash, tag, ... )								\
{																	\
	hash_input_t inputs[] =											\
	{																\
		{ DSI(tag), DSI_SIZE(tag) },								\
		__VA_ARGS__													\
	};																\
	vhash( hash, sizeof(hash), inputs, ARRAY_COUNT(inputs) );		\
}

typedef unsigned char BYTE;

typedef struct
{
	const BYTE *ptr;
	size_t size;
} hash_input_t;

void vhash( BYTE hash[], size_t hash_size,
			const hash_input_t *inputs, size_t count );

void vsend( int sock, struct iovec *parts, size_t count );

void vrecv( int sock, struct iovec *parts, size_t count );

void fwrite_binary( FILE *file, const BYTE buffer[], size_t size );

const unsigned char* encode_BE4( BYTE encoded[4], size_t size );

size_t decode_BE4( const BYTE data[4] );

BYTE *read_file( const char *path );

int open_socket( const char *ip, int port );

static inline void print_bytes( const BYTE bytes[], size_t size )
{
	for ( size_t i=0; i<size; i++ )
	{
		printf( "%02x", bytes[i] );
	}
	printf( "\n" );
}

enum
{
	OFFLINE = 1 << 0,
	ONLINE  = 1 << 1,
};

#if MEASURE == MEASURE_NONE
#define init_measure(...)	/* deleted */
#define start_measure(...)	/* deleted */
#define stop_measure(...)	/* deleted */
#define print_total(...)	/* deleted */
#else
void init_measure();
void start_measure( const char *msg, bool is_online=true );
void stop_measure();
void print_total( const char *msg, int which );
#endif

void alloc_init( void );

#endif