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
#include "utils.h"
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <poll.h>
#include <fcntl.h>
#include <new>
#include <signal.h>
#include <stdlib.h>

void vhash( BYTE hash[], size_t hash_size,
			const hash_input_t *inputs, size_t count )
{
	if ( hash_size == crypto_hash_sha256_BYTES )
	{
		crypto_hash_sha256_state state;
		SODIUM( hash_sha256_init, &state );
		for ( size_t i=0; i<count; i++ )
		{
			SODIUM( hash_sha256_update, &state, inputs[i].ptr, inputs[i].size );
		}
		SODIUM( hash_sha256_final, &state, hash );
	}
	else if ( hash_size == crypto_hash_sha512_BYTES )
	{
		crypto_hash_sha512_state state;
		SODIUM( hash_sha512_init, &state );
		for ( size_t i=0; i<count; i++ )
		{
			SODIUM( hash_sha512_update, &state, inputs[i].ptr, inputs[i].size );
		}
		SODIUM( hash_sha512_final, &state, hash );
	}
	else
	{
		error( 1, 0, "Unsupported hash size %lu", hash_size );
	}
}

void fwrite_binary( FILE *file, const BYTE buffer[], size_t size )
{
	if ( fwrite( buffer, 1, (size_t) size, file ) != (size_t) size )
	{
		error( 1, errno, "fwrite(%ld) failed", size );
	}
}

const BYTE* encode_BE4( BYTE encoded[4], size_t size )
{
	static BYTE static_buffer[4];
	if ( encoded == NULL )
	{
		encoded = static_buffer;
	}

	encoded[3] = size & 0xFF;
	size >>= 8;
	encoded[2] = size & 0xFF;
	size >>= 8;
	encoded[1] = size & 0xFF;
	size >>= 8;
	encoded[0] = size & 0xFF;

	return encoded;
}

size_t decode_BE4( const BYTE data[4] )
{
	size_t value = 0;
	value |= data[0];
	value <<= 8;
	value |= data[1];
	value <<= 8;
	value |= data[2];
	value <<= 8;
	value |= data[3];
	return value;
}


BYTE *read_file( const char *path )
{
	FILE *file = fopen( path, "rb" );
	if ( file == NULL )
	{
		error( 1, errno, "fopen(%s) failed", path );
	}

	fseek( file, 0, SEEK_END );

	long pos = ftell( file );
	if ( pos < 0 )
	{
		error( 1, errno, "ftell failed" );
	}

	size_t file_size = (size_t) pos;

	BYTE *buffer = new BYTE[file_size];
	if ( ! buffer )
	{
		error( 1, errno, "malloc(%lu) failed", file_size );
	}

	fseek( file, 0, SEEK_SET );

	if ( fread( buffer, 1, file_size, file ) != file_size )
	{
		error( 1, errno, "fread(%lu) failed", file_size );
	}

	fclose( file );

	return buffer;
}


static int open_local_socket( uint16_t port )
{
	int sock = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );

	int yes = 1;
	setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes) );

	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	address.sin_addr.s_addr = htonl(INADDR_ANY);

	int result = bind( sock, (struct sockaddr*) &address, sizeof(address) );
	if ( result != 0 )
	{
		if ( errno != EADDRINUSE )
		{
			error( 1, errno, "bind to port %d faild", port );
		}

		result = connect( sock, (struct sockaddr*) &address, sizeof(address) );
		if ( result < 0 )
		{
			error( 1, errno, "connect(%d) failed", port );
		}

		return sock;
	}
	else
	{

		if ( listen( sock, 1 ) != 0 )
		{
			error( 1, errno, "listen failed" );
		}

		int new_sock = accept( sock, NULL, 0 );
		if ( new_sock < 0 )
		{
			error( 1, errno, "accept failed" );
		}

		close( sock );
		return new_sock;
	}
}

enum
{
	SYN     = 1<<0,
	ACK     = 1<<1,
	CTR_INC = 1<<2,
	SYN_ACK = SYN | ACK,
};

static void timeout( int )
{
	error( 1, 0, "Timeout" );
}

static void reset( int, void *arg )
{
	int sock = (int) (intptr_t) arg;
	BYTE b = 0xFF;
	send( sock, &b, 1, 0 );
	close( sock );
}

int open_socket( const char *ip, uint16_t port )
{
	if ( ip == NULL )
	{
		return open_local_socket( port );
	}

	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_port = htons(port);

	int sock = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP );

	address.sin_addr.s_addr = htonl(INADDR_ANY);
	if ( bind( sock, (struct sockaddr*) &address, sizeof(address) ) != 0 )
	{
		error( 1, errno, "bind to local port %d failed", port );
	}

	inet_aton( ip, &address.sin_addr );
	if ( connect( sock, (struct sockaddr*) &address, sizeof(address) ) != 0 )
	{
		error( 1, errno, "connect to %s:%d failed", ip, port );
	}

	BYTE b;

	while ( true )
	{
		b = SYN;
		send( sock, &b, 1, 0 );

		struct pollfd event = { sock, POLLIN, 0 };
		poll( &event, 1, 500 /* 0.5 second */ );

		if ( recv( sock, &b, 1, MSG_DONTWAIT ) == 1 )
		{
			break;
		}
	}

	/* Start timeout. In 2 seconds the process will be killed by signal. */
	on_exit( reset, (void*) (intptr_t) sock );
	signal( SIGALRM, timeout );
	alarm(2);

	if ( b == SYN )
	{
		b = SYN_ACK;
		send( sock, &b, 1, 0 );
		while ( true )
		{
			recv( sock, &b, 1, 0 );
			if ( b == ACK || b == SYN_ACK )
			{
				return sock;
			}
			else if ( b != SYN )
			{
				error( 1, 0, "Expected ACK, got 0x%x", b );
			}
		}
	}
	else if ( b == SYN_ACK )
	{
		b = ACK;
		send( sock, &b, 1, 0 );
		return sock;
	}

	error( 1, 0, "Unexpected data 0x%x", b );
	return 0;
}

static struct msghdr msg;	/* Initialized with zeroes */

void vsend( int sock, struct iovec *parts, size_t count )
{
	static BYTE ctr = 0;

	parts[0].iov_base = &ctr;
	parts[0].iov_len  = sizeof(ctr);

	msg.msg_iov = parts;
	msg.msg_iovlen = count;
	ssize_t result = sendmsg( sock, &msg, 0 );
	if ( result < 0 )
	{
		error( 1, errno, "recvmsg failed" );
	}

	ctr = static_cast<BYTE>( ctr + CTR_INC );
}

void vrecv( int sock, struct iovec *parts, size_t count )
{
	static BYTE ctr = 0;

	BYTE header;
	parts[0].iov_base = &header;
	parts[0].iov_len  = sizeof(header);

	msg.msg_iov = parts;
	msg.msg_iovlen = count;
	ssize_t result = recvmsg( sock, &msg, 0 );
	if ( result <= 0 )
	{
		error( 1, errno, "recvmsg failed" );
	}

	if ( header != ctr )
	{
		error( 1, 0, "Unexpected header 0x%x, expected 0x%x", header, ctr );
	}
	ctr = static_cast<BYTE>( ctr + CTR_INC );
}

static uint64_t nano_time( clockid_t clock )
{
	struct timespec ts;
	clock_gettime( clock, &ts );
	uint64_t nanos = (uint64_t) ts.tv_nsec;
	nanos += ((uint64_t)ts.tv_sec) * 1000u * 1000u * 1000u;
	return nanos;
}

static uint64_t cpu_time()
{
	return nano_time( CLOCK_PROCESS_CPUTIME_ID );
}

static uint64_t raw_time()
{
	return nano_time( CLOCK_MONOTONIC_RAW );
}

static uint64_t cpu_t0, raw_t0;
static uint64_t cpu_total[2]={0}, raw_total[2]={0};
static bool in_measure=false, is_online;

void init_measure()
{
	printf( "%-28s     CPU-time    Real-time\n", "Stage" );
	printf( "========================================================\n" );
}

void start_measure( const char *msg, bool _is_online )
{
	if ( in_measure )
	{
		stop_measure();
	}

	is_online = _is_online;
	printf( "%-28s: ", msg );
	fflush( stdout );
	in_measure = true;
	raw_t0 = raw_time();
	cpu_t0 = cpu_time();
}

static void print_measure( uint64_t cpu, uint64_t raw )
{
#if 0
	printf( "%4lu.%06lu %4lu.%06lu ms\n",
		cpu / 1000 / 1000, cpu % (1000*1000),
		raw / 1000 / 1000, raw % (1000*1000) );
#elif 1
	printf( "%7lu.%03lu %7lu.%03lu us\n",
		cpu / 1000, cpu % 1000,
		raw / 1000, raw % 1000 );
#else
	printf( "%10lu %10lu ns\n", cpu, raw );
#endif
}

void stop_measure()
{
	uint64_t cpu_diff = cpu_time() - cpu_t0;
	uint64_t raw_diff = raw_time() - raw_t0;
	in_measure = false;
	print_measure( cpu_diff, raw_diff );

	cpu_total[is_online] += cpu_diff;
	raw_total[is_online] += raw_diff;
}

void print_total( const char *msg, int which )
{
	printf( "%-28s: ", msg );
	print_measure(
		bool(which & OFFLINE) * cpu_total[false] + bool(which & ONLINE) * cpu_total[true],
		bool(which & OFFLINE) * raw_total[false] + bool(which & ONLINE) * raw_total[true]
	);
}


#ifdef PBC_STATIC_ALLOC

struct pool_t;
typedef struct chunk_t
{
	union
	{
		struct chunk_t *next;
		struct pool_t *pool;
	} meta;
	BYTE buffer[] __attribute__(( aligned(256) ));
} chunk_t;

typedef struct pool_t
{
	size_t size;
	size_t count;
	chunk_t *free_list;
} pool_t;

static pool_t pools[] =
{
	{   16, 64, NULL },
	{   64, 128, NULL },
	{  128, 32, NULL },
	{ 2048, 16, NULL },
};
static void *static_alloc( size_t size )
{
	// fprintf( stderr, "malloc(%lu)\n", size );

	for ( size_t i=0; i<ARRAY_COUNT(pools); i++ )
	{
		pool_t *pool = &pools[i];

		if ( size > pool->size )
		{
			continue;
		}

		chunk_t *chunk = pool->free_list;

		if ( chunk == NULL )
		{
			error( 1, 0, "No more chunks of %lu bytes to allocate", pool->size );
		}

		pool->free_list = chunk->meta.next;
		chunk->meta.pool = pool;
		return chunk->buffer;
	}

	error( 1, 0, "Cannot allocate %lu bytes", size );
	return NULL;
}

static void static_free( void *buffer )
{
	// fprintf( stderr, "free(%p)\n", buffer );
	
	if ( buffer == NULL )
	{
		return;
	}

	chunk_t *chunk = ((chunk_t*)buffer) - 1;
	pool_t *pool = chunk->meta.pool;
	chunk->meta.next = pool->free_list;
	pool->free_list = chunk;
}

static void *static_realloc( void *old, size_t size )
{
	// fprintf( stderr, "realloc(%p, %lu)\n", old, size );
	
	if ( old == NULL )
	{
		return static_alloc( size );
	}

	if ( size == 0 )
	{
		static_free( old );
		return NULL;
	}

	void *new = static_alloc( size );
	memcpy( new, old, size );
	return new;
}

void alloc_init( void )
{
	for ( size_t i=0; i<ARRAY_COUNT(pools); i++ )
	{
		pool_t *pool = &pools[i];
		chunk_t *next = NULL;
		for ( size_t j=0; j<pool->count; j++ )
		{
			chunk_t *chunk = sbrk( (intptr_t)( sizeof(chunk_t) + pool->size ) );
			chunk->meta.next = next;
			next = chunk;
		}
		pool->free_list = next;
	}

	pbc_set_memory_functions( static_alloc, static_realloc, static_free );
}

#else

void alloc_init( void )
{
}

#endif