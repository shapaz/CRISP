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
#define PROTOCOL CHIP
#include "../utils.h"
#include "../pake.h"

int main( int argc, char *argv[] )
{
	if ( argc < 2 || argc > 4 )
	{
		fprintf( stderr, "Usage: %s <password-file> [[<ip>] <port>]\n", argv[0] );
		return 1;
	}

	if ( sodium_init() < 0 )
	{
		error( 1, 0, "sodium_init failed" );
	}

	init_measure();


	/* Load data from password file */

#if MEASURE == MEASURE_ALL
	start_measure( "Loading password file", false );
#endif

	BYTE *pwd_file = read_file( argv[1] );
	BYTE *orig_file = pwd_file;

	const BYTE *network = pwd_file;
	size_t network_size = strlen( (const char*) network );
	pwd_file += network_size+1;

	BYTE *IDi = pwd_file;
	pwd_file += MAX_ID_BYTES;

	BYTE *Xi = pwd_file;
	pwd_file += crypto_core_ristretto255_BYTES;

	const BYTE *Yi = pwd_file;
	pwd_file += crypto_core_ristretto255_BYTES;

	const BYTE *zi = pwd_file;
	pwd_file += crypto_core_ristretto255_SCALARBYTES;


	/* Build outgoing message */

	start_measure( "Blinding", false );

	BYTE r[crypto_core_ristretto255_SCALARBYTES];
	crypto_core_ristretto255_scalar_random( r );
	BYTE Ri[crypto_core_ristretto255_BYTES];
	SODIUM( scalarmult_ristretto255_base, Ri, r );


	/* Send message */

#if MEASURE == MEASURE_ALL
	start_measure( "Connecting", false );
#endif

	const char      *ip = argc>3 ? argv[argc-2] : NULL ;
	const uint16_t port = argc>2 ? (uint16_t) atoi( argv[argc-1] ) : 9999 ;
	const int      sock = open_socket( ip, port );

	start_measure( "Exchanging messages" );

	SEND( sock, { IDi, MAX_ID_BYTES                   },
				{ Xi , crypto_core_ristretto255_BYTES },
				{ Ri , crypto_core_ristretto255_BYTES } );


	/* Receive incoming message */

	BYTE IDj[MAX_ID_BYTES + 1];
	BYTE Xj[crypto_core_ristretto255_BYTES];
	BYTE Rj[crypto_core_ristretto255_BYTES];
	IDj[MAX_ID_BYTES] = '\0';

	RECV( sock, { IDj, MAX_ID_BYTES                   },
				{ Xj , crypto_core_ristretto255_BYTES },
				{ Rj , crypto_core_ristretto255_BYTES } );

	stop_measure();


	/* Check Aj */

	printf( "Identified: %s\n", IDj );


	/* Compute shared secret */

	start_measure( "Computing shared secret" );

	bool is_first = memcmp( Ri, Rj, sizeof(Rj) ) >= 0;

	/* A = Rj ^ r */
	BYTE A[crypto_core_ristretto255_BYTES];
	SODIUM( scalarmult_ristretto255, A, r, Rj );

	/* hj = H2( IDj, Xj ) */
	BYTE IDj_hash[crypto_core_ristretto255_NONREDUCEDSCALARBYTES];
	TAGGED_HASH( IDj_hash, 2, { IDj, MAX_ID_BYTES }, { Xj, sizeof(Xj) } );
	BYTE hj[crypto_core_ristretto255_SCALARBYTES];
	crypto_core_ristretto255_scalar_reduce( hj, IDj_hash );

	/* B = (Rj*Xj*Yi^hj) ^ (r+zi) */
	BYTE B[crypto_core_ristretto255_BYTES];
	SODIUM( scalarmult_ristretto255, B, hj, Yi );
	SODIUM( core_ristretto255_add, B, Xj, B );
	SODIUM( core_ristretto255_add, B, Rj, B );
	crypto_core_ristretto255_scalar_add( r, r, zi );
	SODIUM( scalarmult_ristretto255, B, r, B );


	BYTE S[crypto_hash_sha256_BYTES];
	TAGGED_HASH( S, 4, { A, sizeof(A) },
					   { B, sizeof(B) },
					   { is_first ? IDi : IDj, MAX_ID_BYTES },
					   { is_first ? Xi  : Xj , sizeof(Xj)   },
					   { is_first ? Ri  : Rj , sizeof(Rj)   },
					   { is_first ? IDj : IDi, MAX_ID_BYTES },
					   { is_first ? Xj  : Xi , sizeof(Xj)   },
					   { is_first ? Rj  : Ri , sizeof(Rj)   } );

	stop_measure();

#if 0
	printf("A: ");
	print_bytes( A, sizeof(A) );
	printf("B: ");
	print_bytes( B, sizeof(B) );
	printf("S: ");
	print_bytes( S, sizeof(S) );
#endif


	/* Run PAKE */

	start_measure( "Running PAKE (1)" );

	// TODO: sid?
	PAKE pake;
	PAKE_NewSession( &pake, is_first, NULL, 0, S, sizeof(S),
					 IDi, MAX_ID_BYTES, IDj, MAX_ID_BYTES,
					 network, network_size );

	start_measure( "Sending PAKE message" );

	SEND( sock, { (BYTE*) PAKE_GetOutBuffer(&pake), PAKE_MSG_BYTES } );

	start_measure( "Receiving PAKE message" );

	RECV( sock, { PAKE_GetInBuffer(&pake), PAKE_MSG_BYTES } );

	start_measure( "Running PAKE (2)" );

	BYTE shared_key[PAKE_KEY_BYTES];
	PAKE_NewKey( &pake, shared_key );

	stop_measure();

	print_total( "Total", ONLINE | OFFLINE );
	print_total( "Total Online", ONLINE );

	printf("Shared key: ");
	print_bytes( shared_key, sizeof(shared_key) );


	close( sock );
	free( orig_file );

	return 0;
}