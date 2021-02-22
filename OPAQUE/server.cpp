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
#define PROTOCOL OPAQUE
#include "opaque.h"
#include <cctype>

int main( int argc, char *argv[] )
{
	if ( argc < 1 || argc > 3 )
	{
		fprintf( stderr, "Usage: %s [[<ip>] <port>]\n", argv[0] );
		return 1;
	}

	if ( sodium_init() < 0 )
	{
		error( 1, 0, "sodium_init failed" );
	}

	init_measure();

#if MEASURE == MEASURE_ALL
	start_measure( "Connecting", false );
#endif

	const char      *ip = argc>2 ? argv[argc-2] : NULL ;
	const uint16_t port = argc>1 ? (uint16_t) atoi( argv[argc-1] ) : 9999 ;
	const int      sock = open_socket( ip, port );

	start_measure( "Receiving user msg #1" );

	BYTE sid[MAX_ID_BYTES + 1];
	BYTE ssid[16];
	BYTE X_u[crypto_core_ristretto255_BYTES];
	BYTE alpha[crypto_core_ristretto255_BYTES];
	sid[MAX_ID_BYTES] = '\0';

	RECV( sock, { sid,   MAX_ID_BYTES  },
				{ ssid,  sizeof(ssid)  },
				{ X_u  , sizeof(X_u)   },
				{ alpha, sizeof(alpha) } );


	start_measure( "Validating points" );

	SODIUM( core_ristretto255_is_valid_point, alpha );
	SODIUM( core_ristretto255_is_valid_point, X_u );

	/* Load data from password file */

	start_measure( "Loading password file" );

	// Check sid is alpha-numeric to avoid path traversal.
	char filename[ MAX_ID_BYTES + sizeof(".pwd") ];
	size_t sid_len = strlen( (const char*) sid );
	for ( size_t i=0; i<sid_len; i++ )
	{
		char c = sid[i];
		if ( ! isalnum( c ) )
		{
			error( 1, 0, "Client ID contains invalid char: 0x%x", sid[i] );
		}
		filename[i] = (char) tolower( c );
	}
	memcpy( filename + sid_len, ".pwd", sizeof(".pwd") );

	BYTE *pwd_file = read_file( filename );
	BYTE *orig_file = pwd_file;

	// k_s, p_s, P_s, P_u, c = file[sid]
	const BYTE *k_s = pwd_file;
	pwd_file += crypto_core_ristretto255_SCALARBYTES;
	const BYTE * p_s = pwd_file;
	pwd_file += crypto_core_ristretto255_SCALARBYTES;
	const BYTE *P_s = pwd_file;
	pwd_file += crypto_core_ristretto255_BYTES;
	(void) P_s;	// unused
	BYTE *P_u = pwd_file;
	pwd_file += crypto_core_ristretto255_BYTES;
	BYTE *c = pwd_file;


	start_measure( "Generating Key" );

	// x_s \genR Zq
	BYTE x_s[crypto_core_ristretto255_SCALARBYTES];
	crypto_core_ristretto255_scalar_random( x_s );

	// X_s = g^x_s
	BYTE X_s[crypto_core_ristretto255_BYTES];
	SODIUM( scalarmult_ristretto255_base, X_s, x_s );

	// beta = alpha ^ k_s
	BYTE beta[crypto_core_ristretto255_BYTES];
	SODIUM( scalarmult_ristretto255, beta, k_s, alpha );

	// ssid' = H( sid || ssid || alpha )
	BYTE ssid_pr[crypto_hash_sha256_BYTES];
	TAGGED_HASH( ssid_pr, 3, { sid, MAX_ID_BYTES }, { ssid, sizeof(ssid) }, { alpha, sizeof(alpha) } );

	// e_s = H( X_s || "U" || ssid' )
	// e_u = H( X_u || "S" || ssid' )
	BYTE hash[crypto_core_ristretto255_NONREDUCEDSCALARBYTES];
	BYTE e_s[crypto_core_ristretto255_SCALARBYTES], e_u[crypto_core_ristretto255_SCALARBYTES];
	TAGGED_HASH( hash, 4, { X_s, sizeof(X_s) }, { (const BYTE*) "U", 1 }, { ssid_pr, sizeof(ssid_pr) } );
	crypto_core_ristretto255_scalar_reduce( e_s, hash );
	TAGGED_HASH( hash, 4, { X_u, sizeof(X_u) }, { (const BYTE*) "S", 1 }, { ssid_pr, sizeof(ssid_pr) } );
	crypto_core_ristretto255_scalar_reduce( e_u, hash );

	// K = H( ( X_u * P_u ^ e_u ) ^ ( x_s + e_s * p_s ) )
	SODIUM( scalarmult_ristretto255, P_u, e_u, P_u );
	SODIUM( core_ristretto255_add, X_u, X_u, P_u );
	crypto_core_ristretto255_scalar_mul( e_s, e_s, p_s );
	crypto_core_ristretto255_scalar_add( x_s, x_s, e_s );

	SODIUM( scalarmult_ristretto255, X_u, x_s, X_u );
	BYTE K[crypto_stream_KEYBYTES];
	TAGGED_HASH( K, 5, { X_u, sizeof(X_u) } );

	// SK  = PRF( K, 0 || ssid' )
	// A_s = PRF( K, 1 || ssid' )
	// A_u = PRF( K, 2 || ssid' )
	struct
	{
		BYTE SK[32];
		BYTE A_s[32];
		BYTE A_u[32];
	} out;
	static_assert( sizeof(ssid_pr) >= crypto_stream_NONCEBYTES, "Hash output too short for nonce" );
	SODIUM( stream, (BYTE*) &out, sizeof(out), ssid_pr, K );


	start_measure( "Exchanging messages" );

	SEND( sock, { beta,    sizeof(beta)    },
				{ X_s,     sizeof(X_s)     },
				{ c,       crypto_secretbox_MACBYTES + crypto_core_ristretto255_SCALARBYTES + 2*crypto_core_ristretto255_BYTES },
				{ out.A_s, sizeof(out.A_s) } );

	BYTE A_u[32];

	RECV( sock, { A_u, sizeof(A_u) } );


	start_measure( "Validating Key" );

	// Compare A_s
	if ( sodium_memcmp( A_u, out.A_u, sizeof(A_u) ) != 0 )
	{
		error( 1, 0, "Failed verifying A_u" );
	}

	stop_measure();

	print_total( "Total", ONLINE | OFFLINE );
	print_total( "Total Online", ONLINE );

	printf("Shared key: ");
	print_bytes( out.SK, sizeof(out.SK) );

	free( orig_file );
	close( sock );

	return 0;
}