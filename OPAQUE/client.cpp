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

int main( int argc, char *argv[] )
{
	if ( argc < 3 || argc > 5 )
	{
		fprintf( stderr, "Usage: %s <password> <identity> [[<ip>] <port>]\n", argv[0] );
		return 1;
	}

	if ( sodium_init() < 0 )
	{
		error( 1, 0, "sodium_init failed" );
	}

	init_measure();

	start_measure( "Generating user msg" );

	// sid = identity
	const char *identity = argv[2];
	const size_t id_len = strlen( identity );
	if ( id_len > MAX_ID_BYTES )
	{
		error( 1, 0, "Identity length should be <= %d, but len(%s) = %lu", MAX_ID_BYTES, identity, id_len );
	}
	BYTE sid[MAX_ID_BYTES];
	memcpy( sid, identity, id_len );
	memset( sid + id_len, '\0', MAX_ID_BYTES - id_len );

	// ssid = random()
	BYTE ssid[16];
	randombytes_buf( ssid, sizeof(ssid) );

	// r, x_u \genR Zq
	BYTE r[crypto_core_ristretto255_SCALARBYTES];
	BYTE x_u[crypto_core_ristretto255_SCALARBYTES];
	crypto_core_ristretto255_scalar_random( r );
	crypto_core_ristretto255_scalar_random( x_u );

	// X_u = g^x_u
	BYTE X_u[crypto_core_ristretto255_BYTES];
	SODIUM( scalarmult_ristretto255_base, X_u, x_u );

	// alpha = H1(pwd)^r
	const BYTE *password = (const BYTE*) argv[1];
	const size_t pwd_len = strlen( (const char*) password );
	BYTE pwd_hash[crypto_core_ristretto255_HASHBYTES];
	TAGGED_HASH( pwd_hash, 1, { password, pwd_len } );
	BYTE alpha[crypto_core_ristretto255_BYTES];
	SODIUM( core_ristretto255_from_hash, alpha, pwd_hash );
	SODIUM( scalarmult_ristretto255, alpha, r, alpha );

	stop_measure();

	/* Send message */

#if MEASURE == MEASURE_ALL
	start_measure( "Connecting", false );
#endif

	const char      *ip = argc>4 ? argv[argc-2] : NULL ;
	const uint16_t port = argc>3 ? (uint16_t) atoi( argv[argc-1] ) : 9999 ;
	const int      sock = open_socket( ip, port );

	start_measure( "Exchanging messages #1" );

	SEND( sock, { sid,   sizeof(sid)   },
				{ ssid,  sizeof(ssid)  },
				{ X_u  , sizeof(X_u)   },
				{ alpha, sizeof(alpha) } );


	/* Receive incoming message */

	BYTE beta[crypto_core_ristretto255_BYTES];
	BYTE X_s[crypto_core_ristretto255_BYTES];
	struct
	{
		BYTE p_u[crypto_core_ristretto255_SCALARBYTES];
		BYTE P_u[crypto_core_ristretto255_BYTES];
		BYTE P_s[crypto_core_ristretto255_BYTES];
	} m;
	BYTE c[ crypto_secretbox_MACBYTES + sizeof(m) ];
	BYTE A_s[32];

	RECV( sock, { beta,  sizeof(beta)  },
				{ X_s,   sizeof(X_s)   },
				{ c,     sizeof(c)     },
				{ A_s,   sizeof(A_s)   } );

	start_measure( "Generating Key" );

	// rw = H( pwd || beta^(1/r) )
	SODIUM( core_ristretto255_is_valid_point, beta );
	SODIUM( core_ristretto255_scalar_invert, r, r );
	SODIUM( scalarmult_ristretto255, beta, r, beta );
	BYTE rw[crypto_secretbox_KEYBYTES];
	TAGGED_HASH( rw, 2, { password, pwd_len }, { beta, sizeof(beta) } );
	// TODO: should use pwhash instead?

	// p_u, P_u, P_s = AuthDec( rw, c )
	BYTE nonce[crypto_secretbox_NONCEBYTES] = {};
	SODIUM( secretbox_open_easy, (BYTE*) &m, c, sizeof(c), nonce, rw );

	// ssid' = H( sid || ssid || alpha )
	BYTE ssid_pr[crypto_hash_sha256_BYTES];
	TAGGED_HASH( ssid_pr, 3, { sid, sizeof(sid) }, { ssid, sizeof(ssid) }, { alpha, sizeof(alpha) } );

	// e_s = H( X_s || "U" || ssid' )
	// e_u = H( X_u || "S" || ssid' )
	BYTE hash[crypto_core_ristretto255_NONREDUCEDSCALARBYTES];
	BYTE e_s[crypto_core_ristretto255_SCALARBYTES], e_u[crypto_core_ristretto255_SCALARBYTES];
	TAGGED_HASH( hash, 4, { X_s, sizeof(X_s) }, { (const BYTE*) "U", 1 }, { ssid_pr, sizeof(ssid_pr) } );
	crypto_core_ristretto255_scalar_reduce( e_s, hash );
	TAGGED_HASH( hash, 4, { X_u, sizeof(X_u) }, { (const BYTE*) "S", 1 }, { ssid_pr, sizeof(ssid_pr) } );
	crypto_core_ristretto255_scalar_reduce( e_u, hash );

	// K = H( ( X_s * P_s ^ e_s ) ^ ( x_u + e_u * p_u ) )
	SODIUM( scalarmult_ristretto255, m.P_s, e_s, m.P_s );
	SODIUM( core_ristretto255_add, X_s, X_s, m.P_s );
	crypto_core_ristretto255_scalar_mul( e_u, e_u, m.p_u );
	crypto_core_ristretto255_scalar_add( x_u, x_u, e_u );

	SODIUM( scalarmult_ristretto255, X_s, x_u, X_s );
	BYTE K[crypto_stream_KEYBYTES];
	TAGGED_HASH( K, 5, { X_s, sizeof(X_s) } );

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

	start_measure( "Validating Key" );

	// Compare A_s
	if ( sodium_memcmp( A_s, out.A_s, sizeof(A_s) ) != 0 )
	{
		error( 1, 0, "Failed verifying A_s" );
	}


	start_measure( "Sending message #2" );

	SEND( sock, { out.A_u, sizeof(out.A_u) } );

	stop_measure();


	print_total( "Total", ONLINE | OFFLINE );
	print_total( "Total Online", ONLINE );

	printf("Shared key: ");
	print_bytes( out.SK, sizeof(out.SK) );


	close( sock );

	return 0;
}