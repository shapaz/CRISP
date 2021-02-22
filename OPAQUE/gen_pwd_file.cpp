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
	if ( argc != 4 )
	{
		fprintf( stderr, "Usage: %s <network> <password> <identity>\n", argv[0] );
		return 1;
	}

	if ( sodium_init() < 0 )
	{
		error( 1, 0, "sodium_init failed" );
	}

	const char *identity = argv[3];
	const size_t id_len = strlen( identity );
	if ( id_len > MAX_ID_BYTES )
	{
		error( 1, 0, "Identity length should be <= %d, but len(%s) = %lu", MAX_ID_BYTES, identity, id_len );
	}

	// k_s, p_s, p_u \genR Zq
	BYTE k_s[crypto_core_ristretto255_SCALARBYTES];
	BYTE p_s[crypto_core_ristretto255_SCALARBYTES];
	BYTE p_u[crypto_core_ristretto255_SCALARBYTES];
	crypto_core_ristretto255_scalar_random( k_s );
	crypto_core_ristretto255_scalar_random( p_s );
	crypto_core_ristretto255_scalar_random( p_u );
	fwrite( k_s, 1, sizeof(k_s), stdout );
	fwrite( p_s, 1, sizeof(p_s), stdout );

	// P_s = g^p_s, P_u = g^p_u
	BYTE P_s[crypto_core_ristretto255_BYTES];
	BYTE P_u[crypto_core_ristretto255_BYTES];
	SODIUM( scalarmult_ristretto255_base, P_s, p_s );
	SODIUM( scalarmult_ristretto255_base, P_u, p_u );
	fwrite( P_s, 1, sizeof(P_s), stdout );
	fwrite( P_u, 1, sizeof(P_u), stdout );

	// rw = H2( pwd || H1(pwd)^k_s )
	const BYTE *password = (const BYTE*) argv[2];
	const size_t pwd_len = strlen( (const char*) password );
	BYTE pwd_hash[64];
	TAGGED_HASH( pwd_hash, 1, { password, pwd_len } );
	BYTE T[crypto_core_ristretto255_BYTES];
	SODIUM( core_ristretto255_from_hash, T, pwd_hash );
	SODIUM( scalarmult_ristretto255, T, k_s, T );
	BYTE rw[crypto_secretbox_KEYBYTES];
	TAGGED_HASH( rw, 2, { password, pwd_len }, { T, sizeof(T) } );
	// TODO: should use pwhash instead?

	// c = AE( rw, p_u || P_u || P_s )
	BYTE m[ sizeof(p_u) + sizeof(P_u) + sizeof(P_s) ];
	memcpy( m,                         p_u, sizeof(p_u) );
	memcpy( m+sizeof(p_u),             P_u, sizeof(P_u) );
	memcpy( m+sizeof(p_u)+sizeof(P_u), P_s, sizeof(P_s) );
	BYTE nonce[crypto_secretbox_NONCEBYTES] = {};
	BYTE c[ crypto_secretbox_MACBYTES + sizeof(m) ];
	SODIUM( secretbox_easy, c, m, sizeof(m), nonce, rw );
	fwrite( c, 1, sizeof(c), stdout );

	return 0;
}