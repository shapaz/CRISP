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
#include "../utils.h"
#include "../pairing.h"

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

	const char *network = argv[1];
	size_t network_size = strlen( network );
	fwrite( network, 1, network_size+1, stdout );

	BYTE salt[crypto_hash_sha256_BYTES];
	TAGGED_HASH( salt, 1, { (const BYTE*) network, network_size } );
	static_assert( sizeof(salt) >= crypto_pwhash_SALTBYTES , "Hash output too short for salt" );

	const char *password = argv[2];
	const size_t pwd_len = strlen( password );
	BYTE pwd_hash[crypto_hash_sha256_BYTES];
	SODIUM( pwhash, pwd_hash, sizeof(pwd_hash), password, pwd_len, salt,
			crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE,
			crypto_pwhash_ALG_DEFAULT );

	const char *identity = argv[3];
	const size_t id_len = strlen( identity );
	if ( id_len > MAX_ID_BYTES )
	{
		error( 1, 0, "Identity length should be <= %d, but len(%s) = %lu", MAX_ID_BYTES, identity, id_len );
	}
	BYTE id[MAX_ID_BYTES];
	memcpy( id, identity, id_len );
	memset( id + id_len, '\0', MAX_ID_BYTES - id_len );
	BYTE id_hash[crypto_hash_sha256_BYTES];
	TAGGED_HASH( id_hash, 2, { (const BYTE*) network, network_size }, { id, MAX_ID_BYTES } );
	fwrite( id, 1, MAX_ID_BYTES, stdout );

	G2 g2;
	g2.set_generator();
	g2.serialize( stdout );

	Zr x;
	x.randomize();

	G2 A;
	A.pow( g2, x );
	A.serialize( stdout );

	G1 B;
	B.from_hash( pwd_hash, sizeof(pwd_hash) );
	B.pow( B, x );
	B.serialize( stdout );

	G1 C;
	C.from_hash( id_hash, sizeof(id_hash) );
	C.pow( C, x );
	C.serialize( stdout );

	return 0;
}