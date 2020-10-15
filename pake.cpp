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
/**
 * CPace implementation based on https://github.com/jedisct1/cpace
 */
#define PROTOCOL CPace-Ristretto255
#include "pake.h"

#define DSI1				( (const BYTE*) "CRISP-CPace-Ristretto255-1" )
#define DSI2				( (const BYTE*) "CRISP-CPace-Ristretto255-2" )
#define SHA512_BLOCK_SIZE	128

static const BYTE zpad[SHA512_BLOCK_SIZE] = {0};

void PAKE_NewSession( PAKE *ctx, bool is_first,
	const BYTE sid[], size_t sid_size,
	const BYTE pwd[], size_t pwd_size,
	const BYTE IDi[], size_t IDi_size,
	const BYTE IDj[], size_t IDj_size,
	const BYTE additional_data[], size_t additional_data_size )
{
	if ( IDi_size > UCHAR_MAX || IDj_size > UCHAR_MAX )
	{
		error( 1, 0, "ID should be at most %d bytes long", UCHAR_MAX );
	}

	ctx->is_first = is_first;
	ctx->sid = sid;
	ctx->sid_size = sid_size;

	// h = H( DSI1 || pwd || zpad || sid || len(A) || A || len(B) || B || additional_data )
	crypto_hash_sha512_state state;
	SODIUM( hash_sha512_init, &state );
	SODIUM( hash_sha512_update, &state, DSI(1), DSI_SIZE(1) );
	SODIUM( hash_sha512_update, &state, pwd, pwd_size );
	size_t zpad_size = ( sizeof(zpad) - ( DSI_SIZE(1) + pwd_size ) ) & ( sizeof(zpad) - 1u );
	SODIUM( hash_sha512_update, &state, zpad, zpad_size );
	SODIUM( hash_sha512_update, &state, sid, sid_size );

	BYTE size = (BYTE) ( is_first ? IDi_size : IDj_size );
	SODIUM( hash_sha512_update, &state, &size, 1 );
	SODIUM( hash_sha512_update, &state, is_first ? IDi : IDj, is_first ? IDi_size : IDj_size );
	
	size = (BYTE) ( is_first ? IDj_size : IDi_size );
	SODIUM( hash_sha512_update, &state, &size, 1 );
	SODIUM( hash_sha512_update, &state, is_first ? IDj : IDi, is_first ? IDj_size : IDi_size );
	
	SODIUM( hash_sha512_update, &state, additional_data, additional_data_size );
	static_assert( crypto_hash_sha512_BYTES >= crypto_core_ristretto255_HASHBYTES, "Hash output too short for hash2curve");
	BYTE hash[crypto_hash_sha512_BYTES];
	SODIUM( hash_sha512_final, &state, hash );

	// g = hash2curve(h)
	BYTE g[crypto_core_ristretto255_BYTES];
	SODIUM( core_ristretto255_from_hash, g, hash );

	// x = random()
	crypto_core_ristretto255_scalar_random( ctx->x );

	// X = g^x
	SODIUM( scalarmult_ristretto255, ctx->X, ctx->x, g );
}

void PAKE_NewKey( PAKE *ctx, BYTE key[PAKE_KEY_BYTES] )
{
	// K = Y^x
	BYTE K[crypto_core_ristretto255_BYTES];
	SODIUM( scalarmult_ristretto255, K, ctx->x, ctx->Y );

	// key = H( DSI2 || sid || K || X || Y )
	crypto_hash_sha256_state state;
	SODIUM( hash_sha256_init, &state );
	SODIUM( hash_sha256_update, &state, DSI(2), DSI_SIZE(2) );
	SODIUM( hash_sha256_update, &state, ctx->sid, ctx->sid_size );
	SODIUM( hash_sha256_update, &state, K, sizeof(K) );
	SODIUM( hash_sha256_update, &state, ctx->is_first ? ctx->X : ctx->Y, PAKE_MSG_BYTES );
	SODIUM( hash_sha256_update, &state, ctx->is_first ? ctx->Y : ctx->X, PAKE_MSG_BYTES );
	SODIUM( hash_sha256_final, &state, key );
}
