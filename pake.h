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
#ifndef PAKE_H
#define PAKE_H

#include "utils.h"

#define PAKE_MSG_BYTES	crypto_core_ristretto255_BYTES
#define PAKE_KEY_BYTES	crypto_hash_sha256_BYTES

typedef struct
{
	bool is_first;
	size_t sid_size;
	const BYTE *sid;
	BYTE X[PAKE_MSG_BYTES];
	BYTE Y[PAKE_MSG_BYTES];
	BYTE g[crypto_core_ristretto255_BYTES];
	BYTE x[crypto_core_ristretto255_SCALARBYTES];
} PAKE;

void PAKE_NewSession( PAKE *ctx, bool is_first,
	const BYTE sid[], size_t sid_size,
	const BYTE pwd[], size_t pwd_size,
	const BYTE IDi[], size_t IDi_size,
	const BYTE IDj[], size_t IDj_size,
	const BYTE additional_data[], size_t additional_data_size );

static inline const BYTE *PAKE_GetOutBuffer( PAKE *ctx )
{
	return ctx->X;
}

static inline BYTE *PAKE_GetInBuffer( PAKE *ctx )
{
	return ctx->Y;
}

void PAKE_NewKey( PAKE *ctx, BYTE key[PAKE_KEY_BYTES] );

#endif