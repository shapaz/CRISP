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
#ifndef PAIRING_H
#define PAIRING_H

#include "utils.h"

#define PBC		1
#define MCL		2

#ifndef USE_COMPRESSION
#define USE_COMPRESSION 			0
#endif

#if PAIRING_LIB == PBC

#include <pbc/pbc.h>

#define MAX_Zr_BYTES				20
/* Zr elements aren't points and cannot be compressed */

#define MAX_G1_BYTES_UNCOMPRESSED	128
#define MAX_G1_BYTES_COMPRESSED		65

#define MAX_G2_BYTES_UNCOMPRESSED	128
#define MAX_G2_BYTES_COMPRESSED		65

#define MAX_GT_BYTES				128
/* GT elements aren't points and cannot be compressed */

#if USE_COMPRESSION
#define ELEMENT_FROM_BYTES			element_from_bytes_compressed
#define ELEMENT_TO_BYTES			element_to_bytes_compressed
#define MAX_G1_BYTES				MAX_G1_BYTES_COMPRESSED
#define MAX_G2_BYTES				MAX_G2_BYTES_COMPRESSED
#else
#define ELEMENT_FROM_BYTES			element_from_bytes
#define ELEMENT_TO_BYTES			element_to_bytes
#define MAX_G1_BYTES				MAX_G1_BYTES_UNCOMPRESSED
#define MAX_G2_BYTES				MAX_G2_BYTES_UNCOMPRESSED
#endif

typedef element_t Zr_t;
typedef element_t G1_t;
typedef element_t G2_t;
typedef element_t GT_t;

#elif PAIRING_LIB == MCL


#define C_BN254		254
#define C_BLS12_381	12381

#if CURVE == C_BN254
#include <mcl/bn_c256.h>
#elif CURVE == C_BLS12_381
#include <mcl/bn_c384_256.h>
#else
#error CURVE not supported
#endif

#define MAX_Zr_BYTES				( MCLBN_FR_UNIT_SIZE * 8 )
#define MAX_G1_BYTES				( MCLBN_FP_UNIT_SIZE * 8 )
#define MAX_G2_BYTES				( MAX_G1_BYTES * 2 )
#define MAX_GT_BYTES				( MAX_G1_BYTES * 12 )

typedef mclBnFr Zr_t;
typedef mclBnG1 G1_t;
typedef mclBnG2 G2_t;
typedef mclBnGT GT_t;

#else
#error Please specify PAIRING_LIB 
#endif

class Zr
{
	friend class G1;
	friend class G2;
	Zr_t element;
public:
	Zr();
	~Zr();
	void clear();
	void randomize();
};

class G1
{
	friend class GT;
	G1_t element;
public:
	G1();
	~G1();
	void serialize( FILE *output ) const;
	size_t serialize( BYTE (&buffer)[MAX_G1_BYTES] ) const;
	size_t deserialize( const BYTE (&buffer)[MAX_G1_BYTES] );
	void from_hash( const BYTE hash[], size_t size );
	void pow( const G1 &base, const Zr &exp );
};

class G2
{
	friend class GT;
	G2_t element;
public:
	G2();
	~G2();
	void serialize( FILE *output ) const;
	size_t serialize( BYTE (&buffer)[MAX_G2_BYTES] ) const;
	size_t deserialize( const BYTE (&buffer)[MAX_G2_BYTES] );
	void set_generator();
	void pow( const G2 &base, const Zr &exp );
	bool is1() const;
};

class GT
{
	GT_t element;
public:
	GT();
	~GT();
	void serialize( FILE *output ) const;
	size_t serialize( BYTE (&buffer)[MAX_GT_BYTES] ) const;
	void pairing( const G1 &g1, const G2 &g2 );
	bool operator!=( const GT &other ) const;
};


#endif