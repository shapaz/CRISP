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
struct Pairing
{
	Pairing()
	{
		if ( mclBn_init( MCL_BN254, MCLBN_COMPILED_TIME_VAR ) != 0 )
		{
			error( 1, 0, "MCL initialization failed" );
		}

		#if 0	// TODO
		mclBn_verifyOrderG1(true);
		mclBn_verifyOrderG2(true);
		#endif
	}
};
static Pairing pairing;


Zr::Zr()
{
}

Zr::~Zr()
{
	clear();
}

void Zr::clear()
{
	mclBnFr_clear( &element );
}

void Zr::randomize()
{
	mclBnFr_setByCSPRNG( &element );
}


G1::G1()
{
}

G1::~G1()
{
	mclBnG1_clear( &element );
}

size_t G1::serialize( BYTE (&buffer)[MAX_G1_BYTES] ) const
{
	return mclBnG1_serialize( buffer, sizeof(buffer), &element );
}

size_t G1::deserialize( const BYTE (&buffer)[MAX_G1_BYTES] )
{
	size_t size = mclBnG1_deserialize( &element, buffer, sizeof(buffer) );
	if ( ! mclBnG1_isValid( &element ) )
	{
		error( 1, 0, "Invalid G1 element" );
	}
	return size;
}

void G1::from_hash( const BYTE hash[], size_t size )
{
	mclBnFp fp;
	mclBnFp_setLittleEndian( &fp, hash, size );
	mclBnFp_mapToG1( &element, &fp );
}

void G1::pow( const G1 &base, const Zr &exp )
{
	mclBnG1_mul( &element, &base.element, &exp.element );
}

void G1::serialize( FILE *output ) const
{
	BYTE buffer[MAX_G1_BYTES];
	fwrite_binary( output, buffer, serialize( buffer ) );
}


G2::G2()
{
}

G2::~G2()
{
	mclBnG2_clear( &element );
}

void G2::set_generator()
{
	static const char g2_generator[] = "1"
		" 12723517038133731887338407189719511622662176727675373276651903807414909099441"
        " 4168783608814932154536427934509895782246573715297911553964171371032945126671"
        " 13891744915211034074451795021214165905772212241412891944830863846330766296736"
        " 7937318970632701341203597196594272556916396164729705624521405069090520231616";
	mclBnG2_setStr( &element, g2_generator, sizeof(g2_generator)-1, 10 );
	if ( ! mclBnG2_isValid( &element ) )
	{
		error( 1, 0, "Invalid G2 element" );
	}
}

size_t G2::serialize( BYTE (&buffer)[MAX_G2_BYTES] ) const
{
	return mclBnG2_serialize( buffer, sizeof(buffer), &element );
}

size_t G2::deserialize( const BYTE (&buffer)[MAX_G2_BYTES] )
{
	size_t size = mclBnG2_deserialize( &element, buffer, sizeof(buffer) );
	if ( ! mclBnG2_isValid( &element ) )
	{
		error( 1, 0, "Invalid G2 element" );
	}
	return size;
}

void G2::pow( const G2 &base, const Zr &exp )
{
	mclBnG2_mul( &element, &base.element, &exp.element );
}

void G2::serialize( FILE *output ) const
{
	BYTE buffer[MAX_G2_BYTES];
	fwrite_binary( output, buffer, serialize( buffer ) );
}

bool G2::is1() const
{
	return mclBnG2_isZero( &element );
}


GT::GT()
{
}

GT::~GT()
{
	mclBnGT_clear( &element );
}

size_t GT::serialize( BYTE (&buffer)[MAX_GT_BYTES] ) const
{
	return mclBnGT_serialize( buffer, sizeof(buffer), &element );
}

void GT::pairing( const G1 &g1, const G2 &g2 )
{
	mclBn_pairing( &element, &g1.element, &g2.element );
}

bool GT::operator!=( const GT &other ) const
{
	return ! mclBnGT_isEqual( &element, &other.element );
}

void GT::serialize( FILE *output ) const
{
	BYTE buffer[MAX_GT_BYTES];
	fwrite_binary( output, buffer, serialize( buffer ) );
}
