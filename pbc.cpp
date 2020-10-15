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
 // TODO: let the user decide pairing params?
static const char params[] = "type a\n\
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n\
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n\
r 730750818665451621361119245571504901405976559617\n\
exp2 159\n\
exp1 107\n\
sign1 1\n\
sign0 1\n";

struct Pairing
{
	pairing_t pairing;
	Pairing()
	{
		pairing_init_set_buf( pairing, (const char*) params, sizeof(params) );
		
		#if 0
		fprintf(stderr, "Zr: %d", pairing_length_in_bytes_Zr(pairing));
		fprintf(stderr, "G1: %d", pairing_length_in_bytes_compressed_G1(pairing));
		fprintf(stderr, "G2: %d", pairing_length_in_bytes_compressed_G2(pairing));
		fprintf(stderr, "GT: %d", pairing_length_in_bytes_GT(pairing));
		#endif
	}
	~Pairing()
	{
		pairing_clear( pairing );
	}
};
static Pairing pairing;


template <typename T>
T *unconstify( const T *pointer )
{
	return const_cast<T*>(pointer);
}

Zr::Zr()
{
	element_init_Zr( element, pairing.pairing );
}

Zr::~Zr()
{
	clear();
}

void Zr::clear()
{
	element_clear( element );
}

void Zr::randomize()
{
	element_random( element );
}


G1::G1()
{
	element_init_G1( element, pairing.pairing );
}

G1::~G1()
{
	element_clear( element );
}

size_t G1::serialize( BYTE (&buffer)[MAX_G1_BYTES] ) const
{
	return ELEMENT_TO_BYTES( buffer, unconstify(element) );
}

size_t G1::deserialize( const BYTE (&buffer)[MAX_G1_BYTES] )
{
	return ELEMENT_FROM_BYTES( element, unconstify(buffer) );
}

void G1::from_hash( const BYTE hash[], size_t size )
{
	element_from_hash( element, unconstify(hash), (int) size );
}

void G1::pow( const G1 &base, const Zr &exp )
{
	element_pow_zn( element, unconstify(base.element), unconstify(exp.element) );
}

void G1::serialize( FILE *output ) const
{
	BYTE buffer[MAX_G1_BYTES];
	fwrite_binary( output, buffer, serialize( buffer ) );
}


G2::G2()
{
	element_init_G2( element, pairing.pairing );
}

G2::~G2()
{
	element_clear( element );
}

void G2::set_generator()
{
	element_from_hash( element, NULL, 0 );
}

size_t G2::serialize( BYTE (&buffer)[MAX_G2_BYTES] ) const
{
	return ELEMENT_TO_BYTES( buffer, unconstify(element) );
}

size_t G2::deserialize( const BYTE (&buffer)[MAX_G2_BYTES] )
{
	return ELEMENT_FROM_BYTES( element, unconstify(buffer) );
}

void G2::pow( const G2 &base, const Zr &exp )
{
	element_pow_zn( element, unconstify(base.element), unconstify(exp.element) );
}

void G2::serialize( FILE *output ) const
{
	BYTE buffer[MAX_G2_BYTES];
	fwrite_binary( output, buffer, serialize( buffer ) );
}

bool G2::is1() const
{
	return element_is1( unconstify(element) );
}


GT::GT()
{
	element_init_GT( element, ::pairing.pairing );
}

GT::~GT()
{
	element_clear( element );
}

size_t GT::serialize( BYTE (&buffer)[MAX_GT_BYTES] ) const
{
	return element_to_bytes( buffer, unconstify(element) );
}

void GT::pairing( const G1 &g1, const G2 &g2 )
{
	pairing_apply( element, unconstify(g1.element), unconstify(g2.element), ::pairing.pairing );
}

bool GT::operator!=( const GT &other ) const
{
	return element_cmp( unconstify(element), unconstify(other.element) ) != 0;
}

void GT::serialize( FILE *output ) const
{
	BYTE buffer[MAX_GT_BYTES];
	fwrite_binary( output, buffer, serialize( buffer ) );
}
