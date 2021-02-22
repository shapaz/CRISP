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
#define PROTOCOL CRISP
#include "../utils.h"
#include "../pake.h"
#include "../pairing.h"

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

	alloc_init();

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

	G2 g2;
	pwd_file += g2.deserialize( *(BYTE (*)[MAX_G2_BYTES]) pwd_file );

	G2 Ai;
	pwd_file += Ai.deserialize( *(BYTE (*)[MAX_G2_BYTES]) pwd_file );

	G1 Bi;
	pwd_file += Bi.deserialize( *(BYTE (*)[MAX_G1_BYTES]) pwd_file );

	G1 Ci;
	pwd_file += Ci.deserialize( *(BYTE (*)[MAX_G1_BYTES]) pwd_file );


	/* Build outgoing message */
	start_measure( "Blinding", false );

	Zr r;
	r.randomize();

	Ai.pow( Ai, r );
	BYTE Ai_buf[MAX_G2_BYTES];
	Ai.serialize( Ai_buf );

	Bi.pow( Bi, r );

	Ci.pow( Ci, r );
	BYTE Ci_buf[MAX_G1_BYTES];
	Ci.serialize( Ci_buf );

	stop_measure();

	r.clear();


	/* Send message */

#if MEASURE == MEASURE_ALL
	start_measure( "Connecting", false );
#endif

	const char      *ip = argc>3 ? argv[argc-2] : NULL ;
	const uint16_t port = argc>2 ? (uint16_t) atoi( argv[argc-1] ) : 9999 ;
	const int      sock = open_socket( ip, port );

	start_measure( "Exchanging messages" );

	SEND( sock, { IDi   , MAX_ID_BYTES },
				{ Ai_buf, MAX_G2_BYTES },
				{ Ci_buf, MAX_G1_BYTES } );


	/* Receive incoming message */

	BYTE IDj[MAX_ID_BYTES + 1];
	BYTE Aj_buf[MAX_G2_BYTES];
	BYTE Cj_buf[MAX_G1_BYTES];
	IDj[MAX_ID_BYTES] = '\0';

	RECV( sock, { IDj   , MAX_ID_BYTES },
				{ Aj_buf, MAX_G2_BYTES },
				{ Cj_buf, MAX_G1_BYTES } );

	start_measure( "Parsing incoming message" );

	G2 Aj;
	Aj.deserialize( Aj_buf );

	G1 Cj;
	Cj.deserialize( Cj_buf );


	/* Compute shared secret */

	start_measure( "Computing shared secret" );

	GT t;
	t.pairing( Bi, Aj );

	bool is_first = memcmp( Ai_buf, Aj_buf, sizeof(Ai_buf) ) >= 0;

	BYTE t_buf[MAX_GT_BYTES];
	BYTE S[crypto_hash_sha256_BYTES];
	TAGGED_HASH( S, 4, { t_buf, t.serialize( t_buf ) },
					   { is_first ? IDi    : IDj   , MAX_ID_BYTES   },
					   { is_first ? Ai_buf : Aj_buf, sizeof(Ai_buf) },
					   { is_first ? Ci_buf : Cj_buf, sizeof(Ci_buf) },
					   { is_first ? IDj    : IDi   , MAX_ID_BYTES   },
					   { is_first ? Aj_buf : Ai_buf, sizeof(Aj_buf) },
					   { is_first ? Cj_buf : Ci_buf, sizeof(Cj_buf) } );

	stop_measure();

#if 0
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


	/* Check Aj while waiting for PAKE response */

	start_measure( "Verifying identity" );

	// TODO: this doesn't prevent [0,0] for some reason...
	if ( Aj.is1() )
	{
		error( 1, 0, "Aj == [0]_G2" );
	}

	G1 Hj;
	BYTE IDj_hash[crypto_hash_sha256_BYTES];
	TAGGED_HASH( IDj_hash, 2, { IDj, MAX_ID_BYTES } );
	Hj.from_hash( IDj_hash, sizeof(IDj_hash) );

	GT t1, t2;
	t1.pairing( Cj, g2 );
	t2.pairing( Hj, Aj );
	if ( t1 != t2 )
	{
		error( 1, 0, "e(Cj,g2) != e(H(IDj),Aj)");
	}

	stop_measure();

	printf( "Identified: %s\n", IDj );


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
	delete[] orig_file;

	return 0;
}