/*
 * YaoEvaluator.cpp
 *
 */

#include "YaoEvaluator.h"

#include "GC/Machine.hpp"
#include "GC/Program.hpp"
#include "GC/Processor.hpp"
#include "GC/Secret.hpp"
#include "GC/Thread.hpp"
#include "GC/ThreadMaster.hpp"
#include "Tools/MMO.hpp"
#include "YaoWire.hpp"

#include "Tools/random.h"
#include <emmintrin.h> 

//#include "P256Element.h"
#include "Tools/Bundle.h"

//#include "preprocessing.hpp"
#include "Math/gfp.hpp"

#include <chrono>
#include <thread>


thread_local YaoEvaluator* YaoEvaluator::singleton = 0;

YaoEvaluator::YaoEvaluator(int thread_num, YaoEvalMaster& master) :
		Thread<GC::Secret<YaoEvalWire>>(thread_num, master),
		YaoCommon<YaoEvalWire>(master),
		master(master),
		player(N, 0, "thread" + to_string(thread_num)),
		ot_ext(OTExtensionWithMatrix::setup(player, {}, RECEIVER, true))
{
	set_n_program_threads(master.machine.nthreads);
	this->init(*this);
}

void YaoEvaluator::pre_run()
{
	if (master.opts.cmd_private_output_file.empty())
		processor.out.activate(not continuous());
	if (not continuous())
		receive_to_store(*P);
}

void YaoEvaluator::run(GC::Program& program)
{
	singleton = this;

	if (continuous())
		run(program, *P);
	else
	{
		run_from_store(program);
	}
}

void YaoEvaluator::run(GC::Program& program, Player& P)
{
	PRNG G;
	G.ReSeed();

//	int i,j;

	// (t,n) parameters in PPSS
	int t = 2;
	int n = 3;

	//store horizontal coordinates of points, points[0] = 0. 
	int points[n + 1];

	//store vertical coordinates of points, i.e., n shares. shares[0]=secret, s_i in PPSS
	__m128i shares[n + 1];

	//coefficients of the polynomial
	__m128i coef[t + 1];

	// secret s in PPSS.
	__m128i secret;

	// inpts and outputs from GC.
	__m128i GCout[ n + 1];
	__m128i GCin[ n + 1];
	__m128i pw;

	// rou_i in PPSS, 256 = 32 bytes.
	unsigned char oprf_256[32];
	__m128i oprf_128[n + 1];

	// parses H′(s) as [r||K].
	unsigned char H_s[32];
	unsigned char r[16];
	unsigned char K[16];

	// e_i in PPSS, e_i = s_i XOR rou_i
	__m128i e[n + 1];

	//Commitment C := COM((pw, e, s); r)
	unsigned char comout[32];
	unsigned char comin[ 16 * 2 + 16 * 2 * n];

	unsigned char bytes1[16];
	unsigned char bytes2[16];
	unsigned char bytes3[16];
//	unsigned char bytes4[16];	
	unsigned char combinedBytes[32];

//  User completes the Init and then sends (e, C) to every server
	octetStream Initfinalize;
	unsigned char Init_pack[ 16 * n + 32 ];
	

	//begin 
	auto next = GC::TIME_BREAK;
	printf("Evaluator is ready to secret sharing.\n");

	// Pick a random 128-bit s, s <-> ( -1, s )
	secret = G.get_doubleword();

	//default point secret (0, secret), n shares (1, s1), ..., (n, sn).
	points[0] = 0;
	for (int j = 0; j < n; j++)
        points[j + 1] = j + 1;

	// secret = k0;
	coef[0] = secret;
	// Pick random 128-bit coefficients k_1,...,k_t. Degree t.
	for (int j = 0; j < t; j++){
        coef[j + 1] = G.get_doubleword();
	}
	
	// Compute shares. s_0 = secret, s_1, s_2,...,s_n
	for (int j = 0; j < n + 1; j++){
		shares[j] = _mm_setzero_si128();
	}

	shares[0] = secret;
	for (int j = 1; j < n + 1; j++){
		for (int i = 0; i < t + 1; i++){
			    shares[j] += coef[i] * (points[j]^i);
		}
	}
	
	printf("secret sharing is done.\n");
	do
	{
		receive(P);
		try
		{
			next = program.execute(processor, master.memory, -1);
		}
		catch (needs_cleaning& e)
		{
		}
	}
	while(GC::DONE_BREAK != next);
	 printf("GC is done.\n");

  // std::this_thread::sleep_for(std::chrono::seconds(1));

	// Get GCout and GCin from GC.
	GCout[0] = _mm_setzero_si128();
	for (int j = 0; j < n; j++)
        GCout[j + 1] = G.get_doubleword();

	GCin[0] = _mm_setzero_si128();
	pw = G.get_doubleword();
	for (int j = 0; j < n; j++)
        GCin[j + 1] = pw;


	//Compute OPRF. rou_1, ..., rou_n.
	for (int j = 0; j < n; j++){
		_mm_storeu_si128(reinterpret_cast<__m128i*>(bytes1), GCin[j+1]);
		_mm_storeu_si128(reinterpret_cast<__m128i*>(bytes2), GCout[j+1]);

		for (int i = 0; i < 16; i++) {
			combinedBytes[i] = bytes1[i];
			combinedBytes[i + 16] = bytes2[i];
		}
			
		// int crypto_hash_sha256(unsigned char *out, const unsigned char *in,
    	//                    unsigned long long inlen) __attribute__ ((nonnull(1)));


		// rou_1 = oprf_128[1],..., rou_n = oprf_128[n] 
		crypto_hash_sha256(oprf_256, combinedBytes, 32);
		oprf_128[j + 1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(oprf_256));
		
		// compute e1, ..., en in PPSS, e_i = s_i XOR rou_i
		e[j + 1] = _mm_xor_si128(shares[j + 1], oprf_128[j + 1]);
	}

	// set useless redundance things.
	oprf_128[0] = _mm_setzero_si128();
	e[0] = _mm_setzero_si128();

	//  parses H′(s) as [r||K]
	_mm_storeu_si128(reinterpret_cast<__m128i*>(bytes1), secret);
	crypto_hash_sha256(H_s, bytes1, 16);

	for (int i = 0; i < 16; i++) {
		r[i] = H_s[i];
		K[i] = H_s[i + 16];
	}

	// Compute C := COM((pw, e, s); r)
	// comout = Sha256 (pw, e1,...,en, shares1,...,sharesn, r)

	// copy pw
	_mm_storeu_si128(reinterpret_cast<__m128i*>(bytes1), pw);
	for (int i = 0; i < 16; i++) {
		comin[i] = bytes1[i];
	}
	// copy e1,...en
	for (int j = 0; j < n; j++){
		_mm_storeu_si128(reinterpret_cast<__m128i*>(bytes2), e[j+1]);
			for (int i = 0; i < 16; i++) {
				comin[16 + j * 16 + i] = bytes2[i];
			}
	}
	// copy s1,..,sn
	for (int j = 0; j < n; j++){
		_mm_storeu_si128(reinterpret_cast<__m128i*>(bytes3), shares[j+1]);
			for (int i = 0; i < 16; i++) {
				comin[16 + 16 * n + j * 16 + i] = bytes3[i];
			}
	}
	// copy r
	for (int i = 0; i < 16; i++) {
		comin[16 + 16 * n * 2 + i] = r[i];
	}
	
	crypto_hash_sha256(comout, comin,  16 * 2 + 16 * 2 * n);

	printf("INIT of PPSS, Clients Done. \n");

	//sends (e1, ..., en , C) to server
	//copy (e1, ..., en) to Init_pack
	for (int j = 0; j < n; j++){
	_mm_storeu_si128(reinterpret_cast<__m128i*>(bytes2), e[j+1]);
		for (int i = 0; i < 16; i++) {
			Init_pack[j * 16 + i] = bytes2[i];
		}
	}
	//copy comout to Init_pack
	for (int i = 0; i < 32; i++) {
		Init_pack[ 16 * n + i] = comout[i];
	}
	Initfinalize.store_bytes(Init_pack, sizeof(Init_pack));
	P.send_to(0, Initfinalize);
	printf("Clients has sent (e1, ..., en, C) to server.\n");

}

void YaoEvaluator::run_from_store(GC::Program& program)
{
	machine.reset_timer();
	do
	{
		gates_store.pop(gates);
		output_masks_store.pop(output_masks);
	}
	while(GC::DONE_BREAK != program.execute(processor, master.memory, -1));
}

bool YaoEvaluator::receive(Player& P)
{
#ifdef DEBUG_YAO
	printf("waiting to receive at %d in thread %d\n", processor.PC, thread_num);
#endif
		//Passed Point
		// printf("This is an Evaluator (Passed).\n");
	if (P.receive_long(0) == YaoCommon::DONE)
		return false;
	P.receive_player(0, gates);
	P.receive_player(0, output_masks);
#ifdef DEBUG_YAO
	cout << "received " << gates.size() << " bytes for gates and "
			<< output_masks.size() << " output masks at " << processor.PC
			<< " in thread " << thread_num << endl;
#endif
	return true;
}

void YaoEvaluator::receive_to_store(Player& P)
{
	while (receive(P))
	{
		gates_store.push(gates);
		output_masks_store.push(output_masks);
	}
}
