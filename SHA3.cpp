#include "crypto/SHA3.hpp"

#include <cstring>

#if defined(_MSC_VER) || defined(__WATCOMC__)
	#define UL64(x) x##ui64
#else
	#define UL64(x) x##ULL
#endif

#define GET_UINT64(n, b, i)                        \
{                                                  \
	(n) = ((uint64_t)(b)[(i)    ]      )       \
	    | ((uint64_t)(b)[(i) + 1] <<  8)       \
	    | ((uint64_t)(b)[(i) + 2] << 16)       \
	    | ((uint64_t)(b)[(i) + 3] << 24)       \
	    | ((uint64_t)(b)[(i) + 4] << 32)       \
	    | ((uint64_t)(b)[(i) + 5] << 40)       \
	    | ((uint64_t)(b)[(i) + 6] << 48)       \
	    | ((uint64_t)(b)[(i) + 7] << 56);      \
}

namespace Crypto
{

SHA3::SHA3(std::size_t digest_sz)
	: digest_sz(digest_sz), r(200 - 2 * digest_sz)
{
	// Assert that no overflow occures for r
	if ( 200 <= 2 * digest_sz ) {
		throw SHA3::Exception("Invalid digest length");
	}

	// Prerequesit for HMAC
	if ( r <= digest_sz ) {
		throw SHA3::Exception("Invalid digest length");
	}

	reset();
}

SHA3::~SHA3(void)
{
	reset();
}

void
SHA3::update(const uint8_t *input, std::size_t input_sz)
{
	std::size_t fill;

	if ( (NULL == input) || (0 == input_sz) ) {
		return;
	}

	while ( input_sz >= (fill = r - buffer_sz) ) {
		absorb(input, fill);
		keccakf(state);

		input     += fill;
		input_sz  -= fill;
		buffer_sz  = 0;
	}

	if ( input_sz > 0 ) {
		absorb(input, input_sz);
		buffer_sz += input_sz;
	}
}

void
SHA3::finish(uint8_t *output)
{
	uint8_t pad[200];
	std::size_t pad_sz = r - buffer_sz;

	memset(pad, 0x00, pad_sz);
	pad[0]           = 0x06;
	pad[pad_sz - 1] ^= 0x80;

	update(pad, pad_sz);

	memcpy(output, state, digest_sz);

	reset();
}

void
SHA3::reset(void)
{
	buffer_sz = 0;
	zeroize(state, sizeof(state));
}

void
SHA3::keccakf(uint64_t state[25])
{
	// TODO: optimization and zeroization
	uint64_t Aa, Ae, Ai, Ao, Au;
	uint64_t Ba, Be, Bi, Bo, Bu;
	uint64_t Ca, Ce, Ci, Co, Cu;
	uint64_t Da, De, Di, Do, Du;
	uint64_t Ea, Ee, Ei, Eo, Eu;
	uint64_t state_p[25];

	Aa = state[ 0]; Ae = state[ 5]; Ai = state[10]; Ao = state[15]; Au = state[20];
	Ba = state[ 1]; Be = state[ 6]; Bi = state[11]; Bo = state[16]; Bu = state[21];
	Ca = state[ 2]; Ce = state[ 7]; Ci = state[12]; Co = state[17]; Cu = state[22];
	Da = state[ 3]; De = state[ 8]; Di = state[13]; Do = state[18]; Du = state[23];
	Ea = state[ 4]; Ee = state[ 9]; Ei = state[14]; Eo = state[19]; Eu = state[24];

	for ( std::size_t r = 0 ; r < 24 ; ++r ) {
		// Theta
		uint64_t C[5], D;

		C[0] = Aa ^ Ae ^ Ai ^ Ao ^ Au;
		C[1] = Ba ^ Be ^ Bi ^ Bo ^ Bu;
		C[2] = Ca ^ Ce ^ Ci ^ Co ^ Cu;
		C[3] = Da ^ De ^ Di ^ Do ^ Du;
		C[4] = Ea ^ Ee ^ Ei ^ Eo ^ Eu;

		D = C[4] ^ ROL(C[1], 1);
		Aa ^= D;
		Ae ^= D;
		Ai ^= D;
		Ao ^= D;
		Au ^= D;
		D = C[0] ^ ROL(C[2], 1);
		Ba ^= D;
		Be ^= D;
		Bi ^= D;
		Bo ^= D;
		Bu ^= D;
		D = C[1] ^ ROL(C[3], 1);
		Ca ^= D;
		Ce ^= D;
		Ci ^= D;
		Co ^= D;
		Cu ^= D;
		D = C[2] ^ ROL(C[4], 1);
		Da ^= D;
		De ^= D;
		Di ^= D;
		Do ^= D;
		Du ^= D;
		D = C[3] ^ ROL(C[0], 1);
		Ea ^= D;
		Ee ^= D;
		Ei ^= D;
		Eo ^= D;
		Eu ^= D;

		// Rho and Pi
		state_p[ 0] = Aa;
		state_p[ 5] = ROL(Da, 28);
		state_p[10] = ROL(Ba,  1);
		state_p[15] = ROL(Ea, 27);
		state_p[20] = ROL(Ca, 62);
		state_p[ 1] = ROL(Be, 44);
		state_p[ 6] = ROL(Ee, 20);
		state_p[11] = ROL(Ce,  6);
		state_p[16] = ROL(Ae, 36);
		state_p[21] = ROL(De, 55);
		state_p[ 2] = ROL(Ci, 43);
		state_p[ 7] = ROL(Ai,  3);
		state_p[12] = ROL(Di, 25);
		state_p[17] = ROL(Bi, 10);
		state_p[22] = ROL(Ei, 39);
		state_p[ 3] = ROL(Do, 21);
		state_p[ 8] = ROL(Bo, 45);
		state_p[13] = ROL(Eo,  8);
		state_p[18] = ROL(Co, 15);
		state_p[23] = ROL(Ao, 41);
		state_p[ 4] = ROL(Eu, 14);
		state_p[ 9] = ROL(Cu, 61);
		state_p[14] = ROL(Au, 18);
		state_p[19] = ROL(Du, 56);
		state_p[24] = ROL(Bu,  2);


		// Chi
		Aa = state_p[ 0] ^ ((~state_p[ 1]) & state_p[ 2]);
		Ae = state_p[ 5] ^ ((~state_p[ 6]) & state_p[ 7]);
		Ai = state_p[10] ^ ((~state_p[11]) & state_p[12]);
		Ao = state_p[15] ^ ((~state_p[16]) & state_p[17]);
		Au = state_p[20] ^ ((~state_p[21]) & state_p[22]);

		Ba = state_p[ 1] ^ ((~state_p[ 2]) & state_p[ 3]);
		Be = state_p[ 6] ^ ((~state_p[ 7]) & state_p[ 8]);
		Bi = state_p[11] ^ ((~state_p[12]) & state_p[13]);
		Bo = state_p[16] ^ ((~state_p[17]) & state_p[18]);
		Bu = state_p[21] ^ ((~state_p[22]) & state_p[23]);

		Ca = state_p[ 2] ^ ((~state_p[ 3]) & state_p[ 4]);
		Ce = state_p[ 7] ^ ((~state_p[ 8]) & state_p[ 9]);
		Ci = state_p[12] ^ ((~state_p[13]) & state_p[14]);
		Co = state_p[17] ^ ((~state_p[18]) & state_p[19]);
		Cu = state_p[22] ^ ((~state_p[23]) & state_p[24]);

		Da = state_p[ 3] ^ ((~state_p[ 4]) & state_p[ 0]);
		De = state_p[ 8] ^ ((~state_p[ 9]) & state_p[ 5]);
		Di = state_p[13] ^ ((~state_p[14]) & state_p[10]);
		Do = state_p[18] ^ ((~state_p[19]) & state_p[15]);
		Du = state_p[23] ^ ((~state_p[24]) & state_p[20]);

		Ea = state_p[ 4] ^ ((~state_p[ 0]) & state_p[ 1]);
		Ee = state_p[ 9] ^ ((~state_p[ 5]) & state_p[ 6]);
		Ei = state_p[14] ^ ((~state_p[10]) & state_p[11]);
		Eo = state_p[19] ^ ((~state_p[15]) & state_p[16]);
		Eu = state_p[24] ^ ((~state_p[20]) & state_p[21]);

		// Iota
		Aa ^= RC[r];
	}

	state[ 0] = Aa; state[ 5] = Ae; state[10] = Ai; state[15] = Ao; state[20] = Au;
	state[ 1] = Ba; state[ 6] = Be; state[11] = Bi; state[16] = Bo; state[21] = Bu;
	state[ 2] = Ca; state[ 7] = Ce; state[12] = Ci; state[17] = Co; state[22] = Cu;
	state[ 3] = Da; state[ 8] = De; state[13] = Di; state[18] = Do; state[23] = Du;
	state[ 4] = Ea; state[ 9] = Ee; state[14] = Ei; state[19] = Eo; state[24] = Eu;

	/*
	// TODO: optimizations and check endianness
	uint64_t  Aba, Abe, Abi, Abo, Abu;
	uint64_t  Aga, Age, Agi, Ago, Agu;
	uint64_t  Aka, Ake, Aki, Ako, Aku;
	uint64_t  Ama, Ame, Ami, Amo, Amu;
	uint64_t  Asa, Ase, Asi, Aso, Asu;
	uint64_t  BCa, BCe, BCi, BCo, BCu;
	uint64_t  Da,  De,  Di,  Do,  Du;
	uint64_t  Eba, Ebe, Ebi, Ebo, Ebu;
	uint64_t  Ega, Ege, Egi, Ego, Egu;
	uint64_t  Eka, Eke, Eki, Eko, Eku;
	uint64_t  Ema, Eme, Emi, Emo, Emu;
	uint64_t  Esa, Ese, Esi, Eso, Esu;

	Aba =  state[ 0]; Abe =  state[ 1]; Abi =  state[ 2]; Abo =  state[ 3]; Abu =  state[ 4];
	Aga =  state[ 5]; Age =  state[ 6]; Agi =  state[ 7]; Ago =  state[ 8]; Agu =  state[ 9];
	Aka =  state[10]; Ake =  state[11]; Aki =  state[12]; Ako =  state[13]; Aku =  state[14];
	Ama =  state[15]; Ame =  state[16]; Ami =  state[17]; Amo =  state[18]; Amu =  state[19];
	Asa =  state[20]; Ase =  state[21]; Asi =  state[22]; Aso =  state[23]; Asu =  state[24];

	for ( std::size_t round = 0 ; round < 24 ; round += 2 ) {
		//    prepareTheta
		BCa = Aba^Aga^Aka^Ama^Asa;
		BCe = Abe^Age^Ake^Ame^Ase;
		BCi = Abi^Agi^Aki^Ami^Asi;
		BCo = Abo^Ago^Ako^Amo^Aso;
		BCu = Abu^Agu^Aku^Amu^Asu;

		//thetaRhoPiChiIotaPrepareTheta(round  , A, E)
		Da = BCu^ROL(BCe, 1);
		De = BCa^ROL(BCi, 1);
		Di = BCe^ROL(BCo, 1);
		Do = BCi^ROL(BCu, 1);
		Du = BCo^ROL(BCa, 1);

		Aba ^= Da;
		BCa = Aba;
		Age ^= De;
		BCe = ROL(Age, 44);
		Aki ^= Di;
		BCi = ROL(Aki, 43);
		Amo ^= Do;
		BCo = ROL(Amo, 21);
		Asu ^= Du;
		BCu = ROL(Asu, 14);
		Eba =   BCa ^((~BCe)&  BCi );
		Eba ^= (uint64_t)RC[round];
		Ebe =   BCe ^((~BCi)&  BCo );
		Ebi =   BCi ^((~BCo)&  BCu );
		Ebo =   BCo ^((~BCu)&  BCa );
		Ebu =   BCu ^((~BCa)&  BCe );

		Abo ^= Do;
		BCa = ROL(Abo, 28);
		Agu ^= Du;
		BCe = ROL(Agu, 20);
		Aka ^= Da;
		BCi = ROL(Aka,  3);
		Ame ^= De;
		BCo = ROL(Ame, 45);
		Asi ^= Di;
		BCu = ROL(Asi, 61);
		Ega =   BCa ^((~BCe)&  BCi );
		Ege =   BCe ^((~BCi)&  BCo );
		Egi =   BCi ^((~BCo)&  BCu );
		Ego =   BCo ^((~BCu)&  BCa );
		Egu =   BCu ^((~BCa)&  BCe );

		Abe ^= De;
		BCa = ROL(Abe,  1);
		Agi ^= Di;
		BCe = ROL(Agi,  6);
		Ako ^= Do;
		BCi = ROL(Ako, 25);
		Amu ^= Du;
		BCo = ROL(Amu,  8);
		Asa ^= Da;
		BCu = ROL(Asa, 18);
		Eka =   BCa ^((~BCe)&  BCi );
		Eke =   BCe ^((~BCi)&  BCo );
		Eki =   BCi ^((~BCo)&  BCu );
		Eko =   BCo ^((~BCu)&  BCa );
		Eku =   BCu ^((~BCa)&  BCe );

		Abu ^= Du;
		BCa = ROL(Abu, 27);
		Aga ^= Da;
		BCe = ROL(Aga, 36);
		Ake ^= De;
		BCi = ROL(Ake, 10);
		Ami ^= Di;
		BCo = ROL(Ami, 15);
		Aso ^= Do;
		BCu = ROL(Aso, 56);
		Ema =   BCa ^((~BCe)&  BCi );
		Eme =   BCe ^((~BCi)&  BCo );
		Emi =   BCi ^((~BCo)&  BCu );
		Emo =   BCo ^((~BCu)&  BCa );
		Emu =   BCu ^((~BCa)&  BCe );

		Abi ^= Di;
		BCa = ROL(Abi, 62);
		Ago ^= Do;
		BCe = ROL(Ago, 55);
		Aku ^= Du;
		BCi = ROL(Aku, 39);
		Ama ^= Da;
		BCo = ROL(Ama, 41);
		Ase ^= De;
		BCu = ROL(Ase,  2);
		Esa =   BCa ^((~BCe)&  BCi );
		Ese =   BCe ^((~BCi)&  BCo );
		Esi =   BCi ^((~BCo)&  BCu );
		Eso =   BCo ^((~BCu)&  BCa );
		Esu =   BCu ^((~BCa)&  BCe );

		//    prepareTheta
		BCa = Eba^Ega^Eka^Ema^Esa;
		BCe = Ebe^Ege^Eke^Eme^Ese;
		BCi = Ebi^Egi^Eki^Emi^Esi;
		BCo = Ebo^Ego^Eko^Emo^Eso;
		BCu = Ebu^Egu^Eku^Emu^Esu;

		//thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
		Da = BCu^ROL(BCe, 1);
		De = BCa^ROL(BCi, 1);
		Di = BCe^ROL(BCo, 1);
		Do = BCi^ROL(BCu, 1);
		Du = BCo^ROL(BCa, 1);

		Eba ^= Da;
		BCa = Eba;
		Ege ^= De;
		BCe = ROL(Ege, 44);
		Eki ^= Di;
		BCi = ROL(Eki, 43);
		Emo ^= Do;
		BCo = ROL(Emo, 21);
		Esu ^= Du;
		BCu = ROL(Esu, 14);
		Aba =   BCa ^((~BCe)&  BCi );
		Aba ^= RC[round+1];
		Abe =   BCe ^((~BCi)&  BCo );
		Abi =   BCi ^((~BCo)&  BCu );
		Abo =   BCo ^((~BCu)&  BCa );
		Abu =   BCu ^((~BCa)&  BCe );

		Ebo ^= Do;
		BCa = ROL(Ebo, 28);
		Egu ^= Du;
		BCe = ROL(Egu, 20);
		Eka ^= Da;
		BCi = ROL(Eka, 3);
		Eme ^= De;
		BCo = ROL(Eme, 45);
		Esi ^= Di;
		BCu = ROL(Esi, 61);
		Aga =   BCa ^((~BCe)&  BCi );
		Age =   BCe ^((~BCi)&  BCo );
		Agi =   BCi ^((~BCo)&  BCu );
		Ago =   BCo ^((~BCu)&  BCa );
		Agu =   BCu ^((~BCa)&  BCe );

		Ebe ^= De;
		BCa = ROL(Ebe, 1);
		Egi ^= Di;
		BCe = ROL(Egi, 6);
		Eko ^= Do;
		BCi = ROL(Eko, 25);
		Emu ^= Du;
		BCo = ROL(Emu, 8);
		Esa ^= Da;
		BCu = ROL(Esa, 18);
		Aka =   BCa ^((~BCe)&  BCi );
		Ake =   BCe ^((~BCi)&  BCo );
		Aki =   BCi ^((~BCo)&  BCu );
		Ako =   BCo ^((~BCu)&  BCa );
		Aku =   BCu ^((~BCa)&  BCe );

		Ebu ^= Du;
		BCa = ROL(Ebu, 27);
		Ega ^= Da;
		BCe = ROL(Ega, 36);
		Eke ^= De;
		BCi = ROL(Eke, 10);
		Emi ^= Di;
		BCo = ROL(Emi, 15);
		Eso ^= Do;
		BCu = ROL(Eso, 56);
		Ama =   BCa ^((~BCe)&  BCi );
		Ame =   BCe ^((~BCi)&  BCo );
		Ami =   BCi ^((~BCo)&  BCu );
		Amo =   BCo ^((~BCu)&  BCa );
		Amu =   BCu ^((~BCa)&  BCe );

		Ebi ^= Di;
		BCa = ROL(Ebi, 62);
		Ego ^= Do;
		BCe = ROL(Ego, 55);
		Eku ^= Du;
		BCi = ROL(Eku, 39);
		Ema ^= Da;
		BCo = ROL(Ema, 41);
		Ese ^= De;
		BCu = ROL(Ese, 2);
		Asa =   BCa ^((~BCe)&  BCi );
		Ase =   BCe ^((~BCi)&  BCo );
		Asi =   BCi ^((~BCo)&  BCu );
		Aso =   BCo ^((~BCu)&  BCa );
		Asu =   BCu ^((~BCa)&  BCe );
	}

	state[ 0] = Aba; state[ 1] = Abe; state[ 2] = Abi; state[ 3] = Abo; state[ 4] = Abu;
	state[ 5] = Aga; state[ 6] = Age; state[ 7] = Agi; state[ 8] = Ago; state[ 9] = Agu;
	state[10] = Aka; state[11] = Ake; state[12] = Aki; state[13] = Ako; state[14] = Aku;
	state[15] = Ama; state[16] = Ame; state[17] = Ami; state[18] = Amo; state[19] = Amu;
	state[20] = Asa; state[21] = Ase; state[22] = Asi; state[23] = Aso; state[24] = Asu;
	*/
}

void
SHA3::absorb(const uint8_t *mask, std::size_t mask_sz)
{
	// TODO: optimization and endianness
	//// TODO: rename
	//uint64_t val;
	//std::size_t tmp_buffer_sz;

	//// Align state buffer to 64 bits
	//while ( (buffer_sz % 8) > 0 ) {
	//	if ( 0 == mask_sz ) {
	//		break;
	//	}

	//	((uint8_t*)state)[buffer_sz] ^= mask[0]; // TODO: change for correct endianness

	//	mask      += 1;
	//	mask_sz   -= 1;
	//	buffer_sz += 1;
	//}

	//// Add mask directly to Keccak lanes
	//while ( mask_sz > 8 ) {
	//	GET_UINT64(val, mask, 0);

	//	state[buffer_sz / 8] ^= val;

	//	mask      += 8;
	//	mask_sz   -= 8;
	//	buffer_sz += 8;
	//}

	//// Fill with the remaining bytes
	//while ( mask_sz > 0 ) {
	//	((uint8_t*)state)[buffer_sz] ^= mask[0]; // TODO: change for correct endianness

	//	mask      += 1;
	//	mask_sz   -= 1;
	//	buffer_sz += 1;
	//}	

	// TODO: optimization and check endianness
	uint8_t *s = ((uint8_t*)state) + buffer_sz;

	// Works only because little endian architecture
	for ( std::size_t i = 0 ; i < mask_sz ; ++i ) {
		s[i] ^= mask[i];
	}
}

uint64_t
SHA3::ROL(uint64_t x, std::size_t n)
{
	return (x << n) | (x >> (64 - n));
}

const uint64_t SHA3::RC[24] = {
	UL64(0x0000000000000001), UL64(0x0000000000008082), UL64(0x800000000000808a),
	UL64(0x8000000080008000), UL64(0x000000000000808b), UL64(0x0000000080000001),
	UL64(0x8000000080008081), UL64(0x8000000000008009), UL64(0x000000000000008a),
	UL64(0x0000000000000088), UL64(0x0000000080008009), UL64(0x000000008000000a),
	UL64(0x000000008000808b), UL64(0x800000000000008b), UL64(0x8000000000008089),
	UL64(0x8000000000008003), UL64(0x8000000000008002), UL64(0x8000000000000080),
	UL64(0x000000000000800a), UL64(0x800000008000000a), UL64(0x8000000080008081),
	UL64(0x8000000000008080), UL64(0x0000000080000001), UL64(0x8000000080008008)
};

}
