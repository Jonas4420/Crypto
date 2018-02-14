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
		buffer_sz = 0;

		input     += fill;
		input_sz  -= fill;
	}

	if ( input_sz > 0 ) {
		absorb(input, input_sz);
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
SHA3::keccakf(uint64_t S[25])
{
	uint64_t Aba, Abe, Abi, Abo, Abu;
	uint64_t Aga, Age, Agi, Ago, Agu;
	uint64_t Aka, Ake, Aki, Ako, Aku;
	uint64_t Ama, Ame, Ami, Amo, Amu;
	uint64_t Asa, Ase, Asi, Aso, Asu;
	uint64_t BCa, BCe, BCi, BCo, BCu;
	uint64_t Da,  De,  Di,  Do,  Du;
	uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
	uint64_t Ega, Ege, Egi, Ego, Egu;
	uint64_t Eka, Eke, Eki, Eko, Eku;
	uint64_t Ema, Eme, Emi, Emo, Emu;
	uint64_t Esa, Ese, Esi, Eso, Esu;

	Aba = S[ 0]; Abe = S[ 5]; Abi = S[10]; Abo = S[15]; Abu = S[20];
	Aga = S[ 1]; Age = S[ 6]; Agi = S[11]; Ago = S[16]; Agu = S[21];
	Aka = S[ 2]; Ake = S[ 7]; Aki = S[12]; Ako = S[17]; Aku = S[22];
	Ama = S[ 3]; Ame = S[ 8]; Ami = S[13]; Amo = S[18]; Amu = S[23];
	Asa = S[ 4]; Ase = S[ 9]; Asi = S[14]; Aso = S[19]; Asu = S[24];

	for ( std::size_t r = 0 ; r < 24 ; ++r ) {
		// Theta
		BCa = Aba ^ Abe ^ Abi ^ Abo ^ Abu;
		BCe = Aga ^ Age ^ Agi ^ Ago ^ Agu;
		BCi = Aka ^ Ake ^ Aki ^ Ako ^ Aku;
		BCo = Ama ^ Ame ^ Ami ^ Amo ^ Amu;
		BCu = Asa ^ Ase ^ Asi ^ Aso ^ Asu;

		Da = BCu ^ ROL(BCe, 1);
		Aba ^= Da; Abe ^= Da; Abi ^= Da; Abo ^= Da; Abu ^= Da;
		De = BCa ^ ROL(BCi, 1);
		Aga ^= De; Age ^= De; Agi ^= De; Ago ^= De; Agu ^= De;
		Di = BCe ^ ROL(BCo, 1);
		Aka ^= Di; Ake ^= Di; Aki ^= Di; Ako ^= Di; Aku ^= Di;
		Do = BCi ^ ROL(BCu, 1);
		Ama ^= Do; Ame ^= Do; Ami ^= Do; Amo ^= Do; Amu ^= Do;
		Du = BCo ^ ROL(BCa, 1);
		Asa ^= Du; Ase ^= Du; Asi ^= Du; Aso ^= Du; Asu ^= Du;

		// Rho and Pi
		Eba = Aba;          Ebe = ROL(Ama, 28); Ebi = ROL(Aga,  1);
		Ebo = ROL(Asa, 27); Ebu = ROL(Aka, 62);

		Ega = ROL(Age, 44); Ege = ROL(Ase, 20); Egi = ROL(Ake,  6);
		Ego = ROL(Abe, 36); Egu = ROL(Ame, 55);

		Eka = ROL(Aki, 43); Eke = ROL(Abi,  3); Eki = ROL(Ami, 25);
		Eko = ROL(Agi, 10); Eku = ROL(Asi, 39);

		Ema = ROL(Amo, 21); Eme = ROL(Ago, 45); Emi = ROL(Aso,  8);
		Emo = ROL(Ako, 15); Emu = ROL(Abo, 41);

		Esa = ROL(Asu, 14); Ese = ROL(Aku, 61); Esi = ROL(Abu, 18);
		Eso = ROL(Amu, 56); Esu = ROL(Agu,  2);

		// Chi
		Aba = Eba ^ ((~Ega) & Eka); Abe = Ebe ^ ((~Ege) & Eke); Abi = Ebi ^ ((~Egi) & Eki);
		Abo = Ebo ^ ((~Ego) & Eko); Abu = Ebu ^ ((~Egu) & Eku);

		Aga = Ega ^ ((~Eka) & Ema); Age = Ege ^ ((~Eke) & Eme); Agi = Egi ^ ((~Eki) & Emi);
		Ago = Ego ^ ((~Eko) & Emo); Agu = Egu ^ ((~Eku) & Emu);

		Aka = Eka ^ ((~Ema) & Esa); Ake = Eke ^ ((~Eme) & Ese); Aki = Eki ^ ((~Emi) & Esi);
		Ako = Eko ^ ((~Emo) & Eso); Aku = Eku ^ ((~Emu) & Esu);

		Ama = Ema ^ ((~Esa) & Eba); Ame = Eme ^ ((~Ese) & Ebe); Ami = Emi ^ ((~Esi) & Ebi);
		Amo = Emo ^ ((~Eso) & Ebo); Amu = Emu ^ ((~Esu) & Ebu);

		Asa = Esa ^ ((~Eba) & Ega); Ase = Ese ^ ((~Ebe) & Ege); Asi = Esi ^ ((~Ebi) & Egi);
		Aso = Eso ^ ((~Ebo) & Ego); Asu = Esu ^ ((~Ebu) & Egu);

		// Iota
		Aba ^= RC[r];
	}

	S[ 0] = Aba; S[ 5] = Abe; S[10] = Abi; S[15] = Abo; S[20] = Abu;
	S[ 1] = Aga; S[ 6] = Age; S[11] = Agi; S[16] = Ago; S[21] = Agu;
	S[ 2] = Aka; S[ 7] = Ake; S[12] = Aki; S[17] = Ako; S[22] = Aku;
	S[ 3] = Ama; S[ 8] = Ame; S[13] = Ami; S[18] = Amo; S[23] = Amu;
	S[ 4] = Asa; S[ 9] = Ase; S[14] = Asi; S[19] = Aso; S[24] = Asu;
}

void
SHA3::absorb(const uint8_t *mask, std::size_t mask_sz)
{
	uint64_t dword;

	// Align buffer_sz on 64 bits
	while ( (0 != (buffer_sz % 8)) && (mask_sz > 0) ) {
		dword = ((uint64_t)mask[0]) << (8 * (buffer_sz % 8));

		state[buffer_sz / 8] ^= dword;

		mask      += 1;
		mask_sz   -= 1;
		buffer_sz += 1;
	}

	// Absorb 64 bits of mask at a time
	while ( mask_sz >= 8 ) {
		GET_UINT64(dword, mask, 0);

		state[buffer_sz / 8] ^= dword;

		mask      += 8;
		mask_sz   -= 8;
		buffer_sz += 8;
	}

	// Process remaining bits of mask
	while ( mask_sz > 0 ) {
		dword = ((uint64_t)mask[0]) << (8 * (buffer_sz % 8));

		state[buffer_sz / 8] ^= dword;

		mask      += 1;
		mask_sz   -= 1;
		buffer_sz += 1;
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
