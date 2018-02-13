#include "crypto/SHA256.hpp"

#include <cstring>

#define GET_UINT32(n,b,i)                       \
do {                                            \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )     \
        | ( (uint32_t) (b)[(i) + 1] << 16 )     \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )     \
        | ( (uint32_t) (b)[(i) + 3]       );    \
} while( 0 )

#define PUT_UINT32(n,b,i)                       \
do {                                            \
	(b)[(i)    ] = (uint8_t) ( (n) >> 24 ); \
	(b)[(i) + 1] = (uint8_t) ( (n) >> 16 ); \
	(b)[(i) + 2] = (uint8_t) ( (n) >>  8 ); \
	(b)[(i) + 3] = (uint8_t) ( (n)       ); \
} while( 0 )

#define  SHR(x,n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))

#define S0(x) (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
#define S1(x) (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))

#define S2(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define R(t)                                    \
(                                               \
    W[t] = S1(W[t -  2]) + W[t -  7] +          \
           S0(W[t - 15]) + W[t - 16]            \
)

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    temp2 = S2(a) + F0(a,b,c);                  \
    d += temp1; h = temp1 + temp2;              \
}

namespace Crypto
{

SHA256::SHA256(void)
{
	reset();
}

SHA256::~SHA256(void)
{
	zeroize(total,  sizeof(total));
	zeroize(state,  sizeof(state));
	zeroize(buffer, sizeof(buffer));
}

void 
SHA256::update(const uint8_t *input, std::size_t input_sz)
{
	std::size_t fill;
	uint32_t left;

	if ( NULL == input || 0 == input_sz ) {
		return;
	}

	left = total[0] & 0x3F;
	fill = 64 - left;

	total[0] += (uint32_t)input_sz;
	total[0] &= 0xFFFFFFFF;

	if ( total[0] < (uint32_t)input_sz ) {
		total[1]++;
	}

	if ( left && input_sz >= fill ) {
		memcpy(buffer + left, input, fill);

		process(buffer);

		input    += fill;
		input_sz -= fill;
		left = 0;
	}

	while ( input_sz >= 64 ) {
		process(input);

		input    += 64;
		input_sz -= 64;
	}

	if ( input_sz > 0 ) {
		memcpy(buffer + left, input, input_sz);
	}
}

void 
SHA256::finish(uint8_t *output)
{
	uint32_t last, padn;
	uint32_t high, low;
	uint8_t  msglen[8];

	high = (total[0] >> 29) | (total[1] << 3);
	low  = (total[0] <<  3);

	PUT_UINT32(high, msglen, 0);
	PUT_UINT32(low,  msglen, 4);

	last = total[0] & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	update(padding, padn);
	update(msglen, 8);

	PUT_UINT32(state[0], output,  0);
	PUT_UINT32(state[1], output,  4);
	PUT_UINT32(state[2], output,  8);
	PUT_UINT32(state[3], output, 12);
	PUT_UINT32(state[4], output, 16);
	PUT_UINT32(state[5], output, 20);
	PUT_UINT32(state[6], output, 24);
	PUT_UINT32(state[7], output, 28);

	reset();
}

void
SHA256::reset(void)
{
	zeroize(total, sizeof(total));

	state[0] = 0x6A09E667;
	state[1] = 0xBB67AE85;
	state[2] = 0x3C6EF372;
	state[3] = 0xA54FF53A;
	state[4] = 0x510E527F;
	state[5] = 0x9B05688C;
	state[6] = 0x1F83D9AB;
	state[7] = 0x5BE0CD19;

	zeroize(buffer, sizeof(buffer));
}

void
SHA256::process(const uint8_t data[64])
{
	uint32_t temp1, temp2, W[64];
	uint32_t A[8];
	std::size_t i;

	for ( i = 0 ; i < 8 ; ++i ) {
		A[i] = state[i];
	}

	for ( i = 0 ; i < 16 ; ++i ) {
		GET_UINT32(W[i], data, 4 * i);
	}

	for ( i = 0 ; i < 16 ; i += 8 ) {
		P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[i+0], K[i+0]);
		P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[i+1], K[i+1]);
		P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], W[i+2], K[i+2]);
		P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], W[i+3], K[i+3]);
		P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[i+4], K[i+4]);
		P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[i+5], K[i+5]);
		P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[i+6], K[i+6]);
		P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[i+7], K[i+7]);
	}

	for ( i = 16 ; i < 64 ; i += 8 ) {
		P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(i+0), K[i+0]);
		P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(i+1), K[i+1]);
		P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(i+2), K[i+2]);
		P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(i+3), K[i+3]);
		P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(i+4), K[i+4]);
		P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(i+5), K[i+5]);
		P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(i+6), K[i+6]);
		P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(i+7), K[i+7]);
	}

	for ( i = 0 ; i < 8 ; i++ ) {
		state[i] += A[i];
	}
}

const uint8_t
SHA256::padding[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

const uint32_t
SHA256::K[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

}
