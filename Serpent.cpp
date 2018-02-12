#include "crypto/Serpent.hpp"

#include <cstring>

#define GET_BYTE(n, i)                               \
	((uint8_t)((n) >> (8*(i))))

#define GET_UINT32(n, b, i)                          \
{                                                    \
	(n) = ((uint32_t)(b)[(i)    ]      )         \
	    | ((uint32_t)(b)[(i) + 1] <<  8)         \
	    | ((uint32_t)(b)[(i) + 2] << 16)         \
	    | ((uint32_t)(b)[(i) + 3] << 24);        \
}

#define PUT_UINT32(n, b, i)                          \
{                                                    \
	(b)[(i)    ] = GET_BYTE((n),0);              \
	(b)[(i) + 1] = GET_BYTE((n),1);              \
	(b)[(i) + 2] = GET_BYTE((n),2);              \
	(b)[(i) + 3] = GET_BYTE((n),3);              \
}

#define LOAD_K(x0, x1, x2, x3, i)                    \
	x0 = K[4*i];   x1 = K[4*i+1];                \
        x2 = K[4*i+2]; x3 = K[4*i+3];

#define STORE_K(x0, x1, x2, x3, i)                   \
	K[4*i]   = x0; K[4*i+1] = x1;                \
	K[4*i+2] = x2; K[4*i+3] = x3;

#define ADD_K(x0, x1, x2, x3, i)                     \
	x0 ^= K[4*i];   x1 ^= K[4*i+1];              \
        x2 ^= K[4*i+2]; x3 ^= K[4*i+3];

#define PHI 0x9e3779b9UL

#define LR(x8, x5, x3, x1, i)                        \
	K[i] = ROL(x8 ^ x5 ^ x3 ^ x1 ^ PHI ^ i, 11);

#define S0(x0,x1,x2,x3,x4)                           \
	x4  = x3;                                    \
	x3 |= x0; x0 ^= x4; x4 ^= x2;                \
	x4 =~ x4; x3 ^= x1; x1 &= x0;                \
	x1 ^= x4; x2 ^= x0; x0 ^= x3;                \
	x4 |= x0; x0 ^= x2; x2 &= x1;                \
	x3 ^= x2; x1 =~ x1; x2 ^= x4;                \
	x1 ^= x2;

#define S1(x0,x1,x2,x3,x4)                           \
	x4  = x1;                                    \
	x1 ^= x0; x0 ^= x3; x3 =~ x3;                \
	x4 &= x1; x0 |= x1; x3 ^= x2;                \
	x0 ^= x3; x1 ^= x3; x3 ^= x4;                \
	x1 |= x4; x4 ^= x2; x2 &= x0;                \
	x2 ^= x1; x1 |= x0; x0 =~ x0;                \
	x0 ^= x2; x4 ^= x1;

#define S2(x0,x1,x2,x3,x4)                           \
	x3 =~ x3;                                    \
	x1 ^= x0; x4  = x0; x0 &= x2;                \
	x0 ^= x3; x3 |= x4; x2 ^= x1;                \
	x3 ^= x1; x1 &= x0; x0 ^= x2;                \
	x2 &= x3; x3 |= x1; x0 =~ x0;                \
	x3 ^= x0; x4 ^= x0; x0 ^= x2;                \
	x1 |= x2;

#define S3(x0,x1,x2,x3,x4)                           \
	x4  = x1;                                    \
	x1 ^= x3; x3 |= x0; x4 &= x0;                \
	x0 ^= x2; x2 ^= x1; x1 &= x3;                \
	x2 ^= x3; x0 |= x4; x4 ^= x3;                \
	x1 ^= x0; x0 &= x3; x3 &= x4;                \
	x3 ^= x2; x4 |= x1; x2 &= x1;                \
	x4 ^= x3; x0 ^= x3; x3 ^= x2;

#define S4(x0,x1,x2,x3,x4)                           \
	x4  = x3;                                    \
	x3 &= x0; x0 ^= x4;                          \
	x3 ^= x2; x2 |= x4; x0 ^= x1;                \
	x4 ^= x3; x2 |= x0;                          \
	x2 ^= x1; x1 &= x0;                          \
	x1 ^= x4; x4 &= x2; x2 ^= x3;                \
	x4 ^= x0; x3 |= x1; x1 =~ x1;                \
	x3 ^= x0;

#define S5(x0,x1,x2,x3,x4)                           \
	x4  = x1; x1 |= x0;                          \
	x2 ^= x1; x3 =~ x3; x4 ^= x0;                \
	x0 ^= x2; x1 &= x4; x4 |= x3;                \
	x4 ^= x0; x0 &= x3; x1 ^= x3;                \
	x3 ^= x2; x0 ^= x1; x2 &= x4;                \
	x1 ^= x2; x2 &= x0;                          \
	x3 ^= x2;

#define S6(x0,x1,x2,x3,x4)                           \
	x4  = x1;                                    \
	x3 ^= x0; x1 ^= x2; x2 ^= x0;                \
	x0 &= x3; x1 |= x3; x4 =~ x4;                \
	x0 ^= x1; x1 ^= x2;                          \
	x3 ^= x4; x4 ^= x0; x2 &= x0;                \
	x4 ^= x1; x2 ^= x3; x3 &= x1;                \
	x3 ^= x0; x1 ^= x2;

#define S7(x0,x1,x2,x3,x4)                           \
	x1 =~ x1;                                    \
	x4  = x1; x0 =~ x0; x1 &= x2;                \
	x1 ^= x3; x3 |= x4; x4 ^= x2;                \
	x2 ^= x3; x3 ^= x0; x0 |= x1;                \
	x2 &= x0; x0 ^= x4; x4 ^= x3;                \
	x3 &= x0; x4 ^= x1;                          \
	x2 ^= x4; x3 ^= x1; x4 |= x0;                \
	x4 ^= x1;

#define IS0(x0,x1,x2,x3,x4)                          \
	x4  = x3; x1 ^= x0;                          \
	x3 |= x1; x4 ^= x1; x0 =~ x0;                \
	x2 ^= x3; x3 ^= x0; x0 &= x1;                \
	x0 ^= x2; x2 &= x3; x3 ^= x4;                \
	x2 ^= x3; x1 ^= x3; x3 &= x0;                \
	x1 ^= x0; x0 ^= x2; x4 ^= x3;

#define IS1(x0,x1,x2,x3,x4)                          \
	x1 ^= x3; x4  = x0;                          \
	x0 ^= x2; x2 =~ x2; x4 |= x1;                \
	x4 ^= x3; x3 &= x1; x1 ^= x2;                \
	x2 &= x4; x4 ^= x1; x1 |= x3;                \
	x3 ^= x0; x2 ^= x0; x0 |= x4;                \
	x2 ^= x4; x1 ^= x0;                          \
	x4 ^= x1;

#define IS2(x0,x1,x2,x3,x4)                          \
	x2 ^= x1; x4  = x3; x3 =~ x3;                \
	x3 |= x2; x2 ^= x4; x4 ^= x0;                \
	x3 ^= x1; x1 |= x2; x2 ^= x0;                \
	x1 ^= x4; x4 |= x3; x2 ^= x3;                \
	x4 ^= x2; x2 &= x1;                          \
	x2 ^= x3; x3 ^= x4; x4 ^= x0;

#define IS3(x0,x1,x2,x3,x4)                          \
	x2 ^= x1;                                    \
	x4  = x1; x1 &= x2;                          \
	x1 ^= x0; x0 |= x4; x4 ^= x3;                \
	x0 ^= x3; x3 |= x1; x1 ^= x2;                \
	x1 ^= x3; x0 ^= x2; x2 ^= x3;                \
	x3 &= x1; x1 ^= x0; x0 &= x2;                \
	x4 ^= x3; x3 ^= x0; x0 ^= x1;

#define IS4(x0,x1,x2,x3,x4)                          \
	x2 ^= x3; x4  = x0; x0 &= x1;                \
	x0 ^= x2; x2 |= x3; x4 =~ x4;                \
	x1 ^= x0; x0 ^= x2; x2 &= x4;                \
	x2 ^= x0; x0 |= x4;                          \
	x0 ^= x3; x3 &= x2;                          \
	x4 ^= x3; x3 ^= x1; x1 &= x0;                \
	x4 ^= x1; x0 ^= x3;

#define IS5(x0,x1,x2,x3,x4)                          \
	x4  = x1; x1 |= x2;                          \
	x2 ^= x4; x1 ^= x3; x3 &= x4;                \
	x2 ^= x3; x3 |= x0; x0 =~ x0;                \
	x3 ^= x2; x2 |= x0; x4 ^= x1;                \
	x2 ^= x4; x4 &= x0; x0 ^= x1;                \
	x1 ^= x3; x0 &= x2; x2 ^= x3;                \
	x0 ^= x2; x2 ^= x4; x4 ^= x3;

#define IS6(x0,x1,x2,x3,x4)                          \
	x0 ^= x2;                                    \
	x4  = x0; x0 &= x3; x2 ^= x3;                \
	x0 ^= x2; x3 ^= x1; x2 |= x4;                \
	x2 ^= x3; x3 &= x0; x0 =~ x0;                \
	x3 ^= x1; x1 &= x2; x4 ^= x0;                \
	x3 ^= x4; x4 ^= x2; x0 ^= x1;                \
	x2 ^= x0;

#define IS7(x0,x1,x2,x3,x4)                          \
	x4  = x3; x3 &= x0; x0 ^= x2;                \
	x2 |= x4; x4 ^= x1; x0 =~ x0;                \
	x1 |= x3; x4 ^= x0; x0 &= x2;                \
	x0 ^= x1; x1 &= x2; x3 ^= x2;                \
	x4 ^= x3; x2 &= x3; x3 |= x0;                \
	x1 ^= x4; x3 ^= x4; x4 &= x0;                \
	x4 ^= x2;

#define LT(x0,x1,x2,x3)                              \
	x0  = ROL(x0, 13);                           \
	x2  = ROL(x2, 3);                            \
	x1 ^= x0 ^ x2;                               \
	x3 ^= x2 ^ (x0 << 3);                        \
	x1  = ROL(x1, 1);                            \
	x3  = ROL(x3, 7);                            \
	x0 ^= x1 ^ x3;                               \
	x2 ^= x3 ^ (x1 << 7);                        \
	x0  = ROL(x0, 5);                            \
	x2  = ROL(x2, 22);

#define ILT(x0,x1,x2,x3)                             \
	x2  = ROR(x2, 22);                           \
	x0  = ROR(x0, 5);                            \
	x2 ^= x3 ^ (x1 << 7);                        \
	x0 ^= x1 ^ x3;                               \
	x3  = ROR(x3, 7);                            \
	x1  = ROR(x1, 1);                            \
	x3 ^= x2 ^ (x0 << 3);                        \
	x1 ^= x0 ^ x2;                               \
	x2  = ROR(x2, 3);                            \
	x0  = ROR(x0, 13);

namespace Crypto
{

Serpent::Serpent(const uint8_t *key, std::size_t key_sz)
	: SymmetricCipher(key, key_sz)
{
	uint8_t m[32];
	uint32_t M[8];
	uint32_t r0, r1, r2, r3, r4;

	if ( key_sz > 32 ) {
		throw Serpent::Exception("Key size is not supported");
	}

	// Load key
	memset(m, 0x00, sizeof(m));
	memcpy(m, key,  key_sz);
	if ( key_sz < 32 ) { m[key_sz] = 0x01; }

	GET_UINT32(M[0], m,  0); GET_UINT32(M[1], m,  4);
	GET_UINT32(M[2], m,  8); GET_UINT32(M[3], m, 12);
	GET_UINT32(M[4], m, 16); GET_UINT32(M[5], m, 20);
	GET_UINT32(M[6], m, 24); GET_UINT32(M[7], m, 28);

	// Linear recurrence
	LR(M[  0], M[  3], M[  5], M[  7],   0); LR(M[  1], M[  4], M[  6], K[  0],   1);
	LR(M[  2], M[  5], M[  7], K[  1],   2); LR(M[  3], M[  6], K[  0], K[  2],   3);
	LR(M[  4], M[  7], K[  1], K[  3],   4); LR(M[  5], K[  0], K[  2], K[  4],   5);
	LR(M[  6], K[  1], K[  3], K[  5],   6); LR(M[  7], K[  2], K[  4], K[  6],   7);

	LR(K[  0], K[  3], K[  5], K[  7],   8); LR(K[  1], K[  4], K[  6], K[  8],   9);
	LR(K[  2], K[  5], K[  7], K[  9],  10); LR(K[  3], K[  6], K[  8], K[ 10],  11);
	LR(K[  4], K[  7], K[  9], K[ 11],  12); LR(K[  5], K[  8], K[ 10], K[ 12],  13);
	LR(K[  6], K[  9], K[ 11], K[ 13],  14); LR(K[  7], K[ 10], K[ 12], K[ 14],  15);
	LR(K[  8], K[ 11], K[ 13], K[ 15],  16); LR(K[  9], K[ 12], K[ 14], K[ 16],  17);
	LR(K[ 10], K[ 13], K[ 15], K[ 17],  18); LR(K[ 11], K[ 14], K[ 16], K[ 18],  19);
	LR(K[ 12], K[ 15], K[ 17], K[ 19],  20); LR(K[ 13], K[ 16], K[ 18], K[ 20],  21);
	LR(K[ 14], K[ 17], K[ 19], K[ 21],  22); LR(K[ 15], K[ 18], K[ 20], K[ 22],  23);
	LR(K[ 16], K[ 19], K[ 21], K[ 23],  24); LR(K[ 17], K[ 20], K[ 22], K[ 24],  25);
	LR(K[ 18], K[ 21], K[ 23], K[ 25],  26); LR(K[ 19], K[ 22], K[ 24], K[ 26],  27);
	LR(K[ 20], K[ 23], K[ 25], K[ 27],  28); LR(K[ 21], K[ 24], K[ 26], K[ 28],  29);
	LR(K[ 22], K[ 25], K[ 27], K[ 29],  30); LR(K[ 23], K[ 26], K[ 28], K[ 30],  31);
	LR(K[ 24], K[ 27], K[ 29], K[ 31],  32); LR(K[ 25], K[ 28], K[ 30], K[ 32],  33);
	LR(K[ 26], K[ 29], K[ 31], K[ 33],  34); LR(K[ 27], K[ 30], K[ 32], K[ 34],  35);
	LR(K[ 28], K[ 31], K[ 33], K[ 35],  36); LR(K[ 29], K[ 32], K[ 34], K[ 36],  37);
	LR(K[ 30], K[ 33], K[ 35], K[ 37],  38); LR(K[ 31], K[ 34], K[ 36], K[ 38],  39);
	LR(K[ 32], K[ 35], K[ 37], K[ 39],  40); LR(K[ 33], K[ 36], K[ 38], K[ 40],  41);
	LR(K[ 34], K[ 37], K[ 39], K[ 41],  42); LR(K[ 35], K[ 38], K[ 40], K[ 42],  43);
	LR(K[ 36], K[ 39], K[ 41], K[ 43],  44); LR(K[ 37], K[ 40], K[ 42], K[ 44],  45);
	LR(K[ 38], K[ 41], K[ 43], K[ 45],  46); LR(K[ 39], K[ 42], K[ 44], K[ 46],  47);
	LR(K[ 40], K[ 43], K[ 45], K[ 47],  48); LR(K[ 41], K[ 44], K[ 46], K[ 48],  49);
	LR(K[ 42], K[ 45], K[ 47], K[ 49],  50); LR(K[ 43], K[ 46], K[ 48], K[ 50],  51);
	LR(K[ 44], K[ 47], K[ 49], K[ 51],  52); LR(K[ 45], K[ 48], K[ 50], K[ 52],  53);
	LR(K[ 46], K[ 49], K[ 51], K[ 53],  54); LR(K[ 47], K[ 50], K[ 52], K[ 54],  55);
	LR(K[ 48], K[ 51], K[ 53], K[ 55],  56); LR(K[ 49], K[ 52], K[ 54], K[ 56],  57);
	LR(K[ 50], K[ 53], K[ 55], K[ 57],  58); LR(K[ 51], K[ 54], K[ 56], K[ 58],  59);
	LR(K[ 52], K[ 55], K[ 57], K[ 59],  60); LR(K[ 53], K[ 56], K[ 58], K[ 60],  61);
	LR(K[ 54], K[ 57], K[ 59], K[ 61],  62); LR(K[ 55], K[ 58], K[ 60], K[ 62],  63);
	LR(K[ 56], K[ 59], K[ 61], K[ 63],  64); LR(K[ 57], K[ 60], K[ 62], K[ 64],  65);
	LR(K[ 58], K[ 61], K[ 63], K[ 65],  66); LR(K[ 59], K[ 62], K[ 64], K[ 66],  67);
	LR(K[ 60], K[ 63], K[ 65], K[ 67],  68); LR(K[ 61], K[ 64], K[ 66], K[ 68],  69);
	LR(K[ 62], K[ 65], K[ 67], K[ 69],  70); LR(K[ 63], K[ 66], K[ 68], K[ 70],  71);
	LR(K[ 64], K[ 67], K[ 69], K[ 71],  72); LR(K[ 65], K[ 68], K[ 70], K[ 72],  73);
	LR(K[ 66], K[ 69], K[ 71], K[ 73],  74); LR(K[ 67], K[ 70], K[ 72], K[ 74],  75);
	LR(K[ 68], K[ 71], K[ 73], K[ 75],  76); LR(K[ 69], K[ 72], K[ 74], K[ 76],  77);
	LR(K[ 70], K[ 73], K[ 75], K[ 77],  78); LR(K[ 71], K[ 74], K[ 76], K[ 78],  79);
	LR(K[ 72], K[ 75], K[ 77], K[ 79],  80); LR(K[ 73], K[ 76], K[ 78], K[ 80],  81);
	LR(K[ 74], K[ 77], K[ 79], K[ 81],  82); LR(K[ 75], K[ 78], K[ 80], K[ 82],  83);
	LR(K[ 76], K[ 79], K[ 81], K[ 83],  84); LR(K[ 77], K[ 80], K[ 82], K[ 84],  85);
	LR(K[ 78], K[ 81], K[ 83], K[ 85],  86); LR(K[ 79], K[ 82], K[ 84], K[ 86],  87);
	LR(K[ 80], K[ 83], K[ 85], K[ 87],  88); LR(K[ 81], K[ 84], K[ 86], K[ 88],  89);
	LR(K[ 82], K[ 85], K[ 87], K[ 89],  90); LR(K[ 83], K[ 86], K[ 88], K[ 90],  91);
	LR(K[ 84], K[ 87], K[ 89], K[ 91],  92); LR(K[ 85], K[ 88], K[ 90], K[ 92],  93);
	LR(K[ 86], K[ 89], K[ 91], K[ 93],  94); LR(K[ 87], K[ 90], K[ 92], K[ 94],  95);
	LR(K[ 88], K[ 91], K[ 93], K[ 95],  96); LR(K[ 89], K[ 92], K[ 94], K[ 96],  97);
	LR(K[ 90], K[ 93], K[ 95], K[ 97],  98); LR(K[ 91], K[ 94], K[ 96], K[ 98],  99);
	LR(K[ 92], K[ 95], K[ 97], K[ 99], 100); LR(K[ 93], K[ 96], K[ 98], K[100], 101);
	LR(K[ 94], K[ 97], K[ 99], K[101], 102); LR(K[ 95], K[ 98], K[100], K[102], 103);
	LR(K[ 96], K[ 99], K[101], K[103], 104); LR(K[ 97], K[100], K[102], K[104], 105);
	LR(K[ 98], K[101], K[103], K[105], 106); LR(K[ 99], K[102], K[104], K[106], 107);
	LR(K[100], K[103], K[105], K[107], 108); LR(K[101], K[104], K[106], K[108], 109);
	LR(K[102], K[105], K[107], K[109], 110); LR(K[103], K[106], K[108], K[110], 111);
	LR(K[104], K[107], K[109], K[111], 112); LR(K[105], K[108], K[110], K[112], 113);
	LR(K[106], K[109], K[111], K[113], 114); LR(K[107], K[110], K[112], K[114], 115);
	LR(K[108], K[111], K[113], K[115], 116); LR(K[109], K[112], K[114], K[116], 117);
	LR(K[110], K[113], K[115], K[117], 118); LR(K[111], K[114], K[116], K[118], 119);
	LR(K[112], K[115], K[117], K[119], 120); LR(K[113], K[116], K[118], K[120], 121);
	LR(K[114], K[117], K[119], K[121], 122); LR(K[115], K[118], K[120], K[122], 123);
	LR(K[116], K[119], K[121], K[123], 124); LR(K[117], K[120], K[122], K[124], 125);
	LR(K[118], K[121], K[123], K[125], 126); LR(K[119], K[122], K[124], K[126], 127);
	LR(K[120], K[123], K[125], K[127], 128); LR(K[121], K[124], K[126], K[128], 129);
	LR(K[122], K[125], K[127], K[129], 130); LR(K[123], K[126], K[128], K[130], 131);

	// SBoxes
	LOAD_K(r0, r1, r2, r3,  0); S3(r0, r1, r2, r3, r4); STORE_K(r3, r4, r1, r0,  0);
	LOAD_K(r0, r1, r2, r3,  1); S2(r0, r1, r2, r3, r4); STORE_K(r4, r1, r0, r3,  1);
	LOAD_K(r0, r1, r2, r3,  2); S1(r0, r1, r2, r3, r4); STORE_K(r4, r2, r3, r0,  2);
	LOAD_K(r0, r1, r2, r3,  3); S0(r0, r1, r2, r3, r4); STORE_K(r2, r1, r3, r0,  3);
	LOAD_K(r0, r1, r2, r3,  4); S7(r0, r1, r2, r3, r4); STORE_K(r4, r2, r3, r0,  4);
	LOAD_K(r0, r1, r2, r3,  5); S6(r0, r1, r2, r3, r4); STORE_K(r2, r4, r1, r3,  5);
	LOAD_K(r0, r1, r2, r3,  6); S5(r0, r1, r2, r3, r4); STORE_K(r4, r0, r1, r3,  6);
	LOAD_K(r0, r1, r2, r3,  7); S4(r0, r1, r2, r3, r4); STORE_K(r1, r2, r3, r4,  7);

	LOAD_K(r0, r1, r2, r3,  8); S3(r0, r1, r2, r3, r4); STORE_K(r3, r4, r1, r0,  8);
	LOAD_K(r0, r1, r2, r3,  9); S2(r0, r1, r2, r3, r4); STORE_K(r4, r1, r0, r3,  9);
	LOAD_K(r0, r1, r2, r3, 10); S1(r0, r1, r2, r3, r4); STORE_K(r4, r2, r3, r0, 10);
	LOAD_K(r0, r1, r2, r3, 11); S0(r0, r1, r2, r3, r4); STORE_K(r2, r1, r3, r0, 11);
	LOAD_K(r0, r1, r2, r3, 12); S7(r0, r1, r2, r3, r4); STORE_K(r4, r2, r3, r0, 12);
	LOAD_K(r0, r1, r2, r3, 13); S6(r0, r1, r2, r3, r4); STORE_K(r2, r4, r1, r3, 13);
	LOAD_K(r0, r1, r2, r3, 14); S5(r0, r1, r2, r3, r4); STORE_K(r4, r0, r1, r3, 14);
	LOAD_K(r0, r1, r2, r3, 15); S4(r0, r1, r2, r3, r4); STORE_K(r1, r2, r3, r4, 15);

	LOAD_K(r0, r1, r2, r3, 16); S3(r0, r1, r2, r3, r4); STORE_K(r3, r4, r1, r0, 16);
	LOAD_K(r0, r1, r2, r3, 17); S2(r0, r1, r2, r3, r4); STORE_K(r4, r1, r0, r3, 17);
	LOAD_K(r0, r1, r2, r3, 18); S1(r0, r1, r2, r3, r4); STORE_K(r4, r2, r3, r0, 18);
	LOAD_K(r0, r1, r2, r3, 19); S0(r0, r1, r2, r3, r4); STORE_K(r2, r1, r3, r0, 19);
	LOAD_K(r0, r1, r2, r3, 20); S7(r0, r1, r2, r3, r4); STORE_K(r4, r2, r3, r0, 20);
	LOAD_K(r0, r1, r2, r3, 21); S6(r0, r1, r2, r3, r4); STORE_K(r2, r4, r1, r3, 21);
	LOAD_K(r0, r1, r2, r3, 22); S5(r0, r1, r2, r3, r4); STORE_K(r4, r0, r1, r3, 22);
	LOAD_K(r0, r1, r2, r3, 23); S4(r0, r1, r2, r3, r4); STORE_K(r1, r2, r3, r4, 23);

	LOAD_K(r0, r1, r2, r3, 24); S3(r0, r1, r2, r3, r4); STORE_K(r3, r4, r1, r0, 24);
	LOAD_K(r0, r1, r2, r3, 25); S2(r0, r1, r2, r3, r4); STORE_K(r4, r1, r0, r3, 25);
	LOAD_K(r0, r1, r2, r3, 26); S1(r0, r1, r2, r3, r4); STORE_K(r4, r2, r3, r0, 26);
	LOAD_K(r0, r1, r2, r3, 27); S0(r0, r1, r2, r3, r4); STORE_K(r2, r1, r3, r0, 27);
	LOAD_K(r0, r1, r2, r3, 28); S7(r0, r1, r2, r3, r4); STORE_K(r4, r2, r3, r0, 28);
	LOAD_K(r0, r1, r2, r3, 29); S6(r0, r1, r2, r3, r4); STORE_K(r2, r4, r1, r3, 29);
	LOAD_K(r0, r1, r2, r3, 30); S5(r0, r1, r2, r3, r4); STORE_K(r4, r0, r1, r3, 30);
	LOAD_K(r0, r1, r2, r3, 31); S4(r0, r1, r2, r3, r4); STORE_K(r1, r2, r3, r4, 31);

	LOAD_K(r0, r1, r2, r3, 32); S3(r0, r1, r2, r3, r4); STORE_K(r3, r4, r1, r0, 32);

	// Zeroization
	zeroize(m, sizeof(m));
	zeroize(M, sizeof(M));
}

Serpent::~Serpent(void)
{
	zeroize(K, sizeof(K));
}

void
Serpent::encrypt(const uint8_t *plaintext, uint8_t *ciphertext) const
{
	uint32_t r0, r1, r2, r3, r4;

	// Load plaintext
	GET_UINT32(r0, plaintext,  0);
	GET_UINT32(r1, plaintext,  4);
	GET_UINT32(r2, plaintext,  8);
	GET_UINT32(r3, plaintext, 12);

	// 32 rounds of Serpent
	ADD_K(r0, r1, r2, r3,  0); S0(r0, r1, r2, r3, r4); LT(r2, r1, r3, r0);
	ADD_K(r2, r1, r3, r0,  1); S1(r2, r1, r3, r0, r4); LT(r4, r3, r0, r2);
	ADD_K(r4, r3, r0, r2,  2); S2(r4, r3, r0, r2, r1); LT(r1, r3, r4, r2);
	ADD_K(r1, r3, r4, r2,  3); S3(r1, r3, r4, r2, r0); LT(r2, r0, r3, r1);
	ADD_K(r2, r0, r3, r1,  4); S4(r2, r0, r3, r1, r4); LT(r0, r3, r1, r4);
	ADD_K(r0, r3, r1, r4,  5); S5(r0, r3, r1, r4, r2); LT(r2, r0, r3, r4);
	ADD_K(r2, r0, r3, r4,  6); S6(r2, r0, r3, r4, r1); LT(r3, r1, r0, r4);
	ADD_K(r3, r1, r0, r4,  7); S7(r3, r1, r0, r4, r2); LT(r2, r0, r4, r3);
	ADD_K(r2, r0, r4, r3,  8); S0(r2, r0, r4, r3, r1); LT(r4, r0, r3, r2);
	ADD_K(r4, r0, r3, r2,  9); S1(r4, r0, r3, r2, r1); LT(r1, r3, r2, r4);
	ADD_K(r1, r3, r2, r4, 10); S2(r1, r3, r2, r4, r0); LT(r0, r3, r1, r4);
	ADD_K(r0, r3, r1, r4, 11); S3(r0, r3, r1, r4, r2); LT(r4, r2, r3, r0);
	ADD_K(r4, r2, r3, r0, 12); S4(r4, r2, r3, r0, r1); LT(r2, r3, r0, r1);
	ADD_K(r2, r3, r0, r1, 13); S5(r2, r3, r0, r1, r4); LT(r4, r2, r3, r1);
	ADD_K(r4, r2, r3, r1, 14); S6(r4, r2, r3, r1, r0); LT(r3, r0, r2, r1);
	ADD_K(r3, r0, r2, r1, 15); S7(r3, r0, r2, r1, r4); LT(r4, r2, r1, r3);
	ADD_K(r4, r2, r1, r3, 16); S0(r4, r2, r1, r3, r0); LT(r1, r2, r3, r4);
	ADD_K(r1, r2, r3, r4, 17); S1(r1, r2, r3, r4, r0); LT(r0, r3, r4, r1);
	ADD_K(r0, r3, r4, r1, 18); S2(r0, r3, r4, r1, r2); LT(r2, r3, r0, r1);
	ADD_K(r2, r3, r0, r1, 19); S3(r2, r3, r0, r1, r4); LT(r1, r4, r3, r2);
	ADD_K(r1, r4, r3, r2, 20); S4(r1, r4, r3, r2, r0); LT(r4, r3, r2, r0);
	ADD_K(r4, r3, r2, r0, 21); S5(r4, r3, r2, r0, r1); LT(r1, r4, r3, r0);
	ADD_K(r1, r4, r3, r0, 22); S6(r1, r4, r3, r0, r2); LT(r3, r2, r4, r0);
	ADD_K(r3, r2, r4, r0, 23); S7(r3, r2, r4, r0, r1); LT(r1, r4, r0, r3);
	ADD_K(r1, r4, r0, r3, 24); S0(r1, r4, r0, r3, r2); LT(r0, r4, r3, r1);
	ADD_K(r0, r4, r3, r1, 25); S1(r0, r4, r3, r1, r2); LT(r2, r3, r1, r0);
	ADD_K(r2, r3, r1, r0, 26); S2(r2, r3, r1, r0, r4); LT(r4, r3, r2, r0);
	ADD_K(r4, r3, r2, r0, 27); S3(r4, r3, r2, r0, r1); LT(r0, r1, r3, r4);
	ADD_K(r0, r1, r3, r4, 28); S4(r0, r1, r3, r4, r2); LT(r1, r3, r4, r2);
	ADD_K(r1, r3, r4, r2, 29); S5(r1, r3, r4, r2, r0); LT(r0, r1, r3, r2);
	ADD_K(r0, r1, r3, r2, 30); S6(r0, r1, r3, r2, r4); LT(r3, r4, r1, r2);
	ADD_K(r3, r4, r1, r2, 31); S7(r3, r4, r1, r2, r0);
	ADD_K(r0, r1, r2, r3, 32);

	// Save ciphertext
	PUT_UINT32(r0, ciphertext,  0);
	PUT_UINT32(r1, ciphertext,  4);
	PUT_UINT32(r2, ciphertext,  8);
	PUT_UINT32(r3, ciphertext, 12);
}

void
Serpent::decrypt(const uint8_t *ciphertext, uint8_t *plaintext) const
{
	uint32_t r0, r1, r2, r3, r4;

	// Load ciphertext
	GET_UINT32(r0, ciphertext,  0);
	GET_UINT32(r1, ciphertext,  4);
	GET_UINT32(r2, ciphertext,  8);
	GET_UINT32(r3, ciphertext, 12);

	// 32 rounds of Serpent
	                                              ADD_K(r0, r1, r2, r3, 32);
	                     IS7(r0, r1, r2, r3, r4); ADD_K(r1, r3, r0, r4, 31);
	ILT(r1, r3, r0, r4); IS6(r1, r3, r0, r4, r2); ADD_K(r0, r2, r4, r1, 30);
	ILT(r0, r2, r4, r1); IS5(r0, r2, r4, r1, r3); ADD_K(r2, r3, r0, r4, 29);
	ILT(r2, r3, r0, r4); IS4(r2, r3, r0, r4, r1); ADD_K(r2, r0, r1, r4, 28);
	ILT(r2, r0, r1, r4); IS3(r2, r0, r1, r4, r3); ADD_K(r1, r2, r3, r4, 27);
	ILT(r1, r2, r3, r4); IS2(r1, r2, r3, r4, r0); ADD_K(r2, r0, r4, r3, 26);
	ILT(r2, r0, r4, r3); IS1(r2, r0, r4, r3, r1); ADD_K(r1, r0, r4, r3, 25);
	ILT(r1, r0, r4, r3); IS0(r1, r0, r4, r3, r2); ADD_K(r4, r2, r0, r1, 24);
	ILT(r4, r2, r0, r1); IS7(r4, r2, r0, r1, r3); ADD_K(r2, r1, r4, r3, 23);
	ILT(r2, r1, r4, r3); IS6(r2, r1, r4, r3, r0); ADD_K(r4, r0, r3, r2, 22);
	ILT(r4, r0, r3, r2); IS5(r4, r0, r3, r2, r1); ADD_K(r0, r1, r4, r3, 21);
	ILT(r0, r1, r4, r3); IS4(r0, r1, r4, r3, r2); ADD_K(r0, r4, r2, r3, 20);
	ILT(r0, r4, r2, r3); IS3(r0, r4, r2, r3, r1); ADD_K(r2, r0, r1, r3, 19);
	ILT(r2, r0, r1, r3); IS2(r2, r0, r1, r3, r4); ADD_K(r0, r4, r3, r1, 18);
	ILT(r0, r4, r3, r1); IS1(r0, r4, r3, r1, r2); ADD_K(r2, r4, r3, r1, 17);
	ILT(r2, r4, r3, r1); IS0(r2, r4, r3, r1, r0); ADD_K(r3, r0, r4, r2, 16);
	ILT(r3, r0, r4, r2); IS7(r3, r0, r4, r2, r1); ADD_K(r0, r2, r3, r1, 15);
	ILT(r0, r2, r3, r1); IS6(r0, r2, r3, r1, r4); ADD_K(r3, r4, r1, r0, 14);
	ILT(r3, r4, r1, r0); IS5(r3, r4, r1, r0, r2); ADD_K(r4, r2, r3, r1, 13);
	ILT(r4, r2, r3, r1); IS4(r4, r2, r3, r1, r0); ADD_K(r4, r3, r0, r1, 12);
	ILT(r4, r3, r0, r1); IS3(r4, r3, r0, r1, r2); ADD_K(r0, r4, r2, r1, 11);
	ILT(r0, r4, r2, r1); IS2(r0, r4, r2, r1, r3); ADD_K(r4, r3, r1, r2, 10);
	ILT(r4, r3, r1, r2); IS1(r4, r3, r1, r2, r0); ADD_K(r0, r3, r1, r2,  9);
	ILT(r0, r3, r1, r2); IS0(r0, r3, r1, r2, r4); ADD_K(r1, r4, r3, r0,  8);
	ILT(r1, r4, r3, r0); IS7(r1, r4, r3, r0, r2); ADD_K(r4, r0, r1, r2,  7);
	ILT(r4, r0, r1, r2); IS6(r4, r0, r1, r2, r3); ADD_K(r1, r3, r2, r4,  6);
	ILT(r1, r3, r2, r4); IS5(r1, r3, r2, r4, r0); ADD_K(r3, r0, r1, r2,  5);
	ILT(r3, r0, r1, r2); IS4(r3, r0, r1, r2, r4); ADD_K(r3, r1, r4, r2,  4);
	ILT(r3, r1, r4, r2); IS3(r3, r1, r4, r2, r0); ADD_K(r4, r3, r0, r2,  3);
	ILT(r4, r3, r0, r2); IS2(r4, r3, r0, r2, r1); ADD_K(r3, r1, r2, r0,  2);
	ILT(r3, r1, r2, r0); IS1(r3, r1, r2, r0, r4); ADD_K(r4, r1, r2, r0,  1);
	ILT(r4, r1, r2, r0); IS0(r4, r1, r2, r0, r3); ADD_K(r2, r3, r1, r4,  0);

	// Save plaintext
	PUT_UINT32(r2, plaintext,  0);
	PUT_UINT32(r3, plaintext,  4);
	PUT_UINT32(r1, plaintext,  8);
	PUT_UINT32(r4, plaintext, 12);
}

uint32_t
Serpent::ROL(uint32_t x, std::size_t n)
{
	return (x << n) | (x >> (32 - n));
}

uint32_t
Serpent::ROR(uint32_t x, std::size_t n)
{
	return (x >> n) | (x << (32 - n));
}

}
