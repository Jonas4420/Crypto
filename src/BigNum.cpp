#include "crypto/BigNum.hpp"

#include <memory>
#include <vector>

#if defined(CRYPTO_BIGNUM_HAVE_ASM)

#ifndef asm
#define asm __asm
#endif

#if defined(__GNUC__)

#if defined(__i386__)

#define MULADDC_INIT                        \
    asm(                                    \
        "movl   %%ebx, %0           \n\t"   \
        "movl   %5, %%esi           \n\t"   \
        "movl   %6, %%edi           \n\t"   \
        "movl   %7, %%ecx           \n\t"   \
        "movl   %8, %%ebx           \n\t"

#define MULADDC_CORE                        \
        "lodsl                      \n\t"   \
        "mull   %%ebx               \n\t"   \
        "addl   %%ecx,   %%eax      \n\t"   \
        "adcl   $0,      %%edx      \n\t"   \
        "addl   (%%edi), %%eax      \n\t"   \
        "adcl   $0,      %%edx      \n\t"   \
        "movl   %%edx,   %%ecx      \n\t"   \
        "stosl                      \n\t"

#if defined(CRYPTO_BIGNUM_HAVE_SSE2)

#define MULADDC_HUIT                            \
        "movd     %%ecx,     %%mm1      \n\t"   \
        "movd     %%ebx,     %%mm0      \n\t"   \
        "movd     (%%edi),   %%mm3      \n\t"   \
        "paddq    %%mm3,     %%mm1      \n\t"   \
        "movd     (%%esi),   %%mm2      \n\t"   \
        "pmuludq  %%mm0,     %%mm2      \n\t"   \
        "movd     4(%%esi),  %%mm4      \n\t"   \
        "pmuludq  %%mm0,     %%mm4      \n\t"   \
        "movd     8(%%esi),  %%mm6      \n\t"   \
        "pmuludq  %%mm0,     %%mm6      \n\t"   \
        "movd     12(%%esi), %%mm7      \n\t"   \
        "pmuludq  %%mm0,     %%mm7      \n\t"   \
        "paddq    %%mm2,     %%mm1      \n\t"   \
        "movd     4(%%edi),  %%mm3      \n\t"   \
        "paddq    %%mm4,     %%mm3      \n\t"   \
        "movd     8(%%edi),  %%mm5      \n\t"   \
        "paddq    %%mm6,     %%mm5      \n\t"   \
        "movd     12(%%edi), %%mm4      \n\t"   \
        "paddq    %%mm4,     %%mm7      \n\t"   \
        "movd     %%mm1,     (%%edi)    \n\t"   \
        "movd     16(%%esi), %%mm2      \n\t"   \
        "pmuludq  %%mm0,     %%mm2      \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "movd     20(%%esi), %%mm4      \n\t"   \
        "pmuludq  %%mm0,     %%mm4      \n\t"   \
        "paddq    %%mm3,     %%mm1      \n\t"   \
        "movd     24(%%esi), %%mm6      \n\t"   \
        "pmuludq  %%mm0,     %%mm6      \n\t"   \
        "movd     %%mm1,     4(%%edi)   \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "movd     28(%%esi), %%mm3      \n\t"   \
        "pmuludq  %%mm0,     %%mm3      \n\t"   \
        "paddq    %%mm5,     %%mm1      \n\t"   \
        "movd     16(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm2      \n\t"   \
        "movd     %%mm1,     8(%%edi)   \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm7,     %%mm1      \n\t"   \
        "movd     20(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm4      \n\t"   \
        "movd     %%mm1,     12(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm2,     %%mm1      \n\t"   \
        "movd     24(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm6      \n\t"   \
        "movd     %%mm1,     16(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm4,     %%mm1      \n\t"   \
        "movd     28(%%edi), %%mm5      \n\t"   \
        "paddq    %%mm5,     %%mm3      \n\t"   \
        "movd     %%mm1,     20(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm6,     %%mm1      \n\t"   \
        "movd     %%mm1,     24(%%edi)  \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "paddq    %%mm3,     %%mm1      \n\t"   \
        "movd     %%mm1,     28(%%edi)  \n\t"   \
        "addl     $32,       %%edi      \n\t"   \
        "addl     $32,       %%esi      \n\t"   \
        "psrlq    $32,       %%mm1      \n\t"   \
        "movd     %%mm1,     %%ecx      \n\t"

#define MULADDC_STOP                    \
        "emms                   \n\t"   \
        "movl   %4, %%ebx       \n\t"   \
        "movl   %%ecx, %1       \n\t"   \
        "movl   %%edi, %2       \n\t"   \
        "movl   %%esi, %3       \n\t"   \
        : "=m" (t), "=m" (c), "=m" (d), "=m" (s)        \
        : "m" (t), "m" (s), "m" (d), "m" (c), "m" (b)   \
        : "eax", "ecx", "edx", "esi", "edi"             \
    );

#else

#define MULADDC_STOP                    \
        "movl   %4, %%ebx       \n\t"   \
        "movl   %%ecx, %1       \n\t"   \
        "movl   %%edi, %2       \n\t"   \
        "movl   %%esi, %3       \n\t"   \
        : "=m" (t), "=m" (c), "=m" (d), "=m" (s)        \
        : "m" (t), "m" (s), "m" (d), "m" (c), "m" (b)   \
        : "eax", "ecx", "edx", "esi", "edi"             \
    );

#endif /* CRYPTO_BIGNUM_HAVE_SSE2 */

#endif /* i386 */

#if defined(__amd64__) || defined (__x86_64__)

#define MULADDC_INIT                        \
    asm(                                    \
        "xorq   %%r8, %%r8          \n\t"

#define MULADDC_CORE                        \
        "movq   (%%rsi), %%rax      \n\t"   \
        "mulq   %%rbx               \n\t"   \
        "addq   $8,      %%rsi      \n\t"   \
        "addq   %%rcx,   %%rax      \n\t"   \
        "movq   %%r8,    %%rcx      \n\t"   \
        "adcq   $0,      %%rdx      \n\t"   \
        "nop                        \n\t"   \
        "addq   %%rax,   (%%rdi)    \n\t"   \
        "adcq   %%rdx,   %%rcx      \n\t"   \
        "addq   $8,      %%rdi      \n\t"

#define MULADDC_STOP                        \
        : "+c" (c), "+D" (d), "+S" (s)      \
        : "b" (b)                           \
        : "rax", "rdx", "r8"                \
    );

#endif /* AMD64 */

#endif /* GNUC */

#else /* CRYPTO_BIGNUM_HAVE_ASM */

#define MULADDC_INIT                        \
{                                           \
	uint64_t s0, s1, b0, b1;            \
	uint64_t r0, r1, rx, ry;            \
	b0 = ( b << biH ) >> biH;           \
	b1 = ( b >> biH );

#define MULADDC_CORE                        \
	s0 = ( *s << biH ) >> biH;          \
	s1 = ( *s >> biH ); s++;            \
	rx = s0 * b1; r0 = s0 * b0;         \
	ry = s1 * b0; r1 = s1 * b1;         \
	r1 += ( rx >> biH );                \
	r1 += ( ry >> biH );                \
	rx <<= biH; ry <<= biH;             \
	r0 += rx; r1 += (r0 < rx);          \
	r0 += ry; r1 += (r0 < ry);          \
	r0 +=  c; r1 += (r0 <  c);          \
	r0 += *d; r1 += (r0 < *d);          \
	c = r1; *(d++) = r0;

#define MULADDC_STOP                        \
}

#endif /* C */


namespace Crypto
{

BigNum::BigNum(void)
	: s(1), n(0), p(NULL)
{
}

BigNum::BigNum(int i)
	: BigNum()
{
	// Sign
	s = (i < 0) ? -1 : 1;

	// Number of limbs
	grow(1);

	// Content of limbs
	p[0] = (i < 0) ? -i : i;
}

BigNum::BigNum(std::string str, int radix)
	: BigNum()
{
	if ( radix < 2 || radix > 16 ) {
		throw BigNum::Exception("Radix not supported");
	}

	if ( str.empty() ) {
		return;
	}

	// Sign
	if ( str[0] == '-' ) {
		s = -1;
		str = str.substr(1);
	}

	if( 16 == radix ) {
		// Number of limbs
		grow(bits_to_limbs(str.length() << 2));

		for ( std::size_t i = 0 ; i < str.length() ; ++i ) {
			uint64_t d = get_digit(str[str.length() - i - 1], radix);
			p[i / (2 * ciL)] |= d << ((i % (2 * ciL)) << 2);
		}
	} else {
		for ( std::size_t i = 0 ; i < str.length() ; ++i ) {
			uint64_t d = get_digit(str[i], radix);

			*this *= radix;

			if ( s < 0 ) {
				*this -= d;
			} else {
				*this += d;
			}
		}
	}
}

BigNum::BigNum(const uint8_t *data, std::size_t data_sz)
	: BigNum()
{
	// Sign
	s = 1;

	// Number of limbs
	for ( std::size_t i = 0 ; i < data_sz ; ++i ) {
		if ( 0x00 != data[i] ) {
			data    += i;
			data_sz -= i;
			break;
		}
	}
	grow(chars_to_limbs(data_sz));

	// Content of limbs
	for ( std::size_t i = 0 ; i < data_sz ; ++i ) {
		p[i / ciL] |= ((uint64_t)data[data_sz - i  - 1]) << ((i % ciL) << 3);
	}
}

BigNum::BigNum(const BigNum &other)
	: BigNum()
{
	if ( other == 0 ) {
		return;
	}

	// Sign
	s = other.s;

	// Number of limbs
	std::size_t i;
	for ( i = other.n - 1 ; i > 0 ; --i ) {
		if ( 0 != other.p[i] ) {
			break;
		}
	}
	++i;
	grow(i);

	// Content of limbs
	memcpy(p, other.p, i * ciL);
}

BigNum::BigNum(BigNum &&other)
	: s(other.s), n(other.n), p(other.p)
{
	// Put other in a valid state for destruction
	other.n = 0;
	other.p = NULL;
}

BigNum&
BigNum::operator=(const BigNum &other)
{
	if ( &other != this ) {
		if ( other == 0 ) {
			*this = BigNum();
		} else {
			// Sign
			s = other.s;

			// Number of limbs
			std::size_t i;
			for ( i = other.n - 1 ; i > 0 ; --i ) {
				if ( 0 != other.p[i] ) {
					break;
				}
			}
			++i;
			grow(i);

			// Content of limbs
			if ( NULL != p ) {
				memset(p, 0x00, n * ciL);
			}
			memcpy(p, other.p, i * ciL);
		}
	}

	return *this;
}

BigNum&
BigNum::operator=(BigNum &&other)
{
	if ( &other != this ) {
		// Sign
		std::swap(s, other.s);

		// Swap only if more limbs in other destination
		if ( other.n >= n ) {
			// Number of limbs
			std::swap(n, other.n);

			// Content of limbs
			std::swap(p, other.p);
		} else {
			if ( NULL != p ) {
				memset(p, 0x00, n * ciL);

				if ( NULL != other.p ) {
					memcpy(p, other.p, other.n * ciL);
				}
			}
		}
	}

	return *this;
}

void
BigNum::safe_cond_assign(const BigNum &other, bool cond)
{
	// Sign
	s = s * (1 - cond) + other.s * cond;

	// Number of limbs
	grow(other.n);

	// Content of limbs
	std::size_t i = 0;
	for ( ; i < other.n ; ++i ) {
		p[i] = p[i] * (1 - cond) + other.p[i] * cond;
	}
	for( ; i < n ; ++i ) {
		p[i] *= (1 - cond);
	}
}

void
BigNum::safe_cond_swap(BigNum &other, bool cond)
{
	if ( *this == other ) {
		return;
	}

	// Sign
	int s   = this->s;
	this->s = this->s * (1 - cond) + other.s * cond;
	other.s = other.s * (1 - cond) +       s * cond;

	// Number of limbs
	this->grow(other.n);
	other.grow(this->n);

	// Content of limbs
	for ( std::size_t i = 0 ; i < this->n ; ++i ) {
		uint64_t t = this->p[i];
		this->p[i] = this->p[i] * (1 - cond) + other.p[i] * cond;
		other.p[i] = other.p[i] * (1 - cond) +          t * cond;
	}
}

BigNum::~BigNum(void)
{
	if ( NULL != p ) {
		zeroize(p, n * ciL);
		delete[] p;
	}

	zeroize(&s, sizeof(s));
	zeroize(&n, sizeof(n));
	zeroize(&p, sizeof(p));
}

bool
BigNum::operator==(const BigNum &other) const
{
	return cmp(other) == 0;
}

bool
BigNum::operator!=(const BigNum &other) const
{
	return cmp(other) != 0;
}

bool
BigNum::operator<(const BigNum &other) const
{
	return cmp(other) < 0;
}

bool
BigNum::operator>(const BigNum &other) const
{
	return cmp(other) > 0;
}

bool
BigNum::operator<=(const BigNum &other) const
{
	return cmp(other) <= 0;
}

bool
BigNum::operator>=(const BigNum &other) const
{
	return cmp(other) >= 0;
}

BigNum
BigNum::operator+(const BigNum &other) const
{
	BigNum result(*this);

	result += other;

	return result;
}

BigNum&
BigNum::operator+=(const BigNum &other)
{
	if ( s * other.s < 0 ) {
		if ( cmp_abs(other) >= 0 ) {
			sub_abs(other);
		} else {
			*this = BigNum(other).sub_abs(*this);
		}
	} else {
		add_abs(other);
	}

	return *this;
}

BigNum&
BigNum::operator++(void)
{
	*this += 1;

	return *this;
}

BigNum
BigNum::operator++(int)
{
	BigNum result(*this);

	++(*this);

	return result;
}

BigNum
BigNum::operator-(const BigNum &other) const
{
	BigNum result(*this);

	result -= other;

	return result;
}

BigNum&
BigNum::operator-=(const BigNum &other)
{
	if ( s * other.s > 0 ) {
		if ( cmp_abs(other) >= 0 ) {
			sub_abs(other);
		} else {
			*this = BigNum(other).sub_abs(*this);
			s *= -1;
		}
	} else {
		add_abs(other);
	}

	return *this;
}

BigNum&
BigNum::operator--(void)
{
	*this -= 1;

	return *this;
}

BigNum
BigNum::operator--(int)
{
	BigNum result(*this);

	--(*this);

	return result;
}

BigNum
BigNum::operator*(const BigNum &other) const
{
	BigNum result(*this);

	result *= other;

	return result;
}

BigNum&
BigNum::operator*=(const BigNum &other)
{
	std::size_t i, j;
	BigNum X;

	for ( i = this->n ; i > 0 ; --i ) {
		if ( 0 != this->p[i - 1] ) {
			break;
		}
	}

	for ( j = other.n ; j > 0 ; --j ) {
		if ( 0 != other.p[j - 1] ) {
			break;
		}
	}

	X.grow(i + j);

	for ( i++ ; j > 0 ; --j ) {
		mul_hlp(i - 1, this->p, X.p + j - 1, other.p[j - 1]);
	}

	X.s = this->s * other.s;
	*this = std::move(X);

	return *this;
}

BigNum
BigNum::operator/(const BigNum &other) const
{
	BigNum result(*this);

	result /= other;

	return result;
}

BigNum&
BigNum::operator/=(const BigNum &other)
{
	auto result = div_mod(other);

	*this = std::move(result.first);

	return *this;
}

BigNum
BigNum::operator%(const BigNum &other) const
{
	BigNum result(*this);

	result %= other;

	return result;
}

BigNum&
BigNum::operator%=(const BigNum &other)
{
	if ( other < 0 ) {
		throw BigNum::Exception("Invalid value for modulus");
	}

	auto result = div_mod(other);
	*this = std::move(result.second);

	while ( *this < 0 ) {
		*this += other;
	}

	while ( *this >= other ) {
		*this -= other;
	}

	return *this;
}

std::pair<BigNum, BigNum>
BigNum::div_mod(const BigNum &other) const
{
	BigNum Q, R, X, Y, Z, T1, T2, T3;
	std::size_t n, t, k;

	if ( other == 0 ) {
		throw BigNum::Exception("Illegal division by 0");
	}

	if ( this->cmp_abs(other) < 0 ) {
		return { 0, *this };
	}

	X = this->abs();
	Y = other.abs();

	Z.grow(this->n + 2);
	T1.grow(2);
	T2.grow(3);
	T3.grow(1);

	k = Y.bitlen() % biL;
	if ( k < biL - 1 ) {
		k = biL - 1 - k;
		X = X << k;
		Y = Y << k;
	} else {
		k = 0;
	}

	n = X.n - 1;
	t = Y.n - 1;
	Y = Y << (biL * (n - t));

	while ( X >= Y ) {
		Z.p[n - t]++;
		X = X - Y;
	}
	Y = Y >> (biL * (n - t));

	for ( std::size_t i = n ; i > t ; --i ) {
		if ( X.p[i] >= Y.p[t] ) {
			Z.p[i - t - 1] = ~0;
		} else {
			Z.p[i - t - 1] = int_div_int(X.p[i], X.p[i - 1], Y.p[t]);
		}

		Z.p[i - t - 1]++;
		do
		{
			Z.p[i - t - 1]--;

			memset(T1.p, 0x00, T1.n * ciL);
			T1.p[0] = (t < 1) ? 0 : Y.p[t - 1];
			T1.p[1] = Y.p[t];

			memset(T3.p, 0x00, T3.n * ciL);
			T3.p[0] = Z.p[i - t - 1];
			T1 = T1 * T3;

			memset(T2.p, 0x00, T2.n * ciL);
			T2.p[0] = (i < 2) ? 0 : X.p[i - 2];
			T2.p[1] = (i < 1) ? 0 : X.p[i - 1];
			T2.p[2] = X.p[i];
		} while ( T1 > T2 );

		memset(T3.p, 0x00, T3.n * ciL);
		T3.p[0] = Z.p[i - t - 1];
		T1 = Y * T3;
		T1 = T1 << (biL * (i - t - 1));
		X = X - T1;

		if ( X < 0 ) {
			T1 = Y;
			T1 = T1 << (biL * (i - t - 1));
			X = X + T1;
			Z.p[i - t - 1]--;
		}
	}

	Q = Z;
	Q.s = this->s * other.s;

	X = X >> k;
	X.s = this->s;
	R = X;

	if ( R == 0 ) {
		R.s = 1;
	}

	return { Q, R };
}

BigNum
BigNum::exp_mod(const BigNum &E, const BigNum &N, BigNum *_RR) const
{
	std::size_t wbits, wsize, one = 1;
	std::size_t i, j, nblimbs;
	std::size_t bufsize, nbits;
	uint64_t ei, mm, state;
	BigNum X, RR, T, W[2 << WINDOW_SIZE];
	int neg;

	if ( N < 0 || 0 == (N.p[0] & 0x01) ) {
		throw BigNum::Exception("Invalid value for modulus");
	}

	if ( E < 0 ) {
		throw BigNum::Exception("Invalid value for exponent");
	}

	// Init temps and window size
	mm = N.mont_init();
	i = E.bitlen();

	wsize = (i > 671) ? 6 : (i > 239) ? 5 :
		(i >  79) ? 4 : (i >  23) ? 3 : 1;

	if ( wsize > WINDOW_SIZE ) {
		wsize = WINDOW_SIZE;
	}

	j = N.n + 1;
	X.grow(j);
	W[1].grow(j);
	T.grow(j * 2);

	// Compensate for negative A (and correct at the end)
	neg = (this->s == -1);

	// If 1st call, pre-compute R^2 mod N
	if ( NULL == _RR || NULL == _RR->p ) {
		RR = 1;
		RR <<= (N.n * 2 * biL);
		RR = RR % N;

		if ( NULL != _RR ) {
			*_RR = RR;
		}
	} else {
		RR = *_RR;
	}

	// W[1] = A * R^2 * R^-1 mod N = A * R mod N
	if ( this->cmp_abs(N) >= 0 ) {
		W[1] = this->abs() % N;
	} else {
		W[1] = this->abs();
	}

	W[1].mont_mul(RR, N, mm, T);

	// X = R^2 * R^-1 mod N = R mod N
	X = RR;
	X.mont_mul(1, N, mm, T);

	if ( wsize > 1 ) {
		// W[1 << (wsize - 1)] = W[1] ^ (wsize - 1)
		j = one << (wsize - 1);

		W[j].grow(N.n + 1);
		W[j] = W[1];

		for ( i = 0 ; i < wsize - 1 ; ++i ) {
			W[j].mont_mul(W[j], N, mm, T);
		}

		// W[i] = W[i - 1] * W[1]
		for ( i = j + 1 ; i < (one << wsize) ; ++i ) {
			W[i].grow(N.n + 1);
			W[i] = W[i - 1];

			W[i].mont_mul(W[1], N, mm, T);
		}
	}

	nblimbs = E.n;
	bufsize = 0;
	nbits   = 0;
	wbits   = 0;
	state   = 0;

	while ( true ) {
		if ( 0 == bufsize ) {
			if ( 0 == nblimbs ) {
				break;
			}

			nblimbs--;
			bufsize = sizeof(uint64_t) << 3;
		}

		bufsize--;
		ei = (E.p[nblimbs] >> bufsize) & 0x01;

		// skip leading 0s
		if ( 0 == ei && 0 == state ) {
			continue;
		}

		if ( 0 == ei && 1 == state ) {
			// out of window, square X
			X.mont_mul(X, N, mm, T);
			continue;
		}

		// add ei to current window
		state = 2;

		nbits++;
		wbits |= ( ei << (wsize - nbits));

		if ( nbits == wsize ) {
			// X = X^wsize R^-1 mod N
			for ( i = 0 ; i < wsize ; ++i ) {
				X.mont_mul(X, N, mm, T);
			}

			// X = X * W[wbits] R^-1 mod N
			X.mont_mul(W[wbits], N, mm, T);

			state--;
			nbits = 0;
			wbits = 0;
		}
	}

	// process the remaining bits
	for ( i = 0 ; i < nbits ; ++i ) {
		X.mont_mul(X, N, mm, T);
		wbits <<= 1;

		if ( 0 != (wbits & (one << wsize)) ){
			X.mont_mul(W[1], N, mm, T);
		}
	}

	// X = A^E * R * R^-1 mod N = A^E mod N
	X.mont_mul(1, N, mm, T);

	if ( neg && 0 != E.n && 0 != (E.p[0] & 0x01) ) {
		X.s = -1;
		X = N + X;
	}

	return X;
}

int
BigNum::sign(void) const
{
	return s;
}

BigNum
BigNum::operator+(void) const
{
	BigNum result(*this);

	return result;
}

BigNum
BigNum::operator-(void) const
{
	BigNum result(*this);

	result.s *= -1;

	return result;
}

BigNum
BigNum::abs(void) const
{
	BigNum result(*this);

	result.s = 1;

	return result;
}

BigNum
BigNum::operator<<(std::size_t shift) const
{
	BigNum result(*this);

	result <<= shift;

	return result;
}

BigNum&
BigNum::operator<<=(std::size_t shift)
{
	std::size_t t, v0, v1;
	uint64_t r0 = 0, r1;

	v0 = shift / biL;
	v1 = shift % biL;

	t = bitlen() + shift;

	if( t > n * biL ) {
		grow(bits_to_limbs(t));
	}

	// shift by count / limb_size
	if ( v0 > 0 ) {
		std::size_t i;
		for ( i = n; i > v0 ; --i ) {
			p[i - 1] = p[i - v0 - 1];
		}

		for ( ; i > 0 ; --i ) {
			p[i - 1] = 0;
		}
	}

	// shift by count % limb_size
	if ( v1 > 0 ) {
		std::size_t i;
		for ( i = v0 ; i < n ; ++i ) {
			r1 = p[i] >> (biL - v1);
			p[i] <<= v1;
			p[i]  |= r0;
			r0 = r1;
		}
	}

	return *this;
}

BigNum
BigNum::operator>>(std::size_t shift) const
{
	BigNum result(*this);

	result >>= shift;

	return result;
}

BigNum&
BigNum::operator>>=(std::size_t shift)
{
	std::size_t t, v0, v1;
	uint64_t r0 = 0, r1;

	v0 = shift / biL;
	v1 = shift % biL;

	t = bitlen();

	if ( shift >= t ) {
		if ( NULL != p ) {
			memset(p, 0x00, n * ciL);
		}

		return *this;
	}

	// shift by count / limb_size
	if ( v0 > 0 ) {
		std::size_t i;
		for ( i = 0 ; i < n - v0 ; ++i ) {
			p[i] = p[i + v0];
		}

		for ( ; i < n ; ++i ) {
			p[i] = 0;
		}
	}

	// shift by count % limb_size
	if ( v1 > 0 ) {
		std::size_t i;
		for ( i = n ; i > 0 ; --i ) {
			r1 = p[i - 1] << (biL - v1);
			p[i - 1] >>= v1;
			p[i - 1]  |= r0;
			r0 = r1;
		}
	}

	return *this;
}

std::size_t
BigNum::bitlen(void) const
{
	std::size_t i, j;

	if ( 0 == n ) {
		return 0;
	}

	for ( i = n - 1 ; i > 0 ; --i ) {
		if ( 0 != p[i] ) {
			break;
		}
	}

	j = biL - clz(p[i]);

	return (i * biL) + j;
}

std::size_t
BigNum::size(void) const
{
	return (*this == 0) ? 1 : (bitlen() + 7) >> 3;
}

std::size_t
BigNum::lsb(void) const
{
	std::size_t count = 0;

	for ( std::size_t i = 0 ; i < n ; ++i ) {
		for ( std::size_t j = 0 ; j < biL ; ++j, ++count ) {
			if ( 0 != ((p[i] >> j) & 0x01) ) {
				return count;
			}
		}
	}

	return 0;
}

int
BigNum::get_bit(std::size_t pos) const
{
	if( n * biL <= pos ) {
		return 0;
	}

	return (p[pos / biL] >> (pos % biL)) & 0x01;
}

void
BigNum::set_bit(std::size_t pos, int flag)
{
	std::size_t off = pos / biL;
	std::size_t idx = pos % biL;
	uint64_t val    = flag ? 0x01 : 0x00;

	if ( n * biL <= pos ) {
		if ( 0 == val ) {
			return;
		}

		grow(off + 1);
	}

	p[off] &= ~(((uint64_t)0x01) << idx);
	p[off] |= val << idx;
}

BigNum
BigNum::gcd(const BigNum &lhs, const BigNum &rhs)
{
	std::size_t lz, lzt;
	BigNum TA, TB;

	TA = lhs;
	TB = rhs;

	lz  = TA.lsb();
	lzt = TB.lsb();

	if ( lzt < lz ) {
		lz = lzt;
	}

	TA >>= lz;
	TB >>= lz;

	TA.s = TB.s = 1;

	while ( TA != 0 ) {
		TA >>= TA.lsb();
		TB >>= TB.lsb();

		if ( TA >= TB ) {
			TA.sub_abs(TB);
			TA >>= 1;
		} else {
			TB.sub_abs(TA);
			TB >>= 1;
		}
	}

	return TB << lz;
}

BigNum
BigNum::lcm(const BigNum &lhs, const BigNum &rhs)
{
	return (lhs * rhs) / gcd(lhs, rhs);
}

BigNum
BigNum::inv(const BigNum &other) const
{
	BigNum G, TA, TU, U1, U2, TB, TV, V1, V2;

	if ( other <= 1 ) {
		throw BigNum::Exception("Invalid value for inverse");
	}

	G = gcd(*this, other);

	if ( G != 1 ) {
		return BigNum(0);
	}

	TU = TA = *this % other;
	TV = TB = other;
	U1 = V2 = 1;
	U2 = V1 = 0;

	do {
		while ( 0 == (TU.p[0] & 0x01) ) {
			TU >>= 1;

			if ( (0 != (U1.p[0] & 0x01)) || (0 != (U2.p[0] & 0x01)) ) {
				U1 += TB;
				U2 -= TA;
			}

			U1 >>= 1;
			U2 >>= 1;
		}

		while ( 0 == (TV.p[0] & 0x01) ) {
			TV >>= 1;

			if ( (0 != (V1.p[0] & 0x01)) || (0 != (V2.p[0] & 0x01)) ) {
				V1 += TB;
				V2 -= TA;
			}

			V1 >>= 1;
			V2 >>= 1;
		}

		if ( TU >= TV ) {
			TU -= TV;
			U1 -= V1;
			U2 -= V2;
		} else {
			TV -= TU;
			V1 -= U1;
			V2 -= U2;
		}
	} while ( TU != 0 );

	while ( V1 < 0 ) {
		V1 += other;
	}

	while ( V1 >= other ) {
		V1 -= other;
	}

	return V1;
}

bool
BigNum::is_prime(int (*f_rng)(void*, uint8_t*, std::size_t), void *p_rng) const
{
	bool result = false;
	BigNum X(this->abs());

	// Perform basic checks
	if ( X == 0 ) { return false; }
	if ( X == 1 ) { return false; }
	if ( X == 2 ) { return true; }

	switch ( X.check_small_factors() ) {
		case CRYPTO_BIGNUM_SUCCESS:
			// Check with Rabin-Miller test
			result = (0 == X.miller_rabin(f_rng, p_rng));
			break;
		case CRYPTO_BIGNUM_SMALL_PRIME:
			// Guaranteed to be prime
			result = true;
			break;
		default:
			// Guaranteed to be composite
			result = false;
			break;
	}

	return result;
}

BigNum
BigNum::gen_prime(std::size_t nbits, int (*f_rng)(void *, uint8_t*, std::size_t), void *p_rng, bool dh_flag)
{
	std::size_t k, n;
	uint64_t r;
	BigNum X, Y;

	if ( nbits < 3 || nbits > MAX_BITS ) {
		throw BigNum::Exception("Requested size is not supported");
	}

	n = bits_to_limbs(nbits);

	std::size_t seed_sz = n * ciL;
	std::unique_ptr<uint8_t[]> seed(new uint8_t[seed_sz]);

	if ( 0 != f_rng(p_rng, seed.get(), seed_sz) ) {
		throw BigNum::Exception("Random number generator failure");
	}

	X = BigNum(seed.get(), seed_sz);

	k = X.bitlen();
	if ( k > nbits ) {
		X >>= k - nbits + 1;
	}
	X.set_bit(nbits - 1, 0x01);
	X.p[0] |= 0x01;

	if ( ! dh_flag ) {
		while ( ! X.is_prime(f_rng, p_rng) ) {
			X += 2;
		}
	} else {
		/*
		 * An necessary condition for Y and X = 2Y + 1 to be prime
		 * is X = 2 mod 3 (which is equivalent to Y = 2 mod 3).
		 * Make sure it is satisfied, while keeping X = 3 mod 4
		 */

		X.p[0] |= 2;

		r = (X % 3).limb();
		if      ( 0 == r ) { X += 8; }
		else if ( 1 == r ) { X += 4; }

		// Set Y = (X-1) / 2, which is X / 2 because X is odd
		Y = X;
		Y >>= 1;

		while ( true ) {
			/*
			 * First, check small factors for X and Y
			 * before doing Miller-Rabin on any of them
			 */
			if (    (0 == X.check_small_factors())
			     && (0 == Y.check_small_factors())
			     && (0 == X.miller_rabin(f_rng, p_rng))
			     && (0 == Y.miller_rabin(f_rng, p_rng)) ) {
				break;
			}

			/*
			 * Next candidates. We want to preserve Y = (X-1) / 2 and
			 * Y = 1 mod 2 and Y = 2 mod 3 (eq X = 3 mod 4 and X = 2 mod 3)
			 * so up Y by 6 and X by 12.
			 */
			X += 12;
			Y +=  6;
		}
	}

	zeroize(seed.get(), seed_sz);

	return X;
}

uint64_t
BigNum::limb(std::size_t pos) const
{
	return pos < n ? p[pos] : 0;
}

std::string
BigNum::to_string(int radix, bool lowercase) const
{
	std::string result;

	if ( radix < 2 || radix > 16 ) {
		throw BigNum::Exception("Radix not supported");
	}

	if ( 16 == radix ) {
		bool first = true;

		if ( *this == 0 ) {
			result = "00";
		} else {
			for ( std::size_t i = n ; i > 0 ; --i ) {
				for ( std::size_t j = ciL ; j > 0 ; --j ) {
					int c = (p[i - 1] >> ((j - 1) << 3)) & 0xFF;

					if ( 0 == c && first && 2 != (i + j) ) {
						continue;
					}

					result += "0123456789ABCDEF"[c / 16];
					result += "0123456789ABCDEF"[c % 16];
					first = false;
				}
			}
		}
	} else {
		if ( *this == 0 ) {
			result = "0";
		} else {
			BigNum T = this->abs();
			BigNum R = 0;
			uint64_t r = 0;

			while ( T != 0 ) {
				R = T % radix;
				T = T / radix;
				r = R.limb();

				int c = r + ((r < 10) ? 0x30 : 0x37);
				result = ((char)c) + result;
			}
		}
	}

	// Sign
	if ( s < 0 ) {
		result = '-' + result;
	}

	// Normalize case
	for ( auto &c : result ) {
		c = lowercase ? tolower(c) : toupper(c);
	}

	return result;
}

int
BigNum::to_binary(uint8_t *data, std::size_t &data_sz) const
{
	std::size_t need_sz;

	need_sz = size();
	if ( data_sz < need_sz ) {
		data_sz = need_sz;
		return CRYPTO_BIGNUM_INVALID_LENGTH;
	}

	data_sz = need_sz;
	memset(data, 0x00, data_sz);

	bool first = true;
	for ( std::size_t i = n ; i > 0 ; --i ) {
		for ( std::size_t j = ciL ; j > 0 ; --j ) {
			int c = (p[i - 1] >> ((j - 1) << 3)) & 0xFF;

			if ( 0 == c && first && 2 != (i + j) ) {
				continue;
			}

			*data = (uint8_t)c;
			++data;
			first = false;
		}
	}

	return CRYPTO_BIGNUM_SUCCESS;
}

void
BigNum::grow(std::size_t new_size)
{
	uint64_t *tmp = NULL;

	if ( new_size > MAX_LIMBS ) {
		throw BigNum::Exception("Memory allocation failed");
	}

	if ( n < new_size ) {
		tmp = new uint64_t[new_size];

		memset(tmp, 0x00, new_size * ciL);

		if ( NULL != p ) {
			memcpy(tmp, p, n * ciL);

			zeroize(p, n * ciL);
			delete[] p;
		}

		n = new_size;
		p = tmp;
	}
}

void
BigNum::zeroize(void *v, std::size_t n)
{
	volatile uint8_t *p = static_cast<uint8_t*>(v);

	while ( n-- ) {
		*p++ = 0x00;
	}
}

std::size_t
BigNum::clz(uint64_t x)
{
	std::size_t j;
	uint64_t mask = ((uint64_t)1) << (biL - 1);

	for ( j = 0 ; j < biL ; ++j ) {
		if ( x & mask ) {
			break;
		}

		mask >>= 1;
	}

	return j;
}

std::size_t
BigNum::bits_to_limbs(std::size_t i)
{
	return (i / biL) + ((i % biL) != 0);
}

std::size_t
BigNum::chars_to_limbs(std::size_t i)
{
	return (i / ciL) + ((i % ciL) != 0);
}

uint64_t
BigNum::get_digit(char c, int radix)
{
	uint64_t result = 255;

	if ( c >= 0x30 && c <= 0x39 ) { result = c - 0x30; }
	if ( c >= 0x41 && c <= 0x46 ) { result = c - 0x37; }
	if ( c >= 0x61 && c <= 0x66 ) { result = c - 0x57; }

	if ( result >= (uint64_t)radix ) {
		throw BigNum::Exception("Invalid character");
	}

	return result;
}

int
BigNum::cmp(const BigNum &other) const
{
	std::size_t i, j;

	for ( i = n ; i > 0 ; --i ) {
		if ( 0 != p[i - 1] ) {
			break;
		}
	}

	for ( j = other.n ; j > 0 ; --j ) {
		if ( 0 != other.p[j - 1] ) {
			break;
		}
	}

	if ( 0 == i && 0 == j ) {
		return 0;
	}

	if ( i > j ) { return        s; }
	if ( i < j ) { return -other.s; }

	if ( s > 0 && other.s < 0 ) { return  1; }
	if ( s < 0 && other.s > 0 ) { return -1; }

	for ( ; i > 0 ; --i ) {
		if ( p[i - 1] > other.p[i - 1] ) { return  s; }
		if ( p[i - 1] < other.p[i - 1] ) { return -s; }
	}

	return 0;
}

int
BigNum::cmp_abs(const BigNum &other) const
{
	std::size_t i, j;

	for ( i = n ; i > 0 ; --i ) {
		if ( 0 != p[i - 1] ) {
			break;
		}
	}

	for ( j = other.n ; j > 0 ; --j ) {
		if ( 0 != other.p[j - 1] ) {
			break;
		}
	}

	if ( 0 == i && 0 == j ) {
		return 0;
	}

	if ( i > j ) { return  1; }
	if ( j > i ) { return -1; }

	for ( ; i > 0; --i ) {
		if ( p[i - 1] > other.p[i - 1] ) { return  1; }
		if ( p[i - 1] < other.p[i - 1] ) { return -1; }
	}

	return 0;
}

BigNum&
BigNum::add_abs(const BigNum &other)
{
	std::size_t i, j;
	const BigNum *B = &other;

	// Number of limbs
	for ( j = B->n ; j > 0 ; --j ) {
		if ( 0 != B->p[j - 1] ) {
			break;
		}
	}

	grow(j);

	// Content of limbs
	uint64_t tmp, c = 0;
	for ( i = 0 ; i < j ; ++i ) {
		// Save limb of B as we might have &other == this
		tmp = B->p[i];
		// Add carry
		p[i] += c;
		c = (p[i] < c);
		// Add value
		p[i] += tmp;
		c += (p[i] < tmp);
	}

	while ( 0 != c ) {
		if ( n <= i ) {
			grow(i + 1);
		}

		// Add carry
		p[i] += c;
		c = (p[i] < c);
		++i;
	}

	return *this;
}

BigNum&
BigNum::sub_abs(const BigNum &other)
{
	std::size_t i;
	const BigNum *B = &other;

	// Number of limbs
	for ( i = B->n ; i > 0 ; --i ) {
		if ( 0 != B->p[i - 1] ) {
			break;
		}
	}

	// Content
	sub_hlp(i, B->p, p);

	return *this;
}

void
BigNum::sub_hlp(std::size_t n, uint64_t *s, uint64_t *d)
{
	std::size_t i;
	uint64_t tmp, c, z;

	for ( i = c = 0 ; i < n ; ++i, ++s, ++d ) {
		// Save *s as s could be same as d
		tmp = *s;
		z = (*d < c);       *d -= c;
		c = (*d < tmp) + z; *d -= tmp;
	}

	while ( 0 != c ) {
		z = (*d < c); *d -= c;
		c = z; i++; d++;
	}
}

void
BigNum::mul_hlp(std::size_t i, uint64_t *s, uint64_t *d, uint64_t b)
{
	uint64_t c = 0, t = 0;

#if defined(MULADDC_HUIT)
	for ( ; i >= 8 ; i -= 8 ) {
		MULADDC_INIT
		MULADDC_HUIT
		MULADDC_STOP
	}

	for ( ; i > 0 ; i-- ) {
		MULADDC_INIT
		MULADDC_CORE
		MULADDC_STOP
	}
#else /* MULADDC_HUIT */
	for ( ; i >= 16 ; i -= 16 ) {
		MULADDC_INIT
		MULADDC_CORE   MULADDC_CORE
		MULADDC_CORE   MULADDC_CORE
		MULADDC_CORE   MULADDC_CORE
		MULADDC_CORE   MULADDC_CORE

		MULADDC_CORE   MULADDC_CORE
		MULADDC_CORE   MULADDC_CORE
		MULADDC_CORE   MULADDC_CORE
		MULADDC_CORE   MULADDC_CORE
		MULADDC_STOP
	}

	for ( ; i >= 8 ; i -= 8 ) {
		MULADDC_INIT
		MULADDC_CORE   MULADDC_CORE
		MULADDC_CORE   MULADDC_CORE

		MULADDC_CORE   MULADDC_CORE
		MULADDC_CORE   MULADDC_CORE
		MULADDC_STOP
	}

	for ( ; i > 0 ; i-- ) {
		MULADDC_INIT
		MULADDC_CORE
		MULADDC_STOP
	}
#endif /* MULADDC_HUIT */

	t++;

	do {
		*d += c; c = ( *d < c ); d++;
	} while ( c != 0 );
}

uint64_t
BigNum::int_div_int(uint64_t u1, uint64_t u0, uint64_t d)
{
	const uint64_t radix = ((uint64_t)1) << biH;
	const uint64_t uint_halfword_mask = (((uint64_t) 1) << biH) - 1;
	uint64_t d0, d1, q0, q1, rAX, r0, quotient;
	uint64_t u0_msw, u0_lsw;
	std::size_t s;

	// Check for overflow
	if ( 0 == d || u1 >= d ) {
		return ~((uint64_t)0);
	}

	/*
	 * Algorithm D, Section 4.3.1 - The Art of Computer Programming
	 *   Vol. 2 - Seminumerical Algorithms, Knuth
	 */

	// Normalize the divisor, d, and dividend, u0, u1
	s = clz(d);
	d <<= s;

	u1 <<= s;
	u1 |= (u0 >> (biL - s)) & (-((int64_t)s) >> (biL - 1));
	u0 <<= s;

	d1 = d >> biH;
	d0 = d & uint_halfword_mask;

	u0_msw = u0 >> biH;
	u0_lsw = u0 & uint_halfword_mask;

	// Find the first quotient and remainder
	q1 = u1 / d1;
	r0 = u1 - d1 * q1;

	while ( q1 >= radix || (q1 * d0 > radix * r0 + u0_msw) ) {
		q1 -= 1;
		r0 += d1;

		if ( r0 >= radix ) { break; }
	}

	rAX = (u1 * radix) + (u0_msw - q1 * d);
	q0  = rAX / d1;
	r0  = rAX - q0 * d1;

	while ( q0 >= radix || (q0 * d0 > radix * r0 + u0_lsw) ) {
		q0 -= 1;
		r0 += d1;

		if ( r0 >= radix ) { break; }
	}

	quotient = q1 * radix + q0;

	return quotient;
}

uint64_t
BigNum::mont_init(void) const
{
	uint64_t x, m0;

	x = m0 = this->p[0];
	x += (( m0 + 2) & 4 ) << 1;

	for ( std::size_t i = biL ; i >= 8 ; i /= 2 ) {
		x *= (2 - ( m0 * x ));
	}

	return ~x + 1;
}

// Montgomery multiplication: Q = A * B * R^-1 mod N  (HAC 14.36)
void
BigNum::mont_mul(const BigNum &B, const BigNum &N, uint64_t mm, const BigNum &T)
{
	std::size_t i, n, m;
	uint64_t u0, u1, *d;

	if ( T.n < N.n + 1 || NULL == T.p ) {
		throw BigNum::Exception("Invalid value");
	}

	memset(T.p, 0x00, T.n * ciL);

	d = T.p;
	n = N.n;
	m = (B.n < n) ? B.n : n;

	for ( i = 0 ; i < n ; ++i ) {
		// T = (T + u0*B + u1*N) / 2^biL
		u0 = this->p[i];
		u1 = (d[0] + u0 * B.p[0]) * mm;

		mul_hlp(m,     B.p, d, u0);
		mul_hlp(n, N.p, d, u1);

		*d++ = u0; d[n + 1] = 0;
	}

	memcpy(this->p, d, (n + 1) * ciL);

	if ( this->cmp_abs(N) >= 0 ) {
		sub_hlp(n, N.p, this->p);
	} else {
		// prevent timing attacks
		sub_hlp(n, this->p, T.p);
	}
}

int
BigNum::check_small_factors(void) const
{
	static const std::vector<int> small_primes = {
		2,   3,   5,   7,  11,  13,  17,  19,  23,  29,
		31,  37,  41,  43,  47,  53,  59,  61,  67,  71,
		73,  79,  83,  89,  97, 101, 103, 107, 109, 113,
		127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
		179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
		233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
		283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
		353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
		419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
		467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
		547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
		607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
		661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
		739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
		811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
		877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
		947, 953, 967, 971, 977, 983, 991, 997
	};

	if ( 0 == (p[0] & 0x01) ) {
		return CRYPTO_BIGNUM_PRIME_NOT_ACCEPTABLE;
	}

	for ( auto sp : small_primes ) {
		if (  *this == sp       ) { return CRYPTO_BIGNUM_SMALL_PRIME; }
		if ( (*this %  sp) == 0 ) { return CRYPTO_BIGNUM_PRIME_NOT_ACCEPTABLE; }
	}

	return CRYPTO_BIGNUM_SUCCESS;
}

int
BigNum::miller_rabin(int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) const
{
	BigNum W, R, A, RR;
	std::size_t lsb, bl, t, j, k;
	uint8_t data[MAX_BITS / 8];
	std::size_t data_sz = this->n * ciL;

	W   = *this - 1;
	lsb = W.lsb();
	R   = W >> lsb;

	bl = this->bitlen();

	// HAC, table 4.4
	t = ((bl >= 1300) ?  2 : (bl >=  850) ?  3 :
			(bl >=  650) ?  4 : (bl >=  350) ?  8 :
			(bl >=  250) ? 12 : (bl >=  150) ? 18 : 27);

	for ( std::size_t i = 0 ; i < t ; ++i ) {
		// pick a random A, 1 < A < |X| - 1
		if ( 0 != f_rng(p_rng, data, data_sz) ) {
			throw BigNum::Exception("Random number generator failure");
		}
		A = BigNum(data, data_sz);

		if ( A >= W ) {
			j = A.bitlen() - W.bitlen();
			A >>= (j + 1);
		}

		A.p[0] |= 3;

		int count = 0;
		do {
			if ( 0 != f_rng(p_rng, data, data_sz) ) {
				throw BigNum::Exception("Random number generator failure");
			}
			A = BigNum(data, data_sz);

			j = A.bitlen();
			k = W.bitlen();

			if ( j > k ) {
				A >>= (j - k);
			}

			if ( count++ > 30 ) {
				return CRYPTO_BIGNUM_PRIME_NOT_ACCEPTABLE;
			}
		} while ( (A >= W) || (A <= 1) );

		// A = A^R mod |X|
		A = A.exp_mod(R, *this, &RR);

		if ( A == W || A == 1 ) {
			continue;
		}

		j = 1;
		while ( j < lsb && A != W ) {
			// A = A * A mod |X|
			A = (A * A) % *this;

			if ( A == 1 ) {
				break;
			}

			++j;
		}

		// not prime if A != |X| - 1 or A == 1
		if ( A != W || A == 1 ) {
			return CRYPTO_BIGNUM_PRIME_NOT_ACCEPTABLE;
		}
	}

	return CRYPTO_BIGNUM_SUCCESS;
}

}
