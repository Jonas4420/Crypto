#include "crypto/Utils.hpp"
#include "crypto/BigNum.hpp"

namespace Crypto
{

BigNum::BigNum(void)
	: s(1), n(0), p(NULL)
{
}

BigNum::BigNum(int64_t z)
	: BigNum()
{
	// Sign
	s = (z < 0) ? -1 : 1;

	// Number of limbs
	grow(1);

	// Content of limbs
	p[0] = (z < 0) ? -z : z;
}

BigNum::BigNum(const uint8_t* data, std::size_t data_sz)
	: BigNum()
{
	// Sign
	s = 1;

	// Number of limbs
	for ( std::size_t i = 0 ; i < data_sz ; ++i ) {
		if ( 0 != data[i] ) {
			data    += i;
			data_sz -= i;
			break;
		}
	}
	grow(chars_to_limbs(data_sz));

	// Content of limbs
	memset(p, 0, n * ciL);
	for ( std::size_t i = 0 ; i < data_sz ; ++i ) {
		p[i / ciL] |= ((uint64_t)data[data_sz - i  - 1]) << ((i % ciL) << 3);
	}
}

BigNum::BigNum(std::string str, uint8_t radix)
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

		// Content of limbs
		memset(p, 0, n * ciL);
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

BigNum::BigNum(const BigNum& other)
	: BigNum()
{
	// Sign
	s = other.s;

	// Number of limbs
	grow(other.n);

	// Content of limbs
	if ( NULL != p ) {
		memset(p, 0x00, n * ciL);
	}
	memcpy(p, other.p, other.n * ciL);
}

BigNum::BigNum(BigNum&& other)
	: s(other.s), n(other.n), p(other.p)
{
	// Put other in a valid state for destruction
	other.n = 0;
	other.p = NULL;
}

BigNum&
BigNum::operator=(const BigNum& other)
{
	if ( &other != this ) {
		// Sign
		s = other.s;

		// Number of limbs
		grow(other.n);

		// Content of limbs
		if ( NULL != p ) {
			memset(p, 0x00, n * ciL);
		}
		memcpy(p, other.p, other.n * ciL);
	}

	return *this;
}

BigNum&
BigNum::operator=(BigNum&& other)
{
	if ( &other != this ) {
		// Sign
		std::swap(s, other.s);

		// Number of limbs
		std::swap(n, other.n);

		// Content of limbs
		std::swap(p, other.p);
	}

	return *this;
}

void
BigNum::safe_cond_assign(const BigNum& other, bool cond)
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
BigNum::safe_cond_swap(BigNum& other, bool cond)
{
	if ( *this == other ) {
		return;
	}

	// Sign
	int8_t s = this->s;
	this->s  = this->s * (1 - cond) + other.s * cond;
	other.s  = other.s * (1 - cond) +       s * cond;

	// Number of limbs
	this->grow(other.n);
	other.grow(this->n);

	// Content of limbs
	for ( std::size_t i = 0 ; i < this->n ; ++i ) {
		uint64_t tmp = this->p[i];

		this->p[i] = this->p[i] * (1 - cond) + other.p[i] * cond;
		other.p[i] = other.p[i] * (1 - cond) +        tmp * cond;
	}
}

BigNum::~BigNum(void)
{
	if ( NULL != p ) {
		Utils::zeroize(p, n * ciL);
		delete[] p;
	}

	s = 1;
	n = 0;
	p = NULL;
}

bool
BigNum::operator==(const BigNum& other) const
{
	return cmp(other) == 0;
}

bool
BigNum::operator!=(const BigNum& other) const
{
	return cmp(other) != 0;
}

bool
BigNum::operator<(const BigNum& other) const
{
	return cmp(other) < 0;
}

bool
BigNum::operator>(const BigNum& other) const
{
	return cmp(other) > 0;
}

bool
BigNum::operator<=(const BigNum& other) const
{
	return cmp(other) <= 0;
}

bool
BigNum::operator>=(const BigNum& other) const
{
	return cmp(other) >= 0;
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
		memset(p, 0, n * ciL);

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

int8_t
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
BigNum::operator+(const BigNum& other) const
{
	BigNum result(*this);

	result += other;

	return result;
}

BigNum&
BigNum::operator+=(const BigNum& other)
{
	if ( s * other.s < 0 ) {
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
BigNum::operator-(const BigNum& other) const
{
	BigNum result(*this);

	result -= other;

	return result;
}

BigNum&
BigNum::operator-=(const BigNum& other)
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
BigNum::operator*(const BigNum& other) const
{
	BigNum result(*this);

	result *= other;

	return result;
}

BigNum&
BigNum::operator*=(const BigNum& other)
{
	std::size_t i, j;
	BigNum X;
	const BigNum *A = this;
	const BigNum *B = &other;

	// Sign
	X.s = A->s * B->s;

	// Number of limbs
	for ( i = A->n ; i > 0 ; --i ) {
		if ( 0 != A->p[i - 1] ) {
			break;
		}
	}

	for ( j = B->n ; j > 0 ; --j ) {
		if ( 0 != B->p[j - 1] ) {
			break;
		}
	}

	X.grow(i + j);

	// Content of limbs
	memset(X.p, 0, X.n * ciL);

	for ( i++ ; j > 0 ; --j ) {
		mul_hlp(i - 1, A->p, X.p + j - 1, B->p[j - 1]);
	}

	*this = std::move(X);

	return *this;
}

BigNum
BigNum::operator/(const BigNum& other) const
{
	BigNum result(*this);

	result /= other;

	return result;
}

BigNum&
BigNum::operator/=(const BigNum& other)
{
	auto result = div_mod(other);

	*this = std::move(result.first);

	return *this;
}

BigNum
BigNum::operator%(const BigNum& other) const
{
	BigNum result(*this);

	result %= other;

	return result;
}

BigNum&
BigNum::operator%=(const BigNum& other)
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

BigNum
BigNum::exp_mod(const BigNum& E, const BigNum& N, BigNum *_RR) const
{
	BigNum X;
	BigNum A, RR, T, W[2 << WINDOW_SIZE];
	std::size_t wbits, wsize, one = 1;
	std::size_t nblimbs, bufsize, nbits;
	std::size_t i, j;
	uint64_t mm, ei, state;
	bool neg;

	if ( (N < 0) || (0 == (N.p[0] % 2)) ) {
		throw BigNum::Exception("Invalid value for modulus");
	}

	if ( E < 0 ) {
		throw BigNum::Exception("Invalid value for exponent");
	}

	// Fast Montgomery initialization
	mm = mont_init(N);

	// Init temps and window size
	i = N.bitlen();

	wsize = (i > 671) ? 6 : (i > 239) ? 5 :
		(i >  79) ? 4 : (i >  23) ? 3 : 1;

	if ( wsize > WINDOW_SIZE ) {
		wsize = WINDOW_SIZE;
	}

	j = N.n + 1;
	X.grow(j);
	W[1].grow(j);
	T.grow(2 * j);

	neg = (-1 == this->s);
	A   = this->abs();

	// pre-compute R^2 mod N
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
	if ( A >= N ) {
		W[1] = A % N;
	} else {
		W[1] = A;
	}

	W[1] = mont_mul(W[1], RR, N, mm, T);

	// X = R^2 * R^-1 mod N = R mod N
	X = mont_mul(RR, 1, N, mm, T);

	if ( wsize > 1 ) {
		// W[1 << (wsize - 1)] = W[1] ^ (wsize - 1)
		j = one << (wsize - 1);

		W[j].grow(N.n + 1);
		W[j] = W[1];

		for ( std::size_t i = 0 ; i < wsize - 1 ; ++i ) {
			W[j] = mont_mul(W[j], W[j], N, mm, T);
		}

		// W[i] = W[i - 1] * W[1]
		for ( std::size_t i = j + 1 ; i < (one << wsize) ; ++i ) {
			W[i].grow(N.n + 1);
			W[i] = W[i - 1];

			W[i] = mont_mul(W[i], W[1], N, mm, T);
		}
	}

	nblimbs = E.n;
	bufsize = 0;
	nbits   = 0;
	wbits   = 0;
	state   = 0;

	while ( 1 ) {
		if ( 0 == bufsize ) {
			if ( 0 == nblimbs ) {
				break;
			}

			--nblimbs;
			bufsize = sizeof(uint64_t) << 3;
		}

		--bufsize;
		ei = (E.p[nblimbs] >> bufsize) & 0x01;

		// Skip leading 0s
		if ( (0 == ei) && (0 == state) ) {
			continue;
		}

		if ( (0 == ei) && (1 == state) ) {
			// out of window, square X
			X = mont_mul(X, X, N, mm, T);
			continue;
		}

		state = 2;
		++nbits;
		wbits |= (ei << (wsize - nbits));

		if ( nbits == wsize ) {
			// X = X^wsize R^-1 mod N
			for ( std::size_t i = 0 ; i < wsize ; ++i ) {
				X = mont_mul(X, X, N, mm, T);
			}

			// X = X * W[wbits] R^-1 mod N
			X = mont_mul(X, W[wbits], N, mm, T);

			--state;
			nbits = 0;
			wbits = 0;
		}
	}

	// Process the remaining bits
	for ( std::size_t i = 0 ; i < nbits ; ++i ) {
		X = mont_mul(X, X, N, mm, T);

		wbits <<= 1;

		if ( 0 != (wbits & (one << wsize)) ) {
			X = mont_mul(X, W[1], N, mm, T);
		}
	}

	// X = A^E * R * R^-1 mod N = A^E mod N
	X = mont_mul(X, 1, N, mm, T);

	if ( neg && (0 != E.n) && (0 != (E.p[0] & 0x01)) ) {
		X.s = -1;
		X = N + X;
	}

	return X;
}

std::pair<BigNum, BigNum>
BigNum::div_mod(const BigNum& other) const
{
	BigNum X, Y, Z, T1, T2;
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
	Z = 0;
	T1.grow(2);
	T2.grow(3);

	k = Y.bitlen() % biL;

	if ( k < (biL - 1) ) {
		k = biL - 1 - k;
		X <<= k;
		Y <<= k;
	} else {
		k = 0;
	}

	n = X.n - 1;
	t = Y.n - 1;
	Y <<= (biL * (n - t));

	while ( X >= Y ) {
		Z.p[n - t]++;
		X -= Y;
	}
	Y >>= (biL * (n - t));

	for ( std::size_t i = n ; i > t ; --i ) {
		if ( X.p[i] >= Y.p[t] ) {
			Z.p[i - t - 1] = ~0;
		} else {
			Z.p[i - t - 1] = int_div_int(X.p[i], X.p[i - 1], Y.p[t]);
		}

		Z.p[i - t - 1]++;

		do {
			Z.p[i - t - 1]--;

			T1 = 0;
			T1.p[0] = (t < 1) ? 0 : Y.p[t - 1];
			T1.p[1] = Y.p[t];
			T1 *= Z.p[i - t - 1];

			T2 = 0;
			T2.p[0] = (i < 2) ? 0 : X.p[i - 2];
			T2.p[1] = (i < 1) ? 0 : X.p[i - 1];
			T2.p[2] = X.p[i];
		} while ( T1 > T2 );

		T1 = Y * Z.p[i - t - 1];
		T1 <<= (biL * (i - t - 1));
		X -= T1;

		if ( X < 0 ) {
			T1 = Y;
			T1 <<= (biL * (i - t - 1));
			X += T1;
			Z.p[i - t - 1]--;
		}
	}

	Z.s = this->s * other.s;

	X >>= k;
	X.s = this->s;
	if ( X == 0 ) {
		X.s = 1;
	}

	return { Z, X };
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
	return (bitlen() + 7) >> 3;
}

std::size_t
BigNum::lsb(void) const
{
	std::size_t count = 0;

	for ( std::size_t i = 0 ; i < n ; ++i ) {
		for ( std::size_t j = 0 ; j < biL ; ++j, ++count ) {
			if ( 0 != ((p[i] >>j ) & 1) ) {
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

	p[off] &= ~(((uint64_t)0x01)  << idx);
	p[off] |= val << idx;
}

BigNum
BigNum::gcd(const BigNum& other) const
{
	std::size_t lz, lzt;
	BigNum TA, TB;

	TA = *this;
	TB = other;

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
BigNum::lcm(const BigNum& other) const
{
	return (*this * other) / gcd(other);
}

BigNum
BigNum::inv(const BigNum& other) const
{
	BigNum G, TA, TU, U1, U2, TB, TV, V1, V2;

	if ( other <= 1 ) {
		throw BigNum::Exception("Invalid value for inverse");
	}

	G = gcd(other);

	if ( G != 1 ) {
		return BigNum(0);
	}

	TU = TA = *this % other;
	TV = TB = other;
	U1 = V2 = 1;
	U2 = V1 = 0;

	do {
		while ( 0 == (TU.p[0] & 0x01) ) {
			TU >> 1;

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
BigNum::is_prime(int (*f_rng)(void *, uint8_t*, std::size_t), void *p_rng) const
{
	if ( (*this == 0) || (*this == 1) ) {
		throw BigNum::Exception("Invalid value");
	}

	if ( *this == 2 )                 { return true; }
	if ( has_small_factors() )        { return false; }
	if ( miller_rabin(f_rng, p_rng) ) { return false; }

	return true;
}

BigNum
BigNum::gen_prime(std::size_t nbits, int (*f_rng)(void *, uint8_t*, std::size_t), void *p_rng, bool dh_flag)
{
	BigNum X;
	uint8_t data[MAX_BITS / 8];
	std::size_t data_sz, k;

	if ( nbits < 3 || nbits > MAX_BITS ) {
		throw BigNum::Exception("Requested size is supported");
	}

	data_sz = bits_to_limbs(nbits);

	if ( 0 != f_rng(p_rng, data, data_sz * ciL) ) {
		throw BigNum::Exception("Random number generator failure");
	}

	X = BigNum(data, data_sz * ciL);
	k = X.bitlen();

	if ( k > nbits ) {
		X >>= (k - nbits + 1);
	}

	X.set_bit(nbits - 1, 1);
	X.p[0] |= 1;

	if ( ! dh_flag ) {
		while ( X.is_prime(f_rng, p_rng) ) {
			X += 2;
		}
	} else {
		/*
		 * An necessary condition for Y and X = 2Y + 1 to be prime
		 * is X = 2 mod 3 (which is equivalent to Y = 2 mod 3).
		 * Make sure it is satisfied, while keeping X = 3 mod 4
		 */
		BigNum Y;

		X.p[0] |= 2;

		uint64_t r = static_cast<uint64_t>(X % 3);

		if ( 0 == r ) {
			X += 8;
		} else if ( 1 == r ) {
			X += 4;
		}

		// Set Y = (X-1) / 2, which is X / 2 because X is odd
		Y = X >> 1;

		// First, check small factors for X and Y before doing Miller-Rabin on any of them
		while (    X.has_small_factors()
			|| Y.has_small_factors()
			|| X.miller_rabin(f_rng, p_rng)
			|| Y.miller_rabin(f_rng, p_rng) ) {
			/*
			 * Next candidates. We want to preserve Y = (X-1) / 2 and
			 * Y = 1 mod 2 and Y = 2 mod 3 (eq X = 3 mod 4 and X = 2 mod 3)
			 * so up Y by 6 and X by 12.
			 */
			X += 12;
			Y +=  6;
		}
	}

	return X;
}

BigNum::operator uint64_t(void) const
{
	// Check that there is no overflow
	for ( std::size_t i = 1 ; i < n ; ++i ) {
		if ( 0 != p[i] ) {
			throw BigNum::Exception("Integer overflow");
		}
	}

	return n > 0 ? p[0] : 0;
}

std::string
BigNum::str(uint8_t radix, bool lowercase) const
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
				r = static_cast<uint64_t>(R);

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
BigNum::raw(uint8_t* data, std::size_t& data_sz)
{
	std::size_t need_sz;

	need_sz = size();
	if ( data_sz < need_sz ) {
		data_sz = need_sz;
		return CRYPTO_BIGNUM_INVALID_LENGTH;
	}

	bool first = true;
	data_sz = 0;
	for ( std::size_t i = n ; i > 0 ; --i ) {
		for ( std::size_t j = ciL ; j > 0 ; --j ) {
			int c = (p[i - 1] >> ((j - 1) << 3)) & 0xFF;

			if ( 0 == c && first && 2 != (i + j) ) {
				continue;
			}

			*data = (uint8_t)c;
			++data;
			++data_sz;
			first = false;
		}
	}

	return CRYPTO_BIGNUM_SUCCESS;
}

uint64_t
BigNum::get_digit(char c, uint8_t radix)
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
BigNum::cmp(const BigNum& other) const
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
BigNum::cmp_abs(const BigNum& other) const
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

	if ( cmp_abs(other) < 0 ) {
		throw BigNum::Exception("Invalid value");
	}

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

	for ( ; i > 0 ; --i ) {
		MULADDC_INIT
		MULADDC_CORE
		MULADDC_STOP
	}
#else
	for ( ; i >= 16 ; i -= 16 ) {
		MULADDC_INIT
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE

		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_STOP
	}

	for ( ; i >= 8 ; i -= 8 ) {
		MULADDC_INIT
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE

		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_STOP
	}

	for ( ; i > 0 ; --i ) {
		MULADDC_INIT
		MULADDC_CORE
		MULADDC_STOP
	}
#endif /* MULADDC_HUIT */

	++t;

	do {
		*d += c; c = ( *d < c ); d++;
	} while ( c != 0 );
}

uint64_t
BigNum::int_div_int(uint64_t u1, uint64_t u0, uint64_t d, uint64_t *r)
{
	const uint64_t radix              =  ((uint64_t)1) << biH;
	const uint64_t uint_halfword_mask = (((uint64_t)1) << biH) - 1;
	uint64_t d0, d1, q0, q1, rAX, r0;
	uint64_t u0_msw, u0_lsw;
	size_t s;

	 // Check for overflow
	if ( 0 == d || u1 >= d ) {
		if (r != NULL) { *r = ~0; }
		return ~0;
	}

	/*
	 * Algorithm D, Section 4.3.1 - The Art of Computer Programming
	 *   Vol. 2 - Seminumerical Algorithms, Knuth
	 */

	// Normalize the divisor, d, and dividend, u0, u1
	s = clz(d);
	d = d << s;

	u1 = u1 << s;
	u1 |= (u0 >> (biL - s)) & (-(int64_t)s >> (biL - 1));
	u0 =  u0 << s;

	d1 = d >> biH;
	d0 = d & uint_halfword_mask;

	u0_msw = u0 >> biH;
	u0_lsw = u0 & uint_halfword_mask;

	// Find the first quotient and remainder
	q1 = u1 / d1;
	r0 = u1 - d1 * q1;

	while ( q1 >= radix || ((q1 * d0) > (radix * r0 + u0_msw)) ) {
		q1 -= 1;
		r0 += d1;

		if ( r0 >= radix ) { break; }
	}

	rAX = (u1 * radix) + (u0_msw - q1 * d);
	q0  = rAX / d1;
	r0  = rAX - q0 * d1;

	while ( q0 >= radix || ((q0 * d0) > (radix * r0 + u0_lsw)) ) {
		q0 -= 1;
		r0 += d1;

		if ( r0 >= radix ) { break; }
	}

	if ( NULL != r ) {
		*r = (rAX * radix + u0_lsw - q0 * d) >> s;
	}

	return q1 * radix + q0;
}

void
BigNum::grow(std::size_t new_size)
{
    uint64_t *tmp = NULL;

    if ( new_size > MAX_LIMBS ) {
	    throw BigNum::Exception("Memory allocation failed");
    }

    if ( n < new_size ) {
	    try {
		    tmp = new uint64_t[new_size];
		    memset(tmp, 0, new_size * ciL);
		    memcpy(tmp, p, n * ciL);
	    } catch ( const std::bad_alloc& ba ) {
		    throw BigNum::Exception("Memory allocation failed");
	    }

	    if ( NULL != p ) {
		    Utils::zeroize(p, n * ciL);
		    delete[] p;
	    }

	    n = new_size;
	    p = tmp;
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
BigNum::mont_init(const BigNum &N)
{
	uint64_t x, m0;

	m0 = N.p[0];
	x  = m0;
	x += ( ( m0 + 2 ) & 4 ) << 1;

	for ( std::size_t i = biL ; i >= 8 ; i /= 2 ) {
		x *= (2 - (m0 * x));
	}

	return ~x + 1;
}

BigNum
BigNum::mont_mul(const BigNum &A, const BigNum &B, const BigNum &N, uint64_t mm, const BigNum &T)
{
	BigNum result;
	std::size_t n, m;
	uint64_t u0, u1, *d;

	if ( T.n < N.n + 1 || NULL == T.p ) {
		throw BigNum::Exception("Invalid value");
	}

	memset(T.p, 0, T.n * ciL);
	d = T.p;
	n = N.n;
	m = (B.n < n) ? B.n : n;

	for ( std::size_t i = 0 ; i < n ; ++i ) {
		// T = (T + u0*B + u1*N) / 2^biL
		u0 = A.p[i];
		u1 = (d[0] + u0 * B.p[0]) * mm;

		mul_hlp(m, B.p, d, u0);
		mul_hlp(n, N.p, d, u1);

		*d++ = u0;
		d[n + 1] = 0;
	}

	memcpy(A.p, d, (n + 1) * ciL);

	if ( A.cmp_abs(N) >= 0 ) {
		sub_hlp(n, N.p, A.p);
	} else {
		sub_hlp(n, A.p, T.p);
	}

	return result;
}

bool
BigNum::has_small_factors(void) const
{
	static const std::vector<uint64_t> small_prime = {
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

	for ( auto s : small_prime ) {
		if ( *this == s ) {
			return false;
		}

		if ( 0 == static_cast<uint64_t>(*this % s) ) {
			return true;
		}
	}

	return false;
}

// return true if composite
// return false otherwise
bool
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
				return true;
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
			return true;
		}
	}

	return false;
}

}
