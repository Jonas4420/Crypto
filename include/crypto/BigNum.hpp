#ifndef CRYPTO_BIGNUM_H
#define CRYPTO_BIGNUM_H

#define CRYPTO_BIGNUM_HAVE_ASM
#define CRYPTO_BIGNUM_HAVE_SSE2

#include <stdexcept>

#include <string>

#include <cstring>

namespace Crypto
{

class BigNum
{
	public:
		/* Constructors and destructor */
		BigNum(void);                               // Default constructor
		BigNum(int);                                // Constructor from signed int
		BigNum(std::string, int = 10);              // Constructor from string
		BigNum(const uint8_t*, std::size_t);        // Constructor from array of uint8_t
		BigNum(const BigNum&);                      // Copy Constructor
		BigNum(BigNum&&);                           // Move Constructor
		BigNum& operator=(const BigNum&);           // Copy assignment operator
		BigNum& operator=(BigNum&&);                // Move assignment operator

		void safe_cond_assign(const BigNum&, bool); // Safe copy assignment
		void safe_cond_swap(BigNum&, bool);         // Safe swap assigment

		~BigNum(void);                              // Destructor

		/* Comparison operators */
		bool operator==(const BigNum&) const;
		bool operator!=(const BigNum&) const;
		bool operator<(const BigNum&) const;
		bool operator>(const BigNum&) const;
		bool operator<=(const BigNum&) const;
		bool operator>=(const BigNum&) const;

		/* Arithmetic operators */
		BigNum operator+(const BigNum&) const;
		BigNum& operator+=(const BigNum&);
		BigNum& operator++(void);
		BigNum operator++(int);

		BigNum operator-(const BigNum&) const;
		BigNum& operator-=(const BigNum&);
		BigNum& operator--(void);
		BigNum operator--(int);

		BigNum operator*(const BigNum&) const;
		BigNum& operator*=(const BigNum&);

		BigNum operator/(const BigNum&) const;
		BigNum& operator/=(const BigNum&);

		BigNum operator%(const BigNum&) const;
		BigNum& operator%=(const BigNum&);

		std::pair<BigNum, BigNum> div_mod(const BigNum&) const;
		BigNum exp_mod(const BigNum&, const BigNum&, BigNum* = NULL) const;

		/* Sign */
		int sign(void) const;
		BigNum operator+(void) const;
		BigNum operator-(void) const;
		BigNum abs(void) const;
	
		/* Bit operations */
		BigNum operator<<(std::size_t)  const;
		BigNum& operator<<=(std::size_t);

		BigNum operator>>(std::size_t)  const;
		BigNum& operator>>=(std::size_t);

		std::size_t bitlen(void) const;
		std::size_t size(void) const;
		std::size_t lsb(void) const;

		int get_bit(std::size_t) const;
		void set_bit(std::size_t, int);

		/* Modulo operations */
		BigNum gcd(const BigNum&) const;
		BigNum lcm(const BigNum&) const;
		BigNum inv(const BigNum&) const;

		/* Random and prime operations */
		bool is_prime(int (*)(void *, uint8_t*, std::size_t), void*) const;
		static BigNum gen_prime(std::size_t, int (*)(void *, uint8_t*, std::size_t), void*, bool=false);

		/* Cast and dump functions */
		uint64_t limb(std::size_t = 0) const;
		std::string to_string(int = 10, bool = true) const;
		int to_binary(uint8_t*, std::size_t&) const;

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		/* Return codes */
		static const int CRYPTO_BIGNUM_SUCCESS              = 0x00;
		static const int CRYPTO_BIGNUM_INVALID_LENGTH       = 0x01;
		static const int CRYPTO_BIGNUM_SMALL_PRIME          = 0x02;
		static const int CRYPTO_BIGNUM_PRIME_NOT_ACCEPTABLE = 0x03;
	private:
		int         s; // signed integer
		std::size_t n; // number of limbs
		uint64_t   *p; // vector of limbs

		/* Memory helpers */
		void grow(std::size_t);
		static void zeroize(void*, std::size_t);

		static inline std::size_t clz(uint64_t);
		static inline std::size_t bits_to_limbs(std::size_t);
		static inline std::size_t chars_to_limbs(std::size_t);

		/* Conversion helper */
		static inline uint64_t get_digit(char c, int radix);

		/* Comparison helpers */
		int cmp(const BigNum&) const;
		int cmp_abs(const BigNum&) const;

		/* Arithmetic helpers */
		BigNum& add_abs(const BigNum&);
		BigNum& sub_abs(const BigNum&);
		static void sub_hlp(std::size_t, uint64_t*, uint64_t*);
		static void mul_hlp(std::size_t, uint64_t*, uint64_t*, uint64_t);
		static uint64_t int_div_int(uint64_t, uint64_t, uint64_t, uint64_t* = NULL);

		/* Montgommery ladder helpers */
		uint64_t mont_init(void) const;
		void mont_mul(const BigNum&, const BigNum&, uint64_t, const BigNum&);

		/* Random and prime helpers */
		int check_small_factors(void) const;
		int miller_rabin(int (*)(void *, unsigned char *, size_t), void*) const;

		/* Constants */
		static const std::size_t ciL         = sizeof(uint64_t);
		static const std::size_t biL         = ciL << 3;
		static const std::size_t biH         = ciL << 2;
		static const std::size_t MAX_LIMBS   = 10000;
		static const std::size_t WINDOW_SIZE = 6;
		static const std::size_t MAX_BITS    = 8192;
};

}

#endif
