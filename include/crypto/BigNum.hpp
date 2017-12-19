#ifndef CRYTPO_BIGNUM_H
#define CRYTPO_BIGNUM_H

// Define if embedded ASM is available (support for x86 and x86_64 only)
#define CRYPTO_BIGNUM_HAVE_ASM
// Define if SSE2 instruction set is available
#define CRYPTO_BIGNUM_HAVE_SSE2

#include "crypto/BigNum_Mul.hpp"

namespace Crypto
{

class BigNum
{
	public:
		/* Constructors and destructor */
		BigNum(void);                               // Default constructor
		BigNum(int64_t);                            // Constructor from signed 64 bits int
		BigNum(const uint8_t*, std::size_t);        // Constructor from array of uint8_t
		BigNum(std::string, uint8_t = 10);          // Constructor from string
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

		/* Shift operations */
		BigNum operator<<(std::size_t)  const;
		BigNum& operator<<=(std::size_t);

		BigNum operator>>(std::size_t)  const;
		BigNum& operator>>=(std::size_t);

		/* Sign */
		int8_t sign(void) const;
		BigNum operator+(void) const;
		BigNum operator-(void) const;
		BigNum abs(void) const;

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

		BigNum exp_mod(const BigNum&, const BigNum&, BigNum* = NULL) const;
		std::pair<BigNum, BigNum> div_mod(const BigNum&) const;

		/* Bit operations */
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
		explicit operator uint64_t(void) const;
		std::string str(uint8_t = 10) const;
		int raw(uint8_t*, std::size_t&);

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		/* Return codes */
		static const int CRYPTO_BIGNUM_SUCCESS        = 0x00;
		static const int CRYPTO_BIGNUM_INVALID_LENGTH = 0x01;
	private:
		int8_t      s; // signed integer 
		std::size_t n; // number of limbs
		uint64_t   *p; // vector of limbs

		/* Conversion helper */
		static inline uint64_t get_digit(char c, uint8_t radix);
		
		/* Comparison helpers */
		int cmp(const BigNum&) const;
		int cmp_abs(const BigNum&) const;

		/* Arithmetic operation helpers */
		BigNum& add_abs(const BigNum&);
		BigNum& sub_abs(const BigNum&);
		static void sub_hlp(std::size_t, uint64_t*, uint64_t*);
		static void mul_hlp(std::size_t, uint64_t*, uint64_t*, uint64_t);
		static uint64_t int_div_int(uint64_t, uint64_t, uint64_t, uint64_t* = NULL);

		/* Memory helpers */
		void grow(std::size_t);
		void shrink(std::size_t);

		static inline std::size_t clz(uint64_t);
		static inline std::size_t bits_to_limbs(std::size_t);
		static inline std::size_t chars_to_limbs(std::size_t);

		/* Montgommery ladder helpers */
		static uint64_t mont_init(const BigNum&);
		static BigNum mont_mul(const BigNum&, const BigNum&, const BigNum&, uint64_t, const BigNum&);

		/* Random and prime helpers */
		bool has_small_factors(void) const;
		bool miller_rabin(int (*)(void *, unsigned char *, size_t), void*) const;

		/* Constants */
		static const std::size_t ciL         = (sizeof(uint64_t));
		static const std::size_t biL         = (ciL << 3);
		static const std::size_t biH         = (ciL << 2);
		static const std::size_t MAX_LIMBS   = 10000;
		static const std::size_t WINDOW_SIZE = 6;
		static const std::size_t MAX_BITS    = 8192;
};

}

#endif
