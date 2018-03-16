#ifndef CRYPTO_RSA_H
#define CRYPTO_RSA_H

#include "crypto/BigNum.hpp"

#include <stdexcept>

#include <utility>

#include <cstring>

namespace Crypto
{

class RSA
{
	public:
		class RSAPublicKey
		{
			public:
				RSAPublicKey(const BigNum&, const BigNum&);
				RSAPublicKey(const uint8_t*, std::size_t);

				bool operator==(const RSAPublicKey&) const;

				int to_binary(uint8_t*, std::size_t&) const;

				bool is_valid(void) const;
				std::size_t bitlen(void) const;

				friend RSA;
			protected:
				BigNum n;
				BigNum e;
		};

		class RSAPrivateKey
		{
			public:
				RSAPrivateKey(const BigNum&, const BigNum&, const BigNum&, bool = true);
				RSAPrivateKey(const BigNum&, const BigNum&,
						const BigNum&,const BigNum&, const BigNum&,
						const BigNum&, const BigNum&, const BigNum&);
				RSAPrivateKey(const uint8_t*, std::size_t);

				bool operator==(const RSAPrivateKey&) const;

				int to_binary(uint8_t*, std::size_t&) const;

				bool is_valid(int (*)(void *, uint8_t*, std::size_t) = NULL, void* = NULL) const;
				std::size_t bitlen(void) const;

				friend RSA;
			protected:
				BigNum n;
				BigNum e;
				BigNum d;
				BigNum p;
				BigNum q;
				BigNum dp;
				BigNum dq;
				BigNum qp;
		};

		/* Key pair operations */
		static std::pair<RSAPublicKey, RSAPrivateKey> gen_keypair(int (*)(void *, uint8_t*, std::size_t), void*,
				std::size_t, const BigNum&);

		static bool is_valid(const std::pair<const RSAPublicKey&, const RSAPrivateKey&>&,
				int (*)(void *, uint8_t*, std::size_t) = NULL, void* = NULL);

		/* Textbook RSA */
		static inline int RSAEP(const RSAPublicKey &pubKey, const uint8_t *input, std::size_t input_sz,
				uint8_t *output, std::size_t &output_sz)
		{
			return Encrypt(pubKey, input, input_sz, output, output_sz);
		}

		static inline int RSADP(const RSAPrivateKey &privKey, const uint8_t *input, std::size_t input_sz,
				uint8_t *output, std::size_t &output_sz)
		{
			return Decrypt(privKey, input, input_sz, output, output_sz);
		}

		static inline int RSASP1(const RSAPrivateKey &privKey, const uint8_t *input, std::size_t input_sz,
				uint8_t *output, std::size_t &output_sz)
		{
			return Decrypt(privKey, input, input_sz, output, output_sz);
		}

		static inline int RSAVP1(const RSAPublicKey &pubKey, const uint8_t *input, std::size_t input_sz,
				uint8_t *output, std::size_t &output_sz)
		{
			return Encrypt(pubKey, input, input_sz, output, output_sz);
		}

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const int CRYPTO_RSA_SUCCESS          = 0x00;
		static const int CRYPTO_RSA_INVALID_LENGTH   = 0x01;
		static const int CRYPTO_RSA_OUT_OF_RANGE     = 0x02;
	protected:
		static void zeroize(void *v, std::size_t n)
		{
			volatile uint8_t *p = static_cast<uint8_t*>(v);

			while ( n-- ) {
				*p++ = 0x00;
			}
		}

		static int Encrypt(const RSAPublicKey&, const uint8_t*, std::size_t, uint8_t*, std::size_t&);
		static int Decrypt(const RSAPrivateKey&, const uint8_t*, std::size_t, uint8_t*, std::size_t&);
};

}

#endif
