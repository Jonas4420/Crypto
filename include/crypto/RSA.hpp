#ifndef CRYPTO_RSA_H
#define CRYPTO_RSA_H

#include "crypto/BigNum.hpp"

#include <stdexcept>

#include <utility>

#include <cstring>

namespace Crypto
{

class RSAPublicKey;
class RSAPrivateKey;
class RSA;

class RSAPublicKey
{
	public:
		RSAPublicKey(const BigNum&, const BigNum&);
		RSAPublicKey(const uint8_t*, std::size_t);

		bool operator==(const RSAPublicKey&) const;
		bool operator!=(const RSAPublicKey&) const;

		int to_binary(uint8_t*, std::size_t&) const;

		bool is_valid(void) const;

		friend RSA;
	private:
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
		bool operator!=(const RSAPrivateKey&) const;

		int to_binary(uint8_t*, std::size_t&) const;

		bool is_valid(int (*)(void *, uint8_t*, std::size_t) = NULL, void* = NULL) const;

		friend RSA;
	private:
		BigNum n;
		BigNum e;
		BigNum d;
		BigNum p;
		BigNum q;
		BigNum dp;
		BigNum dq;
		BigNum qp;
};

class RSA
{
	public:
		static std::pair<RSAPublicKey, RSAPrivateKey> gen_keypair(int (*)(void *, uint8_t*, std::size_t), void*,
				std::size_t, const BigNum&);
		static bool is_valid(const RSAPublicKey&, const RSAPrivateKey&);

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const int CRYPTO_RSA_SUCCESS             = 0x00;
		static const int CRYPTO_RSA_INVALID_LENGTH      = 0x01;
	private:
};

}

#endif
