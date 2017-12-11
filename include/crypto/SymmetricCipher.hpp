#ifndef CRYPTO_SYMMETRICCIPHER_H
#define CRYPTO_SYMMETRICCIPHER_H

#include <cstddef>
#include <cstdint>

#include "crypto/Padding.hpp"
#include "crypto/Utils.hpp"

namespace Crypto
{

class SymmetricCipher
{
	public:
		SymmetricCipher(const uint8_t*, std::size_t) {};
		virtual void encrypt(const uint8_t*, uint8_t*) = 0;
		virtual void decrypt(const uint8_t*, uint8_t*) = 0;

		static const uint8_t CRYPTO_SYMMETRIC_CIPHER_SUCCESS         = 0x00;
		static const uint8_t CRYPTO_SYMMETRIC_CIPHER_INVALID_LENGTH  = 0x01;

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const uint8_t CRYPTO_SYMMETRIC_CIPHER_NOT_FULL        = 0x02;
};

}

#endif
