#ifndef CRYPTO_SYMMETRICCIPHER_H
#define CRYPTO_SYMMETRICCIPHER_H

#include <stdexcept>

#include <cstddef>
#include <cstdint>

namespace Crypto
{

class SymmetricCipher
{
	public:
		SymmetricCipher(const uint8_t*, std::size_t) {};
		virtual void encrypt(const uint8_t*, uint8_t*) const = 0;
		virtual void decrypt(const uint8_t*, uint8_t*) const = 0;

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};
	protected:
		void zeroize(void *v, std::size_t n)
		{
			volatile uint8_t *p = static_cast<uint8_t*>(v);

			while ( n-- ) {
				*p++ = 0x00;
			}
		}
};

}

#endif
