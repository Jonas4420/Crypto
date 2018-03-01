#ifndef CRYPTO_CIPHERMODE_H
#define CRYPTO_CIPHERMODE_H

#include <stdexcept>

#include <cstddef>
#include <cstdint>

namespace Crypto
{

class CipherMode
{
	public:
		virtual ~CipherMode(void) = default;

		virtual int update(const uint8_t*, std::size_t, uint8_t*, std::size_t&) = 0;
		virtual int finish(std::size_t&)                                        = 0;

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const int CRYPTO_CIPHER_MODE_SUCCESS         = 0x00;
		static const int CRYPTO_CIPHER_MODE_INVALID_LENGTH  = 0x01;
		static const int CRYPTO_CIPHER_MODE_NOT_FULL        = 0x02;
		static const int CRYPTO_CIPHER_MODE_LENGTH_LIMIT    = 0x03;
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
