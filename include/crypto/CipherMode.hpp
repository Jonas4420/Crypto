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
		virtual int update(const uint8_t*, std::size_t, uint8_t*, std::size_t&) = 0;
		virtual int finish(std::size_t&)                                        = 0;

		static const int CRYPTO_CIPHER_MODE_SUCCESS         = 0x00;
		static const int CRYPTO_CIPHER_MODE_INVALID_LENGTH  = 0x01;
		static const int CRYPTO_CIPHER_MODE_NOT_FULL        = 0x02;
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
