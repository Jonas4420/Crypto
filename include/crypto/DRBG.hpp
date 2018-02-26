#ifndef CRYPTO_DRBG_H
#define CRYPTO_DRBG_H

#include <mutex>

#include <stdexcept>

#include <cstddef>
#include <cstdint>

namespace Crypto
{

class DRBG
{
	public:
		virtual ~DRBG(void) = default;

		virtual int reseed(const uint8_t*, std::size_t, const uint8_t* = NULL, std::size_t = 0) = 0;
		virtual int generate(uint8_t*, std::size_t, const uint8_t* = NULL, std::size_t = 0)     = 0;

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const int CRYPTO_DRBG_SUCCESS         = 0x00;
		static const int CRYPTO_DRBG_RESEED_REQUIRED = 0x01;
		static const int CRYPTO_DRBG_LOCK_FAILED     = 0x02;
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
