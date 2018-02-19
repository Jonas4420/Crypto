#ifndef CRYPTO_PBKDF1_H
#define CRYPTO_PBKDF1_H

#include "crypto/MessageDigest.hpp"
#include "crypto/Utils.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace Crypto
{

template <class MD>
class PBKDF1
{
	public:
		static void derive_key(const uint8_t *password, std::size_t password_sz,
				const uint8_t *salt, std::size_t salt_sz,
				std::size_t iterations,
				uint8_t *key, std::size_t key_sz)
		{
			uint8_t buffer[MD::SIZE];

			if ( key_sz > MD::SIZE ) {
				throw PBKDF1::Exception("Derived key too long");
			}

			MD ctx;
			ctx.update(password, password_sz);
			ctx.update(salt,     salt_sz);
			ctx.finish(buffer);

			for ( std::size_t i = 0 ; i < iterations ; ++i ) {
				ctx.update(buffer, sizeof(buffer));
				ctx.finish(buffer);
			}

			memcpy(key, buffer, key_sz);
			Utils::zeroize(buffer, sizeof(buffer));
		}

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};
};

}

#endif
