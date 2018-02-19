#ifndef CRYPTO_PBKDF2_H
#define CRYPTO_PBKDF2_H

#include "crypto/HMAC.hpp"
#include "crypto/MessageDigest.hpp"
#include "crypto/Utils.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace Crypto
{

template <class MD>
class PBKDF2
{
	public:
		static void derive_key(const uint8_t *password, std::size_t password_sz,
				const uint8_t *salt, std::size_t salt_sz,
				std::size_t iterations,
				uint8_t *key, std::size_t key_sz)
		{
			uint8_t acc[MD::SIZE], buffer[MD::SIZE];
			uint8_t counter[4];
			std::size_t counter_sz = sizeof(counter);

			memset(counter, 0x00, counter_sz);
			counter[3] = 0x01;

			while ( key_sz > 0 ) {
				HMAC<MD> ctx(password, password_sz);
				ctx.update(salt,    salt_sz);
				ctx.update(counter, counter_sz);
				ctx.finish(buffer);

				memcpy(acc, buffer, MD::SIZE);

				for ( std::size_t i = 1 ; i < iterations ; ++i ) {
					//HMAC<MD> ctx(password, password_sz);
					ctx.update(buffer, MD::SIZE);
					ctx.finish(buffer);

					for ( std::size_t j = 0 ; j < MD::SIZE ; ++j ) {
						acc[j] ^= buffer[j];
					}
				}

				for ( std::size_t i = 4 ; i > 0 ; --i ) {
					if ( 0 != ++counter[i - 1] ) {
						break;
					}
				}

				std::size_t write_sz = key_sz < MD::SIZE ? key_sz : MD::SIZE;
				memcpy(key, acc, write_sz);

				key    += write_sz;
				key_sz -= write_sz;
			}
		}

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};
};

}

#endif
