#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <vector>

namespace Crypto
{
	class Utils
	{
		public:
			static void zeroize(void *v, std::size_t n);

			static int from_string(const std::string, uint8_t*, std::size_t&);
			static int to_string(const uint8_t*, std::size_t, std::string&);

			static int from_hex(const std::string, uint8_t*, std::size_t&);
			static int to_hex(const uint8_t*, std::size_t, std::string&, bool=true);

			static const uint8_t CRYPTO_UTILS_SUCCESS          = 0x00;
			static const uint8_t CRYPTO_UTILS_INCORRECT_LENGTH = 0x01;

			class Exception : public std::runtime_error
			{
				public:
					Exception(const char *what_arg) : std::runtime_error(what_arg) {}
			};
	};
}

#endif
