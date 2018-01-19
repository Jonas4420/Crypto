#ifndef CRYPTO_BASE64_H
#define CRYPTO_BASE64_H

#include <stdexcept>

#include <string>

#include <cstddef>
#include <cstdint>

namespace Crypto
{

class Base64
{
	public:
		static int encode(const uint8_t*, std::size_t, std::string&);
		static int decode(const std::string, uint8_t*, std::size_t&);

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const int CRYPTO_BASE64_SUCCESS        = 0x00;
		static const int CRYPTO_BASE64_INVALID_LENGTH = 0x01;
	private:
		static const char    encode_map[64];
		static const uint8_t decode_map[128];
		static const char    pad;
};

}

#endif
