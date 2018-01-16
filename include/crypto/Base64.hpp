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
		static void encode(const uint8_t*, std::size_t, std::string&);
		static void decode(const std::string, uint8_t*, std::size_t&);

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};
	private:
		static const char    encode_map[64];
		static const uint8_t decode_map[128];
		static const char    pad;
};

}

#endif
