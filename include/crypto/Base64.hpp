#ifndef CRYPTO_BASE64_H
#define CRYPTO_BASE64_H

#include <string>
#include <vector>

namespace Crypto
{

class Base64
{
	public:
		static void encode(const uint8_t*, std::size_t, std::string&);
		static void decode(const std::string, uint8_t*, std::size_t&);

	private:
		static const char    encode_map[64];
		static const char    pad;

		static const uint8_t decode_map[128];
};

class Base64Exception : public std::runtime_error
{
	public:
		Base64Exception(const char *what_arg) : std::runtime_error(what_arg) {}
};

}

#endif
