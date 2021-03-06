#ifndef CRYPTO_PEM_H
#define CRYPTO_PEM_H

#include <stdexcept>

#include <string>
#include <vector>

#include <cstddef>
#include <cstdint>

namespace Crypto
{

class PEM
{
	public:
		static int encode(std::string, const uint8_t*, std::size_t, std::string&,
				std::string = "", std::string = "", std::string = "");
		static int decode(std::string, std::string, uint8_t*, std::size_t&,
				std::string = "");

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const int CRYPTO_PEM_SUCCESS        = 0x00;
		static const int CRYPTO_PEM_INVALID_LENGTH = 0x01;
	protected:
		static inline std::string get_header(std::string);
		static inline std::string get_footer(std::string);

		static int no_encrypt(const uint8_t*, std::size_t, std::vector<uint8_t>&);
		static int des_encrypt(std::string, std::string, const uint8_t*, std::size_t, std::vector<uint8_t>&);
		static int des3_encrypt(std::string, std::string, const uint8_t*, std::size_t, std::vector<uint8_t>&);
		static int aes_encrypt(std::string, std::string, std::size_t, const uint8_t*, std::size_t, std::vector<uint8_t>&);

		static int des_decrypt(std::string, std::string, uint8_t*, std::size_t&);
		static int des3_decrypt(std::string, std::string, uint8_t*, std::size_t&);
		static int aes_decrypt(std::string, std::string, std::size_t, uint8_t*, std::size_t&);

		static void key_derivation(std::string, const uint8_t[8], uint8_t*, std::size_t);
};

}

#endif
