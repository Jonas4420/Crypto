#ifndef CRYPTO_PADDING_H
#define CRYPTO_PADDING_H

#include <string>

#include <cstddef>
#include <cstdint>

namespace Crypto
{

class Padding
{
	public:
		static const uint8_t CRYPTO_PADDING_SUCCESS        = 0x00;
		static const uint8_t CRYPTO_PADDING_INVALID_LENGTH = 0x01;
};

class PaddingException : public std::runtime_error
{
	public:
		PaddingException(const char *what_arg) : std::runtime_error(what_arg) {}
};

/*
 * PKCS7 Padding (xx xx xx xx xx 03 03 03)
 */
class PKCS7Padding : public Padding
{
	public:
		static void pad(uint8_t*, std::size_t, std::size_t);
		static void unpad(const uint8_t*, std::size_t, std::size_t&);
};

/*
 * One and Zeroes Padding (xx xx xx xx xx 80 00 00)
 */
class OneAndZeroesPadding : public Padding
{
	public:
		static void pad(uint8_t*, std::size_t, std::size_t);
		static void unpad(const uint8_t*, std::size_t, std::size_t&);
};

/*
 * ANSI X.923 Padding (xx xx xx xx xx 00 00 03)
 */
class ANSIX923Padding : public Padding
{
	public:
		static void pad(uint8_t*, std::size_t, std::size_t);
		static void unpad(const uint8_t*, std::size_t, std::size_t&);
};

}

#endif
