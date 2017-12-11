#include "crypto/Padding.hpp"

namespace Crypto
{

void
PKCS7Padding::pad(uint8_t *data, std::size_t input_sz, std::size_t output_sz)
{
	if ( output_sz <= input_sz ) {
		return;
	}

	std::size_t pad_sz = output_sz - input_sz;

	for ( std::size_t i = 0 ; i < pad_sz ; ++i ) {
		data[input_sz + i] = static_cast<uint8_t>(pad_sz);
	}
}

void
PKCS7Padding::unpad(const uint8_t *data, std::size_t input_sz, std::size_t &output_sz)
{
	uint8_t pad_sz = data[input_sz - 1];

	if ( pad_sz > input_sz ) {
		throw Padding::Exception("Invalid padding");
	}

	if ( 0 == pad_sz ) {
		throw Padding::Exception("Invalid padding");
	}

	for ( std::size_t i = 1 ; i < pad_sz ; ++i ) {
		if ( pad_sz != data[input_sz - 1 - i] ) {
			throw Padding::Exception("Invalid padding");
		}
	}

	output_sz = input_sz - pad_sz;
}

void
OneAndZeroesPadding::pad(uint8_t *data, std::size_t input_sz, std::size_t output_sz)
{
	if ( output_sz <= input_sz ) {
		return;
	}

	std::size_t pad_sz = output_sz - input_sz;

	data[input_sz] = 0x80;
	for ( std::size_t i = 1 ; i < pad_sz ; ++i ) {
		data[input_sz + i] = 0x00;
	}
}

void
OneAndZeroesPadding::unpad(const uint8_t *data, std::size_t input_sz, std::size_t &output_sz)
{
	std::size_t i, pad_sz;

	i = input_sz - 1; pad_sz = 0;
	while ( i < input_sz && 0x00 == data[i] ) {
		--i; ++pad_sz;
	}

	if ( input_sz <= i ) {
		throw Padding::Exception("Invalid padding");
	}

	if ( 0x80 != data[i] ) {
		throw Padding::Exception("Invalid padding");
	}
	++pad_sz;

	output_sz = input_sz - pad_sz;
}

void
ANSIX923Padding::pad(uint8_t *data, std::size_t input_sz, std::size_t output_sz)
{
	if ( output_sz <= input_sz ) {
		return;
	}

	std::size_t pad_sz = output_sz - input_sz;

	for ( std::size_t i = 0 ; i < pad_sz - 1 ; ++i ) {
		data[input_sz + i] = 0x00;
	}
	data[output_sz - 1] = static_cast<uint8_t>(pad_sz);
}

void
ANSIX923Padding::unpad(const uint8_t *data, std::size_t input_sz, std::size_t &output_sz)
{
	uint8_t pad_sz = data[input_sz - 1];

	if ( pad_sz > input_sz ) {
		throw Padding::Exception("Invalid padding");
	}

	if ( 0 == pad_sz ) {
		throw Padding::Exception("Invalid padding");
	}

	for ( std::size_t i = 1 ; i < pad_sz ; ++i ) {
		if ( 0x00 != data[input_sz - 1 - i] ) {
			throw Padding::Exception("Invalid padding");
		}
	}

	output_sz = input_sz - pad_sz;
}

}
