#include "crypto/Utils.hpp"

namespace Crypto
{

void
Utils::zeroize(void *v, std::size_t n)
{
	volatile uint8_t *p = static_cast<uint8_t*>(v);

	while ( n-- ) {
		*p++ = 0x00;
	}
}

void
Utils::from_string(const std::string input, uint8_t *output, std::size_t &output_sz)
{
	if ( input.length() > output_sz ) {
		output_sz = input.length();
		return;
	}

	for ( std::size_t i = 0 ; i < input.length() ; ++i ) {
		output[i] = static_cast<uint8_t>(input[i]);
	}

	output_sz = input.length();
}

void
Utils::to_string(const uint8_t* input, std::size_t input_sz, std::string &output)
{
	for ( std::size_t i = 0 ; i < input_sz ; ++i ) {
		output += static_cast<char>(input[i]);
	}
}

void
Utils::from_hex(const std::string input, uint8_t *output, std::size_t &output_sz)
{
	char c[2];

	if ( input.length() % 2 != 0 ) {
		throw CryptoException("Incorrect length");
	}

	if ( input.length() / 2 > output_sz ) {
		output_sz = input.length() / 2;
		return;
	}

	for ( std::size_t i = 0 ; i < input.length() ; i += 2 ) {
		c[0] = input[i];
		c[1] = input[i+1];

		if ( (c[1] < '0' || c[1] > '9') && (c[1] < 'a' || c[1] > 'f')
				&& (c[1] < 'A' || c[1] > 'F') ) {
			throw CryptoException("Invalid character");
		}

		uint8_t out = 0;

		if ( c[0] >= '0' && c[0] <= '9' ) {
			out |= 0xF0 & ((c[0] - '0') << 4);
		} else if ( c[0] >= 'a' && c[0] <= 'f' ) {
			out |= 0xF0 & ((c[0] - 'a' + 10) << 4);
		} else if ( c[0] >= 'A' && c[0] <= 'F' ) {
			out |= 0xF0 & ((c[0] - 'A' + 10) << 4);
		} else {
			throw CryptoException("Invalid character");
		}

		if ( c[1] >= '0' && c[1] <= '9' ) {
			out |= 0x0F & (c[1] - '0');
		} else if ( c[1] >= 'a' && c[1] <= 'f' ) {
			out |= 0x0F & (c[1] - 'a' + 10);
		} else if ( c[1] >= 'A' && c[1] <= 'F' ) {
			out |= 0x0F & (c[1] - 'A' + 10);
		} else {
			throw CryptoException("Invalid character");
		}

		output[i / 2] = out;
	}

	output_sz = input.length() / 2;
}

void
Utils::to_hex(const uint8_t *input, std::size_t input_sz, std::string &output, bool uppercase)
{
	uint8_t u[2];

	output = "";
	for ( std::size_t i = 0 ; i < input_sz ; ++i ) {
		u[0] = (input[i] & 0xF0) >> 4;
		u[1] = input[i] & 0x0F;

		if ( u[0] < 10 ) {
			output += u[0] + '0';
		} else {
			output += u[0] + (uppercase ? 'A' : 'a') - 10;
		}

		if ( u[1] < 10 ) {
			output += u[1] + '0';
		} else {
			output += u[1] + (uppercase ? 'A' : 'a') - 10;
		}
	}
}

}
