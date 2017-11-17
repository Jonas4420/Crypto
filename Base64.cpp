#include "crypto/Base64.hpp"

namespace Crypto
{

void
Base64::encode(const uint8_t *input, std::size_t input_sz, std::string &output)
{
	std::size_t n = (input_sz / 3) * 3;

	output = "";
	// Encode until padding part
	for ( std::size_t i = 0 ; i < n ; i += 3 ) {
		output += encode_map[ (input[i]   & 0xFC) >> 2];
		output += encode_map[((input[i]   & 0x03) << 4) | ((input[i+1] & 0xF0) >> 4)];
		output += encode_map[((input[i+1] & 0x0F) << 2) | ((input[i+2] & 0xC0) >> 6)];
		output += encode_map[ (input[i+2] & 0x3F)];
	}

	// Pad output if needed
	if ( n < input_sz ) {
		output += encode_map[ (input[n] & 0xFC) >> 2];

		if ( 1 == input_sz % 3 ) {
			output += encode_map[((input[n]   & 0x03) << 4) | 0x00];
			output += pad;
		} else {
			output += encode_map[((input[n]   & 0x03) << 4) | ((input[n+1] & 0xF0) >> 4)];
			output += encode_map[((input[n+1] & 0x0F) << 2) | 0x00];
		}

		output += pad;
	}
}

void
Base64::decode(const std::string input, uint8_t *output, std::size_t &output_sz)
{
	std::size_t i, n;
	uint32_t j, x;

	// First pass: check for validity and get output length
	j = 0;
	for ( i = n = 0 ; i < input.length() ; ++i ) {
		// Skip spaces before checking for EOL
		x = 0;

		while ( i < input.length() && ' ' == input[i] ) {
			++i;
			++x;
		}

		// Spaces at end of buffer are OK
		if ( i == input.length() ) {
			break;
		}

		if ( (input.length() - i) >= 2 && '\r' == input[i] && '\n' == input[i+1] ) {
			continue;
		}

		if ( '\n' == input[i] ) {
			continue;
		}

		// Space inside a line is an error
		if ( 0 != x ) {
			throw Base64Exception("Invalid character");
		}

		// More than 2 '=' is an arror
		if ( '=' == input[i] && 2 < ++j ) {
			throw Base64Exception("Invalid character");
		}

		// Input character out of mapping
		if ( 0x7F < input[i] || 0x7F == decode_map[static_cast<std::size_t>(input[i])] ) {
			throw Base64Exception("Invalid character");
		}

		// '=' was in the middle of the string
		if ( 0x40 > decode_map[static_cast<std::size_t>(input[i])] && 0 != j ) {
			throw Base64Exception("Invalid character");
		}

		++n;
	}

	if ( 0 == n ) {
		output_sz = 0;
		return;
	}

	/* The following expression is to calculate the following formula without
	 * risk of integer overflow in n:
	 *     n = ( ( n * 6 ) + 7 ) >> 3;
	 */
	n = ( 6 * ( n >> 3 ) ) + ( ( 6 * ( n & 0x7 ) + 7 ) >> 3 );
	n -= j;

	if ( n > output_sz ) {
		output_sz = n;
		return;
	}

	x = 0;
	j = 3;
	n = 0;
	uint8_t *p = output;
	for ( i = 0 ; i < input.length() ; ++i ) {
		if ( ' ' == input[i] || '\r' == input[i] || '\n' == input[i] ) {
			continue;
		}

		j -= ( 0x40 == decode_map[static_cast<std::size_t>(input[i])] );
		x  = ( x << 6 ) | ( decode_map[static_cast<std::size_t>(input[i])] & 0x3F );

		if ( 4 == ++n ) {
			n = 0;
			if ( j > 0 ) { *p++ = static_cast<uint8_t>(x >> 16); }
			if ( j > 1 ) { *p++ = static_cast<uint8_t>(x >>  8); }
			if ( j > 2 ) { *p++ = static_cast<uint8_t>(x      ); }
		}
	}

	output_sz = p - output;
}

const char
Base64::encode_map[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
	'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
	'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', '+', '/'
};

const char Base64::pad = '=';

const uint8_t
Base64::decode_map[128] = {
	0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
	0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
	0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
	0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
	0x7F, 0x7F, 0x7F, 0x3E, 0x7F, 0x7F, 0x7F, 0x3F, 0x34, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x7F, 0x7F,
	0x7F, 0x40, 0x7F, 0x7F, 0x7F, 0x00, 0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
	0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x1A, 0x1B, 0x1C,
	0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
	0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	0x31, 0x32, 0x33, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F
};

}
