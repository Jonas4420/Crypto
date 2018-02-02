#include "crypto/ASN1.hpp"

namespace Crypto
{

int
ASN1::read_boolean(const uint8_t *data, std::size_t data_sz,
		bool &boolean, std::size_t &read_sz)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len, read_sz);
	if ( 0 != res )            { return res; }
	if ( Tag::BOOLEAN != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	if ( 1 != len )            { return CRYPTO_ASN1_VALUE_ERROR; }
	data    += read_sz;
	data_sz -= read_sz;

	// Read Value
	boolean  = static_cast<bool>(data[0]);
	read_sz += len;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_integer(const uint8_t *data, std::size_t data_sz,
		BigNum &integer, std::size_t &read_sz)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len, read_sz);
	if ( 0 != res )            { return res; }
	if ( Tag::INTEGER != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	if ( 0 == len )            { return CRYPTO_ASN1_VALUE_ERROR; }
	data    += read_sz;
	data_sz -= read_sz;

	// Check for minimal encoding
	if ( 2 <= len ) {
		if ( (0x00 == data[0]) && (0x00 == (data[1] & 0x80)) ) {
			return CRYPTO_ASN1_VALUE_ERROR;
		}

		if ( (0xFF == data[0]) && (0x00 != (data[1] & 0x80)) ) {
			return CRYPTO_ASN1_VALUE_ERROR;
		}
	}

	// Read value
	try {
		integer = BigNum(data, len);
	} catch ( ... ) {
		return CRYPTO_ASN1_VALUE_ERROR;
	}

	// If negative number encoded
	if ( 0x00 != (data[0] & 0x80) ) {
		try {
			// Compute two complement of integer
			BigNum pow_two(0);
			pow_two.set_bit(integer.size() * 8, 1);
			integer -= pow_two;
		} catch ( ... ) {
			return CRYPTO_ASN1_VALUE_ERROR;
		}
	}

	read_sz += len;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_bit_string(const uint8_t *data, std::size_t data_sz,
		uint8_t *bit_string, std::size_t &bit_string_sz, std::uint8_t &unused_bits,
		std::size_t &read_sz)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len, read_sz);
	if ( 0 != res )               { return res; }
	if ( Tag::BIT_STRING != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	if ( 0 == len )               { return CRYPTO_ASN1_VALUE_ERROR; }
	data    += read_sz;
	data_sz -= read_sz;

	// Check that unused bits is <= 7
	if ( 7 < data[0] ) { return CRYPTO_ASN1_VALUE_ERROR; }

	// Check if size is large enough
	if ( bit_string_sz < len - 1 ) {
		bit_string_sz = len - 1;
		return CRYPTO_ASN1_INVALID_LENGTH;
	}

	// Read value
	unused_bits = data[0];
	memcpy(bit_string, data + 1, len - 1);
	bit_string_sz  = len - 1;
	read_sz += len;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_octet_string(const uint8_t *data, std::size_t data_sz,
		uint8_t *octet_string, std::size_t &octet_string_sz,
		std::size_t &read_sz)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len, read_sz);
	if ( 0 != res )                 { return res; }
	if ( Tag::OCTET_STRING != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	data    += read_sz;
	data_sz -= read_sz;

	// Check if size is large enough
	if ( octet_string_sz < len ) {
		octet_string_sz = len;
		return CRYPTO_ASN1_INVALID_LENGTH;
	}

	// Read Value
	memcpy(octet_string, data, len);
	octet_string_sz = len;
	read_sz        += len;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_null(const uint8_t *data, std::size_t data_sz,
		std::size_t &read_sz)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len, read_sz);
	if ( 0 != res )             { return res; }
	if ( Tag::TAG_NULL != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	data    += read_sz;
	data_sz -= read_sz;

	// Ensure that the length was encoded as 1 byte only and is 0
	if ( 2 != read_sz ) { return CRYPTO_ASN1_VALUE_ERROR; }
	if ( 0 != len )     { return CRYPTO_ASN1_VALUE_ERROR; }

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_oid(const uint8_t *data, std::size_t data_sz,
		OID &oid, std::size_t &read_sz)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len, read_sz);
	if ( 0 != res )                      { return res; }
	if ( Tag::OBJECT_IDENTIFIER != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	if ( 0 == len )                      { return CRYPTO_ASN1_VALUE_ERROR; }
	data    += read_sz;
	data_sz -= read_sz;

	// Read value
	try {
		oid = OID(data, len);
		read_sz += len;
	} catch ( ... ) {
		return CRYPTO_ASN1_VALUE_ERROR;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_sequence(const uint8_t *data, std::size_t data_sz,
		std::vector<std::pair<const uint8_t*, std::size_t>> &sequence,
		std::size_t &read_sz)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len, read_sz);
	if ( 0 != res )             { return res; }
	if ( Tag::SEQUENCE != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	data    += read_sz;
	data_sz -= read_sz;

	// Clear content
	sequence.clear();

	// Read Values
	while ( 0 < len ) {
		std::size_t hdr_sz, item_sz, total_sz;

		// Read Tag and Length
		res = read_header(data, data_sz, tag, item_sz, hdr_sz);
		if ( 0 != res ) { return res; }
		total_sz = hdr_sz + item_sz;

		// Push result and move to next item
		sequence.push_back({ data, total_sz });

		// Move data
		data    += total_sz;
		data_sz -= total_sz;
		len     -= total_sz;
		read_sz += total_sz;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_set(const uint8_t *data, std::size_t data_sz,
		std::vector<std::pair<const uint8_t*, std::size_t>> &set,
		std::size_t& read_sz)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len, read_sz);
	if ( 0 != res )             { return res; }
	if ( Tag::SET != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	data    += read_sz;
	data_sz -= read_sz;

	// Clear content
	set.clear();

	// Read Values
	while ( 0 < len ) {
		std::size_t hdr_sz, item_sz, total_sz;

		// Read Tag and Length
		res = read_header(data, data_sz, tag, item_sz, hdr_sz);
		if ( 0 != res ) { return res; }
		total_sz = hdr_sz + item_sz;

		// Push result and move to next item
		set.push_back({ data, total_sz });

		// Move data
		data    += total_sz;
		data_sz -= total_sz;
		len     -= total_sz;
		read_sz += total_sz;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_data(const uint8_t *data, std::size_t data_sz,
		const Tag &expected, uint8_t *value, std::size_t &value_sz,
		std::size_t &read_sz)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len, read_sz);
	if ( 0 != res )        { return res; }
	if ( expected != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	data    += read_sz;
	data_sz -= read_sz;

	if ( value_sz < len ) {
		value_sz = len;
		return CRYPTO_ASN1_INVALID_LENGTH;
	}

	memcpy(value, data, len);
	value_sz = len;
	read_sz += len; 

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_boolean(bool boolean, uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	int res;

	// Write Tag and Len
	res = write_header(Tag::BOOLEAN, 1, data, data_sz, write_sz);
	if ( 0 != res ) { return res; }
	data += write_sz;

	// Write data
	data[0] = boolean ? 0xFF : 0x00;
	write_sz += 1;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_integer(const BigNum &integer, uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	int res;
	const BigNum *n = NULL;
	BigNum two_cpt(0);
	uint8_t pad = 0x00;
	std::size_t pad_sz = 0;

	// Set value
	if ( integer >= 0 ) {
		n = &integer;
	} else {
		try {
			// Compute two complement of integer
			BigNum pow_two(0);
			pow_two.set_bit(integer.size() * 8, 1);
			two_cpt = pow_two + integer;
		} catch ( ... ) {
			return CRYPTO_ASN1_VALUE_ERROR;
		}

		n = &two_cpt;
	}

	// Check if padding is needed
	if ( integer == 0 ) {
		pad    = 0x00;
		pad_sz = 0;
	} else if ( integer > 0 ) {
		pad    = 0x00;
		pad_sz = (0 == (n->bitlen() % 8));
	} else {
		pad    = 0xFF;
		pad_sz = (0 != (n->bitlen() % 8));
	}

	// Write Tag and Len
	res = write_header(Tag::INTEGER, pad_sz + n->size(), data, data_sz, write_sz);
	if ( 0 != res ) { return res; }
	data += write_sz;

	// Write data
	memset(data, pad, pad_sz);
	data     += pad_sz;
	write_sz += pad_sz;

	res = n->to_binary(data, data_sz);
	if ( 0 != res ) { return res; }
	write_sz += data_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_bit_string(const uint8_t *bit_string, std::size_t bit_string_sz, uint8_t unused_bits,
		uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	int res;

	// Check that unused bits is correct
	if ( 7 < unused_bits ) { return CRYPTO_ASN1_VALUE_ERROR; }

	// Write Tag and Len
	res = write_header(Tag::BIT_STRING, bit_string_sz + 1, data, data_sz, write_sz);
	if ( 0 != res ) { return res; }
	data += write_sz;

	// Write data
	data[0] = unused_bits;
	memcpy(data + 1, bit_string, bit_string_sz);
	write_sz += 1 + bit_string_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_octet_string(const uint8_t *octet_string, std::size_t octet_string_sz,
		uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	int res;

	// Write Tag and Len
	res = write_header(Tag::OCTET_STRING, octet_string_sz, data, data_sz, write_sz);
	if ( 0 != res ) { return res; }
	data += write_sz;

	// Write data
	memcpy(data, octet_string, octet_string_sz);
	write_sz += octet_string_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_null(uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	int res;

	// Write Tag and Len
	res = write_header(Tag::TAG_NULL, 0, data, data_sz, write_sz);
	if ( 0 != res ) { return res; }

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_oid(const OID &oid, uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	int res;
	std::size_t oid_sz = 0;

	// Compute length of OID encoding
	try {
		res = oid.to_binary(NULL, oid_sz);
		if ( OID::CRYPTO_OID_INVALID_LENGTH != res ) { return res; }
	} catch ( ... ) {
		return CRYPTO_ASN1_VALUE_ERROR;
	}

	// Write Tag and Len
	res = write_header(Tag::OBJECT_IDENTIFIER, oid_sz, data, data_sz, write_sz);
	if ( 0 != res ) { return res; }
	data += write_sz;

	// Write Value
	res = oid.to_binary(data, oid_sz);
	if ( 0 != res ) { return res; }
	write_sz += oid_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_sequence(const std::vector<std::pair<const uint8_t*, std::size_t>> &sequence,
		uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	int res;
	std::size_t sequence_sz = 0;

	// Compute sequence size
	for ( auto i : sequence ) {
		sequence_sz += i.second;
	}

	// Write Tag and Len
	res = write_header(Tag::SEQUENCE, sequence_sz, data, data_sz, write_sz);
	if ( 0 != res ) { return res; }
	data += write_sz;

	// Write Values
	for ( auto i : sequence ) {
		memcpy(data, i.first, i.second);
		data     += i.second;
		write_sz += i.second;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_set(const std::vector<std::pair<const uint8_t*, std::size_t>> &set,
		uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	int res;
	std::size_t set_sz = 0;

	// Compute set size
	for ( auto i : set ) {
		set_sz += i.second;
	}

	// Write Tag and Len
	res = write_header(Tag::SET, set_sz, data, data_sz, write_sz);
	if ( 0 != res ) { return res; }
	data += write_sz;

	// Write Values
	for ( auto i : set ) {
		memcpy(data, i.first, i.second);
		data     += i.second;
		write_sz += i.second;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_data(const Tag &tag, const uint8_t *value, std::size_t value_sz,
		uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	int res;

	// Write Tag and Len
	res = write_header(tag, value_sz, data, data_sz, write_sz);
	if ( 0 != res ) { return res; }
	data += write_sz;

	// Write data
	memcpy(data, value, value_sz);
	write_sz += value_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_header(const uint8_t *data, std::size_t data_sz,
		Tag &tag, std::size_t &len, std::size_t &read_sz)
{
	int res;
	std::size_t tag_sz, len_sz;

	// Read Tag
	res = read_tag(data, data_sz, tag, tag_sz);
	if ( 0 != res ) { return res; }
	data    += tag_sz;
	data_sz -= tag_sz;

	// Read Length
	res = read_len(data, data_sz, len, len_sz);
	if ( 0 != res ) { return res; }
	data    += len_sz;
	data_sz -= len_sz;

	// Check if data is long enough
	if ( data_sz < len ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	read_sz = tag_sz + len_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_tag(const uint8_t *data, std::size_t data_sz,
		Tag &tag, std::size_t &read_sz)
{
	// Check if data is long enough
	if ( 0 == data_sz ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Read Tag
	tag = static_cast<Tag>(data[0]);
	read_sz = 1;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_len(const uint8_t *data, std::size_t data_sz,
		std::size_t &len, std::size_t &read_sz)
{
	std::size_t len_sz;

	if ( 0 == data_sz ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Length encoded on 1 byte
	if ( 0x00 == (data[0] & 0x80) ) {
		len = static_cast<std::size_t>(data[0]);
		read_sz = 1;

		return CRYPTO_ASN1_SUCCESS;
	}

	// Read number of bytes used to encode length
	len_sz   = static_cast<std::size_t>(data[0] & 0x7F);
	read_sz  = 1;
	data    += 1;
	data_sz -= 1;

	// If multi-byte length, it cannot have 0 bytes
	if ( 0 == len_sz ) {
		return CRYPTO_ASN1_LENGTH_ERROR;
	}	

	// Length encoded on more than 4 bytes is not supported
	if ( len_sz > 4 ) {
		return CRYPTO_ASN1_LENGTH_ERROR;
	}
	
	// Check if enough data
	if ( data_sz < len_sz ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Read first byte of length
	len = static_cast<std::size_t>(data[0]);
	len_sz  -= 1;
	read_sz += 1;
	data    += 1;
	data_sz -= 1;

	// Read following bytes of length
	for ( std::size_t i = 0 ; i < len_sz ; ++i ) {
		len <<= 8;
		len  |= static_cast<std::size_t>(data[0]);

		read_sz += 1;
		data    += 1;
		data_sz -= 1;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_header(const Tag &tag, std::size_t len, uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	int res;
	std::size_t tag_sz, len_sz;

	// Write Tag
	res = write_tag(tag, data, data_sz, tag_sz);
	if ( 0 != res ) { return res; }
	data    += tag_sz;
	data_sz -= tag_sz;

	// Write Length
	res = write_len(len, data, data_sz, len_sz);
	if ( 0 != res ) { return res; }
	data    += len_sz;
	data_sz -= len_sz;

	// Check if data is long enough
	if ( data_sz < len ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	write_sz = tag_sz + len_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_tag(const Tag &tag, uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	// Check if data is long enough
	if ( 0 == data_sz ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Write tag
	data[0] = static_cast<uint8_t>(tag);
	write_sz = 1;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_len(std::size_t len, uint8_t *data, std::size_t data_sz, std::size_t &write_sz)
{
	uint8_t buf[4];
	std::size_t len_sz;

	if ( 0 == data_sz ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Length encoded on 1 byte
	if ( 0x80 > len ) {
		data[0] = static_cast<uint8_t>(len & 0x7F);
		write_sz = 1;

		return CRYPTO_ASN1_SUCCESS;
	}

	// Copy len into buffer
	for ( std::size_t i = 0 ; i < 4 ; ++i ) {
		buf[3 - i] = static_cast<uint8_t>(len & 0xFF);
		len >>= 8;
	}

	// Length encoded on more than 4 bytes is not supported
	if ( len > 0 ) {
		return CRYPTO_ASN1_LENGTH_ERROR;
	}

	// Get real size of length encoding
	len_sz = 0;
	for ( std::size_t i = 0 ; i < 4 ; ++i ) {
		if ( 0x00 != buf[i] ) {
			len_sz = 4 - i;
			break;
		}
	}

	// Check that enough data
	if ( data_sz < 1 + len_sz ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Write length size
	data[0] = 0x80 | static_cast<uint8_t>(len_sz);
	memcpy(data + 1, buf + (4 - len_sz), len_sz);
	write_sz = 1 + len_sz;

	return CRYPTO_ASN1_SUCCESS;
}

}
