#include "crypto/ASN1.hpp"

namespace Crypto
{

int
ASN1::read_boolean(const uint8_t *&data, std::size_t &data_sz, bool &boolean)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len);
	if ( 0 != res )            { return res; }
	if ( Tag::BOOLEAN != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	if ( 1 != len )            { return CRYPTO_ASN1_VALUE_ERROR; }

	// Read Value
	boolean  = static_cast<bool>(data[0]);

	// Update data
	data    += len;
	data_sz -= len;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_integer(const uint8_t *&data, std::size_t &data_sz, BigNum &integer)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len);
	if ( 0 != res )            { return res; }
	if ( Tag::INTEGER != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	if ( 0 == len )            { return CRYPTO_ASN1_VALUE_ERROR; }

	// Check for minimal encoding
	if ( 2 < len ) {
		if ( (0x00 == data[0]) && (0x00 == (data[1] & 0x80)) ) {
			return CRYPTO_ASN1_VALUE_ERROR;
		}

		if ( (0xFF == data[0]) && (0x00 != (data[1] & 0x80)) ) {
			return CRYPTO_ASN1_VALUE_ERROR;
		}
	}

	// Read value
	// TODO (+check overflow)

	// Update data
	data    += len;
	data_sz -= len;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_bit_string(const uint8_t *&data, std::size_t &data_sz,
		uint8_t *bit_string, std::size_t &bit_string_sz, std::uint8_t &unused_bits)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len);
	if ( 0 != res )               { return res; }
	if ( Tag::BIT_STRING != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	if ( 0 == len )               { return CRYPTO_ASN1_VALUE_ERROR; }

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

	// Update data
	data    += len;
	data_sz -= len;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_octet_string(const uint8_t *&data, std::size_t &data_sz,
		uint8_t *octet_string, std::size_t &octet_string_sz)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len);
	if ( 0 != res )                 { return res; }
	if ( Tag::OCTET_STRING != tag ) { return CRYPTO_ASN1_TAG_ERROR; }

	// Check if size is large enough
	if ( octet_string_sz < len ) {
		octet_string_sz = len;
		return CRYPTO_ASN1_INVALID_LENGTH;
	}

	// Read Value
	memcpy(octet_string, data, len);
	octet_string_sz  = len;

	// Update data
	data    += len;
	data_sz -= len;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_null(const uint8_t *&data, std::size_t &data_sz)
{
	int res;
	Tag tag;
	std::size_t tmp_sz, len;

	tmp_sz = data_sz;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len);
	if ( 0 != res )             { return res; }
	if ( Tag::TAG_NULL != tag ) { return CRYPTO_ASN1_TAG_ERROR; }

	// Ensure that the length was encoded as 1 byte only and is 0
	if ( 2 != (tmp_sz - data_sz) ) { return CRYPTO_ASN1_VALUE_ERROR; }
	if ( 0 != len )                { return CRYPTO_ASN1_VALUE_ERROR; }

	// Update data
	data    += 2;
	data_sz -= 2;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_oid(const uint8_t *&data, std::size_t &data_sz, OID &oid)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len);
	if ( 0 != res )                      { return res; }
	if ( Tag::OBJECT_IDENTIFIER != tag ) { return CRYPTO_ASN1_TAG_ERROR; }
	if ( 0 == len )                      { return CRYPTO_ASN1_VALUE_ERROR; }

	// Read value
	try {
		oid = OID(data, len);
	} catch ( ... ) {
		return CRYPTO_ASN1_VALUE_ERROR;
	}

	// Update data
	data    += len;
	data_sz -= len;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_sequence(const uint8_t *&data, std::size_t &data_sz,
		std::vector<std::pair<const uint8_t*, std::size_t>> &sequence)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len);
	if ( 0 != res )             { return res; }
	if ( Tag::SEQUENCE != tag ) { return CRYPTO_ASN1_TAG_ERROR; }

	// Clear content
	sequence.clear();

	// Read Values
	while ( 0 < len ) {
		// Save begining of encoding
		const uint8_t *tmp = data;
		std::size_t tmp_sz = data_sz;

		// Read Tag and Length
		res = read_header(data, data_sz, tag, len);
		if ( 0 != res ) { return res; }

		// Update object size
		tmp_sz = (tmp_sz - data_sz) + len;
		// Push result and move to next item
		sequence.push_back({ tmp, tmp_sz });

		data    += len;
		data_sz -= len;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_set(const uint8_t *&data, std::size_t &data_sz,
		std::vector<std::pair<const uint8_t*, std::size_t>> &set)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len);
	if ( 0 != res )        { return res; }
	if ( Tag::SET != tag ) { return CRYPTO_ASN1_TAG_ERROR; }

	// Clear content
	set.clear();

	// Read Values
	while ( 0 < len ) {
		// Save begining of encoding
		const uint8_t *tmp = data;
		std::size_t tmp_sz = data_sz;

		// Read Tag and Length
		res = read_header(data, data_sz, tag, len);
		if ( 0 != res ) { return res; }

		// Update object size
		tmp_sz = (tmp_sz - data_sz) + len;
		// Push result and move to next item
		set.push_back({ tmp, tmp_sz });

		data    += len;
		data_sz -= len;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_data(const uint8_t *&data, std::size_t &data_sz,
		const Tag &expected, uint8_t *value, std::size_t &value_sz)
{
	int res;
	Tag tag;
	std::size_t len;

	// Read Tag and Length
	res = read_header(data, data_sz, tag, len);
	if ( 0 != res )        { return res; }
	if ( expected != tag ) { return CRYPTO_ASN1_TAG_ERROR; }

	if ( value_sz < len ) {
		value_sz = len;
		return CRYPTO_ASN1_INVALID_LENGTH;
	}

	memcpy(value, data, len);
	value_sz  = len;

	data    += len;
	data_sz -= len;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_boolean(bool boolean, uint8_t *&data, std::size_t &data_sz)
{
	int res;

	// Write Tag and Len
	res = write_header(Tag::BOOLEAN, 1, data, data_sz);
	if ( 0 != res ) { return res; }

	// Write data
	data[0] = boolean ? 0xFF : 0x00;

	// Update data size
	data    += 1;
	data_sz -= 1;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_integer(const BigNum &integer, uint8_t *&data, std::size_t &data_sz)
{
	int res;
	std::size_t integer_sz;

	// TODO (+check overflow)

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_bit_string(const uint8_t *bit_string, std::size_t bit_string_sz, uint8_t unused_bits,
		uint8_t *&data, std::size_t &data_sz)
{
	int res;

	// Check that unused bits is correct
	if ( 7 < unused_bits ) { return CRYPTO_ASN1_VALUE_ERROR; }

	// Write Tag and Len
	res = write_header(Tag::BIT_STRING, bit_string_sz + 1, data, data_sz);
	if ( 0 != res ) { return res; }

	// Write data
	data[0] = unused_bits;
	memcpy(data + 1, bit_string, bit_string_sz);

	// Update data
	data    += 1 + bit_string_sz;
	data_sz -= 1 + bit_string_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_octet_string(const uint8_t *octet_string, std::size_t octet_string_sz,
		uint8_t *&data, std::size_t &data_sz)
{
	int res;

	// Write Tag and Len
	res = write_header(Tag::OCTET_STRING, octet_string_sz, data, data_sz);
	if ( 0 != res ) { return res; }

	// Write data
	memcpy(data, octet_string, octet_string_sz);

	// Update data size
	data    += octet_string_sz;
	data_sz -= octet_string_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_null(uint8_t *&data, std::size_t &data_sz)
{
	int res;

	// Write Tag and Len
	res = write_header(Tag::TAG_NULL, 0, data, data_sz);
	if ( 0 != res ) { return res; }

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_oid(const OID &oid, uint8_t *&data, std::size_t &data_sz)
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
	res = write_header(Tag::OBJECT_IDENTIFIER, oid_sz, data, data_sz);
	if ( 0 != res ) { return res; }

	// Write Value
	res = oid.to_binary(data, oid_sz);
	if ( 0 != res ) { return res; }

	// Update data
	data    += oid_sz;
	data_sz -= oid_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_sequence(const std::vector<std::pair<const uint8_t*, std::size_t>> &sequence,
		uint8_t *&data, std::size_t &data_sz)
{
	int res;
	std::size_t sequence_sz = 0;

	// Compute sequence size
	for ( auto i : sequence ) {
		sequence_sz += i.second;
	}

	// Write Tag and Len
	res = write_header(Tag::SEQUENCE, sequence_sz, data, data_sz);
	if ( 0 != res ) { return res; }

	// Write Values
	for ( auto i : sequence ) {
		memcpy(data, i.first, i.second);

		// Update data
		data    += i.second;
		data_sz -= i.second;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_set(const std::vector<std::pair<const uint8_t*, std::size_t>> &set,
		uint8_t *&data, std::size_t &data_sz)
{
	int res;
	std::size_t set_sz = 0;

	// Compute set size
	for ( auto i : set ) {
		set_sz += i.second;
	}

	// Write Tag and Len
	res = write_header(Tag::SET, set_sz, data, data_sz);
	if ( 0 != res ) { return res; }

	// Write Values
	for ( auto i : set ) {
		memcpy(data, i.first, i.second);

		// Update data
		data    += i.second;
		data_sz -= i.second;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_data(const Tag &tag, const uint8_t *value, std::size_t value_sz,
		uint8_t *&data, std::size_t &data_sz)
{
	int res;

	// Write Tag and Len
	res = write_header(tag, value_sz, data, data_sz);
	if ( 0 != res ) { return res; }

	// Write data
	memcpy(data, value, value_sz);

	// Update data size
	data    += value_sz;
	data_sz -= value_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_header(const uint8_t *&data, std::size_t &data_sz, Tag &tag, std::size_t &len)
{
	int res;

	// Read Tag
	res = read_tag(data, data_sz, tag);
	if ( 0 != res ) { return res; }

	// Read Length
	res = read_len(data, data_sz, len);
	if ( 0 != res ) { return res; }

	// Check if data is long enough
	if ( data_sz < len ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_tag(const uint8_t *&data, std::size_t &data_sz, Tag &tag)
{
	// Check if data is long enough
	if ( 0 == data_sz ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Read Tag
	tag = static_cast<Tag>(data[0]);

	// Update data
	data    += 1;
	data_sz -= 1;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::read_len(const uint8_t *&data, std::size_t &data_sz, std::size_t &len)
{
	std::size_t len_sz;

	if ( 0 == data_sz ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Length encoded on 1 byte
	if ( 0x00 == (data[0] & 0x80) ) {
		len = static_cast<std::size_t>(data[0]);

		// Update data
		data    += 1;
		data_sz -= 1;

		return CRYPTO_ASN1_SUCCESS;
	}

	// Read number of bytes used to encode length
	len_sz = static_cast<std::size_t>(data[0] & 0x7F);
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
	data    += 1;
	data_sz -= 1;

	// Read following bytes of length
	for ( std::size_t i = 0 ; i < len_sz ; ++i ) {
		len    <<= 8;
		len     |= static_cast<std::size_t>(data[0]);
		data    += 1;
		data_sz -= 1;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_header(const Tag &tag, std::size_t len, uint8_t *&data, std::size_t &data_sz)
{
	int res;

	// Write Tag
	res = write_tag(tag, data, data_sz);
	if ( 0 != res ) { return res; }

	// Write Length
	res = write_len(len, data, data_sz);
	if ( 0 != res ) { return res; }

	// Check if data is long enough
	if ( data_sz < len ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_tag(const Tag &tag, uint8_t *&data, std::size_t &data_sz)
{
	// Check if data is long enough
	if ( 0 == data_sz ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Write tag
	data[0] = static_cast<uint8_t>(tag);

	// Update data
	data    += 1;
	data_sz -= 1;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::write_len(std::size_t len, uint8_t *&data, std::size_t &data_sz)
{
	std::size_t len_sz;

	if ( 0 == data_sz ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Length encoded on 1 byte
	if ( 0x80 > len ) {
		data[0] = static_cast<uint8_t>(len & 0x7F);

		// Update data
		data    += 1;
		data_sz -= 1;

		return CRYPTO_ASN1_SUCCESS;
	}

	// TODO

	return CRYPTO_ASN1_SUCCESS;
}

}
