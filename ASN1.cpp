#include "crypto/ASN1.hpp"

namespace Crypto
{

int
ASN1::get_boolean(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, bool &boolean)
{
	int res;
	std::size_t len_sz;

	// Read Tag and Length
	res = get_header(data, data_sz, read_sz, Tag::BOOLEAN, len_sz);
	if ( 0 != res )    { return res; }
	if ( 0 == len_sz ) { return CRYPTO_ASN1_VALUE_ERROR; }

	// Read Value
	boolean = false;
	for ( std::size_t i = 0 ; i < len_sz ; ++i ) {
		if ( 0x00 != data[i] ) {
			boolean = true;
		}
	}
	read_sz += len_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_integer(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, BigNum &integer)
{
	int res;
	std::size_t len_sz;

	// Read Tag and Length
	res = get_header(data, data_sz, read_sz, Tag::INTEGER, len_sz);
	if ( 0 != res )    { return res; }
	if ( 0 == len_sz ) { return CRYPTO_ASN1_VALUE_ERROR; }

	// Read value
	if ( 0x00 == (data[0] & 0x80) ) {
		// Unsigned integer
		try {
			integer = BigNum(data, len_sz);
	       	} catch ( ... ) {
			return CRYPTO_ASN1_VALUE_ERROR;
		}
	} else {
		// Signed integer

		// Check if len_sz * 8 will not overflow
		std::size_t mask = -1;
		mask ^= (mask >> 3);

		if ( 0 != (mask & len_sz) ) {
			return CRYPTO_ASN1_LENGTH_ERROR;
		}

		try {
			BigNum base = BigNum(1) << (len_sz * 8);
			integer = -(base - BigNum(data, len_sz));
		} catch ( ... ) {
			return CRYPTO_ASN1_VALUE_ERROR;
		}
	}
	read_sz += len_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_bit_string(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, uint8_t *bit_string, std::size_t &bit_string_sz, std::uint8_t &unused_bits)
{
	int res;
	std::size_t len_sz;

	// Read Tag and Length
	res = get_header(data, data_sz, read_sz, Tag::BIT_STRING, len_sz);
	if ( 0 != res )    { return res; }
	if ( 0 == len_sz ) { return CRYPTO_ASN1_VALUE_ERROR; }

	// Check that unused bits is <= 7
	if ( 7 < data[0] ) { return CRYPTO_ASN1_VALUE_ERROR; }

	unused_bits = data[0];
	read_sz += 1;
	len_sz  -= 1;

	// Check if size is large enough
	if ( bit_string_sz < len_sz ) {
		bit_string_sz = len_sz;
		return CRYPTO_ASN1_INVALID_LENGTH;
	}

	// Read value
	memcpy(bit_string, data + 1, len_sz);
	bit_string_sz  = len_sz;
	read_sz       += len_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_octet_string(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, uint8_t *octet_string, std::size_t &octet_string_sz)
{
	int res;
	std::size_t len_sz;

	// Read Tag and Length
	res = get_header(data, data_sz, read_sz, Tag::OCTET_STRING, len_sz);
	if ( 0 != res ) { return res; }

	// Check if size is large enough
	if ( octet_string_sz < len_sz ) {
		octet_string_sz = len_sz;
		return CRYPTO_ASN1_INVALID_LENGTH;
	}

	// Read Value
	memcpy(octet_string, data, len_sz);
	octet_string_sz  = len_sz;
	read_sz         += len_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_null(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz)
{
	int res;
	std::size_t len_sz;

	// Read Tag and Length
	res = get_header(data, data_sz, read_sz, Tag::TAG_NULL, len_sz);
	if ( 0 != res ) { return res; }

	// Ensure that the length was encoded as 1 byte only and is 0
	if ( 2 != read_sz ) { return CRYPTO_ASN1_VALUE_ERROR; }
	if ( 0 != len_sz )  { return CRYPTO_ASN1_VALUE_ERROR; }

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_oid(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, OID &oid)
{
	int res;
	std::size_t len_sz;

	// Read Tag and Length
	res = get_header(data, data_sz, read_sz, Tag::OBJECT_IDENTIFIER, len_sz);
	if ( 0 != res )    { return res; }
	if ( 0 == len_sz ) { return CRYPTO_ASN1_VALUE_ERROR; }

	// Read value
	try {
		oid = OID(data, len_sz);
	} catch ( ... ) {
		return CRYPTO_ASN1_VALUE_ERROR;
	}
	read_sz += len_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_sequence(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, std::vector<std::pair<const uint8_t*, std::size_t>> &sequence)
{
	int res;
	std::size_t len_sz;
	std::vector<std::pair<const uint8_t*, std::size_t>> temp;

	// Read Tag and Length
	res = get_header(data, data_sz, read_sz, Tag::SEQUENCE, len_sz);
	if ( 0 != res ) { return res; }

	read_sz += len_sz;
	// Read Values
	while ( 0 < len_sz ) {
		Tag tag;
		std::size_t cur_sz, tmp_sz;

		cur_sz = 0;

		// Read tag
		res = get_tag(data, len_sz, tmp_sz, tag);
		if ( 0 != res ) { return res; }
		cur_sz += tmp_sz;

		// Read length
		res = get_len(data + cur_sz, len_sz - cur_sz, tmp_sz, len_sz);
		if ( 0 != res )    { return res; }
		cur_sz += tmp_sz;

		// Check if size is large enough
		if ( len_sz < (cur_sz + len_sz ) ) {
			return CRYPTO_ASN1_OUT_OF_DATA;
		}

		// Set Value length
		cur_sz += len_sz;

		// Push result and move to next item
		temp.push_back({ data, cur_sz });
		data   += cur_sz;
		len_sz -= cur_sz;
	}

	// Set values only if no error occured
	sequence.swap(temp);

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_set(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, std::vector<std::pair<const uint8_t*, std::size_t>> &set)
{
	int res;
	std::size_t len_sz;
	std::vector<std::pair<const uint8_t*, std::size_t>> temp;

	// Read Tag and Length
	res = get_header(data, data_sz, read_sz, Tag::SET, len_sz);
	if ( 0 != res ) { return res; }

	read_sz += len_sz;
	// Read Values
	while ( 0 < len_sz ) {
		Tag tag;
		std::size_t cur_sz, tmp_sz;

		cur_sz = 0;

		// Read tag
		res = get_tag(data, len_sz, tmp_sz, tag);
		if ( 0 != res ) { return res; }
		cur_sz += tmp_sz;

		// Read length
		res = get_len(data + cur_sz, len_sz - cur_sz, tmp_sz, len_sz);
		if ( 0 != res )    { return res; }
		cur_sz += tmp_sz;

		// Check if size is large enough
		if ( len_sz < (cur_sz + len_sz ) ) {
			return CRYPTO_ASN1_OUT_OF_DATA;
		}

		// Set Value length
		cur_sz += len_sz;

		// Push result and move to next item
		temp.push_back({ data, cur_sz });
		data   += cur_sz;
		len_sz -= cur_sz;
	}

	// Set values only if no error occured
	set.swap(temp);

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_data(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, const Tag &tag, uint8_t *value, std::size_t &value_sz)
{
	int res;
	std::size_t len_sz;

	// Read Tag and Length
	res = get_header(data, data_sz, read_sz, tag, len_sz);
	if ( 0 != res ) { return res; }

	if ( value_sz < len_sz ) {
		value_sz = len_sz;
		return CRYPTO_ASN1_INVALID_LENGTH;
	}

	memcpy(value, data, len_sz);
	value_sz  = len_sz;
	read_sz  += len_sz;

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_tag(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, Tag &tag)
{
	if ( data_sz < 1 ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	read_sz = 1;
	tag     = static_cast<Tag>(data[0]);

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_len(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, std::size_t &len)
{
	if ( data_sz < 1 ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	if ( 0x00 == (data[0] & 0x80) ) {
		read_sz = 1;
		len     = static_cast<std::size_t>(data[1]);
		return CRYPTO_ASN1_SUCCESS;
	}

	read_sz = 1 + static_cast<std::size_t>(data[1] & 0x7F);

	if ( read_sz < data_sz ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Length of more than 4 bytes is not supported
	if ( read_sz - 1 > 4 ) {
		return CRYPTO_ASN1_LENGTH_ERROR;
	}

	switch ( read_sz - 1 ) {
		case 1:
			len = static_cast<std::size_t>(data[1]);
			break;
		case 2:
			len =  (static_cast<std::size_t>(data[1]) <<  8)
			     |  static_cast<std::size_t>(data[2]);
			break;
		case 3:
			len =  (static_cast<std::size_t>(data[1]) << 16)
			     | (static_cast<std::size_t>(data[2]) <<  8)
			     |  static_cast<std::size_t>(data[3]);
			break;
		case 4:
			len =  (static_cast<std::size_t>(data[1]) << 24)
			     | (static_cast<std::size_t>(data[2]) << 16)
			     | (static_cast<std::size_t>(data[3]) <<  8)
			     |  static_cast<std::size_t>(data[4]);
			break;
		default:
			break;
	}

	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_header(const uint8_t *&data, std::size_t &data_sz, std::size_t &read_sz, const Tag &expected, std::size_t &len_sz)
{
	int res;
	Tag tag;
	std::size_t tmp_sz;

	read_sz = 0;

	// Read tag
	res = get_tag(data, data_sz, tmp_sz, tag);
	if ( 0 != res )        { return res; }
	if ( tag != expected ) { return CRYPTO_ASN1_TAG_ERROR; }
	read_sz += tmp_sz;

	// Read length
	res = get_len(data + read_sz, data_sz - read_sz, tmp_sz, len_sz);
	if ( 0 != res )    { return res; }
	read_sz += tmp_sz;

	// Check if data is long enough
	if ( data_sz < (len_sz + read_sz) ) {
		return CRYPTO_ASN1_OUT_OF_DATA;
	}

	// Move pointer
	data    += read_sz;
	data_sz -= read_sz;
	
	return CRYPTO_ASN1_SUCCESS;
}

}
