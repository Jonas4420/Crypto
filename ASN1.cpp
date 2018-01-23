#include "crypto/ASN1.hpp"

namespace Crypto
{

int
ASN1::get_tag(const uint8_t *data, std::size_t data_sz, Tag &tag)
{
	// TODO
	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_len(const uint8_t *data, std::size_t data_sz, std::size_t &len)
{
	// TODO
	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_boolean(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, bool &boolean)
{
	// TODO
	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_integer(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, BigNum &integer)
{
	// TODO
	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_bit_string(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, uint8_t *bit_string, std::size_t &bit_string_sz)
{
	// TODO
	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_octet_string(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, uint8_t *octet_string, std::size_t &octet_string_sz)
{
	// TODO
	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_null(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz)
{
	// TODO
	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_oid(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, OID &oid)
{
	// TODO
	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_sequence(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, std::vector<std::pair<const uint8_t*, std::size_t>> &sequence)
{
	// TODO
	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_set(const uint8_t *data, std::size_t data_sz, std::size_t &read_sz, std::vector<std::pair<const uint8_t*, std::size_t>> &set)
{
	// TODO
	return CRYPTO_ASN1_SUCCESS;
}

int
ASN1::get_data(const uint8_t *data, std::size_t data_sz, Tag &tag, std::size_t &read_sz, uint8_t *value, std::size_t &value_sz)
{
	// TODO
	return CRYPTO_ASN1_SUCCESS;
}

}
