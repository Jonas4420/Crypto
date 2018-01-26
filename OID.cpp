#include "crypto/OID.hpp"

#include <cstring>

namespace Crypto
{

OID::OID(uint32_t n)
	: nodes(1, n)
{
}

OID::OID(const uint8_t *data, std::size_t data_sz)
{
	int res;
	uint8_t bytes[5];
	std::size_t bytes_sz;
	uint32_t node;

	if ( 0 == data_sz ) {
		throw OID::Exception("Invalid data");
	}

	if ( data[0] < 80 ) {
		// Root node 0 or 1
		nodes.push_back(data[0] / 40);
		nodes.push_back(data[0] % 40);

		data    += 1;
		data_sz -= 1;
	} else {
		// Root node 2
		res = fill_bytes(data, data_sz, bytes, bytes_sz);
		if ( 0 != res ) { throw OID::Exception("Invalid data"); }
		res = decode_node(bytes, bytes_sz, node);
		if ( 0 != res ) { throw OID::Exception("Invalid data"); }

		nodes.push_back(2);
		nodes.push_back(node - 80);
	}

	while ( 0 < data_sz ) {
		res = fill_bytes(data, data_sz, bytes, bytes_sz);
		if ( 0 != res ) { throw OID::Exception("Invalid data"); }
		res = decode_node(bytes, bytes_sz, node);
		if ( 0 != res ) { throw OID::Exception("Invalid data"); }

		nodes.push_back(node);
	}
}

OID::OID(const OID &other)
	: nodes(other.nodes)
{
}

OID&
OID::operator=(const OID &other)
{
	this->nodes = other.nodes;

	return *this;
}

OID
OID::operator+(uint32_t node) const
{
	OID result(*this);

	result += node;

	return result;
}

OID&
OID::operator+=(uint32_t node)
{
	nodes.push_back(node);

	return *this;
}

bool
OID::operator==(const OID &other) const
{
	return this->nodes == other.nodes;
}

bool
OID::operator!=(const OID &other) const
{
	return this->nodes != other.nodes;
}

bool
OID::operator<(const OID &other) const
{
	return this->nodes < other.nodes;
}

std::size_t
OID::size(void) const
{
	return nodes.size();
}

uint32_t
OID::operator[](std::size_t idx) const
{
	return nodes[idx];
}

std::string
OID::to_string(void) const
{
	std::string result;

	result = std::to_string(nodes[0]);
	for ( std::size_t i = 1 ; i < nodes.size() ; ++i ) {
		result += "." + std::to_string(nodes[i]);
	}

	return result;
}

int
OID::to_binary(uint8_t *data, std::size_t &data_sz) const
{
	int res;
	std::vector<uint8_t> result;
	uint8_t node[5];
	std::size_t node_sz;

	// Check that the OID can be encoded in binary
	if ( nodes.size() < 2 ) {
		throw OID::Exception("Impossible to encode any root OID without any second element");
	}

	if ( nodes[0] > 2 ) {
		throw OID::Exception("Impossible to encode any OID with root 3 or higher");
	}

	if ( (0 == nodes[0] || 1 == nodes[0]) && (40 <= nodes[1]) ) {
		throw OID::Exception("Impossible to encode second child >= 40 if root OID is 0 or 1");
	}

	// Encode root OID and second node
	if ( 0 == nodes[0] || 1 == nodes[0] ) {
		// If root is 0 or 1, it fits on 1 byte
		uint8_t tmp =  static_cast<uint8_t>(nodes[0]) * 40
			     + static_cast<uint8_t>(nodes[1]);
		result.push_back(tmp);
	} else {
		res = encode_node(nodes[0] * 40 + nodes[1], node, node_sz);
		if ( 0 != res ) { return res; }

		result.insert(result.end(), node, node + node_sz);
	}

	// Encode following nodes
	for ( std::size_t i = 2 ; i < nodes.size() ; ++i ) {
		encode_node(nodes[i], node, node_sz);
		if ( 0 != res ) { return res; }

		result.insert(result.end(), node, node + node_sz);
	}

	// Check destination size
	if ( data_sz < result.size() ) {
		data_sz = result.size();
		return CRYPTO_OID_INVALID_LENGTH;
	}

	// Copy result into final destionation
	memcpy(data, result.data(), result.size());
	data_sz = result.size();

	return CRYPTO_OID_SUCCESS;
}

int
OID::fill_bytes(const uint8_t *&data, std::size_t &data_sz, uint8_t bytes[5], std::size_t &bytes_sz)
{
	bytes_sz = 0;

	for ( std::size_t i = 0 ; i < 5 ; ++i ) {
		if ( 0 == data_sz ) {
			return CRYPTO_OID_VALUE_ERROR;
		}

		bytes[i] = data[0];
		++bytes_sz;

		data    += 1;
		data_sz -= 1;

		if ( 0x00 == (bytes[i] & 0x80) ) {
			break;
		}
	}

	// Check that last byte is the last chunk of data
	if ( 0x00 != (bytes[bytes_sz - 1] & 0x80) ) {
		return CRYPTO_OID_VALUE_ERROR;
	}

	return CRYPTO_OID_SUCCESS;
}

int
OID::decode_node(uint8_t data[5], std::size_t data_sz, uint32_t &node)
{
	if ( 0 == data_sz ) {
		return CRYPTO_OID_VALUE_ERROR;
	}

	// First byte cannot be null
	if ( 0x80 == data[0] ) {
		return CRYPTO_OID_VALUE_ERROR;
	}

	// Check for overflow
	if ( 5 == data_sz && data[0] >= 0x90 ) {
		return CRYPTO_OID_VALUE_ERROR;
	}

	node = data[0] & 0x7F;

	for ( std::size_t i = 1 ; i < data_sz ; ++i ) {
		node = node << 7;
		node = node | (data[i] & 0x7F);
	}

	return CRYPTO_OID_SUCCESS;
}

int
OID::encode_node(uint32_t node, uint8_t data[5], std::size_t &data_sz)
{
	uint8_t bytes[4];
	uint8_t c[4];

	// Split 32bits unsigned int into array of byte
	data_sz = 0;
	for ( std::size_t i = 0 ; i < 4 ; ++i ) {
		bytes[i] = static_cast<uint8_t>((node >> ((3 - i) * 8)) & 0xFF);

		if ( (0 == data_sz ) && (0x00 != bytes[i]) ) {
			data_sz = 4 - i;
		}
	}

	// If node is 0, one byte is still encoded
	if ( 0 == data_sz ) {
		++data_sz;
	}

	memset(c, 0x00, sizeof(c));

	for ( std::size_t i = 0 ; i < data_sz ; ++i ) {
		for ( std::size_t j = 0 ; j < i ; ++j ) {
			c[3 - i + j]  = (bytes[3 - i] & 0x80) != 0;
			bytes[3 - i]  = (bytes[3 - i] << 1) | c[3 - i + j + 1];
		}

		c[3]    = (bytes[3 - i] & 0x80) != 0;
		data[i] = (bytes[3 - i] & 0x7F) | 0x80;
	}

	// Last byte of encoded data must have bit 7 set to 0
	data[0] = data[0] & 0x7F;

	// Encode shifted bits if needed
	if ( c[0] || c[1] || c[2] || c[3] ) {
		data[data_sz] = 0x80;
		for ( std::size_t i = 0 ; i < 4 ; ++i ) {
			data[data_sz] |= c[i] << (3 - i);
		}
		++data_sz;
	}

	// Reverse array
	for ( std::size_t i = 0 ; i < (data_sz / 2) ; ++i ) {
		std::swap(data[i], data[data_sz - i - 1]);
	}

	return CRYPTO_OID_SUCCESS;
}

}
