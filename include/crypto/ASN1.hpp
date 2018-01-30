#ifndef CRYPTO_ASN1_H
#define CRYPTO_ASN1_H

#include "crypto/BigNum.hpp"
#include "crypto/OID.hpp"

#include <stdexcept>

#include <utility>
#include <vector>

#include <cstddef>
#include <cstdint>

namespace Crypto
{

class ASN1
{
	public:
		enum class Tag : uint8_t;

		static int read_boolean(const uint8_t*, std::size_t, bool&, std::size_t&);
		static int read_integer(const uint8_t*, std::size_t, BigNum&, std::size_t&);
		static int read_bit_string(const uint8_t*, std::size_t, uint8_t*, std::size_t&, uint8_t&, std::size_t&);
		static int read_octet_string(const uint8_t*, std::size_t, uint8_t*, std::size_t&, std::size_t&);
		static int read_null(const uint8_t*, std::size_t, std::size_t&);
		static int read_oid(const uint8_t*, std::size_t, OID&, std::size_t&);
		static int read_sequence(const uint8_t*, std::size_t, std::vector<std::pair<const uint8_t*, std::size_t>>&, std::size_t&);
		static int read_set(const uint8_t*, std::size_t, std::vector<std::pair<const uint8_t*, std::size_t>>&, std::size_t&);
		static int read_data(const uint8_t*, std::size_t, const Tag&, uint8_t*, std::size_t&, std::size_t&);

		static int write_boolean(bool, uint8_t*, std::size_t, std::size_t&);
		static int write_integer(const BigNum&, uint8_t*, std::size_t, std::size_t&);
		static int write_bit_string(const uint8_t*, std::size_t, uint8_t, uint8_t*, std::size_t, std::size_t&);
		static int write_octet_string(const uint8_t*, std::size_t, uint8_t*, std::size_t, std::size_t&);
		static int write_null(uint8_t*, std::size_t, std::size_t&);
		static int write_oid(const OID&, uint8_t*, std::size_t, std::size_t&);
		static int write_sequence(const std::vector<std::pair<const uint8_t*, std::size_t>>&, uint8_t*, std::size_t, std::size_t&);
		static int write_set(const std::vector<std::pair<const uint8_t*, std::size_t>>&, uint8_t*, std::size_t, std::size_t&);
		static int write_data(const Tag&, const uint8_t*, std::size_t, uint8_t*, std::size_t, std::size_t&);

		enum class Tag : uint8_t {
			RESERVED                = 0x00,
			BOOLEAN			= 0x01,
			INTEGER			= 0x02,
			BIT_STRING		= 0x03,
			OCTET_STRING		= 0x04,
			TAG_NULL		= 0x05,
			OBJECT_IDENTIFIER	= 0x06,
			OBJECT_DESCRIPTOR	= 0x07,
			EXTERNAL		= 0x08,
			REAL			= 0x09,
			ENUMERATED		= 0x0A,
			EMBEDDED_PDV		= 0x0B,
			UTF8_STRING		= 0x0C,
			RELATIVE_OID		= 0x0D,
			SEQUENCE		= 0x10,
			SET			= 0x11,
			NUMERIC_STRING		= 0x12,
			PRINTABLE_STRING	= 0x13,
			T61_STRING		= 0x14,
			VIDEOTEXT_STRING	= 0x15,
			IA5_STRING		= 0x16,
			UTC_TIME		= 0x17,
			GENERALIZED_TIME	= 0x18,
			GRAPHIC_STRING		= 0x19,
			VISIBLE_STRING		= 0x1A,
			GENERAL_STRING		= 0x1B,
			UNIVERSAL_STRING	= 0x1C,
			CHARACTER_STRING	= 0x1D,
			BMP_STRING		= 0x1E
		};

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const int CRYPTO_ASN1_SUCCESS        = 0x00;
		static const int CRYPTO_ASN1_INVALID_LENGTH = 0x01;
		static const int CRYPTO_ASN1_OUT_OF_DATA    = 0x02;
		static const int CRYPTO_ASN1_TAG_ERROR      = 0x03;
		static const int CRYPTO_ASN1_LENGTH_ERROR   = 0x04;
		static const int CRYPTO_ASN1_VALUE_ERROR    = 0x05;
	private:
		static int read_header(const uint8_t*, std::size_t, Tag&, std::size_t&, std::size_t&);
		static int read_tag(const uint8_t*, std::size_t, Tag&, std::size_t&);
		static int read_len(const uint8_t*, std::size_t, std::size_t&, std::size_t&);

		static int write_header(const Tag&, std::size_t, uint8_t*, std::size_t, std::size_t&);
		static int write_tag(const Tag&, uint8_t*, std::size_t, std::size_t&);
		static int write_len(std::size_t, uint8_t*, std::size_t, std::size_t&);
};

}

#endif
