#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/ASN1.hpp"
#include "crypto/OID.hpp"
#include "crypto/Utils.hpp"

TEST(ASN1, read_header_abnormal)
{
	// Data_sz is 0 (tag cannot be read)
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t out[256];
		std::size_t out_sz = sizeof(out);
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("0201FF", data, data_sz);
		EXPECT_EQ(res, 0);

		data_sz = 0;
		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::BOOLEAN, out, out_sz, read_sz);
		EXPECT_EQ(res, 2);
	}

	// data_sz is too short for len written in TLV: #1
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t out[256];
		std::size_t out_sz = sizeof(out);
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("0201FF", data, data_sz);
		EXPECT_EQ(res, 0);

		data_sz = 1;
		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::BOOLEAN, out, out_sz, read_sz);
		EXPECT_EQ(res, 2);
	}

	// data_sz is too short for len written in TLV: #2
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t out[256];
		std::size_t out_sz = sizeof(out);
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("028101FF", data, data_sz);
		EXPECT_EQ(res, 0);

		data_sz = 2;
		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::BOOLEAN, out, out_sz, read_sz);
		EXPECT_EQ(res, 2);
	}

	// data_sz is too short for len written in TLV: #2
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t out[256];
		std::size_t out_sz = sizeof(out);
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("02820001FF", data, data_sz);
		EXPECT_EQ(res, 0);

		data_sz = 3;
		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::BOOLEAN, out, out_sz, read_sz);
		EXPECT_EQ(res, 2);
	}

	// Multi bytes length but size is 0
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t out[256];
		std::size_t out_sz = sizeof(out);
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("0280", data, data_sz);
		EXPECT_EQ(res, 0);

		data_sz = 2;
		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::BOOLEAN, out, out_sz, read_sz);
		EXPECT_EQ(res, 4);
	}

	// Multi byte len but size is > 4
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t out[256];
		std::size_t out_sz = sizeof(out);
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("02850000000001FF", data, data_sz);
		EXPECT_EQ(res, 0);

		data_sz = 8;
		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::BOOLEAN, out, out_sz, read_sz);
		EXPECT_EQ(res, 4);
	}

	// Multi byte len, but len is > than data_sz
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t out[256];
		std::size_t out_sz = sizeof(out);
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("028400000001FF", data, data_sz);
		EXPECT_EQ(res, 0);

		data_sz = 5;
		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::BOOLEAN, out, out_sz, read_sz);
		EXPECT_EQ(res, 2);
	}

	// Single byte len, but not enough data to read
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t out[256];
		std::size_t out_sz = sizeof(out);
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("0201FF", data, data_sz);
		EXPECT_EQ(res, 0);

		data_sz = 2;
		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::BOOLEAN, out, out_sz, read_sz);
		EXPECT_EQ(res, 2);
	}

	// Multi byte leng, but not enough data to read
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t out[256];
		std::size_t out_sz = sizeof(out);
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("028400000002FFFF", data, data_sz);
		EXPECT_EQ(res, 0);

		data_sz = 7;
		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::BOOLEAN, out, out_sz, read_sz);
		EXPECT_EQ(res, 2);
	}
}

TEST(ASN1, read_boolean)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "010100", "false" },
		{ "0101AA", "true"  },
		{ "0101FF", "true"  }
	};

	for ( auto test : tests ) {
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		bool boolean;
		std::size_t read_sz;

		res = Crypto::Utils::from_hex(test[0], data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_boolean(data, data_sz, boolean, read_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(boolean, (test[1] == "true"));
		EXPECT_EQ(read_sz, test[0].length() / 2);
	}
}

TEST(ASN1, read_boolean_abnormal)
{
	// Tag is not Boolean
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		bool boolean;
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("0200", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_boolean(data, data_sz, boolean, read_sz);
		EXPECT_EQ(res, 3);
	}

	// Length is not 1
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		bool boolean;
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("01020000", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_boolean(data, data_sz, boolean, read_sz);
		EXPECT_EQ(res, 5);
	}
}

TEST(ASN1, read_integer)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "02020100",      "256", "10" },
		{ "020200c1",      "193", "10" },
		{ "02020081",      "129", "10" },
		{ "02020080",      "128", "10" },
		{ "02017f",        "127", "10" },
		{ "020100",          "0", "10" },
		{ "020181",       "-127", "10" },
		{ "020180",       "-128", "10" },
		{ "0202ff7f",     "-129", "10" },
		{ "0202ff3f",     "-193", "10" },
		{ "0202ff00",     "-256", "10" },
		{ "0203010001", "010001", "16" },
		{
			"024100edf1bb37dd9f6e70a2c4b63017a49152636768f42941d3d7e897c82318"
			"72551eea3a6349b8209531e1ebb84a1cd4ea6dfeb0f04e7ba6841631ef79beb8"
			"3b0c7d",
			"edf1bb37dd9f6e70a2c4b63017a49152636768f42941d3d7e897c8231872551e"
			"ea3a6349b8209531e1ebb84a1cd4ea6dfeb0f04e7ba6841631ef79beb83b0c7d",
			"16"
		},
		{
			"021e009df6c8f5381560fcf54769170fee01966f1425a4b29508a01498bf788d",
			"9df6c8f5381560fcf54769170fee01966f1425a4b29508a01498bf788d",
			"16"
		},
		{
			"021d04b43c6863c1f02a6ebce19775aaea5b59a516460de561866f85d90d60",
			"04b43c6863c1f02a6ebce19775aaea5b59a516460de561866f85d90d60",
			"16"
		},
		{
			"021eff6209370ac7ea9f030ab896e8f011fe6990ebda5b4d6af75feb67408773",
			"-9df6c8f5381560fcf54769170fee01966f1425a4b29508a01498bf788d",
			"16"
		},
		{
			"021dfb4bc3979c3e0fd591431e688a5515a4a65ae9b9f21a9e79907a26f2a0",
			"-04b43c6863c1f02a6ebce19775aaea5b59a516460de561866f85d90d60",
			"16"
		}
	};

	for ( auto test : tests ) {
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		Crypto::BigNum integer;
		std::size_t read_sz;

		res = Crypto::Utils::from_hex(test[0], data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_integer(data, data_sz, integer, read_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(integer, Crypto::BigNum(test[1], atoi(test[2].c_str())));
		EXPECT_EQ(read_sz, test[0].length() / 2);
	}
}

TEST(ASN1, read_integer_abnormal)
{
	// Tag is not Boolean
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		Crypto::BigNum integer;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_TAG_ERROR;

		res = Crypto::Utils::from_hex("0100", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_integer(data, data_sz, integer, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Length is 0
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		Crypto::BigNum integer;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_VALUE_ERROR;

		res = Crypto::Utils::from_hex("0200", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_integer(data, data_sz, integer, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Not minimal encoding (0x00)
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		Crypto::BigNum integer;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_VALUE_ERROR;

		res = Crypto::Utils::from_hex("0202007F", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_integer(data, data_sz, integer, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Not minimal encoding (0xFF)
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		Crypto::BigNum integer;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_VALUE_ERROR;

		res = Crypto::Utils::from_hex("0202FF80", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_integer(data, data_sz, integer, read_sz);
		EXPECT_EQ(res, expected_res);
	}
}

TEST(ASN1, read_bit_string)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "030100",                                     "", "00" },
		{ "03020000",                                 "00", "00" },
		{ "03020100",                                 "00", "01" },
		{ "030A05000102030405060708", "000102030405060708", "05" },
		{ "030A07000102030405060708", "000102030405060708", "07" }
	};

	for ( auto test : tests ) {
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t bit_string[256];
		std::size_t bit_string_sz = sizeof(bit_string);
		uint8_t unused_sz;
		std::size_t read_sz;
		std::string bit_string_str;

		res = Crypto::Utils::from_hex(test[0], data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_bit_string(data, data_sz, bit_string, bit_string_sz, unused_sz, read_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(read_sz, test[0].length() / 2);

		res = Crypto::Utils::to_hex(bit_string, bit_string_sz, bit_string_str);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(bit_string_str, test[1]);
		EXPECT_EQ(unused_sz, atoi(test[2].c_str()));
	}
}

TEST(ASN1, read_bit_string_abnormal)
{
	// Tag is not Bit String
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t bit_string[256];
		std::size_t bit_string_sz = sizeof(bit_string_sz);
		uint8_t unused_sz;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_TAG_ERROR;

		res = Crypto::Utils::from_hex("0100", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_bit_string(data, data_sz, bit_string, bit_string_sz, unused_sz, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Length is 0
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t bit_string[256];
		std::size_t bit_string_sz = sizeof(bit_string_sz);
		uint8_t unused_sz;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_VALUE_ERROR;

		res = Crypto::Utils::from_hex("0300", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_bit_string(data, data_sz, bit_string, bit_string_sz, unused_sz, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Unused bits is > 7
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t bit_string[256];
		std::size_t bit_string_sz = sizeof(bit_string_sz);
		uint8_t unused_sz;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_VALUE_ERROR;

		res = Crypto::Utils::from_hex("03020800", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_bit_string(data, data_sz, bit_string, bit_string_sz, unused_sz, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// bit_string_sz is not large enough
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t bit_string[256];
		std::size_t bit_string_sz;
		uint8_t unused_sz;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_INVALID_LENGTH;

		res = Crypto::Utils::from_hex("0306000001020304", data, data_sz);
		EXPECT_EQ(res, 0);

		bit_string_sz = 4;
		res = Crypto::ASN1::read_bit_string(data, data_sz, bit_string, bit_string_sz, unused_sz, read_sz);
		EXPECT_EQ(res, expected_res);
		EXPECT_EQ(bit_string_sz, (std::size_t)5);
	}
}

TEST(ASN1, read_octet_string)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0400",                                         "" },
		{ "040100",                                     "00" },
		{ "0402FFFF",                                 "FFFF" },
		{ "040A00010203040506070809", "00010203040506070809" }
	};

	for ( auto test : tests ) {
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t octet_string[256];
		std::size_t octet_string_sz = sizeof(octet_string);
		std::size_t read_sz;
		std::string octet_string_str;

		res = Crypto::Utils::from_hex(test[0], data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_octet_string(data, data_sz, octet_string, octet_string_sz, read_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(read_sz, test[0].length() / 2);

		res = Crypto::Utils::to_hex(octet_string, octet_string_sz, octet_string_str);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(octet_string_str, test[1]);
	}
}

TEST(ASN1, read_octet_string_abnormal)
{
	// Tag is not Octet String
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t octet_string[256];
		std::size_t octet_string_sz = sizeof(octet_string_sz);
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_TAG_ERROR;

		res = Crypto::Utils::from_hex("0100", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_octet_string(data, data_sz, octet_string, octet_string_sz, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// bit_string_sz is not large enough
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t octet_string[256];
		std::size_t octet_string_sz = sizeof(octet_string_sz);
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_INVALID_LENGTH;

		res = Crypto::Utils::from_hex("04050001020304", data, data_sz);
		EXPECT_EQ(res, 0);

		octet_string_sz = 4;
		res = Crypto::ASN1::read_octet_string(data, data_sz, octet_string, octet_string_sz, read_sz);
		EXPECT_EQ(res, expected_res);
		EXPECT_EQ(octet_string_sz, (std::size_t)5);
	}
}

TEST(ASN1, read_null)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0500" }
	};

	for ( auto test : tests ) {
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t read_sz;

		res = Crypto::Utils::from_hex(test[0], data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_null(data, data_sz, read_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(read_sz, test[0].length() / 2);
	}
}

TEST(ASN1, read_null_abnormal)
{
	// Tag is not Null
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_TAG_ERROR;

		res = Crypto::Utils::from_hex("0100", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_null(data, data_sz, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// read_sz is not 2
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_VALUE_ERROR;

		res = Crypto::Utils::from_hex("058100", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_null(data, data_sz, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Length is not 0
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_VALUE_ERROR;

		res = Crypto::Utils::from_hex("050100", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_null(data, data_sz, read_sz);
		EXPECT_EQ(res, expected_res);
	}
}

TEST(ASN1, read_oid)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "06010C",           "0.12"           },
		{ "06020C7F",         "0.12.127"       },
		{ "06014F",           "1.39"           },
		{ "0602417F",         "1.25.127"       },
		{ "06017F",           "2.47"           },
		{ "06028100",         "2.48"           },
		{ "06027F7B",         "2.47.123"       },
		{ "06037F007B",       "2.47.0.123"     },
		{ "060381007B",       "2.48.123"       },
		{ "060481008100",     "2.48.128"       },
		{ "06022800",         "1.0.0"          },
		{ "06022801",         "1.0.1"          },
		{ "060328817F",       "1.0.255"        },
		{ "06042883FF7F",     "1.0.65535"      },
		{ "06052887FFFF7F",   "1.0.16777215"   },
		{ "0606288FFFFFFF7F", "1.0.4294967295" }
	};

	for ( auto test : tests ) {
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		Crypto::OID oid;
		std::size_t read_sz;

		res = Crypto::Utils::from_hex(test[0], data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_oid(data, data_sz, oid, read_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(oid.to_string(), test[1]);
		EXPECT_EQ(read_sz, test[0].length() / 2);
	}
}

TEST(ASN1, read_oid_abnormal)
{
	// Tag is not OID
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		Crypto::OID oid;
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("0100", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_oid(data, data_sz, oid, read_sz);
		EXPECT_EQ(res, 3);
	}

	// Length is 0
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		Crypto::OID oid;
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("0600", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_oid(data, data_sz, oid, read_sz);
		EXPECT_EQ(res, 5);
	}

	// OID encoding is invalid
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		Crypto::OID oid;
		std::size_t read_sz;

		res = Crypto::Utils::from_hex("060283FF7F", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_oid(data, data_sz, oid, read_sz);
		EXPECT_EQ(res, 5);
	}
}

TEST(ASN1, read_sequence)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "3000"                                                                     },
		{ "30030101FF",                       "0101FF"                               },
		{ "30060101FF020100",                 "0101FF", "020100"                     },
		{ "300E0101FF02010010060101FF020100", "0101FF", "020100", "10060101FF020100" }
	};

	for ( auto test : tests ) {
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> sequence;
		std::size_t read_sz;

		res = Crypto::Utils::from_hex(test[0], data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_sequence(data, data_sz, sequence, read_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(sequence.size(), test.size() - 1);

		for ( std::size_t i = 0 ; i < sequence.size() ; ++i ) {
			std::string item;

			res = Crypto::Utils::to_hex(sequence[i].first, sequence[i].second, item);
			EXPECT_EQ(res, 0);
			EXPECT_EQ(item, test[i + 1]);
		}
	}
}

TEST(ASN1, read_sequence_abnormal)
{
	// Tag is not Sequence
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> sequence;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_TAG_ERROR;

		res = Crypto::Utils::from_hex("0100", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_sequence(data, data_sz, sequence, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Tag is not Constructed
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> sequence;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_TAG_ERROR;

		res = Crypto::Utils::from_hex("1000", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_sequence(data, data_sz, sequence, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Only Tag in Sequence
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> sequence;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_OUT_OF_DATA;

		res = Crypto::Utils::from_hex("300104", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_sequence(data, data_sz, sequence, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Only Tag and Length in Sequence
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> sequence;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_OUT_OF_DATA;

		res = Crypto::Utils::from_hex("30020401", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_sequence(data, data_sz, sequence, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Data shorter than expected in Sequence's item
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> sequence;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_OUT_OF_DATA;

		res = Crypto::Utils::from_hex("3003040200", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_sequence(data, data_sz, sequence, read_sz);
		EXPECT_EQ(res, expected_res);
	}
}

TEST(ASN1, read_set)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "3100"                                                                     },
		{ "31030101FF",                       "0101FF"                               },
		{ "31060101FF020100",                 "0101FF", "020100"                     },
		{ "310E0101FF02010011060101FF020100", "0101FF", "020100", "11060101FF020100" }
	};

	for ( auto test : tests ) {
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> set;
		std::size_t read_sz;

		res = Crypto::Utils::from_hex(test[0], data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_set(data, data_sz, set, read_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(set.size(), test.size() - 1);

		for ( std::size_t i = 0 ; i < set.size() ; ++i ) {
			std::string item;

			res = Crypto::Utils::to_hex(set[i].first, set[i].second, item);
			EXPECT_EQ(res, 0);
			EXPECT_EQ(item, test[i + 1]);
		}
	}
}

TEST(ASN1, read_set_abnormal)
{
	// Tag is not Set
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> set;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_TAG_ERROR;

		res = Crypto::Utils::from_hex("0100", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_set(data, data_sz, set, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Tag is not constructed
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> set;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_TAG_ERROR;

		res = Crypto::Utils::from_hex("1100", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_set(data, data_sz, set, read_sz);
		EXPECT_EQ(res, expected_res);
	}	

	// Only Tag in Set
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> set;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_OUT_OF_DATA;

		res = Crypto::Utils::from_hex("310104", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_set(data, data_sz, set, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Only Tag and Length in Set
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> set;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_OUT_OF_DATA;

		res = Crypto::Utils::from_hex("31020401", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_set(data, data_sz, set, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Data shorter than expected in Set's item
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::vector<std::pair<const uint8_t*, std::size_t>> set;
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_OUT_OF_DATA;

		res = Crypto::Utils::from_hex("3103040200", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_set(data, data_sz, set, read_sz);
		EXPECT_EQ(res, expected_res);
	}
}

TEST(ASN1, read_data)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "01012C",               "01",               "2C" },
		{ "0500",                 "05",                 "" },
		{ "09080123456789ABCDEF", "09", "0123456789ABCDEF" }
	};

	for ( auto test : tests ) {
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		Crypto::ASN1::Tag tag;
		uint8_t value[256];
		std::size_t value_sz = sizeof(value);
		std::size_t read_sz;
		std::string value_str;

		res = Crypto::Utils::from_hex(test[0], data, data_sz);
		EXPECT_EQ(res, 0);

		tag = static_cast<Crypto::ASN1::Tag>(atoi(test[1].c_str()));
		res = Crypto::ASN1::read_data(data, data_sz, tag, value, value_sz, read_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(read_sz, test[0].length() / 2);

		res = Crypto::Utils::to_hex(value, value_sz, value_str);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(value_str, test[2]);
	}
}

TEST(ASN1, read_data_abnormal)
{
	// Tag is not as specified
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t value[256];
		std::size_t value_sz = sizeof(value);
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_TAG_ERROR;

		res = Crypto::Utils::from_hex("010100", data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::INTEGER, value, value_sz, read_sz);
		EXPECT_EQ(res, expected_res);
	}

	// Not enough space to write data
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		uint8_t value[256];
		std::size_t value_sz = sizeof(value);
		std::size_t read_sz;
		int expected_res = Crypto::ASN1::CRYPTO_ASN1_INVALID_LENGTH;

		res = Crypto::Utils::from_hex("010100", data, data_sz);
		EXPECT_EQ(res, 0);

		value_sz = 0;
		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::BOOLEAN, value, value_sz, read_sz);
		EXPECT_EQ(res, expected_res);
		EXPECT_EQ(value_sz, (std::size_t)1);

		value_sz = 1;
		res = Crypto::ASN1::read_data(data, data_sz, Crypto::ASN1::Tag::BOOLEAN, value, value_sz, read_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(value[0], 0x00);
		EXPECT_EQ(value_sz, (std::size_t)1);
	}
}

TEST(ASN1, write_header_abnormal)
{
	// Data_sz is 0 (tag cannot be written)
	{
		int res;
		uint8_t value[256];
		std::size_t value_sz = sizeof(value);
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;

		memset(value, 0x00, value_sz);
		value_sz = 1;

		data_sz = 0;
		res = Crypto::ASN1::write_data(Crypto::ASN1::Tag::BOOLEAN, value, value_sz, data, data_sz, write_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(write_sz, (std::size_t)3);
	}

	// Data_sz is 1 (len cannot be written)
	{
		int res;
		uint8_t value[256];
		std::size_t value_sz = sizeof(value);
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;

		memset(value, 0x00, value_sz);
		value_sz = 1;

		data_sz = 1;
		res = Crypto::ASN1::write_data(Crypto::ASN1::Tag::BOOLEAN, value, value_sz, data, data_sz, write_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(write_sz, (std::size_t)3);
	}

	// Multi byte length on more than 4 bytes
	if ( sizeof(std::size_t) > 4 ) {
		int res;
		uint8_t value[256];
		std::size_t value_sz = sizeof(value);
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;

		memset(value, 0x00, value_sz);
		value_sz = -1;

		res = Crypto::ASN1::write_data(Crypto::ASN1::Tag::BOOLEAN, value, value_sz, data, data_sz, write_sz);
		EXPECT_EQ(res, 4);
	}

	// Not enough space for multi bytes len #1
	{
		int res;
		uint8_t value[256];
		std::size_t value_sz = sizeof(value);
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;

		memset(value, 0x00, value_sz);
		value_sz = 256;

		data_sz = 2;
		res = Crypto::ASN1::write_data(Crypto::ASN1::Tag::BOOLEAN, value, value_sz, data, data_sz, write_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(write_sz, (std::size_t)260);
	}

	// Not enough space for multi bytes len #2
	{
		int res;
		uint8_t value[65536];
		std::size_t value_sz = sizeof(value);
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;

		memset(value, 0x00, value_sz);
		value_sz = 65536;

		data_sz = 3;
		res = Crypto::ASN1::write_data(Crypto::ASN1::Tag::BOOLEAN, value, value_sz, data, data_sz, write_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(write_sz, (std::size_t)65541);
	}

	// data_sz is not enough for Value
	{
		int res;
		uint8_t value[256];
		std::size_t value_sz = sizeof(value);
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;

		memset(value, 0x00, value_sz);
		value_sz = 1;

		data_sz = 2;
		res = Crypto::ASN1::write_data(Crypto::ASN1::Tag::BOOLEAN, value, value_sz, data, data_sz, write_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(write_sz, (std::size_t)3);
	}
}

TEST(ASN1, write_boolean)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "false", "010100" },
		{ "true",  "0101FF" }
	};

	for ( auto test : tests ) {
		int res;
		bool boolean;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;
		std::string boolean_str;

		boolean = test[0] == "true";
		res = Crypto::ASN1::write_boolean(boolean, data, data_sz, write_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, write_sz, boolean_str);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(boolean_str, test[1]);
	}
}

TEST(ASN1, write_integer)
{
	const std::vector<std::vector<std::string>> tests = {
		{    "256", "10", "02020100"   },
		{    "193", "10", "020200c1"   },
		{    "129", "10", "02020081"   },
		{    "128", "10", "02020080"   },
		{    "127", "10", "02017f"     },
		{      "0", "10", "020100"     },
		{   "-127", "10", "020181"     },
		{   "-128", "10", "020180"     },
		{   "-129", "10", "0202ff7f"   },
		{   "-193", "10", "0202ff3f"   },
		{   "-256", "10", "0202ff00"   },
		{ "010001", "16", "0203010001" },
		{
			"edf1bb37dd9f6e70a2c4b63017a49152636768f42941d3d7e897c8231872551e"
			"ea3a6349b8209531e1ebb84a1cd4ea6dfeb0f04e7ba6841631ef79beb83b0c7d",
			"16",
			"024100edf1bb37dd9f6e70a2c4b63017a49152636768f42941d3d7e897c82318"
			"72551eea3a6349b8209531e1ebb84a1cd4ea6dfeb0f04e7ba6841631ef79beb8"
			"3b0c7d"
		},
		{
			"9df6c8f5381560fcf54769170fee01966f1425a4b29508a01498bf788d",
			"16",
			"021e009df6c8f5381560fcf54769170fee01966f1425a4b29508a01498bf788d"
		},
		{
			"04b43c6863c1f02a6ebce19775aaea5b59a516460de561866f85d90d60",
			"16",
			"021d04b43c6863c1f02a6ebce19775aaea5b59a516460de561866f85d90d60"
		},
		{
			"-9df6c8f5381560fcf54769170fee01966f1425a4b29508a01498bf788d",
			"16",
			"021eff6209370ac7ea9f030ab896e8f011fe6990ebda5b4d6af75feb67408773"
		},
		{
			"-04b43c6863c1f02a6ebce19775aaea5b59a516460de561866f85d90d60",
			"16",
			"021dfb4bc3979c3e0fd591431e688a5515a4a65ae9b9f21a9e79907a26f2a0"
		}
	};

	for ( auto test : tests ) {
		int res;
		Crypto::BigNum integer;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;
		std::string integer_str;

		integer = Crypto::BigNum(test[0], atoi(test[1].c_str()));

		res = Crypto::ASN1::write_integer(integer, data, data_sz, write_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, write_sz, integer_str, false);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(integer_str, test[2]);
	}
}

TEST(ASN1, write_bit_string)
{
	const std::vector<std::vector<std::string>> tests = {
		{                   "", "00", "030100"                   },
		{                 "00", "00", "03020000"                 },
		{                 "00", "01", "03020100"                 },
		{ "000102030405060708", "05", "030A05000102030405060708" },
		{ "000102030405060708", "07", "030A07000102030405060708" }
	};

	for ( auto test : tests ) {
		int res;
		uint8_t bit_string[256];
		std::size_t bit_string_sz = sizeof(bit_string);
		uint8_t unused_bits;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;
		std::string bit_string_str;

		res = Crypto::Utils::from_hex(test[0], bit_string, bit_string_sz);
		EXPECT_EQ(res, 0);
		unused_bits = static_cast<uint8_t>(atoi(test[1].c_str()));
		
		res = Crypto::ASN1::write_bit_string(bit_string, bit_string_sz, unused_bits, data, data_sz, write_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, write_sz, bit_string_str);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(bit_string_str, test[2]);
	}
}

TEST(ASN1, write_bit_string_abnormal)
{
	// Bit string with more than 7 unused bits
	{
		int res;
		uint8_t bit_string[256];
		std::size_t bit_string_sz = sizeof(bit_string);
		uint8_t unused_bits;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;
		std::string bit_string_str;

		res = Crypto::Utils::from_hex("000102030405060708", bit_string, bit_string_sz);
		EXPECT_EQ(res, 0);
		unused_bits = 8;

		res = Crypto::ASN1::write_bit_string(bit_string, bit_string_sz, unused_bits, data, data_sz, write_sz);
		EXPECT_EQ(res, 5);
	}
}

TEST(ASN1, write_octet_string)
{
	const std::vector<std::vector<std::string>> tests = {
		{                     "", "0400"                     },
		{                   "00", "040100"                   },
		{                 "FFFF", "0402FFFF"                 },
		{ "00010203040506070809", "040A00010203040506070809" }
	};

	for ( auto test : tests ) {
		int res;
		uint8_t octet_string[256];
		std::size_t octet_string_sz = sizeof(octet_string);
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;
		std::string octet_string_str;

		res = Crypto::Utils::from_hex(test[0], octet_string, octet_string_sz);
		EXPECT_EQ(res, 0);
		
		res = Crypto::ASN1::write_octet_string(octet_string, octet_string_sz, data, data_sz, write_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, write_sz, octet_string_str);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(octet_string_str, test[1]);
	}
}

TEST(ASN1, write_null)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0500" }
	};

	for ( auto test : tests ) {
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;
		std::string null_str;

		res = Crypto::ASN1::write_null(data, data_sz, write_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, write_sz, null_str);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(null_str, test[0]);
	}
}

TEST(ASN1, write_oid)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0", "12",               "06010C"           },
		{ "0", "12", "127",        "06020C7F"         },
		{ "1", "39",               "06014F"           },
		{ "1", "25", "127",        "0602417F"         },
		{ "2", "47",               "06017F"           },
		{ "2", "48",               "06028100"         },
		{ "2", "47", "123",        "06027F7B"         },
		{ "2", "47", "0",   "123", "06037F007B"       },
		{ "2", "48", "123",        "060381007B"       },
		{ "2", "48", "128",        "060481008100"     },
		{ "1", "0",  "0",          "06022800"         },
		{ "1", "0",  "1",          "06022801"         },
		{ "1", "0",  "255",        "060328817F"       },
		{ "1", "0",  "65535",      "06042883FF7F"     },
		{ "1", "0",  "16777215",   "06052887FFFF7F"   },
		{ "1", "0",  "4294967295", "0606288FFFFFFF7F" }

	};

	for ( auto test : tests ) {
		int res;
		Crypto::OID oid;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;
		std::string oid_str;

		oid = Crypto::OID(atoi(test[0].c_str()));
		for ( std::size_t i = 1 ; i < test.size() - 1 ; ++i ) {
			oid += atoi(test[i].c_str());
		}

		res = Crypto::ASN1::write_oid(oid, data, data_sz, write_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, write_sz, oid_str);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(oid_str, test.back());
	}
}

TEST(ASN1, write_oid_abnormal)
{
	// Non encodable OID
	{
		int res;
		Crypto::OID oid(1);
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;

		res = Crypto::ASN1::write_oid(oid, data, data_sz, write_sz);
		EXPECT_EQ(res, 5);
	}
}

TEST(ASN1, write_sequence)
{
	const std::vector<std::vector<std::string>> tests = {
		{                                         "3000"                             },
		{ "0101FF",                               "30030101FF"                       },
		{ "0101FF", "020100",                     "30060101FF020100"                 },
		{ "0101FF", "020100", "10060101FF020100", "300E0101FF02010010060101FF020100" }
	};

	for ( auto test : tests ) {
		int res;
		std::vector<std::pair<const uint8_t*, std::size_t>> sequence;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;
		std::string sequence_str;

		for ( std::size_t i = 0 ; i < test.size() - 1 ; ++i ) {
			uint8_t *item = new uint8_t[16];
			std::size_t item_sz = 16;

			res = Crypto::Utils::from_hex(test[i], item, item_sz);
			EXPECT_EQ(res, 0);

			sequence.push_back({ item, item_sz });
		}

		res = Crypto::ASN1::write_sequence(sequence, data, data_sz, write_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, write_sz, sequence_str);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(sequence_str, test.back());

		for ( auto item : sequence ) {
			delete[] item.first;
		}
	}
}

TEST(ASN1, write_set)
{
	const std::vector<std::vector<std::string>> tests = {
		{                                         "3100"                             },
		{ "0101FF",                               "31030101FF"                       },
		{ "0101FF", "020100",                     "31060101FF020100"                 },
		{ "0101FF", "020100", "10060101FF020100", "310E0101FF02010010060101FF020100" }
	};

	for ( auto test : tests ) {
		int res;
		std::vector<std::pair<const uint8_t*, std::size_t>> set;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;
		std::string set_str;

		for ( std::size_t i = 0 ; i < test.size() - 1 ; ++i ) {
			uint8_t *item = new uint8_t[16];
			std::size_t item_sz = 16;

			res = Crypto::Utils::from_hex(test[i], item, item_sz);
			EXPECT_EQ(res, 0);

			set.push_back({ item, item_sz });
		}

		res = Crypto::ASN1::write_set(set, data, data_sz, write_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, write_sz, set_str);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(set_str, test.back());

		for ( auto item : set ) {
			delete[] item.first;
		}
	}
}

TEST(ASN1, write_data)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "01",               "2C",               "01012C" },
		{ "05",                 "",                 "0500" },
		{ "09", "0123456789ABCDEF", "09080123456789ABCDEF" }
	};

	for ( auto test : tests ) {
		int res;
		Crypto::ASN1::Tag tag;
		uint8_t value[256];
		std::size_t value_sz = sizeof(value);
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::size_t write_sz;
		std::string data_str;

		tag = static_cast<Crypto::ASN1::Tag>(atoi(test[0].c_str()));
		res = Crypto::Utils::from_hex(test[1], value, value_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::ASN1::write_data(tag, value, value_sz, data, data_sz, write_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, write_sz, data_str);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(data_str, test[2]);
	}
}
