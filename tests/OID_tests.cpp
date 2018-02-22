#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/OID.hpp"
#include "crypto/Utils.hpp"

TEST(OID, construction)
{
	Crypto::OID oid;

	EXPECT_EQ(oid.size(), 0);
	EXPECT_EQ(oid.to_string(), "");

	oid += 2;

	EXPECT_EQ(oid.size(), 1);
	EXPECT_EQ(oid[0], 2);
	EXPECT_EQ(oid.to_string(), "2");

	oid += 47;

	EXPECT_EQ(oid.size(), 2);
	EXPECT_EQ(oid[0],  2);
	EXPECT_EQ(oid[1], 47);
	EXPECT_EQ(oid.to_string(), "2.47");

	oid += 123;

	EXPECT_EQ(oid.size(), 3);
	EXPECT_EQ(oid[0],   2);
	EXPECT_EQ(oid[1],  47);
	EXPECT_EQ(oid[2], 123);
	EXPECT_EQ(oid.to_string(), "2.47.123");
}

TEST(OID, from_binary)
{
	const std::vector<std::vector<std::string>> tests = {
		{           "0C", "0.12"           },
		{         "0C7F", "0.12.127"       },
		{           "4F", "1.39"           },
		{         "417F", "1.25.127"       },
		{           "7F", "2.47"           },
		{         "8100", "2.48"           },
		{         "7F7B", "2.47.123"       },
		{       "7F007B", "2.47.0.123"     },
		{       "81007B", "2.48.123"       },
		{     "81008100", "2.48.128"       },
		{         "2800", "1.0.0"          },
		{         "2801", "1.0.1"          },
		{       "28817F", "1.0.255"        },
		{     "2883FF7F", "1.0.65535"      },
		{   "2887FFFF7F", "1.0.16777215"   },
		{ "288FFFFFFF7F", "1.0.4294967295" }
	};

	for ( auto test : tests ) {
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);

		Crypto::Utils::from_hex(test[0], data, data_sz);

		Crypto::OID oid(data, data_sz);

		EXPECT_EQ(oid.to_string(), test[1]);
	}
}

TEST(OID, from_binary_abnormal)
{
	// Data size is 0
	{
		int res;
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid data";

		res = Crypto::Utils::from_hex("7F007B", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			data_sz = 0;
			Crypto::OID oid(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}
	
	// Not enough data to process: #1
	{
		int res;
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid data";

		res = Crypto::Utils::from_hex("83FF7F", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			data_sz -= 1;
			Crypto::OID oid(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}

	// Not enough data to process: #2
	{
		int res;
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid data";

		res = Crypto::Utils::from_hex("83FF7FFF7F", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			data_sz -= 1;
			Crypto::OID oid(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}

	// Last byte is the last byte to process: #1
	{
		int res;
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid data";

		res = Crypto::Utils::from_hex("83FF", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::OID oid(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}

	// Last byte is the last byte to process: #2
	{
		int res;
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid data";

		res = Crypto::Utils::from_hex("4F83FF", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::OID oid(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}

	// Last byte is the last byte to process: #3
	{
		int res;
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid data";

		res = Crypto::Utils::from_hex("4F8FFFFFFFFF7F", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::OID oid(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}

	// First bit is 0x80 (not minimal): #1
	{
		int res;
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid data";

		res = Crypto::Utils::from_hex("8000", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::OID oid(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}

	// First bit is 0x80 (not minimal): #2
	{
		int res;
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid data";

		res = Crypto::Utils::from_hex("288000", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::OID oid(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}

	// Overflow possible: #1
	{
		int res;
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid data";

		res = Crypto::Utils::from_hex("90FFFFFF7F", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::OID oid(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}

	// Overflow possible: #2
	{
		int res;
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid data";

		res = Crypto::Utils::from_hex("2890FFFFFFFF", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::OID oid(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}
}

TEST(OID, to_binary)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0", "12",                         "0C" },
		{ "0", "12", "127",                "0C7F" },
		{ "1", "39",                         "4F" },
		{ "1", "25", "127",                "417F" },
		{ "2", "47",                         "7F" },
		{ "2", "48",                       "8100" },
		{ "2", "47", "123",                "7F7B" },
		{ "2", "47", "0", "123",         "7F007B" },
		{ "2", "48", "123",              "81007B" },
		{ "2", "48", "128",            "81008100" },
		{ "1",  "0", "0",                  "2800" },
		{ "1",  "0", "1",                  "2801" },
		{ "1",  "0", "255",              "28817F" },
		{ "1",  "0", "65535",          "2883FF7F" },
		{ "1",  "0", "16777215",     "2887FFFF7F" },
		{ "1",  "0", "4294967295", "288FFFFFFF7F" }
	};

	for ( auto test : tests ) {
		int res;
		Crypto::OID oid(atoi(test[0].c_str()));
		uint8_t data[64];
		std::size_t data_sz = sizeof(data);
		std::string binary_str;

		for ( std::size_t i = 1 ; i < test.size() - 1 ; ++i ) {
			oid += atoi(test[i].c_str());
		}

		res = oid.to_binary(data, data_sz);
		EXPECT_EQ(res, 0);

		Crypto::Utils::to_hex(data, data_sz, binary_str);
		EXPECT_EQ(binary_str, test[test.size() - 1]);
		EXPECT_EQ(data_sz, test[test.size() - 1].length() / 2);
	}
}

TEST(OID, to_binary_length)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0", "12",               "1" },
		{ "0", "12", "127",        "2" },
		{ "1", "39",               "1" },
		{ "1", "25", "127",        "2" },
		{ "2", "47",               "1" },
		{ "2", "48",               "2" },
		{ "2", "47", "123",        "2" },
		{ "2", "47", "0", "123",   "3" },
		{ "2", "48", "123",        "3" },
		{ "2", "48", "128",        "4" },
		{ "1",  "0", "0",          "2" },
		{ "1",  "0", "1",          "2" },
		{ "1",  "0", "255",        "3" },
		{ "1",  "0", "65535",      "4" },
		{ "1",  "0", "16777215",   "5" },
		{ "1",  "0", "4294967295", "6" },
	};

	for ( auto test : tests ) {
		int res;
		Crypto::OID oid(atoi(test[0].c_str()));
		uint8_t data[64];
		std::size_t data_sz;

		for ( std::size_t i = 1 ; i < test.size() - 1 ; ++i ) {
			oid += atoi(test[i].c_str());
		}

		std::size_t expected_sz = atoi(test[test.size() - 1].c_str());

		data_sz = 0;
		res = oid.to_binary(data, data_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(data_sz, expected_sz);
	}

}

TEST(OID, to_binary_abnormal)
{
	// Node size < 2
	{
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected("Impossible to encode any root OID without any second element");

		try {
			Crypto::OID oid(1);
			oid.to_binary(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}

	// Root node > 2
	{
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected("Impossible to encode any OID with root 3 or higher");

		try {
			Crypto::OID oid(3);
			oid += 1;
			oid.to_binary(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}
	
	// Root node = 0, second node = 40
	{
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected("Impossible to encode second child >= 40 if root OID is 0 or 1");

		try {
			Crypto::OID oid(0);
			oid += 40;
			oid.to_binary(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}

	// Root node = 0, second node = 40
	{
		uint8_t     data[256];
		std::size_t data_sz = sizeof(data);
		std::string expected("Impossible to encode second child >= 40 if root OID is 0 or 1");

		try {
			Crypto::OID oid(1);
			oid += 256;
			oid.to_binary(data, data_sz);

			FAIL() << "Expected: OID::Exception";
		} catch ( const Crypto::OID::Exception &oe ) {
			EXPECT_EQ(oe.what(), expected);
		}
	}
}

TEST(OID, to_string)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "1",                                    "1" },
		{ "1", "12",                           "1.12" },
		{ "1", "12", "243", "34567", "1.12.243.34567" }
	};

	for ( auto test : tests ) {
		Crypto::OID oid(atoi(test[0].c_str()));

		for ( std::size_t i = 1 ; i < test.size() - 1 ; ++i ) {
			oid += atoi(test[i].c_str());
		}

		std::string expected(test[test.size() - 1]);

		EXPECT_EQ(oid.to_string(), expected);
	}
}

TEST(OID, cmp)
{
	// Test case #1
	{ 
		Crypto::OID oid_1(1);
		oid_1 += 12;
		oid_1 += 243;

		Crypto::OID oid_2(1);
		oid_2 += 12;
		oid_2 += 243;

		EXPECT_TRUE(oid_1  == oid_2);
		EXPECT_FALSE(oid_1 != oid_2);
		EXPECT_FALSE(oid_1  < oid_2);
		EXPECT_FALSE(oid_2  < oid_1);
	}

	// Test case #2
	{ 
		Crypto::OID oid_1(1);
		oid_1 += 12;
		oid_1 += 243;

		Crypto::OID oid_2(1);
		oid_2 += 13;
		oid_2 += 243;

		EXPECT_TRUE(oid_1  != oid_2);
		EXPECT_FALSE(oid_1 == oid_2);
		EXPECT_TRUE(oid_1   < oid_2);
		EXPECT_FALSE(oid_2  < oid_1);
	}
}

TEST(OID, named)
{
	Crypto::OID oid = Crypto::OID::secp256r1();
	uint8_t     data[256];
	std::size_t data_sz = sizeof(data);
	std::string oid_str;

	Crypto::OID expected(1);
	expected += 2;
	expected += 840;
	expected += 10045;
	expected += 3;
	expected += 1;
	expected += 7;
	std::string expected_str("2A8648CE3D030107");

	// Check correct value
	EXPECT_EQ(oid, expected);

	// Check correct encoding
	oid.to_binary(data, data_sz);
	Crypto::Utils::to_hex(data, data_sz, oid_str);
	EXPECT_EQ(oid_str, expected_str);
}
