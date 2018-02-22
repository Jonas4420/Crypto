#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"

TEST(Utils, zeroize)
{
	uint8_t expected[10] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t array[10]    = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	Crypto::Utils::zeroize(array, 10);

	EXPECT_THAT(array, ::testing::ElementsAreArray(expected));
}

TEST(Utils, from_string)
{
	uint8_t expected[6] = { 0x66, 0x6F, 0x6F, 0x62, 0x61, 0x72 };
	std::string in = "foobar";
	uint8_t out[6];
	std::size_t out_sz;

	out_sz = 0;
	Crypto::Utils::from_string(in, NULL, out_sz);
	EXPECT_EQ(out_sz, (std::size_t)6);

	out_sz = 0;
	Crypto::Utils::from_string(in, out, out_sz);
	EXPECT_EQ(out_sz, (std::size_t)6);

	out_sz = 6;
	Crypto::Utils::from_string(in, out, out_sz);
	EXPECT_THAT(out, ::testing::ElementsAreArray(expected));
	EXPECT_EQ(out_sz, (std::size_t)6);
}

TEST(Utils, from_string_empty)
{
	std::string in = "";
	uint8_t out[1];
	std::size_t out_sz;

	out_sz = 1;
	Crypto::Utils::from_string(in, out, out_sz);
	EXPECT_EQ(out_sz, (std::size_t)0);
}

TEST(Utils, to_string)
{
	std::string expected = "foobar";
	uint8_t in[6] = { 0x66, 0x6F, 0x6F, 0x62, 0x61, 0x72 };
	std::size_t in_sz = 6;
	std::string out;

	Crypto::Utils::to_string(in, in_sz, out);
	EXPECT_EQ(out, expected);
}

TEST(Utils, to_string_empty)
{
	std::string expected = "";
	uint8_t in[1];
	std::size_t in_sz = 0;
	std::string out;

	Crypto::Utils::to_string(in, in_sz, out);
	EXPECT_EQ(out, expected);
}

TEST(Utils, from_hex)
{
	uint8_t expected[16] = {
	       	0x00, 0x01, 0x0C, 0x0F, 0x10, 0x11, 0x1C, 0x1F,
		0xC0, 0xC1, 0xCC, 0xCF, 0xF0, 0xF1, 0xFC, 0xFF };
	std::vector<std::string> in = {
		"00010c0f10111c1fc0c1cccff0f1fcff",
		"00010C0F10111C1FC0C1CCCFF0F1FCFF"
	};
	uint8_t out[16];
	std::size_t out_sz;

	for ( std::size_t i = 0 ; i < in.size() ; ++i ) {
		out_sz = 0;
		Crypto::Utils::from_hex(in[i], NULL, out_sz);
		EXPECT_EQ(out_sz, (std::size_t)16);

		Crypto::Utils::zeroize(out, 16);
		out_sz = 16;
		Crypto::Utils::from_hex(in[i], out, out_sz);
		EXPECT_THAT(out, ::testing::ElementsAreArray(expected));
		EXPECT_EQ(out_sz, (std::size_t)16);
	}
}

TEST(Utils, from_hex_empty)
{
	std::string in = "";
	uint8_t out[1];
	std::size_t out_sz;

	out_sz = 1;
	Crypto::Utils::from_hex(in, out, out_sz);
	EXPECT_EQ(out_sz, (std::size_t)0);
}

TEST(Utils, from_hex_incorrect_length)
{
	std::string exception, expected = "Incorrect length";
	std::string in = "0";
	uint8_t out[2];
	std::size_t out_sz = 2;

	try {
		Crypto::Utils::from_hex(in, out, out_sz);
	} catch ( const Crypto::Utils::Exception &ce ) {
		exception = ce.what();
	}

	EXPECT_EQ(exception, expected);
}

TEST(Utils, from_hex_invalid_character)
{
	// Invalid character #1
	{
		std::string exception, expected = "Invalid character";
		std::string in = "0123456789ABCDEFGA";
		uint8_t out[9];
		std::size_t out_sz = 9;

		try {
			Crypto::Utils::from_hex(in, out, out_sz);
		} catch ( const Crypto::Utils::Exception &ce ) {
			exception = ce.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Invalid character #2
	{
		std::string exception, expected = "Invalid character";
		std::string in = "0123456789ABCDEFAG";
		uint8_t out[9];
		std::size_t out_sz = 9;

		try {
			Crypto::Utils::from_hex(in, out, out_sz);
		} catch ( const Crypto::Utils::Exception &ce ) {
			exception = ce.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(Utils, to_hex)
{
	std::vector<std::string> expected = {
		"00010C0F10111C1FC0C1CCCFF0F1FCFF",
		"00010c0f10111c1fc0c1cccff0f1fcff"
	};
	uint8_t in[16] = {
	       	0x00, 0x01, 0x0C, 0x0F, 0x10, 0x11, 0x1C, 0x1F,
		0xC0, 0xC1, 0xCC, 0xCF, 0xF0, 0xF1, 0xFC, 0xFF };
	std::size_t in_sz = 16;
	std::string out;

	Crypto::Utils::to_hex(in, in_sz, out);
	EXPECT_EQ(out, expected[0]);

	Crypto::Utils::to_hex(in, in_sz, out, true);
	EXPECT_EQ(out, expected[0]);

	Crypto::Utils::to_hex(in, in_sz, out, false);
	EXPECT_EQ(out, expected[1]);
}

TEST(Utils, to_hex_empty)
{
	std::string expected = "";
	uint8_t in[1];
	std::size_t in_sz = 0;
	std::string out;

	Crypto::Utils::to_hex(in, in_sz, out);
	EXPECT_EQ(out, expected);
}
