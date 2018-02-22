#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/Padding.hpp"

TEST(PKCS7Padding, pad_correct)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "",               "16", "10101010101010101010101010101010" },
		{ "00",             "16", "000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f" },
		{ "0001",           "16", "00010e0e0e0e0e0e0e0e0e0e0e0e0e0e" },
		{ "000102",         "16", "0001020d0d0d0d0d0d0d0d0d0d0d0d0d" },
		{ "00010203",       "16", "000102030c0c0c0c0c0c0c0c0c0c0c0c" },
		{ "0001020304",     "16", "00010203040b0b0b0b0b0b0b0b0b0b0b" },
		{ "000102030405",   "7",  "00010203040501"                   }
	};

	for ( auto test : tests ) {
		uint8_t data[16];
		std::size_t in_sz, out_sz;
		std::string output;

		in_sz = sizeof(data);
		Crypto::Utils::from_hex(test[0], data, in_sz);
		out_sz = atoi(test[1].c_str());

		Crypto::PKCS7Padding::pad(data, in_sz, out_sz);
		Crypto::Utils::to_hex(data, out_sz, output, false);

		EXPECT_THAT(output, test[2]);
	}
}

TEST(PKCS7Padding, unpad_correct)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "07070707070707",                   "0" },
		{ "000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", "1" },
		{ "00010e0e0e0e0e0e0e0e0e0e0e0e0e0e", "2" },
		{ "0001020d0d0d0d0d0d0d0d0d0d0d0d0d", "3" },
		{ "000102030c0c0c0c0c0c0c0c0c0c0c0c", "4" },
		{ "00010203040b0b0b0b0b0b0b0b0b0b0b", "5" },
		{ "00010203040501",                   "6" }
	};

	for ( auto test : tests ) {
		uint8_t data[16];
		std::size_t in_sz, out_sz, expected_sz;

		in_sz = sizeof(data);
		Crypto::Utils::from_hex(test[0], data, in_sz);

		Crypto::PKCS7Padding::unpad(data, in_sz, out_sz);

		expected_sz = atoi(test[1].c_str());
		EXPECT_THAT(out_sz, expected_sz);
	}
}

TEST(PKCS7Padding, unpad_incorrect)
{
	std::string exception, expected = "Invalid padding";
	const std::vector<std::string> tests = {
		{ "deadbeef0a" },
		{ "deadbeef00" },
		{ "deadbeef02" }
	};

	for ( auto test : tests ) {
		try {
			uint8_t data[16];
			std::size_t in_sz, out_sz;

			in_sz = sizeof(data);
			Crypto::Utils::from_hex(test, data, in_sz);

			Crypto::PKCS7Padding::unpad(data, in_sz, out_sz);
		} catch ( const Crypto::Padding::Exception &pe ) {
			exception = pe.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(OneAndZeroesPadding, pad_correct)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "",               "16", "80000000000000000000000000000000" },
		{ "00",             "16", "00800000000000000000000000000000" },
		{ "0001",           "16", "00018000000000000000000000000000" },
		{ "000102",         "16", "00010280000000000000000000000000" },
		{ "00010203",       "16", "00010203800000000000000000000000" },
		{ "0001020304",     "16", "00010203048000000000000000000000" },
		{ "000102030405",   "7",  "00010203040580"                   }
	};

	for ( auto test : tests ) {
		uint8_t data[16];
		std::size_t in_sz, out_sz;
		std::string output;

		in_sz = sizeof(data);
		Crypto::Utils::from_hex(test[0], data, in_sz);
		out_sz = atoi(test[1].c_str());

		Crypto::OneAndZeroesPadding::pad(data, in_sz, out_sz);
		Crypto::Utils::to_hex(data, out_sz, output, false);

		EXPECT_THAT(output, test[2]);
	}
}

TEST(OneAndZeroesPadding, unpad_correct)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "80000000000000",                   "0" },
		{ "00800000000000000000000000000000", "1" },
		{ "00018000000000000000000000000000", "2" },
		{ "00010280000000000000000000000000", "3" },
		{ "00010203800000000000000000000000", "4" },
		{ "00010203048000000000000000000000", "5" },
		{ "00010203040580",                   "6" }
	};

	for ( auto test : tests ) {
		uint8_t data[16];
		std::size_t in_sz, out_sz, expected_sz;

		in_sz = sizeof(data);
		Crypto::Utils::from_hex(test[0], data, in_sz);

		Crypto::OneAndZeroesPadding::unpad(data, in_sz, out_sz);

		expected_sz = atoi(test[1].c_str());
		EXPECT_THAT(out_sz, expected_sz);
	}
}

TEST(OneAndZeroesPadding, unpad_incorrect)
{
	std::string exception, expected = "Invalid padding";
	const std::vector<std::string> tests = {
		{ "0000000000" },
		{ "deadbeef00" }
	};

	for ( auto test : tests ) {
		try {
			uint8_t data[16];
			std::size_t in_sz, out_sz;

			in_sz = sizeof(data);
			Crypto::Utils::from_hex(test, data, in_sz);

			Crypto::OneAndZeroesPadding::unpad(data, in_sz, out_sz);
		} catch ( const Crypto::Padding::Exception &pe ) {
			exception = pe.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(ANSIX923Padding, pad_correct)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "",               "16", "00000000000000000000000000000010" },
		{ "00",             "16", "0000000000000000000000000000000f" },
		{ "0001",           "16", "0001000000000000000000000000000e" },
		{ "000102",         "16", "0001020000000000000000000000000d" },
		{ "00010203",       "16", "0001020300000000000000000000000c" },
		{ "0001020304",     "16", "0001020304000000000000000000000b" },
		{ "000102030405",   "7",  "00010203040501"                   }
	};

	for ( auto test : tests ) {
		uint8_t data[16];
		std::size_t in_sz, out_sz;
		std::string output;

		in_sz = sizeof(data);
		Crypto::Utils::from_hex(test[0], data, in_sz);
		out_sz = atoi(test[1].c_str());

		Crypto::ANSIX923Padding::pad(data, in_sz, out_sz);
		Crypto::Utils::to_hex(data, out_sz, output, false);

		EXPECT_THAT(output, test[2]);
	}
}

TEST(ANSIX923Padding, unpad_correct)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "00000000000007",                   "0" },
		{ "0000000000000000000000000000000f", "1" },
		{ "0001000000000000000000000000000e", "2" },
		{ "0001020000000000000000000000000d", "3" },
		{ "0001020300000000000000000000000c", "4" },
		{ "0001020304000000000000000000000b", "5" },
		{ "00010203040501",                   "6" }
	};

	for ( auto test : tests ) {
		uint8_t data[16];
		std::size_t in_sz, out_sz, expected_sz;

		in_sz = sizeof(data);
		Crypto::Utils::from_hex(test[0], data, in_sz);

		Crypto::ANSIX923Padding::unpad(data, in_sz, out_sz);

		expected_sz = atoi(test[1].c_str());
		EXPECT_THAT(out_sz, expected_sz);
	}
}

TEST(ANSIX923Padding, unpad_incorrect)
{
	std::string exception, expected = "Invalid padding";
	const std::vector<std::string> tests = {
		{ "deadbeef0a" },
		{ "deadbeef00" },
		{ "deadbeef02" }
	};

	for ( auto test : tests ) {
		try {
			uint8_t data[16];
			std::size_t in_sz, out_sz;

			in_sz = sizeof(data);
			Crypto::Utils::from_hex(test, data, in_sz);

			Crypto::ANSIX923Padding::unpad(data, in_sz, out_sz);
		} catch ( const Crypto::Padding::Exception &pe ) {
			exception = pe.what();
		}

		EXPECT_EQ(exception, expected);
	}
}
