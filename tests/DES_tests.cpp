#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/DES.hpp"
#include "crypto/Utils.hpp"

TEST(DES, constructor)
{
	// Case 1: key_sz = 64 bits
	{
		uint8_t key[8];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::DES ctx(key, key_sz);
	}

	// Case 2: key_sz != 64 bits
	{
		std::string exception, expected("Key size is not supported");
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		try {
			Crypto::DES ctx(key, key_sz);
		} catch ( const Crypto::DES::Exception &de ) {
			exception = de.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(DES, check_weak_keys)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0101010101010101", "true"  },
		{ "FEE0FEE0FEF1FEF1", "true"  },
		{ "0101010101010100", "false" },
		{ "EEE0FEE0FEF1FEF1", "false" }
	};

	for ( auto test : tests ) {
		uint8_t key[8];
		std::size_t key_sz = sizeof(key);
		bool expected = test[1] == "true";

		Crypto::Utils::from_hex(test[0], key, key_sz);
		bool is_weak = Crypto::DES::is_weak_key(key, key_sz);
		EXPECT_EQ(is_weak, expected);
	}

	// Check for invalid key_sz
	{
		std::string exception, expected("Key size is not supported");
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		try {
			Crypto::DES::is_weak_key(key, key_sz);
		} catch ( const Crypto::DES::Exception &de ) {
			exception = de.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(DES, check_parity)
{
	// Case 1: check that parity is correct
	{
		uint8_t key[8];
		uint8_t cnt, parity;

		memset(key, 0x00, sizeof(key));
		cnt = 0;

		// Iterate through all possible byte values
		for ( std::size_t i = 0 ; i < 32 ; ++i ) {
			for ( std::size_t j = 0 ; j < sizeof(key) ; ++j ) {
				key[j] = cnt++;
			}

			// Set the key parity according to the table
			Crypto::DES::set_parity_key(key, sizeof(key));

			// Check the parity with a function
			for ( std::size_t j = 0 ; j < sizeof(key) ; ++j ) {
				parity = key[j] ^ (key[j] >> 4);
				parity = parity ^ (parity >> 1) ^ (parity >> 2) ^ (parity >> 3);
				parity &= 1;

				EXPECT_EQ(parity, 1);
			}

			// Check the parity with the table
			EXPECT_TRUE(Crypto::DES::check_parity_key(key, sizeof(key)));
		}
	}

	// Case 2: check when parity is bad
	{
		uint8_t key[8];
		uint8_t cnt;

		memset(key, 0x00, sizeof(key));
		cnt = 0;

		// Iterate through all possible byte values
		for ( std::size_t i = 0 ; i < 32 ; ++i ) {
			for ( std::size_t j = 0 ; j < sizeof(key) ; ++j ) {
				key[j] = cnt++;
			}

			// Set the key parity according to the table
			Crypto::DES::set_parity_key(key, sizeof(key));

			for ( std::size_t j = 0 ; j < sizeof(key) ; ++j ) {
				key[j] = key[j] ^ 0x01;

				EXPECT_FALSE(Crypto::DES::check_parity_key(key + j, 1));
			}
		}
	}
}

TEST(DES, KAT_enc)
{
	// KAT test vectors for TDES is actually testing DES (K1 = K2 = K3)
	std::vector<std::string> files = {
		"TECBinvperm.rsp", "TECBpermop.rsp", "TECBsubtab.rsp",
		"TECBvarkey.rsp",  "TECBvartext.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "TDES/KAT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[8];
				uint8_t input[Crypto::DES::BLOCK_SIZE];
				uint8_t output[Crypto::DES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t input_sz = sizeof(input);
				std::string output_str;

				res = Crypto::Utils::from_hex(test["KEYs"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["PLAINTEXT"], input, input_sz);
				EXPECT_EQ(res, 0);

				Crypto::DES ctx(key, key_sz);
				ctx.encrypt(input, output);

				res = Crypto::Utils::to_hex(output, sizeof(output), output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CIPHERTEXT"]);
			}
		}
	}
}

TEST(DES, KAT_dec)
{
	// KAT test vectors for TDES is actually testing DES (K1 = K2 = K3)
	std::vector<std::string> files = {
		"TECBinvperm.rsp", "TECBpermop.rsp", "TECBsubtab.rsp",
		"TECBvarkey.rsp",  "TECBvartext.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "TDES/KAT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[8];
				uint8_t input[Crypto::DES::BLOCK_SIZE];
				uint8_t output[Crypto::DES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t input_sz = sizeof(output);
				std::string output_str;

				res = Crypto::Utils::from_hex(test["KEYs"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["CIPHERTEXT"], input, input_sz);
				EXPECT_EQ(res, 0);

				Crypto::DES ctx(key, key_sz);
				ctx.decrypt(input, output);

				res = Crypto::Utils::to_hex(output, sizeof(output), output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);
			}
		}
	}
}
