#include <memory>
#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/DES.hpp"
#include "crypto/ECB.hpp"
#include "crypto/Utils.hpp"

TEST(TripleDES, constructor)
{
	// Case 1: key_sz = 128 bits
	{
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::TripleDES ctx(key, key_sz);
	}

	// Case 2: key_sz = 192 bits
	{
		uint8_t key[24];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::TripleDES ctx(key, key_sz);
	}

	// Case 3: key_sz != 128 bits && key_sz != 192
	{
		std::string exception, expected("Key size is not supported");
		uint8_t key[32];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		try {
			Crypto::TripleDES ctx(key, key_sz);
		} catch ( const Crypto::TripleDES::Exception &tde ) {
			exception = tde.what();
		}

		EXPECT_EQ(exception, expected);
	}

}

TEST(TripleDES, check_weak_keys)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "00000000000000000000000000000000",                 "true"  },
		{ "00000000000000001111111111111111",                 "false" },
		{ "000000000000000000000000000000001111111111111111", "true"  },
		{ "000000000000000011111111111111110000000000000000", "true"  },
		{ "000000000000000011111111111111111111111111111111", "true"  },
		{ "000000000000000011111111111111112222222222222222", "false" }
	};

	for ( auto test : tests ) {
		uint8_t key[24];
		std::size_t key_sz = sizeof(key);
		bool expected = test[1] == "true";

		Crypto::Utils::from_hex(test[0], key, key_sz);
		bool is_weak = Crypto::TripleDES::is_weak_key(key, key_sz);
		EXPECT_EQ(is_weak, expected);
	}

	// Check for invalid key_sz
	{
		std::string exception, expected("Key size is not supported");
		uint8_t key[32];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		try {
			Crypto::TripleDES::is_weak_key(key, key_sz);
		} catch ( const Crypto::TripleDES::Exception &tde ) {
			exception = tde.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(TripleDES, check_parity)
{
	// Case 1: check that parity is correct
	{
		uint8_t key[24];
		uint8_t cnt, parity;

		memset(key, 0x00, sizeof(key));
		cnt = 0;

		// Iterate through all possible byte values
		for ( std::size_t i = 0 ; i < 32 ; ++i ) {
			for ( std::size_t j = 0 ; j < sizeof(key) ; ++j ) {
				key[j] = cnt++;
			}

			// Set the key parity according to the table
			Crypto::TripleDES::set_parity_key(key, sizeof(key));

			// Check the parity with a function
			for ( std::size_t j = 0 ; j < sizeof(key) ; ++j ) {
				parity = key[j] ^ (key[j] >> 4);
				parity = parity ^ (parity >> 1) ^ (parity >> 2) ^ (parity >> 3);
				parity &= 1;

				EXPECT_EQ(parity, 1);
			}

			// Check the parity with the table
			EXPECT_TRUE(Crypto::TripleDES::check_parity_key(key, sizeof(key)));
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
			Crypto::TripleDES::set_parity_key(key, sizeof(key));

			for ( std::size_t j = 0 ; j < sizeof(key) ; ++j ) {
				key[j] = key[j] ^ 0x01;

				EXPECT_FALSE(Crypto::TripleDES::check_parity_key(key + j, 1));
			}
		}
	}
}

TEST(TripleDES, MMT_enc)
{
	std::vector<std::string> files = {
		"TECBMMT2.rsp", "TECBMMT3.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "TDES/MMT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[24];
				std::size_t key_sz = sizeof(key);
				std::size_t input_sz = test["PLAINTEXT"].length() / 2;
				std::size_t output_sz = test["CIPHERTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
				std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY1"], key, key_sz);
				res += Crypto::Utils::from_hex(test["KEY2"], key + 8, key_sz);
				res += Crypto::Utils::from_hex(test["KEY3"], key + 16, key_sz);
				EXPECT_EQ(res, 0);

				key_sz = (0 == memcmp(key, key + 16, 8)) ? 16 : 24;

				res = Crypto::Utils::from_hex(test["PLAINTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::ECB<Crypto::TripleDES> ctx(key, key_sz, true);

				total_sz = output_sz;
				output_sz = 0;
				for ( std::size_t i = 0 ; i < input_sz ; ++i ) {
					current_sz = total_sz - output_sz;

					res = ctx.update(input.get() + i, 1, output.get() + output_sz, current_sz);
					EXPECT_EQ(res, 0);

					output_sz += current_sz;
					EXPECT_EQ(res, 0);
				}

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, (size_t)0);

				res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CIPHERTEXT"]);
			}
		}
	}
}

TEST(TripleDES, MonteCarlo_enc)
{
	std::vector<std::string> files = {
		"TECBMonte3.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "TDES/MCT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[24];
			uint8_t input[Crypto::TripleDES::BLOCK_SIZE];
			uint8_t	output[3][Crypto::TripleDES::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output[0]);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = 0;
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY1"], key, key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY2"], key + 8, key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY3"], key + 16, key_sz);
			EXPECT_EQ(res, 0);

			key_sz = (0 == memcmp(key, key + 16, 8)) ? 16 : 24;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["PLAINTEXT"], input, input_sz);
			EXPECT_EQ(res, 0);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::ECB<Crypto::TripleDES> ctx(key, key_sz, true);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(output[0], output[1], output_sz);
					memcpy(output[1], output[2], output_sz);

					res = ctx.update(input, input_sz, output[2], output_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, (size_t)0);

					memcpy(input, output[2], input_sz);
				}

				res = Crypto::Utils::to_hex(output[2], output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CIPHERTEXT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					key[i] ^= output[2 - (i / 8)][i % 8];
				}

				memcpy(input, output[2], input_sz);
			}
		}
	}
}

TEST(TripleDES, MMT_dec)
{
	std::vector<std::string> files = {
		"TECBMMT2.rsp", "TECBMMT3.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "TDES/MMT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[24];
				std::size_t key_sz = sizeof(key);
				std::size_t input_sz = test["CIPHERTEXT"].length() / 2;
				std::size_t output_sz = test["PLAINTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
				std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY1"], key, key_sz);
				res += Crypto::Utils::from_hex(test["KEY2"], key + 8, key_sz);
				res += Crypto::Utils::from_hex(test["KEY3"], key + 16, key_sz);
				EXPECT_EQ(res, 0);

				key_sz = (0 == memcmp(key, key + 16, 8)) ? 16 : 24;

				res = Crypto::Utils::from_hex(test["CIPHERTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::ECB<Crypto::TripleDES> ctx(key, key_sz, false);

				total_sz = output_sz;
				output_sz = 0;
				for ( std::size_t i = 0 ; i < input_sz ; ++i ) {
					current_sz = total_sz - output_sz;

					res = ctx.update(input.get() + i, 1, output.get() + output_sz, current_sz);
					EXPECT_EQ(res, 0);

					output_sz += current_sz;
					EXPECT_EQ(res, 0);
				}

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, (size_t)0);

				res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);
			}
		}
	}
}

TEST(TripleDES, MonteCarlo_dec)
{
	std::vector<std::string> files = {
		"TECBMonte2.rsp", "TECBMonte3.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "TDES/MCT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[24];
			uint8_t	input[Crypto::TripleDES::BLOCK_SIZE];
			uint8_t output[3][Crypto::TripleDES::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output[0]);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = 0;
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY1"], key, key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY2"], key + 8, key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY3"], key + 16, key_sz);
			EXPECT_EQ(res, 0);

			key_sz = (0 == memcmp(key, key + 16, 8)) ? 16 : 24;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["CIPHERTEXT"], input, input_sz);
			EXPECT_EQ(res, 0);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::ECB<Crypto::TripleDES> ctx(key, key_sz, false);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(output[0], output[1], output_sz);
					memcpy(output[1], output[2], output_sz);

					res = ctx.update(input, input_sz, output[2], output_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, (size_t)0);

					memcpy(input, output[2], input_sz);
				}

				res = Crypto::Utils::to_hex(output[2], output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					key[i] ^= output[2 - (i / 8)][i % 8];
				}

				memcpy(input, output[2], input_sz);
			}
		}
	}
}
