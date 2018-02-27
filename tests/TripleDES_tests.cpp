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
				parity =   parity       ^ (parity >> 1)
					^ (parity >> 2) ^ (parity >> 3);
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

		auto test_vectors = TestVectors::NISTParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[24];
				std::size_t key_sz = sizeof(key);
				std::size_t plain_sz  = test["PLAINTEXT"].length() / 2;
				std::size_t cipher_sz = test["CIPHERTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string cipher_str;

				if ( test["KEY1"] == test["KEY3"] ) {
					res = 0;
					res += Crypto::Utils::from_hex(test["KEY1"], key,     key_sz = 8);
					res += Crypto::Utils::from_hex(test["KEY2"], key + 8, key_sz = 8);
					EXPECT_EQ(res, 0);

					key_sz = 16;
				} else {
					res = 0;
					res += Crypto::Utils::from_hex(test["KEY1"], key,      key_sz = 8);
					res += Crypto::Utils::from_hex(test["KEY2"], key +  8, key_sz = 8);
					res += Crypto::Utils::from_hex(test["KEY3"], key + 16, key_sz = 8);
					EXPECT_EQ(res, 0);

					key_sz = 24;
				}

				res = Crypto::Utils::from_hex(test["PLAINTEXT"], plain.get(), plain_sz);
				EXPECT_EQ(res, 0);

				Crypto::ECB<Crypto::TripleDES> ctx(key, key_sz, true);

				total_sz = cipher_sz;
				cipher_sz = 0;
				for ( std::size_t i = 0 ; i < plain_sz ; ++i ) {
					current_sz = total_sz - cipher_sz;

					res = ctx.update(plain.get() + i, 1, cipher.get() + cipher_sz, current_sz);
					EXPECT_EQ(res, 0);

					cipher_sz += current_sz;
					EXPECT_EQ(res, 0);
				}

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, 0);

				res = Crypto::Utils::to_hex(cipher.get(), cipher_sz, cipher_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(cipher_str, test["CIPHERTEXT"]);
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

		auto test_vectors = TestVectors::NISTParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[24];
			uint8_t plain[Crypto::TripleDES::BLOCK_SIZE];
			uint8_t	cipher[3][Crypto::TripleDES::BLOCK_SIZE];
			std::size_t key_sz    = sizeof(key);
			std::size_t plain_sz  = sizeof(plain);
			std::size_t cipher_sz = sizeof(cipher[0]);
			std::size_t pad_sz    = 0;
			std::string cipher_str;

			res = 0;
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY1"], key,      key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY2"], key + 8,  key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY3"], key + 16, key_sz);
			EXPECT_EQ(res, 0);

			key_sz = (0 == memcmp(key, key + 16, 8)) ? 16 : 24;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["PLAINTEXT"], plain, plain_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				Crypto::ECB<Crypto::TripleDES> ctx(key, key_sz, true);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(cipher[0], cipher[1], cipher_sz);
					memcpy(cipher[1], cipher[2], cipher_sz);

					res = ctx.update(plain, plain_sz, cipher[2], cipher_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(plain, cipher[2], plain_sz);
				}

				res = Crypto::Utils::to_hex(cipher[2], cipher_sz, cipher_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(cipher_str, test["CIPHERTEXT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					key[i] ^= cipher[2 - (i / 8)][i % 8];
				}

				memcpy(plain, cipher[2], plain_sz);
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

		auto test_vectors = TestVectors::NISTParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[24];
				std::size_t key_sz = sizeof(key);
				std::size_t cipher_sz = test["CIPHERTEXT"].length() / 2;
				std::size_t plain_sz  = test["PLAINTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string plain_str;

				if ( test["KEY1"] == test["KEY3"] ) {
					res = 0;
					res += Crypto::Utils::from_hex(test["KEY1"], key,     key_sz = 8);
					res += Crypto::Utils::from_hex(test["KEY2"], key + 8, key_sz = 8);
					EXPECT_EQ(res, 0);

					key_sz = 16;
				} else {
					res = 0;
					res += Crypto::Utils::from_hex(test["KEY1"], key,      key_sz = 8);
					res += Crypto::Utils::from_hex(test["KEY2"], key +  8, key_sz = 8);
					res += Crypto::Utils::from_hex(test["KEY3"], key + 16, key_sz = 8);
					EXPECT_EQ(res, 0);

					key_sz = 24;
				}

				res = Crypto::Utils::from_hex(test["CIPHERTEXT"], cipher.get(), cipher_sz);
				EXPECT_EQ(res, 0);

				Crypto::ECB<Crypto::TripleDES> ctx(key, key_sz, false);

				total_sz = plain_sz;
				plain_sz = 0;
				for ( std::size_t i = 0 ; i < cipher_sz ; ++i ) {
					current_sz = total_sz - plain_sz;

					res = ctx.update(cipher.get() + i, 1, plain.get() + plain_sz, current_sz);
					EXPECT_EQ(res, 0);

					plain_sz += current_sz;
					EXPECT_EQ(res, 0);
				}

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, 0);

				res = Crypto::Utils::to_hex(plain.get(), plain_sz, plain_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(plain_str, test["PLAINTEXT"]);
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

		auto test_vectors = TestVectors::NISTParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[24];
			uint8_t	cipher[Crypto::TripleDES::BLOCK_SIZE];
			uint8_t plain[3][Crypto::TripleDES::BLOCK_SIZE];
			std::size_t key_sz    = sizeof(key);
			std::size_t cipher_sz = sizeof(cipher);
			std::size_t plain_sz  = sizeof(plain[0]);
			std::size_t pad_sz    = 0;
			std::string plain_str;

			res = 0;
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY1"], key,      key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY2"], key + 8,  key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY3"], key + 16, key_sz);
			EXPECT_EQ(res, 0);

			key_sz = (0 == memcmp(key, key + 16, 8)) ? 16 : 24;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["CIPHERTEXT"], cipher, cipher_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				Crypto::ECB<Crypto::TripleDES> ctx(key, key_sz, false);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(plain[0], plain[1], plain_sz);
					memcpy(plain[1], plain[2], plain_sz);

					res = ctx.update(cipher, cipher_sz, plain[2], plain_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(cipher, plain[2], cipher_sz);
				}

				res = Crypto::Utils::to_hex(plain[2], plain_sz, plain_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(plain_str, test["PLAINTEXT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					key[i] ^= plain[2 - (i / 8)][i % 8];
				}

				memcpy(cipher, plain[2], cipher_sz);
			}
		}
	}
}
