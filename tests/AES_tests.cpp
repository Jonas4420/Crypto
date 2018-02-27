#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/AES.hpp"
#include "crypto/Utils.hpp"

TEST(AES, constructor)
{
	// Case 1: key_sz = 128 bits
	{
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::AES ctx(key, key_sz);
	}

	// Case 2: key_sz = 192 bits
	{
		uint8_t key[24];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::AES ctx(key, key_sz);
	}

	// Case 3: key_sz = 256 bits
	{
		uint8_t key[32];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::AES ctx(key, key_sz);
	}

	// Case 4: key_sz = 512 bits
	{
		std::string exception, expected("Key size is not supported");
		uint8_t key[64];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		try {
			Crypto::AES ctx(key, key_sz);
		} catch ( const Crypto::AES::Exception &ae ) {
			exception = ae.what();
		}

		EXPECT_EQ(exception, expected);
	}

}

TEST(AES, KAT_enc)
{
	std::vector<std::string> files = {
		"ECBGFSbox128.rsp",  "ECBGFSbox192.rsp",  "ECBGFSbox256.rsp",
		"ECBKeySbox128.rsp", "ECBKeySbox192.rsp", "ECBKeySbox256.rsp",
		"ECBVarKey128.rsp",  "ECBVarKey192.rsp",  "ECBVarKey256.rsp",
		"ECBVarTxt128.rsp",  "ECBVarTxt192.rsp",  "ECBVarTxt256.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/KAT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t plain[Crypto::AES::BLOCK_SIZE];
				uint8_t cipher[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz   = sizeof(key);
				std::size_t plain_sz = sizeof(plain);
				std::string cipher_str;

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["PLAINTEXT"], plain, plain_sz);
				EXPECT_EQ(res, 0);

				Crypto::AES ctx(key, key_sz);
				ctx.encrypt(plain, cipher);

				res = Crypto::Utils::to_hex(cipher, sizeof(cipher), cipher_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(cipher_str, test["CIPHERTEXT"]);
			}
		}
	}
}

TEST(AES, KAT_dec)
{
	std::vector<std::string> files = {
		"ECBGFSbox128.rsp",  "ECBGFSbox192.rsp",  "ECBGFSbox256.rsp",
		"ECBKeySbox128.rsp", "ECBKeySbox192.rsp", "ECBKeySbox256.rsp",
		"ECBVarKey128.rsp",  "ECBVarKey192.rsp",  "ECBVarKey256.rsp",
		"ECBVarTxt128.rsp",  "ECBVarTxt192.rsp",  "ECBVarTxt256.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/KAT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t cipher[Crypto::AES::BLOCK_SIZE];
				uint8_t plain[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz    = sizeof(key);
				std::size_t cipher_sz = sizeof(plain);
				std::string plain_str;

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["CIPHERTEXT"], cipher, cipher_sz);
				EXPECT_EQ(res, 0);

				Crypto::AES ctx(key, key_sz);
				ctx.decrypt(cipher, plain);

				res = Crypto::Utils::to_hex(plain, sizeof(plain), plain_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(plain_str, test["PLAINTEXT"]);
			}
		}
	}
}
