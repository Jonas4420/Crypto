#include <memory>
#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/AES.hpp"
#include "crypto/OFB.hpp"
#include "crypto/Utils.hpp"

TEST(OFB, KAT_encrypt)
{
	std::vector<std::string> files = {
		"OFBGFSbox128.rsp",  "OFBGFSbox192.rsp",  "OFBGFSbox256.rsp",
		"OFBKeySbox128.rsp", "OFBKeySbox192.rsp", "OFBKeySbox256.rsp",
		"OFBVarKey128.rsp",  "OFBVarKey192.rsp",  "OFBVarKey256.rsp",
		"OFBVarTxt128.rsp",  "OFBVarTxt192.rsp",  "OFBVarTxt256.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/KAT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz  = sizeof(iv);
				std::size_t plain_sz  = test["PLAINTEXT"].length() / 2;
				std::size_t cipher_sz = test["CIPHERTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::size_t pad_sz = 0;
				std::string cipher_str;

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["PLAINTEXT"], plain.get(), plain_sz);
				EXPECT_EQ(res, 0);

				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

				res = ctx.update(plain.get(), plain_sz, cipher.get(), cipher_sz);
				EXPECT_EQ(res, 0);

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

TEST(OFB, MMT_encrypt)
{
	std::vector<std::string> files = {
		"OFBMMT128.rsp",  "OFBMMT192.rsp",  "OFBMMT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MMT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz  = sizeof(iv);
				std::size_t plain_sz  = test["PLAINTEXT"].length() / 2;
				std::size_t cipher_sz = test["CIPHERTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string cipher_str;

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["PLAINTEXT"], plain.get(), plain_sz);
				EXPECT_EQ(res, 0);

				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

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

TEST(OFB, MCT_encrypt)
{
	std::vector<std::string> files = {
		"OFBMCT128.rsp",  "OFBMCT192.rsp",  "OFBMCT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MCT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::AES::BLOCK_SIZE];
			uint8_t plain[Crypto::AES::BLOCK_SIZE];
			uint8_t cipher[Crypto::AES::BLOCK_SIZE];
			uint8_t last_cipher[Crypto::AES::BLOCK_SIZE];
			std::size_t key_sz    = sizeof(key);
			std::size_t iv_sz     = sizeof(iv);
			std::size_t plain_sz  = sizeof(plain);
			std::size_t cipher_sz = sizeof(cipher);
			std::size_t pad_sz = 0;
			std::string cipher_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["PLAINTEXT"], plain, plain_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					memcpy(last_cipher, cipher, cipher_sz);

					res = ctx.update(plain, plain_sz, cipher, cipher_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(plain, (i == 0) ? iv : last_cipher, plain_sz);
				}

				res = Crypto::Utils::to_hex(cipher, cipher_sz, cipher_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(cipher_str, test["CIPHERTEXT"]);

				if ( 16 == key_sz ) {
					for ( std::size_t i = 0 ; i < 16 ; ++i ) {
						key[i] ^= cipher[i];
					}
				} else if ( 24 == key_sz ) {
					for ( std::size_t i = 0 ; i < 8 ; ++i ) {
						key[i] ^= last_cipher[8 + i];
					}
					for ( std::size_t i = 0 ; i < 16 ; ++i ) {
						key[8 + i] ^= cipher[i];
					}
				} else {
					for ( std::size_t i = 0 ; i < 16 ; ++i ) {
						key[i] ^= last_cipher[i];
					}
					for ( std::size_t i = 0 ; i < 16 ; ++i ) {
						key[16 + i] ^= cipher[i];
					}
				}

				memcpy(iv,    cipher,      iv_sz);
				memcpy(plain, last_cipher, plain_sz);
			}
		}
	}
}

TEST(OFB, KAT_decrypt)
{
	std::vector<std::string> files = {
		"OFBGFSbox128.rsp",  "OFBGFSbox192.rsp",  "OFBGFSbox256.rsp",
		"OFBKeySbox128.rsp", "OFBKeySbox192.rsp", "OFBKeySbox256.rsp",
		"OFBVarKey128.rsp",  "OFBVarKey192.rsp",  "OFBVarKey256.rsp",
		"OFBVarTxt128.rsp",  "OFBVarTxt192.rsp",  "OFBVarTxt256.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/KAT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz  = sizeof(iv);
				std::size_t cipher_sz = test["CIPHERTEXT"].length() / 2;
				std::size_t plain_sz  = test["PLAINTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::size_t pad_sz = 0;
				std::string plain_str;

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["CIPHERTEXT"], cipher.get(), cipher_sz);
				EXPECT_EQ(res, 0);

				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

				res = ctx.update(cipher.get(), cipher_sz, plain.get(), plain_sz);
				EXPECT_EQ(res, 0);

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

TEST(OFB, MMT_decrypt)
{
	std::vector<std::string> files = {
		"OFBMMT128.rsp",  "OFBMMT192.rsp",  "OFBMMT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MMT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz  = sizeof(iv);
				std::size_t cipher_sz = test["CIPHERTEXT"].length() / 2;
				std::size_t plain_sz  = test["PLAINTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string plain_str;

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["CIPHERTEXT"], cipher.get(), cipher_sz);
				EXPECT_EQ(res, 0);

				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

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

TEST(OFB, MCT_decrypt)
{
	std::vector<std::string> files = {
		"OFBMCT128.rsp",  "OFBMCT192.rsp",  "OFBMCT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MCT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::AES::BLOCK_SIZE];
			uint8_t cipher[Crypto::AES::BLOCK_SIZE];
			uint8_t plain[Crypto::AES::BLOCK_SIZE];
			uint8_t last_plain[Crypto::AES::BLOCK_SIZE];
			std::size_t key_sz    = sizeof(key);
			std::size_t iv_sz     = sizeof(iv);
			std::size_t cipher_sz = sizeof(cipher);
			std::size_t plain_sz  = sizeof(plain);
			std::size_t pad_sz = 0;
			std::string plain_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["CIPHERTEXT"], cipher, cipher_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					memcpy(last_plain, plain, plain_sz);

					res = ctx.update(cipher, cipher_sz, plain, plain_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(cipher, (i == 0) ? iv : last_plain, cipher_sz);
				}

				res = Crypto::Utils::to_hex(plain, plain_sz, plain_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(plain_str, test["PLAINTEXT"]);

				if ( 16 == key_sz ) {
					for ( std::size_t i = 0 ; i < 16 ; ++i ) {
						key[i] ^= plain[i];
					}
				} else if ( 24 == key_sz ) {
					for ( std::size_t i = 0 ; i < 8 ; ++i ) {
						key[i] ^= last_plain[8 + i];
					}
					for ( std::size_t i = 0 ; i < 16 ; ++i ) {
						key[8 + i] ^= plain[i];
					}
				} else {
					for ( std::size_t i = 0 ; i < 16 ; ++i ) {
						key[i] ^= last_plain[i];
					}
					for ( std::size_t i = 0 ; i < 16 ; ++i ) {
						key[16 + i] ^= plain[i];
					}
				}

				memcpy(iv,    plain,      iv_sz);
				memcpy(cipher, last_plain, cipher_sz);
			}
		}
	}
}

TEST(OFB, update_sz)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)8);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

		cipher_sz = 8;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)8);
	}
}

TEST(OFB, finish_sz)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	// Buffer empty, not finished
	{
		Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

		cipher_sz = 16;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);
	}
}
