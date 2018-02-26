#include <memory>
#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/AES.hpp"
#include "crypto/ECB.hpp"
#include "crypto/Padding.hpp"
#include "crypto/Utils.hpp"

TEST(ECB, KAT_encrypt)
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
				std::size_t key_sz = sizeof(key);
				std::size_t plain_sz  = test["PLAINTEXT"].length() / 2;
				std::size_t cipher_sz = test["CIPHERTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::size_t pad_sz = 0;
				std::string cipher_str;

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["PLAINTEXT"], plain.get(), plain_sz);
				EXPECT_EQ(res, 0);

				Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

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

TEST(ECB, MMT_encrypt)
{
	std::vector<std::string> files = {
		"ECBMMT128.rsp",  "ECBMMT192.rsp",  "ECBMMT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MMT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				std::size_t key_sz = sizeof(key);
				std::size_t plain_sz  = test["PLAINTEXT"].length() / 2;
				std::size_t cipher_sz = test["CIPHERTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string cipher_str;

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["PLAINTEXT"], plain.get(), plain_sz);
				EXPECT_EQ(res, 0);

				Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

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

TEST(ECB, MCT_encrypt)
{
	std::vector<std::string> files = {
		"ECBMCT128.rsp",  "ECBMCT192.rsp",  "ECBMCT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MCT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t plain[Crypto::AES::BLOCK_SIZE];
			uint8_t cipher[Crypto::AES::BLOCK_SIZE];
			uint8_t last_cipher[Crypto::AES::BLOCK_SIZE];
			std::size_t key_sz    = sizeof(key);
			std::size_t plain_sz  = sizeof(plain);
			std::size_t cipher_sz = sizeof(cipher);
			std::size_t pad_sz = 0;
			std::string cipher_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["PLAINTEXT"], plain, plain_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					memcpy(last_cipher, cipher, cipher_sz);

					res = ctx.update(plain, plain_sz, cipher, cipher_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(plain, cipher, plain_sz);
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

				memcpy(plain, cipher, plain_sz);
			}
		}
	}
}

TEST(ECB, encrypt_update_sz)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 16, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 16;
		ret = ctx.update(plain, 16, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 24, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 16;
		ret = ctx.update(plain, 24, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 32, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)32);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 2 * BLOCK_SIZE
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 32;
		ret = ctx.update(plain, 32, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)32);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.25 * BLOCK_SIZE, space = 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);

		cipher_sz = 0;
		ret = ctx.update(plain, 4, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = BLOCK_SIZE
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);

		cipher_sz = 16;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 1.5 * BLOCK_SIZE, space = 2 * BLOCK_SIZE
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);

		cipher_sz = 32;
		ret = ctx.update(plain, 24, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)32);
	}
}

TEST(ECB, encrypt_finish_sz)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	// Buffer empty, not finished
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
	}

	// Buffer not empty, not finished
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = sizeof(cipher);
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 2);
		EXPECT_EQ(cipher_sz, (std::size_t)8);
	}

	// Buffer empty, finished
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, true);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
	}
}

TEST(ECB, KAT_decrypt)
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
				std::size_t key_sz = sizeof(key);
				std::size_t cipher_sz = test["CIPHERTEXT"].length() / 2;
				std::size_t plain_sz  = test["PLAINTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::size_t pad_sz = 0;
				std::string plain_str;

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["CIPHERTEXT"], cipher.get(), cipher_sz);
				EXPECT_EQ(res, 0);

				Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

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

TEST(ECB, MMT_decrypt)
{
	std::vector<std::string> files = {
		"ECBMMT128.rsp",  "ECBMMT192.rsp",  "ECBMMT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MMT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				std::size_t key_sz = sizeof(key);
				std::size_t cipher_sz = test["CIPHERTEXT"].length() / 2;
				std::size_t plain_sz  = test["PLAINTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string plain_str;

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["CIPHERTEXT"], cipher.get(), cipher_sz);
				EXPECT_EQ(res, 0);

				Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

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

TEST(ECB, MCT_decrypt)
{
	std::vector<std::string> files = {
		"ECBMCT128.rsp",  "ECBMCT192.rsp",  "ECBMCT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MCT/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t cipher[Crypto::AES::BLOCK_SIZE];
			uint8_t plain[Crypto::AES::BLOCK_SIZE];
			uint8_t last_plain[Crypto::AES::BLOCK_SIZE];
			std::size_t key_sz    = sizeof(key);
			std::size_t cipher_sz = sizeof(cipher);
			std::size_t plain_sz  = sizeof(plain);
			std::size_t pad_sz = 0;
			std::string plain_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["CIPHERTEXT"], cipher, cipher_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					memcpy(last_plain, plain, plain_sz);

					Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);
					res = ctx.update(cipher, cipher_sz, plain, plain_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(cipher, plain, cipher_sz);
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
			}
		}
	}
}

TEST(ECB, decrypt_update_sz)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 16, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 16;
		ret = ctx.update(cipher, 16, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 24, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 16;
		ret = ctx.update(cipher, 24, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 32, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)32);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 2 * BLOCK_SIZE
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 32;
		ret = ctx.update(cipher, 32, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)32);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.25 * BLOCK_SIZE, space = 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);

		plain_sz = 0;
		ret = ctx.update(cipher, 4, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = 0
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = BLOCK_SIZE
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);

		plain_sz = 16;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 1.5 * BLOCK_SIZE, space = BLOCK_SIZE
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);

		plain_sz = 16;
		ret = ctx.update(cipher, 24, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)32);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 1.5 * BLOCK_SIZE, space = 2 * BLOCK_SIZE
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);

		plain_sz = 32;
		ret = ctx.update(cipher, 24, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)32);
	}
}

TEST(ECB, decrypt_finish_sz)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	// Buffer empty, not finished
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
	}

	// Buffer not empty, not finished
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = sizeof(cipher);
		ret = ctx.update(cipher , 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);

		plain_sz = 0;
		ret = ctx.finish(plain_sz);
		EXPECT_EQ(ret, 2);
		EXPECT_EQ(plain_sz, (std::size_t)8);
	}

	// Buffer empty, finished
	{
		Crypto::ECB<Crypto::AES> ctx(key, key_sz, false);

		plain_sz = 0;
		ret = ctx.finish(plain_sz);
		EXPECT_EQ(ret, 0);

		plain_sz = 0;
		ret = ctx.finish(plain_sz);
		EXPECT_EQ(ret, 0);
	}
}
