#include <memory>
#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/AES.hpp"
#include "crypto/CFB.hpp"
#include "crypto/Utils.hpp"

TEST(CFB8, KAT_enc)
{
	std::vector<std::string> files = {
		"CFB8GFSbox128.rsp",  "CFB8GFSbox192.rsp",  "CFB8GFSbox256.rsp",
		"CFB8KeySbox128.rsp", "CFB8KeySbox192.rsp", "CFB8KeySbox256.rsp",
		"CFB8VarKey128.rsp",  "CFB8VarKey192.rsp",  "CFB8VarKey256.rsp",
		"CFB8VarTxt128.rsp",  "CFB8VarTxt192.rsp",  "CFB8VarTxt256.rsp"
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

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, true);

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

TEST(CFB8, MMT_enc)
{
	std::vector<std::string> files = {
		"CFB8MMT128.rsp",  "CFB8MMT192.rsp",  "CFB8MMT256.rsp",
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

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, true);

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

TEST(CFB8, MonteCarlo_enc)
{
	std::vector<std::string> files = {
		"CFB8MCT128.rsp",  "CFB8MCT192.rsp",  "CFB8MCT256.rsp",
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
			uint8_t buffer[2 * Crypto::AES::BLOCK_SIZE];
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
				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, true);

				for ( std::size_t j = 0 ; j < 1000 ; ++j ) {
					res = ctx.update(plain, plain_sz, cipher, cipher_sz);
					EXPECT_EQ(res, 0);

					memmove(buffer, buffer + cipher_sz, sizeof(buffer) - cipher_sz);
					memcpy(buffer + (sizeof(buffer) - cipher_sz), cipher, cipher_sz);

					memcpy(plain, ((j * cipher_sz) < 16) ? iv + j : buffer + (16 - plain_sz), plain_sz);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);
				}

				res = Crypto::Utils::to_hex(cipher, cipher_sz, cipher_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(cipher_str, test["CIPHERTEXT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					key[i] ^= buffer[i + (32 - key_sz)];
				}

				memcpy(iv,    buffer + 16,            iv_sz);
				memcpy(plain, buffer + 16 - plain_sz, plain_sz);
			}
		}
	}
}

TEST(CFB8, KAT_dec)
{
	std::vector<std::string> files = {
		"CFB8GFSbox128.rsp",  "CFB8GFSbox192.rsp",  "CFB8GFSbox256.rsp",
		"CFB8KeySbox128.rsp", "CFB8KeySbox192.rsp", "CFB8KeySbox256.rsp",
		"CFB8VarKey128.rsp",  "CFB8VarKey192.rsp",  "CFB8VarKey256.rsp",
		"CFB8VarTxt128.rsp",  "CFB8VarTxt192.rsp",  "CFB8VarTxt256.rsp"
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

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, false);

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

TEST(CFB8, MMT_dec)
{
	std::vector<std::string> files = {
		"CFB8MMT128.rsp",  "CFB8MMT192.rsp",  "CFB8MMT256.rsp",
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

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, false);

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

TEST(CFB8, MonteCarlo_dec)
{
	std::vector<std::string> files = {
		"CFB8MCT128.rsp",  "CFB8MCT192.rsp",  "CFB8MCT256.rsp",
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
			uint8_t buffer[2 * Crypto::AES::BLOCK_SIZE];
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
				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, false);

				for ( std::size_t j = 0 ; j < 1000 ; ++j ) {
					res = ctx.update(cipher, cipher_sz, plain, plain_sz);
					EXPECT_EQ(res, 0);

					memmove(buffer, buffer + plain_sz, sizeof(buffer) - plain_sz);
					memcpy(buffer + (sizeof(buffer) - plain_sz), plain, plain_sz);

					memcpy(cipher, ((j * plain_sz) < 16) ? iv + j : buffer + (16 - cipher_sz), cipher_sz);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);
				}

				res = Crypto::Utils::to_hex(plain, plain_sz, plain_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(plain_str, test["PLAINTEXT"]);

				if ( 16 == key_sz ) {
					for ( std::size_t m = 0 ; m < 16 ; ++m ) {
						key[m] ^= buffer[16 + m];
					}
				} else if ( 24 == key_sz ) {
					for ( std::size_t m = 0 ; m < 24 ; ++m ) {
						key[m] ^= buffer[8 + m];
					}
				} else {
					for ( std::size_t m = 0 ; m < 32 ; ++m ) {
						key[m] ^= buffer[m];
					}
				}

				memcpy(iv,     buffer + 16,             iv_sz);
				memcpy(cipher, buffer + 16 - cipher_sz, cipher_sz);
			}
		}
	}
}

TEST(CFB128, KAT_enc)
{
	std::vector<std::string> files = {
		"CFB128GFSbox128.rsp",  "CFB128GFSbox192.rsp",  "CFB128GFSbox256.rsp",
		"CFB128KeySbox128.rsp", "CFB128KeySbox192.rsp", "CFB128KeySbox256.rsp",
		"CFB128VarKey128.rsp",  "CFB128VarKey192.rsp",  "CFB128VarKey256.rsp",
		"CFB128VarTxt128.rsp",  "CFB128VarTxt192.rsp",  "CFB128VarTxt256.rsp"
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

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

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

TEST(CFB128, MMT_enc)
{
	std::vector<std::string> files = {
		"CFB128MMT128.rsp",  "CFB128MMT192.rsp",  "CFB128MMT256.rsp",
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

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

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

TEST(CFB128, MonteCarlo_enc)
{
	std::vector<std::string> files = {
		"CFB128MCT128.rsp",  "CFB128MCT192.rsp",  "CFB128MCT256.rsp",
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
			uint8_t buffer[2 * Crypto::AES::BLOCK_SIZE];
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
				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

				for ( std::size_t j = 0 ; j < 1000 ; ++j ) {
					res = ctx.update(plain, plain_sz, cipher, cipher_sz);
					EXPECT_EQ(res, 0);

					memmove(buffer, buffer + cipher_sz, sizeof(buffer) - cipher_sz);
					memcpy(buffer + (sizeof(buffer) - cipher_sz), cipher, cipher_sz);

					memcpy(plain, ((j * cipher_sz) < 16) ? iv + j : buffer + (16 - plain_sz), plain_sz);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);
				}

				res = Crypto::Utils::to_hex(cipher, cipher_sz, cipher_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(cipher_str, test["CIPHERTEXT"]);

				if ( 16 == key_sz ) {
					for ( std::size_t m = 0 ; m < 16 ; ++m ) {
						key[m] ^= buffer[16 + m];
					}
				} else if ( 24 == key_sz ) {
					for ( std::size_t m = 0 ; m < 24 ; ++m ) {
						key[m] ^= buffer[8 + m];
					}
				} else {
					for ( std::size_t m = 0 ; m < 32 ; ++m ) {
						key[m] ^= buffer[m];
					}
				}

				memcpy(iv,    buffer + 16,            iv_sz);
				memcpy(plain, buffer + 16 - plain_sz, plain_sz);
			}
		}
	}
}

TEST(CFB128, KAT_dec)
{
	std::vector<std::string> files = {
		"CFB128GFSbox128.rsp",  "CFB128GFSbox192.rsp",  "CFB128GFSbox256.rsp",
		"CFB128KeySbox128.rsp", "CFB128KeySbox192.rsp", "CFB128KeySbox256.rsp",
		"CFB128VarKey128.rsp",  "CFB128VarKey192.rsp",  "CFB128VarKey256.rsp",
		"CFB128VarTxt128.rsp",  "CFB128VarTxt192.rsp",  "CFB128VarTxt256.rsp"
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

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

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

TEST(CFB128, MMT_dec)
{
	std::vector<std::string> files = {
		"CFB128MMT128.rsp",  "CFB128MMT192.rsp",  "CFB128MMT256.rsp",
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

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

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

TEST(CFB128, MonteCarlo_dec)
{
	std::vector<std::string> files = {
		"CFB128MCT128.rsp",  "CFB128MCT192.rsp",  "CFB128MCT256.rsp",
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
			uint8_t buffer[2 * Crypto::AES::BLOCK_SIZE];
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
				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

				for ( std::size_t j = 0 ; j < 1000 ; ++j ) {
					res = ctx.update(cipher, cipher_sz, plain, plain_sz);
					EXPECT_EQ(res, 0);

					memmove(buffer, buffer + plain_sz, sizeof(buffer) - plain_sz);
					memcpy(buffer + (sizeof(buffer) - plain_sz), plain, plain_sz);

					memcpy(cipher, ((j * plain_sz) < 16) ? iv + j : buffer + (16 - cipher_sz), cipher_sz);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);
				}

				res = Crypto::Utils::to_hex(plain, plain_sz, plain_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(plain_str, test["PLAINTEXT"]);

				if ( 16 == key_sz ) {
					for ( std::size_t m = 0 ; m < 16 ; ++m ) {
						key[m] ^= buffer[16 + m];
					}
				} else if ( 24 == key_sz ) {
					for ( std::size_t m = 0 ; m < 24 ; ++m ) {
						key[m] ^= buffer[8 + m];
					}
				} else {
					for ( std::size_t m = 0 ; m < 32 ; ++m ) {
						key[m] ^= buffer[m];
					}
				}

				memcpy(iv,     buffer + 16,             iv_sz);
				memcpy(cipher, buffer + 16 - cipher_sz, cipher_sz);
			}
		}
	}
}

TEST(CFB, stream_sz)
{
	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];

	// Stream size is nul
	{
		std::string exception, expected = "Invalid data segment size";

		try {
			Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 0, true);
		} catch ( const Crypto::CipherMode::Exception &cme ) {
			exception = cme.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Stream size is bigger than cipher's BLOCK_SIZE
	{
		std::string exception, expected = "Invalid data segment size";

		try {
			Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 17, true);
		} catch ( const Crypto::CipherMode::Exception &cme ) {
			exception = cme.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(CFB, encrypt_update)
{
	int res;
	const std::vector<std::vector<std::string>> tests = {
		{
			"00000000000000000000000000000000",
			"00000000000000000000000000000000",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"66e94bd4ef8a2c3bba880a22582c72bcc8360d8bbe36c169b520cd775d09aec2"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t iv[16];
		std::size_t iv_sz = sizeof(iv);

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t plain_sz = sizeof(plain);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t cipher_sz = sizeof(cipher);
		std::string ciphertext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], iv,    iv_sz);
		Crypto::Utils::from_hex(test[2], plain, plain_sz);

		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 8, true);

		std::size_t current_sz, offset;
		offset = 0;

		// Buffer is 0
		current_sz = cipher_sz - offset;
		res = ctx.update(plain, 1, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 1
		current_sz = cipher_sz - offset;
		res = ctx.update(plain + 1, 2, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 3
		current_sz = cipher_sz - offset;
		res = ctx.update(plain + 3, 4, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 7
		current_sz = cipher_sz - offset;
		res = ctx.update(plain + 7, 8, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		// Buffer is 7
		current_sz = cipher_sz - offset;
		res = ctx.update(plain + 15, 16, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)16);
		offset += current_sz;

		// Buffer is 7
		current_sz = cipher_sz - offset;
		res = ctx.update(plain + 31, 1, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		res = ctx.finish(current_sz);
		EXPECT_EQ(res, 0);

		Crypto::Utils::to_hex(cipher, offset, ciphertext, false);

		EXPECT_THAT(ciphertext, test[3]);
	}
}

TEST(CFB, decrypt_update)
{
	int res;
	const std::vector<std::vector<std::string>> tests = {
		{
			"00000000000000000000000000000000",
			"00000000000000000000000000000000",
			"66e94bd4ef8a2c3bba880a22582c72bcc8360d8bbe36c169b520cd775d09aec2",
			"0000000000000000000000000000000000000000000000000000000000000000"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t iv[16];
		std::size_t iv_sz = sizeof(iv);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t cipher_sz = sizeof(cipher);

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t plain_sz = sizeof(plain);
		std::string plaintext;

		Crypto::Utils::from_hex(test[0], key,    key_sz);
		Crypto::Utils::from_hex(test[1], iv,     iv_sz);
		Crypto::Utils::from_hex(test[2], cipher, cipher_sz);

		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 8, false);

		std::size_t current_sz, offset;
		offset = 0;

		// Buffer is 0
		current_sz = plain_sz - offset;
		res = ctx.update(cipher, 1, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 1
		current_sz = plain_sz - offset;
		res = ctx.update(cipher + 1, 2, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 3
		current_sz = plain_sz - offset;
		res = ctx.update(cipher + 3, 4, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 7
		current_sz = plain_sz - offset;
		res = ctx.update(cipher + 7, 8, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		// Buffer is 7
		current_sz = plain_sz - offset;
		res = ctx.update(cipher + 15, 16, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)16);
		offset += current_sz;

		// Buffer is 7
		current_sz = plain_sz - offset;
		res = ctx.update(cipher + 31, 1, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		res = ctx.finish(current_sz);
		EXPECT_EQ(res, 0);

		Crypto::Utils::to_hex(plain, offset, plaintext, false);

		EXPECT_THAT(plaintext, test[3]);
	}
}

TEST(CFB, encrypt_update_sz)
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
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 16, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 16;
		ret = ctx.update(plain, 16, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 24, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 16;
		ret = ctx.update(plain, 24, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 32, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)32);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 2 * BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 32;
		ret = ctx.update(plain, 32, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)32);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.25 * BLOCK_SIZE, space = 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

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
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

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
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

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
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

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

TEST(CFB, encrypt_finish_sz)
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
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
	}

	// Buffer not empty, not finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

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
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
	}
}

TEST(CFB, decrypt_update_sz)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 16, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 16;
		ret = ctx.update(cipher, 16, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 24, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 16;
		ret = ctx.update(cipher, 24, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 32, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)32);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 2 * BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 32;
		ret = ctx.update(cipher, 32, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)32);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.25 * BLOCK_SIZE, space = 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

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
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

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
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

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
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

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
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

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

TEST(CFB, decrypt_finish_sz)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	// Buffer empty, not finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
	}

	// Buffer not empty, not finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

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
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.finish(plain_sz);
		EXPECT_EQ(ret, 0);

		plain_sz = 0;
		ret = ctx.finish(plain_sz);
		EXPECT_EQ(ret, 0);
	}
}
