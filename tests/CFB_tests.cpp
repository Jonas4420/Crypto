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

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz = sizeof(iv);
				std::size_t input_sz = test["PLAINTEXT"].length() / 2;
				std::size_t output_sz = test["CIPHERTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
				std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
				std::size_t pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(test["PLAINTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, true);

				res = ctx.update(input.get(), input_sz, output.get(), output_sz);
				EXPECT_EQ(res, 0);

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, 0);

				res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CIPHERTEXT"]);
			}
		}
	}
}

TEST(CFB8, MMT_enc)
{
	std::vector<std::string> files = {
		"CFB8MMT128.rsp", "CFB8MMT192.rsp", "CFB8MMT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MMT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz = sizeof(iv);
				std::size_t input_sz = test["PLAINTEXT"].length() / 2;
				std::size_t output_sz = test["CIPHERTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
				std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(test["PLAINTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, true);

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
				EXPECT_EQ(pad_sz, 0);

				res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CIPHERTEXT"]);
			}
		}
	}
}

TEST(CFB8, MonteCarlo_enc)
{
	std::vector<std::string> files = {
		"CFB8MCT128.rsp", "CFB8MCT192.rsp", "CFB8MCT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MCT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::AES::BLOCK_SIZE];
			uint8_t input[Crypto::AES::BLOCK_SIZE];
			uint8_t output[Crypto::AES::BLOCK_SIZE];
			uint8_t buffer[2 * Crypto::AES::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t iv_sz = sizeof(iv);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = 0;
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["PLAINTEXT"], input, input_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, true);

				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					res = ctx.update(input, input_sz, output, output_sz);
					EXPECT_EQ(res, 0);

					memmove(buffer, buffer + output_sz, sizeof(buffer) - output_sz);
					memcpy(buffer + (sizeof(buffer) - output_sz), output, output_sz);

					memcpy(input, ((i * output_sz) < 16) ? iv + i : buffer + (16 - input_sz), input_sz);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);
				}

				res = Crypto::Utils::to_hex(output, output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CIPHERTEXT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					key[i] ^= buffer[(32 - key_sz) + i];
				}

				memcpy(iv, buffer + 16, iv_sz);
				memcpy(input, buffer + 16 - input_sz, input_sz);
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

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz = sizeof(iv);
				std::size_t input_sz = test["CIPHERTEXT"].length() / 2;
				std::size_t output_sz = test["PLAINTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
				std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
				std::size_t pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(test["CIPHERTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, false);

				res = ctx.update(input.get(), input_sz, output.get(), output_sz);
				EXPECT_EQ(res, 0);

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, 0);

				res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);
			}
		}
	}
}

TEST(CFB8, MMT_dec)
{
	std::vector<std::string> files = {
		"CFB8MMT128.rsp", "CFB8MMT192.rsp", "CFB8MMT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MMT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz = sizeof(iv);
				std::size_t input_sz = test["CIPHERTEXT"].length() / 2;
				std::size_t output_sz = test["PLAINTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
				std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(test["CIPHERTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, false);

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
				EXPECT_EQ(pad_sz, 0);

				res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);
			}
		}
	}
}

TEST(CFB8, MonteCarlo_dec)
{
	std::vector<std::string> files = {
		"CFB8MCT128.rsp", "CFB8MCT192.rsp", "CFB8MCT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MCT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::AES::BLOCK_SIZE];
			uint8_t input[Crypto::AES::BLOCK_SIZE];
			uint8_t output[Crypto::AES::BLOCK_SIZE];
			uint8_t buffer[2 * Crypto::AES::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t iv_sz = sizeof(iv);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = 0;
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["CIPHERTEXT"], input, input_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, false);

				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					res = ctx.update(input, input_sz, output, output_sz);
					EXPECT_EQ(res, 0);

					memmove(buffer, buffer + output_sz, sizeof(buffer) - output_sz);
					memcpy(buffer + (sizeof(buffer) - output_sz), output, output_sz);

					memcpy(input, ((i * output_sz) < 16) ? iv + i : buffer + (16 - input_sz), input_sz);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);
				}

				res = Crypto::Utils::to_hex(output, output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					key[i] ^= buffer[(32 - key_sz) + i];
				}

				memcpy(iv, buffer + 16, iv_sz);
				memcpy(input, buffer + 16 - input_sz, input_sz);
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

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz = sizeof(iv);
				std::size_t input_sz = test["PLAINTEXT"].length() / 2;
				std::size_t output_sz = test["CIPHERTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
				std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
				std::size_t pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(test["PLAINTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

				res = ctx.update(input.get(), input_sz, output.get(), output_sz);
				EXPECT_EQ(res, 0);

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, 0);

				res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CIPHERTEXT"]);
			}
		}
	}
}

TEST(CFB128, MMT_enc)
{
	std::vector<std::string> files = {
		"CFB128MMT128.rsp", "CFB128MMT192.rsp", "CFB128MMT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MMT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz = sizeof(iv);
				std::size_t input_sz = test["PLAINTEXT"].length() / 2;
				std::size_t output_sz = test["CIPHERTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
				std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(test["PLAINTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

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
				EXPECT_EQ(pad_sz, 0);

				res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CIPHERTEXT"]);
			}
		}
	}
}

TEST(CFB128, MonteCarlo_enc)
{
	std::vector<std::string> files = {
		"CFB128MCT128.rsp", "CFB128MCT192.rsp", "CFB128MCT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MCT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["ENCRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::AES::BLOCK_SIZE];
			uint8_t input[Crypto::AES::BLOCK_SIZE];
			uint8_t output[Crypto::AES::BLOCK_SIZE];
			uint8_t buffer[2 * Crypto::AES::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t iv_sz = sizeof(iv);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = 0;
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["PLAINTEXT"], input, input_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					res = ctx.update(input, input_sz, output, output_sz);
					EXPECT_EQ(res, 0);

					memmove(buffer, buffer + output_sz, sizeof(buffer) - output_sz);
					memcpy(buffer + (sizeof(buffer) - output_sz), output, output_sz);

					memcpy(input, ((i * output_sz) < 16) ? iv + i : buffer + (16 - input_sz), input_sz);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);
				}

				res = Crypto::Utils::to_hex(output, output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CIPHERTEXT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					key[i] ^= buffer[(32 - key_sz) + i];
				}

				memcpy(iv, buffer + 16, iv_sz);
				memcpy(input, buffer + 16 - input_sz, input_sz);
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

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz = sizeof(iv);
				std::size_t input_sz = test["CIPHERTEXT"].length() / 2;
				std::size_t output_sz = test["PLAINTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
				std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
				std::size_t pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(test["CIPHERTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

				res = ctx.update(input.get(), input_sz, output.get(), output_sz);
				EXPECT_EQ(res, 0);

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, 0);

				res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);
			}
		}
	}
}

TEST(CFB128, MMT_dec)
{
	std::vector<std::string> files = {
		"CFB128MMT128.rsp", "CFB128MMT192.rsp", "CFB128MMT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MMT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				uint8_t iv[Crypto::AES::BLOCK_SIZE];
				std::size_t key_sz = sizeof(key);
				std::size_t iv_sz = sizeof(iv);
				std::size_t input_sz = test["CIPHERTEXT"].length() / 2;
				std::size_t output_sz = test["PLAINTEXT"].length() / 2;
				std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
				std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(test["CIPHERTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

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
				EXPECT_EQ(pad_sz, 0);

				res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);
			}
		}
	}
}

TEST(CFB128, MonteCarlo_dec)
{
	std::vector<std::string> files = {
		"CFB128MCT128.rsp", "CFB128MCT192.rsp", "CFB128MCT256.rsp",
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "AES/MCT/" + file;

		auto test_vectors = TestVectors::NISTCAVPParser(file_path)["DECRYPT"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::AES::BLOCK_SIZE];
			uint8_t input[Crypto::AES::BLOCK_SIZE];
			uint8_t output[Crypto::AES::BLOCK_SIZE];
			uint8_t buffer[2 * Crypto::AES::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t iv_sz = sizeof(iv);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = 0;
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["CIPHERTEXT"], input, input_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					res = ctx.update(input, input_sz, output, output_sz);
					EXPECT_EQ(res, 0);

					memmove(buffer, buffer + output_sz, sizeof(buffer) - output_sz);
					memcpy(buffer + (sizeof(buffer) - output_sz), output, output_sz);

					memcpy(input, ((i * output_sz) < 16) ? iv + i : buffer + (16 - input_sz), input_sz);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);
				}

				res = Crypto::Utils::to_hex(output, output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					key[i] ^= buffer[(32 - key_sz) + i];
				}

				memcpy(iv, buffer + 16, iv_sz);
				memcpy(input, buffer + 16 - input_sz, input_sz);
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

		uint8_t input[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t input_sz = sizeof(input);

		uint8_t output[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t output_sz = sizeof(output);
		std::string output_str;

		res = 0;
		res += Crypto::Utils::from_hex(test[0], key, key_sz);
		res += Crypto::Utils::from_hex(test[1], iv, iv_sz);
		res += Crypto::Utils::from_hex(test[2], input, input_sz);
		EXPECT_EQ(res, 0);

		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 8, true);

		std::size_t current_sz, offset;
		offset = 0;

		// Buffer is 0
		current_sz = output_sz - offset;
		res = ctx.update(input, 1, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 1
		current_sz = output_sz - offset;
		res = ctx.update(input + 1, 2, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 3
		current_sz = output_sz - offset;
		res = ctx.update(input + 3, 4, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 7
		current_sz = output_sz - offset;
		res = ctx.update(input + 7, 8, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		// Buffer is 7
		current_sz = output_sz - offset;
		res = ctx.update(input + 15, 16, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)16);
		offset += current_sz;

		// Buffer is 7
		current_sz = output_sz - offset;
		res = ctx.update(input + 31, 1, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		res = ctx.finish(current_sz);
		EXPECT_EQ(res, 0);

		Crypto::Utils::to_hex(output, offset, output_str, false);

		EXPECT_THAT(output_str, test[3]);
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

		uint8_t input[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t input_sz = sizeof(input);

		uint8_t output[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t output_sz = sizeof(output);
		std::string output_str;

		res = 0;
		res += Crypto::Utils::from_hex(test[0], key, key_sz);
		res += Crypto::Utils::from_hex(test[1], iv, iv_sz);
		res += Crypto::Utils::from_hex(test[2], input, input_sz);
		EXPECT_EQ(res, 0);

		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 8, false);

		std::size_t current_sz, offset;
		offset = 0;

		// Buffer is 0
		current_sz = output_sz - offset;
		res = ctx.update(input, 1, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 1
		current_sz = output_sz - offset;
		res = ctx.update(input + 1, 2, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 3
		current_sz = output_sz - offset;
		res = ctx.update(input + 3, 4, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 7
		current_sz = output_sz - offset;
		res = ctx.update(input + 7, 8, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		// Buffer is 7
		current_sz = output_sz - offset;
		res = ctx.update(input + 15, 16, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)16);
		offset += current_sz;

		// Buffer is 7
		current_sz = output_sz - offset;
		res = ctx.update(input + 31, 1, output + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		res = ctx.finish(current_sz);
		EXPECT_EQ(res, 0);

		Crypto::Utils::to_hex(output, offset, output_str, false);

		EXPECT_THAT(output_str, test[3]);
	}
}

TEST(CFB, encrypt_update_sz)
{
	int res;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t input[32];
	std::size_t input_sz = sizeof(input);
	memset(input, 0x00, input_sz);

	uint8_t output[32];
	std::size_t output_sz = sizeof(output);
	memset(output, 0x00, output_sz);

	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 0;
		res = ctx.update(input, 16, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer empty, provide = BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 16;
		res = ctx.update(input, 16, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 0;
		res = ctx.update(input, 24, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 16;
		res = ctx.update(input, 24, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 0;
		res = ctx.update(input, 32, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (std::size_t)32);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 2 * BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 32;
		res = ctx.update(input, 32, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)32);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.25 * BLOCK_SIZE, space = 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);

		output_sz = 0;
		res = ctx.update(input, 4, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);

		output_sz = 16;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 1.5 * BLOCK_SIZE, space = 2 * BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);

		output_sz = 32;
		res = ctx.update(input, 24, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)32);
	}
}

TEST(CFB, encrypt_finish_sz)
{
	int res;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t input[32];
	std::size_t input_sz = sizeof(input);
	memset(input, 0x00, input_sz);

	uint8_t output[32];
	std::size_t output_sz = sizeof(output);
	memset(output, 0x00, output_sz);

	// Buffer empty, not finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 0;
		res = ctx.finish(output_sz);
		EXPECT_EQ(res, 0);
	}

	// Buffer not empty, not finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = sizeof(output);
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 0;
		res = ctx.finish(output_sz);
		EXPECT_EQ(res, 2);
		EXPECT_EQ(output_sz, (std::size_t)8);
	}

	// Buffer empty, finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		output_sz = 0;
		res = ctx.finish(output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 0;
		res = ctx.finish(output_sz);
		EXPECT_EQ(res, 0);
	}
}

TEST(CFB, decrypt_update_sz)
{
	int res;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t input[32];
	std::size_t input_sz = sizeof(input);
	memset(input, 0x00, input_sz);

	uint8_t output[32];
	std::size_t output_sz = sizeof(output);
	memset(output, 0x00, output_sz);

	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 0;
		res = ctx.update(input, 16, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer empty, provide = BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 16;
		res = ctx.update(input, 16, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 0;
		res = ctx.update(input, 24, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 16;
		res = ctx.update(input, 24, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 0;
		res = ctx.update(input, 32, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (std::size_t)32);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 2 * BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 32;
		res = ctx.update(input, 32, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)32);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.25 * BLOCK_SIZE, space = 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);

		output_sz = 0;
		res = ctx.update(input, 4, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);

		output_sz = 16;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 1.5 * BLOCK_SIZE, space = BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);

		output_sz = 16;
		res = ctx.update(input, 24, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (std::size_t)32);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 1.5 * BLOCK_SIZE, space = 2 * BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);

		output_sz = 32;
		res = ctx.update(input, 24, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)32);
	}
}

TEST(CFB, decrypt_finish_sz)
{
	int res;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t input[32];
	std::size_t input_sz = sizeof(input);
	memset(input, 0x00, input_sz);

	uint8_t output[32];
	std::size_t output_sz = sizeof(output);
	memset(output, 0x00, output_sz);

	// Buffer empty, not finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		input_sz = 0;
		res = ctx.finish(input_sz);
		EXPECT_EQ(res, 0);
	}

	// Buffer not empty, not finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = sizeof(input);
		res = ctx.update(input , 8, output, output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 0;
		res = ctx.finish(output_sz);
		EXPECT_EQ(res, 2);
		EXPECT_EQ(output_sz, (std::size_t)8);
	}

	// Buffer empty, finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		output_sz = 0;
		res = ctx.finish(output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 0;
		res = ctx.finish(output_sz);
		EXPECT_EQ(res, 0);
	}
}
