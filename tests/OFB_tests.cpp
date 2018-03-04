#include <memory>
#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/AES.hpp"
#include "crypto/OFB.hpp"
#include "crypto/Utils.hpp"

TEST(OFB, KAT_enc)
{
	std::vector<std::string> files = {
		"OFBGFSbox128.rsp",  "OFBGFSbox192.rsp",  "OFBGFSbox256.rsp",
		"OFBKeySbox128.rsp", "OFBKeySbox192.rsp", "OFBKeySbox256.rsp",
		"OFBVarKey128.rsp",  "OFBVarKey192.rsp",  "OFBVarKey256.rsp",
		"OFBVarTxt128.rsp",  "OFBVarTxt192.rsp",  "OFBVarTxt256.rsp"
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

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["PLAINTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

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

TEST(OFB, MMT_enc)
{
	std::vector<std::string> files = {
		"OFBMMT128.rsp", "OFBMMT192.rsp", "OFBMMT256.rsp",
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

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["PLAINTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

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

TEST(OFB, MonteCarlo_enc)
{
	std::vector<std::string> files = {
		"OFBMCT128.rsp", "OFBMCT192.rsp", "OFBMCT256.rsp",
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
			uint8_t output[2][Crypto::AES::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t iv_sz = sizeof(iv);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output[0]);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["PLAINTEXT"], input, input_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					memcpy(output[0], output[1], output_sz);

					res = ctx.update(input, input_sz, output[1], output_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(input, (i == 0) ? iv : output[0], input_sz);
				}

				res = Crypto::Utils::to_hex(output[1], output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CIPHERTEXT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					if ( i < (key_sz - 16) ) {
						key[i] ^= output[0][i + (32 - key_sz)];
					} else {
						key[i] ^= output[1][i - (key_sz - 16)];
					}
				}

				memcpy(iv, output[1], iv_sz);
				memcpy(input, output[0], input_sz);
			}
		}
	}
}

TEST(OFB, KAT_dec)
{
	std::vector<std::string> files = {
		"OFBGFSbox128.rsp",  "OFBGFSbox192.rsp",  "OFBGFSbox256.rsp",
		"OFBKeySbox128.rsp", "OFBKeySbox192.rsp", "OFBKeySbox256.rsp",
		"OFBVarKey128.rsp",  "OFBVarKey192.rsp",  "OFBVarKey256.rsp",
		"OFBVarTxt128.rsp",  "OFBVarTxt192.rsp",  "OFBVarTxt256.rsp"
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

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["CIPHERTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

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

TEST(OFB, MMT_dec)
{
	std::vector<std::string> files = {
		"OFBMMT128.rsp", "OFBMMT192.rsp", "OFBMMT256.rsp",
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

				res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["CIPHERTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

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

TEST(OFB, MonteCarlo_dec)
{
	std::vector<std::string> files = {
		"OFBMCT128.rsp", "OFBMCT192.rsp", "OFBMCT256.rsp",
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
			uint8_t output[2][Crypto::AES::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t iv_sz = sizeof(iv);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output[2]);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["CIPHERTEXT"], input, input_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					memcpy(output[0], output[1], output_sz);

					res = ctx.update(input, input_sz, output[1], output_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(input, (i == 0) ? iv : output[0], input_sz);
				}

				res = Crypto::Utils::to_hex(output[1], output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					if ( i < (key_sz - 16) ) {
						key[i] ^= output[0][i + (32 - key_sz)];
					} else {
						key[i] ^= output[1][i - (key_sz - 16)];
					}
				}

				memcpy(iv, output[1], iv_sz);
				memcpy(input, output[0], input_sz);
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

	uint8_t input[32];
	std::size_t input_sz = sizeof(input);
	memset(input, 0x00, input_sz);

	uint8_t output[32];
	std::size_t output_sz = sizeof(output);
	memset(output, 0x00, output_sz);

	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

		output_sz = 0;
		ret = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(output_sz, (std::size_t)8);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

		output_sz = 8;
		ret = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(output_sz, (std::size_t)8);
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

	uint8_t input[32];
	std::size_t input_sz = sizeof(input);
	memset(input, 0x00, input_sz);

	uint8_t output[32];
	std::size_t output_sz = sizeof(output);
	memset(output, 0x00, output_sz);

	// Buffer empty, not finished
	{
		Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

		output_sz = 16;
		ret = ctx.finish(output_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);
	}
}
