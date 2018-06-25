#include <memory>
#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/AES.hpp"
#include "crypto/CBC_CS.hpp"
#include "crypto/Utils.hpp"

TEST(CBC_CS3, KAT_enc)
{
	std::vector<std::string> files = {
		"CBCGFSbox128.rsp",  "CBCGFSbox192.rsp",  "CBCGFSbox256.rsp",
		"CBCKeySbox128.rsp", "CBCKeySbox192.rsp", "CBCKeySbox256.rsp",
		"CBCVarKey128.rsp",  "CBCVarKey192.rsp",  "CBCVarKey256.rsp",
		"CBCVarTxt128.rsp",  "CBCVarTxt192.rsp",  "CBCVarTxt256.rsp"
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
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(test["PLAINTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

				total_sz = output_sz;
				current_sz = 0;

				output_sz = total_sz - current_sz;
				res = ctx.update(input.get(), input_sz, output.get() + current_sz, output_sz);
				EXPECT_EQ(res, 0);
				current_sz += output_sz;

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, (size_t)0);

				output_sz = total_sz - current_sz;
				res = ctx.steal_last(output.get() + current_sz, output_sz);
				EXPECT_EQ(res, 0);
				current_sz += output_sz;

				res = Crypto::Utils::to_hex(output.get(), current_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CIPHERTEXT"]);
			}
		}
	}
}

TEST(CBC_CS3, MMT_enc)
{
	std::vector<std::string> files = {
		"CBCMMT128.rsp", "CBCMMT192.rsp", "CBCMMT256.rsp",
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
				std::string output_str, expected_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(test["PLAINTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

				total_sz = output_sz;
				current_sz = 0;
				for ( std::size_t i = 0 ; i < input_sz ; ++i ) {
					output_sz = total_sz - current_sz;

					res = ctx.update(input.get() + i, 1, output.get() + current_sz, output_sz);
					EXPECT_EQ(res, 0);

					current_sz += output_sz;
					EXPECT_EQ(res, 0);
				}

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, (size_t)0);

				output_sz = total_sz - current_sz;
				res = ctx.steal_last(output.get() + current_sz, output_sz);
				EXPECT_EQ(res, 0);
				current_sz += output_sz;

				res = Crypto::Utils::to_hex(output.get(), current_sz, output_str, false);
				EXPECT_EQ(res, 0);

				expected_str = test["CIPHERTEXT"];

				if ( expected_str.length() >= 64 ) {
					expected_str = expected_str.substr(0, expected_str.length() - 64)
						+ expected_str.substr(expected_str.length() - 32, 32)
						+ expected_str.substr(expected_str.length() - 64, 32);
				}

				EXPECT_EQ(output_str, expected_str);
			}
		}
	}
}

TEST(CBC_CS3, MonteCarlo_enc)
{
	std::vector<std::string> files = {
		"CBCMCT128.rsp", "CBCMCT192.rsp", "CBCMCT256.rsp",
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
			std::size_t total_sz, current_sz, pad_sz = 0;
			std::string output_str;

			res = 0;
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["PLAINTEXT"], input, input_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

					output_sz = sizeof(output[0]);

					memcpy(output[0], output[1], output_sz);

					total_sz = output_sz;
					current_sz = 0;

					output_sz = total_sz - current_sz;
					res = ctx.update(input, input_sz, output[1] + current_sz, output_sz);
					EXPECT_EQ(res, 0);
					current_sz += output_sz;

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, (size_t)0);

					output_sz = total_sz - current_sz;
					res = ctx.steal_last(output[1] + current_sz, output_sz);
					EXPECT_EQ(res, 0);
					current_sz += output_sz;

					memcpy(input, (i == 0) ? iv : output[0], input_sz);
					memcpy(iv, output[1], iv_sz);
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

TEST(CBC_CS3, steal_test_vector_enc)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefde",
			"1fda34e41989a7146d1facf2ee27b94e28"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdead",
			"c7a6a22ea398069cf0cef3916b93df1a2857"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbe",
			"8ab229d76184379db90a2a3524e91901285765"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			"9af5b187e70fd1098a7b2d177991c99f28576591"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			"2f2b554e3a51134205168f0dbba4b09428576591b7f957b4c5662cdc"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde",
			"29a5c8520353cd8ef05ebe52a817374628576591b7f957b4c5662cdc06"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
			"4625a11618990ecc178db3a91c412a1428576591b7f957b4c5662cdc06e8"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe",
			"432a4f73ea29d6b602219ae25178d09228576591b7f957b4c5662cdc06e8e8"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde",
			"28576591b7f957b4c5662cdc06e8e87378f4eeab34bcb040331bc7dc4e4746e415"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
			"28576591b7f957b4c5662cdc06e8e8734d32c4472ba98cb59c8dab94114aa9d7154f"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe",
			"28576591b7f957b4c5662cdc06e8e87321a6b61145b906aba7cc0cbea76cfb18154fdd"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			"28576591b7f957b4c5662cdc06e8e873ad705fdcce836947d33dfe0b9d89ca22154fdd20"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			"28576591b7f957b4c5662cdc06e8e873233a292b6d1484a28f8ef66da057835d154fdd208142c6f4d55ecedc"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde",
			"28576591b7f957b4c5662cdc06e8e8731b7e668bbc8d45d0fb14780c204fa0a4154fdd208142c6f4d55ecedc4e"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
			"28576591b7f957b4c5662cdc06e8e873ddffe57bbdb72a96041c324a29ea6949154fdd208142c6f4d55ecedc4eee"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe",
			"28576591b7f957b4c5662cdc06e8e873ca0ade9010559d3a48e14f499118f537154fdd208142c6f4d55ecedc4eeea6"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea696932389857b0135032f538291bb5066a17a"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea6962038b41a4fb8e3cac6cb408fa60e91a87aa0"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea69656c357807235debf71a89465c8398aaa7aa07c"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea696952cf00206f49b9b15d6c0232f4d4ec37aa07cde"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea696271c453c42234ad93f3c4429e14fd62c7aa07cde96ecb7418047abfd"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea696e975dd1a602b3de866b8937da79f99ca7aa07cde96ecb7418047abfd02"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea6962505044f7161b3a33b1d45d9f0ea37fb7aa07cde96ecb7418047abfd02dd"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea6962aae9a7298edb7515a970c6587b62ca17aa07cde96ecb7418047abfd02dd31"
		}
	};

	for ( auto test : tests ) {
		int res;
		uint8_t key[32], iv[16];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz = sizeof(iv);
		std::size_t input_sz = test[2].length() / 2;
		std::size_t output_sz = test[3].length() / 2;
		std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
		std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
		std::size_t total_sz, current_sz, pad_sz = 0;
		std::string output_str;

		res = 0;
		res += Crypto::Utils::from_hex(test[0], key, key_sz);
		res += Crypto::Utils::from_hex(test[1], iv, iv_sz);
		res += Crypto::Utils::from_hex(test[2], input.get(), input_sz);
		EXPECT_EQ(res, 0);

		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

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

		current_sz = total_sz - output_sz;
		res = ctx.steal_last(output.get() + output_sz, current_sz);
		EXPECT_EQ(res, 0);
		output_sz += current_sz;

		res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(output_str, test[3]);
	}
}

TEST(CBC_CS3, KAT_dec)
{
	std::vector<std::string> files = {
		"CBCGFSbox128.rsp",  "CBCGFSbox192.rsp",  "CBCGFSbox256.rsp",
		"CBCKeySbox128.rsp", "CBCKeySbox192.rsp", "CBCKeySbox256.rsp",
		"CBCVarKey128.rsp",  "CBCVarKey192.rsp",  "CBCVarKey256.rsp",
		"CBCVarTxt128.rsp",  "CBCVarTxt192.rsp",  "CBCVarTxt256.rsp"
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
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string output_str;

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(test["CIPHERTEXT"], input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, false);

				total_sz = output_sz;
				current_sz = 0;

				output_sz = total_sz - current_sz;
				res = ctx.update(input.get(), input_sz, output.get() + current_sz, output_sz);
				EXPECT_EQ(res, 0);
				current_sz += output_sz;

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, (size_t)0);

				output_sz = total_sz - current_sz;
				res = ctx.steal_last(output.get() + current_sz, output_sz);
				EXPECT_EQ(res, 0);
				current_sz += output_sz;

				res = Crypto::Utils::to_hex(output.get(), current_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);
			}
		}
	}
}

TEST(CBC_CS3, MMT_dec)
{
	std::vector<std::string> files = {
		"CBCMMT128.rsp", "CBCMMT192.rsp", "CBCMMT256.rsp",
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
				std::string input_str, output_str;

				input_str = test["CIPHERTEXT"];

				if ( input_str.length() >= 64 ) {
					input_str = input_str.substr(0, input_str.length() - 64)
						+ input_str.substr(input_str.length() - 32, 32)
						+ input_str.substr(input_str.length() - 64, 32);
				}

				res = 0;
				res += Crypto::Utils::from_hex(test["KEY"], key, key_sz);
				res += Crypto::Utils::from_hex(test["IV"], iv, iv_sz);
				res += Crypto::Utils::from_hex(input_str, input.get(), input_sz);
				EXPECT_EQ(res, 0);

				Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, false);

				total_sz = output_sz;
				current_sz = 0;
				for ( std::size_t i = 0 ; i < input_sz ; ++i ) {
					output_sz = total_sz - current_sz;

					res = ctx.update(input.get() + i, 1, output.get() + current_sz, output_sz);
					EXPECT_EQ(res, 0);

					current_sz += output_sz;
					EXPECT_EQ(res, 0);
				}

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, (size_t)0);

				output_sz = total_sz - current_sz;
				res = ctx.steal_last(output.get() + current_sz, output_sz);
				EXPECT_EQ(res, 0);
				current_sz += output_sz;

				res = Crypto::Utils::to_hex(output.get(), current_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PLAINTEXT"]);
			}
		}
	}
}

TEST(CBC_CS3, MonteCarlo_dec)
{
	std::vector<std::string> files = {
		"CBCMCT128.rsp", "CBCMCT192.rsp", "CBCMCT256.rsp",
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
			std::size_t output_sz = sizeof(output[0]);
			std::size_t total_sz, current_sz, pad_sz = 0;
			std::string output_str;

			res = 0;
			res += Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			res += Crypto::Utils::from_hex(tests.test_cases[0]["CIPHERTEXT"], input, input_sz);
			EXPECT_EQ(res, 0);

			for ( auto test : tests ) {
				for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
					Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, false);

					output_sz = sizeof(output[0]);

					memcpy(output[0], output[1], output_sz);

					total_sz = output_sz;
					current_sz = 0;

					output_sz = total_sz - current_sz;
					res = ctx.update(input, input_sz, output[1] + current_sz, output_sz);
					EXPECT_EQ(res, 0);
					current_sz += output_sz;

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, (size_t)0);

					output_sz = total_sz - current_sz;
					res = ctx.steal_last(output[1] + current_sz, output_sz);
					EXPECT_EQ(res, 0);
					current_sz += output_sz;
					
					uint8_t temp[16];
					memcpy(temp, (0 == i) ? iv : output[0], sizeof(temp));
					memcpy(iv, input, iv_sz);
					memcpy(input, temp, input_sz);
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

TEST(CBC_CS3, steal_test_vector_dec)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"1fda34e41989a7146d1facf2ee27b94e28",
			"deadbeefdeadbeefdeadbeefdeadbeefde"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"c7a6a22ea398069cf0cef3916b93df1a2857",
			"deadbeefdeadbeefdeadbeefdeadbeefdead"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"8ab229d76184379db90a2a3524e91901285765",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbe"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"9af5b187e70fd1098a7b2d177991c99f28576591",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"2f2b554e3a51134205168f0dbba4b09428576591b7f957b4c5662cdc",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"29a5c8520353cd8ef05ebe52a817374628576591b7f957b4c5662cdc06",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"4625a11618990ecc178db3a91c412a1428576591b7f957b4c5662cdc06e8",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"432a4f73ea29d6b602219ae25178d09228576591b7f957b4c5662cdc06e8e8",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e87378f4eeab34bcb040331bc7dc4e4746e415",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e8734d32c4472ba98cb59c8dab94114aa9d7154f",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e87321a6b61145b906aba7cc0cbea76cfb18154fdd",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873ad705fdcce836947d33dfe0b9d89ca22154fdd20",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873233a292b6d1484a28f8ef66da057835d154fdd208142c6f4d55ecedc",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e8731b7e668bbc8d45d0fb14780c204fa0a4154fdd208142c6f4d55ecedc4e",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873ddffe57bbdb72a96041c324a29ea6949154fdd208142c6f4d55ecedc4eee",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873ca0ade9010559d3a48e14f499118f537154fdd208142c6f4d55ecedc4eeea6",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea696932389857b0135032f538291bb5066a17a",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea6962038b41a4fb8e3cac6cb408fa60e91a87aa0",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea69656c357807235debf71a89465c8398aaa7aa07c",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea696952cf00206f49b9b15d6c0232f4d4ec37aa07cde",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea696271c453c42234ad93f3c4429e14fd62c7aa07cde96ecb7418047abfd",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea696e975dd1a602b3de866b8937da79f99ca7aa07cde96ecb7418047abfd02",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea6962505044f7161b3a33b1d45d9f0ea37fb7aa07cde96ecb7418047abfd02dd",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead"
		}, {
			"000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b1c1d1e1f",
			"28576591b7f957b4c5662cdc06e8e873154fdd208142c6f4d55ecedc4eeea6962aae9a7298edb7515a970c6587b62ca17aa07cde96ecb7418047abfd02dd31",
			"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe"
		}
	};

	for ( auto test : tests ) {
		int res;
		uint8_t key[32], iv[16];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz = sizeof(iv);
		std::size_t input_sz = test[2].length() / 2;
		std::size_t output_sz = test[3].length() / 2;
		std::unique_ptr<uint8_t[]> input(new uint8_t[input_sz]);
		std::unique_ptr<uint8_t[]> output(new uint8_t[output_sz]);
		std::size_t total_sz, current_sz, pad_sz = 0;
		std::string output_str;

		res = 0;
		res += Crypto::Utils::from_hex(test[0], key, key_sz);
		res += Crypto::Utils::from_hex(test[1], iv, iv_sz);
		res += Crypto::Utils::from_hex(test[2], input.get(), input_sz);
		EXPECT_EQ(res, 0);

		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, false);

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

		current_sz = total_sz - output_sz;
		res = ctx.steal_last(output.get() + output_sz, current_sz);
		EXPECT_EQ(res, 0);
		output_sz += current_sz;

		res = Crypto::Utils::to_hex(output.get(), output_sz, output_str, false);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(output_str, test[3]);
	}
}

TEST(CBC_CS3, update_sz)
{
	int res;

	uint8_t key[16], iv[16];
	std::size_t key_sz = sizeof(key);
	std::size_t iv_sz = sizeof(iv);
	memset(key, 0x00, key_sz);
	memset(iv, 0x00, iv_sz);

	uint8_t input[64], output[64];
	std::size_t input_sz = sizeof(input);
	std::size_t output_sz = sizeof(output);
	memset(input, 0x00, input_sz);
	memset(output, 0x00, output_sz);

	// buffer_sz = 0, input_sz = 0, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 0;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 0, input_sz = 8, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 8;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 0, input_sz = 24, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 24;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 0, input_sz = 32, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 32;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 15, input_sz = 0, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 15;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 0;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 15, input_sz = 1, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 15;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 1;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 15, input_sz = 16, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 15;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 16;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 15, input_sz = 17, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 15;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 17;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 16, input_sz = 0, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 16;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 0;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 16, input_sz = 15, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 16;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 15;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 16, input_sz = 16, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 16;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 16;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 16, input_sz = 24, output_sz = 16
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 16;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 24;
		output_sz = 16;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 31, input_sz = 0, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 31;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 0;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 31, input_sz = 1, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 31;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 1;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 31, input_sz = 16, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 31;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 16;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);
	}

	// buffer_sz = 31, input_sz = 33, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 31;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 33;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (size_t)32);
	}

	// buffer_sz = 31, input_sz = 33, output_sz = 32
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 31;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 33;
		output_sz = 32;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)32);
	}

	// buffer_sz = 47, input_sz = 1, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 47;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 1;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (size_t)16);
	}
	
	// buffer_sz = 47, input_sz = 1, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 47;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)0);

		input_sz = 1;
		output_sz = 16;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)16);
	}
}

TEST(CBC_CS3, finish_sz)
{
	int res;

	uint8_t key[16], iv[16];
	std::size_t key_sz = sizeof(key);
	std::size_t iv_sz = sizeof(iv);
	memset(key, 0x00, key_sz);
	memset(iv, 0x00, iv_sz);

	uint8_t input[64], output[64];
	std::size_t input_sz = sizeof(input);
	std::size_t output_sz = sizeof(output);
	memset(input, 0x00, input_sz);
	memset(output, 0x00, output_sz);

	std::size_t pad_sz = 0;

	// Buffer empty
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 2);
		EXPECT_EQ(pad_sz, (size_t)16);
	}

	// Buffer not empty < BLOCK_SIZE
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		res = ctx.update(input, 15, output, output_sz);
		EXPECT_EQ(res, 0);

		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 2);
		EXPECT_EQ(pad_sz, (size_t)1);
	}

	// Buffer not empty = BLOCK_SIZE
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		res = ctx.update(input, 16, output, output_sz);
		EXPECT_EQ(res, 0);

		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(pad_sz, (size_t)0);
	}

	// Buffer not empty > BLOCK_SIZE
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		res = ctx.update(input, 24, output, output_sz);
		EXPECT_EQ(res, 0);

		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(pad_sz, (size_t)0);
	}

	// Buffer not empty = 2 * BLOCK_SIZE
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		res = ctx.update(input, 32, output, output_sz);
		EXPECT_EQ(res, 0);

		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(pad_sz, (size_t)0);
	}

	// Buffer not empty > 2 * BLOCK_SIZE
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		res = ctx.update(input, 40, output, output_sz);
		EXPECT_EQ(res, 0);

		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(pad_sz, (size_t)0);
	}
}

TEST(CBC_CS3, steal_last_sz)
{
	int res;

	uint8_t key[16], iv[16];
	std::size_t key_sz = sizeof(key);
	std::size_t iv_sz = sizeof(iv);
	memset(key, 0x00, key_sz);
	memset(iv, 0x00, iv_sz);

	uint8_t input[64], output[64];
	std::size_t input_sz = sizeof(input);
	std::size_t output_sz = sizeof(output);
	memset(input, 0x00, input_sz);
	memset(output, 0x00, output_sz);

	// buffer_sz = 0, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		output_sz = 0;
		res = ctx.steal_last(output, output_sz);
		EXPECT_EQ(res, 2);
		EXPECT_EQ(output_sz, (size_t)16);
	}

	// buffer_sz = 15, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 15;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 0;
		res = ctx.steal_last(output, output_sz);
		EXPECT_EQ(res, 2);
		EXPECT_EQ(output_sz, (size_t)1);
	}

	// buffer_sz = 16, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 16;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 0;
		res = ctx.steal_last(output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (size_t)16);
	}

	// buffer_sz = 16, output_sz = 16
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 16;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 16;
		res = ctx.steal_last(output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)16);
	}

	// buffer_sz = 31, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 31;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 0;
		res = ctx.steal_last(output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (size_t)31);
	}

	// buffer_sz = 31, output_sz = 31
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 31;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 31;
		res = ctx.steal_last(output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)31);
	}

	// buffer_sz = 32, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 32;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 0;
		res = ctx.steal_last(output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (size_t)32);
	}

	// buffer_sz = 32, output_sz = 32
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 32;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 32;
		res = ctx.steal_last(output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)32);
	}

	// buffer_sz = 40, output_sz = 0
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 40;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 0;
		res = ctx.steal_last(output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (size_t)40);
	}

	// buffer_sz = 40, output_sz = 40
	{
		Crypto::CBC_CS3<Crypto::AES> ctx(key, key_sz, iv, true);

		input_sz = 40;
		output_sz = 0;
		res = ctx.update(input, input_sz, output, output_sz);
		EXPECT_EQ(res, 0);

		output_sz = 40;
		res = ctx.steal_last(output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (size_t)40);
	}
}
