#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Serpent.hpp"
#include "crypto/ECB.hpp"
#include "crypto/CBC.hpp"
#include "crypto/Utils.hpp"

/*
 * Information: All serpent test vectors from official serpent website
 * are in big endian encoding, hence the reverse applied when manipulating
 * input and output values
 */

TEST(Serpent, constructor)
{
	// Case 1: key_sz < 256 bits
	{
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::Serpent ctx(key, key_sz);
	}

	// Case 2: key_sz = 256 bits
	{
		uint8_t key[32];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::Serpent ctx(key, key_sz);
	}

	// Case 3: key_sz > 256 bits
	{
		std::string exception, expected("Key size is not supported");
		uint8_t key[64];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		try {
			Crypto::Serpent ctx(key, key_sz);
		} catch ( const Crypto::Serpent::Exception &se ) {
			exception = se.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(Serpent, KAT_enc)
{
	std::vector<std::string> files = {
		"ecb_vk.txt", "ecb_vt.txt", "ecb_tbl.txt"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Serpent/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t input[Crypto::Serpent::BLOCK_SIZE];
			uint8_t output[Crypto::Serpent::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t input_sz = sizeof(input);
			std::string output_str;

			if ( tests.test_cases[0]["CT"].empty() ) {
				if ( ! tests.test_cases[0]["KEY"].empty() ) {
					res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
					EXPECT_EQ(res, 0);
					std::reverse(key, key + key_sz);
				}

				if ( ! tests.test_cases[0]["PT"].empty() ) {
					res = Crypto::Utils::from_hex(tests.test_cases[0]["PT"], input, input_sz);
					EXPECT_EQ(res, 0);
					std::reverse(input, input + input_sz);
				}

				tests.test_cases.erase(tests.test_cases.begin());
			}

			for ( auto test : tests ) {
				if ( ! test["KEY"].empty() ) {
					res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
					EXPECT_EQ(res, 0);
					std::reverse(key, key + key_sz);
				}

				if ( ! test["PT"].empty() ) {
					res = Crypto::Utils::from_hex(test["PT"], input, input_sz);
					EXPECT_EQ(res, 0);
					std::reverse(input, input + input_sz);
				}

				Crypto::Serpent ctx(key, key_sz);
				ctx.encrypt(input, output);

				std::reverse(output, output + sizeof(output));
				res = Crypto::Utils::to_hex(output, sizeof(output), output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CT"]);
			}
		}
	}
}

TEST(Serpent, MonteCarlo_ECB_enc)
{
	std::vector<std::string> files = {
		"ecb_e_m.txt"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Serpent/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t input[Crypto::Serpent::BLOCK_SIZE];
			uint8_t output[2][Crypto::Serpent::BLOCK_SIZE];
			uint8_t output_rev[Crypto::Serpent::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output[0]);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);
			std::reverse(key, key + key_sz);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["PT"], input, input_sz);
			EXPECT_EQ(res, 0);
			std::reverse(input, input + input_sz);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::ECB<Crypto::Serpent> ctx(key, key_sz, true);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(output[0], output[1], output_sz);

					res = ctx.update(input, input_sz, output[1], output_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(input, output[1], input_sz);
				}

				memcpy(output_rev, output[1], output_sz);
				std::reverse(output_rev, output_rev + output_sz);
				res = Crypto::Utils::to_hex(output_rev, output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					if ( i < (key_sz - 16) ) {
						key[i] ^= output[0][i + (32 - key_sz)];
					} else {
						key[i] ^= output[1][i - (key_sz - 16)];
					}
				}

				memcpy(input, output[1], input_sz);
			}
		}
	}
}

TEST(Serpent, MonteCarlo_CBC_enc)
{
	std::vector<std::string> files = {
		"cbc_e_m.txt"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Serpent/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::Serpent::BLOCK_SIZE];
			uint8_t input[Crypto::Serpent::BLOCK_SIZE];
			uint8_t output[2][Crypto::Serpent::BLOCK_SIZE];
			uint8_t output_rev[Crypto::Serpent::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t iv_sz = sizeof(iv);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output[0]);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);
			std::reverse(key, key + key_sz);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			EXPECT_EQ(res, 0);
			std::reverse(iv, iv + iv_sz);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["PT"], input, input_sz);
			EXPECT_EQ(res, 0);
			std::reverse(input, input + input_sz);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::CBC<Crypto::Serpent> ctx(key, key_sz, iv, true);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(output[0], output[1], output_sz);

					res = ctx.update(input, input_sz, output[1], output_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(input, (i == 0) ? iv : output[0], input_sz);
				}

				memcpy(output_rev, output[1], output_sz);
				std::reverse(output_rev, output_rev + output_sz);
				res = Crypto::Utils::to_hex(output_rev, output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CT"]);

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

TEST(Serpent, KAT_dec)
{
	std::vector<std::string> files = {
		"ecb_vk.txt", "ecb_vt.txt", "ecb_tbl.txt"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Serpent/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t input[Crypto::Serpent::BLOCK_SIZE];
			uint8_t output[Crypto::Serpent::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t input_sz = sizeof(input);
			std::string expected_str, output_str;

			if ( tests.test_cases[0]["CT"].empty() ) {
				if ( ! tests.test_cases[0]["KEY"].empty() ) {
					res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
					EXPECT_EQ(res, 0);
					std::reverse(key, key + key_sz);
				}

				if ( ! tests.test_cases[0]["PT"].empty() ) {
					expected_str = tests.test_cases[0]["PT"];
				}

				tests.test_cases.erase(tests.test_cases.begin());
			}

			for ( auto test : tests ) {
				if ( ! test["KEY"].empty() ) {
					res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
					EXPECT_EQ(res, 0);
					std::reverse(key, key + key_sz);
				}

				res = Crypto::Utils::from_hex(test["CT"], input, input_sz);
				EXPECT_EQ(res, 0);
				std::reverse(input, input + input_sz);

				Crypto::Serpent ctx(key, key_sz);
				ctx.decrypt(input, output);

				std::reverse(output, output + sizeof(output));
				res = Crypto::Utils::to_hex(output, sizeof(output), output_str, false);
				EXPECT_EQ(res, 0);

				if ( ! test["PT"].empty() ) {
					expected_str = test["PT"];
				}

				EXPECT_EQ(output_str, expected_str);
			}
		}
	}
}

TEST(Serpent, MonteCarlo_ECB_dec)
{
	std::vector<std::string> files = {
		"ecb_d_m.txt"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Serpent/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t input[Crypto::Serpent::BLOCK_SIZE];
			uint8_t output[2][Crypto::Serpent::BLOCK_SIZE];
			uint8_t output_rev[Crypto::Serpent::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output[0]);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);
			std::reverse(key, key + key_sz);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["CT"], input, input_sz);
			EXPECT_EQ(res, 0);
			std::reverse(input, input + input_sz);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::ECB<Crypto::Serpent> ctx(key, key_sz, false);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(output[0], output[1], output_sz);

					res = ctx.update(input, input_sz, output[1], output_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(input, output[1], input_sz);
				}

				memcpy(output_rev, output[1], output_sz);
				std::reverse(output_rev, output_rev + output_sz);
				res = Crypto::Utils::to_hex(output_rev, output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					if ( i < (key_sz - 16) ) {
						key[i] ^= output[0][i + (32 - key_sz)];
					} else {
						key[i] ^= output[1][i - (key_sz - 16)];
					}
				}
			}
		}
	}
}

TEST(Serpent, MonteCarlo_CBC_dec)
{
	std::vector<std::string> files = {
		"cbc_d_m.txt"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Serpent/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::Serpent::BLOCK_SIZE];
			uint8_t input[Crypto::Serpent::BLOCK_SIZE];
			uint8_t output[2][Crypto::Serpent::BLOCK_SIZE];
			uint8_t output_rev[Crypto::Serpent::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t iv_sz = sizeof(iv);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output[0]);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);
			std::reverse(key, key + key_sz);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			EXPECT_EQ(res, 0);
			std::reverse(iv, iv + iv_sz);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["CT"], input, input_sz);
			EXPECT_EQ(res, 0);
			std::reverse(input, input + input_sz);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::CBC<Crypto::Serpent> ctx(key, key_sz, iv, false);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(output[0], output[1], output_sz);

					res = ctx.update(input, input_sz, output[1], output_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(iv, output[0], iv_sz);
					memcpy(input, output[1], input_sz);
				}

				memcpy(output_rev, output[1], output_sz);
				std::reverse(output_rev, output_rev + output_sz);
				res = Crypto::Utils::to_hex(output_rev, output_sz, output_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["PT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					if ( i < (key_sz - 16) ) {
						key[i] ^= output[0][i + (32 - key_sz)];
					} else {
						key[i] ^= output[1][i - (key_sz - 16)];
					}
				}

				memcpy(iv, output[0], iv_sz);
				memcpy(input, output[1], input_sz);
			}
		}
	}
}
