#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Twofish.hpp"
#include "crypto/ECB.hpp"
#include "crypto/CBC.hpp"
#include "crypto/Utils.hpp"

TEST(Twofish, constructor)
{
	// Case 1: key_sz < 256 bits
	{
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::Twofish ctx(key, key_sz);
	}

	// Case 2: key_sz = 256 bits
	{
		uint8_t key[32];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::Twofish ctx(key, key_sz);
	}

	// Case 3: key_sz > 256 bits
	{
		std::string exception, expected("Key size is not supported");
		uint8_t key[64];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		try {
			Crypto::Twofish ctx(key, key_sz);
		} catch ( const Crypto::Twofish::Exception &te ) {
			exception = te.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(Twofish, KAT_enc)
{
	std::vector<std::string> files = {
		"ECB_VK.TXT", "ECB_VT.TXT", "ECB_TBL.TXT"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Twofish/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t input[Crypto::Twofish::BLOCK_SIZE];
			uint8_t output[Crypto::Twofish::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t input_sz = sizeof(input);
			std::string output_str;

			if ( tests.test_cases[0]["CT"].empty() ) {
				if ( ! tests.test_cases[0]["KEY"].empty() ) {
					res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
					EXPECT_EQ(res, 0);
				}

				if ( ! tests.test_cases[0]["PT"].empty() ) {
					res = Crypto::Utils::from_hex(tests.test_cases[0]["PT"], input, input_sz);
					EXPECT_EQ(res, 0);
				}

				tests.test_cases.erase(tests.test_cases.begin());
			}

			for ( auto test : tests ) {
				if ( ! test["KEY"].empty() ) {
					res = Crypto::Utils::from_hex(test["KEY"], key, key_sz);
					EXPECT_EQ(res, 0);
				}

				if ( ! test["PT"].empty() ) {
					res = Crypto::Utils::from_hex(test["PT"], input, input_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::Twofish ctx(key, key_sz);
				ctx.encrypt(input, output);

				res = Crypto::Utils::to_hex(output, sizeof(output), output_str, true);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(output_str, test["CT"]);
			}
		}
	}
}

TEST(Twofish, MonteCarlo_ECB_enc)
{
	std::vector<std::string> files = {
		"ECB_E_M.TXT"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Twofish/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t input[Crypto::Twofish::BLOCK_SIZE];
			uint8_t output[2][Crypto::Twofish::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output[0]);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["PT"], input, input_sz);
			EXPECT_EQ(res, 0);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::ECB<Crypto::Twofish> ctx(key, key_sz, true);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(output[0], output[1], output_sz);

					res = ctx.update(input, input_sz, output[1], output_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(input, output[1], input_sz);
				}

				res = Crypto::Utils::to_hex(output[1], output_sz, output_str, true);
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

TEST(Twofish, MonteCarlo_CBC_enc)
{
	std::vector<std::string> files = {
		"CBC_E_M.TXT"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Twofish/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::Twofish::BLOCK_SIZE];
			uint8_t input[Crypto::Twofish::BLOCK_SIZE];
			uint8_t output[2][Crypto::Twofish::BLOCK_SIZE];
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

			res = Crypto::Utils::from_hex(tests.test_cases[0]["PT"], input, input_sz);
			EXPECT_EQ(res, 0);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::CBC<Crypto::Twofish> ctx(key, key_sz, iv, true);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(output[0], output[1], output_sz);

					res = ctx.update(input, input_sz, output[1], output_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(input, (i == 0) ? iv : output[0], input_sz);
				}

				res = Crypto::Utils::to_hex(output[1], output_sz, output_str, true);
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

TEST(Twofish, KAT_dec)
{
	std::vector<std::string> files = {
		"ECB_VK.TXT", "ECB_VT.TXT", "ECB_TBL.TXT"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Twofish/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t input[Crypto::Twofish::BLOCK_SIZE];
			uint8_t output[Crypto::Twofish::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t input_sz = sizeof(input);
			std::string expected_str, output_str;

			if ( tests.test_cases[0]["CT"].empty() ) {
				if ( ! tests.test_cases[0]["KEY"].empty() ) {
					res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
					EXPECT_EQ(res, 0);
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
				}

				res = Crypto::Utils::from_hex(test["CT"], input, input_sz);
				EXPECT_EQ(res, 0);

				Crypto::Twofish ctx(key, key_sz);
				ctx.decrypt(input, output);

				res = Crypto::Utils::to_hex(output, sizeof(output), output_str, true);
				EXPECT_EQ(res, 0);

				if ( ! test["PT"].empty() ) {
					expected_str = test["PT"];
				}

				EXPECT_EQ(output_str, expected_str);
			}
		}
	}
}

TEST(Twofish, MonteCarlo_ECB_dec)
{
	std::vector<std::string> files = {
		"ECB_D_M.TXT"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Twofish/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t input[Crypto::Twofish::BLOCK_SIZE];
			uint8_t output[2][Crypto::Twofish::BLOCK_SIZE];
			std::size_t key_sz = sizeof(key);
			std::size_t input_sz = sizeof(input);
			std::size_t output_sz = sizeof(output[0]);
			std::size_t pad_sz = 0;
			std::string output_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["CT"], input, input_sz);
			EXPECT_EQ(res, 0);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::ECB<Crypto::Twofish> ctx(key, key_sz, false);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(output[0], output[1], output_sz);

					res = ctx.update(input, input_sz, output[1], output_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(input, output[1], input_sz);
				}

				res = Crypto::Utils::to_hex(output[1], output_sz, output_str, true);
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

TEST(Twofish, MonteCarlo_CBC_dec)
{
	std::vector<std::string> files = {
		"CBC_D_M.TXT"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "Twofish/" + file;

		auto test_vectors = TestVectors::AESContestParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::Twofish::BLOCK_SIZE];
			uint8_t input[Crypto::Twofish::BLOCK_SIZE];
			uint8_t output[2][Crypto::Twofish::BLOCK_SIZE];
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

			res = Crypto::Utils::from_hex(tests.test_cases[0]["CT"], input, input_sz);
			EXPECT_EQ(res, 0);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::CBC<Crypto::Twofish> ctx(key, key_sz, iv, false);

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

				res = Crypto::Utils::to_hex(output[1], output_sz, output_str, true);
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
