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

		auto test_vectors = TestVectors::AESCandidateParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t plain[Crypto::Twofish::BLOCK_SIZE];
			uint8_t cipher[Crypto::Twofish::BLOCK_SIZE];
			std::size_t key_sz   = sizeof(key);
			std::size_t plain_sz = sizeof(plain);
			std::string cipher_str;

			if ( tests.test_cases[0]["CT"].empty() ) {
				if ( ! tests.test_cases[0]["KEY"].empty() ) {
					res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
					EXPECT_EQ(res, 0);
				}

				if ( ! tests.test_cases[0]["PT"].empty() ) {
					res = Crypto::Utils::from_hex(tests.test_cases[0]["PT"], plain, plain_sz);
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
					res = Crypto::Utils::from_hex(test["PT"], plain, plain_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::Twofish ctx(key, key_sz);
				ctx.encrypt(plain, cipher);

				res = Crypto::Utils::to_hex(cipher, sizeof(cipher), cipher_str, true);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(cipher_str, test["CT"]);
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

		auto test_vectors = TestVectors::AESCandidateParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t plain[Crypto::Twofish::BLOCK_SIZE];
			uint8_t cipher[2][Crypto::Twofish::BLOCK_SIZE];
			std::size_t key_sz    = sizeof(key);
			std::size_t plain_sz  = sizeof(plain);
			std::size_t cipher_sz = sizeof(cipher[0]);
			std::size_t pad_sz = 0;
			std::string cipher_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["PT"], plain, plain_sz);
			EXPECT_EQ(res, 0);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::ECB<Crypto::Twofish> ctx(key, key_sz, true);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(cipher[0], cipher[1], cipher_sz);

					res = ctx.update(plain, plain_sz, cipher[1], cipher_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(plain, cipher[1], plain_sz);
				}

				res = Crypto::Utils::to_hex(cipher[1], cipher_sz, cipher_str, true);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(cipher_str, test["CT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					if ( i < (key_sz - 16) ) {
						key[i] ^= cipher[0][i + (32 - key_sz)];
					} else {
						key[i] ^= cipher[1][i - (key_sz - 16)];
					}
				}

				memcpy(plain, cipher[1], plain_sz);
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

		auto test_vectors = TestVectors::AESCandidateParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::Twofish::BLOCK_SIZE];
			uint8_t plain[Crypto::Twofish::BLOCK_SIZE];
			uint8_t cipher[2][Crypto::Twofish::BLOCK_SIZE];
			std::size_t key_sz    = sizeof(key);
			std::size_t iv_sz     = sizeof(iv);
			std::size_t plain_sz  = sizeof(plain);
			std::size_t cipher_sz = sizeof(cipher[0]);
			std::size_t pad_sz = 0;
			std::string cipher_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["PT"], plain, plain_sz);
			EXPECT_EQ(res, 0);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::CBC<Crypto::Twofish> ctx(key, key_sz, iv, true);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(cipher[0], cipher[1], cipher_sz);

					res = ctx.update(plain, plain_sz, cipher[1], cipher_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(plain, (i == 0) ? iv : cipher[0], plain_sz);
				}

				res = Crypto::Utils::to_hex(cipher[1], cipher_sz, cipher_str, true);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(cipher_str, test["CT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					if ( i < (key_sz - 16) ) {
						key[i] ^= cipher[0][i + (32 - key_sz)];
					} else {
						key[i] ^= cipher[1][i - (key_sz - 16)];
					}
				}

				memcpy(iv,    cipher[1], iv_sz);
				memcpy(plain, cipher[0], plain_sz);
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

		auto test_vectors = TestVectors::AESCandidateParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t cipher[Crypto::Twofish::BLOCK_SIZE];
			uint8_t plain[Crypto::Twofish::BLOCK_SIZE];
			std::size_t key_sz    = sizeof(key);
			std::size_t cipher_sz = sizeof(cipher);
			std::string expected_str, plain_str;

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

				res = Crypto::Utils::from_hex(test["CT"], cipher, cipher_sz);
				EXPECT_EQ(res, 0);

				Crypto::Twofish ctx(key, key_sz);
				ctx.decrypt(cipher, plain);

				res = Crypto::Utils::to_hex(plain, sizeof(plain), plain_str, true);
				EXPECT_EQ(res, 0);

				if ( ! test["PT"].empty() ) {
					expected_str = test["PT"];
				}

				EXPECT_EQ(plain_str, expected_str);
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

		auto test_vectors = TestVectors::AESCandidateParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t cipher[Crypto::Twofish::BLOCK_SIZE];
			uint8_t plain[2][Crypto::Twofish::BLOCK_SIZE];
			std::size_t key_sz    = sizeof(key);
			std::size_t cipher_sz = sizeof(cipher);
			std::size_t plain_sz  = sizeof(plain[0]);
			std::size_t pad_sz = 0;
			std::string plain_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["CT"], cipher, cipher_sz);
			EXPECT_EQ(res, 0);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::ECB<Crypto::Twofish> ctx(key, key_sz, false);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(plain[0], plain[1], plain_sz);

					res = ctx.update(cipher, cipher_sz, plain[1], plain_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(cipher, plain[1], cipher_sz);
				}

				res = Crypto::Utils::to_hex(plain[1], plain_sz, plain_str, true);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(plain_str, test["PT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					if ( i < (key_sz - 16) ) {
						key[i] ^= plain[0][i + (32 - key_sz)];
					} else {
						key[i] ^= plain[1][i - (key_sz - 16)];
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

		auto test_vectors = TestVectors::AESCandidateParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			int res;
			uint8_t key[32];
			uint8_t iv[Crypto::Twofish::BLOCK_SIZE];
			uint8_t cipher[Crypto::Twofish::BLOCK_SIZE];
			uint8_t plain[2][Crypto::Twofish::BLOCK_SIZE];
			std::size_t key_sz    = sizeof(key);
			std::size_t iv_sz     = sizeof(iv);
			std::size_t cipher_sz = sizeof(cipher);
			std::size_t plain_sz  = sizeof(plain[0]);
			std::size_t pad_sz = 0;
			std::string plain_str;

			res = Crypto::Utils::from_hex(tests.test_cases[0]["KEY"], key, key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["IV"], iv, iv_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(tests.test_cases[0]["CT"], cipher, cipher_sz);
			EXPECT_EQ(res, 0);

			int iterations = 0;
			for ( auto test : tests ) {
				if ( TestOptions::get().is_fast && iterations > 100 ) {
					continue;
				}
				++iterations;

				Crypto::CBC<Crypto::Twofish> ctx(key, key_sz, iv, false);

				for ( std::size_t i = 0 ; i < 10000 ; ++i ) {
					memcpy(plain[0], plain[1], plain_sz);

					res = ctx.update(cipher, cipher_sz, plain[1], plain_sz);
					EXPECT_EQ(res, 0);

					res = ctx.finish(pad_sz);
					EXPECT_EQ(res, 0);
					EXPECT_EQ(pad_sz, 0);

					memcpy(iv,     plain[0], iv_sz);
					memcpy(cipher, plain[1], cipher_sz);
				}

				res = Crypto::Utils::to_hex(plain[1], plain_sz, plain_str, true);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(plain_str, test["PT"]);

				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					if ( i < (key_sz - 16) ) {
						key[i] ^= plain[0][i + (32 - key_sz)];
					} else {
						key[i] ^= plain[1][i - (key_sz - 16)];
					}
				}

				memcpy(iv,     plain[0], iv_sz);
				memcpy(cipher, plain[1], cipher_sz);
			}
		}
	}
}
