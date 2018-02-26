#include <memory>
#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/HMAC_DRBG.hpp"
#include "crypto/Utils.hpp"

#include "crypto/SHA1.hpp"
#include "crypto/SHA224.hpp"
#include "crypto/SHA256.hpp"
#include "crypto/SHA384.hpp"
#include "crypto/SHA512.hpp"

TEST(HMAC_DRBG, instantiation_errors)
{
	// Instantiation with NULL entropy
	{
		std::string exception, expected = "Not enough entropy provided";
		try {
			Crypto::HMAC_DRBG<Crypto::SHA512> ctx(NULL, 0, NULL, 0, NULL, 0, false, true);
		} catch ( const Crypto::HMAC_DRBG<Crypto::SHA512>::Exception &hde ) {
			exception = hde.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Instantiation with not enough entropy
	{
		std::string exception, expected = "Not enough entropy provided";
		try {
			uint8_t entropy[16];
			std::size_t entropy_sz = sizeof(entropy);

			Crypto::HMAC_DRBG<Crypto::SHA512> ctx(entropy, entropy_sz, NULL, 0, NULL, 0, false, true);
		} catch ( const Crypto::HMAC_DRBG<Crypto::SHA512>::Exception &hde ) {
			exception = hde.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Instantiation with too much entropy
	{
		std::string exception, expected = "Entropy failure";
		try {
			uint8_t entropy[16];
			std::size_t entropy_sz = (((std::size_t)1) << 32) + 1;

			Crypto::HMAC_DRBG<Crypto::SHA512> ctx(entropy, entropy_sz, NULL, 0, NULL, 0, false, true);
		} catch ( const Crypto::HMAC_DRBG<Crypto::SHA512>::Exception &hde ) {
			exception = hde.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Instantiation with large personalization string
	{
		std::string exception, expected = "Personalization string length is too big";
		try {
			uint8_t entropy[32];
			std::size_t entropy_sz = sizeof(entropy);
			uint8_t perso[32];
			std::size_t perso_sz = (((std::size_t)1) << 32) + 1;

			Crypto::HMAC_DRBG<Crypto::SHA512> ctx(entropy, entropy_sz, NULL, 0, perso, perso_sz, false, true);
		} catch ( const Crypto::HMAC_DRBG<Crypto::SHA512>::Exception &hde ) {
			exception = hde.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(HMAC_DRBG, reseed)
{
	// Reseed with NULL entropy
	{
		uint8_t entropy[32];
		std::size_t entropy_sz = sizeof(entropy);

		std::string exception, expected = "Not enough entropy provided";
		try {
			Crypto::HMAC_DRBG<Crypto::SHA512> ctx(entropy, entropy_sz);
			ctx.reseed(NULL, 0);
		} catch ( const Crypto::HMAC_DRBG<Crypto::SHA512>::Exception &hde ) {
			exception = hde.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Reseed with not enough entropy
	{
		std::string exception, expected = "Not enough entropy provided";
		try {
			uint8_t entropy1[32], entropy2[16];
			std::size_t entropy1_sz = sizeof(entropy1);
			std::size_t entropy2_sz = sizeof(entropy2);

			Crypto::HMAC_DRBG<Crypto::SHA512> ctx(entropy1, entropy1_sz);
			ctx.reseed(entropy2, entropy2_sz);
		} catch ( const Crypto::HMAC_DRBG<Crypto::SHA512>::Exception &hde ) {
			exception = hde.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Reseed with too much entropy
	{
		std::string exception, expected = "Entropy failure";
		try {
			uint8_t entropy1[32], entropy2[32];
			std::size_t entropy1_sz = sizeof(entropy1);
			std::size_t entropy2_sz = (((std::size_t)1) << 32) + 1;

			Crypto::HMAC_DRBG<Crypto::SHA512> ctx(entropy1, entropy1_sz);
			ctx.reseed(entropy2, entropy2_sz);
		} catch ( const Crypto::HMAC_DRBG<Crypto::SHA512>::Exception &hde ) {
			exception = hde.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Reseed with large additional input
	{
		std::string exception, expected = "Additional input length is too big";
		try {
			uint8_t entropy[32];
			std::size_t entropy_sz = sizeof(entropy);
			uint8_t add[32];
			std::size_t add_sz = (((std::size_t)1) << 32) + 1;

			Crypto::HMAC_DRBG<Crypto::SHA512> ctx(entropy, entropy_sz);
			ctx.reseed(entropy, entropy_sz, add, add_sz);
		} catch ( const Crypto::HMAC_DRBG<Crypto::SHA512>::Exception &hde ) {
			exception = hde.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(HMAC_DRBG, generate_errors)
{
	// Reseed needed
	{
		uint8_t entropy[32];
		std::size_t entropy_sz = sizeof(entropy);

		Crypto::HMAC_DRBG<Crypto::SHA512> ctx(entropy, entropy_sz, NULL, 0, NULL, 0, true, true);

		int res = ctx.generate(NULL, 0);
		EXPECT_EQ(res, 1);
	}

	// Too many bytes requested
	{
		std::string exception, expected = "Requested number of bytes is too big";
		uint8_t entropy[32];
		std::size_t entropy_sz = sizeof(entropy);
		std::size_t random_sz  = (((std::size_t)1) << 16) + 1;

		Crypto::HMAC_DRBG<Crypto::SHA512> ctx(entropy, entropy_sz);

		try {
			ctx.generate(NULL, random_sz);
		} catch ( const Crypto::HMAC_DRBG<Crypto::SHA512>::Exception &hde ) {
			exception = hde.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(HMAC_DRBG, reseed_with_pr)
{
	int res;
	uint8_t entropy[32], random[32];
	std::size_t entropy_sz = sizeof(entropy);
	std::size_t random_sz  = sizeof(random);

	Crypto::HMAC_DRBG<Crypto::SHA512> ctx(entropy, entropy_sz, NULL, 0, NULL, 0, true, true);

	res = ctx.generate(random, random_sz);
	EXPECT_EQ(res, 1);

	res = ctx.reseed(entropy, entropy_sz);
	EXPECT_EQ(res, 0);
	res = ctx.generate(random, random_sz);
	EXPECT_EQ(res, 0);

	res = ctx.generate(random, random_sz);
	EXPECT_EQ(res, 1);
}

TEST(HMAC_DRBG, KAT_no_reseed)
{
	std::string file = "HMAC_DRBG.rsp";
	std::string file_path = TestOptions::get().vect_dir + "DRBG/no_reseed/" + file;

	auto test_vectors = TestVectors::NISTParser(file_path);
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		bool pr                = (tests["PredictionResistance"] == "True");
		std::size_t entropy_sz = atoi(tests["EntropyInputLen"].c_str())          / 8;
		std::size_t nonce_sz   = atoi(tests["NonceLen"].c_str())                 / 8;
		std::size_t perso_sz   = atoi(tests["PersonalizationStringLen"].c_str()) / 8;
		std::size_t add_sz     = atoi(tests["AdditionalInputLen"].c_str())       / 8;
		std::size_t random_sz  = atoi(tests["ReturnedBitsLen"].c_str())          / 8;

		std::unique_ptr<uint8_t[]> entropy(new uint8_t[entropy_sz]);
		std::unique_ptr<uint8_t[]> nonce(new uint8_t[nonce_sz]);
		std::unique_ptr<uint8_t[]> perso(new uint8_t[perso_sz]);
		std::unique_ptr<uint8_t[]> add_1(new uint8_t[add_sz]);
		std::unique_ptr<uint8_t[]> add_2(new uint8_t[add_sz]);
		std::unique_ptr<uint8_t[]> random(new uint8_t[random_sz]);

		for ( auto test : tests ) {
			int res;
			Crypto::DRBG *ctx = NULL;
			std::string random_str;

			res = 0;
			res += Crypto::Utils::from_hex(test["EntropyInput"],          entropy.get(), entropy_sz);
			res += Crypto::Utils::from_hex(test["Nonce"],                 nonce.get(),   nonce_sz);
			res += Crypto::Utils::from_hex(test["PersonalizationString"], perso.get(),   perso_sz);
			res += Crypto::Utils::from_hex(test["AdditionalInput:0"],     add_1.get(),   add_sz);
			res += Crypto::Utils::from_hex(test["AdditionalInput:1"],     add_2.get(),   add_sz);
			EXPECT_EQ(res, 0);

			if ( "SHA-1" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA1>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-224" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA224>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-256" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA256>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-384" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA384>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-512" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA512>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			}

			if ( NULL != ctx ) {
				res = ctx->generate(random.get(), random_sz, add_1.get(), add_sz);
				EXPECT_EQ(res, 0);

				res = ctx->generate(random.get(), random_sz, add_2.get(), add_sz);
				EXPECT_EQ(res, 0);

				Crypto::Utils::to_hex(random.get(), random_sz, random_str, false);
				EXPECT_THAT(random_str, test["ReturnedBits"]);

				delete ctx;
			}
		}
	}
}

TEST(HMAC_DRBG, KAT_pr_false)
{
	std::string file = "HMAC_DRBG.rsp";
	std::string file_path = TestOptions::get().vect_dir + "DRBG/pr_false/" + file;

	auto test_vectors = TestVectors::NISTParser(file_path);
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		bool pr                = (tests["PredictionResistance"] == "True");
		std::size_t entropy_sz = atoi(tests["EntropyInputLen"].c_str())          / 8;
		std::size_t nonce_sz   = atoi(tests["NonceLen"].c_str())                 / 8;
		std::size_t perso_sz   = atoi(tests["PersonalizationStringLen"].c_str()) / 8;
		std::size_t add_sz     = atoi(tests["AdditionalInputLen"].c_str())       / 8;
		std::size_t random_sz  = atoi(tests["ReturnedBitsLen"].c_str())          / 8;

		std::unique_ptr<uint8_t[]> entropy(new uint8_t[entropy_sz]);
		std::unique_ptr<uint8_t[]> nonce(new uint8_t[nonce_sz]);
		std::unique_ptr<uint8_t[]> perso(new uint8_t[perso_sz]);
		std::unique_ptr<uint8_t[]> reseed(new uint8_t[entropy_sz]);
		std::unique_ptr<uint8_t[]> add_reseed(new uint8_t[entropy_sz]);
		std::unique_ptr<uint8_t[]> add_1(new uint8_t[add_sz]);
		std::unique_ptr<uint8_t[]> add_2(new uint8_t[add_sz]);
		std::unique_ptr<uint8_t[]> random(new uint8_t[random_sz]);

		for ( auto test : tests ) {
			int res;
			Crypto::DRBG *ctx = NULL;
			std::string random_str;

			res = 0;
			res += Crypto::Utils::from_hex(test["EntropyInput"],          entropy.get(),    entropy_sz);
			res += Crypto::Utils::from_hex(test["Nonce"],                 nonce.get(),      nonce_sz);
			res += Crypto::Utils::from_hex(test["PersonalizationString"], perso.get(),      perso_sz);
			res += Crypto::Utils::from_hex(test["EntropyInputReseed"],    reseed.get(),     entropy_sz);
			res += Crypto::Utils::from_hex(test["AdditionalInputReseed"], add_reseed.get(), add_sz);
			res += Crypto::Utils::from_hex(test["AdditionalInput:0"],     add_1.get(),      add_sz);
			res += Crypto::Utils::from_hex(test["AdditionalInput:1"],     add_2.get(),      add_sz);
			EXPECT_EQ(res, 0);

			if ( "SHA-1" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA1>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-224" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA224>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-256" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA256>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-384" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA384>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-512" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA512>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			}

			if ( NULL != ctx ) {
				res = ctx->reseed(reseed.get(), entropy_sz, add_reseed.get(), add_sz);
				EXPECT_EQ(res, 0);

				res = ctx->generate(random.get(), random_sz, add_1.get(), add_sz);
				EXPECT_EQ(res, 0);

				res = ctx->generate(random.get(), random_sz, add_2.get(), add_sz);
				EXPECT_EQ(res, 0);

				Crypto::Utils::to_hex(random.get(), random_sz, random_str, false);
				EXPECT_THAT(random_str, test["ReturnedBits"]);

				delete ctx;
			}
		}
	}
}

TEST(HMAC_DRBG, KAT_pr_true)
{
	std::string file = "HMAC_DRBG.rsp";
	std::string file_path = TestOptions::get().vect_dir + "DRBG/pr_true/" + file;

	auto test_vectors = TestVectors::NISTParser(file_path);
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		bool pr                = (tests["PredictionResistance"] == "True");
		std::size_t entropy_sz = atoi(tests["EntropyInputLen"].c_str())          / 8;
		std::size_t nonce_sz   = atoi(tests["NonceLen"].c_str())                 / 8;
		std::size_t perso_sz   = atoi(tests["PersonalizationStringLen"].c_str()) / 8;
		std::size_t add_sz     = atoi(tests["AdditionalInputLen"].c_str())       / 8;
		std::size_t random_sz  = atoi(tests["ReturnedBitsLen"].c_str())          / 8;

		std::unique_ptr<uint8_t[]> entropy(new uint8_t[entropy_sz]);
		std::unique_ptr<uint8_t[]> nonce(new uint8_t[nonce_sz]);
		std::unique_ptr<uint8_t[]> perso(new uint8_t[perso_sz]);
		std::unique_ptr<uint8_t[]> entropy_pr_1(new uint8_t[entropy_sz]);
		std::unique_ptr<uint8_t[]> add_1(new uint8_t[add_sz]);
		std::unique_ptr<uint8_t[]> entropy_pr_2(new uint8_t[entropy_sz]);
		std::unique_ptr<uint8_t[]> add_2(new uint8_t[add_sz]);
		std::unique_ptr<uint8_t[]> random(new uint8_t[random_sz]);

		for ( auto test : tests ) {
			int res;
			Crypto::DRBG *ctx = NULL;
			std::string random_str;

			res = 0;
			res += Crypto::Utils::from_hex(test["EntropyInput"],          entropy.get(),      entropy_sz);
			res += Crypto::Utils::from_hex(test["Nonce"],                 nonce.get(),        nonce_sz);
			res += Crypto::Utils::from_hex(test["PersonalizationString"], perso.get(),        perso_sz);
			res += Crypto::Utils::from_hex(test["EntropyInputPR:0"],      entropy_pr_1.get(), entropy_sz);
			res += Crypto::Utils::from_hex(test["AdditionalInput:0"],     add_1.get(),        add_sz);
			res += Crypto::Utils::from_hex(test["EntropyInputPR:1"],      entropy_pr_2.get(), entropy_sz);
			res += Crypto::Utils::from_hex(test["AdditionalInput:1"],     add_2.get(),        add_sz);
			EXPECT_EQ(res, 0);

			if ( "SHA-1" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA1>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-224" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA224>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-256" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA256>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-384" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA384>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			} else if ( "SHA-512" == tests.name ) {
				ctx = new Crypto::HMAC_DRBG<Crypto::SHA512>(entropy.get(), entropy_sz, nonce.get(), nonce_sz, perso.get(), perso_sz, pr);
			}

			if ( NULL != ctx ) {
				res = ctx->generate(random.get(), random_sz, NULL, 0);
				EXPECT_EQ(res, 1);
				res = ctx->reseed(entropy_pr_1.get(), entropy_sz, add_1.get(), add_sz);
				EXPECT_EQ(res, 0);
				res = ctx->generate(random.get(), random_sz, NULL, 0);
				EXPECT_EQ(res, 0);

				res = ctx->generate(random.get(), random_sz, NULL, 0);
				EXPECT_EQ(res, 1);
				res = ctx->reseed(entropy_pr_2.get(), entropy_sz, add_2.get(), add_sz);
				EXPECT_EQ(res, 0);
				res = ctx->generate(random.get(), random_sz, NULL, 0);
				EXPECT_EQ(res, 0);

				Crypto::Utils::to_hex(random.get(), random_sz, random_str, false);
				EXPECT_THAT(random_str, test["ReturnedBits"]);

				delete ctx;
			}
		}
	}
}
