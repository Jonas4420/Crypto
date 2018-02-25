#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/SHA384.hpp"

TEST(SHA384, KAT)
{
	std::vector<std::string> files = {
		"SHA384ShortMsg.rsp", "SHA384LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 48"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t> msg(new uint8_t[msg_sz]);
				uint8_t md[Crypto::SHA384::SIZE];
				std::string md_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::MessageDigest_get<Crypto::SHA384>(msg.get(), msg_sz, md);

				res = Crypto::Utils::to_hex(md, sizeof(md), md_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(md_str, test["MD"]);
			}
		}
	}
}

TEST(SHA384, MonteCarlo)
{
	int res;
	uint8_t seed[Crypto::SHA384::SIZE];
	uint8_t m[4][Crypto::SHA384::SIZE];
	std::size_t md_sz = Crypto::SHA384::SIZE;
	std::string md_str;

	std::string file_path = TestOptions::get().vect_dir + "SHA/" + "SHA384Monte.rsp";

	auto test_vectors = TestVectors::NISTParser(file_path)["L = 48"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		res = Crypto::Utils::from_hex(tests.test_cases[0]["Seed"], seed, md_sz);
		EXPECT_EQ(res, 0);

		tests.test_cases.erase(tests.test_cases.begin());

		for ( auto test : tests ) {
			memcpy(m[0], seed, md_sz);
			memcpy(m[1], seed, md_sz);
			memcpy(m[2], seed, md_sz);

			for ( std::size_t i = 3 ; i < 1003 ; ++i ) {
				Crypto::MessageDigest_get<Crypto::SHA384>(m[0], 3 * md_sz, m[3]);

				memcpy(m[0], m[1], md_sz);
				memcpy(m[1], m[2], md_sz);
				memcpy(m[2], m[3], md_sz);
			}

			memcpy(seed, m[3], md_sz);

			res = Crypto::Utils::to_hex(m[3], md_sz, md_str, false);
			EXPECT_EQ(res, 0);
			EXPECT_EQ(md_str, test["MD"]);
		}
	}
}

TEST(SHA384, update_ctx)
{
	std::vector<std::string> files = {
		"SHA384ShortMsg.rsp", "SHA384LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 48"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t> msg(new uint8_t[msg_sz]);
				uint8_t md[Crypto::SHA384::SIZE];
				std::string md_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::SHA384 ctx;

				for ( std::size_t i = 0 ; i < msg_sz ; ++i ) {
					ctx.update(msg.get() + i, 1);
				}

				ctx.finish(md);

				res = Crypto::Utils::to_hex(md, sizeof(md), md_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(md_str, test["MD"]);
			}
		}
	}
}

TEST(SHA384, reset_ctx)
{
	std::vector<std::string> files = {
		"SHA384ShortMsg.rsp", "SHA384LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 48"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t> msg(new uint8_t[msg_sz]);
				uint8_t md_1[Crypto::SHA384::SIZE];
				uint8_t md_2[Crypto::SHA384::SIZE];
				std::string md_1_str, md_2_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::SHA384 ctx;
				ctx.update(msg.get(), msg_sz);
				ctx.reset();
				ctx.update(msg.get(), msg_sz);
				ctx.finish(md_1);

				res = Crypto::Utils::to_hex(md_1, sizeof(md_1), md_1_str, false);
				EXPECT_EQ(res, 0);

				ctx.update(msg.get(), msg_sz);
				ctx.finish(md_2);

				res = Crypto::Utils::to_hex(md_2, sizeof(md_2), md_2_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(md_1_str, test["MD"]);
				EXPECT_EQ(md_2_str, test["MD"]);
			}
		}
	}
}

