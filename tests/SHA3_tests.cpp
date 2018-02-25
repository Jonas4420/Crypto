#include <memory>
#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/SHA3.hpp"

TEST(SHA3, init)
{
	// SHA-256
	{
		uint8_t input[32];
		std::size_t input_sz = sizeof(input);
		uint8_t output[32];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::Utils::from_hex("4149f41be1d265e668c536b85dde41", input, input_sz);
		expected_str = "229a7702448c640f55dafed08a52aa0b1139657ba9fc4c5eb8587e174ecd9b92";

		Crypto::SHA3 ctx(32);

		ctx.update(input, input_sz);
		ctx.finish(output);

		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}

	// SHA-512
	{
		uint8_t input[64];
		std::size_t input_sz = sizeof(input);
		uint8_t output[64];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::Utils::from_hex("a6e7b218449840d134b566290dc896", input, input_sz);
		expected_str = "3605a21ce00b289022193b70b535e6626f324739542978f5b307194fcf0a5988"
			"f542c0838a0443bb9bb8ff922a6a177fdbd12cf805f3ed809c48e9769c8bbd91";

		Crypto::SHA3 ctx(64);

		ctx.update(input, input_sz);
		ctx.finish(output);

		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}

	// Invalid digest size (200 <= 2 * digest_sz)
	{
		std::string exception, expected("Invalid digest length");
		try {
			Crypto::SHA3 ctx(100);
		} catch ( const Crypto::SHA3::Exception &se ) {
			exception = se.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Invalid digest size (200 - 2 * digest_sz <= digest_sz)
	{
		std::string exception, expected("Invalid digest length");
		try {
			Crypto::SHA3 ctx(67);
		} catch ( const Crypto::SHA3::Exception &se ) {
			exception = se.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(SHA3, test_finish)
{
	// SHA-224
	{
		uint8_t input[143];
		std::size_t input_sz = sizeof(input);
		uint8_t output[28];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::SHA3 ctx(output_sz);

		// Add r - 1 data
		memset(input, 0x00, input_sz);
		ctx.update(input, input_sz);
		ctx.finish(output);

		expected_str = "b6b709fdb9852b8c7439a33595d42dba2940f44c10c3ce09f8b6a87a";
		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}

	// SHA-256
	{
		uint8_t input[135];
		std::size_t input_sz = sizeof(input);
		uint8_t output[32];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::SHA3 ctx(output_sz);

		// Add r - 1 data
		memset(input, 0x00, input_sz);
		ctx.update(input, input_sz);
		ctx.finish(output);

		expected_str = "7d080d7ba978a75c8a7d1f9be566c859084509c9c2b4928435c225d5777d98e3";
		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}

	// SHA-384
	{
		uint8_t input[103];
		std::size_t input_sz = sizeof(input);
		uint8_t output[48];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::SHA3 ctx(output_sz);

		// Add r - 1 data
		memset(input, 0x00, input_sz);
		ctx.update(input, input_sz);
		ctx.finish(output);

		expected_str = "11c556552dda63418669716bad02e4125f4973f3ceea99ee50b6ff117e9f7a3f"
			       "ed0360abb5eff4ac8e954205c01981d2";
		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}

	// SHA-512
	{
		uint8_t input[71];
		std::size_t input_sz = sizeof(input);
		uint8_t output[64];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::SHA3 ctx(output_sz);

		// Add r - 1 data
		memset(input, 0x00, input_sz);
		ctx.update(input, input_sz);
		ctx.finish(output);

		expected_str = "cd87417194c917561a59c7f2eb4b95145971e32e8e4ef3b23b0f190bfd29e369"
			       "2cc7975275750a27df95d5c6a99b7a341e1b8a38a750a51aca5b77bae41fbbfc";
		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}
}

TEST(SHA3_224, KAT)
{
	std::vector<std::string> files = {
		"SHA3_224ShortMsg.rsp", "SHA3_224LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 224"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md[Crypto::SHA3_224::SIZE];
				std::string md_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::MessageDigest_get<Crypto::SHA3_224>(msg.get(), msg_sz, md);

				res = Crypto::Utils::to_hex(md, sizeof(md), md_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(md_str, test["MD"]);
			}
		}
	}
}

TEST(SHA3_224, MonteCarlo)
{
	int res;
	uint8_t m[Crypto::SHA3_224::SIZE];
	std::size_t md_sz = sizeof(m);
	std::string md_str;

	std::string file_path = TestOptions::get().vect_dir + "SHA3/" + "SHA3_224Monte.rsp";

	auto test_vectors = TestVectors::NISTParser(file_path)["L = 224"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		res = Crypto::Utils::from_hex(tests.test_cases[0]["Seed"], m, md_sz);
		EXPECT_EQ(res, 0);

		tests.test_cases.erase(tests.test_cases.begin());

		for ( auto test : tests ) {
			for ( std::size_t i = 1 ; i < 1001 ; ++i ) {
				Crypto::MessageDigest_get<Crypto::SHA3_224>(m, md_sz, m);
			}

			res = Crypto::Utils::to_hex(m, md_sz, md_str, false);
			EXPECT_EQ(res, 0);
			EXPECT_EQ(md_str, test["MD"]);
		}
	}
}

TEST(SHA3_224, update_ctx)
{
	std::vector<std::string> files = {
		"SHA3_224ShortMsg.rsp", "SHA3_224LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 224"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md[Crypto::SHA3_224::SIZE];
				std::string md_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::SHA3_224 ctx;

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

TEST(SHA3_224, reset_ctx)
{
	std::vector<std::string> files = {
		"SHA3_224ShortMsg.rsp", "SHA3_224LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 224"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md_1[Crypto::SHA3_224::SIZE];
				uint8_t md_2[Crypto::SHA3_224::SIZE];
				std::string md_1_str, md_2_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::SHA3_224 ctx;
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

TEST(SHA3_256, KAT)
{
	std::vector<std::string> files = {
		"SHA3_256ShortMsg.rsp", "SHA3_256LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 256"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md[Crypto::SHA3_256::SIZE];
				std::string md_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::MessageDigest_get<Crypto::SHA3_256>(msg.get(), msg_sz, md);

				res = Crypto::Utils::to_hex(md, sizeof(md), md_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(md_str, test["MD"]);
			}
		}
	}
}

TEST(SHA3_256, MonteCarlo)
{
	int res;
	uint8_t m[Crypto::SHA3_256::SIZE];
	std::size_t md_sz = sizeof(m);
	std::string md_str;

	std::string file_path = TestOptions::get().vect_dir + "SHA3/" + "SHA3_256Monte.rsp";

	auto test_vectors = TestVectors::NISTParser(file_path)["L = 256"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		res = Crypto::Utils::from_hex(tests.test_cases[0]["Seed"], m, md_sz);
		EXPECT_EQ(res, 0);

		tests.test_cases.erase(tests.test_cases.begin());

		for ( auto test : tests ) {
			for ( std::size_t i = 1 ; i < 1001 ; ++i ) {
				Crypto::MessageDigest_get<Crypto::SHA3_256>(m, md_sz, m);
			}

			res = Crypto::Utils::to_hex(m, md_sz, md_str, false);
			EXPECT_EQ(res, 0);
			EXPECT_EQ(md_str, test["MD"]);
		}
	}
}

TEST(SHA3_256, update_ctx)
{
	std::vector<std::string> files = {
		"SHA3_256ShortMsg.rsp", "SHA3_256LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 256"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md[Crypto::SHA3_256::SIZE];
				std::string md_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::SHA3_256 ctx;

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

TEST(SHA3_256, reset_ctx)
{
	std::vector<std::string> files = {
		"SHA3_256ShortMsg.rsp", "SHA3_256LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 256"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md_1[Crypto::SHA3_256::SIZE];
				uint8_t md_2[Crypto::SHA3_256::SIZE];
				std::string md_1_str, md_2_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::SHA3_256 ctx;
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

TEST(SHA3_384, KAT)
{
	std::vector<std::string> files = {
		"SHA3_384ShortMsg.rsp", "SHA3_384LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 384"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md[Crypto::SHA3_384::SIZE];
				std::string md_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::MessageDigest_get<Crypto::SHA3_384>(msg.get(), msg_sz, md);

				res = Crypto::Utils::to_hex(md, sizeof(md), md_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(md_str, test["MD"]);
			}
		}
	}
}

TEST(SHA3_384, MonteCarlo)
{
	int res;
	uint8_t m[Crypto::SHA3_384::SIZE];
	std::size_t md_sz = sizeof(m);
	std::string md_str;

	std::string file_path = TestOptions::get().vect_dir + "SHA3/" + "SHA3_384Monte.rsp";

	auto test_vectors = TestVectors::NISTParser(file_path)["L = 384"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		res = Crypto::Utils::from_hex(tests.test_cases[0]["Seed"], m, md_sz);
		EXPECT_EQ(res, 0);

		tests.test_cases.erase(tests.test_cases.begin());

		for ( auto test : tests ) {
			for ( std::size_t i = 1 ; i < 1001 ; ++i ) {
				Crypto::MessageDigest_get<Crypto::SHA3_384>(m, md_sz, m);
			}

			res = Crypto::Utils::to_hex(m, md_sz, md_str, false);
			EXPECT_EQ(res, 0);
			EXPECT_EQ(md_str, test["MD"]);
		}
	}
}

TEST(SHA3_384, update_ctx)
{
	std::vector<std::string> files = {
		"SHA3_384ShortMsg.rsp", "SHA3_384LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 384"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md[Crypto::SHA3_384::SIZE];
				std::string md_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::SHA3_384 ctx;

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

TEST(SHA3_384, reset_ctx)
{
	std::vector<std::string> files = {
		"SHA3_384ShortMsg.rsp", "SHA3_384LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 384"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md_1[Crypto::SHA3_384::SIZE];
				uint8_t md_2[Crypto::SHA3_384::SIZE];
				std::string md_1_str, md_2_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::SHA3_384 ctx;
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

TEST(SHA3_512, KAT)
{
	std::vector<std::string> files = {
		"SHA3_512ShortMsg.rsp", "SHA3_512LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 512"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md[Crypto::SHA3_512::SIZE];
				std::string md_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::MessageDigest_get<Crypto::SHA3_512>(msg.get(), msg_sz, md);

				res = Crypto::Utils::to_hex(md, sizeof(md), md_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(md_str, test["MD"]);
			}
		}
	}
}

TEST(SHA3_512, MonteCarlo)
{
	int res;
	uint8_t m[Crypto::SHA3_512::SIZE];
	std::size_t md_sz = sizeof(m);
	std::string md_str;

	std::string file_path = TestOptions::get().vect_dir + "SHA3/" + "SHA3_512Monte.rsp";

	auto test_vectors = TestVectors::NISTParser(file_path)["L = 512"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		res = Crypto::Utils::from_hex(tests.test_cases[0]["Seed"], m, md_sz);
		EXPECT_EQ(res, 0);

		tests.test_cases.erase(tests.test_cases.begin());

		for ( auto test : tests ) {
			for ( std::size_t i = 1 ; i < 1001 ; ++i ) {
				Crypto::MessageDigest_get<Crypto::SHA3_512>(m, md_sz, m);
			}

			res = Crypto::Utils::to_hex(m, md_sz, md_str, false);
			EXPECT_EQ(res, 0);
			EXPECT_EQ(md_str, test["MD"]);
		}
	}
}

TEST(SHA3_512, update_ctx)
{
	std::vector<std::string> files = {
		"SHA3_512ShortMsg.rsp", "SHA3_512LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 512"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md[Crypto::SHA3_512::SIZE];
				std::string md_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::SHA3_512 ctx;

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

TEST(SHA3_512, reset_ctx)
{
	std::vector<std::string> files = {
		"SHA3_512ShortMsg.rsp", "SHA3_512LongMsg.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "SHA3/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path)["L = 512"];
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				std::size_t msg_sz = atoi(test["Len"].c_str()) / 8;
				std::unique_ptr<uint8_t[]> msg(new uint8_t[msg_sz]);
				uint8_t md_1[Crypto::SHA3_512::SIZE];
				uint8_t md_2[Crypto::SHA3_512::SIZE];
				std::string md_1_str, md_2_str;

				if ( msg_sz > 0 ) {
					res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
					EXPECT_EQ(res, 0);
				}

				Crypto::SHA3_512 ctx;
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
