#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/MD5.hpp"
#include "crypto/HMAC.hpp"

TEST(MD5, digest_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"d41d8cd98f00b204e9800998ecf8427e"
		} , {
			"a",
			"0cc175b9c0f1b6a831c399e269772661"
		}, {
			"abc",
			"900150983cd24fb0d6963f7d28e17f72"
		}, {
			"message digest",
			"f96b697d7cb7938d525a2f31aaf161d0"
		}, {
			"abcdefghijklmnopqrstuvwxyz",
			"c3fcd3d76192e4007dfb496cca67e13b"
		}, {
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			"d174ab98d277d9f5a5611c2c9f419d9f"
		}, {
			"1234567890123456789012345678901234567890123456789012345678901234"
			"5678901234567890",
			"57edf4a22be3c955ac49da2e2107b67a"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);

		uint8_t out[Crypto::MD5::SIZE];
		std::string output;

		Crypto::Utils::from_string(test[0], in, in_sz);
		Crypto::MessageDigest_get<Crypto::MD5>(in, in_sz, out);
		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[1]);
	}
}

TEST(MD5, mac_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			"4869205468657265",
			"5ccec34ea9656392457fa1ac27f08fbc"
		}, {
			"4a656665",
			"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"750c783e6ab0b503eaa86e310a5db738"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			"dddddddddddddddddddddddddddddddddddd",
			"56be34521d144c88dbb8c733f0e8b3f6"
		}, {
			"0102030405060708090a0b0c0d0e0f10111213141516171819",
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
			"697eaf0aca3a3aea3a75164746ffaa79"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579204669727374",
			"6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d"
			"53697a652044617461",
			"6f630fad67cda0ee1fb1f562db3aa53e"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[2048];
		std::size_t key_sz = sizeof(key);
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::HMAC<Crypto::MD5>::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], key, key_sz);
		Crypto::Utils::from_hex(test[1], in, in_sz);

		Crypto::HMAC_get<Crypto::MD5>(key, key_sz, in, in_sz, out);
		Crypto::Utils::to_hex(out, 16, output, false);

		EXPECT_THAT(output, test[2]);
	}
}

TEST(MD5, reset_ctx)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"d41d8cd98f00b204e9800998ecf8427e"
		} , {
			"a",
			"0cc175b9c0f1b6a831c399e269772661"
		}, {
			"abc",
			"900150983cd24fb0d6963f7d28e17f72"
		}, {
			"message digest",
			"f96b697d7cb7938d525a2f31aaf161d0"
		}, {
			"abcdefghijklmnopqrstuvwxyz",
			"c3fcd3d76192e4007dfb496cca67e13b"
		}, {
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			"d174ab98d277d9f5a5611c2c9f419d9f"
		}, {
			"1234567890123456789012345678901234567890123456789012345678901234"
			"5678901234567890",
			"57edf4a22be3c955ac49da2e2107b67a"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);

		uint8_t out_1[Crypto::MD5::SIZE];
		uint8_t out_2[Crypto::MD5::SIZE];
		std::string output_1, output_2;

		Crypto::Utils::from_string(test[0], in, in_sz);

		Crypto::MD5 ctx;
		ctx.update(in, in_sz);
		ctx.reset();
		ctx.update(in, in_sz);
		ctx.finish(out_1);
		Crypto::Utils::to_hex(out_1, sizeof(out_1), output_1, false);

		ctx.update(in, in_sz);
		ctx.finish(out_2);
		Crypto::Utils::to_hex(out_2, sizeof(out_2), output_2, false);

		EXPECT_THAT(output_1, test[1]);
		EXPECT_THAT(output_2, test[1]);
	}
}
