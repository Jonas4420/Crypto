#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/RIPEMD160.hpp"
#include "crypto/HMAC.hpp"

TEST(RIPEMD160, digest_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"9c1185a5c5e9fc54612808977ee8f548b2258d31"
		} , {
			"a",
			"0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"
		}, {
			"abc",
			"8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
		}, {
			"message digest",
			"5d0689ef49d2fae572b881b123a85ffa21595f36"
		}, {
			"abcdefghijklmnopqrstuvwxyz",
			"f71c27109c692c1b56bbdceb5b9d2865b3708dbc"
		}, {
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"12a053384a9c0c88e405a06c27dcf49ada62eb2b"
		}, {
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			"b0e20b6e3116640286ed3a87a5713079b21f5189"
		}, {
			"1234567890123456789012345678901234567890123456789012345678901234"
			"5678901234567890",
			"9b752e45573d4b39f4dbd3323cab82bf63326bfb"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);

		uint8_t out[Crypto::RIPEMD160::SIZE];
		std::string output;

		Crypto::Utils::from_string(test[0], in, in_sz);
		Crypto::MessageDigest_get<Crypto::RIPEMD160>(in, in_sz, out);
		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[1]);
	}
}

TEST(RIPEMD160, mac_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			"4869205468657265",
			"24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668"
		}, {
			"4a656665",
			"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"dda6c0213a485a9e24f4742064a7f033b43c4069"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			"dddddddddddddddddddddddddddddddddddd",
			"b0b105360de759960ab4f35298e116e295d8e7c1"
		}, {
			"0102030405060708090a0b0c0d0e0f10111213141516171819",
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
			"d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4"
		}, {
			"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
			"546573742057697468205472756e636174696f6e",
			"7619693978f91d90539ae786500ff3d8e0518e39"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579204669727374",
			"6466ca07ac5eac29e1bd523e5ada7605b791fd8b"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d"
			"53697a652044617461",
			"69ea60798d71616cce5fd0871e23754cd75d5a0a"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[2048];
		std::size_t key_sz = sizeof(key);
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::HMAC<Crypto::RIPEMD160>::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], key, key_sz);
		Crypto::Utils::from_hex(test[1], in, in_sz);

		Crypto::HMAC_get<Crypto::RIPEMD160>(key, key_sz, in, in_sz, out);
		Crypto::Utils::to_hex(out, 20, output, false);

		EXPECT_THAT(output, test[2]);
	}
}

TEST(RIPEMD160, reset_ctx)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"9c1185a5c5e9fc54612808977ee8f548b2258d31"
		} , {
			"a",
			"0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"
		}, {
			"abc",
			"8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
		}, {
			"message digest",
			"5d0689ef49d2fae572b881b123a85ffa21595f36"
		}, {
			"abcdefghijklmnopqrstuvwxyz",
			"f71c27109c692c1b56bbdceb5b9d2865b3708dbc"
		}, {
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"12a053384a9c0c88e405a06c27dcf49ada62eb2b"
		}, {
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			"b0e20b6e3116640286ed3a87a5713079b21f5189"
		}, {
			"1234567890123456789012345678901234567890123456789012345678901234"
			"5678901234567890",
			"9b752e45573d4b39f4dbd3323cab82bf63326bfb"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);

		uint8_t out_1[Crypto::RIPEMD160::SIZE];
		uint8_t out_2[Crypto::RIPEMD160::SIZE];
		std::string output_1, output_2;

		Crypto::Utils::from_string(test[0], in, in_sz);

		Crypto::RIPEMD160 ctx;
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
