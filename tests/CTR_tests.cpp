#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/AES.hpp"
#include "crypto/CTR.hpp"

TEST(CTR, encrypt_test_vector)
{
	int res;
	const std::vector<std::vector<std::string>> tests = {
		{
			"edfdb257cb37cdf182c5455b0c0efebb",
			"1695fe475421cace3557daca01f445ff",
			"00000000000000000000000000000000",
			"7888beae6e7a426332a7eaa2f808e637"
		}, {
			"00000000000000000000000000000000",
			"00000000000000000000000000000000",
			"66e94bd4ef8a2c3b884cfa59ca342b2e58e2fccefa7e3061367f1d57a4e7455a",
			"0000000000000000000000000000000000000000000000000000000000000000"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t counter[Crypto::AES::BLOCK_SIZE];
		std::size_t counter_sz = sizeof(counter);

		uint8_t input[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t input_sz = sizeof(input);


		uint8_t output[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t output_sz = sizeof(output);
		std::string output_str;

		Crypto::Utils::from_hex(test[0], key, key_sz);
		Crypto::Utils::from_hex(test[1], counter, counter_sz);
		Crypto::Utils::from_hex(test[2], input, input_sz);

		Crypto::CTR<Crypto::AES> ctx(key, key_sz, counter);

		std::size_t current_sz, offset;
		offset = 0;
		for ( std::size_t i = 0 ; i < input_sz ; ++i ) {
			current_sz = output_sz - offset;

			res = ctx.update(input + i, 1, output + offset, current_sz);
			EXPECT_EQ(res, 0);

			offset += current_sz;
		}

		std::size_t pad_sz;
		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);

		Crypto::Utils::to_hex(output, offset, output_str, false);
		EXPECT_THAT(output_str, test[3]);
	}
}

TEST(CTR, decrypt_test_vector)
{
	int res;
	const std::vector<std::vector<std::string>> tests = {
		{
			"54b760dd2968f079ac1d5dd20626445d",
			"46f2c98932349c338e9d67f744a1c988",
			"00000000000000000000000000000000",
			"065bd5a9540d22d5d7b0f75d66cb8b30"
		}, {
			"00000000000000000000000000000000",
			"00000000000000000000000000000000",
			"66e94bd4ef8a2c3b884cfa59ca342b2e58e2fccefa7e3061367f1d57a4e7455a",
			"0000000000000000000000000000000000000000000000000000000000000000"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t counter[Crypto::AES::BLOCK_SIZE];
		std::size_t counter_sz = sizeof(counter);

		uint8_t input[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t input_sz = sizeof(input);

		uint8_t output[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t output_sz = sizeof(output);
		std::string output_str;

		Crypto::Utils::from_hex(test[0], key, key_sz);
		Crypto::Utils::from_hex(test[1], counter, counter_sz);
		Crypto::Utils::from_hex(test[2], input, input_sz);

		Crypto::CTR<Crypto::AES> ctx(key, key_sz, counter);

		std::size_t current_sz, offset;
		offset = 0;
		for ( std::size_t i = 0 ; i < input_sz ; ++i ) {
			current_sz = output_sz - offset;

			res = ctx.update(input + i, 1, output + offset, current_sz);
			EXPECT_EQ(res, 0);

			offset += current_sz;
		}

		std::size_t pad_sz;
		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);

		Crypto::Utils::to_hex(output, offset, output_str, false);
		EXPECT_THAT(output_str, test[3]);
	}
}

TEST(CTR, update_sz)
{
	int res;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t counter[16];
	std::size_t counter_sz = sizeof(counter);
	memset(counter, 0x00, counter_sz);

	uint8_t input[32];
	std::size_t input_sz = sizeof(input);
	memset(input, 0x00, input_sz);

	uint8_t output[32];
	std::size_t output_sz = sizeof(output);
	memset(output, 0x00, output_sz);

	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		Crypto::CTR<Crypto::AES> ctx(key, key_sz, counter);

		output_sz = 0;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(output_sz, (std::size_t)8);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::CTR<Crypto::AES> ctx(key, key_sz, counter);

		output_sz = 8;
		res = ctx.update(input, 8, output, output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)8);
	}
}

TEST(CTR, finish_sz)
{
	int res;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t counter[16];
	std::size_t counter_sz = sizeof(counter);
	memset(counter, 0x00, counter_sz);

	uint8_t input[32];
	std::size_t input_sz = sizeof(input);
	memset(input, 0x00, input_sz);

	uint8_t output[32];
	std::size_t output_sz = sizeof(output);
	memset(output, 0x00, output_sz);

	// Buffer empty, not finished
	{
		Crypto::CTR<Crypto::AES> ctx(key, key_sz, counter);

		output_sz = 16;
		res = ctx.finish(output_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(output_sz, (std::size_t)0);
	}
}
