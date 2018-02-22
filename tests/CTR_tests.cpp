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

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t plain_sz = sizeof(plain);


		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t cipher_sz = sizeof(cipher);
		std::string ciphertext;

		Crypto::Utils::from_hex(test[0], key,     key_sz);
		Crypto::Utils::from_hex(test[1], counter, counter_sz);
		Crypto::Utils::from_hex(test[2], plain,   plain_sz);

		Crypto::CTR<Crypto::AES> ctx(key, key_sz, counter);

		std::size_t current_sz, offset;
		offset = 0;
		for ( std::size_t i = 0 ; i < plain_sz ; ++i ) {
			current_sz = cipher_sz - offset;

			res = ctx.update(plain + i, 1, cipher + offset, current_sz);
			EXPECT_EQ(res, 0);

			offset += current_sz;
		}

		std::size_t pad_sz;
		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);

		Crypto::Utils::to_hex(cipher, offset, ciphertext, false);
		EXPECT_THAT(ciphertext, test[3]);
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

		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t cipher_sz = sizeof(cipher);

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t plain_sz = sizeof(plain);
		std::string plaintext;

		Crypto::Utils::from_hex(test[0], key,     key_sz);
		Crypto::Utils::from_hex(test[1], counter, counter_sz);
		Crypto::Utils::from_hex(test[2], cipher,  cipher_sz);

		Crypto::CTR<Crypto::AES> ctx(key, key_sz, counter);

		std::size_t current_sz, offset;
		offset = 0;
		for ( std::size_t i = 0 ; i < cipher_sz ; ++i ) {
			current_sz = plain_sz - offset;

			res = ctx.update(cipher + i, 1, plain + offset, current_sz);
			EXPECT_EQ(res, 0);

			offset += current_sz;
		}

		std::size_t pad_sz;
		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);

		Crypto::Utils::to_hex(plain, offset, plaintext, false);
		EXPECT_THAT(plaintext, test[3]);
	}
}

TEST(CTR, update_size)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t counter[16];
	std::size_t counter_sz = sizeof(counter);
	memset(counter, 0x00, counter_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		Crypto::CTR<Crypto::AES> ctx(key, key_sz, counter);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)8);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::CTR<Crypto::AES> ctx(key, key_sz, counter);

		cipher_sz = 8;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)8);
	}
}

TEST(CTR, finish_size)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t counter[16];
	std::size_t counter_sz = sizeof(counter);
	memset(counter, 0x00, counter_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	// Buffer empty, not finished
	{
		Crypto::CTR<Crypto::AES> ctx(key, key_sz, counter);

		cipher_sz = 16;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);
	}
}
