#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/Twofish.hpp"

TEST(Twofish128, encrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0",  "9f589f5cf6122c32b6bfec2f2ae8c35a" },
		{ "1",  "d491db16e7b1c39e86cb086b789f5419" },
		{ "2",  "019f9809de1711858faac3a3ba20fbc3" },
		{ "3",  "6363977de839486297e661c6c9d668eb" },
		{ "4",  "816d5bd0fae35342bf2a7412c246f752" },
		{ "5",  "5449eca008ff5921155f598af4ced4d0" },
		{ "6",  "6600522e97aeb3094ed5f92afcbcdd10" },
		{ "7",  "34c8a5fb2d3d08a170d120ac6d26dbfa" },
		{ "8",  "28530b358c1b42ef277de6d4407fc591" },
		{ "9",  "8a8ab983310ed78c8c0ecde030b8dca4" },
		{ "47", "6b459286f3ffd28d49f15b1581b08e42" },
		{ "48", "5d9d4eeffa9151575524f115815a12e0" }
	};

	std::vector<std::string> ciphertexts;
	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	uint8_t plain[16];
	std::size_t plain_sz = sizeof(plain);
	uint8_t cipher[16];
	std::size_t cipher_sz = sizeof(cipher);
	std::string ciphertext;

	memset(key,   0x00, key_sz);
	memset(plain, 0x00, plain_sz);

	for ( std::size_t i = 0 ; i < 50 ; ++i ) {
		Crypto::Twofish ctx(key, key_sz);
		ctx.encrypt(plain, cipher);

		// Shift key
		memcpy(key + 16, key,   key_sz - 16);
		memcpy(key,      plain, 16);

		// Shift plain
		memcpy(plain, cipher, plain_sz);

		// Push result
		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext, false);
		ciphertexts.push_back(ciphertext);
	}

	for ( auto test : tests ) {
		std::size_t idx = atoi(test[0].c_str());
		EXPECT_EQ(ciphertexts[idx], test[1]);
	}
}

TEST(Twofish128, decrypt_test)
{
	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	uint8_t plain[16];
	std::size_t plain_sz = sizeof(plain);
	uint8_t cipher[16];
	uint8_t decrypt[16];

	memset(key,   0x00, key_sz);
	memset(plain, 0x00, plain_sz);

	for ( std::size_t i = 0 ; i < 50 ; ++i ) {
		Crypto::Twofish ctx(key, key_sz);
		ctx.encrypt(plain, cipher);
		ctx.decrypt(cipher, decrypt);

		EXPECT_EQ(0, memcmp(plain, decrypt, plain_sz));

		// Shift key
		memcpy(key + 16, key,   key_sz - 16);
		memcpy(key,      plain, 16);

		// Shift plain
		memcpy(plain, cipher, plain_sz);
	}
}

TEST(Twofish192, encrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0",  "efa71f788965bd4453f860178fc19101" },
		{ "1",  "88b2b2706b105e36b446bb6d731a1e88" },
		{ "2",  "39da69d6ba4997d585b6dc073ca341b2" },
		{ "3",  "182b02d81497ea45f9daacdc29193a65" },
		{ "4",  "7aff7a70ca2ff28ac31dd8ae5daaab63" },
		{ "5",  "d1079b789f666649b6bd7d1629f1f77e" },
		{ "6",  "3af6f7ce5bd35ef18bec6fa787ab506b" },
		{ "7",  "ae8109bfda85c1f2c5038b34ed691bff" },
		{ "8",  "893fd67b98c550073571bd631263fc78" },
		{ "9",  "16434fc9c8841a63d58700b5578e8f67" },
		{ "47", "f0ab73301125fa21ef70be5385fb76b6" },
		{ "48", "e75449212beef9f4a390bd860a640941" }
	};

	std::vector<std::string> ciphertexts;
	uint8_t key[24];
	std::size_t key_sz = sizeof(key);
	uint8_t plain[16];
	std::size_t plain_sz = sizeof(plain);
	uint8_t cipher[16];
	std::size_t cipher_sz = sizeof(cipher);
	std::string ciphertext;

	memset(key,   0x00, key_sz);
	memset(plain, 0x00, plain_sz);

	for ( std::size_t i = 0 ; i < 50 ; ++i ) {
		Crypto::Twofish ctx(key, key_sz);
		ctx.encrypt(plain, cipher);

		// Shift key
		memcpy(key + 16, key,   key_sz - 16);
		memcpy(key,      plain, 16);

		// Shift plain
		memcpy(plain, cipher, plain_sz);

		// Push result
		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext, false);
		ciphertexts.push_back(ciphertext);
	}

	for ( auto test : tests ) {
		std::size_t idx = atoi(test[0].c_str());
		EXPECT_EQ(ciphertexts[idx], test[1]);
	}
}

TEST(Twofish192, decrypt_test)
{
	uint8_t key[24];
	std::size_t key_sz = sizeof(key);
	uint8_t plain[16];
	std::size_t plain_sz = sizeof(plain);
	uint8_t cipher[16];
	uint8_t decrypt[16];

	memset(key,   0x00, key_sz);
	memset(plain, 0x00, plain_sz);

	for ( std::size_t i = 0 ; i < 50 ; ++i ) {
		Crypto::Twofish ctx(key, key_sz);
		ctx.encrypt(plain, cipher);
		ctx.decrypt(cipher, decrypt);

		EXPECT_EQ(0, memcmp(plain, decrypt, plain_sz));

		// Shift key
		memcpy(key + 16, key,   key_sz - 16);
		memcpy(key,      plain, 16);

		// Shift plain
		memcpy(plain, cipher, plain_sz);
	}
}

TEST(Twofish256, encrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0",  "57ff739d4dc92c1bd7fc01700cc8216f" },
		{ "1",  "d43bb7556ea32e46f2a282b7d45b4e0d" },
		{ "2",  "90afe91bb288544f2c32dc239b2635e6" },
		{ "3",  "6cb4561c40bf0a9705931cb6d408e7fa" },
		{ "4",  "3059d6d61753b958d92f4781c8640e58" },
		{ "5",  "e69465770505d7f80ef68ca38ab3a3d6" },
		{ "6",  "5ab67a5f8539a4a5fd9f0373ba463466" },
		{ "7",  "dc096bcd99fc72f79936d4c748e75af7" },
		{ "8",  "c5a3e7cee0f1b7260528a68fb4ea05f2" },
		{ "9",  "43d5cec327b24ab90ad34a79d0469151" },
		{ "47", "431058f4dbc7f734da4f02f04cc4f459" },
		{ "48", "37fe26ff1cf66175f5ddf4c33b97a205" }
	};

	std::vector<std::string> ciphertexts;
	uint8_t key[32];
	std::size_t key_sz = sizeof(key);
	uint8_t plain[16];
	std::size_t plain_sz = sizeof(plain);
	uint8_t cipher[16];
	std::size_t cipher_sz = sizeof(cipher);
	std::string ciphertext;

	memset(key,   0x00, key_sz);
	memset(plain, 0x00, plain_sz);

	for ( std::size_t i = 0 ; i < 50 ; ++i ) {
		Crypto::Twofish ctx(key, key_sz);
		ctx.encrypt(plain, cipher);

		// Shift key
		memcpy(key + 16, key,   key_sz - 16);
		memcpy(key,      plain, 16);

		// Shift plain
		memcpy(plain, cipher, plain_sz);

		// Push result
		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext, false);
		ciphertexts.push_back(ciphertext);
	}

	for ( auto test : tests ) {
		std::size_t idx = atoi(test[0].c_str());
		EXPECT_EQ(ciphertexts[idx], test[1]);
	}
}

TEST(Twofish256, decrypt_test)
{
	uint8_t key[32];
	std::size_t key_sz = sizeof(key);
	uint8_t plain[16];
	std::size_t plain_sz = sizeof(plain);
	uint8_t cipher[16];
	uint8_t decrypt[16];

	memset(key,   0x00, key_sz);
	memset(plain, 0x00, plain_sz);

	for ( std::size_t i = 0 ; i < 50 ; ++i ) {
		Crypto::Twofish ctx(key, key_sz);
		ctx.encrypt(plain, cipher);
		ctx.decrypt(cipher, decrypt);

		EXPECT_EQ(0, memcmp(plain, decrypt, plain_sz));

		// Shift key
		memcpy(key + 16, key,   key_sz - 16);
		memcpy(key,      plain, 16);

		// Shift plain
		memcpy(plain, cipher, plain_sz);
	}
}
