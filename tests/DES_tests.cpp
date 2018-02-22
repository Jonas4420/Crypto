#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/DES.hpp"
#include "crypto/CBC.hpp"

TEST(DES, encrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0000000000000000", "0000000000000000", "8ca64de9c1b123a7" },
		{ "ffffffffffffffff", "ffffffffffffffff", "7359b2163e4edc58" },
		{ "3000000000000000", "1000000000000001", "958e6e627a05557b" },
		{ "1111111111111111", "1111111111111111", "f40379ab9e0ec533" },
		{ "0123456789abcdef", "1111111111111111", "17668dfc7292532d" },
		{ "1111111111111111", "0123456789abcdef", "8a5ae1f81ab8f2dd" },
		{ "0000000000000000", "0000000000000000", "8ca64de9c1b123a7" },
		{ "fedcba9876543210", "0123456789abcdef", "ed39d950fa74bcc4" },
		{ "7ca110454a1a6e57", "01a1d6d039776742", "690f5b0d9a26939b" },
		{ "0131d9619dc1376e", "5cd54ca83def57da", "7a389d10354bd271" },
		{ "07a1133e4a0b2686", "0248d43806f67172", "868ebb51cab4599a" },
		{ "3849674c2602319e", "51454b582ddf440a", "7178876e01f19b2a" },
		{ "04b915ba43feb5b6", "42fd443059577fa2", "af37fb421f8c4095" },
		{ "0113b970fd34f2ce", "059b5e0851cf143a", "86a560f10ec6d85b" },
		{ "0170f175468fb5e6", "0756d8e0774761d2", "0cd3da020021dc09" },
		{ "43297fad38e373fe", "762514b829bf486a", "ea676b2cb7db2b7a" },
		{ "07a7137045da2a16", "3bdd119049372802", "dfd64a815caf1a0f" },
		{ "04689104c2fd3b2f", "26955f6835af609a", "5c513c9c4886c088" },
		{ "37d06bb516cb7546", "164d5e404f275232", "0a2aeeae3ff4ab77" },
		{ "1f08260d1ac2465e", "6b056e18759f5cca", "ef1bf03e5dfa575a" },
		{ "584023641aba6176", "004bd6ef09176062", "88bf0db6d70dee56" },
		{ "025816164629b007", "480d39006ee762f2", "a1f9915541020b56" },
		{ "49793ebc79b3258f", "437540c8698f3cfa", "6fbf1cafcffd0556" },
		{ "4fb05e1515ab73a7", "072d43a077075292", "2f22e49bab7ca1ac" },
		{ "49e95d6d4ca229bf", "02fe55778117f12a", "5a6b612cc26cce4a" },
		{ "018310dc409b26d6", "1d9d5c5018f728c2", "5f4c038ed12b2e41" },
		{ "1c587f1c13924fef", "305532286d6f295a", "63fac0d034d9f793" },
		{ "0101010101010101", "0123456789abcdef", "617b3a0ce8f07100" },
		{ "1f1f1f1f0e0e0e0e", "0123456789abcdef", "db958605f8c8c606" },
		{ "e0fee0fef1fef1fe", "0123456789abcdef", "edbfd1c66c29ccc7" },
		{ "0000000000000000", "ffffffffffffffff", "355550b2150e2451" },
		{ "ffffffffffffffff", "0000000000000000", "caaaaf4deaf1dbae" },
		{ "0123456789abcdef", "0000000000000000", "d5d44ff720683d0d" },
		{ "fedcba9876543210", "ffffffffffffffff", "2a2bb008df97c2f2" }
	};

	for ( auto test : tests ) {
		uint8_t key[8];
		std::size_t key_sz = sizeof(key);

		uint8_t plain[Crypto::DES::BLOCK_SIZE];
		std::size_t plain_sz = sizeof(plain);

		uint8_t cipher[Crypto::DES::BLOCK_SIZE];
		std::string ciphertext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], plain, plain_sz);

		Crypto::DES ctx(key, key_sz);
		ctx.encrypt(plain, cipher);
		Crypto::Utils::to_hex(cipher, sizeof(cipher), ciphertext, false);

		EXPECT_THAT(ciphertext, test[2]);
	}
}

TEST(DES, decrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0000000000000000", "8ca64de9c1b123a7", "0000000000000000" },
		{ "ffffffffffffffff", "7359b2163e4edc58", "ffffffffffffffff" },
		{ "3000000000000000", "958e6e627a05557b", "1000000000000001" },
		{ "1111111111111111", "f40379ab9e0ec533", "1111111111111111" },
		{ "0123456789abcdef", "17668dfc7292532d", "1111111111111111" },
		{ "1111111111111111", "8a5ae1f81ab8f2dd", "0123456789abcdef" },
		{ "0000000000000000", "8ca64de9c1b123a7", "0000000000000000" },
		{ "fedcba9876543210", "ed39d950fa74bcc4", "0123456789abcdef" },
		{ "7ca110454a1a6e57", "690f5b0d9a26939b", "01a1d6d039776742" },
		{ "0131d9619dc1376e", "7a389d10354bd271", "5cd54ca83def57da" },
		{ "07a1133e4a0b2686", "868ebb51cab4599a", "0248d43806f67172" },
		{ "3849674c2602319e", "7178876e01f19b2a", "51454b582ddf440a" },
		{ "04b915ba43feb5b6", "af37fb421f8c4095", "42fd443059577fa2" },
		{ "0113b970fd34f2ce", "86a560f10ec6d85b", "059b5e0851cf143a" },
		{ "0170f175468fb5e6", "0cd3da020021dc09", "0756d8e0774761d2" },
		{ "43297fad38e373fe", "ea676b2cb7db2b7a", "762514b829bf486a" },
		{ "07a7137045da2a16", "dfd64a815caf1a0f", "3bdd119049372802" },
		{ "04689104c2fd3b2f", "5c513c9c4886c088", "26955f6835af609a" },
		{ "37d06bb516cb7546", "0a2aeeae3ff4ab77", "164d5e404f275232" },
		{ "1f08260d1ac2465e", "ef1bf03e5dfa575a", "6b056e18759f5cca" },
		{ "584023641aba6176", "88bf0db6d70dee56", "004bd6ef09176062" },
		{ "025816164629b007", "a1f9915541020b56", "480d39006ee762f2" },
		{ "49793ebc79b3258f", "6fbf1cafcffd0556", "437540c8698f3cfa" },
		{ "4fb05e1515ab73a7", "2f22e49bab7ca1ac", "072d43a077075292" },
		{ "49e95d6d4ca229bf", "5a6b612cc26cce4a", "02fe55778117f12a" },
		{ "018310dc409b26d6", "5f4c038ed12b2e41", "1d9d5c5018f728c2" },
		{ "1c587f1c13924fef", "63fac0d034d9f793", "305532286d6f295a" },
		{ "0101010101010101", "617b3a0ce8f07100", "0123456789abcdef" },
		{ "1f1f1f1f0e0e0e0e", "db958605f8c8c606", "0123456789abcdef" },
		{ "e0fee0fef1fef1fe", "edbfd1c66c29ccc7", "0123456789abcdef" },
		{ "0000000000000000", "355550b2150e2451", "ffffffffffffffff" },
		{ "ffffffffffffffff", "caaaaf4deaf1dbae", "0000000000000000" },
		{ "0123456789abcdef", "d5d44ff720683d0d", "0000000000000000" },
		{ "fedcba9876543210", "2a2bb008df97c2f2", "ffffffffffffffff" }
	};

	for ( auto test : tests ) {
		uint8_t key[8];
		std::size_t key_sz = sizeof(key);

		uint8_t cipher[Crypto::DES::BLOCK_SIZE];
		std::size_t cipher_sz = sizeof(cipher);

		uint8_t plain[Crypto::DES::BLOCK_SIZE];
		std::string plaintext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], cipher, cipher_sz);

		Crypto::DES ctx(key, key_sz);
		ctx.decrypt(cipher, plain);
		Crypto::Utils::to_hex(plain, sizeof(plain), plaintext, false);

		EXPECT_THAT(plaintext, test[2]);
	}
}

TEST(DES, check_weak_keys)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0101010101010101", "true"  },
		{ "FEE0FEE0FEF1FEF1", "true"  },
		{ "0101010101010100", "false" },
		{ "EEE0FEE0FEF1FEF1", "false" }
	};

	for ( auto test : tests ) {
		uint8_t key[8];
		std::size_t key_sz = sizeof(key);
		bool expected = test[1] == "true";

		Crypto::Utils::from_hex(test[0], key, key_sz);
		bool is_weak = Crypto::DES::is_weak_key(key, key_sz);
		EXPECT_EQ(is_weak, expected);
	}
}

TEST(DES, check_parity)
{
	uint8_t key[8];
	uint8_t cnt, parity;

	memset(key, 0x00, 8);
	cnt = 0;

	// Iterate through all possible byte values
	for ( std::size_t i = 0 ; i < 32 ; ++i ) {
		for ( std::size_t j = 0 ; j < sizeof(key) ; ++j ) {
			key[j] = cnt++;
		}

		// Set the key parity according to the table
		Crypto::DES::set_parity_key(key, sizeof(key));

		// Check the parity with a function
		for ( std::size_t j = 0 ; j < sizeof(key) ; ++j ) {
			parity = key[j] ^ (key[j] >> 4);
			parity =   parity       ^ (parity >> 1)
				^ (parity >> 2) ^ (parity >> 3);
			parity &= 1;

			EXPECT_EQ(parity, 1);
		}

		// Check the parity with the table
		EXPECT_TRUE(Crypto::DES::check_parity_key(key, sizeof(key)));
	}
}

TEST(DES, cbc)
{
	// Encrypt CBC
	{
		int res;
		uint8_t key[8], iv[8];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);

		uint8_t plain[64], cipher[64];
		std::size_t plain_sz  = sizeof(cipher);
		std::size_t cipher_sz = sizeof(cipher);

		Crypto::Utils::from_hex("0123456789abcdef", key, key_sz);
		Crypto::Utils::from_hex("fedcba9876543210", iv,  iv_sz);
		Crypto::Utils::from_hex("37363534333231204e6f77206973207468652074696d6520", plain,  plain_sz);

		Crypto::CBC<Crypto::DES> ctx(key, key_sz, iv, true);

		res = ctx.update(plain, plain_sz, cipher, cipher_sz);
		EXPECT_EQ(res, 0);

		std::size_t pad_sz;
		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);

		std::string ciphertext;
		std::string expected = "ccd173ffab2039f4acd8aefddfd8a1eb468e91157888ba68";
		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext, false);
		EXPECT_THAT(ciphertext, expected);
	}

	// Decrypt CBC
	{
		int res;
		uint8_t key[8], iv[8];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);

		uint8_t plain[64], cipher[64];
		std::size_t plain_sz  = sizeof(cipher);
		std::size_t cipher_sz = sizeof(cipher);

		Crypto::Utils::from_hex("0123456789abcdef", key, key_sz);
		Crypto::Utils::from_hex("fedcba9876543210", iv,  iv_sz);
		Crypto::Utils::from_hex("ccd173ffab2039f4acd8aefddfd8a1eb468e91157888ba68", cipher,  cipher_sz);

		Crypto::CBC<Crypto::DES> ctx(key, key_sz, iv, false);

		res = ctx.update(cipher, cipher_sz, plain, plain_sz);
		EXPECT_EQ(res, 0);

		std::size_t pad_sz;
		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);

		std::string plaintext;
		std::string expected = "37363534333231204e6f77206973207468652074696d6520";
		Crypto::Utils::to_hex(plain, plain_sz, plaintext, false);
		EXPECT_THAT(plaintext, expected);
	}
}

TEST(TripleDES, des_ede2_encrypt)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0000000000000000ffffffffffffffff", "0000000000000000", "9295b59bb384736e" },
		{ "ffffffffffffffff3000000000000000", "ffffffffffffffff", "199e9d6df39aa816" }
	};

	for ( auto test : tests ) {
		uint8_t key[24];
		std::size_t key_sz = sizeof(key);

		uint8_t plain[Crypto::TripleDES::BLOCK_SIZE];
		std::size_t plain_sz = sizeof(plain);

		uint8_t cipher[Crypto::TripleDES::BLOCK_SIZE];
		std::string ciphertext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], plain, plain_sz);

		Crypto::TripleDES ctx(key, key_sz);
		ctx.encrypt(plain, cipher);
		Crypto::Utils::to_hex(cipher, sizeof(cipher), ciphertext, false);

		EXPECT_THAT(ciphertext, test[2]);
	}
}

TEST(TripleDES, des_ede2_decrypt)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "0000000000000000ffffffffffffffff","9295b59bb384736e", "0000000000000000" },
		{ "ffffffffffffffff3000000000000000", "199e9d6df39aa816", "ffffffffffffffff" }
	};

	for ( auto test : tests ) {
		uint8_t key[24];
		std::size_t key_sz = sizeof(key);

		uint8_t cipher[Crypto::TripleDES::BLOCK_SIZE];
		std::size_t cipher_sz = sizeof(cipher);

		uint8_t plain[Crypto::TripleDES::BLOCK_SIZE];
		std::string plaintext;

		Crypto::Utils::from_hex(test[0], key,    key_sz);
		Crypto::Utils::from_hex(test[1], cipher, cipher_sz);

		Crypto::TripleDES ctx(key, key_sz);
		ctx.decrypt(cipher, plain);
		Crypto::Utils::to_hex(plain, sizeof(plain), plaintext, false);

		EXPECT_THAT(plaintext, test[2]);
	}
}

TEST(TripleDES, des_ede3_cbc)
{
	// Encrypt DES-EDE3 CBC
	{
		int res;
		uint8_t key[24], iv[8];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);

		uint8_t plain[64], cipher[64];
		std::size_t plain_sz  = sizeof(cipher);
		std::size_t cipher_sz = sizeof(cipher);

		Crypto::Utils::from_hex("0123456789abcdeff1e0d3c2b5a49786fedcba9876543210", key, key_sz);
		Crypto::Utils::from_hex("fedcba9876543210",                                 iv,  iv_sz);
		Crypto::Utils::from_hex("37363534333231204e6f77206973207468652074696d6520", plain,  plain_sz);

		Crypto::CBC<Crypto::TripleDES> ctx(key, key_sz, iv, true);

		res = ctx.update(plain, plain_sz, cipher, cipher_sz);
		EXPECT_EQ(res, 0);

		std::size_t pad_sz;
		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);

		std::string ciphertext;
		std::string expected = "3fe301c962ac01d02213763c1cbd4cdc799657c064ecf5d4";
		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext, false);
		EXPECT_THAT(ciphertext, expected);
	}

	// Decrypt DES-EDE3 CBC
	{
		int res;
		uint8_t key[24], iv[8];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);

		uint8_t plain[64], cipher[64];
		std::size_t plain_sz  = sizeof(cipher);
		std::size_t cipher_sz = sizeof(cipher);

		Crypto::Utils::from_hex("0123456789abcdeff1e0d3c2b5a49786fedcba9876543210", key, key_sz);
		Crypto::Utils::from_hex("fedcba9876543210",                                 iv,  iv_sz);
		Crypto::Utils::from_hex("3fe301c962ac01d02213763c1cbd4cdc799657c064ecf5d4", cipher,  cipher_sz);

		Crypto::CBC<Crypto::TripleDES> ctx(key, key_sz, iv, false);

		res = ctx.update(cipher, cipher_sz, plain, plain_sz);
		EXPECT_EQ(res, 0);

		std::size_t pad_sz;
		res = ctx.finish(pad_sz);
		EXPECT_EQ(res, 0);

		std::string plaintext;
		std::string expected = "37363534333231204e6f77206973207468652074696d6520";
		Crypto::Utils::to_hex(plain, plain_sz, plaintext, false);
		EXPECT_THAT(plaintext, expected);
	}
}

TEST(TripleDES, check_weak_keys)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "00000000000000000000000000000000",                 "true"  },
		{ "00000000000000001111111111111111",                 "false" },
		{ "000000000000000000000000000000001111111111111111", "true"  },
		{ "000000000000000011111111111111110000000000000000", "true"  },
		{ "000000000000000011111111111111111111111111111111", "true"  },
		{ "000000000000000011111111111111112222222222222222", "false" }
	};

	for ( auto test : tests ) {
		uint8_t key[24];
		std::size_t key_sz = sizeof(key);
		bool expected = test[1] == "true";

		Crypto::Utils::from_hex(test[0], key, key_sz);
		bool is_weak = Crypto::TripleDES::is_weak_key(key, key_sz);
		EXPECT_EQ(is_weak, expected);
	}
}
