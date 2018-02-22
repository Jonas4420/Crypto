#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/AES.hpp"

TEST(AES, constructor)
{
	// Case 1: key_sz = 128 bits
	{
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::AES ctx(key, key_sz);
	}

	// Case 2: key_sz = 192 bits
	{
		uint8_t key[24];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::AES ctx(key, key_sz);
	}

	// Case 3: key_sz = 256 bits
	{
		uint8_t key[32];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::AES ctx(key, key_sz);
	}

	// Case 4: key_sz = 512 bits
	{
		std::string exception, expected("Key size is not supported");
		uint8_t key[64];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		try {
			Crypto::AES ctx(key, key_sz);
		} catch ( const Crypto::AES::Exception &ae ) {
			exception = ae.what();
		}

		EXPECT_EQ(exception, expected);
	}

}

TEST(AES128, encrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"00000000000000000000000000000000",
			"f34481ec3cc627bacd5dc3fb08f273e6",
			"0336763e966d92595a567cc9ce537f5e"
		}, {
			"00000000000000000000000000000000",
			"9798c4640bad75c7c3227db910174e72",
			"a9a1631bf4996954ebc093957b234589"
		}, {
			"00000000000000000000000000000000",
			"96ab5c2ff612d9dfaae8c31f30c42168",
			"ff4f8391a6a40ca5b25d23bedd44a597"
		}, {
			"e0000000000000000000000000000000",
			"00000000000000000000000000000000",
			"72a1da770f5d7ac4c9ef94d822affd97"
		}, {
			"f0000000000000000000000000000000",
			"00000000000000000000000000000000",
			"970014d634e2b7650777e8e84d03ccd8"
		}, {
			"f8000000000000000000000000000000",
			"00000000000000000000000000000000",
			"f17e79aed0db7e279e955b5f493875a7"
		}, {
			"fffffffffffff0000000000000000000",
			"00000000000000000000000000000000",
			"7b90785125505fad59b13c186dd66ce3"
		}, {
			"fffffffffffff8000000000000000000",
			"00000000000000000000000000000000",
			"8b527a6aebdaec9eaef8eda2cb7783e5"
		}, {
			"fffffffffffffc000000000000000000",
			"00000000000000000000000000000000",
			"43fdaf53ebbc9880c228617d6a9b548b"
		}, {
			"ffffffffffffffffffffffffffffc000",
			"00000000000000000000000000000000",
			"70c46bb30692be657f7eaa93ebad9897"
		}, {
			"ffffffffffffffffffffffffffffe000",
			"00000000000000000000000000000000",
			"323994cfb9da285a5d9642e1759b224a"
		}, {
			"fffffffffffffffffffffffffffff000",
			"00000000000000000000000000000000",
			"1dbf57877b7b17385c85d0b54851e371"
		}, {
			"00000000000000000000000000000000",
			"ffffffffffffffc00000000000000000",
			"3a4d354f02bb5a5e47d39666867f246a"
		}, {
			"00000000000000000000000000000000",
			"ffffffffffffffe00000000000000000",
			"d451b8d6e1e1a0ebb155fbbf6e7b7dc3"
		}, {
			"00000000000000000000000000000000",
			"fffffffffffffff00000000000000000",
			"6898d4f42fa7ba6a10ac05e87b9f2080"
		}, {
			"00000000000000000000000000000000",
			"ffffffffffffffffffffffffe0000000",
			"082eb8be35f442fb52668e16a591d1d6"
		}, {
			"00000000000000000000000000000000",
			"fffffffffffffffffffffffff0000000",
			"e656f9ecf5fe27ec3e4a73d00c282fb3"
		}, {
			"00000000000000000000000000000000",
			"fffffffffffffffffffffffff8000000",
			"2ca8209d63274cd9a29bb74bcd77683a"
	       	}
	};

	for ( auto test : tests ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t plain[Crypto::AES::BLOCK_SIZE];
		std::size_t plain_sz = sizeof(plain);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE];
		std::string ciphertext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], plain, plain_sz);

		Crypto::AES ctx(key, key_sz);
		ctx.encrypt(plain, cipher);
		Crypto::Utils::to_hex(cipher, sizeof(cipher), ciphertext, false);

		EXPECT_THAT(ciphertext, test[2]);
	}
}

TEST(AES128, decrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"00000000000000000000000000000000",
			"db4f1aa530967d6732ce4715eb0ee24b",
			"ff000000000000000000000000000000"
		}, {
			"00000000000000000000000000000000",
			"a81738252621dd180a34f3455b4baa2f",
			"ff800000000000000000000000000000"
		}, {
			"00000000000000000000000000000000",
			"77e2b508db7fd89234caf7939ee5621a",
			"ffc00000000000000000000000000000"
		}, {
			"00000000000000000000000000000000",
			"dc43be40be0e53712f7e2bf5ca707209",
			"6a118a874519e64e9963798a503f1d35"
		}, {
			"00000000000000000000000000000000",
			"92beedab1895a94faa69b632e5cc47ce",
			"cb9fceec81286ca3e989bd979b0cb284"
		}, {
			"00000000000000000000000000000000",
			"459264f4798f6a78bacb89c15ed3d601",
			"b26aeb1874e47ca8358ff22378f09144"
		}, {
			"b69418a85332240dc82492353956ae0c",
			"a303d940ded8f0baff6f75414cac5243",
			"00000000000000000000000000000000"
		}, {
			"71b5c08a1993e1362e4d0ce9b22b78d5",
			"c2dabd117f8a3ecabfbb11d12194d9d0",
			"00000000000000000000000000000000"
		}, {
			"e234cdca2606b81f29408d5f6da21206",
			"fff60a4740086b3b9c56195b98d91a7b",
			"00000000000000000000000000000000"
		}, {
			"ffffffffffffffff0000000000000000",
			"84be19e053635f09f2665e7bae85b42d",
			"00000000000000000000000000000000"
		}, {
			"ffffffffffffffff8000000000000000",
			"32cd652842926aea4aa6137bb2be2b5e",
			"00000000000000000000000000000000"
		} 
	};

	for ( auto test : tests ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE];
		std::size_t cipher_sz = sizeof(cipher);

		uint8_t plain[Crypto::AES::BLOCK_SIZE];
		std::string plaintext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], cipher, cipher_sz);

		Crypto::AES ctx(key, key_sz);
		ctx.decrypt(cipher, plain);
		Crypto::Utils::to_hex(plain, sizeof(plain), plaintext, false);

		EXPECT_THAT(plaintext, test[2]);
	}
}

TEST(AES192, encrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"000000000000000000000000000000000000000000000000",
			"fffffffffffffffffffff80000000000",
			"156f07767a85a4312321f63968338a01"
		}, {
			"000000000000000000000000000000000000000000000000",
			"fffffffffffffffffffffc0000000000",
			"15eec9ebf42b9ca76897d2cd6c5a12e2"
		}, {
			"000000000000000000000000000000000000000000000000",
			"fffffffffffffffffffffe0000000000",
			"db0d3a6fdcc13f915e2b302ceeb70fd8"
		}, {
			"000000000000000000000000000000000000000000000000",
			"51719783d3185a535bd75adc65071ce1",
			"4f354592ff7c8847d2d0870ca9481b7c"
		}, {
			"000000000000000000000000000000000000000000000000",
			"26aa49dcfe7629a8901a69a9914e6dfd",
			"d5e08bf9a182e857cf40b3a36ee248cc"
		}, {
			"000000000000000000000000000000000000000000000000",
			"941a4773058224e1ef66d10e0a6ee782",
			"067cd9d3749207791841562507fa9626"
		}, {
			"d2926527e0aa9f37b45e2ec2ade5853ef807576104c7ace3",
			"00000000000000000000000000000000",
			"dd619e1cf204446112e0af2b9afa8f8c"
		}, {
			"982215f4e173dfa0fcffe5d3da41c4812c7bcc8ed3540f93",
			"00000000000000000000000000000000",
			"d4f0aae13c8fe9339fbf9e69ed0ad74d"
		}, {
			"98c6b8e01e379fbd14e61af6af891596583565f2a27d59e9",
			"00000000000000000000000000000000",
			"19c80ec4a6deb7e5ed1033dda933498f"
		}, {
			"fffffffffffffffffffffffffff800000000000000000000",
			"00000000000000000000000000000000",
			"8dd274bd0f1b58ae345d9e7233f9b8f3"
		}, {
			"fffffffffffffffffffffffffffc00000000000000000000",
			"00000000000000000000000000000000",
			"9d6bdc8f4ce5feb0f3bed2e4b9a9bb0b"
		}, {
			"fffffffffffffffffffffffffffe00000000000000000000",
			"00000000000000000000000000000000",
			"fd5548bcf3f42565f7efa94562528d46"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[24];
		std::size_t key_sz = sizeof(key);

		uint8_t plain[Crypto::AES::BLOCK_SIZE];
		std::size_t plain_sz = sizeof(plain);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE];
		std::string ciphertext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], plain, plain_sz);

		Crypto::AES ctx(key, key_sz);
		ctx.encrypt(plain, cipher);
		Crypto::Utils::to_hex(cipher, sizeof(cipher), ciphertext, false);

		EXPECT_THAT(ciphertext, test[2]);
	}
}

TEST(AES192, decrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"fffffffffffffffffffffffffffffffff000000000000000",
			"bb2852c891c5947d2ed44032c421b85f",
			"00000000000000000000000000000000"
		}, {
			"fffffffffffffffffffffffffffffffff800000000000000",
			"1b9f5fbd5e8a4264c0a85b80409afa5e",
			"00000000000000000000000000000000"
		}, {
			"fffffffffffffffffffffffffffffffffc00000000000000",
			"30dab809f85a917fe924733f424ac589",
			"00000000000000000000000000000000"
		}, {
			"61257134a518a0d57d9d244d45f6498cbc32f2bafc522d79",
			"cfe4d74002696ccf7d87b14a2f9cafc9",
			"00000000000000000000000000000000"
		}, {
			"b0ab0a6a818baef2d11fa33eac947284fb7d748cfb75e570",
			"d2eafd86f63b109b91f5dbb3a3fb7e13",
			"00000000000000000000000000000000"
		}, {
			"ee053aa011c8b428cdcc3636313c54d6a03cac01c71579d6",
			"9b9fdd1c5975655f539998b306a324af",
			"00000000000000000000000000000000"
		}, {
			"000000000000000000000000000000000000000000000000",
			"275cfc0413d8ccb70513c3859b1d0f72",
			"1b077a6af4b7f98229de786d7516b639"
		}, {
			"000000000000000000000000000000000000000000000000",
			"c9b8135ff1b5adc413dfd053b21bd96d",
			"9c2d8842e5f48f57648205d39a239af1"
		}, {
			"000000000000000000000000000000000000000000000000",
			"4a3650c3371ce2eb35e389a171427440",
			"bff52510095f518ecca60af4205444bb"
		}, {
			"000000000000000000000000000000000000000000000000",
			"b2099795e88cc158fd75ea133d7e7fbe",
			"ffffffffffffffffffffc00000000000"
		}, {
			"000000000000000000000000000000000000000000000000",
			"a6cae46fb6fadfe7a2c302a34242817b",
			"ffffffffffffffffffffe00000000000"
		}, {
			"000000000000000000000000000000000000000000000000",
			"026a7024d6a902e0b3ffccbaa910cc3f",
			"fffffffffffffffffffff00000000000"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[24];
		std::size_t key_sz = sizeof(key);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE];
		std::size_t cipher_sz = sizeof(cipher);

		uint8_t plain[Crypto::AES::BLOCK_SIZE];
		std::string plaintext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], cipher, cipher_sz);

		Crypto::AES ctx(key, key_sz);
		ctx.decrypt(cipher, plain);
		Crypto::Utils::to_hex(plain, sizeof(plain), plaintext, false);

		EXPECT_THAT(plaintext, test[2]);
	}
}

TEST(AES256, encrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c",
			"00000000000000000000000000000000",
			"352065272169abf9856843927d0674fd"
		}, {
			"984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627",
			"00000000000000000000000000000000",
			"4307456a9e67813b452e15fa8fffe398"
		}, {
			"b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f",
			"00000000000000000000000000000000",
			"4663446607354989477a5c6f0f007ef4"
		}, {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0b24af36193ce4665f2825d7b4749c98",
			"a9ff75bd7cf6613d3731c77c3b6d0c04"
		}, {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"761c1fe41a18acf20d241650611d90f1",
			"623a52fcea5d443e48d9181ab32c7421"
		}, {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"8a560769d605868ad80d819bdba03771",
			"38f2c7ae10612415d27ca190d27da8b4"
		}, {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"ffffffc0000000000000000000000000",
			"1f8eedea0f62a1406d58cfc3ecea72cf"
		}, {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"ffffffe0000000000000000000000000",
			"abf4154a3375a1d3e6b1d454438f95a6"
		}, {
			"ffffffffffffffffffffffffffffffffffff8000000000000000000000000000",
			"00000000000000000000000000000000",
			"45d089c36d5c5a4efc689e3b0de10dd5"
		}, {
			"ffffffffffffffffffffffffffffffffffffc000000000000000000000000000",
			"00000000000000000000000000000000",
			"b4da5df4becb5462e03a0ed00d295629"
		}, {
			"ffffffffffffffffffffffffffffffffffffe000000000000000000000000000",
			"00000000000000000000000000000000",
			"dcf4e129136c1a4b7a0f38935cc34b2b"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[32];
		std::size_t key_sz = sizeof(key);

		uint8_t plain[Crypto::AES::BLOCK_SIZE];
		std::size_t plain_sz = sizeof(plain);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE];
		std::string ciphertext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], plain, plain_sz);

		Crypto::AES ctx(key, key_sz);
		ctx.encrypt(plain, cipher);
		Crypto::Utils::to_hex(cipher, sizeof(cipher), ciphertext, false);

		EXPECT_THAT(ciphertext, test[2]);
	}
}

TEST(AES256, decrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"fffffffffffffffffffffffffffffffffffffffffffffff00000000000000000",
			"edf61ae362e882ddc0167474a7a77f3a",
			"00000000000000000000000000000000"
		}, {
			"fffffffffffffffffffffffffffffffffffffffffffffff80000000000000000",
			"6168b00ba7859e0970ecfd757efecf7c",
			"00000000000000000000000000000000"
		}, {
			"fffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000",
			"d1415447866230d28bb1ea18a4cdfd02",
			"00000000000000000000000000000000"
		}, {
			"f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9",
			"a3944b95ca0b52043584ef02151926a8",
			"00000000000000000000000000000000"
		}, {
			"797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e",
			"a74289fe73a4c123ca189ea1e1b49ad5",
			"00000000000000000000000000000000"
		}, {
			"6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707",
			"b91d4ea4488644b56cf0812fa7fcf5fc",
			"00000000000000000000000000000000"
		}, {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"623a52fcea5d443e48d9181ab32c7421",
			"761c1fe41a18acf20d241650611d90f1"
		}, {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"38f2c7ae10612415d27ca190d27da8b4",
			"8a560769d605868ad80d819bdba03771"
		}, {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"1bc704f1bce135ceb810341b216d7abe",
			"91fbef2d15a97816060bee1feaa49afe"
		}, {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"ddc6bf790c15760d8d9aeb6f9a75fd4e",
			"80000000000000000000000000000000"
		}, {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"0a6bdc6d4c1e6280301fd8e97ddbe601",
			"c0000000000000000000000000000000"
		}, {
			"0000000000000000000000000000000000000000000000000000000000000000",
			"9b80eefb7ebe2d2b16247aa0efc72f5d",
			"e0000000000000000000000000000000"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[32];
		std::size_t key_sz = sizeof(key);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE];
		std::size_t cipher_sz = sizeof(cipher);

		uint8_t plain[Crypto::AES::BLOCK_SIZE];
		std::string plaintext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], cipher, cipher_sz);

		Crypto::AES ctx(key, key_sz);
		ctx.decrypt(cipher, plain);
		Crypto::Utils::to_hex(plain, sizeof(plain), plaintext, false);

		EXPECT_THAT(plaintext, test[2]);
	}
}
