#include <memory>
#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/AES.hpp"
#include "crypto/DES.hpp"
#include "crypto/GCM.hpp"
#include "crypto/Utils.hpp"

#if defined(_MSC_VER) || defined(__WATCOMC__)
	#define UL64(x) x##ui64
#else
	#define UL64(x) x##ULL
#endif

TEST(GCM, constructor)
{
	// Normal case encrypt
	{
		uint8_t key[16], iv[16], add[16];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);
		std::size_t add_sz = sizeof(add);

		memset(key, 0x00, key_sz);
		memset(iv,  0x00, iv_sz);
		memset(add, 0x00, add_sz);

		Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);
	}

	// Normal case decrypt
	{
		uint8_t key[16], iv[16], add[16];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);
		std::size_t add_sz = sizeof(add);

		memset(key, 0x00, key_sz);
		memset(iv,  0x00, iv_sz);
		memset(add, 0x00, add_sz);

		Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, false);
	}
	
	// Normal case no additional data
	{
		uint8_t key[16], iv[16];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);

		memset(key, 0x00, key_sz);
		memset(iv,  0x00, iv_sz);

		Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, NULL, 0, true);
	}

	// Construction with a block size != 16
	{
		std::string exception, expected("Cipher block size not supported");
		uint8_t key[8], iv[16], add[16];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);
		std::size_t add_sz = sizeof(add);

		memset(key, 0x00, key_sz);
		memset(iv,  0x00, iv_sz);
		memset(add, 0x00, add_sz);

		try {
			Crypto::GCM<Crypto::DES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);
		} catch ( const Crypto::CipherMode::Exception &cme ) {
			exception = cme.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// IV size = 0
	{
		std::string exception, expected("IV length does not meet length requirements");
		uint8_t key[16], iv[16], add[16];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = 0;
		std::size_t add_sz = sizeof(add);

		memset(key, 0x00, key_sz);
		memset(iv,  0x00, iv_sz);
		memset(add, 0x00, add_sz);

		try {
			Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);
		} catch ( const Crypto::CipherMode::Exception &cme ) {
			exception = cme.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// IV size > 2^64
	if ( sizeof(std::size_t) > 8 ) {
		std::string exception, expected("IV length does not meet length requirements");
		uint8_t key[16], iv[16], add[16];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = -1;
		std::size_t add_sz = sizeof(add);

		memset(key, 0x00, key_sz);
		memset(add, 0x00, add_sz);

		try {
			Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);
		} catch ( const Crypto::CipherMode::Exception &cme ) {
			exception = cme.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Add size > 2^64
	if ( sizeof(std::size_t) > 8 ) {
		std::string exception, expected("Additional Input length does not meet length requirements");
		uint8_t key[16], iv[16], add[16];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);
		std::size_t add_sz = -1;

		memset(key, 0x00, key_sz);
		memset(iv,  0x00, iv_sz);

		try {
			Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);
		} catch ( const Crypto::CipherMode::Exception &cme ) {
			exception = cme.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(GCM, update_sz)
{
	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		int ret;
		uint8_t key[16], iv[16], add[16], plain[32], cipher[32];
		std::size_t key_sz    = sizeof(key);
		std::size_t iv_sz     = sizeof(iv);
		std::size_t add_sz    = sizeof(add);
		std::size_t plain_sz  = sizeof(plain);
		std::size_t cipher_sz = sizeof(cipher);

		memset(key,    0x00, key_sz);
		memset(iv,     0x00, iv_sz);
		memset(add,    0x00, add_sz);
		memset(plain,  0x00, plain_sz);
		memset(cipher, 0x00, cipher_sz);

		Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)8);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		int ret;
		uint8_t key[16], iv[16], add[16], plain[32], cipher[32];
		std::size_t key_sz    = sizeof(key);
		std::size_t iv_sz     = sizeof(iv);
		std::size_t add_sz    = sizeof(add);
		std::size_t plain_sz  = sizeof(plain);
		std::size_t cipher_sz = sizeof(cipher);

		memset(key,    0x00, key_sz);
		memset(iv,     0x00, iv_sz);
		memset(add,    0x00, add_sz);
		memset(plain,  0x00, plain_sz);
		memset(cipher, 0x00, cipher_sz);

		Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);

		cipher_sz = 8;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)8);
	}

	// Total input size overflows
	{
		int ret;
		uint8_t key[16], iv[16], add[16], plain[32], cipher[32];
		std::size_t key_sz    = sizeof(key);
		std::size_t iv_sz     = sizeof(iv);
		std::size_t add_sz    = sizeof(add);
		std::size_t plain_sz  = sizeof(plain);
		std::size_t cipher_sz = sizeof(cipher);

		memset(key,    0x00, key_sz);
		memset(iv,     0x00, iv_sz);
		memset(add,    0x00, add_sz);
		memset(plain,  0x00, plain_sz);
		memset(cipher, 0x00, cipher_sz);

		Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);

		plain_sz = cipher_sz = 1;
		ret = ctx.update(plain, plain_sz, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);

		plain_sz = cipher_sz = -1;
		ret = ctx.update(plain, plain_sz, cipher, cipher_sz);
		EXPECT_EQ(ret, 3);
	}

	// Total input size is bigger than what GCM can produce
	{
		int ret;
		uint8_t key[16], iv[16], add[16], plain[32], cipher[32];
		std::size_t key_sz    = sizeof(key);
		std::size_t iv_sz     = sizeof(iv);
		std::size_t add_sz    = sizeof(add);
		std::size_t plain_sz  = sizeof(plain);
		std::size_t cipher_sz = sizeof(cipher);

		memset(key,    0x00, key_sz);
		memset(iv,     0x00, iv_sz);
		memset(add,    0x00, add_sz);
		memset(plain,  0x00, plain_sz);
		memset(cipher, 0x00, cipher_sz);

		Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);

		plain_sz = cipher_sz = 1;
		ret = ctx.update(plain, plain_sz, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);

		plain_sz = cipher_sz = UL64(0x0000000FFFFFFFE0);
		ret = ctx.update(plain, plain_sz, cipher, cipher_sz);
		EXPECT_EQ(ret, 3);
	}
}

TEST(GCM, finish_sz)
{
	int ret;
	uint8_t key[16], iv[16], add[16], plain[32], cipher[32];
	std::size_t key_sz    = sizeof(key);
	std::size_t iv_sz     = sizeof(iv);
	std::size_t add_sz    = sizeof(add);
	std::size_t plain_sz  = sizeof(plain);
	std::size_t cipher_sz = sizeof(cipher);

	memset(key,    0x00, key_sz);
	memset(iv,     0x00, iv_sz);
	memset(add,    0x00, add_sz);
	memset(plain,  0x00, plain_sz);
	memset(cipher, 0x00, cipher_sz);

	// Buffer empty, not finished
	{
		Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);

		cipher_sz = 16;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);
	}
}

TEST(GCM, get_tag)
{
	// Normal case
	{
		int ret;
		uint8_t key[16], iv[16], add[16], tag[16];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);
		std::size_t add_sz = sizeof(add);
		std::size_t tag_sz = sizeof(tag);
		std::size_t pad_sz = 0;

		memset(key, 0x00, key_sz);
		memset(iv,  0x00, iv_sz);
		memset(add, 0x00, add_sz);
		memset(tag, 0x00, tag_sz);

		Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);

		ret = ctx.finish(pad_sz);
		EXPECT_EQ(ret, 0);

		ret = ctx.get_tag(tag, tag_sz);
		EXPECT_EQ(ret, 0);
	}

	// Requested tag is too small
	{
		int ret;
		uint8_t key[16], iv[16], add[16], tag[3];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);
		std::size_t add_sz = sizeof(add);
		std::size_t tag_sz = sizeof(tag);
		std::size_t pad_sz = 0;

		memset(key, 0x00, key_sz);
		memset(iv,  0x00, iv_sz);
		memset(add, 0x00, add_sz);
		memset(tag, 0x00, tag_sz);

		Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);

		ret = ctx.finish(pad_sz);
		EXPECT_EQ(ret, 0);

		ret = ctx.get_tag(tag, tag_sz);
		EXPECT_EQ(ret, 1);
	}

	// Requested tag is too big
	{
		int ret;
		uint8_t key[16], iv[16], add[16], tag[17];
		std::size_t key_sz = sizeof(key);
		std::size_t iv_sz  = sizeof(iv);
		std::size_t add_sz = sizeof(add);
		std::size_t tag_sz = sizeof(tag);
		std::size_t pad_sz = 0;

		memset(key, 0x00, key_sz);
		memset(iv,  0x00, iv_sz);
		memset(add, 0x00, add_sz);
		memset(tag, 0x00, tag_sz);

		Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv, iv_sz, add, add_sz, true);

		ret = ctx.finish(pad_sz);
		EXPECT_EQ(ret, 0);

		ret = ctx.get_tag(tag, tag_sz);
		EXPECT_EQ(ret, 1);
	}
}

TEST(GCM, KAT_enc)
{
	std::vector<std::string> files = {
		"gcmEncryptExtIV128.rsp", "gcmEncryptExtIV192.rsp", "gcmEncryptExtIV256.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "GCM/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				std::size_t key_sz    = test["Key"].length() / 2;
				std::size_t iv_sz     = test["IV"].length() / 2;
				std::size_t add_sz    = test["AAD"].length() / 2;
				std::size_t plain_sz  = test["PT"].length() / 2;
				std::size_t cipher_sz = test["CT"].length() / 2;
				std::size_t tag_sz    = test["Tag"].length() / 2;
				std::unique_ptr<uint8_t[]> iv(new uint8_t[iv_sz]);
				std::unique_ptr<uint8_t[]> add(new uint8_t[add_sz]);
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::unique_ptr<uint8_t[]> tag(new uint8_t[tag_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string cipher_str, tag_str;

				res = Crypto::Utils::from_hex(test["Key"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["IV"], iv.get(), iv_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["AAD"], add.get(), add_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["PT"], plain.get(), plain_sz);
				EXPECT_EQ(res, 0);

				Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv.get(), iv_sz, add.get(), add_sz, true);

				total_sz = cipher_sz;
				cipher_sz = 0;
				for ( std::size_t i = 0 ; i < plain_sz ; ++i ) {
					current_sz = total_sz - cipher_sz;

					res = ctx.update(plain.get() + i, 1, cipher.get() + cipher_sz, current_sz);
					EXPECT_EQ(res, 0);

					cipher_sz += current_sz;
					EXPECT_EQ(res, 0);
				}

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, 0);

				res = ctx.get_tag(tag.get(), tag_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::to_hex(cipher.get(), cipher_sz, cipher_str, false);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(cipher_str, test["CT"]);

				if ( test["Tag"].length() > 0 ) {
					res = Crypto::Utils::to_hex(tag.get(), tag_sz, tag_str, false);
					EXPECT_EQ(res, 0);

					EXPECT_EQ(tag_str, test["Tag"]);
				}
			}
		}
	}
}

TEST(GCM, KAT_dec)
{
	std::vector<std::string> files = {
		"gcmDecrypt128.rsp", "gcmDecrypt192.rsp", "gcmDecrypt256.rsp"
	};

	for ( auto file : files ) {
		std::string file_path = TestOptions::get().vect_dir + "GCM/" + file;

		auto test_vectors = TestVectors::NISTParser(file_path);
		EXPECT_FALSE(test_vectors.empty());

		for ( auto tests : test_vectors ) {
			for ( auto test : tests ) {
				int res;
				uint8_t key[32];
				std::size_t key_sz    = test["Key"].length() / 2;
				std::size_t iv_sz     = test["IV"].length() / 2;
				std::size_t add_sz    = test["AAD"].length() / 2;
				std::size_t cipher_sz = test["CT"].length() / 2;
				std::size_t plain_sz  = test["CT"].length() / 2;
				std::size_t tag_sz    = test["Tag"].length() / 2;
				std::unique_ptr<uint8_t[]> iv(new uint8_t[iv_sz]);
				std::unique_ptr<uint8_t[]> add(new uint8_t[add_sz]);
				std::unique_ptr<uint8_t[]> cipher(new uint8_t[cipher_sz]);
				std::unique_ptr<uint8_t[]> plain(new uint8_t[plain_sz]);
				std::unique_ptr<uint8_t[]> tag(new uint8_t[tag_sz]);
				std::size_t total_sz, current_sz, pad_sz = 0;
				std::string plain_str, tag_str;
				bool is_auth = false;

				res = Crypto::Utils::from_hex(test["Key"], key, key_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["IV"], iv.get(), iv_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["AAD"], add.get(), add_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["CT"], cipher.get(), cipher_sz);
				EXPECT_EQ(res, 0);

				res = Crypto::Utils::from_hex(test["Tag"], tag.get(), tag_sz);
				EXPECT_EQ(res, 0);

				Crypto::GCM<Crypto::AES> ctx(key, key_sz, iv.get(), iv_sz, add.get(), add_sz, false);

				total_sz = plain_sz;
				plain_sz = 0;
				for ( std::size_t i = 0 ; i < cipher_sz ; ++i ) {
					current_sz = total_sz - plain_sz;

					res = ctx.update(cipher.get() + i, 1, plain.get() + plain_sz, current_sz);
					EXPECT_EQ(res, 0);

					plain_sz += current_sz;
					EXPECT_EQ(res, 0);
				}

				res = ctx.finish(pad_sz);
				EXPECT_EQ(res, 0);
				EXPECT_EQ(pad_sz, 0);

				res = ctx.check_tag(tag.get(), tag_sz, is_auth);
				EXPECT_EQ(res, 0);

				EXPECT_EQ(is_auth, ! test.has("FAIL"));

				if ( ! test.has("FAIL") ) {
					res = Crypto::Utils::to_hex(plain.get(), plain_sz, plain_str, false);
					EXPECT_EQ(res, 0);

					EXPECT_EQ(plain_str, test["PT"]);
				}
			}
		}
	}
}
