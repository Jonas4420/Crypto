#include <vector>

#include "TestOptions.hpp"
#include "TestVectors.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/HMAC.hpp"
#include "crypto/Utils.hpp"

#include "crypto/SHA1.hpp"
#include "crypto/SHA224.hpp"
#include "crypto/SHA256.hpp"
#include "crypto/SHA384.hpp"
#include "crypto/SHA512.hpp"

TEST(HMAC, update_ctx)
{
	std::string file = "HMAC.rsp";
	std::string file_path = TestOptions::get().vect_dir + "HMAC/" + file;

	auto test_vectors = TestVectors::NISTParser(file_path)["L=32"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		for ( auto test : tests ) {
			int res;
			std::size_t key_sz = atoi(test["Klen"].c_str());
			std::size_t msg_sz = test["Msg"].length() / 2;
			std::unique_ptr<uint8_t> key(new uint8_t[key_sz]);
			std::unique_ptr<uint8_t> msg(new uint8_t[msg_sz]);
			uint8_t mac[Crypto::SHA256::SIZE];
			std::string mac_str;

			res = Crypto::Utils::from_hex(test["Key"], key.get(), key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
			EXPECT_EQ(res, 0);

			Crypto::HMAC<Crypto::SHA256> ctx(key.get(), key_sz);

			for ( std::size_t i = 0 ; i < msg_sz ; ++i ) {
				ctx.update(msg.get() + i, 1);
			}

			ctx.finish(mac);

			res = Crypto::Utils::to_hex(mac, atoi(test["Tlen"].c_str()), mac_str, false);
			EXPECT_EQ(res, 0);

			EXPECT_EQ(mac_str, test["Mac"]);
		}
	}
}

TEST(HMAC, reset_ctx)
{
	std::string file = "HMAC.rsp";
	std::string file_path = TestOptions::get().vect_dir + "HMAC/" + file;

	auto test_vectors = TestVectors::NISTParser(file_path)["L=32"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		for ( auto test : tests ) {
			int res;
			std::size_t key_sz = atoi(test["Klen"].c_str());
			std::size_t msg_sz = test["Msg"].length() / 2;
			std::unique_ptr<uint8_t> key(new uint8_t[key_sz]);
			std::unique_ptr<uint8_t> msg(new uint8_t[msg_sz]);
			uint8_t mac_1[Crypto::SHA256::SIZE];
			uint8_t mac_2[Crypto::SHA256::SIZE];
			std::string mac_1_str, mac_2_str;

			res = Crypto::Utils::from_hex(test["Key"], key.get(), key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
			EXPECT_EQ(res, 0);

			Crypto::HMAC<Crypto::SHA256> ctx(key.get(), key_sz);

			ctx.update(msg.get(), msg_sz);
			ctx.reset();
			ctx.update(msg.get(), msg_sz);
			ctx.finish(mac_1);

			res = Crypto::Utils::to_hex(mac_1, atoi(test["Tlen"].c_str()), mac_1_str, false);
			EXPECT_EQ(res, 0);

			ctx.update(msg.get(), msg_sz);
			ctx.finish(mac_2);

			res = Crypto::Utils::to_hex(mac_2, atoi(test["Tlen"].c_str()), mac_2_str, false);
			EXPECT_EQ(res, 0);

			EXPECT_EQ(mac_1_str, test["Mac"]);
			EXPECT_EQ(mac_2_str, test["Mac"]);
		}
	}
}

TEST(HMAC_SHA1, KAT)
{
	std::string file = "HMAC.rsp";
	std::string file_path = TestOptions::get().vect_dir + "HMAC/" + file;

	auto test_vectors = TestVectors::NISTParser(file_path)["L=20"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		for ( auto test : tests ) {
			int res;
			std::size_t key_sz = atoi(test["Klen"].c_str());
			std::size_t msg_sz = test["Msg"].length() / 2;
			std::unique_ptr<uint8_t> key(new uint8_t[key_sz]);
			std::unique_ptr<uint8_t> msg(new uint8_t[msg_sz]);
			uint8_t mac[Crypto::SHA1::SIZE];
			std::string mac_str;

			res = Crypto::Utils::from_hex(test["Key"], key.get(), key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
			EXPECT_EQ(res, 0);

			Crypto::HMAC_get<Crypto::SHA1>(key.get(), key_sz, msg.get(), msg_sz, mac);

			res = Crypto::Utils::to_hex(mac, atoi(test["Tlen"].c_str()), mac_str, false);
			EXPECT_EQ(res, 0);

			EXPECT_EQ(mac_str, test["Mac"]);
		}
	}
}

TEST(HMAC_SHA224, KAT)
{
	std::string file = "HMAC.rsp";
	std::string file_path = TestOptions::get().vect_dir + "HMAC/" + file;

	auto test_vectors = TestVectors::NISTParser(file_path)["L=28"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		for ( auto test : tests ) {
			int res;
			std::size_t key_sz = atoi(test["Klen"].c_str());
			std::size_t msg_sz = test["Msg"].length() / 2;
			std::unique_ptr<uint8_t> key(new uint8_t[key_sz]);
			std::unique_ptr<uint8_t> msg(new uint8_t[msg_sz]);
			uint8_t mac[Crypto::SHA224::SIZE];
			std::string mac_str;

			res = Crypto::Utils::from_hex(test["Key"], key.get(), key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
			EXPECT_EQ(res, 0);

			Crypto::HMAC_get<Crypto::SHA224>(key.get(), key_sz, msg.get(), msg_sz, mac);

			res = Crypto::Utils::to_hex(mac, atoi(test["Tlen"].c_str()), mac_str, false);
			EXPECT_EQ(res, 0);

			EXPECT_EQ(mac_str, test["Mac"]);
		}
	}
}

TEST(HMAC_SHA256, KAT)
{
	std::string file = "HMAC.rsp";
	std::string file_path = TestOptions::get().vect_dir + "HMAC/" + file;

	auto test_vectors = TestVectors::NISTParser(file_path)["L=32"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		for ( auto test : tests ) {
			int res;
			std::size_t key_sz = atoi(test["Klen"].c_str());
			std::size_t msg_sz = test["Msg"].length() / 2;
			std::unique_ptr<uint8_t> key(new uint8_t[key_sz]);
			std::unique_ptr<uint8_t> msg(new uint8_t[msg_sz]);
			uint8_t mac[Crypto::SHA256::SIZE];
			std::string mac_str;

			res = Crypto::Utils::from_hex(test["Key"], key.get(), key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
			EXPECT_EQ(res, 0);

			Crypto::HMAC_get<Crypto::SHA256>(key.get(), key_sz, msg.get(), msg_sz, mac);

			res = Crypto::Utils::to_hex(mac, atoi(test["Tlen"].c_str()), mac_str, false);
			EXPECT_EQ(res, 0);

			EXPECT_EQ(mac_str, test["Mac"]);
		}
	}
}

TEST(HMAC_SHA384, KAT)
{
	std::string file = "HMAC.rsp";
	std::string file_path = TestOptions::get().vect_dir + "HMAC/" + file;

	auto test_vectors = TestVectors::NISTParser(file_path)["L=48"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		for ( auto test : tests ) {
			int res;
			std::size_t key_sz = atoi(test["Klen"].c_str());
			std::size_t msg_sz = test["Msg"].length() / 2;
			std::unique_ptr<uint8_t> key(new uint8_t[key_sz]);
			std::unique_ptr<uint8_t> msg(new uint8_t[msg_sz]);
			uint8_t mac[Crypto::SHA384::SIZE];
			std::string mac_str;

			res = Crypto::Utils::from_hex(test["Key"], key.get(), key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
			EXPECT_EQ(res, 0);

			Crypto::HMAC_get<Crypto::SHA384>(key.get(), key_sz, msg.get(), msg_sz, mac);

			res = Crypto::Utils::to_hex(mac, atoi(test["Tlen"].c_str()), mac_str, false);
			EXPECT_EQ(res, 0);

			EXPECT_EQ(mac_str, test["Mac"]);
		}
	}
}

TEST(HMAC_SHA512, KAT)
{
	std::string file = "HMAC.rsp";
	std::string file_path = TestOptions::get().vect_dir + "HMAC/" + file;

	auto test_vectors = TestVectors::NISTParser(file_path)["L=64"];
	EXPECT_FALSE(test_vectors.empty());

	for ( auto tests : test_vectors ) {
		for ( auto test : tests ) {
			int res;
			std::size_t key_sz = atoi(test["Klen"].c_str());
			std::size_t msg_sz = test["Msg"].length() / 2;
			std::unique_ptr<uint8_t> key(new uint8_t[key_sz]);
			std::unique_ptr<uint8_t> msg(new uint8_t[msg_sz]);
			uint8_t mac[Crypto::SHA512::SIZE];
			std::string mac_str;

			res = Crypto::Utils::from_hex(test["Key"], key.get(), key_sz);
			EXPECT_EQ(res, 0);

			res = Crypto::Utils::from_hex(test["Msg"], msg.get(), msg_sz);
			EXPECT_EQ(res, 0);

			Crypto::HMAC_get<Crypto::SHA512>(key.get(), key_sz, msg.get(), msg_sz, mac);

			res = Crypto::Utils::to_hex(mac, atoi(test["Tlen"].c_str()), mac_str, false);
			EXPECT_EQ(res, 0);

			EXPECT_EQ(mac_str, test["Mac"]);
		}
	}
}
