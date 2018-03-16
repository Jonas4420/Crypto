#include <memory>
#include <vector>

#include "TestOptions.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/RSA.hpp"
#include "crypto/ASN1.hpp"
#include "crypto/BigNum.hpp"
#include "crypto/HMAC_DRBG.hpp"
#include "crypto/PEM.hpp"
#include "crypto/SHA512.hpp"
#include "crypto/Utils.hpp"

static int
hmac_drbg_rand(void *state, uint8_t *data, std::size_t data_sz)
{
	((void)state);

	static uint8_t seed[512] = { 0 };
	static std::size_t seed_sz = sizeof(seed);
	static Crypto::HMAC_DRBG<Crypto::SHA512> ctx(seed, seed_sz);

	return ctx.generate(data, data_sz);
}

TEST(RSAPublicKey, constructor)
{
	// Case #1: small key
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		Crypto::RSA::RSAPublicKey expected(55, 3);

		res = Crypto::Utils::from_hex("3006020137020103", data, data_sz);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(Crypto::RSA::RSAPublicKey(data, data_sz), expected);
	}

	// Case #2: from actual PEM file (OpenSSL key)
	{
		int res;
		uint8_t data[512];
		std::size_t data_sz = sizeof(data);

		Crypto::BigNum n("D738A35A688C5025CC9C100F2D4447AD9B4E76D18B9D13D8A2C76103A74CE1B4"
				"5435324600C3A45FA0C6A6F67FFC64A8E6A6DC1AADADD08CD0A5FF0D9A1BE83C"
				"27A5573A114EDA75DC18776FAE0085EFC43508611E5BE0EB008A9A1456AE2EDB"
				"2D42646A24B52BAB907763078FE5BD13A95C699C5AF72686C5EF501155DD05DA"
				"9F0A35F23918E1ED25C835E5AE861AD662F0D1A82EF4F4055A1D08A818C41B41"
				"631700914623827EE4554146A5B2A08B0A23E31E1043D4CC1EC76F650934821E"
				"CBC9ABC499FEE61269DDA55852D64F44CD72C5377449E92064B0476F86C58941"
				"98750E8DDADCF8074CF33072E7515D15A32F387A0B2D48F768DF7CECEB94E033", 16);
		Crypto::BigNum e("010001", 16);
		Crypto::RSA::RSAPublicKey expected(n, e);

		std::string pem = "-----BEGIN RSA PUBLIC KEY-----\n"
			"MIIBCgKCAQEA1zijWmiMUCXMnBAPLURHrZtOdtGLnRPYosdhA6dM4bRUNTJGAMOk\n"
			"X6DGpvZ//GSo5qbcGq2t0IzQpf8NmhvoPCelVzoRTtp13Bh3b64Ahe/ENQhhHlvg\n"
			"6wCKmhRWri7bLUJkaiS1K6uQd2MHj+W9E6lcaZxa9yaGxe9QEVXdBdqfCjXyORjh\n"
			"7SXINeWuhhrWYvDRqC709AVaHQioGMQbQWMXAJFGI4J+5FVBRqWyoIsKI+MeEEPU\n"
			"zB7Hb2UJNIIey8mrxJn+5hJp3aVYUtZPRM1yxTd0SekgZLBHb4bFiUGYdQ6N2tz4\n"
			"B0zzMHLnUV0Voy84egstSPdo33zs65TgMwIDAQAB\n"
			"-----END RSA PUBLIC KEY-----";

		res = Crypto::PEM::decode("RSA PUBLIC KEY", pem, data, data_sz);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(Crypto::RSA::RSAPublicKey(data, data_sz), expected);
	}
}

TEST(RSAPublicKey, constructor_abnormal)
{
	// Not a sequence
	{
		int res;
		std::string exception, expected = "Bad RSAPublicKey format";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("020103", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPublicKey pubKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Data is longer than sequence size
	{
		int res;
		std::string exception, expected = "Bad RSAPublicKey format";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("3003020137FF", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPublicKey pubKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Sequence size is not 2
	{
		int res;
		std::string exception, expected = "Bad RSAPublicKey format";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("3009020103020103020103", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPublicKey pubKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// First item is not an integer
	{
		int res;
		std::string exception, expected = "Bad RSAPublicKey format";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("3006010100020103", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPublicKey pubKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Second item is not an integer
	{
		int res;
		std::string exception, expected = "Bad RSAPublicKey format";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("3006020137010100", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPublicKey pubKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(RSAPublicKey, to_binary)
{
	// Case #1: small key
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::string pubKey_str, expected = "3006020137020103";

		Crypto::RSA::RSAPublicKey pubKey(55, 3);

		res = pubKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, data_sz, pubKey_str);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(pubKey_str, expected);
	}

	// Case #2: from actual PEM file (OpenSSL key)
	{
		int res;
		uint8_t data[512];
		std::size_t data_sz = sizeof(data);
		std::string pubKey_str;
		
		std::string expected = "3082010A0282010100"
			"D738A35A688C5025CC9C100F2D4447AD9B4E76D18B9D13D8A2C76103A74CE1B4"
			"5435324600C3A45FA0C6A6F67FFC64A8E6A6DC1AADADD08CD0A5FF0D9A1BE83C"
			"27A5573A114EDA75DC18776FAE0085EFC43508611E5BE0EB008A9A1456AE2EDB"
			"2D42646A24B52BAB907763078FE5BD13A95C699C5AF72686C5EF501155DD05DA"
			"9F0A35F23918E1ED25C835E5AE861AD662F0D1A82EF4F4055A1D08A818C41B41"
			"631700914623827EE4554146A5B2A08B0A23E31E1043D4CC1EC76F650934821E"
			"CBC9ABC499FEE61269DDA55852D64F44CD72C5377449E92064B0476F86C58941"
			"98750E8DDADCF8074CF33072E7515D15A32F387A0B2D48F768DF7CECEB94E033"
			"0203010001";

		Crypto::BigNum n("D738A35A688C5025CC9C100F2D4447AD9B4E76D18B9D13D8A2C76103A74CE1B4"
				"5435324600C3A45FA0C6A6F67FFC64A8E6A6DC1AADADD08CD0A5FF0D9A1BE83C"
				"27A5573A114EDA75DC18776FAE0085EFC43508611E5BE0EB008A9A1456AE2EDB"
				"2D42646A24B52BAB907763078FE5BD13A95C699C5AF72686C5EF501155DD05DA"
				"9F0A35F23918E1ED25C835E5AE861AD662F0D1A82EF4F4055A1D08A818C41B41"
				"631700914623827EE4554146A5B2A08B0A23E31E1043D4CC1EC76F650934821E"
				"CBC9ABC499FEE61269DDA55852D64F44CD72C5377449E92064B0476F86C58941"
				"98750E8DDADCF8074CF33072E7515D15A32F387A0B2D48F768DF7CECEB94E033", 16);
		Crypto::BigNum e("010001", 16);
		Crypto::RSA::RSAPublicKey pubKey(n, e);

		res = pubKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, data_sz, pubKey_str);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(pubKey_str, expected);
	}
}

TEST(RSAPublicKey, to_binary_abnormal)
{
	// Case #1: Not enough space to write (small)
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		Crypto::RSA::RSAPublicKey pubKey(55, 3);

		data_sz = 0;
		res = pubKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(data_sz, 8);

		res = pubKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(data_sz, 8);
	}

	// Case #2: not enough space to write (larger)
	{
		int res;
		uint8_t data[512];
		std::size_t data_sz = sizeof(data);
		
		Crypto::BigNum n("D738A35A688C5025CC9C100F2D4447AD9B4E76D18B9D13D8A2C76103A74CE1B4"
				"5435324600C3A45FA0C6A6F67FFC64A8E6A6DC1AADADD08CD0A5FF0D9A1BE83C"
				"27A5573A114EDA75DC18776FAE0085EFC43508611E5BE0EB008A9A1456AE2EDB"
				"2D42646A24B52BAB907763078FE5BD13A95C699C5AF72686C5EF501155DD05DA"
				"9F0A35F23918E1ED25C835E5AE861AD662F0D1A82EF4F4055A1D08A818C41B41"
				"631700914623827EE4554146A5B2A08B0A23E31E1043D4CC1EC76F650934821E"
				"CBC9ABC499FEE61269DDA55852D64F44CD72C5377449E92064B0476F86C58941"
				"98750E8DDADCF8074CF33072E7515D15A32F387A0B2D48F768DF7CECEB94E033", 16);
		Crypto::BigNum e("010001", 16);
		Crypto::RSA::RSAPublicKey pubKey(n, e);

		data_sz = 0;
		res = pubKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(data_sz, 270);

		res = pubKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(data_sz, 270);
	}
}

TEST(RSAPublicKey, is_valid)
{
	std::vector<std::vector<std::string>> tests = {
		{
			// N == 0
			"00", "03",
			"false"
		}, {
			// N is even
			"02", "03",
			"false"
		}, {
			// E == 0
			"09", "00",
			"false"
		}, {
			// E is even
			"09", "04",
			"false"
		}, {
			// E > N
			"09", "13",
			"false"
		}, {
			// Normal case #1
			"09", "03",
			"true"
		}, {
			// Normal case #2
			"37", "03",
			"true"
		}, {
			// Normal case #3
			"4D", "03",
			"true"
		}, {
			// Normal case #4
			"D738A35A688C5025CC9C100F2D4447AD9B4E76D18B9D13D8A2C76103A74CE1B4"
			"5435324600C3A45FA0C6A6F67FFC64A8E6A6DC1AADADD08CD0A5FF0D9A1BE83C"
			"27A5573A114EDA75DC18776FAE0085EFC43508611E5BE0EB008A9A1456AE2EDB"
			"2D42646A24B52BAB907763078FE5BD13A95C699C5AF72686C5EF501155DD05DA"
			"9F0A35F23918E1ED25C835E5AE861AD662F0D1A82EF4F4055A1D08A818C41B41"
			"631700914623827EE4554146A5B2A08B0A23E31E1043D4CC1EC76F650934821E"
			"CBC9ABC499FEE61269DDA55852D64F44CD72C5377449E92064B0476F86C58941"
			"98750E8DDADCF8074CF33072E7515D15A32F387A0B2D48F768DF7CECEB94E033",
			"010001",
			"true"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum n(test[0], 16);
		Crypto::BigNum e(test[1], 16);
		bool expected = (test[2] == "true");

		Crypto::RSA::RSAPublicKey publicKey(n, e);

		EXPECT_EQ(publicKey.is_valid(), expected);
	}
}

TEST(RSAPrivateKey, constructor)
{
	// Case #1: small key (Carmichael function)
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		Crypto::RSA::RSAPrivateKey expected(3, 5, 11, true);

		res = Crypto::Utils::from_hex("301B02010002013702010302010702010502010B020103020107020101", data, data_sz);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(Crypto::RSA::RSAPrivateKey(data, data_sz), expected);
	}

	// Case #2: small key (Euler totient)
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		Crypto::RSA::RSAPrivateKey expected(3, 5, 11, false);

		res = Crypto::Utils::from_hex("301B02010002013702010302011B02010502010B020103020107020101", data, data_sz);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(Crypto::RSA::RSAPrivateKey(data, data_sz), expected);
	}

	// Case #3: from actual PEM file (OpenSSL key)
	{
		int res;
		uint8_t data[2048];
		std::size_t data_sz = sizeof(data);

		Crypto::BigNum e("010001", 16);
		Crypto::BigNum p("EE6AC711ACA6BE66E8396A278AC5BF4C026796EB1D4A432C23CAEF0DA5DED23B"
				"3ABB9580AFB82DEE905B239B0D7AA176FC36825ACA6A65055D2BF868F62F775C"
				"039F87F6F8F4695EA4A77977FBD26FE4DDE631A8B500A0F69411ED86AAD920FE"
				"862E626239C074D8700ED64C35CA236F03196AE1AB7FC053524B2AC575D2415B", 16);
		Crypto::BigNum q("E717EE83532B676DE2887680049A89C36ACD544C983BD11FAFB08F76D8D3403F"
				"3EE984705704283B2B008F3D5FBDF9D073C8D57DD8B8123C9F5B812216F89D85"
				"CB52EA303D890E17C955E77284DFB4D7388EF9749C9E40CB448C749F7F7C446F"
				"3E8B151C885591E7912ABA363840B3FCC4B0CF0A849666416B7025AFA081FC09", 16);
		Crypto::RSA::RSAPrivateKey expected(e, p, q, false);

		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"MIIEpAIBAAKCAQEA1zijWmiMUCXMnBAPLURHrZtOdtGLnRPYosdhA6dM4bRUNTJG\n"
			"AMOkX6DGpvZ//GSo5qbcGq2t0IzQpf8NmhvoPCelVzoRTtp13Bh3b64Ahe/ENQhh\n"
			"Hlvg6wCKmhRWri7bLUJkaiS1K6uQd2MHj+W9E6lcaZxa9yaGxe9QEVXdBdqfCjXy\n"
			"ORjh7SXINeWuhhrWYvDRqC709AVaHQioGMQbQWMXAJFGI4J+5FVBRqWyoIsKI+Me\n"
			"EEPUzB7Hb2UJNIIey8mrxJn+5hJp3aVYUtZPRM1yxTd0SekgZLBHb4bFiUGYdQ6N\n"
			"2tz4B0zzMHLnUV0Voy84egstSPdo33zs65TgMwIDAQABAoIBAQCrwTJz+w1HBPNl\n"
			"9Fb4TA5b2J5kqlOd1nHDbhPZA5GSagPttCIzh+5MtpTyN7Pp6zbzY2QyEjqtPUNh\n"
			"xcrIGs9Z+lWz585aPHNkY04lnRojyTWvEPHYdYBoarUxw1tthE07sElMf+DpafBP\n"
			"poMpbjFXWIg8bCAYLvHNUm92dix99wTVkzZSeEWxtiq2qm3XE7OQ9hQv3GkEOB3e\n"
			"GszQruW8QB6661XN844+tfHZuk5+lvWThmWwcrkgfLbIb976186dBPGgzgFEEU2Q\n"
			"K2vtERm0ozx916+lB6uHYty1kASaQvktMp9Eqbdxq1gG8LUH97GXOeD/ukGbGlzz\n"
			"8FztnbiRAoGBAO5qxxGspr5m6DlqJ4rFv0wCZ5brHUpDLCPK7w2l3tI7OruVgK+4\n"
			"Le6QWyObDXqhdvw2glrKamUFXSv4aPYvd1wDn4f2+PRpXqSneXf70m/k3eYxqLUA\n"
			"oPaUEe2Gqtkg/oYuYmI5wHTYcA7WTDXKI28DGWrhq3/AU1JLKsV10kFbAoGBAOcX\n"
			"7oNTK2dt4oh2gASaicNqzVRMmDvRH6+wj3bY00A/PumEcFcEKDsrAI89X7350HPI\n"
			"1X3YuBI8n1uBIhb4nYXLUuowPYkOF8lV53KE37TXOI75dJyeQMtEjHSff3xEbz6L\n"
			"FRyIVZHnkSq6NjhAs/zEsM8KhJZmQWtwJa+ggfwJAoGBAJrRcbVzdM+9SV1HJqhB\n"
			"oug7w4LH6Dw6BGa1t6gYJupDle8LtQXmRsVcriIf5I/WW8qJpvpH6PDym78azyXW\n"
			"St7QZ37GDIHCDrhDHGiieNM6PjHl21S2NNAJ9N5WDYlzmHQPmMmKEQSPK60m0VQ4\n"
			"j+vdilrScihB/pk4wGx7Bu5zAoGAOJhBz2Ok85WTrvvmajo2lucnFggUGEIk0nAZ\n"
			"EnATfF6A18uZf5YDDEqBvpK3Sd1OUazTrBhRLBYwqMY9RQbp/QRIcBYUW+ZZqPMi\n"
			"1Yb5Cl7S+SDakCipkZ5eD4moPRS9ccG6D9zLqAngIWitMqWV7sd0zZ+zzOmKB/fV\n"
			"IufaLZECgYA/hnbYoBvjfj4CkO3j9wKYMxZdFfRm3TPnIAsTLI4h6P71yL+YMwNe\n"
			"VUCfZXWtupC90L0OrEV08mmxq/14njzTGRQBBfpJp/OHfdrCmPxZxI+4DKeTFK1f\n"
			"Uv6swUMSdoKmgkbFk5YqIoooSq9n/oNYgJ2jKA90kamcKUonELpGSg==\n"
			"-----END RSA PRIVATE KEY-----";

		res = Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(Crypto::RSA::RSAPrivateKey(data, data_sz), expected);
	}
}

TEST(RSAPrivateKey, constructor_abnormal)
{
	// Not a sequence
	{
		int res;
		std::string exception, expected = "Bad RSAPrivateKey format";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("311B02010002013702010302010702010502010B020103020107020101", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPrivateKey privKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Data is longer than sequence size
	{
		int res;
		std::string exception, expected = "Bad RSAPrivateKey format";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("300302010002013702010302010702010502010B020103020107020101", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPrivateKey privKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Sequence size is null
	{
		int res;
		std::string exception, expected = "Bad RSAPrivateKey format";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("3000", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPrivateKey privKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// First value of sequence is not an integer
	{
		int res;
		std::string exception, expected = "Bad RSAPrivateKey format";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("301B0101FF02013702010302010702010502010B020103020107020101", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPrivateKey privKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// First value is not 0
	{
		int res;
		std::string exception, expected = "RSAPrivateKey version is not supported";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("301B02010102013702010302010702010502010B020103020107020101", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPrivateKey privKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Sequence size is not 9
	{
		int res;
		std::string exception, expected = "Bad RSAPrivateKey format";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("301802010002013702010302010702010502010B020103020107", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPrivateKey privKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Item of sequence is not an integer
	{
		int res;
		std::string exception, expected = "Bad RSAPrivateKey format";
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		res = Crypto::Utils::from_hex("301B0201000201370101FF02010702010502010B020103020107020101", data, data_sz);
		EXPECT_EQ(res, 0);

		try {
			Crypto::RSA::RSAPrivateKey privKey(data, data_sz);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(RSAPrivateKey, to_binary)
{
	// Case #1: small key (Carmichael function)
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::string privKey_str, expected = "301B02010002013702010302010702010502010B020103020107020101";

		Crypto::RSA::RSAPrivateKey privKey(3, 5, 11, true);

		res = privKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, data_sz, privKey_str);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(privKey_str, expected);
	}

	// Case #2: small key (Euler totient)
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);
		std::string privKey_str, expected = "301B02010002013702010302011B02010502010B020103020107020101";

		Crypto::RSA::RSAPrivateKey privKey(3, 5, 11, false);

		res = privKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, data_sz, privKey_str);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(privKey_str, expected);
	}

	// Case #3: from actual PEM file (OpenSSL key)
	{
		int res;
		uint8_t data[2048];
		std::size_t data_sz = sizeof(data);
		std::string privKey_str;
		
		std::string expected = "308204A40201000282010100D738A35A688C5025CC9C100F2D4447AD9B4E76D1"
			"8B9D13D8A2C76103A74CE1B45435324600C3A45FA0C6A6F67FFC64A8E6A6DC1A"
			"ADADD08CD0A5FF0D9A1BE83C27A5573A114EDA75DC18776FAE0085EFC4350861"
			"1E5BE0EB008A9A1456AE2EDB2D42646A24B52BAB907763078FE5BD13A95C699C"
			"5AF72686C5EF501155DD05DA9F0A35F23918E1ED25C835E5AE861AD662F0D1A8"
			"2EF4F4055A1D08A818C41B41631700914623827EE4554146A5B2A08B0A23E31E"
			"1043D4CC1EC76F650934821ECBC9ABC499FEE61269DDA55852D64F44CD72C537"
			"7449E92064B0476F86C5894198750E8DDADCF8074CF33072E7515D15A32F387A"
			"0B2D48F768DF7CECEB94E03302030100010282010100ABC13273FB0D4704F365"
			"F456F84C0E5BD89E64AA539DD671C36E13D90391926A03EDB4223387EE4CB694"
			"F237B3E9EB36F3636432123AAD3D4361C5CAC81ACF59FA55B3E7CE5A3C736463"
			"4E259D1A23C935AF10F1D87580686AB531C35B6D844D3BB0494C7FE0E969F04F"
			"A683296E315758883C6C20182EF1CD526F76762C7DF704D59336527845B1B62A"
			"B6AA6DD713B390F6142FDC6904381DDE1ACCD0AEE5BC401EBAEB55CDF38E3EB5"
			"F1D9BA4E7E96F5938665B072B9207CB6C86FDEFAD7CE9D04F1A0CE0144114D90"
			"2B6BED1119B4A33C7DD7AFA507AB8762DCB590049A42F92D329F44A9B771AB58"
			"06F0B507F7B19739E0FFBA419B1A5CF3F05CED9DB89102818100EE6AC711ACA6"
			"BE66E8396A278AC5BF4C026796EB1D4A432C23CAEF0DA5DED23B3ABB9580AFB8"
			"2DEE905B239B0D7AA176FC36825ACA6A65055D2BF868F62F775C039F87F6F8F4"
			"695EA4A77977FBD26FE4DDE631A8B500A0F69411ED86AAD920FE862E626239C0"
			"74D8700ED64C35CA236F03196AE1AB7FC053524B2AC575D2415B02818100E717"
			"EE83532B676DE2887680049A89C36ACD544C983BD11FAFB08F76D8D3403F3EE9"
			"84705704283B2B008F3D5FBDF9D073C8D57DD8B8123C9F5B812216F89D85CB52"
			"EA303D890E17C955E77284DFB4D7388EF9749C9E40CB448C749F7F7C446F3E8B"
			"151C885591E7912ABA363840B3FCC4B0CF0A849666416B7025AFA081FC090281"
			"81009AD171B57374CFBD495D4726A841A2E83BC382C7E83C3A0466B5B7A81826"
			"EA4395EF0BB505E646C55CAE221FE48FD65BCA89A6FA47E8F0F29BBF1ACF25D6"
			"4ADED0677EC60C81C20EB8431C68A278D33A3E31E5DB54B634D009F4DE560D89"
			"7398740F98C98A11048F2BAD26D154388FEBDD8A5AD2722841FE9938C06C7B06"
			"EE73028180389841CF63A4F39593AEFBE66A3A3696E727160814184224D27019"
			"1270137C5E80D7CB997F96030C4A81BE92B749DD4E51ACD3AC18512C1630A8C6"
			"3D4506E9FD04487016145BE659A8F322D586F90A5ED2F920DA9028A9919E5E0F"
			"89A83D14BD71C1BA0FDCCBA809E02168AD32A595EEC774CD9FB3CCE98A07F7D5"
			"22E7DA2D910281803F8676D8A01BE37E3E0290EDE3F7029833165D15F466DD33"
			"E7200B132C8E21E8FEF5C8BF9833035E55409F6575ADBA90BDD0BD0EAC4574F2"
			"69B1ABFD789E3CD319140105FA49A7F3877DDAC298FC59C48FB80CA79314AD5F"
			"52FEACC143127682A68246C593962A228A284AAF67FE8358809DA3280F7491A9"
			"9C294A2710BA464A";

		Crypto::BigNum e("010001", 16);
		Crypto::BigNum p("EE6AC711ACA6BE66E8396A278AC5BF4C026796EB1D4A432C23CAEF0DA5DED23B"
				"3ABB9580AFB82DEE905B239B0D7AA176FC36825ACA6A65055D2BF868F62F775C"
				"039F87F6F8F4695EA4A77977FBD26FE4DDE631A8B500A0F69411ED86AAD920FE"
				"862E626239C074D8700ED64C35CA236F03196AE1AB7FC053524B2AC575D2415B", 16);
		Crypto::BigNum q("E717EE83532B676DE2887680049A89C36ACD544C983BD11FAFB08F76D8D3403F"
				"3EE984705704283B2B008F3D5FBDF9D073C8D57DD8B8123C9F5B812216F89D85"
				"CB52EA303D890E17C955E77284DFB4D7388EF9749C9E40CB448C749F7F7C446F"
				"3E8B151C885591E7912ABA363840B3FCC4B0CF0A849666416B7025AFA081FC09", 16);
		Crypto::RSA::RSAPrivateKey privKey(e, p, q, false);

		res = privKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 0);

		res = Crypto::Utils::to_hex(data, data_sz, privKey_str);
		EXPECT_EQ(res, 0);

		EXPECT_EQ(privKey_str, expected);
	}
}

TEST(RSAPrivateKey, to_binary_abnormal)
{
	// Case #1: Not enough space to write (small with Carmichael function)
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		Crypto::RSA::RSAPrivateKey privKey(3, 5, 11, true);

		data_sz = 0;
		res = privKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(data_sz, 29);

		res = privKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(data_sz, 29);
	}

	// Case #2: Not enough space to write (small with Euler totient)
	{
		int res;
		uint8_t data[256];
		std::size_t data_sz = sizeof(data);

		Crypto::RSA::RSAPrivateKey privKey(3, 5, 11, false);

		data_sz = 0;
		res = privKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(data_sz, 29);

		res = privKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(data_sz, 29);
	}

	// Case #3: Not enough space to write (large from OpenSSL key)
	{
		int res;
		uint8_t data[2048];
		std::size_t data_sz = sizeof(data);

		Crypto::BigNum e("010001", 16);
		Crypto::BigNum p("EE6AC711ACA6BE66E8396A278AC5BF4C026796EB1D4A432C23CAEF0DA5DED23B"
				"3ABB9580AFB82DEE905B239B0D7AA176FC36825ACA6A65055D2BF868F62F775C"
				"039F87F6F8F4695EA4A77977FBD26FE4DDE631A8B500A0F69411ED86AAD920FE"
				"862E626239C074D8700ED64C35CA236F03196AE1AB7FC053524B2AC575D2415B", 16);
		Crypto::BigNum q("E717EE83532B676DE2887680049A89C36ACD544C983BD11FAFB08F76D8D3403F"
				"3EE984705704283B2B008F3D5FBDF9D073C8D57DD8B8123C9F5B812216F89D85"
				"CB52EA303D890E17C955E77284DFB4D7388EF9749C9E40CB448C749F7F7C446F"
				"3E8B151C885591E7912ABA363840B3FCC4B0CF0A849666416B7025AFA081FC09", 16);
		Crypto::RSA::RSAPrivateKey privKey(e, p, q, false);

		data_sz = 0;
		res = privKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(data_sz, 1192);

		res = privKey.to_binary(data, data_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(data_sz, 1192);
	}
}

TEST(RSAPrivateKey, is_valid_no_rng)
{
	std::vector<std::vector<std::string>> tests = {
		{
			// N == 0
			"00", "03", "07", "05", "0B", "03", "07", "01",
			"false"
		}, {
			// N is even
			"02", "03", "07", "05", "0B", "03", "07", "01",
			"false"
		}, {
			// E == 1
			"37", "01", "07", "05", "0B", "03", "07", "01",
			"false"
		}, {
			// E is even
			"37", "02", "07", "05", "0B", "03", "07", "01",
			"false"
		}, {
			// E == N
			"37", "37", "07", "05", "0B", "03", "07", "01",
			"false"
		}, {
			// P == 1
			"37", "03", "07", "01", "0B", "03", "07", "01",
			"false"
		}, {
			// P is even
			"37", "03", "07", "02", "0B", "03", "07", "01",
			"false"
		}, {
			// Q == 1
			"37", "03", "07", "05", "01", "03", "07", "01",
			"false"
		}, {
			// Q is even
			"37", "03", "07", "05", "02", "03", "07", "01",
			"false"
		}, {
			// D == 1
			"37", "03", "01", "05", "0B", "03", "07", "01",
			"false"
		}, {
			// D == N
			"37", "03", "37", "05", "0B", "03", "07", "01",
			"false"
		}, {
			// N != P * Q
			"4D", "03", "37", "05", "0B", "03", "07", "01",
			"false"
		}, {
			// DP == 0
			"37", "03", "07", "05", "0B", "00", "07", "01",
			"false"
		}, {
			// DQ == 0
			"37", "03", "07", "05", "0B", "03", "00", "01",
			"false"
		}, {
			// QP == 0
			"37", "03", "07", "05", "0B", "03", "07", "00",
			"false"
		}, {
			// (D*E) % (P-1) != 1
			"4D", "03", "1B", "07", "0B", "03", "07", "01",
			"false"
		}, {
			// (D*E) % (Q-1) != 1
			"23", "03", "1B", "05", "07", "03", "07", "01",
			"false"
		}, {
			// (DP - D) % (P-1) != 0
			"37", "03", "1B", "05", "0B", "02", "07", "01",
			"false"
		}, {
			// (DQ - D) % (Q-1) != 0
			"37", "03", "1B", "05", "0B", "03", "06", "01",
			"false"
		}, {
			// (QP * Q) % P != 1
			"37", "03", "1B", "05", "0B", "03", "07", "02",
			"false"
		}, {
			// Normal case #1 (Carmichael function)
			"37", "03", "07", "05", "0B", "03", "07", "01",
			"true"
		}, {
			// Normal case #2 (Euler totient)
			"37", "03", "1B", "05", "0B", "03", "07", "01",
			"true"
		}, {
			// Normal case #3 (OpenSSL key)
			"D738A35A688C5025CC9C100F2D4447AD9B4E76D18B9D13D8A2C76103A74CE1B4"
			"5435324600C3A45FA0C6A6F67FFC64A8E6A6DC1AADADD08CD0A5FF0D9A1BE83C"
			"27A5573A114EDA75DC18776FAE0085EFC43508611E5BE0EB008A9A1456AE2EDB"
			"2D42646A24B52BAB907763078FE5BD13A95C699C5AF72686C5EF501155DD05DA"
			"9F0A35F23918E1ED25C835E5AE861AD662F0D1A82EF4F4055A1D08A818C41B41"
			"631700914623827EE4554146A5B2A08B0A23E31E1043D4CC1EC76F650934821E"
			"CBC9ABC499FEE61269DDA55852D64F44CD72C5377449E92064B0476F86C58941"
			"98750E8DDADCF8074CF33072E7515D15A32F387A0B2D48F768DF7CECEB94E033",
			"010001",
			"ABC13273FB0D4704F365F456F84C0E5BD89E64AA539DD671C36E13D90391926A"
			"03EDB4223387EE4CB694F237B3E9EB36F3636432123AAD3D4361C5CAC81ACF59"
			"FA55B3E7CE5A3C7364634E259D1A23C935AF10F1D87580686AB531C35B6D844D"
			"3BB0494C7FE0E969F04FA683296E315758883C6C20182EF1CD526F76762C7DF7"
			"04D59336527845B1B62AB6AA6DD713B390F6142FDC6904381DDE1ACCD0AEE5BC"
			"401EBAEB55CDF38E3EB5F1D9BA4E7E96F5938665B072B9207CB6C86FDEFAD7CE"
			"9D04F1A0CE0144114D902B6BED1119B4A33C7DD7AFA507AB8762DCB590049A42"
			"F92D329F44A9B771AB5806F0B507F7B19739E0FFBA419B1A5CF3F05CED9DB891",
			"EE6AC711ACA6BE66E8396A278AC5BF4C026796EB1D4A432C23CAEF0DA5DED23B"
			"3ABB9580AFB82DEE905B239B0D7AA176FC36825ACA6A65055D2BF868F62F775C"
			"039F87F6F8F4695EA4A77977FBD26FE4DDE631A8B500A0F69411ED86AAD920FE"
			"862E626239C074D8700ED64C35CA236F03196AE1AB7FC053524B2AC575D2415B",
			"E717EE83532B676DE2887680049A89C36ACD544C983BD11FAFB08F76D8D3403F"
			"3EE984705704283B2B008F3D5FBDF9D073C8D57DD8B8123C9F5B812216F89D85"
			"CB52EA303D890E17C955E77284DFB4D7388EF9749C9E40CB448C749F7F7C446F"
			"3E8B151C885591E7912ABA363840B3FCC4B0CF0A849666416B7025AFA081FC09",
			"9AD171B57374CFBD495D4726A841A2E83BC382C7E83C3A0466B5B7A81826EA43"
			"95EF0BB505E646C55CAE221FE48FD65BCA89A6FA47E8F0F29BBF1ACF25D64ADE"
			"D0677EC60C81C20EB8431C68A278D33A3E31E5DB54B634D009F4DE560D897398"
			"740F98C98A11048F2BAD26D154388FEBDD8A5AD2722841FE9938C06C7B06EE73",
			"389841CF63A4F39593AEFBE66A3A3696E727160814184224D270191270137C5E"
			"80D7CB997F96030C4A81BE92B749DD4E51ACD3AC18512C1630A8C63D4506E9FD"
			"04487016145BE659A8F322D586F90A5ED2F920DA9028A9919E5E0F89A83D14BD"
			"71C1BA0FDCCBA809E02168AD32A595EEC774CD9FB3CCE98A07F7D522E7DA2D91",
			"3F8676D8A01BE37E3E0290EDE3F7029833165D15F466DD33E7200B132C8E21E8"
			"FEF5C8BF9833035E55409F6575ADBA90BDD0BD0EAC4574F269B1ABFD789E3CD3"
			"19140105FA49A7F3877DDAC298FC59C48FB80CA79314AD5F52FEACC143127682"
			"A68246C593962A228A284AAF67FE8358809DA3280F7491A99C294A2710BA464A",
			"true"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum n(test[0], 16);
		Crypto::BigNum e(test[1], 16);
		Crypto::BigNum d(test[2], 16);
		Crypto::BigNum p(test[3], 16);
		Crypto::BigNum q(test[4], 16);
		Crypto::BigNum dp(test[5], 16);
		Crypto::BigNum dq(test[6], 16);
		Crypto::BigNum qp(test[7], 16);
		bool expected = (test[8] == "true");

		Crypto::RSA::RSAPrivateKey privateKey(n, e, d, p, q, dp, dq, qp);

		EXPECT_EQ(privateKey.is_valid(), expected);
	}
}

TEST(RSAPrivateKey, is_valid_rng)
{
	std::vector<std::vector<std::string>> tests {
		{
			// P not prime, Q not prime
			"138D", "03", "0C93", "23", "8F", "17", "5F", "0C",
			"false"
		}, {
			// P not prime, Q prime
			"0181", "03", "E3", "23", "0B", "17", "07", "10",
			"false"
		}, {
			// P prime, Q not prime
			"0181", "03", "E3", "0B", "23", "07", "17", "06",
			"false"
		}, {
			// Normal case #1 (Carmichael function)
			"37", "03", "07", "05", "0B", "03", "07", "01",
			"true"
		}, {
			// Normal case #1 (Euler totient)
			"37", "03", "1B", "05", "0B", "03", "07", "01",
			"true"
		}, {
			// Normal case #3 (OpenSSL key)
			"D738A35A688C5025CC9C100F2D4447AD9B4E76D18B9D13D8A2C76103A74CE1B4"
			"5435324600C3A45FA0C6A6F67FFC64A8E6A6DC1AADADD08CD0A5FF0D9A1BE83C"
			"27A5573A114EDA75DC18776FAE0085EFC43508611E5BE0EB008A9A1456AE2EDB"
			"2D42646A24B52BAB907763078FE5BD13A95C699C5AF72686C5EF501155DD05DA"
			"9F0A35F23918E1ED25C835E5AE861AD662F0D1A82EF4F4055A1D08A818C41B41"
			"631700914623827EE4554146A5B2A08B0A23E31E1043D4CC1EC76F650934821E"
			"CBC9ABC499FEE61269DDA55852D64F44CD72C5377449E92064B0476F86C58941"
			"98750E8DDADCF8074CF33072E7515D15A32F387A0B2D48F768DF7CECEB94E033",
			"010001",
			"ABC13273FB0D4704F365F456F84C0E5BD89E64AA539DD671C36E13D90391926A"
			"03EDB4223387EE4CB694F237B3E9EB36F3636432123AAD3D4361C5CAC81ACF59"
			"FA55B3E7CE5A3C7364634E259D1A23C935AF10F1D87580686AB531C35B6D844D"
			"3BB0494C7FE0E969F04FA683296E315758883C6C20182EF1CD526F76762C7DF7"
			"04D59336527845B1B62AB6AA6DD713B390F6142FDC6904381DDE1ACCD0AEE5BC"
			"401EBAEB55CDF38E3EB5F1D9BA4E7E96F5938665B072B9207CB6C86FDEFAD7CE"
			"9D04F1A0CE0144114D902B6BED1119B4A33C7DD7AFA507AB8762DCB590049A42"
			"F92D329F44A9B771AB5806F0B507F7B19739E0FFBA419B1A5CF3F05CED9DB891",
			"EE6AC711ACA6BE66E8396A278AC5BF4C026796EB1D4A432C23CAEF0DA5DED23B"
			"3ABB9580AFB82DEE905B239B0D7AA176FC36825ACA6A65055D2BF868F62F775C"
			"039F87F6F8F4695EA4A77977FBD26FE4DDE631A8B500A0F69411ED86AAD920FE"
			"862E626239C074D8700ED64C35CA236F03196AE1AB7FC053524B2AC575D2415B",
			"E717EE83532B676DE2887680049A89C36ACD544C983BD11FAFB08F76D8D3403F"
			"3EE984705704283B2B008F3D5FBDF9D073C8D57DD8B8123C9F5B812216F89D85"
			"CB52EA303D890E17C955E77284DFB4D7388EF9749C9E40CB448C749F7F7C446F"
			"3E8B151C885591E7912ABA363840B3FCC4B0CF0A849666416B7025AFA081FC09",
			"9AD171B57374CFBD495D4726A841A2E83BC382C7E83C3A0466B5B7A81826EA43"
			"95EF0BB505E646C55CAE221FE48FD65BCA89A6FA47E8F0F29BBF1ACF25D64ADE"
			"D0677EC60C81C20EB8431C68A278D33A3E31E5DB54B634D009F4DE560D897398"
			"740F98C98A11048F2BAD26D154388FEBDD8A5AD2722841FE9938C06C7B06EE73",
			"389841CF63A4F39593AEFBE66A3A3696E727160814184224D270191270137C5E"
			"80D7CB997F96030C4A81BE92B749DD4E51ACD3AC18512C1630A8C63D4506E9FD"
			"04487016145BE659A8F322D586F90A5ED2F920DA9028A9919E5E0F89A83D14BD"
			"71C1BA0FDCCBA809E02168AD32A595EEC774CD9FB3CCE98A07F7D522E7DA2D91",
			"3F8676D8A01BE37E3E0290EDE3F7029833165D15F466DD33E7200B132C8E21E8"
			"FEF5C8BF9833035E55409F6575ADBA90BDD0BD0EAC4574F269B1ABFD789E3CD3"
			"19140105FA49A7F3877DDAC298FC59C48FB80CA79314AD5F52FEACC143127682"
			"A68246C593962A228A284AAF67FE8358809DA3280F7491A99C294A2710BA464A",
			"true"
		}
	};

	for ( auto test : tests ) {
		Crypto::BigNum n(test[0], 16);
		Crypto::BigNum e(test[1], 16);
		Crypto::BigNum d(test[2], 16);
		Crypto::BigNum p(test[3], 16);
		Crypto::BigNum q(test[4], 16);
		Crypto::BigNum dp(test[5], 16);
		Crypto::BigNum dq(test[6], 16);
		Crypto::BigNum qp(test[7], 16);
		bool expected = (test[8] == "true");

		Crypto::RSA::RSAPrivateKey privateKey(n, e, d, p, q, dp, dq, qp);

		EXPECT_TRUE(privateKey.is_valid());
		EXPECT_EQ(privateKey.is_valid(hmac_drbg_rand, NULL), expected);
	}
}

TEST(RSA, gen_keypair)
{
	std::vector<std::vector<std::string>> tests = {
		{ "128",  "10" },
		{ "512",  "10" },
		{ "1024", "10" },
		{ "2048",  "5" },
		{ "4096",  "1" }
	};

	for ( auto test : tests ) {
		std::size_t n_bits = atoi(test[0].c_str());
		std::size_t iterations = atoi(test[1].c_str());

		if ( TestOptions::get().is_fast ) {
			if ( n_bits > 512 ) { continue; }

			iterations = 5;
		}

		for ( std::size_t i = 0 ; i < iterations ; ++i ) {
			// Generate Key Pair and check validity
			auto keyPair = Crypto::RSA::gen_keypair(hmac_drbg_rand, NULL, n_bits, 3);
			EXPECT_TRUE(Crypto::RSA::is_valid(keyPair, hmac_drbg_rand, NULL));

			// Check keys' size
			EXPECT_EQ(keyPair.first.bitlen(), n_bits);
			EXPECT_EQ(keyPair.second.bitlen(), n_bits);
		}
	}
}

TEST(RSA, gen_keypair_abnormal)
{
	// Case #1: no PRNG
	{
		std::string exception, expected = "Invalid key pair parameters";

		try {
			auto keyPair = Crypto::RSA::gen_keypair(NULL, NULL, 2048, 3);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Case #2: nbits < 128
	{
		std::string exception, expected = "Invalid key pair parameters";

		try {
			auto keyPair = Crypto::RSA::gen_keypair(hmac_drbg_rand, NULL, 64, 3);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Case #3: nbits is odd
	{
		std::string exception, expected = "Invalid key pair parameters";

		try {
			auto keyPair = Crypto::RSA::gen_keypair(hmac_drbg_rand, NULL, 129, 3);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Case #4: E < 3
	{
		std::string exception, expected = "Invalid key pair parameters";

		try {
			auto keyPair = Crypto::RSA::gen_keypair(hmac_drbg_rand, NULL, 129, 2);
		} catch ( const Crypto::RSA::Exception &re ) {
			exception = re.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(RSA, is_valid)
{
	std::vector<std::vector<std::string>> tests = {
		{
			// RSAPublicKey invalid, RSAPrivateKey invalid
			"3006020100020103",
			"301B02010002010002010302010702010502010B020103020107020101",
			"false"
		}, {
			// RSAPublicKey invalid, RSAPrivateKey valid
			"3006020100020103",
			"301B02010002013702010302010702010502010B020103020107020101",
			"false"
		}, {
			// RSAPublicKey valid, RSAPrivateKey invalid
			"3006020137020103",
			"301B02010002010002010302010702010502010B020103020107020101",
			"false"
		}, {
			// RSAPublicKey valid , RSAPrivateKey valid, different N, different E
			"300602014D020105",
			"301B02010002013702010302010702010502010B020103020107020101",
			"false"
		}, {
			// RSAPublicKey valid , RSAPrivateKey valid, different N, same E
			"300602014D020103",
			"301B02010002013702010302010702010502010B020103020107020101",
			"false"
		}, {
			// RSAPublicKey valid , RSAPrivateKey valid, same N, different E
			"3006020137020105",
			"301B02010002013702010302010702010502010B020103020107020101",
			"false"
		}, {
			// RSAPublicKey valid, RSAPrivateKey valid, same N and E (Small case)
			"3006020137020103",
			"301B02010002013702010302010702010502010B020103020107020101",
			"true"
		}, {
			// RSAPublicKey valid, RSAPrivateKey valid, same N and E (Larger case)
			"3082010A0282010100D738A35A688C5025CC9C100F2D4447AD9B4E76D18B9D13"
			"D8A2C76103A74CE1B45435324600C3A45FA0C6A6F67FFC64A8E6A6DC1AADADD0"
			"8CD0A5FF0D9A1BE83C27A5573A114EDA75DC18776FAE0085EFC43508611E5BE0"
			"EB008A9A1456AE2EDB2D42646A24B52BAB907763078FE5BD13A95C699C5AF726"
			"86C5EF501155DD05DA9F0A35F23918E1ED25C835E5AE861AD662F0D1A82EF4F4"
			"055A1D08A818C41B41631700914623827EE4554146A5B2A08B0A23E31E1043D4"
			"CC1EC76F650934821ECBC9ABC499FEE61269DDA55852D64F44CD72C5377449E9"
			"2064B0476F86C5894198750E8DDADCF8074CF33072E7515D15A32F387A0B2D48"
			"F768DF7CECEB94E0330203010001",
			"308204A40201000282010100D738A35A688C5025CC9C100F2D4447AD9B4E76D1"
			"8B9D13D8A2C76103A74CE1B45435324600C3A45FA0C6A6F67FFC64A8E6A6DC1A"
			"ADADD08CD0A5FF0D9A1BE83C27A5573A114EDA75DC18776FAE0085EFC4350861"
			"1E5BE0EB008A9A1456AE2EDB2D42646A24B52BAB907763078FE5BD13A95C699C"
			"5AF72686C5EF501155DD05DA9F0A35F23918E1ED25C835E5AE861AD662F0D1A8"
			"2EF4F4055A1D08A818C41B41631700914623827EE4554146A5B2A08B0A23E31E"
			"1043D4CC1EC76F650934821ECBC9ABC499FEE61269DDA55852D64F44CD72C537"
			"7449E92064B0476F86C5894198750E8DDADCF8074CF33072E7515D15A32F387A"
			"0B2D48F768DF7CECEB94E03302030100010282010100ABC13273FB0D4704F365"
			"F456F84C0E5BD89E64AA539DD671C36E13D90391926A03EDB4223387EE4CB694"
			"F237B3E9EB36F3636432123AAD3D4361C5CAC81ACF59FA55B3E7CE5A3C736463"
			"4E259D1A23C935AF10F1D87580686AB531C35B6D844D3BB0494C7FE0E969F04F"
			"A683296E315758883C6C20182EF1CD526F76762C7DF704D59336527845B1B62A"
			"B6AA6DD713B390F6142FDC6904381DDE1ACCD0AEE5BC401EBAEB55CDF38E3EB5"
			"F1D9BA4E7E96F5938665B072B9207CB6C86FDEFAD7CE9D04F1A0CE0144114D90"
			"2B6BED1119B4A33C7DD7AFA507AB8762DCB590049A42F92D329F44A9B771AB58"
			"06F0B507F7B19739E0FFBA419B1A5CF3F05CED9DB89102818100EE6AC711ACA6"
			"BE66E8396A278AC5BF4C026796EB1D4A432C23CAEF0DA5DED23B3ABB9580AFB8"
			"2DEE905B239B0D7AA176FC36825ACA6A65055D2BF868F62F775C039F87F6F8F4"
			"695EA4A77977FBD26FE4DDE631A8B500A0F69411ED86AAD920FE862E626239C0"
			"74D8700ED64C35CA236F03196AE1AB7FC053524B2AC575D2415B02818100E717"
			"EE83532B676DE2887680049A89C36ACD544C983BD11FAFB08F76D8D3403F3EE9"
			"84705704283B2B008F3D5FBDF9D073C8D57DD8B8123C9F5B812216F89D85CB52"
			"EA303D890E17C955E77284DFB4D7388EF9749C9E40CB448C749F7F7C446F3E8B"
			"151C885591E7912ABA363840B3FCC4B0CF0A849666416B7025AFA081FC090281"
			"81009AD171B57374CFBD495D4726A841A2E83BC382C7E83C3A0466B5B7A81826"
			"EA4395EF0BB505E646C55CAE221FE48FD65BCA89A6FA47E8F0F29BBF1ACF25D6"
			"4ADED0677EC60C81C20EB8431C68A278D33A3E31E5DB54B634D009F4DE560D89"
			"7398740F98C98A11048F2BAD26D154388FEBDD8A5AD2722841FE9938C06C7B06"
			"EE73028180389841CF63A4F39593AEFBE66A3A3696E727160814184224D27019"
			"1270137C5E80D7CB997F96030C4A81BE92B749DD4E51ACD3AC18512C1630A8C6"
			"3D4506E9FD04487016145BE659A8F322D586F90A5ED2F920DA9028A9919E5E0F"
			"89A83D14BD71C1BA0FDCCBA809E02168AD32A595EEC774CD9FB3CCE98A07F7D5"
			"22E7DA2D910281803F8676D8A01BE37E3E0290EDE3F7029833165D15F466DD33"
			"E7200B132C8E21E8FEF5C8BF9833035E55409F6575ADBA90BDD0BD0EAC4574F2"
			"69B1ABFD789E3CD319140105FA49A7F3877DDAC298FC59C48FB80CA79314AD5F"
			"52FEACC143127682A68246C593962A228A284AAF67FE8358809DA3280F7491A9"
			"9C294A2710BA464A",
			"true"
		}
	};

	for ( auto test : tests ) {
		int res;
		uint8_t pub[1024], priv[2048];
		std::size_t pub_sz = sizeof(pub);
		std::size_t priv_sz = sizeof(priv);
		bool expected = (test[2] == "true");

		res = 0;
		res += Crypto::Utils::from_hex(test[0], pub, pub_sz);
		res += Crypto::Utils::from_hex(test[1], priv, priv_sz);
		EXPECT_EQ(res, 0);

		Crypto::RSA::RSAPublicKey pubKey(pub, pub_sz);
		Crypto::RSA::RSAPrivateKey privKey(priv, priv_sz);

		EXPECT_EQ(Crypto::RSA::is_valid({ pubKey, privKey }), expected);
	}
}
