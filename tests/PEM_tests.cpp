#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Base64.hpp"
#include "crypto/Padding.hpp"
#include "crypto/PEM.hpp"
#include "crypto/Utils.hpp"

TEST(PEM, read_pem)
{
	const std::vector<std::vector<std::string>> tests = {
		{ // No password
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"MIIBOQIBAAJBAO3xuzfdn25wosS2MBekkVJjZ2j0KUHT1+iXyCMYclUe6jpjSbgg\n"
			"lTHh67hKHNTqbf6w8E57poQWMe95vrg7DH0CAwEAAQJAA4duS2nSD4VEJL6+/9rE\n"
			"/P/UbM4SPpOxxBVcNokKSRDg/Tmqu23v4d54zo6Eda37Qu8g/zbI9yYdBCTbtL98\n"
			"AQIhAP8qL5ncipV+FX61+WPG4UdOwf/lMTrzlQNBvrAw4my9AiEA7rkdkx/jFeB6\n"
			"mgneJpEUfeLs2au378u+PeL3JUhZesECIBCv85j+YVnRexpkUEEEOqttLSbNGGEg\n"
			"mPgzjoL7T3OJAiBcH8389+I/kAhgJ4y2X2iECC2U9sKd5Id/BHaRybDWQQIgFsej\n"
			"qJsGpgA5lvH3ckSU5mKXdiI08XznSoDnNZAbl/A=\n"
			"-----END RSA PRIVATE KEY-----\n",
			"",
			"30820139020100024100edf1bb37dd9f6e70a2c4b63017a49152636768f42941"
			"d3d7e897c8231872551eea3a6349b8209531e1ebb84a1cd4ea6dfeb0f04e7ba6"
			"841631ef79beb83b0c7d0203010001024003876e4b69d20f854424bebeffdac4"
			"fcffd46cce123e93b1c4155c36890a4910e0fd39aabb6defe1de78ce8e8475ad"
			"fb42ef20ff36c8f7261d0424dbb4bf7c01022100ff2a2f99dc8a957e157eb5f9"
			"63c6e1474ec1ffe5313af3950341beb030e26cbd022100eeb91d931fe315e07a"
			"9a09de2691147de2ecd9abb7efcbbe3de2f72548597ac1022010aff398fe6159"
			"d17b1a645041043aab6d2d26cd18612098f8338e82fb4f738902205c1fcdfcf7"
			"e23f900860278cb65f6884082d94f6c29de4877f047691c9b0d641022016c7a3"
			"a89b06a6003996f1f7724494e66297762234f17ce74a80e735901b97f0"
		}, { // DES-CBC
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: DES-CBC,E1B8CAB6B7D6912E\n"
			"\n"
			"+rmPSdoXPjx27ZcRq2vrmU2jw03aPEfhpPfkZBrbrgjYhKYFJolUn0kaP757THah\n"
			"XMBQ6tk3M/KAEEWmzVdlVHDGVdGegEtaI5LiEUweLzpIE7mzZBli3h64qoxUjURi\n"
			"7EQWe+2fzQTC5i5uMh0HtTkdl1gczl9LrOwUNAKlkiBNOxQLpipG1MOZh2GTXgBk\n"
			"o82qoKpSoQP45OOfEhyuFJFVpiat02A96+gbnD0M/ZIhJIBIvTVozhsSQlhrgquJ\n"
			"SgoPIBu4ZVw+S0ej/Ps62DD7c2r9gq5E1tw5y8YxB8HRMt6mDTCynJGdyuH4bjI5\n"
			"X86Z1qlOoo7U2LNWU0Zwu39RLh4vdjn9tl5MUgnIVGULnutHK7gd7/EL/RHk10Zr\n"
			"vx+xybxL4FrGbwDQtr/6QjWoZ0KK8P9n+Z0MpNiLRSk=\n"
			"-----END RSA PRIVATE KEY-----\n",
			"DES-CBC",
			"30820139020100024100bec4eea4db5f076d08fa834bb80e305de7c748ba1efc"
			"14f7ca4fd1054d1a4ba20f6c97bce8adc24664271872ca2df3f326384701d3af"
			"602c7a32890f1ca1b8af020301000102400b5ead6281f89df6afac4e9afab34d"
			"caaaffc3a3e428de0f0eadc7256bbcff78e4a0e0feba748edd552053363591e1"
			"afaf951a5b7cc22fb57ba794ca7f994b71022100fd076868b74a610062fc0abd"
			"78283d09cfed2e4fa79ddd4146d5205fa90433cb022100c1025ffc46254addaa"
			"48c96160b286f6e2e4123bfeddf756fd8d5aeaaca61a2d0220263de560d63aee"
			"98315da87de4582889801c77c06033f2c9b7dbe44db0eccaab02206006ac76b8"
			"f788ddec00b6a08a19886880cdf3fc817b31b9c80072015bd0702902206ed701"
			"bdadca215e4ee5331d42324f8e96efd1c4315968a2be1c1b30dacf1d24"
		}, { // DES-EDE3-CBC
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: DES-EDE3-CBC,6EA9947D472B817B\n"
			"\n"
			"86rtK1vZWpK/IsVCL2J41Wwnn8CnnYb4TL1Q/Ch1XwYwYUgiSaNncQXxqklVfd2Y\n"
			"Q5yvtpvUGHBKJ7MKKbQmBFpeKcWuGbH1D9guEDnmnxjmdqyRlCkhUYNosld6TCuI\n"
			"wT5roCB7KfVz8vgj5T/IL0IXNOfE+PQyhAz0NOsMoFmV6DFFZS7u6NzwPyLhQJoE\n"
			"u+XNIgoAkYNM4QZcJIsneu/r3P4muagbmTkPucOKISrUqkT0lq/1DVo1GrX9nVKf\n"
			"zhEvbHJlT4ny43I6IolSbp2FJkOICUOYqNWhBLvOGkymoraGmwsX0EfJtpNjEJd4\n"
			"kpIZRWJPqnO2LaX0PH7mttSf9WdhNtAl1gHuZ4V2znw8f0/DzOGB5QrHZZlNfjeL\n"
			"/UogdgX7nwX4xlc8Bop0+m2rNA1aBQkRHTe8kQ6r5mg=\n"
			"-----END RSA PRIVATE KEY-----\n",
			"DES-EDE3-CBC",
			"3082013a020100024100bd803735035f92d44d047c3ed3fe2d740caa6989da4a"
			"5b9f9b79a350f9609c368b95689cf145040a6a56c8cd8cc4624c2acecb0336f0"
			"c43ef0ae3a34f5699ffb0203010001024100ae82e1d4673bdf9ab5267948deaf"
			"47aa847376e7a5682ec2684a7754fda2b3978d3ab9d06055d6d0fb2d1763806b"
			"cd010e5149b50d3c79a19032395cce313c21022100ea2e09b8fec1aa131cfb84"
			"4ff981c1be5051c1d108811bbc6c32258f63e49ed1022100cf286fab91f2045c"
			"4e4b2af849eb777831a54910f6fc7ce464391f745a8f3d0b022010e6c5b8de5a"
			"27e63d3f41eb6bbc9bb91a9eebf8243efd3b7a2b9c5e5efd4f21022037899db6"
			"9fa004af42864074e44c6e7118ce39328524d7cedb57bd291286485502204013"
			"846f5dc035a82a1ccbaecf0464468337699918fb6ab6e6d23e887318f24b"
		}, { // AES-128-CBC
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: AES-128-CBC,DB1FECFA42F5746785A82673E649BA2C\n"
			"\n"
			"m4XV3MNectM/n6JzhgXavOGnVcj/u5qD0+iZsvyVjTZWjPpV2rhGVSGK/sMCF+OU\n"
			"2pfK4gIhkUPVupI9SjC+fSNelRyyaC4ndC/cp6gvcj5KdjSHCl4tkBVbO/Ov13t2\n"
			"oWDLJ4Tc8X3AU81e57H7hamVNWX9mrsbXjKw2Z7c5tG4NKUOibedUVyZ+iFS1wIy\n"
			"P3e5JX4ih/tbsTak/bliVsjecWPXO4J+tjoAFPTCyATyJ+ey1zpafvJyE/dQmBLF\n"
			"Z2kFDlFRx3mwTsTeiW37IxIW89hVH5DNv3nSp6kA0rf94cIObLL2A2wyNk9Hs/Ko\n"
			"KHYLHtsqWuVcUfEIi+fvBGwX4u7mTbR2bNhSGx/D0iFoGWR70fgV8RVhlbaS12C4\n"
			"aw2V8WvRPDn9PlHQ/JC3biJLEuTRIk+G3jMdeEU9yfKK7tE1XpQ6I6+tMeW4QQ0R\n"
			"-----END RSA PRIVATE KEY-----\n",
			"AES-128-CBC",
			"3082013c020100024100ceb9f7849440dbe89e25aed5d04e2c32480244b5a670"
			"dcb48b9fb810536430a2e047dc08b8ad68cc447c83225e31c6c1ebcf0dee8b7f"
			"4d421d6f2cfcd13fee2f020301000102404138f13bf61e648386e9f2b868e951"
			"0e6823b713ecb86d19d57785f638a942a27f635b96c53a19b750d837944c3090"
			"e82b2be616bf8499f17700a99bb34b4369022100f3ab105291f15d3a4fdc6917"
			"c99adeef2ddd5a849d798eff06e4cc2732448843022100d9304a2e4f6ea3f628"
			"e0ec434358fff4f63a16b9b46f3c3652f2060d9bd349a5022100eeadba9056da"
			"890a6c5da727a0d82dd53524e4dc8ff0194cdfb0cff4f8fd3e47022100aa77d3"
			"919bb8fcaa66157c7ba2edc52090eeb10d9b48bf9ae7e99cc4abace01d022100"
			"f0a33ddf97a09b2c9d7a90684ed9c5148756b387d6e5e8e204e22b563b807540"
		}, { // AES-192-CBC
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: AES-192-CBC,851668740A8196507414BFD12D20C338\n"
			"\n"
			"XiuCFzAX3zEvDGsgp69RqBgCMlb2Rw+ZPBZhVG0QK76LKpHn7YPQZhUd0/9Ucqgx\n"
			"z3Efxut49fmqA+SiD18stb7gJ6zzvxPeMxppLy3mQobLz9MJ9qsgE/6hkwAzl06B\n"
			"M1f4dCuDwycws//sPWdAGLfMexHX8s2r2nKFppgtezkR4ATkuC5UC47OJB7z3QSu\n"
			"jG+xOtncIMcMLSzde/Y+4WRnTdcCm14wYU5lUS1k7TlhgczIlBqtGs2LKkeutvwE\n"
			"9nCE6HRu9giFc1ulPTf5ZZeWNtbtc3f8XROMjjJxqza7inhrSbV67MxCvcTW1cUc\n"
			"VxI+TbZRQV541DjKyllDFH5MCPHUd+N/CCzg6/QPiRM4wljz9XU4kRQQyANm2MrU\n"
			"DwtOyvOYS8DOvxU6I18SlnR/8uo76ai6K7c0T39hw4DdcjHp1rZB1kenunP4rJ7N\n"
			"-----END RSA PRIVATE KEY-----\n",
			"AES-192-CBC",
			"3082013c020100024100e3232909a475514c47938a4f4b5173a39e10d0f9c1a5"
			"48390a830545bc7f334e6a3373aa7e0c0ec388b2ee52deea86f650b96188c61f"
			"31899a22304bc6150973020301000102406ef261bd4003be2e5058151b1e632e"
			"e520f47ddf4163869fb62ec1888ac6673c5eaebb1f34870d9c9f8805fbe0c017"
			"d35e40489049f28a43d493abacf07289a1022100f5969db9bde114f046965955"
			"f5fc9ac7f12714f32ce0198576e739ce9e2d57d5022100ecc44b6288e8126504"
			"b8b40c8fe8312eff1933b9a10766a7dc8a73760db60827022100cf40d34cabe4"
			"66723b6fa866b5d7fe9b5b74fae61969e9bfcb4f696667f0a61d022100c20db8"
			"839016354d5a6b5016a3b3f8ebbde51801e2bb40260099f13c26ccb52d022100"
			"a2abcda197685962372f799cbbf4485558895e01edf275fb7d356f378042660d"
		}, { // AES-256-CBC
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: AES-256-CBC,0410ED48623F4808B7F8A88095B06850\n"
			"\n"
			"UHeB1YIuxwSi+reVBHAVT1DYtaaypVQ1kS7+T4chomIAOckSZ5ArozAyB4d7f/SI\n"
			"3Ltkf1f3gPEFT/qP+ogb3ZRy/Z7R3t6iYgiQruCERlqC4nYIlfN7QAGjN1dsNlzT\n"
			"fePHc4D+wL6ZTWaQ23U1JHMrveYHdIh/eNjQOBkfJd7Mr0sQagfQ2+zTLUv+8swJ\n"
			"yEk5WLbOBB2M4xXmNeWQ+/kSevApEvd3fztDqzXjEw3r7M04dAFdiSWVi0ArBBgj\n"
			"3n/fTCiXXw1lwy8tSa7+kZY5qc/ZA6ljcKotppFMtXAd4s+NnpNGiuURqg3pkjcW\n"
			"zMY+CeFrsB2d0Rz/niBn1xZg44HLsmHCVLnZez8BnA75cI0vAs86BBvjfnD4rH/e\n"
			"LsHIT+pVdovBzzDAlyXCKvloLtB0Blgv4s98G84S+XU=\n"
			"-----END RSA PRIVATE KEY-----\n",
			"AES-256-CBC",
			"3082013b020100024100e13d5f1ba577a4cbb5955835a04709ade691368bf878"
			"dff6241544c9daef4196abd1abb2fa5effbb6143696aaa17d74086732663efd7"
			"587a1c63faf1f23e2db10203010001024100893ab40c8b06d71fc9f540b6037d"
			"e476d0485efc6e996e926faf89a6963e392da7c816abbab3202f2b66fcf39149"
			"d4d79f9abf72c577b99922a01032ff2ade71022100f2cc0df1363b89e90c71f2"
			"cbd2fec13fb4e080aa218283695758d27a3f6f7ca5022100ed7ce74a49a80c5f"
			"2a95dfac7d0f77d196ecf1e565c2327aef2f2f4b9940a31d022042ded49034c1"
			"9d30248f55b1b1811cb4711acc150f79a4bbe4a4c0038f69234902200f58b1ed"
			"8802f701b353ca0770716e71b9ca07fba5eebdaa5a08778af0155035022100ad"
			"cdc35aef3e07ed19f7ccfdfd4ac672cb167eb95ff6cb22bb0fba03df33e232"
		}
	};

	for ( auto test : tests ) {
		int ret;
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string der;

		ret = Crypto::PEM::decode("RSA PRIVATE KEY", test[0], data, data_sz, test[1]);
		EXPECT_EQ(ret, 0);

		Crypto::Utils::to_hex(data, data_sz, der, false);
		EXPECT_THAT(der, test[2]);
	}
}

TEST(PEM, read_pem_abnormal)
{
	// Missing header
	{
		std::string pem = ""
			"MIIBOQIBAAJBAO3xuzfdn25wosS2MBekkVJjZ2j0KUHT1+iXyCMYclUe6jpjSbgg\n"
			"lTHh67hKHNTqbf6w8E57poQWMe95vrg7DH0CAwEAAQJAA4duS2nSD4VEJL6+/9rE\n"
			"/P/UbM4SPpOxxBVcNokKSRDg/Tmqu23v4d54zo6Eda37Qu8g/zbI9yYdBCTbtL98\n"
			"AQIhAP8qL5ncipV+FX61+WPG4UdOwf/lMTrzlQNBvrAw4my9AiEA7rkdkx/jFeB6\n"
			"mgneJpEUfeLs2au378u+PeL3JUhZesECIBCv85j+YVnRexpkUEEEOqttLSbNGGEg\n"
			"mPgzjoL7T3OJAiBcH8389+I/kAhgJ4y2X2iECC2U9sKd5Id/BHaRybDWQQIgFsej\n"
			"qJsGpgA5lvH3ckSU5mKXdiI08XznSoDnNZAbl/A=\n"
			"-----END RSA PRIVATE KEY-----\n";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Missing header";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem,  data, data_sz);

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// Missing new line after header
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----"
			"MIIBOQIBAAJBAO3xuzfdn25wosS2MBekkVJjZ2j0KUHT1+iXyCMYclUe6jpjSbgg\n"
			"lTHh67hKHNTqbf6w8E57poQWMe95vrg7DH0CAwEAAQJAA4duS2nSD4VEJL6+/9rE\n"
			"/P/UbM4SPpOxxBVcNokKSRDg/Tmqu23v4d54zo6Eda37Qu8g/zbI9yYdBCTbtL98\n"
			"AQIhAP8qL5ncipV+FX61+WPG4UdOwf/lMTrzlQNBvrAw4my9AiEA7rkdkx/jFeB6\n"
			"mgneJpEUfeLs2au378u+PeL3JUhZesECIBCv85j+YVnRexpkUEEEOqttLSbNGGEg\n"
			"mPgzjoL7T3OJAiBcH8389+I/kAhgJ4y2X2iECC2U9sKd5Id/BHaRybDWQQIgFsej\n"
			"qJsGpgA5lvH3ckSU5mKXdiI08XznSoDnNZAbl/A=\n"
			"-----END RSA PRIVATE KEY-----\n";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Missing data";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz);

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// Missing footer
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"MIIBOQIBAAJBAO3xuzfdn25wosS2MBekkVJjZ2j0KUHT1+iXyCMYclUe6jpjSbgg\n"
			"lTHh67hKHNTqbf6w8E57poQWMe95vrg7DH0CAwEAAQJAA4duS2nSD4VEJL6+/9rE\n"
			"/P/UbM4SPpOxxBVcNokKSRDg/Tmqu23v4d54zo6Eda37Qu8g/zbI9yYdBCTbtL98\n"
			"AQIhAP8qL5ncipV+FX61+WPG4UdOwf/lMTrzlQNBvrAw4my9AiEA7rkdkx/jFeB6\n"
			"mgneJpEUfeLs2au378u+PeL3JUhZesECIBCv85j+YVnRexpkUEEEOqttLSbNGGEg\n"
			"mPgzjoL7T3OJAiBcH8389+I/kAhgJ4y2X2iECC2U9sKd5Id/BHaRybDWQQIgFsej\n"
			"qJsGpgA5lvH3ckSU5mKXdiI08XznSoDnNZAbl/A=\n"
			"";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Missing footer";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz);

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// Missing new line before footer
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"MIIBOQIBAAJBAO3xuzfdn25wosS2MBekkVJjZ2j0KUHT1+iXyCMYclUe6jpjSbgg\n"
			"lTHh67hKHNTqbf6w8E57poQWMe95vrg7DH0CAwEAAQJAA4duS2nSD4VEJL6+/9rE\n"
			"/P/UbM4SPpOxxBVcNokKSRDg/Tmqu23v4d54zo6Eda37Qu8g/zbI9yYdBCTbtL98\n"
			"AQIhAP8qL5ncipV+FX61+WPG4UdOwf/lMTrzlQNBvrAw4my9AiEA7rkdkx/jFeB6\n"
			"mgneJpEUfeLs2au378u+PeL3JUhZesECIBCv85j+YVnRexpkUEEEOqttLSbNGGEg\n"
			"mPgzjoL7T3OJAiBcH8389+I/kAhgJ4y2X2iECC2U9sKd5Id/BHaRybDWQQIgFsej\n"
			"qJsGpgA5lvH3ckSU5mKXdiI08XznSoDnNZAbl/A="
			"-----END RSA PRIVATE KEY-----";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Missing footer";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz);

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// Line is more than 80 characters
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"MIIBOQIBAAJBAO3xuzfdn25wosS2MBekkVJjZ2j0KUHT1+iXyCMYclUe6jpjSbgg\n"
			"lTHh67hKHNTqbf6w8E57poQWMe95vrg7DH0CAwEAAQJAA4duS2nSD4VEJL6+/9rE\n"
			"/P/UbM4SPpOxxBVcNokKSRDg/Tmqu23v4d54zo6Eda37Qu8g/zbI9yYdBCTbtL98AQIhAP8qL5ncipV+\n"
			"FX61+WPG4UdOwf/lMTrzlQNBvrAw4my9AiEA7rkdkx/jFeB6\n"
			"mgneJpEUfeLs2au378u+PeL3JUhZesECIBCv85j+YVnRexpkUEEEOqttLSbNGGEg\n"
			"mPgzjoL7T3OJAiBcH8389+I/kAhgJ4y2X2iECC2U9sKd5Id/BHaRybDWQQIgFsej\n"
			"qJsGpgA5lvH3ckSU5mKXdiI08XznSoDnNZAbl/A=\n"
			"-----END RSA PRIVATE KEY-----";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Line is longer than 80 characters";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz);

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// Invalid length
	{
		int res;
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"MIIBOQIBAAJBAO3xuzfdn25wosS2MBekkVJjZ2j0KUHT1+iXyCMYclUe6jpjSbgg\n"
			"lTHh67hKHNTqbf6w8E57poQWMe95vrg7DH0CAwEAAQJAA4duS2nSD4VEJL6+/9rE\n"
			"/P/UbM4SPpOxxBVcNokKSRDg/Tmqu23v4d54zo6Eda37Qu8g/zbI9yYdBCTbtL98\n"
			"AQIhAP8qL5ncipV+FX61+WPG4UdOwf/lMTrzlQNBvrAw4my9AiEA7rkdkx/jFeB6\n"
			"mgneJpEUfeLs2au378u+PeL3JUhZesECIBCv85j+YVnRexpkUEEEOqttLSbNGGEg\n"
			"mPgzjoL7T3OJAiBcH8389+I/kAhgJ4y2X2iECC2U9sKd5Id/BHaRybDWQQIgFsej\n"
			"qJsGpgA5lvH3ckSU5mKXdiI08XznSoDnNZAbl/A=\n"
			"-----END RSA PRIVATE KEY-----";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);

		data_sz = 100;
		res = Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz);
		EXPECT_EQ(res, 1);
		EXPECT_EQ(((int)data_sz), 317);
	}

	// Invalid Base64 characters
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"MIIBOQIBAAJBAO3xuzfdn25wosS2MBekkVJjZ2j0KUHT1+iXyCMYclUe6jpjSbgg\n"
			"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n"
			"/P/UbM4SPpOxxBVcNokKSRDg/Tmqu23v4d54zo6Eda37Qu8g/zbI9yYdBCTbtL98\n"
			"AQIhAP8qL5ncipV+FX61+WPG4UdOwf/lMTrzlQNBvrAw4my9AiEA7rkdkx/jFeB6\n"
			"mgneJpEUfeLs2au378u+PeL3JUhZesECIBCv85j+YVnRexpkUEEEOqttLSbNGGEg\n"
			"mPgzjoL7T3OJAiBcH8389+I/kAhgJ4y2X2iECC2U9sKd5Id/BHaRybDWQQIgFsej\n"
			"qJsGpgA5lvH3ckSU5mKXdiI08XznSoDnNZAbl/A=\n"
			"-----END RSA PRIVATE KEY-----\n";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid character";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem,  data, data_sz);

			FAIL() << "Expected: Base64::Exception";
		} catch ( const Crypto::Base64::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// No new line after Proc-Type
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED"
			"DEK-Info: DES-CBC,E1B8CAB6B7D6912E\n"
			"\n"
			"+rmPSdoXPjx27ZcRq2vrmU2jw03aPEfhpPfkZBrbrgjYhKYFJolUn0kaP757THah\n"
			"XMBQ6tk3M/KAEEWmzVdlVHDGVdGegEtaI5LiEUweLzpIE7mzZBli3h64qoxUjURi\n"
			"7EQWe+2fzQTC5i5uMh0HtTkdl1gczl9LrOwUNAKlkiBNOxQLpipG1MOZh2GTXgBk\n"
			"o82qoKpSoQP45OOfEhyuFJFVpiat02A96+gbnD0M/ZIhJIBIvTVozhsSQlhrgquJ\n"
			"SgoPIBu4ZVw+S0ej/Ps62DD7c2r9gq5E1tw5y8YxB8HRMt6mDTCynJGdyuH4bjI5\n"
			"X86Z1qlOoo7U2LNWU0Zwu39RLh4vdjn9tl5MUgnIVGULnutHK7gd7/EL/RHk10Zr\n"
			"vx+xybxL4FrGbwDQtr/6QjWoZ0KK8P9n+Z0MpNiLRSk=\n"
			"-----END RSA PRIVATE KEY-----\n";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Missing metadata";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz, "DES-CBC");

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// No metadata
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"\n"
			"+rmPSdoXPjx27ZcRq2vrmU2jw03aPEfhpPfkZBrbrgjYhKYFJolUn0kaP757THah\n"
			"XMBQ6tk3M/KAEEWmzVdlVHDGVdGegEtaI5LiEUweLzpIE7mzZBli3h64qoxUjURi\n"
			"7EQWe+2fzQTC5i5uMh0HtTkdl1gczl9LrOwUNAKlkiBNOxQLpipG1MOZh2GTXgBk\n"
			"o82qoKpSoQP45OOfEhyuFJFVpiat02A96+gbnD0M/ZIhJIBIvTVozhsSQlhrgquJ\n"
			"SgoPIBu4ZVw+S0ej/Ps62DD7c2r9gq5E1tw5y8YxB8HRMt6mDTCynJGdyuH4bjI5\n"
			"X86Z1qlOoo7U2LNWU0Zwu39RLh4vdjn9tl5MUgnIVGULnutHK7gd7/EL/RHk10Zr\n"
			"vx+xybxL4FrGbwDQtr/6QjWoZ0KK8P9n+Z0MpNiLRSk=\n"
			"-----END RSA PRIVATE KEY-----\n";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Missing metadata";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz, "DES-CBC");

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// No new line after metadata
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: DES-CBC,E1B8CAB6B7D6912E"
			""
			"+rmPSdoXPjx27ZcRq2vrmU2jw03aPEfhpPfkZBrbrgjYhKYFJolUn0kaP757THah\n"
			"XMBQ6tk3M/KAEEWmzVdlVHDGVdGegEtaI5LiEUweLzpIE7mzZBli3h64qoxUjURi\n"
			"7EQWe+2fzQTC5i5uMh0HtTkdl1gczl9LrOwUNAKlkiBNOxQLpipG1MOZh2GTXgBk\n"
			"o82qoKpSoQP45OOfEhyuFJFVpiat02A96+gbnD0M/ZIhJIBIvTVozhsSQlhrgquJ\n"
			"SgoPIBu4ZVw+S0ej/Ps62DD7c2r9gq5E1tw5y8YxB8HRMt6mDTCynJGdyuH4bjI5\n"
			"X86Z1qlOoo7U2LNWU0Zwu39RLh4vdjn9tl5MUgnIVGULnutHK7gd7/EL/RHk10Zr\n"
			"vx+xybxL4FrGbwDQtr/6QjWoZ0KK8P9n+Z0MpNiLRSk=\n"
			"-----END RSA PRIVATE KEY-----\n";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Missing metadata";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz, "DES-CBC");

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// No second new line after metadata
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: DES-CBC,E1B8CAB6B7D6912E\n"
			""
			"+rmPSdoXPjx27ZcRq2vrmU2jw03aPEfhpPfkZBrbrgjYhKYFJolUn0kaP757THah\n"
			"XMBQ6tk3M/KAEEWmzVdlVHDGVdGegEtaI5LiEUweLzpIE7mzZBli3h64qoxUjURi\n"
			"7EQWe+2fzQTC5i5uMh0HtTkdl1gczl9LrOwUNAKlkiBNOxQLpipG1MOZh2GTXgBk\n"
			"o82qoKpSoQP45OOfEhyuFJFVpiat02A96+gbnD0M/ZIhJIBIvTVozhsSQlhrgquJ\n"
			"SgoPIBu4ZVw+S0ej/Ps62DD7c2r9gq5E1tw5y8YxB8HRMt6mDTCynJGdyuH4bjI5\n"
			"X86Z1qlOoo7U2LNWU0Zwu39RLh4vdjn9tl5MUgnIVGULnutHK7gd7/EL/RHk10Zr\n"
			"vx+xybxL4FrGbwDQtr/6QjWoZ0KK8P9n+Z0MpNiLRSk=\n"
			"-----END RSA PRIVATE KEY-----\n";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Missing metadata";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz, "DES-CBC");

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// Unsupported encryption Algorithm
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: AES-128-CTR,E1B8CAB6B7D6912E\n"
			"\n"
			"+rmPSdoXPjx27ZcRq2vrmU2jw03aPEfhpPfkZBrbrgjYhKYFJolUn0kaP757THah\n"
			"XMBQ6tk3M/KAEEWmzVdlVHDGVdGegEtaI5LiEUweLzpIE7mzZBli3h64qoxUjURi\n"
			"7EQWe+2fzQTC5i5uMh0HtTkdl1gczl9LrOwUNAKlkiBNOxQLpipG1MOZh2GTXgBk\n"
			"o82qoKpSoQP45OOfEhyuFJFVpiat02A96+gbnD0M/ZIhJIBIvTVozhsSQlhrgquJ\n"
			"SgoPIBu4ZVw+S0ej/Ps62DD7c2r9gq5E1tw5y8YxB8HRMt6mDTCynJGdyuH4bjI5\n"
			"X86Z1qlOoo7U2LNWU0Zwu39RLh4vdjn9tl5MUgnIVGULnutHK7gd7/EL/RHk10Zr\n"
			"vx+xybxL4FrGbwDQtr/6QjWoZ0KK8P9n+Z0MpNiLRSk=\n"
			"-----END RSA PRIVATE KEY-----\n";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Encryption algorithm not supported";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz, "DES-CBC");

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// DES-CBC Invalid IV
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: DES-CBC,E1B8CAB6B7D691\n"
			"\n"
			"+rmPSdoXPjx27ZcRq2vrmU2jw03aPEfhpPfkZBrbrgjYhKYFJolUn0kaP757THah\n"
			"XMBQ6tk3M/KAEEWmzVdlVHDGVdGegEtaI5LiEUweLzpIE7mzZBli3h64qoxUjURi\n"
			"7EQWe+2fzQTC5i5uMh0HtTkdl1gczl9LrOwUNAKlkiBNOxQLpipG1MOZh2GTXgBk\n"
			"o82qoKpSoQP45OOfEhyuFJFVpiat02A96+gbnD0M/ZIhJIBIvTVozhsSQlhrgquJ\n"
			"SgoPIBu4ZVw+S0ej/Ps62DD7c2r9gq5E1tw5y8YxB8HRMt6mDTCynJGdyuH4bjI5\n"
			"X86Z1qlOoo7U2LNWU0Zwu39RLh4vdjn9tl5MUgnIVGULnutHK7gd7/EL/RHk10Zr\n"
			"vx+xybxL4FrGbwDQtr/6QjWoZ0KK8P9n+Z0MpNiLRSk=\n"
			"-----END RSA PRIVATE KEY-----\n";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "IV malformed";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz, "DES-CBC");

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// DES-EDE3-CBC Invalid IV
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: DES-EDE3-CBC,6EA9947D472B81\n"
			"\n"
			"86rtK1vZWpK/IsVCL2J41Wwnn8CnnYb4TL1Q/Ch1XwYwYUgiSaNncQXxqklVfd2Y\n"
			"Q5yvtpvUGHBKJ7MKKbQmBFpeKcWuGbH1D9guEDnmnxjmdqyRlCkhUYNosld6TCuI\n"
			"wT5roCB7KfVz8vgj5T/IL0IXNOfE+PQyhAz0NOsMoFmV6DFFZS7u6NzwPyLhQJoE\n"
			"u+XNIgoAkYNM4QZcJIsneu/r3P4muagbmTkPucOKISrUqkT0lq/1DVo1GrX9nVKf\n"
			"zhEvbHJlT4ny43I6IolSbp2FJkOICUOYqNWhBLvOGkymoraGmwsX0EfJtpNjEJd4\n"
			"kpIZRWJPqnO2LaX0PH7mttSf9WdhNtAl1gHuZ4V2znw8f0/DzOGB5QrHZZlNfjeL\n"
			"/UogdgX7nwX4xlc8Bop0+m2rNA1aBQkRHTe8kQ6r5mg=\n"
			"-----END RSA PRIVATE KEY-----\n";
			uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "IV malformed";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz, "DES-EDE3-CBC");

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// AES-128-CBC Invalid IV
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: AES-128-CBC,DB1FECFA42F5746785A82673E649BA\n"
			"\n"
			"m4XV3MNectM/n6JzhgXavOGnVcj/u5qD0+iZsvyVjTZWjPpV2rhGVSGK/sMCF+OU\n"
			"2pfK4gIhkUPVupI9SjC+fSNelRyyaC4ndC/cp6gvcj5KdjSHCl4tkBVbO/Ov13t2\n"
			"oWDLJ4Tc8X3AU81e57H7hamVNWX9mrsbXjKw2Z7c5tG4NKUOibedUVyZ+iFS1wIy\n"
			"P3e5JX4ih/tbsTak/bliVsjecWPXO4J+tjoAFPTCyATyJ+ey1zpafvJyE/dQmBLF\n"
			"Z2kFDlFRx3mwTsTeiW37IxIW89hVH5DNv3nSp6kA0rf94cIObLL2A2wyNk9Hs/Ko\n"
			"KHYLHtsqWuVcUfEIi+fvBGwX4u7mTbR2bNhSGx/D0iFoGWR70fgV8RVhlbaS12C4\n"
			"aw2V8WvRPDn9PlHQ/JC3biJLEuTRIk+G3jMdeEU9yfKK7tE1XpQ6I6+tMeW4QQ0R\n"
			"-----END RSA PRIVATE KEY-----\n";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "IV malformed";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz, "AES-128-CBC");

			FAIL() << "Expected: PEM::Exception";
		} catch ( const Crypto::PEM::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}

	// Padding malformed (wrong password)
	{
		std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: AES-128-CBC,DB1FECFA42F5746785A82673E649BA2C\n"
			"\n"
			"m4XV3MNectM/n6JzhgXavOGnVcj/u5qD0+iZsvyVjTZWjPpV2rhGVSGK/sMCF+OU\n"
			"2pfK4gIhkUPVupI9SjC+fSNelRyyaC4ndC/cp6gvcj5KdjSHCl4tkBVbO/Ov13t2\n"
			"oWDLJ4Tc8X3AU81e57H7hamVNWX9mrsbXjKw2Z7c5tG4NKUOibedUVyZ+iFS1wIy\n"
			"P3e5JX4ih/tbsTak/bliVsjecWPXO4J+tjoAFPTCyATyJ+ey1zpafvJyE/dQmBLF\n"
			"Z2kFDlFRx3mwTsTeiW37IxIW89hVH5DNv3nSp6kA0rf94cIObLL2A2wyNk9Hs/Ko\n"
			"KHYLHtsqWuVcUfEIi+fvBGwX4u7mTbR2bNhSGx/D0iFoGWR70fgV8RVhlbaS12C4\n"
			"aw2V8WvRPDn9PlHQ/JC3biJLEuTRIk+G3jMdeEU9yfKK7tE1XpQ6I6+tMeW4QQ0R\n"
			"-----END RSA PRIVATE KEY-----\n";
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string expected = "Invalid padding";

		try {
			Crypto::PEM::decode("RSA PRIVATE KEY", pem, data, data_sz, "AES-128-CBC-WRONG");

			FAIL() << "Expected: Padding::Exception";
		} catch ( const Crypto::Padding::Exception &pe ) {
			EXPECT_EQ(pe.what(), expected);
		}
	}
}

TEST(PEM, write_pem)
{
	const std::vector<std::vector<std::string>> tests = {
		{ // Zero data
			"",
			"",
			"",
			"",
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"-----END RSA PRIVATE KEY-----\n"
		}, { // One byte
			"00",
			"",
			"",
			"",
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"AA==\n"
			"-----END RSA PRIVATE KEY-----\n"
		}, { // No password
			"30820139020100024100edf1bb37dd9f6e70a2c4b63017a49152636768f42941"
			"d3d7e897c8231872551eea3a6349b8209531e1ebb84a1cd4ea6dfeb0f04e7ba6"
			"841631ef79beb83b0c7d0203010001024003876e4b69d20f854424bebeffdac4"
			"fcffd46cce123e93b1c4155c36890a4910e0fd39aabb6defe1de78ce8e8475ad"
			"fb42ef20ff36c8f7261d0424dbb4bf7c01022100ff2a2f99dc8a957e157eb5f9"
			"63c6e1474ec1ffe5313af3950341beb030e26cbd022100eeb91d931fe315e07a"
			"9a09de2691147de2ecd9abb7efcbbe3de2f72548597ac1022010aff398fe6159"
			"d17b1a645041043aab6d2d26cd18612098f8338e82fb4f738902205c1fcdfcf7"
			"e23f900860278cb65f6884082d94f6c29de4877f047691c9b0d641022016c7a3"
			"a89b06a6003996f1f7724494e66297762234f17ce74a80e735901b97f0",
			"",
			"",
			"",
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"MIIBOQIBAAJBAO3xuzfdn25wosS2MBekkVJjZ2j0KUHT1+iXyCMYclUe6jpjSbgg\n"
			"lTHh67hKHNTqbf6w8E57poQWMe95vrg7DH0CAwEAAQJAA4duS2nSD4VEJL6+/9rE\n"
			"/P/UbM4SPpOxxBVcNokKSRDg/Tmqu23v4d54zo6Eda37Qu8g/zbI9yYdBCTbtL98\n"
			"AQIhAP8qL5ncipV+FX61+WPG4UdOwf/lMTrzlQNBvrAw4my9AiEA7rkdkx/jFeB6\n"
			"mgneJpEUfeLs2au378u+PeL3JUhZesECIBCv85j+YVnRexpkUEEEOqttLSbNGGEg\n"
			"mPgzjoL7T3OJAiBcH8389+I/kAhgJ4y2X2iECC2U9sKd5Id/BHaRybDWQQIgFsej\n"
			"qJsGpgA5lvH3ckSU5mKXdiI08XznSoDnNZAbl/A=\n"
			"-----END RSA PRIVATE KEY-----\n"
		}, { // DES-CBC
			"30820139020100024100bec4eea4db5f076d08fa834bb80e305de7c748ba1efc"
			"14f7ca4fd1054d1a4ba20f6c97bce8adc24664271872ca2df3f326384701d3af"
			"602c7a32890f1ca1b8af020301000102400b5ead6281f89df6afac4e9afab34d"
			"caaaffc3a3e428de0f0eadc7256bbcff78e4a0e0feba748edd552053363591e1"
			"afaf951a5b7cc22fb57ba794ca7f994b71022100fd076868b74a610062fc0abd"
			"78283d09cfed2e4fa79ddd4146d5205fa90433cb022100c1025ffc46254addaa"
			"48c96160b286f6e2e4123bfeddf756fd8d5aeaaca61a2d0220263de560d63aee"
			"98315da87de4582889801c77c06033f2c9b7dbe44db0eccaab02206006ac76b8"
			"f788ddec00b6a08a19886880cdf3fc817b31b9c80072015bd0702902206ed701"
			"bdadca215e4ee5331d42324f8e96efd1c4315968a2be1c1b30dacf1d24",
			"DES-CBC",
			"DES-CBC",
			"E1B8CAB6B7D6912E",
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: DES-CBC,E1B8CAB6B7D6912E\n"
			"\n"
			"+rmPSdoXPjx27ZcRq2vrmU2jw03aPEfhpPfkZBrbrgjYhKYFJolUn0kaP757THah\n"
			"XMBQ6tk3M/KAEEWmzVdlVHDGVdGegEtaI5LiEUweLzpIE7mzZBli3h64qoxUjURi\n"
			"7EQWe+2fzQTC5i5uMh0HtTkdl1gczl9LrOwUNAKlkiBNOxQLpipG1MOZh2GTXgBk\n"
			"o82qoKpSoQP45OOfEhyuFJFVpiat02A96+gbnD0M/ZIhJIBIvTVozhsSQlhrgquJ\n"
			"SgoPIBu4ZVw+S0ej/Ps62DD7c2r9gq5E1tw5y8YxB8HRMt6mDTCynJGdyuH4bjI5\n"
			"X86Z1qlOoo7U2LNWU0Zwu39RLh4vdjn9tl5MUgnIVGULnutHK7gd7/EL/RHk10Zr\n"
			"vx+xybxL4FrGbwDQtr/6QjWoZ0KK8P9n+Z0MpNiLRSk=\n"
			"-----END RSA PRIVATE KEY-----\n"
		}, { // DES-EDE3-CBC
			"3082013a020100024100bd803735035f92d44d047c3ed3fe2d740caa6989da4a"
			"5b9f9b79a350f9609c368b95689cf145040a6a56c8cd8cc4624c2acecb0336f0"
			"c43ef0ae3a34f5699ffb0203010001024100ae82e1d4673bdf9ab5267948deaf"
			"47aa847376e7a5682ec2684a7754fda2b3978d3ab9d06055d6d0fb2d1763806b"
			"cd010e5149b50d3c79a19032395cce313c21022100ea2e09b8fec1aa131cfb84"
			"4ff981c1be5051c1d108811bbc6c32258f63e49ed1022100cf286fab91f2045c"
			"4e4b2af849eb777831a54910f6fc7ce464391f745a8f3d0b022010e6c5b8de5a"
			"27e63d3f41eb6bbc9bb91a9eebf8243efd3b7a2b9c5e5efd4f21022037899db6"
			"9fa004af42864074e44c6e7118ce39328524d7cedb57bd291286485502204013"
			"846f5dc035a82a1ccbaecf0464468337699918fb6ab6e6d23e887318f24b",
			"DES-EDE3-CBC",
			"DES-EDE3-CBC",
			"6EA9947D472B817B",
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: DES-EDE3-CBC,6EA9947D472B817B\n"
			"\n"
			"86rtK1vZWpK/IsVCL2J41Wwnn8CnnYb4TL1Q/Ch1XwYwYUgiSaNncQXxqklVfd2Y\n"
			"Q5yvtpvUGHBKJ7MKKbQmBFpeKcWuGbH1D9guEDnmnxjmdqyRlCkhUYNosld6TCuI\n"
			"wT5roCB7KfVz8vgj5T/IL0IXNOfE+PQyhAz0NOsMoFmV6DFFZS7u6NzwPyLhQJoE\n"
			"u+XNIgoAkYNM4QZcJIsneu/r3P4muagbmTkPucOKISrUqkT0lq/1DVo1GrX9nVKf\n"
			"zhEvbHJlT4ny43I6IolSbp2FJkOICUOYqNWhBLvOGkymoraGmwsX0EfJtpNjEJd4\n"
			"kpIZRWJPqnO2LaX0PH7mttSf9WdhNtAl1gHuZ4V2znw8f0/DzOGB5QrHZZlNfjeL\n"
			"/UogdgX7nwX4xlc8Bop0+m2rNA1aBQkRHTe8kQ6r5mg=\n"
			"-----END RSA PRIVATE KEY-----\n"
		}, { // AES-128-CBC
			"3082013c020100024100ceb9f7849440dbe89e25aed5d04e2c32480244b5a670"
			"dcb48b9fb810536430a2e047dc08b8ad68cc447c83225e31c6c1ebcf0dee8b7f"
			"4d421d6f2cfcd13fee2f020301000102404138f13bf61e648386e9f2b868e951"
			"0e6823b713ecb86d19d57785f638a942a27f635b96c53a19b750d837944c3090"
			"e82b2be616bf8499f17700a99bb34b4369022100f3ab105291f15d3a4fdc6917"
			"c99adeef2ddd5a849d798eff06e4cc2732448843022100d9304a2e4f6ea3f628"
			"e0ec434358fff4f63a16b9b46f3c3652f2060d9bd349a5022100eeadba9056da"
			"890a6c5da727a0d82dd53524e4dc8ff0194cdfb0cff4f8fd3e47022100aa77d3"
			"919bb8fcaa66157c7ba2edc52090eeb10d9b48bf9ae7e99cc4abace01d022100"
			"f0a33ddf97a09b2c9d7a90684ed9c5148756b387d6e5e8e204e22b563b807540",
			"AES-128-CBC",
			"AES-128-CBC",
			"DB1FECFA42F5746785A82673E649BA2C",
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: AES-128-CBC,DB1FECFA42F5746785A82673E649BA2C\n"
			"\n"
			"m4XV3MNectM/n6JzhgXavOGnVcj/u5qD0+iZsvyVjTZWjPpV2rhGVSGK/sMCF+OU\n"
			"2pfK4gIhkUPVupI9SjC+fSNelRyyaC4ndC/cp6gvcj5KdjSHCl4tkBVbO/Ov13t2\n"
			"oWDLJ4Tc8X3AU81e57H7hamVNWX9mrsbXjKw2Z7c5tG4NKUOibedUVyZ+iFS1wIy\n"
			"P3e5JX4ih/tbsTak/bliVsjecWPXO4J+tjoAFPTCyATyJ+ey1zpafvJyE/dQmBLF\n"
			"Z2kFDlFRx3mwTsTeiW37IxIW89hVH5DNv3nSp6kA0rf94cIObLL2A2wyNk9Hs/Ko\n"
			"KHYLHtsqWuVcUfEIi+fvBGwX4u7mTbR2bNhSGx/D0iFoGWR70fgV8RVhlbaS12C4\n"
			"aw2V8WvRPDn9PlHQ/JC3biJLEuTRIk+G3jMdeEU9yfKK7tE1XpQ6I6+tMeW4QQ0R\n"
			"-----END RSA PRIVATE KEY-----\n"
		}, { // AES-192-CBC
			"3082013c020100024100e3232909a475514c47938a4f4b5173a39e10d0f9c1a5"
			"48390a830545bc7f334e6a3373aa7e0c0ec388b2ee52deea86f650b96188c61f"
			"31899a22304bc6150973020301000102406ef261bd4003be2e5058151b1e632e"
			"e520f47ddf4163869fb62ec1888ac6673c5eaebb1f34870d9c9f8805fbe0c017"
			"d35e40489049f28a43d493abacf07289a1022100f5969db9bde114f046965955"
			"f5fc9ac7f12714f32ce0198576e739ce9e2d57d5022100ecc44b6288e8126504"
			"b8b40c8fe8312eff1933b9a10766a7dc8a73760db60827022100cf40d34cabe4"
			"66723b6fa866b5d7fe9b5b74fae61969e9bfcb4f696667f0a61d022100c20db8"
			"839016354d5a6b5016a3b3f8ebbde51801e2bb40260099f13c26ccb52d022100"
			"a2abcda197685962372f799cbbf4485558895e01edf275fb7d356f378042660d",
			"AES-192-CBC",
			"AES-192-CBC",
			"851668740A8196507414BFD12D20C338",
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: AES-192-CBC,851668740A8196507414BFD12D20C338\n"
			"\n"
			"XiuCFzAX3zEvDGsgp69RqBgCMlb2Rw+ZPBZhVG0QK76LKpHn7YPQZhUd0/9Ucqgx\n"
			"z3Efxut49fmqA+SiD18stb7gJ6zzvxPeMxppLy3mQobLz9MJ9qsgE/6hkwAzl06B\n"
			"M1f4dCuDwycws//sPWdAGLfMexHX8s2r2nKFppgtezkR4ATkuC5UC47OJB7z3QSu\n"
			"jG+xOtncIMcMLSzde/Y+4WRnTdcCm14wYU5lUS1k7TlhgczIlBqtGs2LKkeutvwE\n"
			"9nCE6HRu9giFc1ulPTf5ZZeWNtbtc3f8XROMjjJxqza7inhrSbV67MxCvcTW1cUc\n"
			"VxI+TbZRQV541DjKyllDFH5MCPHUd+N/CCzg6/QPiRM4wljz9XU4kRQQyANm2MrU\n"
			"DwtOyvOYS8DOvxU6I18SlnR/8uo76ai6K7c0T39hw4DdcjHp1rZB1kenunP4rJ7N\n"
			"-----END RSA PRIVATE KEY-----\n"
		}, { // AES-256-CBC
			"3082013b020100024100e13d5f1ba577a4cbb5955835a04709ade691368bf878"
			"dff6241544c9daef4196abd1abb2fa5effbb6143696aaa17d74086732663efd7"
			"587a1c63faf1f23e2db10203010001024100893ab40c8b06d71fc9f540b6037d"
			"e476d0485efc6e996e926faf89a6963e392da7c816abbab3202f2b66fcf39149"
			"d4d79f9abf72c577b99922a01032ff2ade71022100f2cc0df1363b89e90c71f2"
			"cbd2fec13fb4e080aa218283695758d27a3f6f7ca5022100ed7ce74a49a80c5f"
			"2a95dfac7d0f77d196ecf1e565c2327aef2f2f4b9940a31d022042ded49034c1"
			"9d30248f55b1b1811cb4711acc150f79a4bbe4a4c0038f69234902200f58b1ed"
			"8802f701b353ca0770716e71b9ca07fba5eebdaa5a08778af0155035022100ad"
			"cdc35aef3e07ed19f7ccfdfd4ac672cb167eb95ff6cb22bb0fba03df33e232",
			"AES-256-CBC",
			"AES-256-CBC",
			"0410ED48623F4808B7F8A88095B06850",
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"Proc-Type: 4,ENCRYPTED\n"
			"DEK-Info: AES-256-CBC,0410ED48623F4808B7F8A88095B06850\n"
			"\n"
			"UHeB1YIuxwSi+reVBHAVT1DYtaaypVQ1kS7+T4chomIAOckSZ5ArozAyB4d7f/SI\n"
			"3Ltkf1f3gPEFT/qP+ogb3ZRy/Z7R3t6iYgiQruCERlqC4nYIlfN7QAGjN1dsNlzT\n"
			"fePHc4D+wL6ZTWaQ23U1JHMrveYHdIh/eNjQOBkfJd7Mr0sQagfQ2+zTLUv+8swJ\n"
			"yEk5WLbOBB2M4xXmNeWQ+/kSevApEvd3fztDqzXjEw3r7M04dAFdiSWVi0ArBBgj\n"
			"3n/fTCiXXw1lwy8tSa7+kZY5qc/ZA6ljcKotppFMtXAd4s+NnpNGiuURqg3pkjcW\n"
			"zMY+CeFrsB2d0Rz/niBn1xZg44HLsmHCVLnZez8BnA75cI0vAs86BBvjfnD4rH/e\n"
			"LsHIT+pVdovBzzDAlyXCKvloLtB0Blgv4s98G84S+XU=\n"
			"-----END RSA PRIVATE KEY-----\n"
		}
	};

	for ( auto test : tests ) {
		int ret;
		uint8_t data[1024];
		std::size_t data_sz = sizeof(data);
		std::string pem = "";

		Crypto::Utils::from_hex(test[0], data, data_sz);
		ret = Crypto::PEM::encode("RSA PRIVATE KEY", data, data_sz, pem,
				test[1], test[2], test[3]);
		EXPECT_EQ(ret, 0);

		EXPECT_THAT(pem, test[4]);
	}
}
