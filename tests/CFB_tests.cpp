#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/AES.hpp"
#include "crypto/CFB.hpp"

TEST(CFB8, encrypt_test_vector)
{
	int res;
	const std::vector<std::vector<std::string>> test = {
		{
			"c57d699d89df7cfbef71c080a6b10ac3",
			"fcb2bc4c006b87483978796a2ae2c42e",
			"61",
			"24"
		}, {
			"0d8f3dc3edee60db658bb97faf46fba3",
			"e481fdc42e606b96a383c0a1a5520ebb",
			"aacd",
			"5066"
		}, {
			"c8fe9bf77b930f46d2078b8c0e657cd4",
			"f475c64991b20eaee183a22629e21e22",
			"c90635",
			"d27691"
		}, {
			"280cf81af5cc7e7363579c1da03390e6",
			"5d6cf4722d0e21f1d9ced53a0e36c342",
			"b2a22ced",
			"73f3aebf"
		}, {
			"5d5e7f20e0a66d3e09e0e5a9912f8a46",
			"052d7ea0ad1f2956a23b27afe1d87b6b",
			"b84a90fc6d",
			"1a9a61c307"
		}, {
			"ec89fb348787cf902ca973c47081438d",
			"528fe95c711bd13f37bc52cc9e96d45c",
			"14253472e99d",
			"cfc247e33a3b"
		}, {
			"6607987c354809cba818639dcd185147",
			"552c101a0b7c0ca143af258453937fa3",
			"9b1a5a1369166e",
			"b7ab2a4cc71904"
		}, {
			"c028e6bf2b749ffa86759f2f84e93cb0",
			"288c752d9faccf367e5d0cca1fa6ec3b",
			"324015878cdc82bf",
			"873250152fc6a5bb"
		}, {
			"d01da95d2c2a61da06ea78cfba59cc30",
			"f9a393ad90814faf262e3a5b1d97592e",
			"57c1a30e48166d9640",
			"e9a8c3b776edd39e3d"
		}, {
			"3a6f9159263fa6cef2a075caface5817",
			"0fc23662b7dbf73827f0c7de321ca36e",
			"87efeb8d559ed3367728",
			"8e9c50425614d540ce11"
		}
	};

	for ( std::size_t i = 0 ; i < test.size() ; ++i ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t iv[16];
		std::size_t iv_sz = sizeof(iv);

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t plain_sz = sizeof(plain);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t cipher_sz = sizeof(cipher);
		std::string ciphertext;

		Crypto::Utils::from_hex(test[i][0], key,   key_sz);
		Crypto::Utils::from_hex(test[i][1], iv,    iv_sz);
		Crypto::Utils::from_hex(test[i][2], plain, plain_sz);

		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, true);

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
		EXPECT_THAT(ciphertext, test[i][3]);
	}
}

TEST(CFB8, decrypt_test_vector)
{
	int res;
	const std::vector<std::vector<std::string>> test = {
		{
			"03edfe082550bd5ac8ddf64f42a0547f",
			"52acd8dab62c981da08e51939cc08dab",
			"21",
			"09"
		}, {
			"38cf776750162edc63c3b5dbe311ab9f",
			"98fbbd288872c40f1926b16ecaec1561",
			"4878",
			"eb24"
		}, {
			"c9053c87c3e56bc5e52bd31f6545f991",
			"b8f9640d0923da13fe6eb87b01f0cfa0",
			"aeb6d2",
			"910949"
		}, {
			"e96771f5f20a89ee871261d2d18e1e46",
			"6e86403e33396655907ae06ef192262f",
			"83cab2f3",
			"3b7f1f1c"
		}, {
			"92ad13ecb60bde1bb3b34ce07867672b",
			"f95a4060b8f80e3f839d4c3ca33dad94",
			"49f73e652b",
			"17b9b9e16d"
		}, {
			"eb57b8dd076e7bbb33d4bfc4d7ecb27e",
			"51135997a067dcd2e016c57134c5fa52",
			"b0eacbf2ca46",
			"ca989fa4e818"
		}, {
			"70abc48bb1be490183f0fe3df56195ff",
			"e251f179174b71ee1e488ab3dd200483",
			"08fbef9b2a369a",
			"5405da1186b7e0"
		}, {
			"1273b8e0eee1a1ca827059b4d0a3a55d",
			"622cab49092d026f554dd98a6441dc26",
			"b3cb9d8892423aeb",
			"d497df73afb9787c"
		}, {
			"49437e06b6faa5f20fd98bf71f8ff554",
			"63c818e0d3cb5b7054ef3e1e87df0e12",
			"01992a986279c3685e",
			"f203bcd402b65919da"
		}, {
			"6399c1dc068ba3509845628fa9ed1a96",
			"1157c2766c86b754df485be9dd5851df",
			"c9c284e9abbfe6fb11fe",
			"feff4e2e2458addf2a54"
		}
	};

	for ( std::size_t i = 0 ; i < test.size() ; ++i ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t iv[16];
		std::size_t iv_sz = sizeof(iv);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t cipher_sz = sizeof(cipher);

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t plain_sz = sizeof(plain);
		std::string plaintext;

		Crypto::Utils::from_hex(test[i][0], key,    key_sz);
		Crypto::Utils::from_hex(test[i][1], iv,     iv_sz);
		Crypto::Utils::from_hex(test[i][2], cipher, cipher_sz);

		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 1, false);

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
		EXPECT_THAT(plaintext, test[i][3]);
	}
}

TEST(CFB128, encrypt_test_vector)
{
	int res;
	const std::vector<std::vector<std::string>> test = {
		{
			"085b8af6788fa6bc1a0b47dcf50fbd35",
			"58cb2b12bb52c6f14b56da9210524864",
			"4b5a872260293312eea1a570fd39c788",
			"e92c80e0cfb6d8b1c27fd58bc3708b16"
		},
		{
			"701ccc4c0e36e512ce077f5af6ccb957",
			"5337ddeaf89a00dd4d58d860de968469",
			"cc1172f2f80866d0768b25f70fcf6361aab7c627c8488f97525d7d88949beeea",
			"cdcf093bb7840df225683b58a479b00d5de5553a7e85eae4b70bf46dc729dd31"
		},
		{
			"0a8e8876c96cddf3223069002002c99f",
			"b125a20ecd79e8b5ae91af738037acf7",
			"4fd0ecac65bfd321c88ebca0daea35d2b061205d696aab08bea68320db65451a6d6c3679fdf633f37cf8ebcf1fa94b91",
			"cdd1ba252b2c009f34551a6a200602d71ffbf13e684a5e60478cdf74ffe61dfded344bdc7e8000c3b0b67552917f3e4c"
		},
		{
			"b9ba9fa32cc491d8ac2beb5f99193d57",
			"95511452b71e53e93afad07ba1aa4d98",
			"b40382705aaeea41097c309da6cd06010f15e09c0130fa4b3af69cc8da109d1f0f0a2661f1a8b89bab7e7009dcbb8a883d46254a830c45cd87981e0ea4e490fa",
			"800bf8840a73c9279a9cdb61436f8af20ae17c5a9b95bf25e456f48cc3cc2f9dffd86c48645fa187cac5becd058e46554ae3b4825a1ef4467849c9d13536adfc"
		},
		{
			"5947bbd78b06bb5ea2fc67ed7b24216e",
			"8e4722ad2230b15f2eea302173bc1795",
			"9e69423653c20c982794ed35d63c1a78e8ac14f37e1888ae4bf273bfe119891b2e4ed8ac46e7a9a463c7a710298d43b02f0c5606bcfc08adceeef2ec61867f8bede498e53163803f2f86fc58782fb841",
			"b23f0fdfc1519c408ee7a8ba46ea79f2cbea0032685af82f76a7e2b377741aaa618ef3953edbe39e8df1dd283b2e54a0f1327ce332188f6572574ce59428636f3b6e37054a4705b02bedf377e465e5f6"
		},
		{
			"abce650e78f969b3b210151c74117fd2",
			"bc4659fbb7073c1f2185cd8ac5314bd1",
			"322eae07df5ad2ddd64bba34e42d30c1b884f842e71efa123345a3fb0c39884c57dd4c2c6fb0c42e69ff5a269d59af3a6144853c182edb376ca65947d7ccefae6806ba25c4f527706ba85a353c0fd10e3cb244dd93a2d060d7b055058dde1dff",
			"40ec099d74b804fe5fc3810aaa6a1f66c5dd882711b1c95f9405e43cecfe14a48518f1077c97db0b3f69d4ed7a6d287f2b71b1cbfe62b851a343d92f50b94eaf16a6c39df972afa4c2e9cd3d171f62b3a2ca699c0219db8fb4aefc9aeafd488c"
		},
		{
			"9f56e19b09dd3fee0e110f71e9967b7a",
			"1155cf4231bf7ac55d5e6eb27a974fad",
			"ad1e4d3162a5084f581117639a13fc35df5449625ffe0f01e57d9a8726875be8515926ffe7449e30cd69ed4ca0c1b8b4486051c2d0fa2f6474a69c0afce2aec349d778a22edf81678145765b714c1b7c197287da56f59141d6978618729e1d89be20ace3de7d9b3c9b2d195ab6bc0fd4",
			"d9f0e125fe7f82b22d8f6084364388fba90809640bd6cb6331fe6eb2e4586b18af5f6b589aaeccd48e66392e1bdcc733e4f2ec3c7824a77323c757a147500d8aac31d7cee4be2d063db7f709bdb0abf63b184baa7ff3280e28fd378e4d2fa24688bf3bc4ab5d970c88728dfb2d4d61c2"
		},
		{
			"31c485c996d6ceb2d17e0aa05b2490e4",
			"8c37f33405051b4c50abd16c6456643e",
			"ac68de6a2c2144c6b4fd975a8dec93447391e7c9a4fde63d36be7f23ad186f96cd92b5e8adb546880d100329e97fe8204fad860e6dd8b3c0eed4805387536b9ccc63d6c74938b83dce2c93cc0a04a6025b7563d9e5e7239ae27819fb3844848a51e4294f273401ad9e592f8a170334b042f0667233b29f92b9b13262eb73232a",
			"bcb37030075abbc91a75a302e5afe7281f7fd594c74a09737ae81f50573eb144c1d6c5190e10a61587848fefe2d3b0b3c05629f78a16758eaf40253322f3f7a8d755034be407b2af3761c3e704419686616194482cca5f603be89a1f06c7a190587c2f9338d48bcda1615c4257728ec34f2ce6ad0b58a197148ed10ede6a6561"
		},
		{
			"556ccfa360ecb5025032dddb124cad4d",
			"d54c6fdcc85dc0a28c0b06205fee8854",
			"71fbf180effac3dca0d69d40e4017dbe50455396f9fb6507ef7df26507de156cded8edd41a05fb25f352cbcdf3b2d770f90fa87f84863e0c2ed3b2dd770a1abfc489ad1ca82a28d061bd7039a6b5788da021657136def0c78d0b0cc7cfbec9512cf579811fd01185f3fdd2ab857328be4b63d293956b43df130e484b9861eccb1d06992b095e7febb0fb394c1954aeab",
			"e59b831cccd4acd94be7a9ffd3cc3167a9b6e085bfb976500d25fdfa2782f89c420241253f1b8ebdbbccd184d88a9db0da2ae1927137d1c2b08646ad50791ab66f7f88c365d567e8a8cbdf9aaae53d4e4ce964f9a14bd30a3c7cac53b245443dc16628d697afe62e0ed83bad707ad53f64a627b52bd66fb29484876919e41f8776e54cc9780841504f8c6b481cf112b2"
		},
		{
			"7cb81fc4b203b0fa9bec49759bd515c2",
			"4d5e2fa3bf73f488b3e7e125f03dfbbe",
			"362789b376d85eb8181d4eeea52d42e873ce7741c11a2f820383a7457b15489b09fb21ac4445959dc9e851b7d40682c50d7044bda46a5da39fae2bab73b3db9ed22edc7ec5da936dfa7451cb5f0a829ff0762738cc2686148f1e1f00dc3fe38139c9a173201fc1f052ca34736fc1ab3dc4e707f864d6119b7adb6c8ddd41c80de5d357d17e9c85ed7af1e4f72cb2656932ccce469202680109eef89a9f42f10a",
			"ac23259f68d4f82604cabd2e4237821c8b6c0aad0dfb1120b6b057223c994d62b5c6f63a25edbb797cd299f81ccb86d50134ad26107865142004c2d9d52fe3f91acf7b9b8111c8b4e14b05b173730e7b812036029846f1c1c6ffb30f6abcfc3e1ea631480e0d0bda106bb87319fdae09a11b89e8dde625d53a19c65ae58fbe3f4bcbc3c99af05cb0a7cc4b793d8cdb1cfa3173ede595c8c561f92c3fe3638b8d"
		}
	};

	for ( std::size_t i = 0 ; i < test.size() ; ++i ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t iv[16];
		std::size_t iv_sz = sizeof(iv);

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t plain_sz = sizeof(plain);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t cipher_sz = sizeof(cipher);
		std::string ciphertext;

		Crypto::Utils::from_hex(test[i][0], key,   key_sz);
		Crypto::Utils::from_hex(test[i][1], iv,    iv_sz);
		Crypto::Utils::from_hex(test[i][2], plain, plain_sz);

		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

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
		EXPECT_THAT(ciphertext, test[i][3]);
	}
}

TEST(CFB128, decrypt_test_vector)
{
	int res;
	const std::vector<std::vector<std::string>> test = {
		{
			"beb622d0228cde29b342bbcf4c1c83b4",
			"75c282fa581d9c671edf5d540951b680",
			"a5dd69d94112f3ffc2f267adde70b996",
			"860476c81685b58e71e2599efe083ce5"
		},
		{
			"c4666081e0b0eddb10a9a607c807378f",
			"5f23623288e4a41b03186024755a10ea",
			"7138c2b69191cf88702f7d25e9170dd6effdb80416b44f4d54e81fd7090f17e4",
			"2fd02dab9054248073ebc0b07aed383756ccfa4fa6298722775be6a9b4ed27a5"
		},
		{
			"df010376a6b03279338773a70e012382",
			"67455decec549365742525d8dbf1fed9",
			"c8bedc6e272366e4c584d2364fac4e2980359ace3a4ebc62d5bcf472b71ff2422477477058e61ad5d3b81cacf5a0bef6",
			"9b9c3dea553ec235db0011b27191544171845b7bdda0dc04a089583959bba5ab7048f8ca87eab073a8b824fdd4e82e40"
		},
		{
			"ff01aa4f7106c6bd24399076f901a530",
			"089b4f6054eeeef76d4e13f75de64f7e",
			"228377c8fae0edfae8cc43e5a07ceefa5d8f1b84d33842e5649efe2396831ca4c524f1361561f153ab1e7ea21de9fec026dd30419fc6c0f2aa86196131b77aa0",
			"ae9cb9dfa305af83e95a3b2099f70907edcd49fbc6efc5ebe744184c76b4f56bf35774f3fe215e1c8ee42172a2dd3e6f9ccd3d9bb044325e61a6bb97e48e9986"
		},
		{
			"d33d4062ab32298eafcca86b5088d5fd",
			"fcfffce8b020240f9f694adcb8ddf213",
			"208d49796fed810f37350b85d49c575f4d64ac973e02bde5157f7e3d811e3598283fd4f7998386a5813188bd21d93aedff377679dc592083e704fe893055ca2f5fa4863fa6ad10eef4f2f6616c5b8b6f",
			"1fe1318adb99e6d4fced292902fe8c831ba488a43f85964d6ff54b322663b380bc99fed15568278cfe1d0af795c71355bf65e876855763655eec3abf3d4b27a0341d607f4bfbd82c8900fd436f7c4186"
		},
		{
			"47e13544a7bbf74dd68ab5ce66e5bdaa",
			"69480b4dd38cf3b47e2b7652751395ae",
			"26a7b649fd8435c5dd29ba1683ae0fb515ebb6e45cdfc4362d53f35128baf2f3a65cff33ecb3b80aa5152e118f943c8c742317a85cfa2501013b136783d522e25da8c1f398eb611d3ecb85a4125518957e960406cd01009f9a11a95a882fd586",
			"3e2e583a3a0389ca324f2aaa52b7823904ab288dae562995cf1d70c796d785fd361261434eea480ceb3d369d969652c7ff194931c0a9bd978f5ae4094d6ef32d986a092c580ccbf865e5095a7b80559be13f842f9bea9e42a3a01ef8a24a6526"
		},
		{
			"ae86823695b48e8c612ae5a01b597f97",
			"b26eef7b1d14894c0c6388ce5273f4f2",
			"34a2642a230ad03d2c688cca80baeaee9a20e1d4c548b1cede29c6a45bf4df2c8c476f1a21a4431aed23661ce96342ef7cc60712f9de51c76a2205688ce67bfe1a8ae3104ef1e1b9a6347bfde498355d58be7aa9611a3e1632a6e291d2d8585266d187b3b3d7f143df05931677410c60",
			"569a910bc6aa97b8939ca703fc10ce0d171625bc735a1fea7148650541109d955b1b686c6cc404b2d3d92ad9faaff217dc7b31b038b770959aeccd1ca55d650364fde51df8d4f0aeb05fa364f5028f709c179ca6df0bdfc1cb850f238d755ac44a733fce558402be0c70bc0871b8e62f"
		},
		{
			"b85df29c9244229835d73441dc37555e",
			"c1375430efedb2d311a37bfa5ad2110e",
			"2a0ea682b6b22122e828e2b6e1574303e7c1d32f1563a6c751dcf0077fd2d255f492740e2ef65485c28cde4995f43ca74f8a6f700d469ffd57e0af6f5137153b35f3e9e700693b0e6cc0aaaa1f5232932255464294bb1fdba056536bac40a96dd37a2c9496d37ec4ce0c6f61e539cecd466a802c128bce6b15890380f8b737f3",
			"c232a0bbf967ef28b74e7b809c62bc8c1cf2d52a273a84162900da834448fd567870471498f29770619dec504922e379eaba0d3a712602583d00279d8fc6a6d568cb94a330039a189ed5802abb7a2898c13ef89c00d73fca9a2f2ffc2107ab498212c56835c0fc26f835a69c00bb3eaa695ac20e8bdb0f5b5b6684d02bee8fb2"
		},
		{
			"e96771f5f20a89ee871261d2d18e1e46",
			"8c664a37d245d26c0c55adfb424758ba",
			"400c6d6bbfd0a676bcb88d20e41151abfed50e951e189e1d1ba2b30244de228e4ff382d39230f63576ad4728282f363b914d105689d1823f4761af631c5f80d4620d3b8eaff558fe4e8890c5ef0536b99d9cca2cf1d4cc72852ace9dacfacd8b60a3c1237ce773db2c908f7da159fa2c090b65a2bee723bbbd4437375b79b2bb33fd3c1a63cdf0d3f80e6ddba6f4299c",
			"8aaafd56c5d5d54fbe16f115c3216bd1f4376666931a2ef1ffc5468ad12150c39250dca2d63c6ea166bb0ef4aaa3d5849c1f9c621c55826a1ca362f03bcba4dcbd654b300d16519710130e5360bd949aaded6a648f96dd8937a77287d4a4ac2941729475b635b9797476b4dca4171787ff15882d3b4872ed0999a7546dbb61698e8348f70e4a14981a78156150484532"
		},
		{
			"aef49da33f538ee66e178d4b6121055d",
			"842566e68b61ff7bf001f2642da62f64",
			"6625811419bdee71535f597f7c228bafd890fd69b805a699ed58116a82bdb251abea7a4ef879a96fce8ee49518b9877a3a1e3cf346d3cd73738936d1cb6fff4b2353c8ca500a26689813ad2f67774e2343f3e4830259094d3b342e00faabeba5b8a893108a390c649836ddd5d12489b2dd591ca25361032e2da1207f793a1e69513002a90ccc036bb63e9c10be87df2def960cd7a1b1621e311735d7aee4419f",
			"415991f65e1a95040cef9960556f61e617827c30c74bf353cdd86173dbe4cc983a2ee6bc8ca6cfb71121e7b0d0178f2e13445c710dcc176b781201971171f7489f18faf110f39accd1cf08c85a958d7698b116f1c0d75812ac9b0b39aee7f7159ccad8fdae9b99f2d695eacf12c6469d5b51a34de26eac73613dcb2f77122cb1f8dd5162786a12052dc7b6dea6acc4989dcc7eafd9374f6c29697c74749ef16d"
		}
	};

	for ( std::size_t i = 0 ; i < test.size() ; ++i ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t iv[16];
		std::size_t iv_sz = sizeof(iv);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t cipher_sz = sizeof(cipher);

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t plain_sz = sizeof(plain);
		std::string plaintext;

		Crypto::Utils::from_hex(test[i][0], key,    key_sz);
		Crypto::Utils::from_hex(test[i][1], iv,     iv_sz);
		Crypto::Utils::from_hex(test[i][2], cipher, cipher_sz);

		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

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
		EXPECT_THAT(plaintext, test[i][3]);
	}
}

TEST(CFB, stream_size)
{
	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];

	// Stream size is nul
	{
		std::string expected = "Invalid data segment size";

		try {
			Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 0);
			FAIL() << "Expected: SymmetricCipher::Exception";
		} catch ( const Crypto::SymmetricCipher::Exception& sce ) {
			EXPECT_EQ(sce.what(), expected);
		} catch ( ... ) {
			FAIL() << "Expected: SymmetricCipher::Exception";
		}
	}

	// Stream size is bigger than cipher's BLOCK_SIZE
	{
		std::string expected = "Invalid data segment size";

		try {
			Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 17);
			FAIL() << "Expected: SymmetricCipher::Exception";
		} catch ( const Crypto::SymmetricCipher::Exception& sce ) {
			EXPECT_EQ(sce.what(), expected);
		} catch ( ... ) {
			FAIL() << "Expected: SymmetricCipher::Exception";
		}
	}
}

TEST(CFB, encrypt_update)
{
	int res;
	const std::vector<std::vector<std::string>> test = {
		{
			"00000000000000000000000000000000",
			"00000000000000000000000000000000",
			"00000000000000000000000000000000"
			"00000000000000000000000000000000",
			"66e94bd4ef8a2c3bba880a22582c72bc"
			"c8360d8bbe36c169b520cd775d09aec2"
		}
	};

	for ( std::size_t i = 0 ; i < test.size() ; ++i ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t iv[16];
		std::size_t iv_sz = sizeof(iv);

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t plain_sz = sizeof(plain);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t cipher_sz = sizeof(cipher);
		std::string ciphertext;

		Crypto::Utils::from_hex(test[i][0], key,   key_sz);
		Crypto::Utils::from_hex(test[i][1], iv,    iv_sz);
		Crypto::Utils::from_hex(test[i][2], plain, plain_sz);

		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 8, true);

		std::size_t current_sz, offset;
		offset = 0;

		// Buffer is 0
		current_sz = cipher_sz - offset;
		res = ctx.update(plain, 1, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 1
		current_sz = cipher_sz - offset;
		res = ctx.update(plain + 1, 2, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 3
		current_sz = cipher_sz - offset;
		res = ctx.update(plain + 3, 4, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 7
		current_sz = cipher_sz - offset;
		res = ctx.update(plain + 7, 8, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		// Buffer is 7
		current_sz = cipher_sz - offset;
		res = ctx.update(plain + 15, 16, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)16);
		offset += current_sz;

		// Buffer is 7
		current_sz = cipher_sz - offset;
		res = ctx.update(plain + 31, 1, cipher + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		res = ctx.finish(current_sz);
		EXPECT_EQ(res, 0);

		Crypto::Utils::to_hex(cipher, offset, ciphertext, false);

		EXPECT_THAT(ciphertext, test[i][3]);
	}
}

TEST(CFB, decrypt_update)
{
	int res;
	const std::vector<std::vector<std::string>> test = {
		{
			"00000000000000000000000000000000",
			"00000000000000000000000000000000",
			"66e94bd4ef8a2c3bba880a22582c72bc"
			"c8360d8bbe36c169b520cd775d09aec2",
			"00000000000000000000000000000000"
			"00000000000000000000000000000000"
		}
	};

	for ( std::size_t i = 0 ; i < test.size() ; ++i ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t iv[16];
		std::size_t iv_sz = sizeof(iv);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t cipher_sz = sizeof(cipher);

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 4];
		std::size_t plain_sz = sizeof(plain);
		std::string plaintext;

		Crypto::Utils::from_hex(test[i][0], key,    key_sz);
		Crypto::Utils::from_hex(test[i][1], iv,     iv_sz);
		Crypto::Utils::from_hex(test[i][2], cipher, cipher_sz);

		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 8, false);

		std::size_t current_sz, offset;
		offset = 0;

		// Buffer is 0
		current_sz = plain_sz - offset;
		res = ctx.update(cipher, 1, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 1
		current_sz = plain_sz - offset;
		res = ctx.update(cipher + 1, 2, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 3
		current_sz = plain_sz - offset;
		res = ctx.update(cipher + 3, 4, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)0);
		offset += current_sz;

		// Buffer is 7
		current_sz = plain_sz - offset;
		res = ctx.update(cipher + 7, 8, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		// Buffer is 7
		current_sz = plain_sz - offset;
		res = ctx.update(cipher + 15, 16, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)16);
		offset += current_sz;

		// Buffer is 7
		current_sz = plain_sz - offset;
		res = ctx.update(cipher + 31, 1, plain + offset, current_sz);
		EXPECT_EQ(res, 0);
		EXPECT_EQ(current_sz, (std::size_t)8);
		offset += current_sz;

		res = ctx.finish(current_sz);
		EXPECT_EQ(res, 0);

		Crypto::Utils::to_hex(plain, offset, plaintext, false);

		EXPECT_THAT(plaintext, test[i][3]);
	}
}

TEST(CFB, encrypt_update_size)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 16, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 16;
		ret = ctx.update(plain, 16, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 24, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 16;
		ret = ctx.update(plain, 24, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 32, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)32);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 2 * BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 32;
		ret = ctx.update(plain, 32, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)32);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.25 * BLOCK_SIZE, space = 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);

		cipher_sz = 0;
		ret = ctx.update(plain, 4, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);

		cipher_sz = 16;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 1.5 * BLOCK_SIZE, space = 2 * BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);

		cipher_sz = 32;
		ret = ctx.update(plain, 24, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)32);
	}
}

TEST(CFB, encrypt_finish_size)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	// Buffer empty, not finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
	}

	// Buffer not empty, not finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = sizeof(cipher);
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 2);
		EXPECT_EQ(cipher_sz, (std::size_t)8);
	}

	// Buffer empty, finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, true);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
	}
}

TEST(CFB, decrypt_update_size)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	// Buffer empty, provide < BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 16, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 16;
		ret = ctx.update(cipher, 16, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 24, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 1.5 * BLOCK_SIZE, space BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 16;
		ret = ctx.update(cipher, 24, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 32, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)32);
	}

	// Buffer empty, provide = 2 * BLOCK_SIZE, space 2 * BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 32;
		ret = ctx.update(cipher, 32, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)32);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.25 * BLOCK_SIZE, space = 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);

		plain_sz = 0;
		ret = ctx.update(cipher, 4, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = 0
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 0.5 * BLOCK_SIZE, space = BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);

		plain_sz = 16;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)16);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 1.5 * BLOCK_SIZE, space = BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);

		plain_sz = 16;
		ret = ctx.update(cipher, 24, plain, plain_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(plain_sz, (std::size_t)32);
	}

	// Buffer = 0.5 * BLOCK_SIZE, provide = 1.5 * BLOCK_SIZE, space = 2 * BLOCK_SIZE
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.update(cipher, 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)0);

		plain_sz = 32;
		ret = ctx.update(cipher, 24, plain, plain_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(plain_sz, (std::size_t)32);
	}
}

TEST(CFB, decrypt_finish_size)
{
	int ret;

	uint8_t key[16];
	std::size_t key_sz = sizeof(key);
	memset(key, 0x00, key_sz);

	uint8_t iv[16];
	std::size_t iv_sz = sizeof(iv);
	memset(iv, 0x00, iv_sz);

	uint8_t cipher[32];
	std::size_t cipher_sz = sizeof(cipher);
	memset(cipher, 0x00, cipher_sz);

	uint8_t plain[32];
	std::size_t plain_sz = sizeof(plain);
	memset(plain, 0x00, plain_sz);

	// Buffer empty, not finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		cipher_sz = 0;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
	}

	// Buffer not empty, not finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = sizeof(cipher);
		ret = ctx.update(cipher , 8, plain, plain_sz);
		EXPECT_EQ(ret, 0);

		plain_sz = 0;
		ret = ctx.finish(plain_sz);
		EXPECT_EQ(ret, 2);
		EXPECT_EQ(plain_sz, (std::size_t)8);
	}

	// Buffer empty, finished
	{
		Crypto::CFB<Crypto::AES> ctx(key, key_sz, iv, 16, false);

		plain_sz = 0;
		ret = ctx.finish(plain_sz);
		EXPECT_EQ(ret, 0);

		plain_sz = 0;
		ret = ctx.finish(plain_sz);
		EXPECT_EQ(ret, 0);
	}
}
