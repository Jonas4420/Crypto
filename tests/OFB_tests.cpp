#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/AES.hpp"
#include "crypto/OFB.hpp"

TEST(OFB, encrypt_test_vector)
{
	int res;
	const std::vector<std::vector<std::string>> tests = {
		{
			"d7d57bd847154af9722a8df096e61a42",
			"fdde201c91e401d9723868c2a612b77a",
			"81883f22165282ba6a442a8dd2a768d4",
			"84cc130b6867623696aa8f523d968ade"
		}, {
			"c9f4ce21b4c7daaa4f93e292dc605bc5",
			"5e5a8cf2808c720e01c1ed92d470a45d",
			"8e19c5cacd015a662e7f40cdecadbf79a68081c06d9544b41c2dd248e77633b4",
			"885dc48add7ee6a1839bc5c5e03beae071301ecf91a0111520cde0d3a112f5d2"
		}, {
			"7a70cc6b261eeccb05c57117d5763197",
			"bb7b9667fbd76d5ee204828769a341b1",
			"823cbaae3760c85512a3c83fd60bb54b7cfc739b295b63e05ef435d86e19fd15"
			"368c89ff08a0f21ce89a728ffb5d75df",
			"f5c49aae8a026bf05e525a12ab7e195eea8a1b71a8d32a5113aa8974858f2cfc"
			"0339805003a0cb1a7be19f376d4604eb"
		}, {
			"85dbd5a6e73681a51a4a7d4e93ca7d0c",
			"89d897c5aa9e0a5d5586d4b4664fc927",
			"e3dbfc6ae1a879870fd22644c8135fe063355dfc0a8dad45c9c6e052e6e085cf"
			"717754dc1b49acb04cf340826ffb0da991138f022a9c34923a6a116c98c7d3d5",
			"48a34bd814dd4e1b92a5aa04218136bcd428fd34ca151a78e0eb2c8f24d4f070"
			"978aacd5e1351c909c818db45d25b34fc21cb06a3984f969ab825ef795888da9"
		}, {
			"18b9887a34438fb2e759027e54e334b6",
			"a5be8621e58dae325c6b868fd783e2cd",
			"8cd659df925950b516f737fc92d2fafa008c008c9dfe0e75ed2d68f6ff79399f"
			"f2183464b8c37cf31aafc145fcbfac73e3f87eccb435f424bf1c6d6efb504e8e"
			"93e8a668a2210e3d3b4fd437ad1a5842",
			"82736a8fd3c07941b1173c9c51bfe0d8590f237ae36e7b93481b7b4ad88da9d6"
			"8f427305b95e4b90f7212dba00f6d6bde7e39a74da702012f36c4cd0a0c27756"
			"052ac1bd3bf1501c86c1186a69a7296c"
		}, {
			"da52c0e4609e82ee926174a9eaf90b08",
			"f2d0c5e86b4ddb40d30713aaa5a153fe",
			"91d6c95a614cf85de16eeabe5976c2a2a9d307042f79a7aaeb7c3c57e1dd8d43"
			"bfa458c8c02e4f5ed0c960c9f17e3991dd2e0cb3ede18f96395a484001ef07ca"
			"4c97b411ce454aaf0f74242aca03786a93442171bd50a1467b9d663245d24c2f",
			"416ae1e3d8350e7c291ef419c5e3465b388ee2d2f0014c04a5977e5617a00dfb"
			"eba7743155720fd646bbe64d8bbfd08817c4c4e97c1134574bc3829297655c08"
			"e39de77951d3996a1700a26bdc4292d3ce5c4294feab7619007bf3bd031bc763"
		}, {
			"56d6f7e2a870b92d55ff8d6e9c554d2a",
			"b512f0e11e27fd1a94aa0c697bb6da5e",
			"e62cdeac43667749701314c546f778a4c758e4f55760e7d729c3783cf7a242ed"
			"f6ae3fcf0990886434896c945455bfae0e5674aa06ee6fb1512d94df2cac2447"
			"eeb849373bb3efbe7bb8d66c8a7ee559b17fc268d6599fcdef7457cdbde5b9c5"
			"b692236e4397545f2be97bd44f3993ad",
			"3abae717e8370f53c3ee5571739dce8a611bb51538569fdd17f3c011642cd781"
			"11dc9520f9d357351ffb8ab77b38bb5c34f2dd02e497ff876887f2a3b26fbfca"
			"b7955817780fca751b9ef74eedd38ee0ab4bc1ece453e6765916d345e1bdbd42"
			"ad6d508c5ff375df20fc8948b6310f2d"
		}, {
			"09f216ff78dfe419dfcef1a855473414",
			"722174c892d265291982c6f042ced145",
			"11f435e7e3656fcfa8e0df230311ca21054e84e13c8590e7ec7309f59c174022"
			"d467a7302641ee1b6ba46bee4f20bfda108bb78982f670b057dfbfe49da9cfae"
			"88490ce17241402b20d2fceb476d3a424e6c406d56ffc85278695d584d6c087c"
			"b4012ca2cf4daf284fd15ac1f2e183814957e934bf88dff4d777adfbb54933b5",
			"e0e518e2d339b2e878937cd44d4e5bac40315eb226949a8b0e5863d9e543bc09"
			"936440c654764f03e5adab5b76b61218492e9f0e4578de990f1a486506c26eea"
			"4a3ea9682946ae4a462f90482a2cff19ac7846587dae80a3f1d3408583d06559"
			"4869b00ddd17ae19d8e09d8d31eb7f7579320c9f26467ff0c58c86f22a3a217e"
		}, {
			"cde9b69eea2b6a5588457e35e0a08803",
			"52323b54d69a62fec0689baee1b3ec63",
			"967798995af6f435b3a6f92bff77a11fa44d1426ae0f6e7dbafac27b123c5fc4"
			"19be52c0ea412c4b3cac05ae89a4c0ce6f5e91a456b1bded5370a1234cf6f6ab"
			"5d0253507bc6f3f0573ab97585b67107dec059812323e021e341ad839ea9e3d0"
			"2aeca43356add48ccef81f693ed53d32ba1c74a35e8a5f7f3115ef834f7daf99"
			"48244c4fc31f5487678d3e70fb27abb5",
			"6a5747276037643bbd0013c265d8d9a80b0299b283514d5256fecb5c787002a2"
			"91a18a765fa046c3243418b02eebfc0c599576e52dd8c30291c97ceaa8bd2d7d"
			"bee3e66db7b585ea2b67f46f6711df28456b801556e233a96da1a8c34cd4d615"
			"4b20f43ae27b8ae83d907f9355c87aa021a280232265e99b4e189f4a3ccaa6b5"
			"e04153961e8e427a2dd53e5ec6f5112a"
		}, {
			"939aac71e337709855715a57e3a4648f",
			"493509b56a92f14040eb9b66a188bc57",
			"9c22efddc7de496a916d15d710de374d57478126ed64c9ad7e823e24d19bfc0c"
			"fac3dda0d1c292a3a203f35b26ad94deb20f998caf41cbdd4a08eb5d6cfb46f4"
			"ede4896b0569d72c03ec194941af95c0573cc3fe8f045ba19946b382803248f3"
			"dd4f9a454b1a3e8e1af02ea8482d637dac96a68275f4a382d3023f9df4892b90"
			"32cab9378b1cef5051d6db81226f259d1be4eb23495ac807600536b5b0481754",
			"7c0217d4f990342be5a35e2bdd4756ae7f461add633a7b0f5174ee107a7c0c53"
			"b1c787cb83e5ddb876e251a23caf7959d952638c2aa28b2b08928c9b88e4c0e0"
			"fd0d8154690c3638ce692f20905e7263ff359bcc17e3b43d2276ef1fc4c88228"
			"2f9a453bc03eb29e9c95986318c19150acf1bf33270752d32488543f598f8ed4"
			"db3ccb990c8bfdf64cae0d1c6011042acda8c2687a758c2ba8080720990be88d"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t iv[16];
		std::size_t iv_sz = sizeof(iv);

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t plain_sz = sizeof(plain);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t cipher_sz = sizeof(cipher);
		std::string ciphertext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], iv,    iv_sz);
		Crypto::Utils::from_hex(test[2], plain, plain_sz);

		Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

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

TEST(OFB, decrypt_test_vector)
{
	int res;
	const std::vector<std::vector<std::string>> tests = {
		{
			"8368189d41eaa20d06a3a2d2a91e43f7",
			"cf04ac0e4733952ba538711f79eef8ca",
			"7ddda312308993a58e636744a0a38491",
			"696ca57339840fb3c150e0c111d9e13e"
		}, {
			"5124c6fdb0856ded76afb6febdaa981e",
			"937ebdeec379685a71d466703f788ff7",
			"b01c0e4470b20d489fb8848b209312bf309f792b4a7da4a047aae8afca568a19",
			"5a5928dd09e78a21256eadb062630a3f0b47ca2376ccae314948143fff2512d4"
		}, {
			"6a8f6487e76058bc5a126276e48fdd77",
			"6e75d8b8ac0976143ea103a710caec02",
			"29c360fac9b361c449e112415e3a7aefe149cacb2d08e2c2c9f61768476934ec"
			"6b26be4c902f7dc548dc378e432dbfc5",
			"424ddc343067612fdb426920f40ab4d82e3d4f9485b07fef91617556d3093874"
			"840e8110ff375b7a68f98c471ca10acc"
		}, {
			"01963d44aea026b2205238454d5bb73f",
			"9442a6e0f3a53f10b0ccf5b0ccc1793a",
			"a1452e63a52fd294009482289812735166117f5427a6759154b8b4be5561f873"
			"f29673eb0a0b200987515499914196d9029eb0371af6065d75c9276b39eea283",
			"c54cfacd953736a2d8db0b8b63b555253a0ca6f6e05f2e918d18be95669fa856"
			"09f827d6da014add2964626670c202b195248fc986372c92adbb10c0e7c36e04"
		}, {
			"4ea87b0b346054c097edc5601b782870",
			"9a3e23333b2b2de7eceea67a7ca97641",
			"323d2253511545302c6fb5a5bc324d74cad7386a0225aa3f493fcdbd50e1ff24"
			"69e73ace9a0fd30ff0ff685f168a14bb262fe448bfe28f3a581061f4d4dd7970"
			"56b034e256f1e998f511d7258dcb5bbe",
			"0c7734310c5ca82b520bf1e0a1614c7ddd0c002711ef0b239de8fa256e15b320"
			"56b992747ff3a3a310d52e9df36275d9192dad61caa16715744552c865c5ae94"
			"77a70a2c3a02a01ba176b927445094d2"
		}, {
			"1956f40b2334a6546b3071f2d17f4a59",
			"765cfb560c46777a20cce091232ccaf2",
			"bd2190e1bfa0be9430f5081e9ec58dee5186fbcb80e5605ec4643df1cc48dd76"
			"53b2e4cb4f0c2b3c6ba6cb4ab8a178aa9f0d11911b4e742f25c497796fabd52c"
			"543f850f0f24d1782c06c6113d7da7dcce3387759b48169800f5bce2b070e4dc",
			"045ad66c515d407ab73ea0c6f6ae869872342fc72956a659945454005e37c76e"
			"d07df996ffe1322840cf23843b34346a1e730ab721ddceaf362ed256054c105e"
			"d581a80c04ef22ae1b5eb8742c6e3c9c0e0e29fad211b4f40adc1520f7c6821e"
		}, {
			"4e47e1b5c1b489295d3a2bf049f4be2d",
			"83fdf064d213df417ba0e75ec517bf63",
			"afaff2d1ec65cc8e1700e7c133c970b100d347916f960e4a58da817b6fd705be"
			"759a832eabaa76268cec434bbbc4cacc3b7d3ae8deeb29b1004ee410747a030a"
			"bf35414184e18bbe405b57ed382237e9afbcaefa5b55425d1aaad243e2252a1b"
			"f649d514605132de9b14cbb1902ce191",
			"94a7bed3b5a158e85f9e4778a7de105ff4f3b2a61c2fead82cbe949d7a4ee961"
			"a6c62949ba2c69d513d836a455b612c2fbb6ca243a0a18a853cadb6b73b60019"
			"2de1d51ddf80030718b079fbb581073a06b66ba4ad524d3d09efaa59e6919bca"
			"15b2b92bd9f8c17d6e463f4ea5fd5f5e"
		}, {
			"613485e5bb84b91cdd0ca02f8d83e0bb",
			"ad8a7564f6ce8abb6949ddb7d7186580",
			"a35e2bb864d4dea2db117ef77f7f63ff86518229b208e3ad6e3c55711999602a"
			"a2287bc355cf7f02f41c5c690a3e0a5a7c54c37f61eb706913c1617786cf40fa"
			"d98748962b5bb2ecb07e707504ee1eb1bfb23682496083d2f0e3d87c377b016a"
			"7105fafb8f7d5fa737c124e51698864c76f241f9137204322a292248d4a58ac2",
			"ed5068003163c424ae9a8e51e3d77684c69073a824dc4721568f7528657c3dd2"
			"8d66219f398ed57105aa35cfef3ac078eab30ae0f3ed752b0e320b099ea42b15"
			"6f818904c4b6c534cabde53dfa62e7b74518a8bca3f36ee85b130e8520d38c00"
			"6e6adef34bbc8df56b757b500d703e5777aa545c4170404754f03dbf22c9f0d7"
		}, {
			"8198b36e880cf50dbf6724feaaac8688",
			"fbaa2882a2a4acdb299e4f82c93f2af7",
			"af5245ca51e55d4da0ab30a376e789b71d8826a063f26b80f10158acd84bb90d"
			"6da69cc657eb0816e6f9ec80a7fc562a35efe584515f81293572490a2629cdc9"
			"49e27e63b7216312d38f0d72dc43cce2be41232d2e407a6af5b113208cfc3fae"
			"ea0dd2ea9a0fd409107779bf3d4553a66186c7e4211ebe09d9c49c36334e7684"
			"f92f80a3273ec4c245b91aaff3895440",
			"b2516a356e437513f0df83938afefbe9f9ef1ec879797997f31da96a1ea7a15d"
			"395ecdb94b7fda14cdc0b75c171784fa8832d574b64f9450c6be25dc83b93d3b"
			"bf0145a661bf4db775282b98649b64613aeedb8bb770f67cc3421ac6761e5d76"
			"3c21ac2d1e729e4597ad7fca9fdc70878b26634df78cd0f36fb3b138a1357915"
			"abba4ff5f8dfaef268307022f2e23528"
		}, {
			"e30b4c874c4c4f6e0cf1f8ef58e5d375",
			"7e26f07f8024343cec35409e71e0cd8c",
			"5dcaa173ede14fd2d658973926168ff34fd6df9bce3280d40b00c43b80e2979a"
			"1e19045fec9afb4cf264516f55100855c3aad17b11bfcf0523b79eb20d659410"
			"77dd46ec46864e0d79704c2250e72bf8b448a6f0d3130ab10b423d1a09d9ff7a"
			"32bf700441ccd27d3223913860c28044ea5766e45a55b93f8948a959bd666142"
			"1566898e27950f04e726279bcbc990a22c80193ef0ae65196671eb59713240cf",
			"8ceca4dc346cfd6b15774e082db1a89497b7d85d6b5b7102e77417f7a243fafe"
			"17118b7a3bb49d1657cf61b866da395a5b3f349183a53dfa11fc0ac053bddff4"
			"9dd472ee55f5e43a2f8bc785e2bc420300694919ff7bb43feb75a9cac44ece96"
			"f679e618db5d7433af12dcc7e0963ff10b45d835f9a8f42627e7f3fd50389326"
			"85965ad0e183f5955e671fc2b878dd51051eedaf85310d1e4e8f75f2decf36c7"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		uint8_t iv[16];
		std::size_t iv_sz = sizeof(iv);

		uint8_t cipher[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t cipher_sz = sizeof(cipher);

		uint8_t plain[Crypto::AES::BLOCK_SIZE * 10];
		std::size_t plain_sz = sizeof(plain);
		std::string plaintext;

		Crypto::Utils::from_hex(test[0], key,    key_sz);
		Crypto::Utils::from_hex(test[1], iv,     iv_sz);
		Crypto::Utils::from_hex(test[2], cipher, cipher_sz);

		Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

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

TEST(OFB, update_size)
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
		Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

		cipher_sz = 0;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 1);
		EXPECT_EQ(cipher_sz, (std::size_t)8);
	}

	// Buffer empty, provide = BLOCK_SIZE, space 0
	{
		Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

		cipher_sz = 8;
		ret = ctx.update(plain, 8, cipher, cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)8);
	}
}

TEST(OFB, finish_size)
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
		Crypto::OFB<Crypto::AES> ctx(key, key_sz, iv);

		cipher_sz = 16;
		ret = ctx.finish(cipher_sz);
		EXPECT_EQ(ret, 0);
		EXPECT_EQ(cipher_sz, (std::size_t)0);
	}
}
