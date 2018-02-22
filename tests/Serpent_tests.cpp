#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/Serpent.hpp"

TEST(Serpent, constructor)
{
	// Case 1: key_sz < 256 bits
	{
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::Serpent ctx(key, key_sz);
	}

	// Case 2: key_sz = 256 bits
	{
		uint8_t key[32];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		Crypto::Serpent ctx(key, key_sz);
	}

	// Case 3: key_sz > 256 bits
	{
		std::string exception, expected("Key size is not supported");
		uint8_t key[64];
		std::size_t key_sz = sizeof(key);

		memset(key, 0x00, key_sz);

		try {
			Crypto::Serpent ctx(key, key_sz);
		} catch ( const Crypto::Serpent::Exception &se ) {
			exception = se.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(Serpent128, encrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"80000000000000000000000000000000", "00000000000000000000000000000000",
			"264E5481EFF42A4606ABDA06C0BFDA3D", "EFE6F058D74E357A1CA935D35E0E4F24",
			"1036FF0164E192D27AF351734141994A"
		},
		{
			"00000000000000000000000000000000", "00000000000000000000000000000000",
			"3620B17AE6A993D09618B8768266BAE9", "5C82365D84D3EF87264E2ED70CD7AE4D",
			"03158A530ED8835D808EBD795D5C918D"
		},
		{
			"000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
			"563E2CF8740A27C164804560391E9B27", "70795D35DEC6561F8AD83B2F454F9CC5",
			"4EA3765A7C3A94786850DF4812249718"
		},
		{
			"2BD6459F82C5B300952C49104881FF48", "EA024714AD5C4D84EA024714AD5C4D84",
			"92D7F8EF2C36C53409F275902F06539F", "180B795EAD8C6CB128348093A7E8E442",
			"C5F9E521F5FC7D9BB0C4674C48525460"
		},
		{
			"FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD", "FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD",
			"81F9163BDF39B5BB2932AB91DF2A5FFC", "2A73C8A40BD34279FDE37842E4E87C24",
			"0BAA3BFB7DB2A883AB7E69A28773B6CB"
		},
		{
			"FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE", "FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE",
			"DCAFAFAF80E044DF6582C735E63479A3", "A9D549C7580C2E8B45651B6E1D43A857",
			"511F5998593CA8783E925539DA491278"
		},
		{
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			"2DEE675B6B7401367DA2A80FB44B8065", "7D0E063CF4F0C32B88A23809A20C6DD2",
			"8DECE855514D26080EED341724C12F2B"
		},
		{
			"01010101010101010101010101010101", "01010101010101010101010101010101",
			"5107E36DBE81D9996D1EF7F3656FFC63", "79A0EA76DA42AA9192E2A94C49F5F468",
			"1A134619DF5403845CC1F38FB6BC1E8C"
		},
		{
			"02020202020202020202020202020202", "02020202020202020202020202020202",
			"1AE5355487F88F824B6462B45C4C6AA5", "75B0E5EDA1DD33AFCC6F56A64021E310",
			"0424C7643461CB4940CD77AF1659F9E9"
		},
		{
			"03030303030303030303030303030303", "03030303030303030303030303030303",
			"1F830AF7D2A1B18F7A011C6FD0EEE8FB", "59F81DC12BC019758130AE35FA1FF75D",
			"A82EF14625CF33CA326AD5788E1179CE"
		},
		{
			"00000000000000000000000000000000", "80000000000000000000000000000000",
			"A3B35DE7C358DDD82644678C64B8BCBB", "1DDF9883B4663045753758E0B9B2C09B",
			"BE5AE44A1CF1BB86DD7A3B61CEEA01EC"
		},
		{
			"00000000000000000000000000000000", "40000000000000000000000000000000",
			"04ABCFE4E0AF27FF92A2BB10949D7DD2", "30A8B737B223B87223BF125CF1B65B9C",
			"91A668E67BD17FD1FF4379056FDE9C5A"
		},
		{
			"00000000000000000000000000000000", "20000000000000000000000000000000",
			"8F773194B78EF2B2740237EF12D08608", "F6E554CB2EA1943BCA585614A788C788",
			"87A56307277E47977ED9DD8907D34571"
		},
		{
			"00000000000000000000000000000000", "00000000000000000000000000000004",
			"B598247AA82F5C79F9FF0E7EC61B83C4", "BFE72FAFF181ABB99F63684CCA421A80",
			"4144E5DDB81C046C9B5D0F3CDAFEE61A"
		},
		{
			"00000000000000000000000000000000", "00000000000000000000000000000002",
			"0C5DABB01245E3A3544E291F3B0F250F", "B9FD1CB725D6B5C9887F4046A706F4AD",
			"85611634788571B6A13B7BBB1E827B85"
		},
		{
			"00000000000000000000000000000000", "00000000000000000000000000000001",
			"9BEDCEA16BDE863526A937208CBF0ABC", "78B754EC57D5D3DCD717F4DB195A7E01",
			"DE9012B1D5572CF087FA218362A2CD40"
		},
		{
			"00000000000000000000000000000004", "00000000000000000000000000000000",
			"D69C8CCF5DEC9EFA90684C7B70FCDFAF", "17FA1BAC6912853D23264A3EDC5C60EF",
			"3866B821AAE3EBF31BA8BF5211FD6E0E"
		},
		{
			"00000000000000000000000000000002", "00000000000000000000000000000000",
			"39B65E77A4D26218E5ED7092AB64D07E", "5DF9D1DCF497C6BA66C4CB19E735A5CC",
			"82EC5C2782B07903FFE8D8E4C34572BF"
		},
		{
			"00000000000000000000000000000001", "00000000000000000000000000000000",
			"F668C7091F81B2827DA77DD419B708E1", "15AE94D9E155576A35A9656BD9D0B4F5",
			"B47920C11586C6EF270ACA452175A57D"
		},
		{
			"40000000000000000000000000000000", "00000000000000000000000000000000",
			"4A231B3BC727993407AC6EC8350E8524", "0D66A10F4CCFA964D6BEB74C19949FB9",
			"F671FE662E31745E6C413E778F515CDB"
		},
		{
			"20000000000000000000000000000000", "00000000000000000000000000000000",
			"E03269F9E9FD853C7D8156DF14B98D56", "FDA6AE47AF8647EB1521B683D9A0C9C1",
			"3A0DA4296EA6C1DAC9CD5AA659105D5E"
		},
		{
			"10000000000000000000000000000000", "00000000000000000000000000000000",
			"A798181C3081AC59D5BA89754DACC48F", "83A05DE8D972F0BFB9A3A243475DC759",
			"44786BFE6600C9CC3EC38E5C2CE72DE3"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);
		uint8_t plain[Crypto::Serpent::BLOCK_SIZE];
		std::size_t plain_sz = sizeof(plain);
		uint8_t cipher[Crypto::Serpent::BLOCK_SIZE];
		std::size_t cipher_sz = sizeof(cipher);
		std::string ciphertext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], plain, plain_sz);

		Crypto::Serpent ctx(key, key_sz);

		// Check for 1 round
		ctx.encrypt(plain, cipher);
		memcpy(plain, cipher, plain_sz);

		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext);
		EXPECT_EQ(ciphertext, test[2]);

		// Check for 100 rounds
		for ( std::size_t i = 1 ; i < 100 ; ++i ) {
			ctx.encrypt(plain, cipher);
			memcpy(plain, cipher, plain_sz);
		}

		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext);
		EXPECT_EQ(ciphertext, test[3]);

		// Check for 1000 rounds
		for ( std::size_t i = 100 ; i < 1000 ; ++i ) {
			ctx.encrypt(plain, cipher);
			memcpy(plain, cipher, plain_sz);
		}

		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext);
		EXPECT_EQ(ciphertext, test[4]);
	}
}

TEST(Serpent128, decrypt_test)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "80000000000000000000000000000000", "00000000000000000000000000000000", },
		{ "00000000000000000000000000000000", "00000000000000000000000000000000", },
		{ "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", },
		{ "2BD6459F82C5B300952C49104881FF48", "EA024714AD5C4D84EA024714AD5C4D84", },
		{ "FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD", "FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD", },
		{ "FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE", "FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE", },
		{ "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", },
		{ "01010101010101010101010101010101", "01010101010101010101010101010101", },
		{ "02020202020202020202020202020202", "02020202020202020202020202020202", },
		{ "03030303030303030303030303030303", "03030303030303030303030303030303", },
		{ "00000000000000000000000000000000", "80000000000000000000000000000000", },
		{ "00000000000000000000000000000000", "40000000000000000000000000000000", },
		{ "00000000000000000000000000000000", "20000000000000000000000000000000", },
		{ "00000000000000000000000000000000", "00000000000000000000000000000004", },
		{ "00000000000000000000000000000000", "00000000000000000000000000000002", },
		{ "00000000000000000000000000000000", "00000000000000000000000000000001", },
		{ "00000000000000000000000000000004", "00000000000000000000000000000000", },
		{ "00000000000000000000000000000002", "00000000000000000000000000000000", },
		{ "00000000000000000000000000000001", "00000000000000000000000000000000", },
		{ "40000000000000000000000000000000", "00000000000000000000000000000000", },
		{ "20000000000000000000000000000000", "00000000000000000000000000000000", },
		{ "10000000000000000000000000000000", "00000000000000000000000000000000", }
	};

	for ( auto test : tests ) {
		uint8_t key[16];
		std::size_t key_sz = sizeof(key);
		uint8_t plain[Crypto::Serpent::BLOCK_SIZE];
		std::size_t plain_sz = sizeof(plain);
		uint8_t cipher[Crypto::Serpent::BLOCK_SIZE];
		uint8_t decrypt[Crypto::Serpent::BLOCK_SIZE];

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], plain, plain_sz);

		Crypto::Serpent ctx(key, key_sz);

		for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
			ctx.encrypt(plain, cipher);
			ctx.decrypt(cipher, decrypt);

			EXPECT_EQ(memcmp(plain, decrypt, 16), 0);
			
			memcpy(plain, cipher, plain_sz);
		}
	}
}

TEST(Serpent192, encrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"800000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000", "9E274EAD9B737BB21EFCFCA548602689",
			"B083CEAE24F090E4F24E743F1D47BFC2", "71CC05731B193A9A88F50214C29F4E32"
		},
		{
			"400000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000", "92FC8E510399E46A041BF365E7B3AE82",
			"398AC3834C7AC39729BCBE24FF4E5730", "7CCD5336689B33F43687ED383F3A8E5E"
		},
		{
			"200000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000", "5E0DA386C46AD493DEA203FDC6F57D70",
		       	"2456C40C8B6A097B12E98F5E903BAA27", "60B3A7D149FAF6ED0FAA65D0959CBD38"
		},
		{
			"000000000000000000000000000000000000000000000004",
			"00000000000000000000000000000000", "8AF1A83901D7DD153FF8D271B210E3AB",
			"F02E053812A685F8F1D7FD1FB8322BB5", "7948DD537FE3890E17AD1290B36C361D"
		},
		{
			"000000000000000000000000000000000000000000000002",
			"00000000000000000000000000000000", "4209B9F47FE46DA7095E093698227280",
			"8AC961F0A9970920492640219FE797D3", "2EB997E2B73893313FE25F2A0F146236"
		},
		{
			"000000000000000000000000000000000000000000000001",
			"00000000000000000000000000000000", "5D058517AC7CC5AFD5C33253D4703B46",
			"24D84667315E1BA4A6A35FFBB10DC850", "15BC4AB683508CB087C5031E1659A42E"
		},
		{
			"000000000000000000000000000000000000000000000000",
			"80000000000000000000000000000000", "23F5F432AD687E0D4574C16459618ABB",
			"62A463BBEAA7F9E29AEDCAC5876D9E7F", "F8EEA0DC3CB6BC151C83B6362475C00D"
		},
		{
			"000000000000000000000000000000000000000000000000",
			"40000000000000000000000000000000", "56CD894936F6E9A4A4304CAE06F97CE3",
			"6C1D827CDB3E409F1FF65435731D8D99", "2EE6B5B7E696E5719FC425D71624DF9D"
		},
		{
			"000000000000000000000000000000000000000000000000",
			"20000000000000000000000000000000", "B604D94F461AF9F4771BC53F8E3C227B",
			"58670E5DB79C694A9FA5946B2BCB1E52", "7577E74D656FE1BB0429E152B131DDD6"
		},
		{
			"000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000004", "9BAC7EE501F03D6DEBE0F9EE68FBB3C1",
			"2512C7E75A2090FAC34E6E7BF2E68DF1", "3227BAAA0075064AF568BE0BA3D10DD8"
		},
		{
			"000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000002", "444E6201556F1C9D73299183B7ABCA9D",
			"F2EC0124AB2D213C020CB5B406A589AC", "726E406B386642EC091196A2A2D2C763"
		},
		{
			"000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000001", "497EA15A5AAB3CB115C3E0091C2E4047",
			"9F37BA396674224EFD509B39DDEB632C", "9EF469F484B2CA8D16D76F852DE34C83"
		},
		{
			"000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000", "A583EF976A292B406BBD5DC8256B0442",
			"08271FE10C7C285F8750BBB63156FAA4", "85CC556DF866ED82E230A57829DD803A"
		},
		{
			"010101010101010101010101010101010101010101010101",
			"01010101010101010101010101010101", "3C30CC53B1408BF333B85DD1C6632A29",
			"BFFF142EEFF2A6325C02B993AB777665", "2D2E39D18DE901FFFEE49849FBA9991D"
		},
		{
			"020202020202020202020202020202020202020202020202",
			"02020202020202020202020202020202", "9CCCE11543D31C4527860F2411FC6435",
			"7FD1E9A1F8D0F305A9FD7D8DDDEA7954", "B8EE48B0C092A2692C1D844E6A203E24"
		},
		{
			"FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD",
			"FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD", "7510879F6854807D0B5063E6302483E9",
			"7BFF29C6EEE8D28B34F77EBA4932CE0C", "A7B9703457808E90A67DE747F950413A"
		},
		{
			"FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE",
			"FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE", "A59BD7823058443E5707A964F9C4480A",
			"FCDD3635452B2733598A1945105C459F", "4B2A9BCC347570FCAA7BD542596B29BA"
		},
		{
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "08FC09BD2580A3FFBC8453FAF21417C0",
			"5323949BFFD4A3062D87A3576DF20256", "E2AB1C4953224BBF636C3109756D9F4C"
		},
		{
			"000102030405060708090A0B0C0D0E0F1011121314151617",
			"00112233445566778899AABBCCDDEEFF", "6AB816C82DE53B93005008AFA2246A02",
			"D8789291A6307A1DFCFB310CB5CEE8E1", "D4D1005991ACF56FDD6C45ED867CD679"
		},
		{
			"2BD6459F82C5B300952C49104881FF482BD6459F82C5B300",
			"EA024714AD5C4D84EA024714AD5C4D84", "827B18C2678A239DFC5512842000E204",
			"696E45B38A8181D1B07F1D311A6F4CFE", "7ECD356D2BE7B1FB7971A1A94BC7BE49"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[24];
		std::size_t key_sz = sizeof(key);
		uint8_t plain[Crypto::Serpent::BLOCK_SIZE];
		std::size_t plain_sz = sizeof(plain);
		uint8_t cipher[Crypto::Serpent::BLOCK_SIZE];
		std::size_t cipher_sz = sizeof(cipher);
		std::string ciphertext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], plain, plain_sz);

		Crypto::Serpent ctx(key, key_sz);

		// Check for 1 round
		ctx.encrypt(plain, cipher);
		memcpy(plain, cipher, plain_sz);

		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext);
		EXPECT_EQ(ciphertext, test[2]);

		// Check for 100 rounds
		for ( std::size_t i = 1 ; i < 100 ; ++i ) {
			ctx.encrypt(plain, cipher);
			memcpy(plain, cipher, plain_sz);
		}

		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext);
		EXPECT_EQ(ciphertext, test[3]);

		// Check for 1000 rounds
		for ( std::size_t i = 100 ; i < 1000 ; ++i ) {
			ctx.encrypt(plain, cipher);
			memcpy(plain, cipher, plain_sz);
		}

		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext);
		EXPECT_EQ(ciphertext, test[4]);
	}
}

TEST(Serpent192, decrypt_test)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "800000000000000000000000000000000000000000000000", "00000000000000000000000000000000", },
		{ "400000000000000000000000000000000000000000000000", "00000000000000000000000000000000", },
		{ "200000000000000000000000000000000000000000000000", "00000000000000000000000000000000", },
		{ "000000000000000000000000000000000000000000000004", "00000000000000000000000000000000", },
		{ "000000000000000000000000000000000000000000000002", "00000000000000000000000000000000", },
		{ "000000000000000000000000000000000000000000000001", "00000000000000000000000000000000", },
		{ "000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", },
		{ "000000000000000000000000000000000000000000000000", "40000000000000000000000000000000", },
		{ "000000000000000000000000000000000000000000000000", "20000000000000000000000000000000", },
		{ "000000000000000000000000000000000000000000000000", "00000000000000000000000000000004", },
		{ "000000000000000000000000000000000000000000000000", "00000000000000000000000000000002", },
		{ "000000000000000000000000000000000000000000000000", "00000000000000000000000000000001", },
		{ "000000000000000000000000000000000000000000000000", "00000000000000000000000000000000", },
		{ "010101010101010101010101010101010101010101010101", "01010101010101010101010101010101", },
		{ "020202020202020202020202020202020202020202020202", "02020202020202020202020202020202", },
		{ "FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD", "FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD", },
		{ "FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE", "FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE", },
		{ "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", },
		{ "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", },
		{ "2BD6459F82C5B300952C49104881FF482BD6459F82C5B300", "EA024714AD5C4D84EA024714AD5C4D84", }
	};

	for ( auto test : tests ) {
		uint8_t key[24];
		std::size_t key_sz = sizeof(key);
		uint8_t plain[Crypto::Serpent::BLOCK_SIZE];
		std::size_t plain_sz = sizeof(plain);
		uint8_t cipher[Crypto::Serpent::BLOCK_SIZE];
		uint8_t decrypt[Crypto::Serpent::BLOCK_SIZE];

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], plain, plain_sz);

		Crypto::Serpent ctx(key, key_sz);

		for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
			ctx.encrypt(plain, cipher);
			ctx.decrypt(cipher, decrypt);

			EXPECT_EQ(memcmp(plain, decrypt, 16), 0);
			
			memcpy(plain, cipher, plain_sz);
		}
	}
}

TEST(Serpent256, encrypt_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"8000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000", "A223AA1288463C0E2BE38EBD825616C0",
			"739E0148971FD975B585EAFDBD659E2C", "BEFD00E0D6E27E56951DC6614440D286"
		},
		{
			"4000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000", "EAE1D405570174DF7DF2F9966D509159",
			"DF58B1EBBD9DDCC116F56C6D980A7645", "7DF5CFCD017AC3D8679BD2D526231245"
		},
		{
			"2000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000", "65F37684471E921DC8A30F45B43C4499",
			"2E88497FC401DE30A8CFF71B7766545E", "05752E50BA0AF425A8A4042C14251A3E"
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000004",
			"00000000000000000000000000000000", "F6899D57F734AFD6473278DBDE8FB99D",
			"7717739E2C592125161908A62EB36DFD", "60EF243A4A7B68DFFEEF694497363C50"
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000002",
			"00000000000000000000000000000000", "A6726CE53BD62BC873F6C0463A5841FC",
			"147774B20566CFAE6C5C760639336196", "290E45C7A204E9BC93299CEBB2EE9C45"
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000001",
			"00000000000000000000000000000000", "9858FD31C9C6B54AC0C99CC52324ED34",
			"60EBE7B4DFDF854790596ED1DB88FC3B", "A30D5F7410F1139ED83A172024215F0F"
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"80000000000000000000000000000000", "8314675E8AD5C3ECD83D852BCF7F566E",
			"4644E40D4FB7744E554082C4131986C4", "BFA1F3B34FAE99E61EB82270659143F4"
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"40000000000000000000000000000000", "893BF67B1A845579C8FADC05BFDC0894",
			"CA1EB8489C6EE3F806A722381A6B9AAE", "419D83BD019AB99E838A29F472C02369"
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"20000000000000000000000000000000", "302F8325DEB1E1A0955D6273368A0DC4",
			"168E86D50ACA29921EC539FC4868BFA2", "FA7E42B0AED91835B8886812AA7AE42F"
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000004", "9D9286D5E97CCDEC47E03CB12C34B339",
			"02B6A23367D280DA87C96894EDC104A3", "7DBB4267014B28D3856BBC1BA7CD43F0"
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000002", "BC2C09F0B3FC63CE17F1BE7F267E3E0A",
			"9681CC2716B5ED254EA269FD204677BB", "8231B03C2341DDBB3DE39E8E81E3CF1A"
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000001", "AD86DE83231C3203A86AE33B721EAA9F",
			"691ECDC9D8F9EF1BF3EBD89F263255F1", "8D5ADB96C504CB8DBE460D670A3D0F02"
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000000",
			"00000000000000000000000000000000", "49672BA898D98DF95019180445491089",
			"5A445EFD4923EBDDEA1D5BE4511BD4D6", "D72EC2B7B93FBB567CEFBAB3FAB43FB4"
		},
		{
			"0101010101010101010101010101010101010101010101010101010101010101",
			"01010101010101010101010101010101", "EC9723B15B2A6489F84C4524FFFC2748",
			"C30321FEF2B731221F72F7179F80D076", "3A9A9597F18CBCDF5D76E42E9B13F036"
		},
		{
			"0202020202020202020202020202020202020202020202020202020202020202",
			"02020202020202020202020202020202", "1187F485538514476184E567DA0421C7",
			"0DE23E89A6BEAAAD147F2B214C02319F", "3998EEDAC1B8CFF4820B29378872E991"
		},
		{
			"FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD",
			"FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD", "8B54C5B81ADBE4E1712931515684E692",
			"42848DF6AF3797DEB13F31F32175BF0D", "4B1F16E4A1BFE985EF59542692303CD0"
		},
		{
			"FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE",
			"FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE", "CBB014220EA4B36A5B5554140AFD721A",
			"AFC5B856315EAD9E37C02BE901CF0B25", "A39086F5BAF30B353D61856D4959C374"
		},
		{
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "6AC7579D9377845A816CA6D758F3FEFF",
			"9D449D3B8DFDA00437078C4FBB8FA432", "8D78EE979E720912419CBBC642567A2E"
		},
		{
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF", "2868B7A2D28ECD5E4FDEFAC3C4330074",
			"8BF56992354F3F1A0F4E49DCBA82CBC0", "9B1D8B34845DF9BFD36AAAD0CDA1C8FE"
		},
		{
			"2BD6459F82C5B300952C49104881FF482BD6459F82C5B300952C49104881FF48",
			"EA024714AD5C4D84EA024714AD5C4D84", "3E507730776B93FDEA661235E1DD99F0",
			"3B5462E5D87A40C4BE745E3994D5E373", "99D5D067EF7C787E6A764EB47DAC59AD"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[32];
		std::size_t key_sz = sizeof(key);
		uint8_t plain[Crypto::Serpent::BLOCK_SIZE];
		std::size_t plain_sz = sizeof(plain);
		uint8_t cipher[Crypto::Serpent::BLOCK_SIZE];
		std::size_t cipher_sz = sizeof(cipher);
		std::string ciphertext;

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], plain, plain_sz);

		Crypto::Serpent ctx(key, key_sz);

		// Check for 1 round
		ctx.encrypt(plain, cipher);
		memcpy(plain, cipher, plain_sz);

		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext);
		EXPECT_EQ(ciphertext, test[2]);

		// Check for 100 rounds
		for ( std::size_t i = 1 ; i < 100 ; ++i ) {
			ctx.encrypt(plain, cipher);
			memcpy(plain, cipher, plain_sz);
		}

		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext);
		EXPECT_EQ(ciphertext, test[3]);

		// Check for 1000 rounds
		for ( std::size_t i = 100 ; i < 1000 ; ++i ) {
			ctx.encrypt(plain, cipher);
			memcpy(plain, cipher, plain_sz);
		}

		Crypto::Utils::to_hex(cipher, cipher_sz, ciphertext);
		EXPECT_EQ(ciphertext, test[4]);
	}
}

TEST(Serpent256, decrypt_test)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "8000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000" },
		{ "4000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000" },
		{ "2000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000" },
		{ "0000000000000000000000000000000000000000000000000000000000000004", "00000000000000000000000000000000" },
		{ "0000000000000000000000000000000000000000000000000000000000000002", "00000000000000000000000000000000" },
		{ "0000000000000000000000000000000000000000000000000000000000000001", "00000000000000000000000000000000" },
		{ "0000000000000000000000000000000000000000000000000000000000000000", "80000000000000000000000000000000" },
		{ "0000000000000000000000000000000000000000000000000000000000000000", "40000000000000000000000000000000" },
		{ "0000000000000000000000000000000000000000000000000000000000000000", "20000000000000000000000000000000" },
		{ "0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000004" },
		{ "0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000002" },
		{ "0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000001" },
		{ "0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000" },
		{ "0101010101010101010101010101010101010101010101010101010101010101", "01010101010101010101010101010101" },
		{ "0202020202020202020202020202020202020202020202020202020202020202", "02020202020202020202020202020202" },
		{ "FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD", "FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD" },
		{ "FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE", "FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE" },
		{ "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" },
		{ "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF" },
		{ "2BD6459F82C5B300952C49104881FF482BD6459F82C5B300952C49104881FF48", "EA024714AD5C4D84EA024714AD5C4D84" }
	};

	for ( auto test : tests ) {
		uint8_t key[32];
		std::size_t key_sz = sizeof(key);
		uint8_t plain[Crypto::Serpent::BLOCK_SIZE];
		std::size_t plain_sz = sizeof(plain);
		uint8_t cipher[Crypto::Serpent::BLOCK_SIZE];
		uint8_t decrypt[Crypto::Serpent::BLOCK_SIZE];

		Crypto::Utils::from_hex(test[0], key,   key_sz);
		Crypto::Utils::from_hex(test[1], plain, plain_sz);

		Crypto::Serpent ctx(key, key_sz);

		for ( std::size_t i = 0 ; i < 1000 ; ++i ) {
			ctx.encrypt(plain, cipher);
			ctx.decrypt(cipher, decrypt);

			EXPECT_EQ(memcmp(plain, decrypt, 16), 0);
			
			memcpy(plain, cipher, plain_sz);
		}
	}
}
