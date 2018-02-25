#include <vector>

#include "TestOptions.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/PBKDF2.hpp"
#include "crypto/SHA1.hpp"
#include "crypto/Utils.hpp"

TEST(PBKDF2, test_vectors)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"70617373776f7264", "73616c74",
			"1", "20",
			"0c60c80f961f0e71f3a9b524af6012062fe037a6"
	       	}, {
			"70617373776f7264", "73616c74",
			"2", "20",
			"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
		}, {
			"70617373776f7264", "73616c74",
			"4096", "20",
			"4b007901b765489abead49d926f721d065a429c1"
		}, {
			"70617373776f7264", "73616c74",
			"16777216", "20",
			"eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"
		}, {
			"7061737300776f7264", "7361006c74",
			"4096", "16",
			"56fa6aa75548099dcc37d7f03425e0c3"
		}, {
			"70617373776f726450415353574f524470617373776f7264",
			"73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c54"
			"73616c74",
			"4096", "25",
			"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
		}
	};

	for ( auto test : tests ) {
		uint8_t password[64];
		std::size_t password_sz = sizeof(password);
		uint8_t salt[64];
		std::size_t salt_sz = sizeof(salt);
		uint8_t key[64];
		std::string output = "";

		Crypto::Utils::from_hex(test[0], password, password_sz);
		Crypto::Utils::from_hex(test[1], salt,     salt_sz);
		std::size_t iterations = atoi(test[2].c_str());
		std::size_t key_sz     = atoi(test[3].c_str());

		if ( TestOptions::get().is_fast && iterations > 10000 ) {
			continue;
		}

		Crypto::PBKDF2<Crypto::SHA1>::derive_key(password, password_sz,
				salt, salt_sz, iterations, key, key_sz);
		Crypto::Utils::to_hex(key, key_sz, output, false);

		EXPECT_EQ(output, test[4]);
	}
}
