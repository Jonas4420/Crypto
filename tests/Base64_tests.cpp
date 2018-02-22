#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Base64.hpp"
#include "crypto/Utils.hpp"

TEST(Base64, encode_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "",       ""         },
		{ "f",      "Zg=="     },
		{ "fo",     "Zm8="     },
		{ "foo",    "Zm9v"     },
		{ "foob",   "Zm9vYg==" },
		{ "fooba",  "Zm9vYmE=" },
		{ "foobar", "Zm9vYmFy" }
	};

	for ( auto test : tests ) {
		uint8_t in[6];
		std::size_t in_sz = sizeof(in);
		Crypto::Utils::from_string(test[0], in, in_sz);
		std::string out;

		Crypto::Base64::encode(in, in_sz, out);
		EXPECT_EQ(out, test[1]);
	}
}

TEST(Base64, encode_regular)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "010203040506070809", "AQIDBAUGBwgJ" },
		{ "0102030405060708",   "AQIDBAUGBwg=" },
		{ "01020304050607",     "AQIDBAUGBw==" }
	};

	for ( auto test : tests ) {
		uint8_t in[9];
		std::size_t in_sz = sizeof(in);
		Crypto::Utils::from_hex(test[0], in, in_sz);
		std::string out;

		Crypto::Base64::encode(in, in_sz, out);
		EXPECT_EQ(out, test[1]);
	}
}

TEST(Base64, decode_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "",         ""       },
		{ "Zg==",     "f"      },
		{ "Zm8=",     "fo"     },
		{ "Zm9v",     "foo"    },
		{ "Zm9vYg==", "foob"   },
		{ "Zm9vYmE=", "fooba"  }, 
		{ "Zm9vYmFy", "foobar" }
	};
	
	for ( auto test : tests ) {
		uint8_t output[6];
		std::size_t output_sz = sizeof(output);
		std::string out;

		Crypto::Base64::decode(test[0], output, output_sz);
		Crypto::Utils::to_string(output, output_sz, out);
		EXPECT_EQ(out, test[1]);
	}
}

TEST(Base64, decode_regular)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "AQIDBAUGBwgJ", "010203040506070809" },
		{ "AQIDBAUGBwg=", "0102030405060708"   },
		{ "AQIDBAUGBw==", "01020304050607"     }
	};

	for ( auto test : tests ) {
		uint8_t output[9];
		std::size_t output_sz = sizeof(output);
		std::string out;

		Crypto::Base64::decode(test[0], output, output_sz);
		Crypto::Utils::to_hex(output, output_sz, out);
		EXPECT_EQ(out, test[1]);
	}
}

TEST(Base64, decode_regular_spaces)
{
	const std::vector<std::vector<std::string>> tests = {
		{ "Zm9vYmFy\n",     "foobar" },
		{ "Zm9vYmFy\r\n",   "foobar" },
		{ "Zm9vYmFy ",      "foobar" },
		{ "Zm9vYmFy \n",    "foobar" },
		{ "Zm9vYmFy \r\n",  "foobar" },
		{ "Zm9vYmFy  ",     "foobar" },
		{ "Zm9vYmFy  \n",   "foobar" },
		{ "Zm9vYmFy  \r\n", "foobar" },
		{ "Zm9vYmF\ny",     "foobar" },
		{ "Zm9vYmF\r\ny",   "foobar" },
		{ "Zm9vYmF \ny",    "foobar" },
		{ "Zm9vYmF \r\ny",  "foobar" },
		{ "Zm9vYmF  \ny",   "foobar" },
		{ "Zm9vYmF  \r\ny", "foobar" }
	};

	for ( auto test : tests ) {
		uint8_t output[6];
		std::size_t output_sz = sizeof(output);
		std::string out;

		Crypto::Base64::decode(test[0], output, output_sz);
		Crypto::Utils::to_string(output, output_sz, out);
		EXPECT_EQ(out, test[1]);
	}
}

TEST(Base64, decode_invalid_character)
{
	std::string exception, expected = "Invalid character";
	const std::vector<std::string> tests = {
		"zm#=",       "zm===",       "zm=masd",     "zm masd",
		"Zm9vYmFy\r", "Zm9vYmFy \r", "Zm9vYmFy  \r" "Zm9vYmF\ry",
		"Zm9vYmF y",  "Zm9vYmF \ry", "Zm9vYmF  y",  "Zm9vYmF  \ry"
	};

	for ( auto test : tests ) {
		try {
			uint8_t output[11];
			std::size_t output_sz = sizeof(output);
			Crypto::Base64::decode(test, output, output_sz);
		} catch ( const Crypto::Base64::Exception &b64e ) {
			exception = b64e.what();
		}

		EXPECT_EQ(exception, expected);
	}
}
