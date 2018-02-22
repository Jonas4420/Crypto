#include <vector>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "crypto/Utils.hpp"
#include "crypto/SHA3.hpp"
#include "crypto/HMAC.hpp"

TEST(SHA3, init)
{
	// SHA-256
	{
		uint8_t input[32];
		std::size_t input_sz = sizeof(input);
		uint8_t output[32];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::Utils::from_hex("4149f41be1d265e668c536b85dde41", input, input_sz);
		expected_str = "229a7702448c640f55dafed08a52aa0b1139657ba9fc4c5eb8587e174ecd9b92";

		Crypto::SHA3 ctx(32);

		ctx.update(input, input_sz);
		ctx.finish(output);

		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}

	// SHA-512
	{
		uint8_t input[64];
		std::size_t input_sz = sizeof(input);
		uint8_t output[64];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::Utils::from_hex("a6e7b218449840d134b566290dc896", input, input_sz);
		expected_str = "3605a21ce00b289022193b70b535e6626f324739542978f5b307194fcf0a5988"
			"f542c0838a0443bb9bb8ff922a6a177fdbd12cf805f3ed809c48e9769c8bbd91";

		Crypto::SHA3 ctx(64);

		ctx.update(input, input_sz);
		ctx.finish(output);

		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}

	// Invalid digest size (200 <= 2 * digest_sz)
	{
		std::string exception, expected("Invalid digest length");
		try {
			Crypto::SHA3 ctx(100);
		} catch ( const Crypto::SHA3::Exception &se ) {
			exception = se.what();
		}

		EXPECT_EQ(exception, expected);
	}

	// Invalid digest size (200 - 2 * digest_sz <= digest_sz)
	{
		std::string exception, expected("Invalid digest length");
		try {
			Crypto::SHA3 ctx(67);
		} catch ( const Crypto::SHA3::Exception &se ) {
			exception = se.what();
		}

		EXPECT_EQ(exception, expected);
	}
}

TEST(SHA3, test_finish)
{
	// SHA-224
	{
		uint8_t input[143];
		std::size_t input_sz = sizeof(input);
		uint8_t output[28];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::SHA3 ctx(output_sz);

		// Add r - 1 data
		memset(input, 0x00, input_sz);
		ctx.update(input, input_sz);
		ctx.finish(output);

		expected_str = "b6b709fdb9852b8c7439a33595d42dba2940f44c10c3ce09f8b6a87a";
		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}

	// SHA-256
	{
		uint8_t input[135];
		std::size_t input_sz = sizeof(input);
		uint8_t output[32];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::SHA3 ctx(output_sz);

		// Add r - 1 data
		memset(input, 0x00, input_sz);
		ctx.update(input, input_sz);
		ctx.finish(output);

		expected_str = "7d080d7ba978a75c8a7d1f9be566c859084509c9c2b4928435c225d5777d98e3";
		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}

	// SHA-384
	{
		uint8_t input[103];
		std::size_t input_sz = sizeof(input);
		uint8_t output[48];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::SHA3 ctx(output_sz);

		// Add r - 1 data
		memset(input, 0x00, input_sz);
		ctx.update(input, input_sz);
		ctx.finish(output);

		expected_str = "11c556552dda63418669716bad02e4125f4973f3ceea99ee50b6ff117e9f7a3f"
			       "ed0360abb5eff4ac8e954205c01981d2";
		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}

	// SHA-512
	{
		uint8_t input[71];
		std::size_t input_sz = sizeof(input);
		uint8_t output[64];
		std::size_t output_sz = sizeof(output);
		std::string output_str, expected_str;

		Crypto::SHA3 ctx(output_sz);

		// Add r - 1 data
		memset(input, 0x00, input_sz);
		ctx.update(input, input_sz);
		ctx.finish(output);

		expected_str = "cd87417194c917561a59c7f2eb4b95145971e32e8e4ef3b23b0f190bfd29e369"
			       "2cc7975275750a27df95d5c6a99b7a341e1b8a38a750a51aca5b77bae41fbbfc";
		Crypto::Utils::to_hex(output, output_sz, output_str, false);
		EXPECT_EQ(output_str, expected_str);
	}
}

TEST(SHA3_224, digest_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
		}, {
			"01",
			"488286d9d32716e5881ea1ee51f36d3660d70f0db03b3f612ce9eda4"
		}, {
			"69cb",
			"94bd25c4cf6ca889126df37ddd9c36e6a9b28a4fe15cc3da6debcdd7"
		}, {
			"bf5831",
			"1bb36bebde5f3cb6d8e4672acf6eec8728f31a54dacc2560da2a00cc"
		}, {
			"d148ce6d",
			"0b521dac1efe292e20dfb585c8bff481899df72d59983315958391ba"
		}, {
			"91c71068f8",
			"989f017709f50bd0230623c417f3daf194507f7b90a11127ba1638fa"
		}, {
			"e7183e4d89c9",
			"650618f3b945c07de85b8478d69609647d5e2a432c6b15fbb3db91e4"
		}, {
			"d85e470a7c6988",
			"8a134c33c7abd673cd3d0c33956700760de980c5aee74c96e6ba08b2"
		}, {
			"e4ea2c16366b80d6",
			"7dd1a8e3ffe8c99cc547a69af14bd63b15ac26bd3d36b8a99513e89e"
		}, {
			"b29373f6f8839bd498",
			"e02a13fa4770f824bcd69799284878f19bfdc833ac6d865f28b757d0"
		}, {
			"49ec72c29b63036dbecd",
			"47cab44618f62dd431ccb13b3b9cd985d816c5d6026afc38a281aa00"
		}, {
			"502f4e28a6feb4c6a1cc47",
			"bbe61d85b4cae716329e2bcc4038e282b4d7836eb846228835f65308"
		}, {
			"e723c64b2258b5124f88405f",
			"d09da094cfefaad46b7b335830a9305570f4f4afe79f8629ff9d0c3d"
		}, {
			"0d512eceb74d8a047531c1f716",
			"29ae0744051e55167176317eb17850a22939d8d94ebb0a90b6d98fde"
		}, {
			"3b9ab76a23ae56340b5f4b80e1f3",
			"c0903be96f38051cfc2a5ad256aa0b8332217f450eab904ee84b6541"
		}, {
			"e9fef751a20297ad1938662d131e7a",
			"48eba36dfe0575597d13ca26133267199dae76d63d1b9e9612720d08"
		}, {
			"31c82d71785b7ca6b651cb6c8c9ad5e2aceb0b0633c088d33aa247ada7a594ff"
			"4936c023251319820a9b19fc6c48de8a6f7ada214176ccdaadaeef51ed43714a"
			"c0c8269bbd497e46e78bb5e58196494b2471b1680e2d4c6dbd249831bd83a4d3"
			"be06c8a2e903933974aa05ee748bfe6ef359f7a143edf0d4918da916bd6f15e2"
			"6a790cff514b40a5da7f72e1ed2fe63a05b8149587bea05653718cc8980eadbf"
			"eca85b7c9c286dd040936585938be7f98219700c83a9443c2856a80ff46852b2"
			"6d1b1edf72a30203cf6c44a10fa6eaf1920173cedfb5c4cf3ac665b37a86ed02"
			"155bbbf17dc2e786af9478fe0889d86c5bfa85a242eb0854b1482b7bd16f67f8"
			"0bef9c7a628f05a107936a64273a97b0088b0e515451f916b5656230a12ba6dc"
			"78",
			"aab23c9e7fb9d7dacefdfd0b1ae85ab1374abff7c4e3f7556ecae412"
		}, {
			"ab4f9d765085ccb474be6e2369568292532f6fa4dd9c50d02a7d8fab0fabb56a"
			"7f9680a2462c3753fafd3a252f9dddf1eb4a76835acfb59fc2a83441b8674f29"
			"95573697245e40549d2883f1d781a153b903e470f2f28e53e9646a66f7a5a7f0"
			"d5d9e6dd50e392be44867010c7ca77c1a5a2e1f00dcb82f589f759a1332b65c6"
			"2766b9fa3483d399d7602a0969400642976e948d13243a8b89aa287ad5c230b4"
			"7344d7783606aced3dfed86424abf7de77b026ce6cc35d20d1c500794332b0c1"
			"a1bc67dfc033c4c360a8a3aa5fd2f19d2db1bf3b807094b949900827e6438ef5"
			"991692b539d3c42227a6b362847e9d88a1b6855db7f58760d953690b26bd7258"
			"439a7f8409ae53137a3f2f14fa77a2a6bc0aa3bb7a19dd1c69554aae6c6703f3"
			"879057d3978c1a9d41bd3f492985aa0064f43fde2fa33ff6e1dfd4961e0aeacd"
			"4e3f412b4d35c0c864660d8779705a9c82bb824c405c54f429392e4da66ecfee"
			"7ef066139270ee9ccc83be5952ff5c84ffa8938f130cc52129ab825b6a5b585f"
			"01ebed13ce074c225f5b7d441cfc58c0c1039a2f127b3982ca7df546d4993027"
			"bd78ffb36ac08161063870d23f2df556b214",
			"d61f04985026eee29d0f9700f8c5aea32ec2c23b1a9357edeb2be20c"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_224::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], in, in_sz);
		Crypto::MessageDigest_get<Crypto::SHA3_224>(in, in_sz, out);
		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[1]);
	}
}

TEST(SHA3_224, test_update)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
		}, {
			"01",
			"488286d9d32716e5881ea1ee51f36d3660d70f0db03b3f612ce9eda4"
		}, {
			"69cb",
			"94bd25c4cf6ca889126df37ddd9c36e6a9b28a4fe15cc3da6debcdd7"
		}, {
			"bf5831",
			"1bb36bebde5f3cb6d8e4672acf6eec8728f31a54dacc2560da2a00cc"
		}, {
			"d148ce6d",
			"0b521dac1efe292e20dfb585c8bff481899df72d59983315958391ba"
		}, {
			"91c71068f8",
			"989f017709f50bd0230623c417f3daf194507f7b90a11127ba1638fa"
		}, {
			"e7183e4d89c9",
			"650618f3b945c07de85b8478d69609647d5e2a432c6b15fbb3db91e4"
		}, {
			"d85e470a7c6988",
			"8a134c33c7abd673cd3d0c33956700760de980c5aee74c96e6ba08b2"
		}, {
			"e4ea2c16366b80d6",
			"7dd1a8e3ffe8c99cc547a69af14bd63b15ac26bd3d36b8a99513e89e"
		}, {
			"b29373f6f8839bd498",
			"e02a13fa4770f824bcd69799284878f19bfdc833ac6d865f28b757d0"
		}, {
			"49ec72c29b63036dbecd",
			"47cab44618f62dd431ccb13b3b9cd985d816c5d6026afc38a281aa00"
		}, {
			"502f4e28a6feb4c6a1cc47",
			"bbe61d85b4cae716329e2bcc4038e282b4d7836eb846228835f65308"
		}, {
			"e723c64b2258b5124f88405f",
			"d09da094cfefaad46b7b335830a9305570f4f4afe79f8629ff9d0c3d"
		}, {
			"0d512eceb74d8a047531c1f716",
			"29ae0744051e55167176317eb17850a22939d8d94ebb0a90b6d98fde"
		}, {
			"3b9ab76a23ae56340b5f4b80e1f3",
			"c0903be96f38051cfc2a5ad256aa0b8332217f450eab904ee84b6541"
		}, {
			"e9fef751a20297ad1938662d131e7a",
			"48eba36dfe0575597d13ca26133267199dae76d63d1b9e9612720d08"
		}, {
			"31c82d71785b7ca6b651cb6c8c9ad5e2aceb0b0633c088d33aa247ada7a594ff"
			"4936c023251319820a9b19fc6c48de8a6f7ada214176ccdaadaeef51ed43714a"
			"c0c8269bbd497e46e78bb5e58196494b2471b1680e2d4c6dbd249831bd83a4d3"
			"be06c8a2e903933974aa05ee748bfe6ef359f7a143edf0d4918da916bd6f15e2"
			"6a790cff514b40a5da7f72e1ed2fe63a05b8149587bea05653718cc8980eadbf"
			"eca85b7c9c286dd040936585938be7f98219700c83a9443c2856a80ff46852b2"
			"6d1b1edf72a30203cf6c44a10fa6eaf1920173cedfb5c4cf3ac665b37a86ed02"
			"155bbbf17dc2e786af9478fe0889d86c5bfa85a242eb0854b1482b7bd16f67f8"
			"0bef9c7a628f05a107936a64273a97b0088b0e515451f916b5656230a12ba6dc"
			"78",
			"aab23c9e7fb9d7dacefdfd0b1ae85ab1374abff7c4e3f7556ecae412"
		}, {
			"ab4f9d765085ccb474be6e2369568292532f6fa4dd9c50d02a7d8fab0fabb56a"
			"7f9680a2462c3753fafd3a252f9dddf1eb4a76835acfb59fc2a83441b8674f29"
			"95573697245e40549d2883f1d781a153b903e470f2f28e53e9646a66f7a5a7f0"
			"d5d9e6dd50e392be44867010c7ca77c1a5a2e1f00dcb82f589f759a1332b65c6"
			"2766b9fa3483d399d7602a0969400642976e948d13243a8b89aa287ad5c230b4"
			"7344d7783606aced3dfed86424abf7de77b026ce6cc35d20d1c500794332b0c1"
			"a1bc67dfc033c4c360a8a3aa5fd2f19d2db1bf3b807094b949900827e6438ef5"
			"991692b539d3c42227a6b362847e9d88a1b6855db7f58760d953690b26bd7258"
			"439a7f8409ae53137a3f2f14fa77a2a6bc0aa3bb7a19dd1c69554aae6c6703f3"
			"879057d3978c1a9d41bd3f492985aa0064f43fde2fa33ff6e1dfd4961e0aeacd"
			"4e3f412b4d35c0c864660d8779705a9c82bb824c405c54f429392e4da66ecfee"
			"7ef066139270ee9ccc83be5952ff5c84ffa8938f130cc52129ab825b6a5b585f"
			"01ebed13ce074c225f5b7d441cfc58c0c1039a2f127b3982ca7df546d4993027"
			"bd78ffb36ac08161063870d23f2df556b214",
			"d61f04985026eee29d0f9700f8c5aea32ec2c23b1a9357edeb2be20c"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_224::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], in, in_sz);

		Crypto::SHA3_224 ctx;
		for ( std::size_t i = 0 ; i < in_sz ; ++i ) {
			ctx.update(&in[i], 1);
		}
		ctx.finish(out);

		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[1]);
	}
}

TEST(SHA3_224, reset_ctx)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
		}, {
			"01",
			"488286d9d32716e5881ea1ee51f36d3660d70f0db03b3f612ce9eda4"
		}, {
			"69cb",
			"94bd25c4cf6ca889126df37ddd9c36e6a9b28a4fe15cc3da6debcdd7"
		}, {
			"bf5831",
			"1bb36bebde5f3cb6d8e4672acf6eec8728f31a54dacc2560da2a00cc"
		}, {
			"d148ce6d",
			"0b521dac1efe292e20dfb585c8bff481899df72d59983315958391ba"
		}, {
			"91c71068f8",
			"989f017709f50bd0230623c417f3daf194507f7b90a11127ba1638fa"
		}, {
			"e7183e4d89c9",
			"650618f3b945c07de85b8478d69609647d5e2a432c6b15fbb3db91e4"
		}, {
			"d85e470a7c6988",
			"8a134c33c7abd673cd3d0c33956700760de980c5aee74c96e6ba08b2"
		}, {
			"e4ea2c16366b80d6",
			"7dd1a8e3ffe8c99cc547a69af14bd63b15ac26bd3d36b8a99513e89e"
		}, {
			"b29373f6f8839bd498",
			"e02a13fa4770f824bcd69799284878f19bfdc833ac6d865f28b757d0"
		}, {
			"49ec72c29b63036dbecd",
			"47cab44618f62dd431ccb13b3b9cd985d816c5d6026afc38a281aa00"
		}, {
			"502f4e28a6feb4c6a1cc47",
			"bbe61d85b4cae716329e2bcc4038e282b4d7836eb846228835f65308"
		}, {
			"e723c64b2258b5124f88405f",
			"d09da094cfefaad46b7b335830a9305570f4f4afe79f8629ff9d0c3d"
		}, {
			"0d512eceb74d8a047531c1f716",
			"29ae0744051e55167176317eb17850a22939d8d94ebb0a90b6d98fde"
		}, {
			"3b9ab76a23ae56340b5f4b80e1f3",
			"c0903be96f38051cfc2a5ad256aa0b8332217f450eab904ee84b6541"
		}, {
			"e9fef751a20297ad1938662d131e7a",
			"48eba36dfe0575597d13ca26133267199dae76d63d1b9e9612720d08"
		}, {
			"31c82d71785b7ca6b651cb6c8c9ad5e2aceb0b0633c088d33aa247ada7a594ff"
			"4936c023251319820a9b19fc6c48de8a6f7ada214176ccdaadaeef51ed43714a"
			"c0c8269bbd497e46e78bb5e58196494b2471b1680e2d4c6dbd249831bd83a4d3"
			"be06c8a2e903933974aa05ee748bfe6ef359f7a143edf0d4918da916bd6f15e2"
			"6a790cff514b40a5da7f72e1ed2fe63a05b8149587bea05653718cc8980eadbf"
			"eca85b7c9c286dd040936585938be7f98219700c83a9443c2856a80ff46852b2"
			"6d1b1edf72a30203cf6c44a10fa6eaf1920173cedfb5c4cf3ac665b37a86ed02"
			"155bbbf17dc2e786af9478fe0889d86c5bfa85a242eb0854b1482b7bd16f67f8"
			"0bef9c7a628f05a107936a64273a97b0088b0e515451f916b5656230a12ba6dc"
			"78",
			"aab23c9e7fb9d7dacefdfd0b1ae85ab1374abff7c4e3f7556ecae412"
		}, {
			"ab4f9d765085ccb474be6e2369568292532f6fa4dd9c50d02a7d8fab0fabb56a"
			"7f9680a2462c3753fafd3a252f9dddf1eb4a76835acfb59fc2a83441b8674f29"
			"95573697245e40549d2883f1d781a153b903e470f2f28e53e9646a66f7a5a7f0"
			"d5d9e6dd50e392be44867010c7ca77c1a5a2e1f00dcb82f589f759a1332b65c6"
			"2766b9fa3483d399d7602a0969400642976e948d13243a8b89aa287ad5c230b4"
			"7344d7783606aced3dfed86424abf7de77b026ce6cc35d20d1c500794332b0c1"
			"a1bc67dfc033c4c360a8a3aa5fd2f19d2db1bf3b807094b949900827e6438ef5"
			"991692b539d3c42227a6b362847e9d88a1b6855db7f58760d953690b26bd7258"
			"439a7f8409ae53137a3f2f14fa77a2a6bc0aa3bb7a19dd1c69554aae6c6703f3"
			"879057d3978c1a9d41bd3f492985aa0064f43fde2fa33ff6e1dfd4961e0aeacd"
			"4e3f412b4d35c0c864660d8779705a9c82bb824c405c54f429392e4da66ecfee"
			"7ef066139270ee9ccc83be5952ff5c84ffa8938f130cc52129ab825b6a5b585f"
			"01ebed13ce074c225f5b7d441cfc58c0c1039a2f127b3982ca7df546d4993027"
			"bd78ffb36ac08161063870d23f2df556b214",
			"d61f04985026eee29d0f9700f8c5aea32ec2c23b1a9357edeb2be20c"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);

		uint8_t out_1[Crypto::SHA3_224::SIZE];
		uint8_t out_2[Crypto::SHA3_224::SIZE];
		std::string output_1, output_2;

		Crypto::Utils::from_hex(test[0], in, in_sz);

		Crypto::SHA3_224 ctx;
		ctx.update(in, in_sz);
		ctx.reset();
		ctx.update(in, in_sz);
		ctx.finish(out_1);
		Crypto::Utils::to_hex(out_1, sizeof(out_1), output_1, false);

		ctx.update(in, in_sz);
		ctx.finish(out_2);
		Crypto::Utils::to_hex(out_2, sizeof(out_2), output_2, false);

		EXPECT_THAT(output_1, test[1]);
		EXPECT_THAT(output_2, test[1]);
	}
}

TEST(SHA3_224, mac_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			"4869205468657265",
			"3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7"
		}, {
			"4a656665",
			"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"7fdb8dd88bd2f60d1b798634ad386811c2cfc85bfaf5d52bbace5e66"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			"dddddddddddddddddddddddddddddddddddd",
			"676cfc7d16153638780390692be142d2df7ce924b909c0c08dbfdc1a"
		}, {
			"0102030405060708090a0b0c0d0e0f10111213141516171819",
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
			"a9d7685a19c4e0dbd9df2556cc8a7d2a7733b67625ce594c78270eeb"
		}, {
			"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
			"546573742057697468205472756e636174696f6e",
			"49fdd3abd005ebb8ae63fea946d1883cc7f3be2f6b42cdce921110e0"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579204669727374",
			"b4a1f04c00287a9b7f6075b313d279b833bc8f75124352d05fb9995f"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579204669727374",
			"b96d730c148c2daad8649d83defaa3719738d34775397b7571c38515"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa",
			"5468697320697320612074657374207573696e672061206c6172676572207468"
			"616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
			"647320746f20626520686173686564206265666f7265206265696e6720757365"
			"642062792074686520484d414320616c676f726974686d2e",
			"05d8cd6d00faea8d1eb68ade28730bbd3cbab6929f0a086b29cd62a0"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"5468697320697320612074657374207573696e672061206c6172676572207468"
			"616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
			"647320746f20626520686173686564206265666f7265206265696e6720757365"
			"642062792074686520484d414320616c676f726974686d2e",
			"c79c9b093424e588a9878bbcb089e018270096e9b4b1a9e8220c866a"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[2048];
		std::size_t key_sz = sizeof(key);
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_224::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], key, key_sz);
		Crypto::Utils::from_hex(test[1], in,  in_sz);

		Crypto::HMAC_get<Crypto::SHA3_224>(key, key_sz, in, in_sz, out);
		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[2]);
	}
}

TEST(SHA3_256, digest_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
		}, {
			"e9",
			"f0d04dd1e6cfc29a4460d521796852f25d9ef8d28b44ee91ff5b759d72c1e6d6"
		}, {
			"d477",
			"94279e8f5ccdf6e17f292b59698ab4e614dfe696a46c46da78305fc6a3146ab7"
		}, {
			"b053fa",
			"9d0ff086cd0ec06a682c51c094dc73abdc492004292344bd41b82a60498ccfdb"
		}, {
			"e7372105",
			"3a42b68ab079f28c4ca3c752296f279006c4fe78b1eb79d989777f051e4046ae"
		}, {
			"0296f2c40a",
			"53a018937221081d09ed0497377e32a1fa724025dfdc1871fa503d545df4b40d"
		}, {
			"e6fd42037f80",
			"2294f8d3834f24aa9037c431f8c233a66a57b23fa3de10530bbb6911f6e1850f"
		}, {
			"37b442385e0538",
			"cfa55031e716bbd7a83f2157513099e229a88891bb899d9ccd317191819998f8"
		}, {
			"8bca931c8a132d2f",
			"dbb8be5dec1d715bd117b24566dc3f24f2cc0c799795d0638d9537481ef1e03e"
		}, {
			"fb8dfa3a132f9813ac",
			"fd09b3501888445ffc8c3bb95d106440ceee469415fce1474743273094306e2e"
		}, {
			"71fbacdbf8541779c24a",
			"cc4e5a216b01f987f24ab9cad5eb196e89d32ed4aac85acb727e18e40ceef00e"
		}, {
			"7e8f1fd1882e4a7c49e674",
			"79bef78c78aa71e11a3375394c2562037cd0f82a033b48a6cc932cc43358fd9e"
		}, {
			"5c56a6b18c39e66e1b7a993a",
			"b697556cb30d6df448ee38b973cb6942559de4c2567b1556240188c55ec0841c"
		}, {
			"9c76ca5b6f8d1212d8e6896ad8",
			"69dfc3a25865f3535f18b4a7bd9c0c69d78455f1fc1f4bf4e29fc82bf32818ec"
		}, {
			"687ff7485b7eb51fe208f6ff9a1b",
			"fe7e68ae3e1a91944e4d1d2146d9360e5333c099a256f3711edc372bc6eeb226"
		}, {
			"4149f41be1d265e668c536b85dde41",
			"229a7702448c640f55dafed08a52aa0b1139657ba9fc4c5eb8587e174ecd9b92"
		}, {
			"b1caa396771a09a1db9bc20543e988e359d47c2a616417bbca1b62cb02796a88"
			"8fc6eeff5c0b5c3d5062fcb4256f6ae1782f492c1cf03610b4a1fb7b814c0578"
			"78e1190b9835425c7a4a0e182ad1f91535ed2a35033a5d8c670e21c575ff43c1"
			"94a58a82d4a1a44881dd61f9f8161fc6b998860cbe4975780be93b6f87980bad"
			"0a99aa2cb7556b478ca35d1f3746c33e2bb7c47af426641cc7bbb3425e214482"
			"0345e1d0ea5b7da2c3236a52906acdc3b4d34e474dd714c0c40bf006a3a1d889"
			"a632983814bbc4a14fe5f159aa89249e7c738b3b73666bac2a615a83fd21ae0a"
			"1ce7352ade7b278b587158fd2fabb217aa1fe31d0bda53272045598015a8ae4d"
			"8cec226fefa58daa05500906c4d85e7567",
			"cb5648a1d61c6c5bdacd96f81c9591debc3950dcf658145b8d996570ba881a05"
		}, {
			"712b03d9ebe78d3a032a612939c518a6166ca9a161183a7596aa35b294d19d1f"
			"962da3ff64b57494cb5656e24adcf3b50e16f4e52135d2d9de76e94aa801cf49"
			"db10e384035329c54c9455bb3a9725fd9a44f44cb9078d18d3783d46ce372c31"
			"281aecef2f8b53d5702b863d71bc5786a33dd15d9256103b5ff7572f703d5cde"
			"6695e6c84f239acd1d6512ef581330590f4ab2a114ea064a693d5f8df5d90858"
			"7bc7f998cde4a8b43d8821595566597dc8b3bf9ea78b154bd8907ee6c5d4d8a8"
			"51f94be510962292b7ddda04d17b79fab4c022deb400e5489639dbc448f573d5"
			"cf72073a8001b36f73ac6677351b39d9bdb900e9a1121f488a7fa0aee60682e7"
			"dc7c531c85ec0154593ded3ae70e4121cae58445d8896b549cacf22d07cdace7"
			"625d57158721b44851d796d6511c38dac28dd37cbf2d7073b407fbc813149adc"
			"485e3dacee66755443c389d2d90dc70d8ff91816c0c5d7adbad7e30772a1f3ce"
			"76c72a6a2284ec7f174aefb6e9a895c118717999421b470a9665d2728c3c60c6"
			"d3e048d58b43c0d1b5b2f00be8b64bfe453d1e8fadf5699331f9",
			"095dcd0bc55206d2e1e715fb7173fc16a81979f278495dfc69a6d8f3174eba5a"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_256::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], in, in_sz);
		Crypto::MessageDigest_get<Crypto::SHA3_256>(in, in_sz, out);
		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[1]);
	}
}

TEST(SHA3_256, test_update)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
		}, {
			"e9",
			"f0d04dd1e6cfc29a4460d521796852f25d9ef8d28b44ee91ff5b759d72c1e6d6"
		}, {
			"d477",
			"94279e8f5ccdf6e17f292b59698ab4e614dfe696a46c46da78305fc6a3146ab7"
		}, {
			"b053fa",
			"9d0ff086cd0ec06a682c51c094dc73abdc492004292344bd41b82a60498ccfdb"
		}, {
			"e7372105",
			"3a42b68ab079f28c4ca3c752296f279006c4fe78b1eb79d989777f051e4046ae"
		}, {
			"0296f2c40a",
			"53a018937221081d09ed0497377e32a1fa724025dfdc1871fa503d545df4b40d"
		}, {
			"e6fd42037f80",
			"2294f8d3834f24aa9037c431f8c233a66a57b23fa3de10530bbb6911f6e1850f"
		}, {
			"37b442385e0538",
			"cfa55031e716bbd7a83f2157513099e229a88891bb899d9ccd317191819998f8"
		}, {
			"8bca931c8a132d2f",
			"dbb8be5dec1d715bd117b24566dc3f24f2cc0c799795d0638d9537481ef1e03e"
		}, {
			"fb8dfa3a132f9813ac",
			"fd09b3501888445ffc8c3bb95d106440ceee469415fce1474743273094306e2e"
		}, {
			"71fbacdbf8541779c24a",
			"cc4e5a216b01f987f24ab9cad5eb196e89d32ed4aac85acb727e18e40ceef00e"
		}, {
			"7e8f1fd1882e4a7c49e674",
			"79bef78c78aa71e11a3375394c2562037cd0f82a033b48a6cc932cc43358fd9e"
		}, {
			"5c56a6b18c39e66e1b7a993a",
			"b697556cb30d6df448ee38b973cb6942559de4c2567b1556240188c55ec0841c"
		}, {
			"9c76ca5b6f8d1212d8e6896ad8",
			"69dfc3a25865f3535f18b4a7bd9c0c69d78455f1fc1f4bf4e29fc82bf32818ec"
		}, {
			"687ff7485b7eb51fe208f6ff9a1b",
			"fe7e68ae3e1a91944e4d1d2146d9360e5333c099a256f3711edc372bc6eeb226"
		}, {
			"4149f41be1d265e668c536b85dde41",
			"229a7702448c640f55dafed08a52aa0b1139657ba9fc4c5eb8587e174ecd9b92"
		}, {
			"b1caa396771a09a1db9bc20543e988e359d47c2a616417bbca1b62cb02796a88"
			"8fc6eeff5c0b5c3d5062fcb4256f6ae1782f492c1cf03610b4a1fb7b814c0578"
			"78e1190b9835425c7a4a0e182ad1f91535ed2a35033a5d8c670e21c575ff43c1"
			"94a58a82d4a1a44881dd61f9f8161fc6b998860cbe4975780be93b6f87980bad"
			"0a99aa2cb7556b478ca35d1f3746c33e2bb7c47af426641cc7bbb3425e214482"
			"0345e1d0ea5b7da2c3236a52906acdc3b4d34e474dd714c0c40bf006a3a1d889"
			"a632983814bbc4a14fe5f159aa89249e7c738b3b73666bac2a615a83fd21ae0a"
			"1ce7352ade7b278b587158fd2fabb217aa1fe31d0bda53272045598015a8ae4d"
			"8cec226fefa58daa05500906c4d85e7567",
			"cb5648a1d61c6c5bdacd96f81c9591debc3950dcf658145b8d996570ba881a05"
		}, {
			"712b03d9ebe78d3a032a612939c518a6166ca9a161183a7596aa35b294d19d1f"
			"962da3ff64b57494cb5656e24adcf3b50e16f4e52135d2d9de76e94aa801cf49"
			"db10e384035329c54c9455bb3a9725fd9a44f44cb9078d18d3783d46ce372c31"
			"281aecef2f8b53d5702b863d71bc5786a33dd15d9256103b5ff7572f703d5cde"
			"6695e6c84f239acd1d6512ef581330590f4ab2a114ea064a693d5f8df5d90858"
			"7bc7f998cde4a8b43d8821595566597dc8b3bf9ea78b154bd8907ee6c5d4d8a8"
			"51f94be510962292b7ddda04d17b79fab4c022deb400e5489639dbc448f573d5"
			"cf72073a8001b36f73ac6677351b39d9bdb900e9a1121f488a7fa0aee60682e7"
			"dc7c531c85ec0154593ded3ae70e4121cae58445d8896b549cacf22d07cdace7"
			"625d57158721b44851d796d6511c38dac28dd37cbf2d7073b407fbc813149adc"
			"485e3dacee66755443c389d2d90dc70d8ff91816c0c5d7adbad7e30772a1f3ce"
			"76c72a6a2284ec7f174aefb6e9a895c118717999421b470a9665d2728c3c60c6"
			"d3e048d58b43c0d1b5b2f00be8b64bfe453d1e8fadf5699331f9",
			"095dcd0bc55206d2e1e715fb7173fc16a81979f278495dfc69a6d8f3174eba5a"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_256::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], in, in_sz);

		Crypto::SHA3_256 ctx;
		for ( std::size_t i = 0 ; i < in_sz ; ++i ) {
			ctx.update(&in[i], 1);
		}
		ctx.finish(out);

		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[1]);
	}
}

TEST(SHA3_256, reset_ctx)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
		}, {
			"e9",
			"f0d04dd1e6cfc29a4460d521796852f25d9ef8d28b44ee91ff5b759d72c1e6d6"
		}, {
			"d477",
			"94279e8f5ccdf6e17f292b59698ab4e614dfe696a46c46da78305fc6a3146ab7"
		}, {
			"b053fa",
			"9d0ff086cd0ec06a682c51c094dc73abdc492004292344bd41b82a60498ccfdb"
		}, {
			"e7372105",
			"3a42b68ab079f28c4ca3c752296f279006c4fe78b1eb79d989777f051e4046ae"
		}, {
			"0296f2c40a",
			"53a018937221081d09ed0497377e32a1fa724025dfdc1871fa503d545df4b40d"
		}, {
			"e6fd42037f80",
			"2294f8d3834f24aa9037c431f8c233a66a57b23fa3de10530bbb6911f6e1850f"
		}, {
			"37b442385e0538",
			"cfa55031e716bbd7a83f2157513099e229a88891bb899d9ccd317191819998f8"
		}, {
			"8bca931c8a132d2f",
			"dbb8be5dec1d715bd117b24566dc3f24f2cc0c799795d0638d9537481ef1e03e"
		}, {
			"fb8dfa3a132f9813ac",
			"fd09b3501888445ffc8c3bb95d106440ceee469415fce1474743273094306e2e"
		}, {
			"71fbacdbf8541779c24a",
			"cc4e5a216b01f987f24ab9cad5eb196e89d32ed4aac85acb727e18e40ceef00e"
		}, {
			"7e8f1fd1882e4a7c49e674",
			"79bef78c78aa71e11a3375394c2562037cd0f82a033b48a6cc932cc43358fd9e"
		}, {
			"5c56a6b18c39e66e1b7a993a",
			"b697556cb30d6df448ee38b973cb6942559de4c2567b1556240188c55ec0841c"
		}, {
			"9c76ca5b6f8d1212d8e6896ad8",
			"69dfc3a25865f3535f18b4a7bd9c0c69d78455f1fc1f4bf4e29fc82bf32818ec"
		}, {
			"687ff7485b7eb51fe208f6ff9a1b",
			"fe7e68ae3e1a91944e4d1d2146d9360e5333c099a256f3711edc372bc6eeb226"
		}, {
			"4149f41be1d265e668c536b85dde41",
			"229a7702448c640f55dafed08a52aa0b1139657ba9fc4c5eb8587e174ecd9b92"
		}, {
			"b1caa396771a09a1db9bc20543e988e359d47c2a616417bbca1b62cb02796a88"
			"8fc6eeff5c0b5c3d5062fcb4256f6ae1782f492c1cf03610b4a1fb7b814c0578"
			"78e1190b9835425c7a4a0e182ad1f91535ed2a35033a5d8c670e21c575ff43c1"
			"94a58a82d4a1a44881dd61f9f8161fc6b998860cbe4975780be93b6f87980bad"
			"0a99aa2cb7556b478ca35d1f3746c33e2bb7c47af426641cc7bbb3425e214482"
			"0345e1d0ea5b7da2c3236a52906acdc3b4d34e474dd714c0c40bf006a3a1d889"
			"a632983814bbc4a14fe5f159aa89249e7c738b3b73666bac2a615a83fd21ae0a"
			"1ce7352ade7b278b587158fd2fabb217aa1fe31d0bda53272045598015a8ae4d"
			"8cec226fefa58daa05500906c4d85e7567",
			"cb5648a1d61c6c5bdacd96f81c9591debc3950dcf658145b8d996570ba881a05"
		}, {
			"712b03d9ebe78d3a032a612939c518a6166ca9a161183a7596aa35b294d19d1f"
			"962da3ff64b57494cb5656e24adcf3b50e16f4e52135d2d9de76e94aa801cf49"
			"db10e384035329c54c9455bb3a9725fd9a44f44cb9078d18d3783d46ce372c31"
			"281aecef2f8b53d5702b863d71bc5786a33dd15d9256103b5ff7572f703d5cde"
			"6695e6c84f239acd1d6512ef581330590f4ab2a114ea064a693d5f8df5d90858"
			"7bc7f998cde4a8b43d8821595566597dc8b3bf9ea78b154bd8907ee6c5d4d8a8"
			"51f94be510962292b7ddda04d17b79fab4c022deb400e5489639dbc448f573d5"
			"cf72073a8001b36f73ac6677351b39d9bdb900e9a1121f488a7fa0aee60682e7"
			"dc7c531c85ec0154593ded3ae70e4121cae58445d8896b549cacf22d07cdace7"
			"625d57158721b44851d796d6511c38dac28dd37cbf2d7073b407fbc813149adc"
			"485e3dacee66755443c389d2d90dc70d8ff91816c0c5d7adbad7e30772a1f3ce"
			"76c72a6a2284ec7f174aefb6e9a895c118717999421b470a9665d2728c3c60c6"
			"d3e048d58b43c0d1b5b2f00be8b64bfe453d1e8fadf5699331f9",
			"095dcd0bc55206d2e1e715fb7173fc16a81979f278495dfc69a6d8f3174eba5a"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);

		uint8_t out_1[Crypto::SHA3_256::SIZE];
		uint8_t out_2[Crypto::SHA3_256::SIZE];
		std::string output_1, output_2;

		Crypto::Utils::from_hex(test[0], in, in_sz);

		Crypto::SHA3_256 ctx;
		ctx.update(in, in_sz);
		ctx.reset();
		ctx.update(in, in_sz);
		ctx.finish(out_1);
		Crypto::Utils::to_hex(out_1, sizeof(out_1), output_1, false);

		ctx.update(in, in_sz);
		ctx.finish(out_2);
		Crypto::Utils::to_hex(out_2, sizeof(out_2), output_2, false);

		EXPECT_THAT(output_1, test[1]);
		EXPECT_THAT(output_2, test[1]);
	}
}

TEST(SHA3_256, mac_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			"4869205468657265",
			"ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb"
		}, {
			"4a656665",
			"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			"dddddddddddddddddddddddddddddddddddd",
			"84ec79124a27107865cedd8bd82da9965e5ed8c37b0ac98005a7f39ed58a4207"
		}, {
			"0102030405060708090a0b0c0d0e0f10111213141516171819",
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
			"57366a45e2305321a4bc5aa5fe2ef8a921f6af8273d7fe7be6cfedb3f0aea6d7"
		}, {
			"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
			"546573742057697468205472756e636174696f6e",
			"6e02c64537fb118057abb7fb66a23b3c5d31bc4b9832edf9528474ce498bdd97"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579204669727374",
			"ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579204669727374",
			"a6072f86de52b38bb349fe84cd6d97fb6a37c4c0f62aae93981193a7229d3467"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa",
			"5468697320697320612074657374207573696e672061206c6172676572207468"
			"616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
			"647320746f20626520686173686564206265666f7265206265696e6720757365"
			"642062792074686520484d414320616c676f726974686d2e",
			"65c5b06d4c3de32a7aef8763261e49adb6e2293ec8e7c61e8de61701fc63e123"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"5468697320697320612074657374207573696e672061206c6172676572207468"
			"616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
			"647320746f20626520686173686564206265666f7265206265696e6720757365"
			"642062792074686520484d414320616c676f726974686d2e",
			"e6a36d9b915f86a093cac7d110e9e04cf1d6100d30475509c2475f571b758b5a"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[2048];
		std::size_t key_sz = sizeof(key);
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_256::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], key, key_sz);
		Crypto::Utils::from_hex(test[1], in,  in_sz);

		Crypto::HMAC_get<Crypto::SHA3_256>(key, key_sz, in, in_sz, out);
		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[2]);
	}
}

TEST(SHA3_384, digest_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
			"c3713831264adb47fb6bd1e058d5f004"
		}, {
			"80",
			"7541384852e10ff10d5fb6a7213a4a6c15ccc86d8bc1068ac04f69277142944f"
			"4ee50d91fdc56553db06b2f5039c8ab7"
		}, {
			"fb52",
			"d73a9d0e7f1802352ea54f3e062d3910577bf87edda48101de92a3de957e698b"
			"836085f5f10cab1de19fd0c906e48385"
		}, {
			"6ab7d6",
			"ea12d6d32d69ad2154a57e0e1be481a45add739ee7dd6e2a27e544b6c8b5ad12"
			"2654bbf95134d567987156295d5e57db"
		}, {
			"11587dcb",
			"cb6e6ce4a266d438ddd52867f2e183021be50223c7d57f8fdcaa18093a9d0126"
			"607df026c025bff40bc314af43fd8a08"
		}, {
			"4d7fc6cae6",
			"e570d463a010c71b78acd7f9790c78ce946e00cc54dae82bfc3833a10f0d8d35"
			"b03cbb4aa2f9ba4b27498807a397cd47"
		}, {
			"5a6659e9f0e7",
			"21b1f3f63b907f968821185a7fe30b16d47e1d6ee5b9c80be68947854de7a8ef"
			"4a03a6b2e4ec96abdd4fa29ab9796f28"
		}, {
			"17510eca2fe11b",
			"35fba6958b6c68eae8f2b5f5bdf5ebcc565252bc70f983548c2dfd5406f111a0"
			"a95b1bb9a639988c8d65da912d2c3ea2"
		}, {
			"c44a2c58c84c393a",
			"60ad40f964d0edcf19281e415f7389968275ff613199a069c916a0ff7ef65503"
			"b740683162a622b913d43a46559e913c"
		}, {
			"a36e5a59043b6333d7",
			"bd045661663436d07720ff3c8b6f922066dfe244456a56ca46dfb3f7e271116d"
			"932107c7b04cc7c60173e08d0c2e107c"
		}, {
			"c0920f2bd1e2d302259b",
			"3d1584220409f88d38409a29ecaebb490ef884b5acba2c7eaf23914bab7f5f0f"
			"c97ee1e6336f88dfd4d0a06e902ccd25"
		}, {
			"70ae731af5e0d92d264ec9",
			"563359fd93fe09f3fe49fcf5f17e7f92aab589cdec3e55e4c3715e7775814bbb"
			"fb8c4c732e28d3b6e6404860812dc6e9"
		}, {
			"69c74a9b0db538eeff64d93d",
			"88c66389ca2c320a39022aa441fa884fbc6ed2d3cc9ac475372d947d4960579a"
			"64e061a297d1831d3524f98d8094404b"
		}, {
			"a4a9327be21b9277e08c40abc7",
			"751f5da5ff9e2460c99348070d5068d8a3d7ffcec7fd0e6f68f6cd4a2ef4226d"
			"f8d9b4613c3b0d10a168eaf54eabe01a"
		}, {
			"cc4764d3e295097298f2af8882f6",
			"10f287f256643ad0dfb5955dd34587882e445cd5ae8da337e7c170fc0c1e48a0"
			"3fb7a54ec71335113dbdccccc944da41"
		}, {
			"5a23ad0ce89e0fb1df4a95bb2488f0",
			"23840671e7570a248cf3579c7c8810b5fcc35b975a3a43b506cc67faefa6dbe1"
			"c945abc09a903e199f759dcbc7f2c4d0"
		}, {
			"5fe35923b4e0af7dd24971812a58425519850a506dfa9b0d254795be785786c3"
			"19a2567cbaa5e35bcf8fe83d943e23fa5169b73adc1fcf8b607084b15e6a013d"
			"f147e46256e4e803ab75c110f77848136be7d806e8b2f868c16c3a90c1446340"
			"7038cb7d9285079ef162c6a45cedf9c9f066375c969b5fcbcda37f02aacff4f3"
			"1cded3767570885426bebd9eca877e44674e9ae2f0c24cdd0e7e1aaf1ff2fe7f"
			"80a1c4f5078eb34cd4f06fa94a2d1eab5806ca43fd0f06c60b63d5402b95c70c"
			"21ea65a151c5cfaf8262a46be3c722264b",
			"3054d249f916a6039b2a9c3ebec1418791a0608a170e6d36486035e5f92635ea"
			"ba98072a85373cb54e2ae3f982ce132b"
		}, {
			"035adcb639e5f28bb5c88658f45c1ce0be16e7dafe083b98d0ab45e8dcdbfa38"
			"e3234dfd973ba555b0cf8eea3c82ae1a3633fc565b7f2cc839876d3989f35731"
			"be371f60de140e3c916231ec780e5165bf5f25d3f67dc73a1c33655dfdf439df"
			"bf1cbba8b779158a810ad7244f06ec078120cd18760af436a238941ce1e68788"
			"0b5c879dc971a285a74ee85c6a746749a30159ee842e9b03f31d613dddd22975"
			"cd7fed06bd049d772cb6cc5a705faa734e87321dc8f2a4ea366a368a98bf06ee"
			"2b0b54ac3a3aeea637caebe70ad09ccda93cc06de95df73394a87ac9bbb5083a"
			"4d8a2458e91c7d5bf113aecae0ce279fdda76ba690787d26345e94c3edbc16a3"
			"5c83c4d071b132dd81187bcd9961323011509c8f644a1c0a3f14ee40d7dd186f"
			"807f9edc7c02f6761061bbb6dd91a6c96ec0b9f10edbbd29dc52",
			"02535d86cc7518484a2a238c921b739b1704a50370a2924abf39958c5976e658"
			"dc5e87440063112459bddb40308b1c70"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_384::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], in, in_sz);
		Crypto::MessageDigest_get<Crypto::SHA3_384>(in, in_sz, out);
		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[1]);
	}
}

TEST(SHA3_384, test_update)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
			"c3713831264adb47fb6bd1e058d5f004"
		}, {
			"80",
			"7541384852e10ff10d5fb6a7213a4a6c15ccc86d8bc1068ac04f69277142944f"
			"4ee50d91fdc56553db06b2f5039c8ab7"
		}, {
			"fb52",
			"d73a9d0e7f1802352ea54f3e062d3910577bf87edda48101de92a3de957e698b"
			"836085f5f10cab1de19fd0c906e48385"
		}, {
			"6ab7d6",
			"ea12d6d32d69ad2154a57e0e1be481a45add739ee7dd6e2a27e544b6c8b5ad12"
			"2654bbf95134d567987156295d5e57db"
		}, {
			"11587dcb",
			"cb6e6ce4a266d438ddd52867f2e183021be50223c7d57f8fdcaa18093a9d0126"
			"607df026c025bff40bc314af43fd8a08"
		}, {
			"4d7fc6cae6",
			"e570d463a010c71b78acd7f9790c78ce946e00cc54dae82bfc3833a10f0d8d35"
			"b03cbb4aa2f9ba4b27498807a397cd47"
		}, {
			"5a6659e9f0e7",
			"21b1f3f63b907f968821185a7fe30b16d47e1d6ee5b9c80be68947854de7a8ef"
			"4a03a6b2e4ec96abdd4fa29ab9796f28"
		}, {
			"17510eca2fe11b",
			"35fba6958b6c68eae8f2b5f5bdf5ebcc565252bc70f983548c2dfd5406f111a0"
			"a95b1bb9a639988c8d65da912d2c3ea2"
		}, {
			"c44a2c58c84c393a",
			"60ad40f964d0edcf19281e415f7389968275ff613199a069c916a0ff7ef65503"
			"b740683162a622b913d43a46559e913c"
		}, {
			"a36e5a59043b6333d7",
			"bd045661663436d07720ff3c8b6f922066dfe244456a56ca46dfb3f7e271116d"
			"932107c7b04cc7c60173e08d0c2e107c"
		}, {
			"c0920f2bd1e2d302259b",
			"3d1584220409f88d38409a29ecaebb490ef884b5acba2c7eaf23914bab7f5f0f"
			"c97ee1e6336f88dfd4d0a06e902ccd25"
		}, {
			"70ae731af5e0d92d264ec9",
			"563359fd93fe09f3fe49fcf5f17e7f92aab589cdec3e55e4c3715e7775814bbb"
			"fb8c4c732e28d3b6e6404860812dc6e9"
		}, {
			"69c74a9b0db538eeff64d93d",
			"88c66389ca2c320a39022aa441fa884fbc6ed2d3cc9ac475372d947d4960579a"
			"64e061a297d1831d3524f98d8094404b"
		}, {
			"a4a9327be21b9277e08c40abc7",
			"751f5da5ff9e2460c99348070d5068d8a3d7ffcec7fd0e6f68f6cd4a2ef4226d"
			"f8d9b4613c3b0d10a168eaf54eabe01a"
		}, {
			"cc4764d3e295097298f2af8882f6",
			"10f287f256643ad0dfb5955dd34587882e445cd5ae8da337e7c170fc0c1e48a0"
			"3fb7a54ec71335113dbdccccc944da41"
		}, {
			"5a23ad0ce89e0fb1df4a95bb2488f0",
			"23840671e7570a248cf3579c7c8810b5fcc35b975a3a43b506cc67faefa6dbe1"
			"c945abc09a903e199f759dcbc7f2c4d0"
		}, {
			"5fe35923b4e0af7dd24971812a58425519850a506dfa9b0d254795be785786c3"
			"19a2567cbaa5e35bcf8fe83d943e23fa5169b73adc1fcf8b607084b15e6a013d"
			"f147e46256e4e803ab75c110f77848136be7d806e8b2f868c16c3a90c1446340"
			"7038cb7d9285079ef162c6a45cedf9c9f066375c969b5fcbcda37f02aacff4f3"
			"1cded3767570885426bebd9eca877e44674e9ae2f0c24cdd0e7e1aaf1ff2fe7f"
			"80a1c4f5078eb34cd4f06fa94a2d1eab5806ca43fd0f06c60b63d5402b95c70c"
			"21ea65a151c5cfaf8262a46be3c722264b",
			"3054d249f916a6039b2a9c3ebec1418791a0608a170e6d36486035e5f92635ea"
			"ba98072a85373cb54e2ae3f982ce132b"
		}, {
			"035adcb639e5f28bb5c88658f45c1ce0be16e7dafe083b98d0ab45e8dcdbfa38"
			"e3234dfd973ba555b0cf8eea3c82ae1a3633fc565b7f2cc839876d3989f35731"
			"be371f60de140e3c916231ec780e5165bf5f25d3f67dc73a1c33655dfdf439df"
			"bf1cbba8b779158a810ad7244f06ec078120cd18760af436a238941ce1e68788"
			"0b5c879dc971a285a74ee85c6a746749a30159ee842e9b03f31d613dddd22975"
			"cd7fed06bd049d772cb6cc5a705faa734e87321dc8f2a4ea366a368a98bf06ee"
			"2b0b54ac3a3aeea637caebe70ad09ccda93cc06de95df73394a87ac9bbb5083a"
			"4d8a2458e91c7d5bf113aecae0ce279fdda76ba690787d26345e94c3edbc16a3"
			"5c83c4d071b132dd81187bcd9961323011509c8f644a1c0a3f14ee40d7dd186f"
			"807f9edc7c02f6761061bbb6dd91a6c96ec0b9f10edbbd29dc52",
			"02535d86cc7518484a2a238c921b739b1704a50370a2924abf39958c5976e658"
			"dc5e87440063112459bddb40308b1c70"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_384::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], in, in_sz);

		Crypto::SHA3_384 ctx;
		for ( std::size_t i = 0 ; i < in_sz ; ++i ) {
			ctx.update(&in[i], 1);
		}
		ctx.finish(out);

		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[1]);
	}
}

TEST(SHA3_384, reset_ctx)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
			"c3713831264adb47fb6bd1e058d5f004"
		}, {
			"80",
			"7541384852e10ff10d5fb6a7213a4a6c15ccc86d8bc1068ac04f69277142944f"
			"4ee50d91fdc56553db06b2f5039c8ab7"
		}, {
			"fb52",
			"d73a9d0e7f1802352ea54f3e062d3910577bf87edda48101de92a3de957e698b"
			"836085f5f10cab1de19fd0c906e48385"
		}, {
			"6ab7d6",
			"ea12d6d32d69ad2154a57e0e1be481a45add739ee7dd6e2a27e544b6c8b5ad12"
			"2654bbf95134d567987156295d5e57db"
		}, {
			"11587dcb",
			"cb6e6ce4a266d438ddd52867f2e183021be50223c7d57f8fdcaa18093a9d0126"
			"607df026c025bff40bc314af43fd8a08"
		}, {
			"4d7fc6cae6",
			"e570d463a010c71b78acd7f9790c78ce946e00cc54dae82bfc3833a10f0d8d35"
			"b03cbb4aa2f9ba4b27498807a397cd47"
		}, {
			"5a6659e9f0e7",
			"21b1f3f63b907f968821185a7fe30b16d47e1d6ee5b9c80be68947854de7a8ef"
			"4a03a6b2e4ec96abdd4fa29ab9796f28"
		}, {
			"17510eca2fe11b",
			"35fba6958b6c68eae8f2b5f5bdf5ebcc565252bc70f983548c2dfd5406f111a0"
			"a95b1bb9a639988c8d65da912d2c3ea2"
		}, {
			"c44a2c58c84c393a",
			"60ad40f964d0edcf19281e415f7389968275ff613199a069c916a0ff7ef65503"
			"b740683162a622b913d43a46559e913c"
		}, {
			"a36e5a59043b6333d7",
			"bd045661663436d07720ff3c8b6f922066dfe244456a56ca46dfb3f7e271116d"
			"932107c7b04cc7c60173e08d0c2e107c"
		}, {
			"c0920f2bd1e2d302259b",
			"3d1584220409f88d38409a29ecaebb490ef884b5acba2c7eaf23914bab7f5f0f"
			"c97ee1e6336f88dfd4d0a06e902ccd25"
		}, {
			"70ae731af5e0d92d264ec9",
			"563359fd93fe09f3fe49fcf5f17e7f92aab589cdec3e55e4c3715e7775814bbb"
			"fb8c4c732e28d3b6e6404860812dc6e9"
		}, {
			"69c74a9b0db538eeff64d93d",
			"88c66389ca2c320a39022aa441fa884fbc6ed2d3cc9ac475372d947d4960579a"
			"64e061a297d1831d3524f98d8094404b"
		}, {
			"a4a9327be21b9277e08c40abc7",
			"751f5da5ff9e2460c99348070d5068d8a3d7ffcec7fd0e6f68f6cd4a2ef4226d"
			"f8d9b4613c3b0d10a168eaf54eabe01a"
		}, {
			"cc4764d3e295097298f2af8882f6",
			"10f287f256643ad0dfb5955dd34587882e445cd5ae8da337e7c170fc0c1e48a0"
			"3fb7a54ec71335113dbdccccc944da41"
		}, {
			"5a23ad0ce89e0fb1df4a95bb2488f0",
			"23840671e7570a248cf3579c7c8810b5fcc35b975a3a43b506cc67faefa6dbe1"
			"c945abc09a903e199f759dcbc7f2c4d0"
		}, {
			"5fe35923b4e0af7dd24971812a58425519850a506dfa9b0d254795be785786c3"
			"19a2567cbaa5e35bcf8fe83d943e23fa5169b73adc1fcf8b607084b15e6a013d"
			"f147e46256e4e803ab75c110f77848136be7d806e8b2f868c16c3a90c1446340"
			"7038cb7d9285079ef162c6a45cedf9c9f066375c969b5fcbcda37f02aacff4f3"
			"1cded3767570885426bebd9eca877e44674e9ae2f0c24cdd0e7e1aaf1ff2fe7f"
			"80a1c4f5078eb34cd4f06fa94a2d1eab5806ca43fd0f06c60b63d5402b95c70c"
			"21ea65a151c5cfaf8262a46be3c722264b",
			"3054d249f916a6039b2a9c3ebec1418791a0608a170e6d36486035e5f92635ea"
			"ba98072a85373cb54e2ae3f982ce132b"
		}, {
			"035adcb639e5f28bb5c88658f45c1ce0be16e7dafe083b98d0ab45e8dcdbfa38"
			"e3234dfd973ba555b0cf8eea3c82ae1a3633fc565b7f2cc839876d3989f35731"
			"be371f60de140e3c916231ec780e5165bf5f25d3f67dc73a1c33655dfdf439df"
			"bf1cbba8b779158a810ad7244f06ec078120cd18760af436a238941ce1e68788"
			"0b5c879dc971a285a74ee85c6a746749a30159ee842e9b03f31d613dddd22975"
			"cd7fed06bd049d772cb6cc5a705faa734e87321dc8f2a4ea366a368a98bf06ee"
			"2b0b54ac3a3aeea637caebe70ad09ccda93cc06de95df73394a87ac9bbb5083a"
			"4d8a2458e91c7d5bf113aecae0ce279fdda76ba690787d26345e94c3edbc16a3"
			"5c83c4d071b132dd81187bcd9961323011509c8f644a1c0a3f14ee40d7dd186f"
			"807f9edc7c02f6761061bbb6dd91a6c96ec0b9f10edbbd29dc52",
			"02535d86cc7518484a2a238c921b739b1704a50370a2924abf39958c5976e658"
			"dc5e87440063112459bddb40308b1c70"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);

		uint8_t out_1[Crypto::SHA3_384::SIZE];
		uint8_t out_2[Crypto::SHA3_384::SIZE];
		std::string output_1, output_2;

		Crypto::Utils::from_hex(test[0], in, in_sz);

		Crypto::SHA3_384 ctx;
		ctx.update(in, in_sz);
		ctx.reset();
		ctx.update(in, in_sz);
		ctx.finish(out_1);
		Crypto::Utils::to_hex(out_1, sizeof(out_1), output_1, false);

		ctx.update(in, in_sz);
		ctx.finish(out_2);
		Crypto::Utils::to_hex(out_2, sizeof(out_2), output_2, false);

		EXPECT_THAT(output_1, test[1]);
		EXPECT_THAT(output_2, test[1]);
	}
}

TEST(SHA3_384, mac_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			"4869205468657265",
			"68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a"
			"20d370b47743130e26ac7e3d532886bd"
		}, {
			"4a656665",
			"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"f1101f8cbf9766fd6764d2ed61903f21ca9b18f57cf3e1a23ca13508a93243ce"
			"48c045dc007f26a21b3f5e0e9df4c20a"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			"dddddddddddddddddddddddddddddddddddd",
			"275cd0e661bb8b151c64d288f1f782fb91a8abd56858d72babb2d476f0458373"
			"b41b6ab5bf174bec422e53fc3135ac6e"
		}, {
			"0102030405060708090a0b0c0d0e0f10111213141516171819",
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
			"3a5d7a879702c086bc96d1dd8aa15d9c46446b95521311c606fdc4e308f4b984"
			"da2d0f9449b3ba8425ec7fb8c31bc136"
		}, {
			"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
			"546573742057697468205472756e636174696f6e",
			"47c51ace1ffacffd74947246826157838fe243be4734c51835e02aaebca45b27"
			"2fdb8395389a25831645baf174697e0c"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579204669727374",
			"0fc19513bf6bd878037016706a0e57bc528139836b9a42c3d419e498e0e1fb96"
			"16fd669138d33a1105e07c72b6953bcc"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579204669727374",
			"713dff0302c85086ec5ad0768dd65a13ddd79068d8d4c6212b712e4164944911"
			"1480230044185a99103ed82004ddbfcc"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa",
			"5468697320697320612074657374207573696e672061206c6172676572207468"
			"616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
			"647320746f20626520686173686564206265666f7265206265696e6720757365"
			"642062792074686520484d414320616c676f726974686d2e",
			"026fdf6b50741e373899c9f7d5406d4eb09fc6665636fc1a530029ddf5cf3ca5"
			"a900edce01f5f61e2f408cdf2fd3e7e8"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"5468697320697320612074657374207573696e672061206c6172676572207468"
			"616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
			"647320746f20626520686173686564206265666f7265206265696e6720757365"
			"642062792074686520484d414320616c676f726974686d2e",
			"cad18a8ff6c4cc3ad487b95f9769e9b61c062aefd6952569e6e6421897054cfc"
			"70b5fdc6605c18457112fc6aaad45585"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[2048];
		std::size_t key_sz = sizeof(key);
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_384::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], key, key_sz);
		Crypto::Utils::from_hex(test[1], in,  in_sz);

		Crypto::HMAC_get<Crypto::SHA3_384>(key, key_sz, in, in_sz, out);
		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[2]);
	}
}

TEST(SHA3_512, digest_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
			"15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
		}, {
			"e5",
			"150240baf95fb36f8ccb87a19a41767e7aed95125075a2b2dbba6e565e1ce857"
			"5f2b042b62e29a04e9440314a821c6224182964d8b557b16a492b3806f4c39c1"
		}, {
			"ef26",
			"809b4124d2b174731db14585c253194c8619a68294c8c48947879316fef249b1"
			"575da81ab72aad8fae08d24ece75ca1be46d0634143705d79d2f5177856a0437"
		}, {
			"37d518",
			"4aa96b1547e6402c0eee781acaa660797efe26ec00b4f2e0aec4a6d10688dd64"
			"cbd7f12b3b6c7f802e2096c041208b9289aec380d1a748fdfcd4128553d781e3"
		}, {
			"fc7b8cda",
			"58a5422d6b15eb1f223ebe4f4a5281bc6824d1599d979f4c6fe45695ca890142"
			"60b859a2d46ebf75f51ff204927932c79270dd7aef975657bb48fe09d8ea008e"
		}, {
			"4775c86b1c",
			"ce96da8bcd6bc9d81419f0dd3308e3ef541bc7b030eee1339cf8b3c4e8420cd3"
			"03180f8da77037c8c1ae375cab81ee475710923b9519adbddedb36db0c199f70"
		}, {
			"71a986d2f662",
			"def6aac2b08c98d56a0501a8cb93f5b47d6322daf99e03255457c303326395f7"
			"65576930f8571d89c01e727cc79c2d4497f85c45691b554e20da810c2bc865ef"
		}, {
			"ec83d707a1414a",
			"84fd3775bac5b87e550d03ec6fe4905cc60e851a4c33a61858d4e7d8a34d471f"
			"05008b9a1d63044445df5a9fce958cb012a6ac778ecf45104b0fcb979aa4692d"
		}, {
			"af53fa3ff8a3cfb2",
			"03c2ac02de1765497a0a6af466fb64758e3283ed83d02c0edb3904fd3cf29644"
			"2e790018d4bf4ce55bc869cebb4aa1a799afc9d987e776fef5dfe6628e24de97"
		}, {
			"3d6093966950abd846",
			"53e30da8b74ae76abf1f65761653ebfbe87882e9ea0ea564addd7cfd5a652457"
			"8ad6be014d7799799ef5e15c679582b791159add823b95c91e26de62dcb74cfa"
		}, {
			"1ca984dcc913344370cf",
			"6915ea0eeffb99b9b246a0e34daf3947852684c3d618260119a22835659e4f23"
			"d4eb66a15d0affb8e93771578f5e8f25b7a5f2a55f511fb8b96325ba2cd14816"
		}, {
			"fc7b8cdadebe48588f6851",
			"c8439bb1285120b3c43631a00a3b5ac0badb4113586a3dd4f7c66c5d81012f74"
			"12617b169fa6d70f8e0a19e5e258e99a0ed2dcfa774c864c62a010e9b90ca00d"
		}, {
			"ecb907adfb85f9154a3c23e8",
			"94ae34fed2ef51a383fb853296e4b797e48e00cad27f094d2f411c400c4960ca"
			"4c610bf3dc40e94ecfd0c7a18e418877e182ca3ae5ca5136e2856a5531710f48"
		}, {
			"d91a9c324ece84b072d0753618",
			"fb1f06c4d1c0d066bdd850ab1a78b83296eba0ca423bb174d74283f46628e609"
			"5539214adfd82b462e8e9204a397a83c6842b721a32e8bb030927a568f3c29e6"
		}, {
			"c61a9188812ae73994bc0d6d4021",
			"069e6ab1675fed8d44105f3b62bbf5b8ff7ae804098986879b11e0d7d9b1b4cb"
			"7bc47aeb74201f509ddc92e5633abd2cbe0ddca2480e9908afa632c8c8d5af2a"
		}, {
			"a6e7b218449840d134b566290dc896",
			"3605a21ce00b289022193b70b535e6626f324739542978f5b307194fcf0a5988"
			"f542c0838a0443bb9bb8ff922a6a177fdbd12cf805f3ed809c48e9769c8bbd91"
		}, {
			"664ef2e3a7059daf1c58caf52008c5227e85cdcb83b4c59457f02c508d4f4f69"
			"f826bd82c0cffc5cb6a97af6e561c6f96970005285e58f21ef6511d26e709889"
			"a7e513c434c90a3cf7448f0caeec7114c747b2a0758a3b4503a7cf0c69873ed3"
			"1d94dbef2b7b2f168830ef7da3322c3d3e10cafb7c2c33c83bbf4c46a31da90c"
			"ff3bfd4ccc6ed4b310758491eeba603a76",
			"e5825ff1a3c070d5a52fbbe711854a440554295ffb7a7969a17908d10163bfbe"
			"8f1d52a676e8a0137b56a11cdf0ffbb456bc899fc727d14bd8882232549d914e"
		}, {
			"991c4e7402c7da689dd5525af76fcc58fe9cc1451308c0c4600363586ccc83c9"
			"ec10a8c9ddaec3d7cfbd206484d09634b9780108440bf27a5fa4a428446b3214"
			"fa17084b6eb197c5c59a4e8df1cfc521826c3b1cbf6f4212f6bfb9bc106dfb55"
			"68395643de58bffa2774c31e67f5c1e7017f57caadbb1a56cc5b8a5cf9584552"
			"e17e7af9542ba13e9c54695e0dc8f24eddb93d5a3678e10c8a80ff4f27b677d4"
			"0bef5cb5f9b3a659cc4127970cd2c11ebf22d514812dfefdd73600dfc10efba3"
			"8e93e5bff47736126043e50f8b9b941e4ec3083fb762dbf15c86",
			"cd0f2a48e9aa8cc700d3f64efb013f3600ebdbb524930c682d21025eab990eb6"
			"d7c52e611f884031fafd9360e5225ab7e4ec24cbe97f3af6dbe4a86a4f068ba7"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_512::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], in, in_sz);
		Crypto::MessageDigest_get<Crypto::SHA3_512>(in, in_sz, out);
		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[1]);
	}
}

TEST(SHA3_512, test_update)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
			"15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
		}, {
			"e5",
			"150240baf95fb36f8ccb87a19a41767e7aed95125075a2b2dbba6e565e1ce857"
			"5f2b042b62e29a04e9440314a821c6224182964d8b557b16a492b3806f4c39c1"
		}, {
			"ef26",
			"809b4124d2b174731db14585c253194c8619a68294c8c48947879316fef249b1"
			"575da81ab72aad8fae08d24ece75ca1be46d0634143705d79d2f5177856a0437"
		}, {
			"37d518",
			"4aa96b1547e6402c0eee781acaa660797efe26ec00b4f2e0aec4a6d10688dd64"
			"cbd7f12b3b6c7f802e2096c041208b9289aec380d1a748fdfcd4128553d781e3"
		}, {
			"fc7b8cda",
			"58a5422d6b15eb1f223ebe4f4a5281bc6824d1599d979f4c6fe45695ca890142"
			"60b859a2d46ebf75f51ff204927932c79270dd7aef975657bb48fe09d8ea008e"
		}, {
			"4775c86b1c",
			"ce96da8bcd6bc9d81419f0dd3308e3ef541bc7b030eee1339cf8b3c4e8420cd3"
			"03180f8da77037c8c1ae375cab81ee475710923b9519adbddedb36db0c199f70"
		}, {
			"71a986d2f662",
			"def6aac2b08c98d56a0501a8cb93f5b47d6322daf99e03255457c303326395f7"
			"65576930f8571d89c01e727cc79c2d4497f85c45691b554e20da810c2bc865ef"
		}, {
			"ec83d707a1414a",
			"84fd3775bac5b87e550d03ec6fe4905cc60e851a4c33a61858d4e7d8a34d471f"
			"05008b9a1d63044445df5a9fce958cb012a6ac778ecf45104b0fcb979aa4692d"
		}, {
			"af53fa3ff8a3cfb2",
			"03c2ac02de1765497a0a6af466fb64758e3283ed83d02c0edb3904fd3cf29644"
			"2e790018d4bf4ce55bc869cebb4aa1a799afc9d987e776fef5dfe6628e24de97"
		}, {
			"3d6093966950abd846",
			"53e30da8b74ae76abf1f65761653ebfbe87882e9ea0ea564addd7cfd5a652457"
			"8ad6be014d7799799ef5e15c679582b791159add823b95c91e26de62dcb74cfa"
		}, {
			"1ca984dcc913344370cf",
			"6915ea0eeffb99b9b246a0e34daf3947852684c3d618260119a22835659e4f23"
			"d4eb66a15d0affb8e93771578f5e8f25b7a5f2a55f511fb8b96325ba2cd14816"
		}, {
			"fc7b8cdadebe48588f6851",
			"c8439bb1285120b3c43631a00a3b5ac0badb4113586a3dd4f7c66c5d81012f74"
			"12617b169fa6d70f8e0a19e5e258e99a0ed2dcfa774c864c62a010e9b90ca00d"
		}, {
			"ecb907adfb85f9154a3c23e8",
			"94ae34fed2ef51a383fb853296e4b797e48e00cad27f094d2f411c400c4960ca"
			"4c610bf3dc40e94ecfd0c7a18e418877e182ca3ae5ca5136e2856a5531710f48"
		}, {
			"d91a9c324ece84b072d0753618",
			"fb1f06c4d1c0d066bdd850ab1a78b83296eba0ca423bb174d74283f46628e609"
			"5539214adfd82b462e8e9204a397a83c6842b721a32e8bb030927a568f3c29e6"
		}, {
			"c61a9188812ae73994bc0d6d4021",
			"069e6ab1675fed8d44105f3b62bbf5b8ff7ae804098986879b11e0d7d9b1b4cb"
			"7bc47aeb74201f509ddc92e5633abd2cbe0ddca2480e9908afa632c8c8d5af2a"
		}, {
			"a6e7b218449840d134b566290dc896",
			"3605a21ce00b289022193b70b535e6626f324739542978f5b307194fcf0a5988"
			"f542c0838a0443bb9bb8ff922a6a177fdbd12cf805f3ed809c48e9769c8bbd91"
		}, {
			"664ef2e3a7059daf1c58caf52008c5227e85cdcb83b4c59457f02c508d4f4f69"
			"f826bd82c0cffc5cb6a97af6e561c6f96970005285e58f21ef6511d26e709889"
			"a7e513c434c90a3cf7448f0caeec7114c747b2a0758a3b4503a7cf0c69873ed3"
			"1d94dbef2b7b2f168830ef7da3322c3d3e10cafb7c2c33c83bbf4c46a31da90c"
			"ff3bfd4ccc6ed4b310758491eeba603a76",
			"e5825ff1a3c070d5a52fbbe711854a440554295ffb7a7969a17908d10163bfbe"
			"8f1d52a676e8a0137b56a11cdf0ffbb456bc899fc727d14bd8882232549d914e"
		}, {
			"991c4e7402c7da689dd5525af76fcc58fe9cc1451308c0c4600363586ccc83c9"
			"ec10a8c9ddaec3d7cfbd206484d09634b9780108440bf27a5fa4a428446b3214"
			"fa17084b6eb197c5c59a4e8df1cfc521826c3b1cbf6f4212f6bfb9bc106dfb55"
			"68395643de58bffa2774c31e67f5c1e7017f57caadbb1a56cc5b8a5cf9584552"
			"e17e7af9542ba13e9c54695e0dc8f24eddb93d5a3678e10c8a80ff4f27b677d4"
			"0bef5cb5f9b3a659cc4127970cd2c11ebf22d514812dfefdd73600dfc10efba3"
			"8e93e5bff47736126043e50f8b9b941e4ec3083fb762dbf15c86",
			"cd0f2a48e9aa8cc700d3f64efb013f3600ebdbb524930c682d21025eab990eb6"
			"d7c52e611f884031fafd9360e5225ab7e4ec24cbe97f3af6dbe4a86a4f068ba7"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_512::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], in, in_sz);

		Crypto::SHA3_512 ctx;
		for ( std::size_t i = 0 ; i < in_sz ; ++i ) {
			ctx.update(&in[i], 1);
		}
		ctx.finish(out);

		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[1]);
	}
}

TEST(SHA3_512, reset_ctx)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"",
			"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
			"15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
		}, {
			"e5",
			"150240baf95fb36f8ccb87a19a41767e7aed95125075a2b2dbba6e565e1ce857"
			"5f2b042b62e29a04e9440314a821c6224182964d8b557b16a492b3806f4c39c1"
		}, {
			"ef26",
			"809b4124d2b174731db14585c253194c8619a68294c8c48947879316fef249b1"
			"575da81ab72aad8fae08d24ece75ca1be46d0634143705d79d2f5177856a0437"
		}, {
			"37d518",
			"4aa96b1547e6402c0eee781acaa660797efe26ec00b4f2e0aec4a6d10688dd64"
			"cbd7f12b3b6c7f802e2096c041208b9289aec380d1a748fdfcd4128553d781e3"
		}, {
			"fc7b8cda",
			"58a5422d6b15eb1f223ebe4f4a5281bc6824d1599d979f4c6fe45695ca890142"
			"60b859a2d46ebf75f51ff204927932c79270dd7aef975657bb48fe09d8ea008e"
		}, {
			"4775c86b1c",
			"ce96da8bcd6bc9d81419f0dd3308e3ef541bc7b030eee1339cf8b3c4e8420cd3"
			"03180f8da77037c8c1ae375cab81ee475710923b9519adbddedb36db0c199f70"
		}, {
			"71a986d2f662",
			"def6aac2b08c98d56a0501a8cb93f5b47d6322daf99e03255457c303326395f7"
			"65576930f8571d89c01e727cc79c2d4497f85c45691b554e20da810c2bc865ef"
		}, {
			"ec83d707a1414a",
			"84fd3775bac5b87e550d03ec6fe4905cc60e851a4c33a61858d4e7d8a34d471f"
			"05008b9a1d63044445df5a9fce958cb012a6ac778ecf45104b0fcb979aa4692d"
		}, {
			"af53fa3ff8a3cfb2",
			"03c2ac02de1765497a0a6af466fb64758e3283ed83d02c0edb3904fd3cf29644"
			"2e790018d4bf4ce55bc869cebb4aa1a799afc9d987e776fef5dfe6628e24de97"
		}, {
			"3d6093966950abd846",
			"53e30da8b74ae76abf1f65761653ebfbe87882e9ea0ea564addd7cfd5a652457"
			"8ad6be014d7799799ef5e15c679582b791159add823b95c91e26de62dcb74cfa"
		}, {
			"1ca984dcc913344370cf",
			"6915ea0eeffb99b9b246a0e34daf3947852684c3d618260119a22835659e4f23"
			"d4eb66a15d0affb8e93771578f5e8f25b7a5f2a55f511fb8b96325ba2cd14816"
		}, {
			"fc7b8cdadebe48588f6851",
			"c8439bb1285120b3c43631a00a3b5ac0badb4113586a3dd4f7c66c5d81012f74"
			"12617b169fa6d70f8e0a19e5e258e99a0ed2dcfa774c864c62a010e9b90ca00d"
		}, {
			"ecb907adfb85f9154a3c23e8",
			"94ae34fed2ef51a383fb853296e4b797e48e00cad27f094d2f411c400c4960ca"
			"4c610bf3dc40e94ecfd0c7a18e418877e182ca3ae5ca5136e2856a5531710f48"
		}, {
			"d91a9c324ece84b072d0753618",
			"fb1f06c4d1c0d066bdd850ab1a78b83296eba0ca423bb174d74283f46628e609"
			"5539214adfd82b462e8e9204a397a83c6842b721a32e8bb030927a568f3c29e6"
		}, {
			"c61a9188812ae73994bc0d6d4021",
			"069e6ab1675fed8d44105f3b62bbf5b8ff7ae804098986879b11e0d7d9b1b4cb"
			"7bc47aeb74201f509ddc92e5633abd2cbe0ddca2480e9908afa632c8c8d5af2a"
		}, {
			"a6e7b218449840d134b566290dc896",
			"3605a21ce00b289022193b70b535e6626f324739542978f5b307194fcf0a5988"
			"f542c0838a0443bb9bb8ff922a6a177fdbd12cf805f3ed809c48e9769c8bbd91"
		}, {
			"664ef2e3a7059daf1c58caf52008c5227e85cdcb83b4c59457f02c508d4f4f69"
			"f826bd82c0cffc5cb6a97af6e561c6f96970005285e58f21ef6511d26e709889"
			"a7e513c434c90a3cf7448f0caeec7114c747b2a0758a3b4503a7cf0c69873ed3"
			"1d94dbef2b7b2f168830ef7da3322c3d3e10cafb7c2c33c83bbf4c46a31da90c"
			"ff3bfd4ccc6ed4b310758491eeba603a76",
			"e5825ff1a3c070d5a52fbbe711854a440554295ffb7a7969a17908d10163bfbe"
			"8f1d52a676e8a0137b56a11cdf0ffbb456bc899fc727d14bd8882232549d914e"
		}, {
			"991c4e7402c7da689dd5525af76fcc58fe9cc1451308c0c4600363586ccc83c9"
			"ec10a8c9ddaec3d7cfbd206484d09634b9780108440bf27a5fa4a428446b3214"
			"fa17084b6eb197c5c59a4e8df1cfc521826c3b1cbf6f4212f6bfb9bc106dfb55"
			"68395643de58bffa2774c31e67f5c1e7017f57caadbb1a56cc5b8a5cf9584552"
			"e17e7af9542ba13e9c54695e0dc8f24eddb93d5a3678e10c8a80ff4f27b677d4"
			"0bef5cb5f9b3a659cc4127970cd2c11ebf22d514812dfefdd73600dfc10efba3"
			"8e93e5bff47736126043e50f8b9b941e4ec3083fb762dbf15c86",
			"cd0f2a48e9aa8cc700d3f64efb013f3600ebdbb524930c682d21025eab990eb6"
			"d7c52e611f884031fafd9360e5225ab7e4ec24cbe97f3af6dbe4a86a4f068ba7"
		}
	};

	for ( auto test : tests ) {
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);

		uint8_t out_1[Crypto::SHA3_512::SIZE];
		uint8_t out_2[Crypto::SHA3_512::SIZE];
		std::string output_1, output_2;

		Crypto::Utils::from_hex(test[0], in, in_sz);

		Crypto::SHA3_512 ctx;
		ctx.update(in, in_sz);
		ctx.reset();
		ctx.update(in, in_sz);
		ctx.finish(out_1);
		Crypto::Utils::to_hex(out_1, sizeof(out_1), output_1, false);

		ctx.update(in, in_sz);
		ctx.finish(out_2);
		Crypto::Utils::to_hex(out_2, sizeof(out_2), output_2, false);

		EXPECT_THAT(output_1, test[1]);
		EXPECT_THAT(output_2, test[1]);
	}
}

TEST(SHA3_512, mac_test_vector)
{
	const std::vector<std::vector<std::string>> tests = {
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			"4869205468657265",
			"eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba"
			"47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e"
		}, {
			"4a656665",
			"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b"
			"287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			"dddddddddddddddddddddddddddddddddddd",
			"309e99f9ec075ec6c6d475eda1180687fcf1531195802a99b5677449a8625182"
			"851cb332afb6a89c411325fbcbcd42afcb7b6e5aab7ea42c660f97fd8584bf03"
		}, {
			"0102030405060708090a0b0c0d0e0f10111213141516171819",
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
			"b27eab1d6e8d87461c29f7f5739dd58e98aa35f8e823ad38c5492a2088fa0281"
			"993bbfff9a0e9c6bf121ae9ec9bb09d84a5ebac817182ea974673fb133ca0d1d"
		}, {
			"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
			"546573742057697468205472756e636174696f6e",
			"0fa7475948f43f48ca0516671e18978c6e21415f4e7d4e47ab7659e73acffa9f"
				"0665eb712bfe8369ed2d3d0bda0a6d5dff68918662d639abfd1725187d85a665"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579204669727374",
			"00f751a9e50695b090ed6911a4b65524951cdc15a73a5d58bb55215ea2cd839a"
				"c79d2b44a39bafab27e83fde9e11f6340b11d991b1b91bf2eee7fc872426c3a4"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
			"65204b6579202d2048617368204b6579204669727374",
			"b14835c819a290efb010ace6d8568dc6b84de60bc49b004c3b13eda763589451"
			"e5dd74292884d1bdce64e6b919dd61dc9c56a282a81c0bd14f1f365b49b83a5b"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaa",
			"5468697320697320612074657374207573696e672061206c6172676572207468"
			"616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
			"647320746f20626520686173686564206265666f7265206265696e6720757365"
			"642062792074686520484d414320616c676f726974686d2e",
			"38a456a004bd10d32c9ab8336684112862c3db61adcca31829355eaf46fd5c73"
			"d06a1f0d13fec9a652fb3811b577b1b1d1b9789f97ae5b83c6f44dfcf1d67eba"
		}, {
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"5468697320697320612074657374207573696e672061206c6172676572207468"
			"616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
			"647320746f20626520686173686564206265666f7265206265696e6720757365"
			"642062792074686520484d414320616c676f726974686d2e",
			"dc030ee7887034f32cf402df34622f311f3e6cf04860c6bbd7fa488674782b46"
			"59fdbdf3fd877852885cfe6e22185fe7b2ee952043629bc9d5f3298a41d02c66"
		}
	};

	for ( auto test : tests ) {
		uint8_t key[2048];
		std::size_t key_sz = sizeof(key);
		uint8_t in[2048];
		std::size_t in_sz = sizeof(in);
		uint8_t out[Crypto::SHA3_512::SIZE];
		std::string output;

		Crypto::Utils::from_hex(test[0], key, key_sz);
		Crypto::Utils::from_hex(test[1], in,  in_sz);

		Crypto::HMAC_get<Crypto::SHA3_512>(key, key_sz, in, in_sz, out);
		Crypto::Utils::to_hex(out, sizeof(out), output, false);

		EXPECT_THAT(output, test[2]);
	}
}
