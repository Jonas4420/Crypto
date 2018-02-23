#include <cstdlib>

#include "gtest/gtest.h"

bool isFast = false;

int
main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);

	const char* env_fast = std::getenv("CRYPTO_TEST_IS_FAST");
	isFast = env_fast ? (1 == atoi(env_fast)) : false;

	return RUN_ALL_TESTS();
}
