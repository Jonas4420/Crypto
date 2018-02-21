#include <cstdlib>

#include "gtest/gtest.h"

bool isFast = false;

int
main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);

	isFast = false;

	if ( const char* env_fast = std::getenv("CRYPTO_TEST_IS_FAST") ) {
		isFast = (1 == atoi(env_fast));
	}

	return RUN_ALL_TESTS();
}
