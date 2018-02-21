#include "gtest/gtest.h"

bool isFast;

int
main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);

	isFast = false;

	if ( argc > 1 ) {
		if ( std::string(argv[1]) == "-fast" ) {
			isFast = true;
		}
	}

	return RUN_ALL_TESTS();
}
