#include "crypto/SHA384.hpp"

#include <cstring>

#if defined(_MSC_VER) || defined(__WATCOMC__)
	#define UL64(x) x##ui64
#else
	#define UL64(x) x##ULL
#endif

namespace Crypto
{

SHA384::SHA384(void)
{
	reset();
}

void 
SHA384::finish(uint8_t *output)
{
	uint8_t tmp[64];

	SHA512::finish(tmp);
	memcpy(output, tmp, 48);
}

void
SHA384::reset(void)
{
	total[0] = 0;
	total[1] = 0;

	state[0] = UL64(0xCBBB9D5DC1059ED8);
	state[1] = UL64(0x629A292A367CD507);
	state[2] = UL64(0x9159015A3070DD17);
	state[3] = UL64(0x152FECD8F70E5939);
	state[4] = UL64(0x67332667FFC00B31);
	state[5] = UL64(0x8EB44A8768581511);
	state[6] = UL64(0xDB0C2E0D64F98FA7);
	state[7] = UL64(0x47B5481DBEFA4FA4);

	zeroize(buffer, sizeof(buffer));
}

}
