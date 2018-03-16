#include "crypto/SHA224.hpp"

#include <cstring>

namespace Crypto
{

const OID SHA224::oid_alg = OID::id_sha224();

SHA224::SHA224(void)
{
	reset();
}

void
SHA224::finish(uint8_t *output)
{
	uint8_t tmp[32];

	SHA256::finish(tmp);
	memcpy(output, tmp, 28);

	reset();
}

void
SHA224::reset(void)
{
	zeroize(total, sizeof(total));

	state[0] = 0xC1059ED8;
	state[1] = 0x367CD507;
	state[2] = 0x3070DD17;
	state[3] = 0xF70E5939;
	state[4] = 0xFFC00B31;
	state[5] = 0x68581511;
	state[6] = 0x64F98FA7;
	state[7] = 0xBEFA4FA4;

	zeroize(buffer, sizeof(buffer));
}

}
