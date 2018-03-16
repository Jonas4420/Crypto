#ifndef CRYPTO_SHA384_H
#define CRYPTO_SHA384_H

#include "crypto/SHA512.hpp"

namespace Crypto
{

class SHA384 : public SHA512
{
	public:
		SHA384(void);
		virtual void finish(uint8_t*);
		virtual void reset(void);

		static const OID oid_alg;
		static const std::size_t SIZE       = 48;
		static const std::size_t BLOCK_SIZE = 128;
};

}

#endif
