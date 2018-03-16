#ifndef CRYPTO_SHA224_H
#define CRYPTO_SHA224_H

#include "crypto/SHA256.hpp"

namespace Crypto
{

class SHA224 : public SHA256
{
	public:
		SHA224(void);
		virtual void finish(uint8_t*);
		virtual void reset(void);

		static const std::size_t SIZE       = 28;
		static const std::size_t BLOCK_SIZE = 64;
};

}

#endif
