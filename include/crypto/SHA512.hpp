#ifndef CRYPTO_SHA512_H
#define CRYPTO_SHA512_H

#include "crypto/MessageDigest.hpp"

namespace Crypto
{

class SHA512 : public MessageDigest
{
	public:
		SHA512(void);
		virtual ~SHA512(void);

		virtual void update(const uint8_t*, std::size_t);
		virtual void finish(uint8_t*);
		virtual void reset(void);

		static const OID oid_alg;
		static const std::size_t SIZE       = 64;
		static const std::size_t BLOCK_SIZE = 128;
	protected:
		uint64_t total[2];
		uint64_t state[8];
		uint8_t  buffer[128];

		virtual void process(const uint8_t[128]);

		static const uint8_t  padding[128];
		static const uint64_t K[80];
};

}

#endif
