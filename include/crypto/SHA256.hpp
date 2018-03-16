#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H

#include "crypto/MessageDigest.hpp"

namespace Crypto
{

class SHA256 : public MessageDigest
{
	public:
		SHA256(void);
		virtual ~SHA256(void);

		virtual void update(const uint8_t*, std::size_t);
		virtual void finish(uint8_t*);
		virtual void reset(void);

		static const OID oid_alg;
		static const std::size_t SIZE       = 32;
		static const std::size_t BLOCK_SIZE = 64;
	protected:
		uint32_t total[2];
		uint32_t state[8];
		uint8_t  buffer[64];

		virtual void process(const uint8_t[64]);

		static const uint8_t  padding[64];
		static const uint32_t K[64];
};

}

#endif
