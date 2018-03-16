#ifndef CRYPTO_MD5_H
#define CRYPTO_MD5_H

#include "crypto/MessageDigest.hpp"

namespace Crypto
{

class MD5 : public MessageDigest
{
	public:
		MD5(void);
		~MD5(void);

		virtual void update(const uint8_t*, std::size_t);
		virtual void finish(uint8_t*);
		virtual void reset(void);

		static const OID oid_alg;
		static const std::size_t SIZE       = 16;
		static const std::size_t BLOCK_SIZE = 64;
	protected:
		uint32_t total[2];
		uint32_t state[4];
		uint8_t  buffer[64];

		void process(const uint8_t[64]);

		static const uint8_t padding[64];
};

}

#endif
