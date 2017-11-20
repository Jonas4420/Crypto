#ifndef CRYPTO_SHA1_H
#define CRYPTO_SHA1_H

#include "crypto/MessageDigest.hpp"

namespace Crypto
{

class SHA1 : public MessageDigest
{
	public:
		SHA1(void);
		~SHA1(void);

		virtual void update(const uint8_t*, std::size_t);
		virtual void finish(uint8_t*);

		static const std::size_t SIZE       = 20;
		static const std::size_t BLOCK_SIZE = 64;
	protected:
		std::size_t size;
		uint32_t    total[2];
		uint32_t    state[5];
		uint8_t     buffer[64];

		virtual void process(const uint8_t[64]);

		static const uint8_t padding[64];
};

}

#endif
