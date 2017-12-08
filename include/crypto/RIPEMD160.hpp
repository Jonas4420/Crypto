#ifndef CRYPTO_RIPEMD160_H
#define CRYPTO_RIPEMD160_H

#include "crypto/MessageDigest.hpp"

namespace Crypto
{

class RIPEMD160 : public MessageDigest
{
	public:
		RIPEMD160(void);
		~RIPEMD160(void);

		void update(const uint8_t*, std::size_t);
		void finish(uint8_t*);

		static const std::size_t SIZE =  20;
		static const std::size_t BLOCK_SIZE = 64;
	private:
		uint32_t total[2];
		uint32_t state[5];
		uint8_t  buffer[64];

		void process(const uint8_t[64]);

		static const uint8_t  padding[64];
};

}

#endif
