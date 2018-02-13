#ifndef CRYPTO_SHA3_H
#define CRYPTO_SHA3_H

#include "crypto/MessageDigest.hpp"

#include <stdexcept>

namespace Crypto
{

class SHA3 : public MessageDigest
{
	public:
		SHA3(std::size_t);
		virtual ~SHA3(void);

		virtual void update(const uint8_t*, std::size_t);
		virtual void finish(uint8_t*);
		virtual void reset(void);

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};
	protected:
		uint64_t    state[25];
		std::size_t digest_sz;
		std::size_t buffer_sz;
		const std::size_t r;

		static void keccakf(uint64_t[25]);
		static void absorb(uint8_t*, std::size_t, const uint8_t*, std::size_t);

		static inline uint64_t ROL(uint64_t, std::size_t);

		static const uint64_t RC[24];
};

template<std::size_t DS>
class SHA3_Final : public SHA3
{
	public:
		SHA3_Final(void) : SHA3(DS) {}
		static const std::size_t SIZE       = DS;
		static const std::size_t BLOCK_SIZE = 200 - 2 * DS;
};

typedef SHA3_Final<28> SHA3_224;
typedef SHA3_Final<32> SHA3_256;
typedef SHA3_Final<48> SHA3_384;
typedef SHA3_Final<64> SHA3_512;

}

#endif
