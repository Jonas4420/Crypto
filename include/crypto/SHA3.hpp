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

		virtual void absorb(const uint8_t*, std::size_t);

		static void keccakf(uint64_t[25]);
		static inline uint64_t ROL(uint64_t, std::size_t);

		static const uint64_t RC[24];
};

class SHA3_224 : public SHA3
{
	public:
		SHA3_224(void) : SHA3(SIZE) {}
		static const OID oid_alg;
		static const std::size_t SIZE       = 28;
		static const std::size_t BLOCK_SIZE = 144;
};

class SHA3_256 : public SHA3
{
	public:
		SHA3_256(void) : SHA3(SIZE) {}
		static const OID oid_alg;
		static const std::size_t SIZE       = 32;
		static const std::size_t BLOCK_SIZE = 136;
};

class SHA3_384 : public SHA3
{
	public:
		SHA3_384(void) : SHA3(SIZE) {}
		static const OID oid_alg;
		static const std::size_t SIZE       = 48;
		static const std::size_t BLOCK_SIZE = 104;
};

class SHA3_512 : public SHA3
{
	public:
		SHA3_512(void) : SHA3(SIZE) {}
		static const OID oid_alg;
		static const std::size_t SIZE       = 64;
		static const std::size_t BLOCK_SIZE = 72;
};

}

#endif
