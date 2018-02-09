#ifndef CRYPTO_TWOFISH_H
#define CRYPTO_TWOFISH_H

#include "crypto/SymmetricCipher.hpp"

namespace Crypto
{

class Twofish : public SymmetricCipher
{
	public:
		Twofish(const uint8_t*, std::size_t);
		~Twofish(void);

		virtual void encrypt(const uint8_t*, uint8_t*) const;
		virtual void decrypt(const uint8_t*, uint8_t*) const;

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const std::size_t BLOCK_SIZE = 16;
	protected:
		uint32_t K[40];
		uint8_t s[4][256];

		static const uint8_t  q[2][256];
		static const uint32_t mds[4][256];

		uint32_t g(uint32_t) const;
		uint32_t h(uint8_t, const uint32_t*, std::size_t) const;
		void h0(uint8_t, const uint32_t*, std::size_t, uint8_t[4]) const;

		static inline uint32_t ROL(uint32_t, std::size_t);
		static inline uint32_t ROR(uint32_t, std::size_t);
		static inline uint32_t RS_Mod(uint32_t);
		static inline uint32_t RS(uint32_t, uint32_t);
};

}

#endif
