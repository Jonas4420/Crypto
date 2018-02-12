#ifndef CRYPTO_SERPENT_H
#define CRYPTO_SERPENT_H

#include "crypto/SymmetricCipher.hpp"

namespace Crypto
{

class Serpent : public SymmetricCipher
{
	public:
		Serpent(const uint8_t*, std::size_t);
		~Serpent(void);

		virtual void encrypt(const uint8_t*, uint8_t*) const;
		virtual void decrypt(const uint8_t*, uint8_t*) const;

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const std::size_t BLOCK_SIZE = 16;
	protected:
		uint32_t K[132];

		static inline uint32_t ROL(uint32_t, std::size_t);
		static inline uint32_t ROR(uint32_t, std::size_t);
};

}

#endif
