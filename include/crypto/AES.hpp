#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include "crypto/SymmetricCipher.hpp"

namespace Crypto
{

class AES : public SymmetricCipher
{
	public:
		AES(const uint8_t*, std::size_t);
		~AES(void);

		virtual void encrypt(const uint8_t*, uint8_t*);
		virtual void decrypt(const uint8_t*, uint8_t*);

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const std::size_t BLOCK_SIZE = 16;
	protected:
		std::size_t nr;

		uint32_t *rk_enc;
		uint32_t buf_enc[68];

		uint32_t *rk_dec;
		uint32_t buf_dec[68];

		void set_keyenc(void);
		void set_keydec(void);

		static const uint8_t  FSb[256];
		static const uint32_t FT0[256], FT1[256], FT2[256], FT3[256];
		static const uint8_t  RSb[256];
		static const uint32_t RT0[256], RT1[256], RT2[256], RT3[256];

		static const uint32_t RCON[10];
};

}

#endif
