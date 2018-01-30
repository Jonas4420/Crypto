#ifndef CRYPTO_DES_H
#define CRYPTO_DES_H

#include "crypto/SymmetricCipher.hpp"

namespace Crypto
{

class DES : public SymmetricCipher
{
	public:
		DES(const uint8_t*, std::size_t);
		~DES(void);

		virtual void encrypt(const uint8_t*, uint8_t*) const;
		virtual void decrypt(const uint8_t*, uint8_t*) const;

		static void set_parity_key(uint8_t*, std::size_t);
		static bool check_parity_key(const uint8_t*, std::size_t);
		static bool is_weak_key(const uint8_t*, std::size_t);

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const std::size_t BLOCK_SIZE = 8;
		friend class TripleDES;
	protected:
		uint32_t sk_enc[32];
		uint32_t sk_dec[32];

		static void set_key(uint32_t[32], const uint8_t[8]);
		void process(const uint32_t*, const uint8_t*, uint8_t*) const;

		static const uint8_t  odd_parity_table[128];
		static const uint32_t LHs[16];
		static const uint32_t RHs[16];
		static const uint32_t SB[8][64];
};

class TripleDES : public SymmetricCipher
{
	public:
		TripleDES(const uint8_t*, std::size_t);
		~TripleDES(void);

		virtual void encrypt(const uint8_t*, uint8_t*) const;
		virtual void decrypt(const uint8_t*, uint8_t*) const;

		static void set_parity_key(uint8_t*, std::size_t);
		static bool check_parity_key(const uint8_t*, std::size_t);
		static bool is_weak_key(const uint8_t*, std::size_t);

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const std::size_t BLOCK_SIZE = 8;
	protected:
		uint32_t sk_enc[96];
		uint32_t sk_dec[96];

		static void set_2key(uint32_t[96], uint32_t[96], const uint8_t[16]);
		static void set_3key(uint32_t[96], uint32_t[96], const uint8_t[24]);
		void process(const uint32_t*, const uint8_t*, uint8_t*) const;
};

}

#endif
