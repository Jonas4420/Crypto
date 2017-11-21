#ifndef CRYPTO_SYMMETRICCIPHER_H
#define CRYPTO_SYMMETRICCIPHER_H

#include <cstddef>
#include <cstdint>

#include "crypto/Utils.hpp"
#include "crypto/Padding.hpp"

namespace Crypto
{

class SymmetricCipher
{
	public:
		SymmetricCipher(const uint8_t*, std::size_t) {};
		virtual void encrypt(const uint8_t*, uint8_t*) = 0;
		virtual void decrypt(const uint8_t*, uint8_t*) = 0;

		static const uint8_t CRYPTO_SYMMETRIC_CIPHER_SUCCESS        = 0x00;
		static const uint8_t CRYPTO_SYMMETRIC_CIPHER_INVALID_LENGTH = 0x01;
};

template <class SC, class P = PKCS7Padding>
int
encrypt_ecb(const uint8_t     *key,    std::size_t key_sz,
		const uint8_t *plain,  std::size_t plain_sz,
		uint8_t       *cipher, std::size_t &cipher_sz)
{
	std::size_t pad_sz = SC::BLOCK_SIZE - (plain_sz % SC::BLOCK_SIZE);

	if ( cipher_sz < plain_sz + pad_sz ) {
		cipher_sz = plain_sz + pad_sz;
		return SC::CRYPTO_SYMMETRIC_CIPHER_INVALID_LENGTH;
	}

	SC sc(key, key_sz);

	std::size_t num_block = (plain_sz + pad_sz) / SC::BLOCK_SIZE;
	for ( std::size_t i = 0 ; i < num_block - 1 ; ++i ) {
		sc.encrypt(plain, cipher);

		plain  += SC::BLOCK_SIZE;
		cipher += SC::BLOCK_SIZE;
	}

	uint8_t tmp[SC::BLOCK_SIZE];
	memcpy(tmp, plain, SC::BLOCK_SIZE - pad_sz);
	P::pad(tmp, SC::BLOCK_SIZE - pad_sz, SC::BLOCK_SIZE);

	sc.encrypt(tmp, cipher);

	Utils::zeroize(tmp, SC::BLOCK_SIZE);

	return SC::CRYPTO_SYMMETRIC_CIPHER_SUCCESS;
}

}

#endif
