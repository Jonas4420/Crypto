#ifndef CRYPTO_OFB_H
#define CRYPTO_OFB_H

#include "crypto/CipherMode.hpp"
#include "crypto/SymmetricCipher.hpp"

#include <type_traits>

#include <cstring>

namespace Crypto
{

template <class SC>
class OFB : public CipherMode
{
	static_assert(std::is_base_of<SymmetricCipher, SC>::value,
			"Template argument should be a SymmetricCipher");

	public:
		OFB(const uint8_t *key, std::size_t key_sz, const uint8_t iv[SC::BLOCK_SIZE])
			: sc_ctx(key, key_sz), iv_offset(0)
		{
			sc_ctx.encrypt(iv, this->iv);
		}

		~OFB(void)
		{
			zeroize(iv,         sizeof(iv));
			zeroize(&iv_offset, sizeof(iv_offset));
		}

		int update(const uint8_t *input, std::size_t input_sz, uint8_t *output, std::size_t &output_sz)
		{
			// Check that output is large enough
			if ( output_sz < input_sz ) {
				output_sz = input_sz;
				return CRYPTO_CIPHER_MODE_INVALID_LENGTH;
			}

			// Process input
			for ( std::size_t i = 0 ; i < input_sz ; ++i ) {
				output[i] = input[i] ^ iv[iv_offset];
				++iv_offset;

				if ( BLOCK_SIZE == iv_offset ) {
					sc_ctx.encrypt(iv, iv);
					iv_offset = 0;
				}
			}

			output_sz = input_sz;

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		int finish(std::size_t &pad_sz)
		{
			pad_sz = 0;

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		static const std::size_t BLOCK_SIZE = SC::BLOCK_SIZE;
	protected:
		SC sc_ctx;

		uint8_t     iv[BLOCK_SIZE];
		std::size_t iv_offset;
};

}

#endif
