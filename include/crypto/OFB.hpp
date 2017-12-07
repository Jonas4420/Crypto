#ifndef CRYPTO_OFB_H
#define CRYPTO_OFB_H

#include <cstddef>
#include <cstdint>

#include "crypto/SymmetricCipher.hpp"
#include "crypto/Utils.hpp"

namespace Crypto
{

template <class SC>
class OFB final
{
	public:
		OFB(const uint8_t *key, std::size_t key_sz, const uint8_t iv[SC::BLOCK_SIZE])
			: sc_ctx(key, key_sz), iv_offset(0), is_finished(false)
		{
			sc_ctx.encrypt(iv, this->iv);
		}

		~OFB(void)
		{
			Utils::zeroize(iv, sizeof(iv));
		}

		int update(const uint8_t *input, std::size_t input_sz, uint8_t *output, std::size_t &output_sz)
		{
			if ( is_finished ) {
				throw SymmetricCipherException("Cipher has finished processing data");
			}

			// Check that output is large enough
			if ( output_sz < input_sz ) {
				output_sz = input_sz;
				return SC::CRYPTO_SYMMETRIC_CIPHER_INVALID_LENGTH;
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

			return SC::CRYPTO_SYMMETRIC_CIPHER_SUCCESS;
		}

		int finish(std::size_t &pad_sz)
		{
			if ( ! is_finished ) {
				pad_sz = 0;
				is_finished = true;
			}

			return SC::CRYPTO_SYMMETRIC_CIPHER_SUCCESS;
		}

		static const std::size_t BLOCK_SIZE = SC::BLOCK_SIZE;
	private:
		SC sc_ctx;

		uint8_t     iv[BLOCK_SIZE];
		std::size_t iv_offset;
		bool        is_finished;
};

}

#endif
