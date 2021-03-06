#ifndef CRYPTO_CBC_H
#define CRYPTO_CBC_H

#include "crypto/CipherMode.hpp"
#include "crypto/SymmetricCipher.hpp"

#include <type_traits>

#include <cstring>

namespace Crypto
{

template <class SC>
class CBC : public CipherMode
{
	static_assert(std::is_base_of<SymmetricCipher, SC>::value,
			"Template argument should be a SymmetricCipher");

	public:
		CBC(const uint8_t *key, std::size_t key_sz, const uint8_t iv[SC::BLOCK_SIZE], bool is_encrypt)
			: sc_ctx(key, key_sz), buffer_sz(0), is_encrypt(is_encrypt)
		{
			memcpy(this->iv, iv, BLOCK_SIZE);
		}

		~CBC(void)
		{
			zeroize(iv,          sizeof(iv));
			zeroize(buffer,      sizeof(buffer));
			zeroize(&buffer_sz,  sizeof(buffer_sz));
			zeroize(&is_encrypt, sizeof(is_encrypt));
		}

		int update(const uint8_t *input, std::size_t input_sz, uint8_t *output, std::size_t &output_sz)
		{
			std::size_t need_sz, total_sz, write_sz;

			// Check that output is large enough
			total_sz = buffer_sz + input_sz;
			need_sz  = (total_sz / BLOCK_SIZE) * BLOCK_SIZE;
			if ( output_sz < need_sz ) {
				output_sz = need_sz;
				return CRYPTO_CIPHER_MODE_INVALID_LENGTH;
			}

			// Process input
			output_sz = 0;
			while ( total_sz >= BLOCK_SIZE ) {
				// Fill the buffer with input
				if ( buffer_sz < BLOCK_SIZE ) {
					write_sz = BLOCK_SIZE - buffer_sz;

					memcpy(buffer + buffer_sz, input, write_sz);

					buffer_sz += BLOCK_SIZE;
					input     += write_sz;
					input_sz  -= write_sz;
				}

				if ( is_encrypt ) {
					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						buffer[i] ^= iv[i];
					}

					sc_ctx.encrypt(buffer, output);
					buffer_sz = 0;

					memcpy(iv, output, BLOCK_SIZE);
				} else {
					sc_ctx.decrypt(buffer, output);
					buffer_sz = 0;

					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						output[i] ^= iv[i];
						iv[i]      = buffer[i];
					}
				}

				// Update size of data
				output    += BLOCK_SIZE;
				output_sz += BLOCK_SIZE;
				total_sz  -= BLOCK_SIZE;
			}

			// Copy remaining part of input into buffer
			if ( input_sz > 0 ) {
				memcpy(buffer + buffer_sz, input, input_sz);
				buffer_sz += input_sz;
			}

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		int finish(std::size_t &pad_sz)
		{
			if ( buffer_sz != 0 ) {
				pad_sz = BLOCK_SIZE - buffer_sz;
				return CRYPTO_CIPHER_MODE_NOT_FULL;
			}

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		static const std::size_t BLOCK_SIZE = SC::BLOCK_SIZE;
	protected:
		SC sc_ctx;

		uint8_t     iv[BLOCK_SIZE];
		uint8_t     buffer[BLOCK_SIZE];
		std::size_t buffer_sz;
		bool        is_encrypt;
};

}

#endif
