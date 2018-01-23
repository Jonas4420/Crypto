#ifndef CRYPTO_CFB_H
#define CRYPTO_CFB_H

#include "crypto/CipherMode.hpp"
#include "crypto/SymmetricCipher.hpp"

#include <cstring>

namespace Crypto
{

template <class SC>
class CFB : public CipherMode
{
	public:
		CFB(const uint8_t *key, std::size_t key_sz, const uint8_t iv[SC::BLOCK_SIZE], std::size_t STREAM_SIZE = SC::BLOCK_SIZE, bool is_encrypt = true)
			: sc_ctx(key, key_sz), buffer_sz(0), STREAM_SIZE(STREAM_SIZE), is_encrypt(is_encrypt)
		{
			if ( STREAM_SIZE < 1 || STREAM_SIZE > BLOCK_SIZE ) {
				throw SymmetricCipher::Exception("Invalid data segment size");
			}

			memcpy(this->iv, iv, BLOCK_SIZE);
		}

		~CFB(void)
		{
			zeroize(buffer, sizeof(buffer));
			zeroize(iv,     sizeof(iv));
			zeroize(ov,     sizeof(ov));
		}

		int update(const uint8_t *input, std::size_t input_sz, uint8_t *output, std::size_t &output_sz)
		{
			std::size_t need_sz, total_sz, write_sz;

			// Check that output is large enough
			need_sz = ((buffer_sz + input_sz) / STREAM_SIZE) * STREAM_SIZE;
			if ( output_sz < need_sz ) {
				output_sz = need_sz;
				return CRYPTO_CIPHER_MODE_INVALID_LENGTH;
			}

			// Process input
			total_sz  = buffer_sz + input_sz;
			output_sz = 0;
			while ( total_sz >= STREAM_SIZE ) {
				// Fill the buffer with input
				if ( buffer_sz < STREAM_SIZE ) {
					write_sz = STREAM_SIZE - buffer_sz;

					memcpy(buffer + buffer_sz, input, write_sz);
					buffer_sz = STREAM_SIZE;

					input    += write_sz;
					input_sz -= write_sz;
				}

				sc_ctx.encrypt(iv, ov);

				for ( std::size_t i = 0 ; i < STREAM_SIZE ; ++i ) {
					output[i] = buffer[i] ^ ov[i];
				}

				for ( std::size_t i = 0 ; i < BLOCK_SIZE - STREAM_SIZE ; ++i ) {
					iv[i] = iv[STREAM_SIZE + i];
				}
				for ( std::size_t i = 0 ; i < STREAM_SIZE ; ++i ) {
					iv[(BLOCK_SIZE - STREAM_SIZE) + i] =
						is_encrypt ?  output[i] : buffer[i];
				}

				buffer_sz = 0;

				// Update size of data
				output    += STREAM_SIZE;
				output_sz += STREAM_SIZE;
				total_sz  -= STREAM_SIZE;
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
				pad_sz = STREAM_SIZE - buffer_sz;
				return CRYPTO_CIPHER_MODE_NOT_FULL;
			}

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		static const std::size_t BLOCK_SIZE = SC::BLOCK_SIZE;
	protected:
		SC sc_ctx;

		uint8_t     buffer[BLOCK_SIZE];
		std::size_t buffer_sz;
		std::size_t STREAM_SIZE;
		uint8_t     iv[BLOCK_SIZE];
		uint8_t     ov[BLOCK_SIZE];
		bool        is_encrypt;
};

}

#endif
