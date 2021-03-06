#ifndef CRYPTO_CFB_H
#define CRYPTO_CFB_H

#include "crypto/CipherMode.hpp"
#include "crypto/SymmetricCipher.hpp"

#include <type_traits>

#include <cstring>

namespace Crypto
{

template <class SC>
class CFB : public CipherMode
{
	static_assert(std::is_base_of<SymmetricCipher, SC>::value,
			"Template argument should be a SymmetricCipher");

	public:
		CFB(const uint8_t *key, std::size_t key_sz, const uint8_t iv[SC::BLOCK_SIZE], std::size_t stream_sz, bool is_encrypt)
			: sc_ctx(key, key_sz), buffer_sz(0), stream_sz(stream_sz), is_encrypt(is_encrypt)
		{
			if ( stream_sz < 1 || stream_sz > BLOCK_SIZE ) {
				throw CipherMode::Exception("Invalid data segment size");
			}

			memcpy(this->iv, iv, BLOCK_SIZE);
		}

		~CFB(void)
		{
			zeroize(buffer,      sizeof(buffer));
			zeroize(&buffer_sz,  sizeof(buffer_sz));
			zeroize(&stream_sz,  sizeof(stream_sz));
			zeroize(iv,          sizeof(iv));
			zeroize(ov,          sizeof(ov));
			zeroize(&is_encrypt, sizeof(is_encrypt));
		}

		int update(const uint8_t *input, std::size_t input_sz, uint8_t *output, std::size_t &output_sz)
		{
			std::size_t need_sz, total_sz, write_sz;

			// Check that output is large enough
			need_sz = ((buffer_sz + input_sz) / stream_sz) * stream_sz;
			if ( output_sz < need_sz ) {
				output_sz = need_sz;
				return CRYPTO_CIPHER_MODE_INVALID_LENGTH;
			}

			// Process input
			total_sz  = buffer_sz + input_sz;
			output_sz = 0;
			while ( total_sz >= stream_sz ) {
				// Fill the buffer with input
				if ( buffer_sz < stream_sz ) {
					write_sz = stream_sz - buffer_sz;

					memcpy(buffer + buffer_sz, input, write_sz);
					buffer_sz = stream_sz;

					input    += write_sz;
					input_sz -= write_sz;
				}

				sc_ctx.encrypt(iv, ov);

				for ( std::size_t i = 0 ; i < stream_sz ; ++i ) {
					output[i] = buffer[i] ^ ov[i];
				}

				for ( std::size_t i = 0 ; i < BLOCK_SIZE - stream_sz ; ++i ) {
					iv[i] = iv[stream_sz + i];
				}
				for ( std::size_t i = 0 ; i < stream_sz ; ++i ) {
					iv[(BLOCK_SIZE - stream_sz) + i] =
						is_encrypt ?  output[i] : buffer[i];
				}

				buffer_sz = 0;

				// Update size of data
				output    += stream_sz;
				output_sz += stream_sz;
				total_sz  -= stream_sz;
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
				pad_sz = stream_sz - buffer_sz;
				return CRYPTO_CIPHER_MODE_NOT_FULL;
			}

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		static const std::size_t BLOCK_SIZE = SC::BLOCK_SIZE;
	protected:
		SC sc_ctx;

		uint8_t     buffer[BLOCK_SIZE];
		std::size_t buffer_sz;
		std::size_t stream_sz;
		uint8_t     iv[BLOCK_SIZE];
		uint8_t     ov[BLOCK_SIZE];
		bool        is_encrypt;
};

}

#endif
