#ifndef CRYPTO_ECB_H
#define CRYPTO_ECB_H

#include <cstddef>
#include <cstdint>

#include "crypto/SymmetricCipher.hpp"
#include "crypto/Utils.hpp"

namespace Crypto
{

template <class SC>
class ECB final
{
	public:
		ECB(const uint8_t *key, std::size_t key_sz, bool is_encrypt = true)
			: sc_ctx(key, key_sz), buffer_sz(0), is_encrypt(is_encrypt), is_finished(false)
		{
		}

		~ECB(void)
		{
			Utils::zeroize(buffer, sizeof(buffer));
		}

		int update(const uint8_t *input, std::size_t input_sz, uint8_t *output, std::size_t &output_sz)
		{
			std::size_t need_sz, total_sz, write_sz;

			if ( is_finished ) {
				throw SymmetricCipherException("Cipher has finished processing data");
			}

			// Check that output is large enough
			need_sz = ((buffer_sz + input_sz) / BLOCK_SIZE) * BLOCK_SIZE;
			if ( output_sz < need_sz ) {
				output_sz = need_sz;
				return SC::CRYPTO_SYMMETRIC_CIPHER_INVALID_LENGTH;
			}

			// Process input
			total_sz  = buffer_sz + input_sz;
			output_sz = 0;
			while ( total_sz >= BLOCK_SIZE ) {
				// Fill the buffer with input
				if ( buffer_sz < BLOCK_SIZE ) {
					write_sz = BLOCK_SIZE - buffer_sz;

					memcpy(buffer + buffer_sz, input, write_sz);
					buffer_sz = BLOCK_SIZE;

					input    += write_sz;
					input_sz -= write_sz;
				}

				if ( is_encrypt ) {
					sc_ctx.encrypt(buffer, output);
				} else {
					sc_ctx.decrypt(buffer, output);
				}
				buffer_sz = 0;

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

			return SC::CRYPTO_SYMMETRIC_CIPHER_SUCCESS;
		}

		int finish(std::size_t &pad_sz)
		{
			if ( ! is_finished ) {
				if ( buffer_sz != 0 ) {
					pad_sz = BLOCK_SIZE - buffer_sz;
					return SC::CRYPTO_SYMMETRIC_CIPHER_NOT_FULL;
				}

				is_finished = true;
			}

			return SC::CRYPTO_SYMMETRIC_CIPHER_SUCCESS;
		}

		static const std::size_t BLOCK_SIZE = SC::BLOCK_SIZE;
	private:
		SC sc_ctx;

		uint8_t     buffer[BLOCK_SIZE];
		std::size_t buffer_sz;
		bool        is_encrypt;
		bool        is_finished;
};

/*
template <class SC, class P>
int ECB_process(const uint8_t *key,   std::size_t key_sz,
		const uint8_t *input, std::size_t input_sz,
		uint8_t *output,      std::size_t &output_sz,
		bool is_encrypt = true)
{
	std::size_t need_sz, total_sz, tmp_sz;

	if ( is_encrypt ) {
		need_sz = input_sz + (SC::BLOCK_SIZE - (input_sz % SC::BLOCK_SIZE));
	} else {
		need_sz = input_sz;
	}

	if ( output_sz < need_sz ) {
		output_sz = need_sz;
		return SC::CRYPTO_SYMMETRIC_CIPHER_INVALID_LENGTH;
	}

	ECB<SC, P> ctx(key, key_sz, is_encrypt);

	total_sz = tmp_sz = output_sz;
	ctx.update(input, input_sz, output, tmp_sz);
	output    += tmp_sz;
	output_sz  = tmp_sz;

	tmp_sz = total_sz - output_sz;
	ctx.finish(output, tmp_sz);
	output_sz += tmp_sz;

	return SC::CRYPTO_SYMMETRIC_CIPHER_SUCCESS;
}
*/

}

#endif
