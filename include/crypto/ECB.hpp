#ifndef CRYPTO_ECB_H
#define CRYPTO_ECB_H

#include <cstddef>
#include <cstdint>

#include "crypto/Padding.hpp"
#include "crypto/SymmetricCipher.hpp"
#include "crypto/Utils.hpp"

namespace Crypto
{

template <class SC, class P = PKCS7Padding>
class ECB final
{
	public:
		ECB(const uint8_t *key, std::size_t key_sz, bool is_encrypt = true)
			: sc_ctx(key, key_sz), buffer_sz(0), is_encrypt(is_encrypt)
		{
		}

		~ECB(void)
		{
			Utils::zeroize(buffer, sizeof(buffer));
		}

		int update(const uint8_t *input, std::size_t input_sz, uint8_t *output, std::size_t &output_sz)
		{
			return is_encrypt ?
				encrypt_update(input, input_sz, output, output_sz) :
				decrypt_update(input, input_sz, output, output_sz);
		}

		int finish(uint8_t *output, std::size_t &output_sz)
		{
			return is_encrypt ?
				encrypt_finish(output, output_sz) :
				decrypt_finish(output, output_sz);
		}

		static const std::size_t BLOCK_SIZE = SC::BLOCK_SIZE;
	private:
		SC sc_ctx;
		P  p_ctx;

		uint8_t     buffer[BLOCK_SIZE];
		std::size_t buffer_sz;
		bool        is_encrypt;

		int encrypt_update(const uint8_t *plain, std::size_t plain_sz, uint8_t *cipher, std::size_t &cipher_sz)
		{
			std::size_t need_sz, total_sz, write_sz;

			// Check that cipher is large enough
			need_sz = ((buffer_sz + plain_sz) / BLOCK_SIZE) * BLOCK_SIZE;
			if ( need_sz > cipher_sz ) {
				cipher_sz = need_sz;
				return SC::CRYPTO_SYMMETRIC_CIPHER_INVALID_LENGTH;
			}

			// Encrypt provided plaintext 
			total_sz  = buffer_sz + plain_sz;
			cipher_sz = 0;
			while ( total_sz >= BLOCK_SIZE ) {
				// Fill the buffer with plaintext
				if ( buffer_sz < BLOCK_SIZE ) {
					write_sz = BLOCK_SIZE - buffer_sz;

					memcpy(buffer + buffer_sz, plain, write_sz);
					buffer_sz = BLOCK_SIZE;

					plain    += write_sz;
					plain_sz -= write_sz;
				}

				// Encrypt data
				sc_ctx.encrypt(buffer, cipher);
				buffer_sz = 0;

				// Update size of data
				cipher    += BLOCK_SIZE;
				cipher_sz += BLOCK_SIZE;
				total_sz  -= BLOCK_SIZE;
			}

			// Copy remaining part of plaintext into buffer
			if ( plain_sz > 0 ) {
				memcpy(buffer + buffer_sz, plain, plain_sz);
				buffer_sz += plain_sz % BLOCK_SIZE;
			}
			cipher_sz = need_sz;

			return SC::CRYPTO_SYMMETRIC_CIPHER_SUCCESS;
		}

		int encrypt_finish(uint8_t *cipher, std::size_t &cipher_sz)
		{
			if ( BLOCK_SIZE > cipher_sz ) {
				cipher_sz = BLOCK_SIZE;
				return SC::CRYPTO_SYMMETRIC_CIPHER_INVALID_LENGTH;
			}

			P::pad(buffer, buffer_sz, BLOCK_SIZE);
			sc_ctx.encrypt(buffer, cipher);
			cipher_sz = BLOCK_SIZE;

			return SC::CRYPTO_SYMMETRIC_CIPHER_SUCCESS;
		}

		int decrypt_update(const uint8_t *cipher, std::size_t cipher_sz, uint8_t *plain, std::size_t &plain_sz)
		{
			// TODO: always keep buffer full, so we can have padding at finish
			return SC::CRYPTO_SYMMETRIC_CIPHER_SUCCESS;
		}

		int decrypt_finish(uint8_t *plain, std::size_t &plain_sz)
		{
			if ( 0 != buffer_sz % BLOCK_SIZE ) {
				throw PaddingException("Invalid padding");
			}

			if ( BLOCK_SIZE > plain_sz ) {
				plain_sz = BLOCK_SIZE;
				return SC::CRYPTO_SYMMETRIC_CIPHER_INVALID_LENGTH;
			}

			sc_ctx.decrypt(buffer, plain);
			P::unpad(plain, BLOCK_SIZE, plain_sz);

			return SC::CRYPTO_SYMMETRIC_CIPHER_SUCCESS;
		}
};

template <class SC, class P>
int ECB_process(const uint8_t *key,   std::size_t key_sz,
		const uint8_t *input, std::size_t input_sz,
		uint8_t *output,      std::size_t &output_sz,
		bool is_encrypt)
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

}

#endif
