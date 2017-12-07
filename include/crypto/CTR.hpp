#ifndef CRYPTO_CTR_H
#define CRYPTO_CTR_H

#include <cstddef>
#include <cstdint>

#include "crypto/SymmetricCipher.hpp"
#include "crypto/Utils.hpp"

namespace Crypto
{

template <class SC>
class CTR final
{
	public:
		CTR(const uint8_t *key, std::size_t key_sz, uint8_t counter[SC::BLOCK_SIZE])
			: sc_ctx(key, key_sz), is_finished(false)
		{
			memcpy(this->begin,   counter, BLOCK_SIZE);
			memcpy(this->counter, counter, BLOCK_SIZE);

			sc_ctx.encrypt(this->counter, stream);
			stream_sz = 0;
		}

		~CTR(void)
		{
			Utils::zeroize(counter, sizeof(counter));
			Utils::zeroize(stream,  sizeof(stream));
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
				output[i] = input[i] ^ stream[stream_sz];
				++stream_sz;

				if ( BLOCK_SIZE == stream_sz ) {
					for ( std::size_t i = BLOCK_SIZE - 1 ; i < BLOCK_SIZE ; --i ) {
						if ( ++counter[i] != 0 ) {
							break;
						}
					}

					if ( 0 == memcmp(begin, counter, BLOCK_SIZE) ) {
						throw SymmetricCipherException("Counter MUST be unique for a given key");
					}

					sc_ctx.encrypt(counter, stream);
					stream_sz = 0;
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

		uint8_t     begin[BLOCK_SIZE];
		uint8_t     counter[BLOCK_SIZE];
		uint8_t     stream[BLOCK_SIZE];
		std::size_t stream_sz;
		bool        is_finished;
};

}

#endif
