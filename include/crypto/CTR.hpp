#ifndef CRYPTO_CTR_H
#define CRYPTO_CTR_H

#include "crypto/CipherMode.hpp"
#include "crypto/SymmetricCipher.hpp"

#include <cstring>

namespace Crypto
{

template <class SC>
class CTR : public CipherMode
{
	public:
		CTR(const uint8_t *key, std::size_t key_sz, uint8_t counter[SC::BLOCK_SIZE])
			: sc_ctx(key, key_sz)
		{
			memcpy(this->begin,   counter, BLOCK_SIZE);
			memcpy(this->counter, counter, BLOCK_SIZE);

			sc_ctx.encrypt(this->counter, stream);
			stream_sz = 0;
		}

		~CTR(void)
		{
			zeroize(begin,   sizeof(begin));
			zeroize(counter, sizeof(counter));
			zeroize(stream,  sizeof(stream));
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
				output[i] = input[i] ^ stream[stream_sz];
				++stream_sz;

				if ( BLOCK_SIZE == stream_sz ) {
					for ( std::size_t j = BLOCK_SIZE - 1 ; j < BLOCK_SIZE ; --j ) {
						if ( ++counter[j] != 0 ) {
							break;
						}
					}

					if ( 0 == memcmp(begin, counter, BLOCK_SIZE) ) {
						throw SymmetricCipher::Exception("Counter MUST be unique for a given key");
					}

					sc_ctx.encrypt(counter, stream);
					stream_sz = 0;
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

		uint8_t     begin[BLOCK_SIZE];
		uint8_t     counter[BLOCK_SIZE];
		uint8_t     stream[BLOCK_SIZE];
		std::size_t stream_sz;
};

}

#endif
