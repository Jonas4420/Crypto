#ifndef CRYPTO_CBC_CS_H
#define CRYPTO_CBC_CS_H

#include "crypto/CipherMode.hpp"
#include "crypto/SymmetricCipher.hpp"

#include <cstring>

namespace Crypto
{

template <class SC>
class CBC_CS1 : public CipherMode
{
	public:
		CBC_CS1(const uint8_t *key, std::size_t key_sz, const uint8_t iv[SC::BLOCK_SIZE], bool is_encrypt)
			: sc_ctx(key, key_sz), buffer_sz(0), is_encrypt(is_encrypt)
		{
			memcpy(this->iv, iv, BLOCK_SIZE);
		}

		~CBC_CS1(void)
		{
			zeroize(buffer,      sizeof(buffer));
			zeroize(iv,          sizeof(iv));
			zeroize(&buffer_sz,  sizeof(buffer_sz));
			zeroize(&is_encrypt, sizeof(is_encrypt));
		}

		int update(const uint8_t *input, std::size_t input_sz, uint8_t *output, std::size_t &output_sz)
		{
			std::size_t need_sz, total_sz, write_sz;

			// Check that output size is large enough
			total_sz = input_sz + buffer_sz;
			need_sz = total_sz < sizeof(buffer) ? 0
				: (total_sz - (BLOCK_SIZE + (total_sz % BLOCK_SIZE)));
			if ( output_sz < need_sz ) {
				output_sz = need_sz;
				return CRYPTO_CIPHER_MODE_INVALID_LENGTH;
			}

			// Process input
			output_sz = 0;
			while ( total_sz >= sizeof(buffer) ) {
				// Fill buffer with input
				if ( buffer_sz < sizeof(buffer) ) {
					write_sz = sizeof(buffer) - buffer_sz;

					memcpy(buffer + buffer_sz, input, write_sz);

					buffer_sz += write_sz;
					input     += write_sz;
					input_sz  -= write_sz;
				}

				if ( is_encrypt ) {
					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						buffer[i] ^= iv[i];
					}

					sc_ctx.encrypt(buffer, output);
					buffer_sz -= BLOCK_SIZE;

					memcpy(iv, output, BLOCK_SIZE);
				} else {
					sc_ctx.decrypt(buffer, output);
					buffer_sz -= BLOCK_SIZE;

					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						output[i] ^= iv[i];
						iv[i]      = buffer[i];
					}
				}

				memcpy(buffer, buffer + BLOCK_SIZE, buffer_sz);

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
			if ( buffer_sz < BLOCK_SIZE ) {
				pad_sz = BLOCK_SIZE - buffer_sz;
				return CRYPTO_CIPHER_MODE_NOT_FULL;
			}

			pad_sz = 0;

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		int steal_last(uint8_t *output, std::size_t &output_sz)
		{
			std::size_t steal_sz = buffer_sz % BLOCK_SIZE;

			if ( buffer_sz < BLOCK_SIZE ) {
				output_sz = BLOCK_SIZE - buffer_sz;
				return CRYPTO_CIPHER_MODE_NOT_FULL;
			}

			if ( output_sz < buffer_sz ) {
				output_sz = buffer_sz;
				return CRYPTO_CIPHER_MODE_INVALID_LENGTH;
			}

			if ( is_encrypt ) {
				for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
					buffer[i] ^= iv[i];
				}

				if ( 0 != steal_sz ) {
					sc_ctx.encrypt(buffer, buffer);

					for ( std::size_t i = 0 ; i < steal_sz ; ++i ) {
						output[i] = buffer[i];
						buffer[i] ^= buffer[i + BLOCK_SIZE];
					}
				}

				sc_ctx.encrypt(buffer, output + steal_sz);
			} else {
				sc_ctx.decrypt(buffer + steal_sz, buffer + steal_sz);

				if ( 0 != steal_sz ) {
					for ( std::size_t i = 0 ; i < steal_sz ; ++i ) {
						output[i + BLOCK_SIZE] = buffer[i] ^ buffer[i + steal_sz];
						buffer[i + steal_sz]   = buffer[i];
					}

					sc_ctx.decrypt(buffer + steal_sz, buffer + steal_sz);
				}

				for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
					output[i] = buffer[i + steal_sz] ^ iv[i];
				}
			}

			output_sz = buffer_sz;

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		static const std::size_t BLOCK_SIZE = SC::BLOCK_SIZE;
	protected:
		SC sc_ctx;

		uint8_t     buffer[2 * BLOCK_SIZE];
		uint8_t     iv[BLOCK_SIZE];
		std::size_t buffer_sz;
		bool        is_encrypt;
};

template <class SC>
class CBC_CS2 : public CipherMode
{
	public:
		CBC_CS2(const uint8_t *key, std::size_t key_sz, const uint8_t iv[SC::BLOCK_SIZE], bool is_encrypt)
			: sc_ctx(key, key_sz), buffer_sz(0), is_encrypt(is_encrypt)
		{
			memcpy(this->iv, iv, BLOCK_SIZE);
		}

		~CBC_CS2(void)
		{
			zeroize(buffer,      sizeof(buffer));
			zeroize(iv,          sizeof(iv));
			zeroize(&buffer_sz,  sizeof(buffer_sz));
			zeroize(&is_encrypt, sizeof(is_encrypt));
		}

		int update(const uint8_t *input, std::size_t input_sz, uint8_t *output, std::size_t &output_sz)
		{
			std::size_t need_sz, total_sz, write_sz;

			// Check that output size is large enough
			total_sz = input_sz + buffer_sz;
			need_sz = total_sz < sizeof(buffer) ? 0
				: (total_sz - (BLOCK_SIZE + (total_sz % BLOCK_SIZE)));
			if ( output_sz < need_sz ) {
				output_sz = need_sz;
				return CRYPTO_CIPHER_MODE_INVALID_LENGTH;
			}

			// Process input
			output_sz = 0;
			while ( total_sz >= sizeof(buffer) ) {
				// Fill buffer with input
				if ( buffer_sz < sizeof(buffer) ) {
					write_sz = sizeof(buffer) - buffer_sz;

					memcpy(buffer + buffer_sz, input, write_sz);

					buffer_sz += write_sz;
					input     += write_sz;
					input_sz  -= write_sz;
				}

				if ( is_encrypt ) {
					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						buffer[i] ^= iv[i];
					}

					sc_ctx.encrypt(buffer, output);
					buffer_sz -= BLOCK_SIZE;

					memcpy(iv, output, BLOCK_SIZE);
				} else {
					sc_ctx.decrypt(buffer, output);
					buffer_sz -= BLOCK_SIZE;

					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						output[i] ^= iv[i];
						iv[i]      = buffer[i];
					}
				}

				memcpy(buffer, buffer + BLOCK_SIZE, buffer_sz);

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
			if ( buffer_sz < BLOCK_SIZE ) {
				pad_sz = BLOCK_SIZE - buffer_sz;
				return CRYPTO_CIPHER_MODE_NOT_FULL;
			}

			pad_sz = 0;

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		int steal_last(uint8_t *output, std::size_t &output_sz)
		{
			std::size_t steal_sz = buffer_sz % BLOCK_SIZE;

			if ( buffer_sz < BLOCK_SIZE ) {
				output_sz = BLOCK_SIZE - buffer_sz;
				return CRYPTO_CIPHER_MODE_NOT_FULL;
			}

			if ( output_sz < buffer_sz ) {
				output_sz = buffer_sz;
				return CRYPTO_CIPHER_MODE_INVALID_LENGTH;
			}

			if ( is_encrypt ) {
				for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
					buffer[i] ^= iv[i];
				}

				if ( 0 != steal_sz ) {
					sc_ctx.encrypt(buffer, buffer);

					for ( std::size_t i = 0 ; i < steal_sz ; ++i ) {
						output[i + BLOCK_SIZE] = buffer[i];
						buffer[i] ^= buffer[i + BLOCK_SIZE];
					}
				}

				sc_ctx.encrypt(buffer, output);
			} else {
				sc_ctx.decrypt(buffer, buffer);

				if ( 0 != steal_sz ) {
					for  ( std::size_t i = 0 ; i < steal_sz ; ++i ) {
						output[i + BLOCK_SIZE] = buffer[i] ^ buffer[i + BLOCK_SIZE];
						buffer[i] = buffer[i + BLOCK_SIZE];
					}

					sc_ctx.decrypt(buffer, buffer);
				}

				for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
					output[i] = buffer[i] ^ iv[i];
				}
			}

			output_sz = buffer_sz;

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		static const std::size_t BLOCK_SIZE = SC::BLOCK_SIZE;
	protected:
		SC sc_ctx;

		uint8_t     buffer[2 * BLOCK_SIZE];
		uint8_t     iv[BLOCK_SIZE];
		std::size_t buffer_sz;
		bool        is_encrypt;
};

template <class SC>
class CBC_CS3 : public CipherMode
{
	public:
		CBC_CS3(const uint8_t *key, std::size_t key_sz, const uint8_t iv[SC::BLOCK_SIZE], bool is_encrypt)
			: sc_ctx(key, key_sz), buffer_sz(0), is_encrypt(is_encrypt)
		{
			memcpy(this->iv, iv, BLOCK_SIZE);
		}

		~CBC_CS3(void)
		{
			zeroize(buffer,      sizeof(buffer));
			zeroize(iv,          sizeof(iv));
			zeroize(&buffer_sz,  sizeof(buffer_sz));
			zeroize(&is_encrypt, sizeof(is_encrypt));
		}

		int update(const uint8_t *input, std::size_t input_sz, uint8_t *output, std::size_t &output_sz)
		{
			std::size_t need_sz, total_sz, write_sz;

			total_sz = input_sz + buffer_sz;
			need_sz = total_sz < sizeof(buffer) ? 0
				: (total_sz - (2 * BLOCK_SIZE + (total_sz % BLOCK_SIZE)));
			if ( output_sz < need_sz ) {
				output_sz = need_sz;
				return CRYPTO_CIPHER_MODE_INVALID_LENGTH;
			}

			// Process input
			output_sz = 0;
			while ( total_sz >= sizeof(buffer) ) {
				// Fill buffer with input
				if ( buffer_sz < sizeof(buffer) ) {
					write_sz = sizeof(buffer) - buffer_sz;

					memcpy(buffer + buffer_sz, input, write_sz);

					buffer_sz += write_sz;
					input     += write_sz;
					input_sz  -= write_sz;
				}

				if ( is_encrypt ) {
					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						buffer[i] ^= iv[i];
					}

					sc_ctx.encrypt(buffer, output);
					buffer_sz -= BLOCK_SIZE;

					memcpy(iv, output, BLOCK_SIZE);
				} else {
					sc_ctx.decrypt(buffer, output);
					buffer_sz -= BLOCK_SIZE;

					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						output[i] ^= iv[i];
						iv[i]      = buffer[i];
					}
				}

				memcpy(buffer,              buffer + BLOCK_SIZE,     BLOCK_SIZE);
				memcpy(buffer + BLOCK_SIZE, buffer + 2 * BLOCK_SIZE, BLOCK_SIZE);

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
			if ( buffer_sz < BLOCK_SIZE ) {
				pad_sz = BLOCK_SIZE - buffer_sz;
				return CRYPTO_CIPHER_MODE_NOT_FULL;
			}

			pad_sz = 0;

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		int steal_last(uint8_t *output, std::size_t &output_sz)
		{
			std::size_t steal_sz = buffer_sz % BLOCK_SIZE;
			uint8_t *p_buffer = buffer;

			if ( buffer_sz < BLOCK_SIZE ) {
				output_sz = BLOCK_SIZE - buffer_sz;
				return CRYPTO_CIPHER_MODE_NOT_FULL;
			}

			if ( output_sz < buffer_sz ) {
				output_sz = buffer_sz;
				return CRYPTO_CIPHER_MODE_INVALID_LENGTH;
			}

			if ( is_encrypt ) {
				for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
					p_buffer[i] ^= iv[i];
				}

				if ( buffer_sz == 2 * BLOCK_SIZE ) {
					sc_ctx.encrypt(p_buffer, output + BLOCK_SIZE);

					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						p_buffer[i + BLOCK_SIZE] ^= output[i + BLOCK_SIZE];
						p_buffer[i] = p_buffer[i + BLOCK_SIZE];
					}
				} else if ( buffer_sz > 2 * BLOCK_SIZE ) {
					sc_ctx.encrypt(p_buffer, output);

					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						p_buffer[i + BLOCK_SIZE] ^= output[i];
					}

					output   += BLOCK_SIZE;
					p_buffer += BLOCK_SIZE;
				}

				if ( 0 != steal_sz ) {
					sc_ctx.encrypt(p_buffer, p_buffer);

					for ( std::size_t i = 0 ; i < steal_sz ; ++i ) {
						output[i + BLOCK_SIZE] = p_buffer[i];
						p_buffer[i] ^= p_buffer[i + BLOCK_SIZE];
					}
				}

				sc_ctx.encrypt(p_buffer, output);
			} else {
				if ( buffer_sz > 2 * BLOCK_SIZE ) {
					p_buffer += BLOCK_SIZE;
					output   += BLOCK_SIZE;
				}

				if ( 0 != steal_sz ) {
					sc_ctx.decrypt(p_buffer, p_buffer);

					for ( std::size_t i = 0 ; i < steal_sz ; ++i ) {
						output[i + BLOCK_SIZE] = p_buffer[i] ^ p_buffer[i + BLOCK_SIZE];
						p_buffer[i] = p_buffer[i + BLOCK_SIZE];
					}
				}

				if ( buffer_sz == 2 * BLOCK_SIZE ) {
					sc_ctx.decrypt(p_buffer, output + BLOCK_SIZE);

					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						output[i + BLOCK_SIZE] ^= p_buffer[i + BLOCK_SIZE];
						p_buffer[i] = p_buffer[i + BLOCK_SIZE];
					}
				} else if ( buffer_sz > 2 * BLOCK_SIZE ) {
					sc_ctx.decrypt(p_buffer, output);

					p_buffer -= BLOCK_SIZE;
					output   -= BLOCK_SIZE;

					for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
						output[i + BLOCK_SIZE] ^= p_buffer[i];
					}
				}

				sc_ctx.decrypt(p_buffer, output);

				for ( std::size_t i = 0 ; i < BLOCK_SIZE ; ++i ) {
					output[i] ^= iv[i];
				}
			}

			output_sz = buffer_sz;

			return CRYPTO_CIPHER_MODE_SUCCESS;
		}

		static const std::size_t BLOCK_SIZE = SC::BLOCK_SIZE;
	protected:
		SC sc_ctx;

		uint8_t     buffer[3 * BLOCK_SIZE];
		uint8_t     iv[BLOCK_SIZE];
		std::size_t buffer_sz;
		bool        is_encrypt;
};

}

#endif
