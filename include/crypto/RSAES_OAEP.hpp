#ifndef CRYPTO_RSAES_OAEP_H
#define CRYPTO_RSAES_OAEP_H

#include "crypto/MessageDigest.hpp"
#include "crypto/RSA.hpp"

#include <memory>
#include <type_traits>

#include <cstring>

namespace Crypto
{

template<class MD>
class RSAES_OAEP
{
	static_assert(std::is_base_of<MessageDigest, MD>::value,
			"Template argument should be a MessageDigest");

	public:
		static int Encrypt(const RSA::RSAPublicKey &pubKey,
				const uint8_t *input, std::size_t input_sz, const uint8_t *label, std::size_t label_sz,
				uint8_t *output, std::size_t &output_sz,
				int (*f_rng)(void*, uint8_t*, std::size_t), void *p_rng)
		{
			std::size_t key_sz   = pubKey.size();
			std::size_t unpad_sz = input_sz + 2 * MD::SIZE + 2;

			// 1. Length checking
			if ( unpad_sz < input_sz ) {
				return RSA::CRYPTO_RSA_MESSAGE_TOO_LONG;
			}

			if ( unpad_sz > key_sz ) {
				return RSA::CRYPTO_RSA_MESSAGE_TOO_LONG;
			}

			if ( output_sz < key_sz ) {
				output_sz = key_sz;
				return RSA::CRYPTO_RSA_INVALID_LENGTH;
			}

			// 2. EME-OAEP encoding
			uint8_t *p = output;

			*p = 0x00;
			p += 1;

			if ( 0 != f_rng(p_rng, p, MD::SIZE) ) {
				output_sz = 0;
				return RSA::CRYPTO_RSA_RNG_ERROR;
			}
			p += MD::SIZE;

			MessageDigest_get<MD>(label, label_sz, p);
			p += MD::SIZE;

			memset(p, 0x00, key_sz - (input_sz + (2 * MD::SIZE) + 2));
			p += (key_sz - (input_sz + (2 * MD::SIZE) + 2));

			*p = 0x01;
			p += 1;

			memcpy(p, input, input_sz);

			MGF1_mask(output + 1, MD::SIZE, output + 1 + MD::SIZE, key_sz - (1 + MD::SIZE));
			MGF1_mask(output + 1 + MD::SIZE, key_sz - (1 + MD::SIZE), output + 1, MD::SIZE);

			// 3. RSA encryption
			return RSA::RSAEP(pubKey, output, key_sz, output, output_sz);
		}

		static int Decrypt(const RSA::RSAPrivateKey &privKey,
				const uint8_t *input, std::size_t input_sz, const uint8_t *label, std::size_t label_sz,
				uint8_t *output, std::size_t &output_sz)
		{
			std::size_t key_sz   = privKey.size();
			std::size_t unpad_sz = 2 * MD::SIZE + 2;
			uint8_t lHash[MD::SIZE];

			// 1. Length checking
			if ( key_sz != input_sz ) {
				return RSA::CRYPTO_RSA_DECRYPTION_ERROR;
			}

			if ( unpad_sz > key_sz ) {
				return RSA::CRYPTO_RSA_DECRYPTION_ERROR;
			}

			// 2. RSA decryption
			std::unique_ptr<uint8_t[]> em(new uint8_t[key_sz]);

			if ( 0 != RSA::RSADP(privKey, input, input_sz, em.get(), key_sz) ) {
				return RSA::CRYPTO_RSA_DECRYPTION_ERROR;
			}

			// 3. EME-OAEP decoding (constant time)
			uint8_t bad = 0;
			uint8_t *p = em.get();

			MessageDigest_get<MD>(label, label_sz, lHash);

			MGF1_mask(p + 1 + MD::SIZE, key_sz - (1 + MD::SIZE), p + 1, MD::SIZE);
			MGF1_mask(p + 1, MD::SIZE, p + 1 + MD::SIZE, key_sz - (1 + MD::SIZE));

			bad |= *p;
			p += 1;

			p += MD::SIZE;

			for ( std::size_t i = 0 ; i < MD::SIZE ; ++i ) {
				bad |= (lHash[i] ^ *p);
				p += 1;
			}

			std::size_t pad_sz = 0;
			uint8_t pad_done = 0x00;
			for ( std::size_t i = 0 ; i < key_sz - ((p - em.get()) + 1) ; ++i ) {
				pad_done |= p[i];
				pad_sz   += ((pad_done | static_cast<uint8_t>(-pad_done)) >> 7) ^ 1;
			}
			p += pad_sz;

			bad |= (0x01 ^ *p);

			if ( 0x00 != bad ) {
				zeroize(em.get(), key_sz);
				return RSA::CRYPTO_RSA_DECRYPTION_ERROR;
			}

			std::size_t need_sz = key_sz - (p - em.get());

			if ( output_sz < need_sz ) {
				output_sz = need_sz;
				zeroize(em.get(), key_sz);
				return RSA::CRYPTO_RSA_INVALID_LENGTH;
			}

			output_sz = need_sz;
			memcpy(output, p, need_sz);

			zeroize(em.get(), key_sz);

			return RSA::CRYPTO_RSA_SUCCESS;
		}

	private:
		static void MGF1_mask(const uint8_t *input, std::size_t input_sz, uint8_t *output, std::size_t output_sz)
		{
			uint8_t mask[MD::SIZE];
			uint8_t counter[4];
			std::size_t write_sz;
			MD ctx;

			memset(counter, 0x00, sizeof(counter));

			while ( output_sz > 0 ) {
				write_sz = output_sz < MD::SIZE ? output_sz : MD::SIZE;

				ctx.update(input,   input_sz);
				ctx.update(counter, sizeof(counter));
				ctx.finish(mask);

				for ( std::size_t i = 0 ; i < write_sz ; ++i ) {
					output[i] ^= mask[i];
				}

				for ( std::size_t i = sizeof(counter) - 1 ; i < sizeof(counter) ; --i ) {
					if ( ++counter[i] != 0 ) {
						break;
					}
				}

				output    += write_sz;
				output_sz -= write_sz;
			}

			zeroize(mask,    sizeof(mask));
			zeroize(counter, sizeof(counter));
		}

		static void zeroize(void *v, std::size_t n)
		{
			volatile uint8_t *p = static_cast<uint8_t*>(v);

			while ( n-- ) {
				*p++ = 0x00;
			}
		}
};

}

#endif
