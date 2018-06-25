#ifndef CRYPTO_RSAES_PKCS1_v1_5_H
#define CRYPTO_RSAES_PKCS1_v1_5_H

#include "crypto/MessageDigest.hpp"
#include "crypto/RSA.hpp"

#include <memory>
#include <type_traits>

#include <cstring>

namespace Crypto
{

template<class MD>
class RSAES_PKCS1_v1_5
{
	static_assert(std::is_base_of<MessageDigest, MD>::value,
			"Template argument should be a MessageDigest");

	public:
		static int Encrypt(const RSA::RSAPublicKey &pubKey,
				int (*f_rng)(void*, uint8_t*, std::size_t), void *p_rng,
				const uint8_t *input, std::size_t input_sz,
				uint8_t *output, std::size_t &output_sz)
		{
			std::size_t key_sz   = pubKey.n.size();
			std::size_t unpad_sz = input_sz + 11;

			// 1. Length checking
			if ( unpad_sz < input_sz ) {
				return CRYPTO_RSA_MESSAGE_TOO_LONG;
			}

			if ( unpad_sz > key_sz ) {
				return CRYPTO_RSA_MESSAGE_TOO_LONG;
			}

			if ( output_sz < key_sz ) {
				output_sz = key_sz;
				return CRYPTO_RSA_INVALID_LENGTH;
			}

			// 2. EME-PKCS1-v1_5 encoding
			uint8_t *p = output;

			*p = 0x00;
			p += 1;

			*p = 0x02;
			p += 1;

			for ( std::size_t i = 0 ; i < key_sz - (input_sz + 3) ; ++i ) {
				do {
					if ( 0 != f_rng(p_rng, p, 1) ) {
						output_sz = 0;
						return CRYPTO_RSA_RNG_ERROR;
					}
				} while ( 0x00 == *p );

				p += 1;
			}

			*p = 0x00;
			p += 1;

			memcpy(p, input, input_sz);

			// 3. RSA encryption
			return RSAEP(pubKey, output, key_sz, output, output_sz);
		}

		static int Decrypt(const RSA::RSAPrivateKey &privKey,
				const uint8_t *input, std::size_t input_sz,
				uint8_t *output, std::size_t &output_sz)
		{
			std::size_t key_sz   = privKey.n.size();
			std::size_t unpad_sz = 11;

			// 1. Length checking
			if ( key_sz != input_sz ) {
				return CRYPTO_RSA_DECRYPTION_ERROR;
			}

			if ( unpad_sz > key_sz ) {
				return CRYPTO_RSA_DECRYPTION_ERROR;
			}

			// 2. RSA decryption
			std::unique_ptr<uint8_t[]> em(new uint8_t[key_sz]);

			if ( 0 != RSADP(privKey, input, input_sz, em.get(), key_sz) ) {
				return CRYPTO_RSA_DECRYPTION_ERROR;
			}

			// 3. EME-PKCS1-v1_5 decoding (constant time)
			uint8_t bad = 0;
			uint8_t *p = em.get();

			bad |= *p;
			p += 1;

			bad |= (*p ^ 0x02);
			p += 1;

			std::size_t pad_sz = 0;
			uint8_t pad_done = 0x00;
			for ( std::size_t i = 0 ; i < key_sz - 3 ; ++i ) {
				pad_done |= ((p[i]     | static_cast<uint8_t>(-p[i])) >> 7)     ^ 1;
				pad_sz   += ((pad_done | static_cast<uint8_t>(-pad_done)) >> 7) ^ 1;
			}
			p += pad_sz;

			bad |= *p;
			p += 1;

			bad |= (pad_sz < 8);

			if ( 0x00 != bad ) {
				zeroize(em.get(), key_sz);
				return CRYPTO_RSA_DECRYPTION_ERROR;
			}

			std::size_t need_sz = key_sz - (p - em.get());

			if ( output_sz < need_sz ) {
				output_sz = need_sz;
				zeroize(em.get(), key_sz);
				return CRYPTO_RSA_INVALID_LENGTH;
			}

			output_sz = need_sz;
			memcpy(output, p, need_sz);

			zeroize(em.get(), key_sz);

			return CRYPTO_RSA_SUCCESS;
		}
};

}

#endif
