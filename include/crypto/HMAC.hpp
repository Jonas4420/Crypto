#ifndef CRYPTO_HMAC_H
#define CRYPTO_HMAC_H

#include "crypto/MessageDigest.hpp"

#include <type_traits>

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace Crypto
{

template <class MD>
class HMAC
{
	static_assert(std::is_base_of<MessageDigest, MD>::value,
			"Template argument should be a MessageDigest");

	public:
		HMAC(const uint8_t *key, std::size_t key_sz)
		{
			uint8_t K0[MD::BLOCK_SIZE];
			uint8_t *ipad, *opad;

			zeroize(K0, MD::BLOCK_SIZE);

			if ( key_sz > MD::BLOCK_SIZE ) {
				md_ctx.update(key, key_sz);
				md_ctx.finish(K0);
			} else {
				for ( std::size_t i = 0 ; i < key_sz ; ++i ) {
					K0[i] = key[i];
				}
			}

			ipad = hmac_ctx;
			opad = hmac_ctx + MD::BLOCK_SIZE;

			memset(ipad, 0x36, MD::BLOCK_SIZE);
			memset(opad, 0x5C, MD::BLOCK_SIZE);

			for ( std::size_t i = 0 ; i < MD::BLOCK_SIZE ; ++i ) {
				ipad[i] ^= K0[i];
				opad[i] ^= K0[i];
			}

			zeroize(K0, sizeof(K0));

			md_ctx.update(ipad, MD::BLOCK_SIZE);
		}

		~HMAC(void)
		{
			zeroize(hmac_ctx, sizeof(hmac_ctx));
		}

		void update(const uint8_t *input, std::size_t input_sz)
		{
			md_ctx.update(input, input_sz);
		}

		void finish(uint8_t *output)
		{
			uint8_t tmp[MD::SIZE];
			uint8_t *opad;

			opad = hmac_ctx + MD::BLOCK_SIZE;
			md_ctx.finish(tmp);

			md_ctx.update(opad, MD::BLOCK_SIZE);
			md_ctx.update(tmp,  MD::SIZE);
			md_ctx.finish(output);

			reset();
		}

		void reset(void)
		{
			uint8_t *ipad = hmac_ctx;

			md_ctx.reset();
			md_ctx.update(ipad, MD::BLOCK_SIZE);
		}

		static const std::size_t SIZE = MD::SIZE;
	protected:
		MD md_ctx;
		uint8_t hmac_ctx[2 * MD::BLOCK_SIZE];

		void zeroize(void *v, std::size_t n)
		{
			volatile uint8_t *p = static_cast<uint8_t*>(v);

			while ( n-- ) {
				*p++ = 0x00;
			}
		}
};


template <class MD>
void HMAC_get(const uint8_t *key, std::size_t key_sz, const uint8_t *input, std::size_t input_sz, uint8_t *output)
{
	static_assert(std::is_base_of<MessageDigest, MD>::value,
			"Template argument should be a MessageDigest");

	HMAC<MD> ctx(key, key_sz);
	ctx.update(input, input_sz);
	ctx.finish(output);
}

}

#endif
