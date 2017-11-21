#ifndef CRYPTO_HMAC_H
#define CRYPTO_HMAC_H

#include "crypto/MessageDigest.hpp"
#include "crypto/Utils.hpp"

namespace Crypto
{

template <class MD>
class HMAC final
{
	public:
		HMAC(const uint8_t *key, std::size_t key_sz)
		{
			uint8_t K0[MD::BLOCK_SIZE];
			uint8_t *ipad, *opad;

			Utils::zeroize(K0, MD::BLOCK_SIZE);

			if ( key_sz > MD::BLOCK_SIZE ) {
				md_ctx.update(key, key_sz);
				md_ctx.finish(K0);
				md_ctx = MD();
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

			Utils::zeroize(K0, sizeof(K0));

			md_ctx.update(ipad, MD::BLOCK_SIZE);
		}

		~HMAC(void)
		{
			Utils::zeroize(hmac_ctx, sizeof(hmac_ctx));
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

			md_ctx = MD();
			md_ctx.update(opad, MD::BLOCK_SIZE);
			md_ctx.update(tmp,  MD::SIZE);
			md_ctx.finish(output);
		}

		void reset(void)
		{
			uint8_t *ipad = hmac_ctx;

			md_ctx = MD();
			md_ctx.update(ipad, MD::BLOCK_SIZE);
		}

		static const std::size_t SIZE = MD::SIZE;
	private:
		MD md_ctx;
		uint8_t hmac_ctx[2 * MD::BLOCK_SIZE];
};

template <typename MD, typename = std::enable_if<std::is_base_of<MessageDigest, MD>::value>>
void getHMAC(const uint8_t *key, std::size_t key_sz, const uint8_t *input, std::size_t input_sz, uint8_t *output)
{
	HMAC<MD> ctx(key, key_sz);
	ctx.update(input, input_sz);
	ctx.finish(output);
}

}

#endif
