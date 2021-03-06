#ifndef CRYPTO_MESSAGEDIGEST_H
#define CRYPTO_MESSAGEDIGEST_H

#include <type_traits>

#include <cstddef>
#include <cstdint>

namespace Crypto
{

class MessageDigest
{
	public:
		virtual ~MessageDigest(void) = default;

		virtual void update(const uint8_t*, std::size_t) = 0;
		virtual void finish(uint8_t*)                    = 0;
		virtual void reset(void)                         = 0;
	protected:
		void zeroize(void *v, std::size_t n)
		{
			volatile uint8_t *p = static_cast<uint8_t*>(v);

			while ( n-- ) {
				*p++ = 0x00;
			}
		}
};

template <class MD>
static void MessageDigest_get(const uint8_t *input, std::size_t input_sz, uint8_t *output)
{
	static_assert(std::is_base_of<MessageDigest, MD>::value,
			"Template argument should be a MessageDigest");

	MD ctx;
	ctx.update(input, input_sz);
	ctx.finish(output);
}

}

#endif
