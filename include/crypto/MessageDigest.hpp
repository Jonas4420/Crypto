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
		virtual void update(const uint8_t*, std::size_t) = 0;
		virtual void finish(uint8_t*) = 0;
};


template <typename T, typename = std::enable_if<std::is_base_of<MessageDigest, T>::value>>
static void getMessageDigest(const uint8_t *input, std::size_t input_sz, uint8_t *output)
{
	T ctx;
	ctx.update(input, input_sz);
	ctx.finish(output);
}

}

#endif
