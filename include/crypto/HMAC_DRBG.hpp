#ifndef CRYPTO_HMAC_DRBG_H
#define CRYPTO_HMAC_DRBG_H

#include <memory>

#include "crypto/HMAC.hpp"
#include "crypto/Utils.hpp"

namespace Crypto
{

template <class MD>
class HMAC_DRBG final
{
	public:
		HMAC_DRBG(const uint8_t *entropy, std::size_t entropy_sz,
				const uint8_t *nonce = NULL, std::size_t nonce_sz = 0,
				const uint8_t *perso = NULL, std::size_t perso_sz = 0,
				bool prediction_resistance = false)
		{
			// Check inputs
			security_strength = MD::SIZE <= 20 ? 16 : (MD::SIZE <= 28 ? 24 : 32);

			if ( NULL == entropy || entropy_sz < security_strength ) {
				throw HMAC_DRBG::Exception("Not enough entropy provided");
			}

			if ( entropy_sz > MAX_LENGTH ) {
				throw HMAC_DRBG::Exception("Entropy failure");
			}

			if ( perso_sz > MAX_PERSONALIZATION_STRING_LENGTH ) {
				throw HMAC_DRBG::Exception("Personalization string length is too big");
			}

			// Set reseed interval
			reseed_counter  = prediction_resistance ? 1 : 0;
			reseed_interval = prediction_resistance ? 1 : RESEED_INTERVAL;

			// Initialize current state
			memset(K, 0x00, sizeof(K));
			memset(V, 0x01, sizeof(V));

			// Create seed
			std::size_t seed_sz = 0;
			seed_sz += (NULL != entropy && 0 != entropy_sz) ? entropy_sz : 0;
			seed_sz += (NULL != nonce   && 0 != nonce_sz)   ? nonce_sz   : 0;
			seed_sz += (NULL != perso   && 0 != perso_sz)   ? perso_sz   : 0;

			std::unique_ptr<uint8_t[]> seed{new uint8_t[seed_sz]};
			std::size_t seed_offset = 0;

			if ( NULL != entropy && 0 != entropy_sz ) {
				memcpy(seed.get() + seed_offset, entropy, entropy_sz);
				seed_offset += entropy_sz;
			}
			if ( NULL != nonce   && 0 != nonce_sz ) {
				memcpy(seed.get() + seed_offset, nonce, nonce_sz);
				seed_offset += nonce_sz;
			}
			if ( NULL != perso && 0 != perso_sz ) {
				memcpy(seed.get() + seed_offset, perso, perso_sz);
				seed_offset += perso_sz;
			}

			// Update state of DRBG
			update(seed.get(), seed_sz);
		}
		
		~HMAC_DRBG(void)
		{
			Utils::zeroize(V, sizeof(V));
			Utils::zeroize(K, sizeof(K));
		}

		void reseed(const uint8_t *entropy, std::size_t entropy_sz,
				const uint8_t *add = NULL, std::size_t add_sz = 0)
		{
			// Check inputs
			if ( NULL == entropy || entropy_sz < security_strength ) {
				throw HMAC_DRBG::Exception("Not enough entropy provided");
			}

			if ( entropy_sz > MAX_LENGTH ) {
				throw HMAC_DRBG::Exception("Entropy failure");
			}

			if ( add_sz > MAX_ADDITIONAL_INPUT_LENGTH ) {
				throw HMAC_DRBG::Exception("Additional input length is too big");
			}

			std::size_t seed_sz = 0;
			seed_sz += entropy_sz;
			seed_sz += (NULL != add && 0 != add_sz) ? add_sz : 0;

			std::unique_ptr<uint8_t[]> seed{new uint8_t[seed_sz]};

			memcpy(seed.get(), entropy, entropy_sz);
			if ( NULL != add && 0 != add_sz ) {
				memcpy(seed.get() + entropy_sz, add, add_sz);
			}

			update(seed.get(), seed_sz);
			reseed_counter = 0;
		}

		int generate(uint8_t *output, std::size_t output_sz,
				const uint8_t *additional_input = NULL, std::size_t additional_input_sz = 0)
		{
			std::size_t temp_sz;

			if ( reseed_counter >= reseed_interval ) {
				return CRYPTO_HMAC_DRBG_RESEED_REQUIRED;
			}

			if ( output_sz > MAX_NUMBER_OF_BYTES_PER_REQUEST ) {
				throw HMAC_DRBG::Exception("Requested number of bytes is too big");
			}

			if ( NULL != additional_input && 0 != additional_input_sz ) {
				update(additional_input, additional_input_sz);
			}

			while ( 0 != output_sz ) {
				HMAC<MD> ctx(K, sizeof(K));
				ctx.update(V,   sizeof(V));
				ctx.finish(V);

				temp_sz = output_sz < sizeof(V) ? output_sz : sizeof(V);

				memcpy(output, V, temp_sz);
				output    += temp_sz;
				output_sz -= temp_sz;
			}

			update(additional_input, additional_input_sz);
			reseed_counter = reseed_counter + 1;

			return CRYPTO_HMAC_DRBG_SUCCESS;
		}

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const uint8_t CRYPTO_HMAC_DRBG_SUCCESS         = 0x00;
		static const uint8_t CRYPTO_HMAC_DRBG_RESEED_REQUIRED = 0x01;
	private:
		std::size_t security_strength;
		uint8_t     V[MD::SIZE];
		uint8_t     K[MD::SIZE];
		uint64_t    reseed_counter;
		uint64_t    reseed_interval;

		void update(const uint8_t *data, std::size_t data_sz)
		{
			uint8_t round = (NULL == data || 0 == data_sz) ? 1 : 2 ;

			for ( uint8_t sep = 0 ; sep < round ; ++sep ) {
				HMAC<MD> ctx_1(K,  sizeof(K));
				ctx_1.update(V,    sizeof(V));
				ctx_1.update(&sep, sizeof(sep));
				ctx_1.update(data, data_sz);
				ctx_1.finish(K);

				HMAC<MD> ctx_2(K, sizeof(K));
				ctx_2.update(V,   sizeof(V));
				ctx_2.finish(V);
			}
		}

		static const std::size_t MAX_LENGTH                        = ((std::size_t)1) << 32;
		static const std::size_t MAX_PERSONALIZATION_STRING_LENGTH = ((std::size_t)1) << 32;
		static const std::size_t MAX_ADDITIONAL_INPUT_LENGTH       = ((std::size_t)1) << 32;
		static const std::size_t MAX_NUMBER_OF_BYTES_PER_REQUEST   = ((std::size_t)1) << 16;
		static const uint64_t    RESEED_INTERVAL                   = ((std::size_t)1) << 48;
};

}

#endif
