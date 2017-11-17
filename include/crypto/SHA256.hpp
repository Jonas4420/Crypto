#include <vector>

namespace Crypto
{

class SHA256
{
	public:
		SHA256(void);
		~SHA256(void);

		void starts(bool);
		void update(const uint8_t*, std::size_t);
		void finish(unsigned char[32]);

		static void digest(const uint8_t*, std::size_t, uint8_t[32], bool=false);
	private:
		uint32_t total[2];
		uint32_t state[8];
		uint8_t  buffer[64];
		bool     is224;

		void process(const uint8_t[64]);
		static const uint8_t  padding[64];
		static const uint32_t K[64];

};

}
