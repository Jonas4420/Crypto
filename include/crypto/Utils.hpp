#include <string>
#include <vector>

namespace Crypto
{
	class Utils
	{
		public:
			void static zeroize(void *v, std::size_t n);

			void static from_string(const std::string, uint8_t*, std::size_t&);
			void static to_string(const uint8_t*, std::size_t, std::string&);

			void static from_hex(const std::string, uint8_t*, std::size_t&);
			void static to_hex(const uint8_t*, std::size_t, std::string&, bool=true);
	};

	class CryptoException : public std::runtime_error
	{
		public:
			CryptoException(const char *what_arg) : std::runtime_error(what_arg) {}
	};

}
