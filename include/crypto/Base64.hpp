#include <string>
#include <vector>

namespace Crypto
{

class Base64
{
	public:
		static std::string encode(const std::vector<uint8_t>&);
		static std::vector<uint8_t> decode(const std::string);

	private:
		static const char    encode_map[64];
		static const char    pad;

		static const uint8_t decode_map[128];
};

class Base64Exception : public std::runtime_error
{
	public:
		Base64Exception(const char *what_arg) : std::runtime_error(what_arg) {}
};

}
