#ifndef TESTOPTIONS_H
#define TESTOPTIONS_H

#include <string>

#include <cstdlib>

class TestOptions
{
	public:
		static TestOptions& get() {
			static TestOptions instance;
			return instance;
		}

		bool        is_fast;
		std::string vect_dir; 
	private:
		TestOptions(void) 
		{ 
			const char *env_fast     = std::getenv("CRYPTO_TEST_IS_FAST");
			const char *env_vect_dir = std::getenv("CRYPTO_TEST_VECT_DIR");

			is_fast   = env_fast     ? atoi(env_fast) : false;
			vect_dir  = env_vect_dir ? env_vect_dir   : ".";
			vect_dir += "/";
		}

		~TestOptions(void) { }

		TestOptions(const TestOptions&)            = delete;
		TestOptions(TestOptions&&)                 = delete;
		TestOptions& operator=(const TestOptions&) = delete;
		TestOptions& operator=(TestOptions&&)      = delete;
};

#endif
