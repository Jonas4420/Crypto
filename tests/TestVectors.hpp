#ifndef TESTVECTORS_H
#define TESTVECTORS_H

#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

class TestPair
{
	public:
		TestPair(std::string str)
		{
			std::size_t pos;

			if ( std::string::npos != (pos = str.find(" = ")) ) {
				key   = str.substr(0, pos);
				value = str.substr(pos + 3);
			} else {
				key = str;
			}
		}

		std::string key;
		std::string value;
};

class TestCase : public std::vector<TestPair>
{
	public:
		std::string operator [](std::string key)
		{
			std::size_t pos, idx = 0;

			if ( std::string::npos != (pos = key.find(":")) ) {
				idx = atoi(key.substr(pos + 1).c_str());
				key = key.substr(0, pos);
			}	

			for ( auto pair : *this ) {
				if ( pair.key == key ) {
					if ( idx == 0 ) {
						return pair.value;
					} else {
						--idx;
					}
				}
			}

			return "";
		}
};

class TestVector
{
	public:
		std::vector<TestCase>::iterator begin() { return test_cases.begin(); }
		std::vector<TestCase>::iterator end()   { return test_cases.end(); }

		std::string name;
		std::vector<TestPair> options;
		std::vector<TestCase> test_cases;
};

class TestVectors
{
	public:
		TestVectors operator [](std::string name)
		{
			TestVectors result;

			for ( auto vec : vectors ) {
				if ( vec.name == name ) {
					result.vectors.push_back(vec);
				}
			}

			return result;
		}

		std::vector<TestVector>::iterator begin() { return vectors.begin(); }
		std::vector<TestVector>::iterator end()   { return vectors.end(); }

		bool empty(void) { return vectors.empty(); }

		static TestVectors NISTParser(std::string file_path)
		{
			TestVectors result;
			TestCase test_case;
			std::string line;

			std::ifstream ifs(file_path);
			State state = State::HEADER;

			while ( std::getline(ifs, line) ) {
				trim_line(line);

				// Skip comments
				if ( starts_with(line, "#") ) { continue; }

				bool line_processed = false;
				while ( ! line_processed ) {
					switch ( state ) {
						case State::HEADER:
							if ( starts_with(line, "[") && ends_with(line, "]") ) {
								state = State::VECTORS;
							} else {
								line_processed = true;
							}

							break;
						case State::VECTORS:
							result.vectors.push_back(TestVector());
							result.vectors.back().name = line.substr(1, line.size() - 2);

							state = State::OPTIONS;
							line_processed = true;

							break;
						case State::OPTIONS:
							if ( starts_with(line, "[") && ends_with(line, "]") ) {
								line = line.substr(1, line.size() - 2);
								result.vectors.back().options.push_back(TestPair(line));

								line_processed = true;
							} else {
								state = State::TESTS;
							}
							break;
						case State::TESTS:
							if ( starts_with(line, "[") && ends_with(line, "]") ) {
								state = State::VECTORS;
							} else if ( line.empty() ) {
								if ( ! test_case.empty() ) {
									result.vectors.back().test_cases.push_back(test_case);
									test_case = TestCase();
								}

								line_processed = true;
							} else {
								test_case.push_back(TestPair(line));

								line_processed = true;
							}
							break;
						default:
							break;

					}
				}
			}

			return result;
		}

		std::vector<TestVector> vectors;
	private:
		enum class State { HEADER, VECTORS, OPTIONS, TESTS };

		static void trim_line(std::string &str)
		{
			bool trimmed = false;
			std::size_t trim_sz = str.size();

			while ( trim_sz > 0 && ! trimmed ) {
				char c = str[trim_sz - 1];

				switch ( c ) {
					case ' ':
					case '\n':
					case '\r':
					case '\t':
						trim_sz -= 1;
						break;
					default:
						trimmed = true;
						break;
				}
			}

			str = str.substr(0, trim_sz);
		}

		static bool starts_with(std::string str, std::string prefix)
		{
			return 0 == str.compare(0, prefix.size(), prefix);
		}

		static bool ends_with(std::string str, std::string suffix)
		{
			std::reverse(str.begin(),    str.end());
			std::reverse(suffix.begin(), suffix.end());

			return starts_with(str, suffix);
		}
};

#endif
