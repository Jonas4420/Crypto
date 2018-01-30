#ifndef CRYPTO_ECDOMAINPARAMETERS_H
#define CRYPTO_ECDOMAINPARAMETERS_H

#include "crypto/BigNum.hpp"
#include "crypto/ECCurve.hpp"

#include <stdexcept>

#include <string>
#include <utility>
#include <vector>

#include <cstring>

namespace Crypto
{

class ECPrivateKey;
class SubjectPublicKeyInfo;
class ECDomainParameters;

class ECPrivateKey
{
	public:
		/* Constructors and destructor */
		ECPrivateKey(const BigNum&, const ECDomainParameters* = NULL, const SubjectPublicKeyInfo* = NULL);
		ECPrivateKey(const uint8_t*, std::size_t);
		ECPrivateKey(const ECPrivateKey&);
		ECPrivateKey& operator=(const ECPrivateKey&);

		~ECPrivateKey(void);

		/* Getter */
		const BigNum& getPrivateKey(void) const;

		/* Dump function */
		int to_binary(const ECDomainParameters&, uint8_t*, std::size_t&, bool = true) const;

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};
	private:
		BigNum                privateKey;
		ECDomainParameters   *parameters;
		SubjectPublicKeyInfo *publicKey;
};

class SubjectPublicKeyInfo
{
	public:
		/* Constructors and destructor */
		SubjectPublicKeyInfo(const ECPoint&);
		SubjectPublicKeyInfo(const ECDomainParameters&, const uint8_t*, std::size_t);
		SubjectPublicKeyInfo(const SubjectPublicKeyInfo&);
		SubjectPublicKeyInfo& operator=(const SubjectPublicKeyInfo&);

		~SubjectPublicKeyInfo(void);

		/* Getter */
		const ECPoint& getSubjectPublicKey(void) const;

		/* Dump function */
		int to_binary(const ECDomainParameters&, uint8_t*, std::size_t&, bool = false) const;

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};
	private:
		ECPoint *subjectPublicKey;
};

class ECDomainParameters
{
	public:
		/* Constructors and destructor */
		ECDomainParameters(const ECCurve&, const ECPoint&, const BigNum&, const BigNum& = BigNum(0));
		ECDomainParameters(const uint8_t*, std::size_t);
		ECDomainParameters(const ECDomainParameters&);
		ECDomainParameters& operator=(const ECDomainParameters&);

		~ECDomainParameters(void);

		/* Get by OID */
		static std::vector<std::string> getECDomainParametersList(void);
		static ECDomainParameters getECDomainParametersByCurveName(std::string);

		/* Key management */
		std::pair<ECPrivateKey, SubjectPublicKeyInfo> generateKeyPair(int (*)(void *, uint8_t*, std::size_t), void*) const;
		SubjectPublicKeyInfo makeSubjectPublicKeyInfo(const ECPrivateKey&) const;
		SubjectPublicKeyInfo loadSubjectPublicKeyInfo(uint8_t*, std::size_t) const;
		bool isValidKeyPair(const ECPrivateKey&, const SubjectPublicKeyInfo&);
		bool isValidECPrivateKey(const ECPrivateKey&) const;
		bool isValidSubjectPublicKeyInfo(const ECPrivateKey&) const;

		/* Getters */
		std::string getCurveName(void) const;
		const ECCurve* getCurve(void) const;
		const ECPoint* getBase(void) const;
		const BigNum& getOrder(void) const;
		const BigNum& getCofactor(void) const;

		/* Dump functions */
		int to_binary(uint8_t*, std::size_t&, bool = false, bool = true) const;

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};
	protected:
		std::string curve_name;
		ECCurve    *curve;
		ECPoint    *base;
		BigNum      order;
		BigNum      cofactor;
};

}

#endif
