#include "crypto/ECDomainParameters.hpp"

namespace Crypto
{

ECPrivateKey::ECPrivateKey(const BigNum &privateKey,
		const ECDomainParameters *parameters,
		const SubjectPublicKeyInfo *publicKey)
{
	((void)privateKey);
	((void)parameters);
	((void)publicKey);
	// TODO
}

ECPrivateKey::ECPrivateKey(const uint8_t *data, std::size_t data_sz)
{
	((void)data);
	((void)data_sz);
	// TODO
}

ECPrivateKey::ECPrivateKey(const ECPrivateKey &other)
{
	((void)other);
	// TODO
}

ECPrivateKey&
ECPrivateKey::operator=(const ECPrivateKey &other)
{
	((void)other);
	// TODO
	return *this;
}

ECPrivateKey::~ECPrivateKey(void)
{
	// TODO
}

const BigNum&
ECPrivateKey::getPrivateKey(void) const
{
	return privateKey;
}

int
ECPrivateKey::to_binary(const ECDomainParameters &parameters,
		uint8_t *data, std::size_t &data_sz, bool write_all_infos) const
{
	((void)parameters);
	((void)data);
	((void)data_sz);
	((void)write_all_infos);
	// TODO
	return 0;
}

SubjectPublicKeyInfo::SubjectPublicKeyInfo(const ECPoint &subjectPublicKey)
{
	((void)subjectPublicKey);
	// TODO
}

SubjectPublicKeyInfo::SubjectPublicKeyInfo(const ECDomainParameters &parameters, const uint8_t *data, std::size_t data_sz)
{
	((void)parameters);
	((void)data);
	((void)data_sz);
	// TODO
}

SubjectPublicKeyInfo::SubjectPublicKeyInfo(const SubjectPublicKeyInfo &other)
{
	((void)other);
	// TODO
}

SubjectPublicKeyInfo&
SubjectPublicKeyInfo::operator=(const SubjectPublicKeyInfo &other)
{
	((void)other);
	// TODO
	return *this;
}

SubjectPublicKeyInfo::~SubjectPublicKeyInfo(void)
{
	// TODO
}

const ECPoint&
SubjectPublicKeyInfo::getSubjectPublicKey(void) const
{
	if ( NULL == subjectPublicKey ) {
		throw SubjectPublicKeyInfo::Exception("No Public Key available");
	}

	return *subjectPublicKey;
}

int
SubjectPublicKeyInfo::to_binary(const ECDomainParameters &parameters, uint8_t *data, std::size_t &data_sz, bool compress) const
{
	((void)parameters);
	((void)data);
	((void)data_sz);
	((void)compress);
	// TODO
	return 0;
}

ECDomainParameters::ECDomainParameters(const ECCurve &curve, const ECPoint &base, const BigNum &order, const BigNum &cofactor)
{
	((void)curve);
	((void)base);
	((void)order);
	((void)cofactor);
	// TODO
}

ECDomainParameters::ECDomainParameters(const uint8_t *data, std::size_t data_sz)
{
	((void)data);
	((void)data_sz);
	// TODO
}

ECDomainParameters::ECDomainParameters(const ECDomainParameters &other)
{
	((void)other);
	// TODO
}

ECDomainParameters&
ECDomainParameters::operator=(const ECDomainParameters &other)
{
	((void)other);
	// TODO
}

ECDomainParameters::~ECDomainParameters(void)
{
	// TODO
}

std::vector<std::string>
ECDomainParameters::getECDomainParametersList(void)
{
	// TODO
}

ECDomainParameters
ECDomainParameters::getECDomainParametersByCurveName(std::string curve_name)
{
	((void)curve_name);
	// TODO
}

std::pair<ECPrivateKey, SubjectPublicKeyInfo>
ECDomainParameters::generateKeyPair(int (*f_rng)(void *, uint8_t*, std::size_t), void *p_rng) const
{
	((void)f_rng);
	((void)p_rng);
	// TODO
}

SubjectPublicKeyInfo
ECDomainParameters::makeSubjectPublicKeyInfo(const ECPrivateKey &privateKey) const
{
	((void)privateKey);
	// TODO
}

SubjectPublicKeyInfo
ECDomainParameters::loadSubjectPublicKeyInfo(uint8_t *data, std::size_t data_sz) const
{
	((void)data);
	((void)data_sz);
	// TODO
}

bool
ECDomainParameters::isValidKeyPair(const ECPrivateKey &privateKey, const SubjectPublicKeyInfo &publicKey)
{
	((void)privateKey);
	((void)publicKey);
	// TODO
}

bool
ECDomainParameters::isValidECPrivateKey(const ECPrivateKey &privateKey) const
{
	((void)privateKey);
	// TODO
}

bool
ECDomainParameters::isValidSubjectPublicKeyInfo(const ECPrivateKey &privateKey) const
{
	((void)privateKey);
	// TODO
}

std::string
ECDomainParameters::getCurveName(void) const
{
	return curve_name;
}

const ECCurve*
ECDomainParameters::getCurve(void) const
{
	return curve;
}

const ECPoint*
ECDomainParameters::getBase(void) const
{
	return base;
}

const BigNum&
ECDomainParameters::getOrder(void) const
{
	return order;
}

const BigNum&
ECDomainParameters::getCofactor(void) const
{
	return cofactor;
}

int
ECDomainParameters::to_binary(uint8_t *data, std::size_t &data_sz, bool write_curve_name, bool compress) const
{
	((void)data);
	((void)data_sz);
	((void)write_curve_name);
	((void)compress);
	// TODO
}

}
