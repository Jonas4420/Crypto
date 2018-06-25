#include "crypto/RSA.hpp"

#include "crypto/ASN1.hpp"

#include <memory>
#include <vector>

namespace Crypto
{

RSA::RSAPublicKey::RSAPublicKey(const BigNum &n, const BigNum &e)
	: n(n), e(e)
{
}

RSA::RSAPublicKey::RSAPublicKey(const uint8_t *data, std::size_t data_sz)
{
	int res;
	std::size_t read_sz;
	std::vector<std::pair<const uint8_t*, std::size_t>> sequence;

	// Read sequence
	res = Crypto::ASN1::read_sequence(data, data_sz, sequence, read_sz);
	if ( ASN1::CRYPTO_ASN1_SUCCESS != res ) { throw RSA::Exception("Bad RSAPublicKey format"); }
	if ( data_sz != read_sz )               { throw RSA::Exception("Bad RSAPublicKey format"); }
	if ( 2 != sequence.size() )             { throw RSA::Exception("Bad RSAPublicKey format"); }

	std::size_t i = 0;
	std::vector<BigNum*> fields = { &n, &e };

	for ( auto field : fields ) {
		res = Crypto::ASN1::read_integer(sequence[i].first, sequence[i].second, *field, read_sz);
		if ( ASN1::CRYPTO_ASN1_SUCCESS != res ) { throw RSA::Exception("Bad RSAPublicKey format"); }

		++i;
	}
}

bool
RSA::RSAPublicKey::operator==(const RSAPublicKey &other) const
{
	return (this->n == other.n) && (this->e == other.e);
}

int
RSA::RSAPublicKey::to_binary(uint8_t *data, std::size_t &data_sz) const
{
	int res;
	std::vector<std::pair<const uint8_t*, std::size_t>> sequence;
	std::vector<std::unique_ptr<uint8_t[]>> fields_data;
	std::size_t field_sz;

	// Make fields
	std::vector<const BigNum*> fields = { &n, &e };
	for ( auto field : fields ) {
		ASN1::write_integer(*field, NULL, 0, field_sz);
		fields_data.push_back(std::unique_ptr<uint8_t[]>(new uint8_t[field_sz]));

		ASN1::write_integer(*field, fields_data.back().get(), field_sz, field_sz);
		sequence.push_back({ fields_data.back().get(), field_sz});
	}

	// Write sequence
	res = ASN1::write_sequence(sequence, data, data_sz, data_sz);
	if ( 0 != res ) { return RSA::CRYPTO_RSA_INVALID_LENGTH; }

	return RSA::CRYPTO_RSA_SUCCESS;
}

bool
RSA::RSAPublicKey::is_valid(void) const
{
	bool is_valid = true;

	is_valid = is_valid && (n > 1) && (0 != n.get_bit(0));
	is_valid = is_valid && (e > 2) && (0 != e.get_bit(0));
	is_valid = is_valid && (e < n);

	return is_valid;
}

std::size_t
RSA::RSAPublicKey::bitlen(void) const
{
	return n.bitlen();
}

std::size_t
RSA::RSAPublicKey::size(void) const
{
	return n.size();
}

RSA::RSAPrivateKey::RSAPrivateKey(const BigNum &e, const BigNum &p, const BigNum &q, bool carmichael)
	: e(e), p(p), q(q)
{
	BigNum p1 = p - 1;
	BigNum q1 = q - 1;

	n  = p * q;
	d  = e.inv(carmichael ? BigNum::lcm(p1, q1) : (p1 * q1));
	dp = d % (p1);
	dq = d % (q1);
	qp = q.inv(p);
}

RSA::RSAPrivateKey::RSAPrivateKey(const BigNum &n, const BigNum &e,
		const BigNum &d, const BigNum &p, const BigNum &q,
		const BigNum &dp, const BigNum &dq, const BigNum &qp)
	: n(n), e(e), d(d), p(p), q(q), dp(dp), dq(dq), qp(qp)
{
}

RSA::RSAPrivateKey::RSAPrivateKey(const uint8_t *data, std::size_t data_sz)
{
	int res;
	std::size_t read_sz;
	std::vector<std::pair<const uint8_t*, std::size_t>> sequence;
	BigNum version;

	// Read sequence
	res = Crypto::ASN1::read_sequence(data, data_sz, sequence, read_sz);
	if ( ASN1::CRYPTO_ASN1_SUCCESS != res ) { throw RSA::Exception("Bad RSAPrivateKey format"); }
	if ( data_sz != read_sz )               { throw RSA::Exception("Bad RSAPrivateKey format"); }
	if ( 0 == sequence.size() )             { throw RSA::Exception("Bad RSAPrivateKey format"); }

	// Get version
	res = Crypto::ASN1::read_integer(sequence[0].first, sequence[0].second, version, read_sz);
	if ( ASN1::CRYPTO_ASN1_SUCCESS != res ) { throw RSA::Exception("Bad RSAPrivateKey format"); }

	// Check that version is 0
	if ( version != 0 )         { throw RSA::Exception("RSAPrivateKey version is not supported"); }
	if ( 9 != sequence.size() ) { throw RSA::Exception("Bad RSAPrivateKey format"); }

	std::size_t i = 1;
	std::vector<BigNum*> fields = { &n, &e, &d, &p, &q, &dp, &dq, &qp };
	for ( auto field : fields ) {
		res = Crypto::ASN1::read_integer(sequence[i].first, sequence[i].second, *field, read_sz);
		if ( ASN1::CRYPTO_ASN1_SUCCESS != res ) { throw RSA::Exception("Bad RSAPrivateKey format"); }

		++i;
	}
}

bool
RSA::RSAPrivateKey::operator==(const RSAPrivateKey &other) const
{
	return (this->n == other.n) && (this->e == other.e)
		&& (this->d == other.d) && (this->p == other.p) && (this->q == other.q)
		&& (this->dp == other.dp) && (this->dq == other.dq) && (this->qp == other.qp);
}

int
RSA::RSAPrivateKey::to_binary(uint8_t *data, std::size_t &data_sz) const
{
	int res;
	std::vector<std::pair<const uint8_t*, std::size_t>> sequence;
	std::vector<std::unique_ptr<uint8_t[]>> fields_data;
	std::size_t field_sz;

	BigNum version(0);

	// Make fields
	std::vector<const BigNum*> fields = { &version, &n, &e, &d, &p, &q, &dp, &dq, &qp };
	for ( auto field : fields ) {
		ASN1::write_integer(*field, NULL, 0, field_sz);
		fields_data.push_back(std::unique_ptr<uint8_t[]>(new uint8_t[field_sz]));

		ASN1::write_integer(*field, fields_data.back().get(), field_sz, field_sz);
		sequence.push_back({ fields_data.back().get(), field_sz});
	}

	// Write sequence
	res = ASN1::write_sequence(sequence, data, data_sz, data_sz);
	if ( 0 != res ) { return RSA::CRYPTO_RSA_INVALID_LENGTH; }

	return RSA::CRYPTO_RSA_SUCCESS;
}

bool
RSA::RSAPrivateKey::is_valid(int (*f_rng)(void *, uint8_t*, std::size_t), void *p_rng) const
{
	bool is_valid = true;

	BigNum p1 = p - 1;
	BigNum q1 = q - 1;

	is_valid = is_valid && (n > 1) && (0 != n.get_bit(0));
	is_valid = is_valid && (e > 1) && (0 != e.get_bit(0)) && (e < n);
	is_valid = is_valid && (p > 1) && (0 != p.get_bit(0));
	is_valid = is_valid && (q > 1) && (0 != q.get_bit(0));
	is_valid = is_valid && (d > 1) && (d < n);
	is_valid = is_valid && (n == p * q);

	if ( NULL != f_rng ) {
		is_valid = is_valid && p.is_prime(f_rng, p_rng);
		is_valid = is_valid && q.is_prime(f_rng, p_rng);
	}

	is_valid = is_valid && (dp > 0) && (dq > 0) && (qp > 0);

	is_valid = is_valid && ((((d * e) - 1)  % (p1)) == 0);
	is_valid = is_valid && ((((d * e) - 1)  % (q1)) == 0);
	is_valid = is_valid && (( (dp - d)      % (p1)) == 0);
	is_valid = is_valid && (( (dq - d)      % (q1)) == 0);
	is_valid = is_valid && ((((qp * q) - 1) %  p  ) == 0);

	return is_valid;
}

std::size_t
RSA::RSAPrivateKey::bitlen(void) const
{
	return n.bitlen();
}

std::size_t
RSA::RSAPrivateKey::size(void) const
{
	return n.size();
}

std::pair<RSA::RSAPublicKey, RSA::RSAPrivateKey>
RSA::gen_keypair(int (*f_rng)(void *, uint8_t*, std::size_t), void *p_rng,
		std::size_t n_bits, const BigNum &e)
{
	BigNum n, p, q;

	if ( (NULL == f_rng)|| (n_bits < 128) || (0 != (n_bits % 2)) || (e < 3) ) {
		throw RSA::Exception("Invalid key pair parameters");
	}

	do {
		p = BigNum::gen_prime(n_bits >> 1, f_rng, p_rng, false);
		q = BigNum::gen_prime(n_bits >> 1, f_rng, p_rng, false);
		p.safe_cond_swap(q, p < q);

		n = p * q;
	} while ( (p == q) || (n_bits != n.bitlen()) || BigNum::gcd(e, (p - 1) * (q - 1)) != 1 );

	RSAPublicKey pubKey(n, e);
	RSAPrivateKey privKey(e, p, q);

	return { pubKey, privKey };
}

bool
RSA::is_valid(const std::pair<const RSA::RSAPublicKey&, const RSA::RSAPrivateKey&> &keyPair,
		int (*f_rng)(void *, uint8_t*, std::size_t), void *p_rng)
{
	bool is_valid = true;

	is_valid = is_valid && keyPair.first.is_valid();
	is_valid = is_valid && keyPair.second.is_valid(f_rng, p_rng);
	is_valid = is_valid && (keyPair.first.n == keyPair.second.n);
	is_valid = is_valid && (keyPair.first.e == keyPair.second.e);

	return is_valid;
}

int
RSA::Encrypt(const RSA::RSAPublicKey &pubKey, const uint8_t *input, std::size_t input_sz,
		uint8_t *output, std::size_t &output_sz)
{
	std::size_t key_sz = pubKey.size();
	BigNum m(input, input_sz);

	if ( m >= pubKey.n ) {
		return CRYPTO_RSA_OUT_OF_RANGE;
	}

	if ( output_sz < key_sz ) {
		output_sz = key_sz;
		return CRYPTO_RSA_INVALID_LENGTH;
	}

	BigNum c = m.exp_mod(pubKey.e, pubKey.n);

	// Padding on key size's length
	// TODO: check sizes
	memset(output, 0x00, key_sz);
	output += (key_sz - c.size());

	c.to_binary(output, output_sz);
	output_sz = key_sz;

	return CRYPTO_RSA_SUCCESS;
}

int
RSA::Decrypt(const RSA::RSAPrivateKey &privKey, const uint8_t *input, std::size_t input_sz,
		uint8_t *output, std::size_t &output_sz)
{
	std::size_t key_sz = privKey.size();
	BigNum c(input, input_sz);

	if ( c >= privKey.n ) {
		return CRYPTO_RSA_OUT_OF_RANGE;
	}

	if ( output_sz < key_sz ) {
		output_sz = key_sz;
		return CRYPTO_RSA_INVALID_LENGTH;
	}

	BigNum m1 = c.exp_mod(privKey.dp, privKey.p);
	BigNum m2 = c.exp_mod(privKey.dq, privKey.q);
	BigNum h  = ((m1 - m2) * privKey.qp) % privKey.p;
	BigNum m  = m2 + (privKey.q * h);

	// Padding on key size's length
	// TODO: check sizes
	memset(output, 0x00, key_sz);
	output += (key_sz - m.size());

	m.to_binary(output, output_sz);
	output_sz = key_sz;

	return CRYPTO_RSA_SUCCESS;
}

}
