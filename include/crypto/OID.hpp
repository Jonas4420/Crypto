#ifndef CRYPTO_OID_H
#define CRYPTO_OID_H

#include "crypto/MD5.hpp"
#include "crypto/RIPEMD160.hpp"
#include "crypto/SHA1.hpp"
#include "crypto/SHA224.hpp"
#include "crypto/SHA256.hpp"
#include "crypto/SHA384.hpp"
#include "crypto/SHA512.hpp"
#include "crypto/SHA3.hpp"

#include <stdexcept>

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <cstddef>
#include <cstdint>

namespace Crypto
{

class OID
{
	public:
		/* Constructors and destructors */
		OID(void);
		OID(uint32_t);
		OID(const uint8_t*, std::size_t);
		OID(const OID&);
		OID& operator=(const OID&);

		/* Node operators */
		OID operator+(uint32_t) const;
		OID& operator+=(uint32_t);

		/* Comparison operators */
		bool operator==(const OID&) const;
		bool operator!=(const OID&) const;
		bool operator<(const OID&) const;

		/* Cast and dump functions */
		std::size_t size(void) const;
		uint32_t operator[](std::size_t) const;
		std::string to_string(void) const;
		int to_binary(uint8_t*, std::size_t&) const;

		/* Access common OID by name (directly from Crypto++) */
#define DEFINE_OID(value, name)	static inline OID name() {return value;}
		DEFINE_OID(1, iso)
			DEFINE_OID(iso()+2, member_body)
				DEFINE_OID(member_body()+840, iso_us)
					DEFINE_OID(iso_us()+10040, ansi_x9_57)
						DEFINE_OID(ansi_x9_57()+4+1, id_dsa)
					DEFINE_OID(iso_us()+10045, ansi_x9_62)
						DEFINE_OID(ansi_x9_62()+1, id_fieldType)
							DEFINE_OID(id_fieldType()+1, prime_field)
							DEFINE_OID(id_fieldType()+2, characteristic_two_field)
								DEFINE_OID(characteristic_two_field()+3, id_characteristic_two_basis)
									DEFINE_OID(id_characteristic_two_basis()+1, gnBasis)
									DEFINE_OID(id_characteristic_two_basis()+2, tpBasis)
									DEFINE_OID(id_characteristic_two_basis()+3, ppBasis)
						DEFINE_OID(ansi_x9_62()+2, id_publicKeyType)
							DEFINE_OID(id_publicKeyType()+1, id_ecPublicKey)
						DEFINE_OID(ansi_x9_62()+3, ansi_x9_62_curves)
							DEFINE_OID(ansi_x9_62_curves()+1, ansi_x9_62_curves_prime)
								DEFINE_OID(ansi_x9_62_curves_prime()+1, secp192r1)
								DEFINE_OID(ansi_x9_62_curves_prime()+7, secp256r1)
					DEFINE_OID(iso_us()+113549, rsadsi)
						DEFINE_OID(rsadsi()+1, pkcs)
							DEFINE_OID(pkcs()+1, pkcs_1)
								DEFINE_OID(pkcs_1()+1, rsaEncryption);
						DEFINE_OID(rsadsi()+2, rsadsi_digestAlgorithm)
							DEFINE_OID(rsadsi_digestAlgorithm()+2, id_md2)
							DEFINE_OID(rsadsi_digestAlgorithm()+5, id_md5)
			DEFINE_OID(iso()+3, identified_organization)
				// Arc from http://tools.ietf.org/html/draft-josefsson-pkix-newcurves
				DEFINE_OID(identified_organization()+6, dod)
					DEFINE_OID(dod()+1, internet)
						DEFINE_OID(internet()+4, internet_private)
							DEFINE_OID(internet_private()+1, enterprise)
								DEFINE_OID(enterprise()+11591,GNU)
									DEFINE_OID(GNU()+15,ellipticCurve)
										DEFINE_OID(ellipticCurve()+1,id_curve25519)
										DEFINE_OID(ellipticCurve()+2,id_curve448)
										DEFINE_OID(ellipticCurve()+3,id_curve25519ph)
										DEFINE_OID(ellipticCurve()+4,id_curve448ph)
				DEFINE_OID(identified_organization()+14, oiw);
					DEFINE_OID(oiw()+3, oiw_secsig);
						DEFINE_OID(oiw_secsig()+2, oiw_secsig_algorithms);
							DEFINE_OID(oiw_secsig_algorithms()+26, id_sha1);
				DEFINE_OID(identified_organization()+36, teletrust);
					DEFINE_OID(teletrust()+3, teletrust_algorithm)
						DEFINE_OID(teletrust_algorithm()+2+1, id_ripemd160)
						DEFINE_OID(teletrust_algorithm()+3+2+8+1, teletrust_ellipticCurve)
							DEFINE_OID(teletrust_ellipticCurve()+1+1, brainpoolP160r1)
							DEFINE_OID(teletrust_ellipticCurve()+1+3, brainpoolP192r1)
							DEFINE_OID(teletrust_ellipticCurve()+1+5, brainpoolP224r1)
							DEFINE_OID(teletrust_ellipticCurve()+1+7, brainpoolP256r1)
							DEFINE_OID(teletrust_ellipticCurve()+1+9, brainpoolP320r1)
							DEFINE_OID(teletrust_ellipticCurve()+1+11, brainpoolP384r1)
							DEFINE_OID(teletrust_ellipticCurve()+1+13, brainpoolP512r1)
				DEFINE_OID(identified_organization()+132, certicom);
					DEFINE_OID(certicom()+0, certicom_ellipticCurve);
						// these are sorted by curve type and then by OID
						// first curves based on GF(p)
						DEFINE_OID(certicom_ellipticCurve()+6, secp112r1);
						DEFINE_OID(certicom_ellipticCurve()+7, secp112r2);
						DEFINE_OID(certicom_ellipticCurve()+8, secp160r1);
						DEFINE_OID(certicom_ellipticCurve()+9, secp160k1);
						DEFINE_OID(certicom_ellipticCurve()+10, secp256k1);
						DEFINE_OID(certicom_ellipticCurve()+28, secp128r1);
						DEFINE_OID(certicom_ellipticCurve()+29, secp128r2);
						DEFINE_OID(certicom_ellipticCurve()+30, secp160r2);
						DEFINE_OID(certicom_ellipticCurve()+31, secp192k1);
						DEFINE_OID(certicom_ellipticCurve()+32, secp224k1);
						DEFINE_OID(certicom_ellipticCurve()+33, secp224r1);
						DEFINE_OID(certicom_ellipticCurve()+34, secp384r1);
						DEFINE_OID(certicom_ellipticCurve()+35, secp521r1);
						// then curves based on GF(2^n)
						DEFINE_OID(certicom_ellipticCurve()+1, sect163k1);
						DEFINE_OID(certicom_ellipticCurve()+2, sect163r1);
						DEFINE_OID(certicom_ellipticCurve()+3, sect239k1);
						DEFINE_OID(certicom_ellipticCurve()+4, sect113r1);
						DEFINE_OID(certicom_ellipticCurve()+5, sect113r2);
						DEFINE_OID(certicom_ellipticCurve()+15, sect163r2);
						DEFINE_OID(certicom_ellipticCurve()+16, sect283k1);
						DEFINE_OID(certicom_ellipticCurve()+17, sect283r1);
						DEFINE_OID(certicom_ellipticCurve()+22, sect131r1);
						DEFINE_OID(certicom_ellipticCurve()+23, sect131r2);
						DEFINE_OID(certicom_ellipticCurve()+24, sect193r1);
						DEFINE_OID(certicom_ellipticCurve()+25, sect193r2);
						DEFINE_OID(certicom_ellipticCurve()+26, sect233k1);
						DEFINE_OID(certicom_ellipticCurve()+27, sect233r1);
						DEFINE_OID(certicom_ellipticCurve()+36, sect409k1);
						DEFINE_OID(certicom_ellipticCurve()+37, sect409r1);
						DEFINE_OID(certicom_ellipticCurve()+38, sect571k1);
						DEFINE_OID(certicom_ellipticCurve()+39, sect571r1);
		DEFINE_OID(2, joint_iso_ccitt)
			DEFINE_OID(joint_iso_ccitt()+16, country)
				DEFINE_OID(country()+840, joint_iso_ccitt_us)
					DEFINE_OID(joint_iso_ccitt_us()+1, us_organization)
						DEFINE_OID(us_organization()+101, us_gov)
							DEFINE_OID(us_gov()+3, csor)
								DEFINE_OID(csor()+4, nistalgorithms)
									DEFINE_OID(nistalgorithms()+1, aes)
										DEFINE_OID(aes()+1, id_aes128_ECB)
										DEFINE_OID(aes()+2, id_aes128_cbc)
										DEFINE_OID(aes()+3, id_aes128_ofb)
										DEFINE_OID(aes()+4, id_aes128_cfb)
										DEFINE_OID(aes()+21, id_aes192_ECB)
										DEFINE_OID(aes()+22, id_aes192_cbc)
										DEFINE_OID(aes()+23, id_aes192_ofb)
										DEFINE_OID(aes()+24, id_aes192_cfb)
										DEFINE_OID(aes()+41, id_aes256_ECB)
										DEFINE_OID(aes()+42, id_aes256_cbc)
										DEFINE_OID(aes()+43, id_aes256_ofb)
										DEFINE_OID(aes()+44, id_aes256_cfb)
									DEFINE_OID(nistalgorithms()+2, nist_hashalgs)
										DEFINE_OID(nist_hashalgs()+1, id_sha256)
										DEFINE_OID(nist_hashalgs()+2, id_sha384)
										DEFINE_OID(nist_hashalgs()+3, id_sha512)
										DEFINE_OID(nist_hashalgs()+4, id_sha224)
										DEFINE_OID(nist_hashalgs()+7, id_sha3_224)
										DEFINE_OID(nist_hashalgs()+8, id_sha3_256)
										DEFINE_OID(nist_hashalgs()+9, id_sha3_384)
										DEFINE_OID(nist_hashalgs()+10, id_sha3_512)
#undef DEFINE_OID

		template<class MD>
		static inline OID get_oid(void)
		{
			if ( std::is_same<MD, MD5>::value )       { return id_md5(); }
			if ( std::is_same<MD, RIPEMD160>::value ) { return id_ripemd160(); }
			if ( std::is_same<MD, SHA1>::value )      { return id_sha1(); }
			if ( std::is_same<MD, SHA224>::value )    { return id_sha224(); }
			if ( std::is_same<MD, SHA256>::value )    { return id_sha256(); }
			if ( std::is_same<MD, SHA384>::value )    { return id_sha384(); }
			if ( std::is_same<MD, SHA512>::value )    { return id_sha512(); }
			if ( std::is_same<MD, SHA3_224>::value )  { return id_sha3_224(); }
			if ( std::is_same<MD, SHA3_256>::value )  { return id_sha3_256(); }
			if ( std::is_same<MD, SHA3_384>::value )  { return id_sha3_384(); }
			if ( std::is_same<MD, SHA3_512>::value )  { return id_sha3_512(); }

			return 0;
		}

		class Exception : public std::runtime_error
		{
			public:
				Exception(const char *what_arg) : std::runtime_error(what_arg) {}
		};

		static const int CRYPTO_OID_SUCCESS        = 0x00;
		static const int CRYPTO_OID_INVALID_LENGTH = 0x01;
		static const int CRYPTO_OID_VALUE_ERROR    = 0x02;
	protected:
		std::vector<uint32_t> nodes;

		static int fill_bytes(const uint8_t*&, std::size_t&, uint8_t[5], std::size_t&);
		static int decode_node(uint8_t[5], std::size_t, uint32_t&);
		static int encode_node(uint32_t, uint8_t[5], std::size_t&);
};

}

#endif
