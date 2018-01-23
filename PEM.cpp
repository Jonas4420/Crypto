#include "crypto/AES.hpp"
#include "crypto/Base64.hpp"
#include "crypto/CBC.hpp"
#include "crypto/DES.hpp"
#include "crypto/MD5.hpp"
#include "crypto/Padding.hpp"
#include "crypto/PBKDF1.hpp"
#include "crypto/PEM.hpp"
#include "crypto/Utils.hpp"

namespace Crypto
{

int
PEM::encode(std::string tag,
		const uint8_t *data, std::size_t data_sz,
		std::string &pem,
		std::string algorithm, std::string password)
{
	// TODO
	return CRYPTO_PEM_SUCCESS;
}

int
PEM::decode(std::string tag,
		std::string pem,
		uint8_t *data, std::size_t &data_sz,
		std::string password)
{
	const std::string hdr  = get_header(tag);
	const std::string ftr  = get_footer(tag);
	const std::string proc = "Proc-Type: 4,ENCRYPTED";
	const std::string dek  = "DEK-Info: ";

	int res;
	std::size_t pos;
	bool is_encrypted = false;
	std::string metadata, enc, iv;

	// Check for header
	pos = pem.find(hdr);
	if ( 0 == pos ) { pem = pem.substr(hdr.length()); }
	else            { throw PEM::Exception("Missing header"); }

	// Check for new line
	pos = pem.find(" ");
	if ( 0 == pos ) { pem = pem.substr(1); }
	pos = pem.find("\r");
	if ( 0 == pos ) { pem = pem.substr(1); }
	pos = pem.find("\n");
	if ( 0 == pos ) { pem = pem.substr(1); }
	else            { throw PEM::Exception("Missing data"); }

	// Check for metadata
	pos = pem.find(proc);
	if ( 0 == pos ) { pem = pem.substr(proc.length()); is_encrypted = true; }

	if ( is_encrypted ) {
		// Check for new line
		pos = pem.find("\r");
		if ( 0 == pos ) { pem = pem.substr(1); }
		pos = pem.find("\n");
		if ( 0 == pos ) { pem = pem.substr(1); }
		else            { throw PEM::Exception("Missing metadata"); }

		// Check for metadata
		pos = pem.find(dek);
		if ( 0 == pos ) { pem = pem.substr(dek.length()); }
		else            { throw PEM::Exception("Missing metadata"); }
		pos = pem.find("\n");
		if ( 0 == pos ) { throw PEM::Exception("Missing metadata"); }

		metadata = pem.substr(0, pos);
		pem      = pem.substr(pos + 1);
		// Read algorithm and IV
		pos      = metadata.find(",");
		enc      = metadata.substr(0, pos);
		iv       = metadata.substr(pos + 1);

		// Check for new line
		pos = pem.find("\r");
		if ( 0 == pos ) { pem = pem.substr(1); }
		pos = pem.find("\n");
		if ( 0 == pos ) { pem = pem.substr(1); }
		else            { throw PEM::Exception("Missing metadata"); }
	}

	// Check for footer
	pos = pem.find(ftr);
	if ( std::string::npos == pos ) { throw PEM::Exception("Missing footer"); }

	// Extract data
	pem = pem.substr(0, pos);

	// Check new line
	pos = pem.find_last_of("\n");
	if ( pem.length() - 1 != pos ) { throw PEM::Exception("Missing footer"); }

	// Check that lines are no more than 80 characters
	std::size_t line_sz = 0;
	for ( std::size_t i = 0 ; i < pem.length() ; ++i ) {
		++line_sz;

		if ( line_sz >= 80 ) {
			throw PEM::Exception("Line is longer than 80 characters");
		}

		if ( '\n' == pem[i] ) {
			line_sz = 0;
		}
	}

	// Try to decode data
	res = Base64::decode(pem, data, data_sz);
	if ( 0 != res ) { return CRYPTO_PEM_INVALID_LENGTH; }

	if ( is_encrypted ) {
		if (        "DES-CBC" == enc ) {
			res = des_decrypt(password, iv, data, data_sz);
		} else if ( "DES-EDE3-CBC" == enc ) {
			res = des3_decrypt(password, iv, data, data_sz);
		} else if ( "AES-128-CBC" == enc ) {
			res = aes_decrypt(password, iv, 16, data, data_sz);
		} else if ( "AES-192-CBC" == enc ) {
			res = aes_decrypt(password, iv, 24, data, data_sz);
		} else if ( "AES-256-CBC" == enc ) {
			res = aes_decrypt(password, iv, 32 ,data, data_sz);
		} else {
			throw PEM::Exception("Encryption algorithm not supported");
		}

		if ( 0 != res ) {
			throw PEM::Exception("Error occured during decryption");
		}
	}

	return CRYPTO_PEM_SUCCESS;
}

std::string
PEM::get_header(std::string tag)
{
	return "-----BEGIN " + tag + "-----";
}

std::string
PEM::get_footer(std::string tag)
{
	return "-----END " + tag + "-----";
}

int
PEM::des_decrypt(std::string pwd, std::string salt,
		uint8_t *data, std::size_t &data_sz)
{
	int res;
	uint8_t key[8], iv[8], buffer[MD5::SIZE];
	std::size_t key_sz = sizeof(key);
	std::size_t iv_sz  = sizeof(iv);
	std::size_t pad_sz = 0;

	if ( 16 != salt.length() ) {
		throw PEM::Exception("IV malformed");
	}

	Utils::from_hex(salt, iv, iv_sz);

	// Key derivation
	MD5 md_ctx;
	md_ctx.update((uint8_t*)pwd.c_str(), pwd.length());
	md_ctx.update(iv, 8);
	md_ctx.finish(buffer);
	memcpy(key, buffer, key_sz);

	// Decryption
	CBC<DES> ctx(key, key_sz, iv, false);
	res = ctx.update(data, data_sz, data, data_sz);
	if ( 0 != res ) { return res; }
	res = ctx.finish(pad_sz);
	if ( 0 != res ) { return res; }

	// Clean data
	Utils::zeroize(key,    sizeof(key));
	Utils::zeroize(iv,     sizeof(iv));
	Utils::zeroize(buffer, sizeof(buffer));

	// Unpadding
	PKCS7Padding::unpad(data, data_sz, data_sz);

	return CRYPTO_PEM_SUCCESS;
}

int
PEM::des3_decrypt(std::string pwd, std::string salt,
		uint8_t *data, std::size_t &data_sz)
{
	int res;
	uint8_t key[24], iv[8], buffer[16];
	std::size_t key_sz = sizeof(key);
	std::size_t iv_sz  = sizeof(iv);
	std::size_t pad_sz = 0;

	if ( 16 != salt.length() ) {
		throw PEM::Exception("IV malformed");
	}

	Utils::from_hex(salt, iv, iv_sz);

	// Key derivation
	MD5 md_ctx;
	md_ctx.update((uint8_t*)pwd.c_str(), pwd.length());
	md_ctx.update(iv, 8);
	md_ctx.finish(buffer);
	memcpy(key, buffer, 16);

	md_ctx.reset();
	md_ctx.update(key, 16);
	md_ctx.update((uint8_t*)pwd.c_str(), pwd.length());
	md_ctx.update(iv, 8);
	md_ctx.finish(buffer);
	memcpy(key + 16, buffer, 8);

	// Decryption
	CBC<TripleDES> ctx(key, key_sz, iv, false);
	res = ctx.update(data, data_sz, data, data_sz);
	if ( 0 != res ) { return res; }
	res = ctx.finish(pad_sz);
	if ( 0 != res ) { return res; }

	// Clean data
	Utils::zeroize(key,    sizeof(key));
	Utils::zeroize(iv,     sizeof(iv));
	Utils::zeroize(buffer, sizeof(buffer));

	// Unpadding
	PKCS7Padding::unpad(data, data_sz, data_sz);

	return CRYPTO_PEM_SUCCESS;
}

int
PEM::aes_decrypt(std::string pwd, std::string salt, std::size_t key_sz,
		uint8_t *data, std::size_t &data_sz)
{
	int res;
	uint8_t key[32], iv[16], buffer[16];
	std::size_t iv_sz  = sizeof(iv);
	std::size_t pad_sz = 0;

	if ( 32 != salt.length() ) {
		throw PEM::Exception("IV malformed");
	}

	Utils::from_hex(salt, iv, iv_sz);

	// Key derivation
	MD5 md_ctx;
	md_ctx.update((uint8_t*)pwd.c_str(), pwd.length());
	md_ctx.update(iv, 8);
	md_ctx.finish(buffer);
	memcpy(key, buffer, 16);

	md_ctx.reset();
	md_ctx.update(key, 16);
	md_ctx.update((uint8_t*)pwd.c_str(), pwd.length());
	md_ctx.update(iv, 8);
	md_ctx.finish(buffer);
	memcpy(key + 16, buffer, key_sz - 16);

	// Decryption
	CBC<AES> ctx(key, key_sz, iv, false);
	res = ctx.update(data, data_sz, data, data_sz);
	if ( 0 != res ) { return res; }
	res = ctx.finish(pad_sz);
	if ( 0 != res ) { return res; }

	// Clean data
	Utils::zeroize(key,    sizeof(key));
	Utils::zeroize(iv,     sizeof(iv));
	Utils::zeroize(buffer, sizeof(buffer));

	// Unpadding
	PKCS7Padding::unpad(data, data_sz, data_sz);

	return CRYPTO_PEM_SUCCESS;
}

}
