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
		std::string enc, std::string pwd, std::string iv)
{
	std::string base64;
	std::vector<uint8_t> v_data;
	bool is_encrypted = ("" != enc);

	pem = "";

	if ( "" == enc ) {
		no_encrypt(data, data_sz, v_data);
	} else if ( "DES-CBC" == enc ) {
		des_encrypt(pwd, iv, data, data_sz, v_data);
	} else if ( "DES-EDE3-CBC" == enc ) {
		des3_encrypt(pwd, iv, data, data_sz, v_data);
	} else if ( "AES-128-CBC" == enc ) {
		aes_encrypt(pwd, iv, 16, data, data_sz, v_data);
	} else if ( "AES-192-CBC" == enc ) {
		aes_encrypt(pwd, iv, 24, data, data_sz, v_data);
	} else if ( "AES-256-CBC" == enc ) {
		aes_encrypt(pwd, iv, 32 ,data, data_sz, v_data);
	} else {
		throw PEM::Exception("Encryption algorithm not supported");
	}

	// Add footer
	pem += get_header(tag) + "\n";

	// Add metadata
	if ( is_encrypted ) {
		pem += "Proc-Type: 4,ENCRYPTED\n";
		pem += "DEK-Info: " + enc + "," + iv + "\n";
		pem += "\n";
	}

	// Add data
	if ( v_data.size() > 0 ) {
		Base64::encode(v_data.data(), v_data.size(), base64);
	}

	while ( ! base64.empty() ) {
		std::size_t line_sz = base64.length() >= 64 ?
			64 : base64.length();

		pem   += base64.substr(0, line_sz) + "\n";
		base64 = base64.substr(line_sz);
	}

	// Add footer
	pem += get_footer(tag) + "\n";

	return CRYPTO_PEM_SUCCESS;
}

int
PEM::decode(std::string tag,
		std::string pem,
		uint8_t *data, std::size_t &data_sz,
		std::string pwd)
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
			res = des_decrypt(pwd, iv, data, data_sz);
		} else if ( "DES-EDE3-CBC" == enc ) {
			res = des3_decrypt(pwd, iv, data, data_sz);
		} else if ( "AES-128-CBC" == enc ) {
			res = aes_decrypt(pwd, iv, 16, data, data_sz);
		} else if ( "AES-192-CBC" == enc ) {
			res = aes_decrypt(pwd, iv, 24, data, data_sz);
		} else if ( "AES-256-CBC" == enc ) {
			res = aes_decrypt(pwd, iv, 32 ,data, data_sz);
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
PEM::no_encrypt(const uint8_t *data, std::size_t data_sz, std::vector<uint8_t> &output)
{
	output.clear();

	output.assign(data, data + data_sz);

	return CRYPTO_PEM_SUCCESS;
}

int
PEM::des_encrypt(std::string pwd, std::string salt,
		const uint8_t *data, std::size_t data_sz, std::vector<uint8_t> &output)
{
	uint8_t key[8], iv[8];
	uint8_t in[8], out[8];
	std::size_t key_sz = sizeof(key);
	std::size_t iv_sz  = sizeof(iv);
	std::size_t in_sz  = sizeof(in);
	std::size_t out_sz = sizeof(out);

	if ( 16 != salt.length() ) {
		throw PEM::Exception("IV malformed");
	}

	output.clear();

	// Key derivation
	Utils::from_hex(salt, iv, iv_sz);
	key_derivation(pwd, iv, key, key_sz);

	// Encryption
	CBC<DES> ctx(key, key_sz, iv, true);

	while ( data_sz > 0 ) {
		// Copy data to buffer
		in_sz  = (data_sz > 8) ? 8 : data_sz;
		out_sz = 8;
		memcpy(in, data, in_sz);

		// Update cipher
		ctx.update(in, in_sz, out, out_sz);

		// Write result
		if ( 0 < out_sz ) {
			output.insert(output.end(), out, out + out_sz);
		}

		// Move data pointer
		data    += in_sz;
		data_sz -= in_sz;
	}

	// Padding steps
	ctx.finish(in_sz);
	// If no bytes needed, add full block of padding
	in_sz  = (in_sz == 0) ? 8 : in_sz;
	out_sz = 8;
	PKCS7Padding::pad(in, 8 - in_sz, 8);

	// Update data
	ctx.update(in + (8 - in_sz), in_sz, out, out_sz);
	output.insert(output.end(), out, out+ out_sz);

	ctx.finish(in_sz);

	// Clean data
	Utils::zeroize(key, sizeof(key));
	Utils::zeroize(iv,  sizeof(iv));
	Utils::zeroize(in,  sizeof(in));
	Utils::zeroize(out, sizeof(out));

	return CRYPTO_PEM_SUCCESS;
}

int
PEM::des3_encrypt(std::string pwd, std::string salt,
		const uint8_t *data, std::size_t data_sz, std::vector<uint8_t> &output)
{
	uint8_t key[24], iv[8];
	uint8_t in[8], out[8];
	std::size_t key_sz = sizeof(key);
	std::size_t iv_sz  = sizeof(iv);
	std::size_t in_sz  = sizeof(in);
	std::size_t out_sz = sizeof(out);

	if ( 16 != salt.length() ) {
		throw PEM::Exception("IV malformed");
	}

	output.clear();

	// Key derivation
	Utils::from_hex(salt, iv, iv_sz);
	key_derivation(pwd, iv, key, key_sz);

	// Encryption
	CBC<TripleDES> ctx(key, key_sz, iv, true);

	while ( data_sz > 0 ) {
		// Copy data to buffer
		in_sz  = (data_sz > 8) ? 8 : data_sz;
		out_sz = 8;
		memcpy(in, data, in_sz);

		// Update cipher
		ctx.update(in, in_sz, out, out_sz);

		// Write result
		if ( 0 < out_sz ) {
			output.insert(output.end(), out, out + out_sz);
		}

		// Move data pointer
		data    += in_sz;
		data_sz -= in_sz;
	}

	// Padding steps
	ctx.finish(in_sz);
	// If no bytes needed, add full block of padding
	in_sz  = (in_sz == 0) ? 8 : in_sz;
	out_sz = 8;
	PKCS7Padding::pad(in, 8 - in_sz, 8);

	// Update data
	ctx.update(in + (8 - in_sz), in_sz, out, out_sz);
	output.insert(output.end(), out, out+ out_sz);

	ctx.finish(in_sz);

	// Clean data
	Utils::zeroize(key, sizeof(key));
	Utils::zeroize(iv,  sizeof(iv));
	Utils::zeroize(in,  sizeof(in));
	Utils::zeroize(out, sizeof(out));

	return CRYPTO_PEM_SUCCESS;
}

int
PEM::aes_encrypt(std::string pwd, std::string salt, std::size_t key_sz,
		const uint8_t *data, std::size_t data_sz, std::vector<uint8_t> &output)
{
	uint8_t key[32], iv[16];
	uint8_t in[16], out[16];
	std::size_t iv_sz  = sizeof(iv);
	std::size_t in_sz  = sizeof(in);
	std::size_t out_sz = sizeof(out);

	if ( 32 != salt.length() ) {
		throw PEM::Exception("IV malformed");
	}

	output.clear();

	// Key derivation
	Utils::from_hex(salt, iv, iv_sz);
	key_derivation(pwd, iv, key, key_sz);

	// Encryption
	CBC<AES> ctx(key, key_sz, iv, true);

	while ( data_sz > 0 ) {
		// Copy data to buffer
		in_sz  = (data_sz > 16) ? 16 : data_sz;
		out_sz = 16;
		memcpy(in, data, in_sz);

		// Update cipher
		ctx.update(in, in_sz, out, out_sz);

		// Write result
		if ( 0 < out_sz ) {
			output.insert(output.end(), out, out + out_sz);
		}

		// Move data pointer
		data    += in_sz;
		data_sz -= in_sz;
	}

	// Padding steps
	ctx.finish(in_sz);
	// If no bytes needed, add full block of padding
	in_sz  = (in_sz == 0) ? 16 : in_sz;
	out_sz = 16;
	PKCS7Padding::pad(in, 16 - in_sz, 16);

	// Update data
	ctx.update(in + (16 - in_sz), in_sz, out, out_sz);
	output.insert(output.end(), out, out+ out_sz);

	ctx.finish(in_sz);

	// Clean data
	Utils::zeroize(key, sizeof(key));
	Utils::zeroize(iv,  sizeof(iv));
	Utils::zeroize(in,  sizeof(in));
	Utils::zeroize(out, sizeof(out));

	return CRYPTO_PEM_SUCCESS;
}

int
PEM::des_decrypt(std::string pwd, std::string salt,
		uint8_t *data, std::size_t &data_sz)
{
	int res;
	uint8_t key[8], iv[8];
	std::size_t key_sz = sizeof(key);
	std::size_t iv_sz  = sizeof(iv);
	std::size_t pad_sz = 0;

	if ( 16 != salt.length() ) {
		throw PEM::Exception("IV malformed");
	}

	// Key derivation
	Utils::from_hex(salt, iv, iv_sz);
	key_derivation(pwd, iv, key, key_sz);

	// Decryption
	CBC<DES> ctx(key, key_sz, iv, false);
	res = ctx.update(data, data_sz, data, data_sz);
	if ( 0 != res ) { return res; }
	res = ctx.finish(pad_sz);
	if ( 0 != res ) { return res; }

	// Clean data
	Utils::zeroize(key, sizeof(key));
	Utils::zeroize(iv,  sizeof(iv));

	// Unpadding
	PKCS7Padding::unpad(data, data_sz, data_sz);

	return CRYPTO_PEM_SUCCESS;
}

int
PEM::des3_decrypt(std::string pwd, std::string salt,
		uint8_t *data, std::size_t &data_sz)
{
	int res;
	uint8_t key[24], iv[8];
	std::size_t key_sz = sizeof(key);
	std::size_t iv_sz  = sizeof(iv);
	std::size_t pad_sz = 0;

	if ( 16 != salt.length() ) {
		throw PEM::Exception("IV malformed");
	}

	// Key derivation
	Utils::from_hex(salt, iv, iv_sz);
	key_derivation(pwd, iv, key, key_sz);

	// Decryption
	CBC<TripleDES> ctx(key, key_sz, iv, false);
	res = ctx.update(data, data_sz, data, data_sz);
	if ( 0 != res ) { return res; }
	res = ctx.finish(pad_sz);
	if ( 0 != res ) { return res; }

	// Clean data
	Utils::zeroize(key, sizeof(key));
	Utils::zeroize(iv,  sizeof(iv));

	// Unpadding
	PKCS7Padding::unpad(data, data_sz, data_sz);

	return CRYPTO_PEM_SUCCESS;
}

int
PEM::aes_decrypt(std::string pwd, std::string salt, std::size_t key_sz,
		uint8_t *data, std::size_t &data_sz)
{
	int res;
	uint8_t key[32], iv[16];
	std::size_t iv_sz  = sizeof(iv);
	std::size_t pad_sz = 0;

	if ( 32 != salt.length() ) {
		throw PEM::Exception("IV malformed");
	}

	// Key derivation
	Utils::from_hex(salt, iv, iv_sz);
	key_derivation(pwd, iv, key, key_sz);

	// Decryption
	CBC<AES> ctx(key, key_sz, iv, false);
	res = ctx.update(data, data_sz, data, data_sz);
	if ( 0 != res ) { return res; }
	res = ctx.finish(pad_sz);
	if ( 0 != res ) { return res; }

	// Clean data
	Utils::zeroize(key, sizeof(key));
	Utils::zeroize(iv,  sizeof(iv));

	// Unpadding
	PKCS7Padding::unpad(data, data_sz, data_sz);

	return CRYPTO_PEM_SUCCESS;
}

void
PEM::key_derivation(std::string pwd, const uint8_t iv[8], uint8_t *key, std::size_t key_sz)
{
	uint8_t buffer[MD5::SIZE];

	MD5 md_ctx;
	md_ctx.update((uint8_t*)pwd.c_str(), pwd.length());
	md_ctx.update(iv, 8);
	md_ctx.finish(buffer);

	if ( key_sz <= MD5::SIZE ) {
		memcpy(key, buffer, key_sz);
	} else {
		memcpy(key, buffer, MD5::SIZE);

		md_ctx.reset();
		md_ctx.update(key, MD5::SIZE);
		md_ctx.update((uint8_t*)pwd.c_str(), pwd.length());
		md_ctx.update(iv, 8);

		md_ctx.finish(buffer);

		memcpy(key + MD5::SIZE, buffer, key_sz - MD5::SIZE);
	}

	Utils::zeroize(buffer, sizeof(buffer));
}

}
