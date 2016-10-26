////////////////////////////////////////////////////////////////////////////////
// name  : signature.cpp
// author: chenyao
// mail  : cheny@meizu.com
////////////////////////////////////////////////////////////////////////////////

#include <iostream>
#include <string>
#include <exception>
#include <iomanip>
using namespace std;

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#ifdef WIN32
#ifdef __cplusplus
extern "C" {
#endif
#	pragma warning(push)
#	pragma warning(disable: 4996)
#	include <openssl/applink.c>
#	pragma warning(pop)
#ifdef __cplusplus
};
#pragma comment(lib, "libeay32.lib") // dynamic library
#endif
#endif

std::string RSASignature(const std::string &prikey, const std::string &plain);
std::string RSAVerifier(const std::string &pubkey, const std::string &cipher);

int main(int argc, char* argv[])
{
    try {
		using std::string;

		string prikeyName = "prikey.pem";
		string pubkeyName = "pubkey.pem";

		string strPlainText = "openssl signature demo";
		string strSignature, strVerifier;

		strSignature = RSASignature(prikeyName, strPlainText);
		if (strSignature.empty()) {
			cout << "signature failure" << endl;
			return -1;
		}

		strVerifier = RSAVerifier(pubkeyName, strSignature);
		cout << strVerifier << endl;
    } catch( ... ) {
        cerr << "Caught Exception..." << endl;
		return -1;
    }

	return 0;
}

/*!
 * \author  chenyao
 * \mail    cheny@meizu.com
 * \padding
 *		RSA_PKCS1_PADDING 
 *			the padding to use: PKCS#1 v1.5
 * \command 
 *      openssl rsautl -sign -inkey prikey.pem -in origin -out sign
 * \help    
 * \details must be private key
 */
std::string RSASignature(const std::string &prikey, const std::string &plain)
{
	BIO* bioKeyFile = BIO_new_file(prikey.c_str(), "rb");
	if (NULL == bioKeyFile)
		return "";

	std::string cipher("");
	RSA* pRSAKey = RSA_new();
    int  nSignLen = 0;
    unsigned char* pSignVal = NULL;

	if (NULL == PEM_read_bio_RSAPrivateKey(bioKeyFile, &pRSAKey, NULL, NULL))
		goto _cleanup;

	nSignLen = RSA_size(pRSAKey);
	pSignVal = new unsigned char[nSignLen]();

    nSignLen = RSA_private_encrypt(plain.size(), (unsigned char*) plain.c_str(), 
			pSignVal, pRSAKey, RSA_PKCS1_PADDING);

	if (nSignLen >= 0) {
		cipher = std::string((char*) pSignVal, nSignLen);
	}

	delete[] pSignVal, pSignVal = NULL;

_cleanup:
	RSA_free(pRSAKey);
	BIO_free(bioKeyFile);
	//CRYPTO_cleanup_all_ex_data(); 

	return cipher;
}

/*!
 * \author  chenyao
 * \mail    cheny@meizu.com
 * \padding
 *		RSA_PKCS1_PADDING 
 *			the padding to use: PKCS#1 v1.5
 * \command 
 *      openssl rsautl -verify -inkey pubkey.pem -pubin -in sign -out verify
 * \help    
 * \details must be public key
 *		PEM_read_RSA_PUBKEY() reads the PEM format. 
 *		PEM_read_RSAPublicKey() reads the PKCS#1 format. 
 */
std::string RSAVerifier(const std::string &pubkey, const std::string &cipher)
{
	BIO* bioKeyFile = BIO_new_file(pubkey.c_str(), "rb");
	if (NULL == bioKeyFile)
		return "";

	std::string plain("");
	RSA* pRSAKey = RSA_new();
    int  nVerifyLen = 0;
    unsigned char* pVerifyVal = NULL;

	if (NULL == PEM_read_bio_RSA_PUBKEY(bioKeyFile, &pRSAKey, NULL, NULL))
		goto _cleanup;

	nVerifyLen = RSA_size(pRSAKey);
	pVerifyVal = new unsigned char[nVerifyLen]();

	nVerifyLen = RSA_public_decrypt(cipher.size(), (unsigned char*) cipher.c_str(), 
			pVerifyVal, pRSAKey, RSA_PKCS1_PADDING);

	if (nVerifyLen >= 0) {
		plain = std::string((char*)(pVerifyVal), nVerifyLen);
	}

	delete[] pVerifyVal, pVerifyVal = NULL;

_cleanup:
	RSA_free(pRSAKey);
	BIO_free(bioKeyFile);
	//CRYPTO_cleanup_all_ex_data(); 

	return plain;
}
