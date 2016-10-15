////////////////////////////////////////////////////////////////////////////////
// name  : signature.cpp
// author: chenyao
// mail  : cheny@meizu.com
////////////////////////////////////////////////////////////////////////////////

#include <iostream>
#include <string>
#include <exception>
#include <assert.h>
using namespace std;

#include "cryptopp/dll.h"				// Just use to dynamic library
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/pssr.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
USING_NAMESPACE(CryptoPP)

// Crypto++ Library
#ifdef WIN32
#	pragma comment(lib, "cryptopp.lib") // use dynamic library
//#	pragma comment(lib, "cryptlib.lib") // use static library
#endif

void SaveKey( const RSA::PublicKey& PublicKey, const string& filename );
void SaveKey( const RSA::PrivateKey& PrivateKey, const string& filename );
void LoadKey( const string& filename, RSA::PublicKey& PublicKey );
void LoadKey( const string& filename, RSA::PrivateKey& PrivateKey );

int RSASignature(const std::string &prikey, 
		const unsigned char *plain, unsigned int plainlen,
		unsigned char *cipher, unsigned int cipherlen);
bool RSAVerifier(const std::string &pubkey, 
		const unsigned char *cipher, unsigned int cipherlen,
		const unsigned char *plain, unsigned int plainlen);

int main(int argc, char* argv[])
{
    try {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 1024);

        RSA::PrivateKey privateKey(parameters);
        RSA::PublicKey publicKey(parameters);

		std::string prikeyName("prikey.der");
		std::string pubkeyName("pubkey.der");
		SaveKey(privateKey, prikeyName);
		SaveKey(publicKey, pubkeyName);

        ////////////////////////////////////////////////
        // Secret to protect
		char szPlainText[128] = "RSA signature demo";
		unsigned char szCipherText[256] = {0};

        ////////////////////////////////////////////////
        // Signature
		int nLength = RSASignature(prikeyName, 
				(unsigned char*) szPlainText, strlen(szPlainText),
				szCipherText, sizeof(szCipherText));

        ////////////////////////////////////////////////
        // Verifier
		bool bResult = RSAVerifier(pubkeyName, szCipherText, nLength, 
				(unsigned char*) szPlainText, strlen(szPlainText));

		// Result
		if (true == bResult) {
			cout << "Signature on message verified" << endl;
		} else {
			cout << "Message verification failed" << endl;
		}
    } catch( CryptoPP::Exception& e ) {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

	return 0;
}

/*!
 * \author  chenyao
 * \mail    cheny@meizu.com
 * \padding
 *		RSASSA_PKCS1v15_SHA_Signer 
 *			the padding to use: PKCS#1 v1.5
 *          openssl dgst -sha1 -sign prikey.pem -out sign.sha1 origin
 * \help    http://cryptopp.com/wiki/RSA_Signature_Schemes
 * \details must be private key
 *
 */
int RSASignature(const std::string &prikey, 
		const unsigned char *plain, unsigned int plainlen,
		unsigned char *cipher, unsigned int cipherlen) 
{
	////////////////////////////////////////////////
	// Load keys
	AutoSeededRandomPool rng;

	RSA::PrivateKey  privateKey;
	LoadKey(prikey, privateKey);

	// Signer object
	RSASSA_PKCS1v15_SHA_Signer signer( privateKey );

	// Create signature space
	size_t length = signer.MaxSignatureLength();
	SecByteBlock signature( length );

	// Sign message
	length = signer.SignMessage(rng, (const byte*) plain,
			plainlen, signature);

	// Resize now we know the true size of the signature
	signature.resize(length);

	////////////////////////////////////////////////
	// Copy
	assert(cipherlen >= signature.size());
	memcpy_s(cipher, cipherlen, static_cast<void*>(signature), signature.size());

	return static_cast<int>(signature.size());
}

/*!
 * \author  chenyao
 * \mail    cheny@meizu.com
 * \padding
 *		RSASSA_PKCS1v15_SHA_Verifier 
 *			the padding to use: PKCS#1 v1.5
 *          openssl dgst -sha1 -verify pubkey.pem -signature sign.sha1 origin
 * \help    http://cryptopp.com/wiki/RSA_Signature_Schemes
 * \details must be public key
 */
bool RSAVerifier(const std::string &pubkey, 
		const unsigned char *cipher, unsigned int cipherlen,
		const unsigned char *plain, unsigned int plainlen) 
{
	////////////////////////////////////////////////
	// Load keys
	RSA::PublicKey publicKey;
	LoadKey(pubkey, publicKey);

	////////////////////////////////////////////////
	// Verifier object
	RSASSA_PKCS1v15_SHA_Verifier verifier( publicKey );

	// Verify
	return verifier.VerifyMessage( plain, plainlen, cipher, cipherlen );
}

/*!
 * \author  chenyao
 * \mail    cheny@meizu.com
 * \padding
 *		RSASSA_PKCS1v15_SHA_Verifier 
 *			the padding to use: PKCS#1 v1.5
 * \help    http://cryptopp.com/wiki/RSA_Signature_Schemes
 * \details must be public key
 */
bool RSAVerifier(const std::string &pubkey, 
		const std::string &cipher, const std::string &plain)
{
	////////////////////////////////////////////////
	// Load keys
	RSA::PublicKey publicKey;
	LoadKey(pubkey, publicKey);

	////////////////////////////////////////////////
	// Verify and Recover
	RSASS<PKCS1v15, SHA>::Verifier verifier(publicKey);

	if (cipher.size() != verifier.SignatureLength())
		return false;

#if 0
	std::string recovered;
	StringSource ss(plain+cipher, true, 
		new VerifierFilter(verifier, new StringSink(recovered),
			SignatureVerificationFilter::SIGNATURE_AT_END
				| SignatureVerificationFilter::THROW_EXCEPTION 
			) // SignatureVerificationFilter
	); // StringSource

	return true;
#else
	VerifierFilter *verifierFilter = new VerifierFilter(verifier);
	verifierFilter->Put((byte*) cipher.c_str(), verifier.SignatureLength());
	StringSource ss(plain, true, verifierFilter);

	return verifierFilter->GetLastResult();
#endif
}

void SaveKey( const RSA::PublicKey& PublicKey, const string& filename )
{
    // DER Encode Key - X.509 key format
    PublicKey.Save(
        FileSink( filename.c_str(), true /*binary*/ ).Ref()
    );
}

void SaveKey( const RSA::PrivateKey& PrivateKey, const string& filename )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Save(
        FileSink( filename.c_str(), true /*binary*/ ).Ref()
    );
}

void LoadKey( const string& filename, RSA::PublicKey& PublicKey )
{
    // DER Encode Key - X.509 key format
    PublicKey.Load(
        FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
    );
}

void LoadKey( const string& filename, RSA::PrivateKey& PrivateKey )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Load(
        FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
    );
}

