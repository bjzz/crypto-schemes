////////////////////////////////////////////////////////////////////////////////
// name  : encryption.cpp
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
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/SecBlock.h"
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

int RSAEncryption(const std::string &pubkey, 
		const unsigned char *plain, unsigned int plainlen,
		unsigned char *cipher, unsigned int cipherlen);
int RSADecryption(const std::string &prikey, 
		const unsigned char *cipher, unsigned int cipherlen,
		unsigned char *plain, unsigned int plainlen);

void RSAEncryption(const std::string &pubkey, 
		const std::string &plain, std::string &cipher);
void RSADecryption(const std::string &prikey, 
		const std::string &cipher, std::string &plain);

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
		char szPlainText[128] = "RSA encryption demo";
		unsigned char szCipherText[256] = {0};

        ////////////////////////////////////////////////
        // Encryption
		int nLength = RSAEncryption(pubkeyName, 
				(unsigned char*) szPlainText, strlen(szPlainText),
				szCipherText, sizeof(szCipherText));

        ////////////////////////////////////////////////
        // Decryption
		memset(szPlainText, 0, sizeof(szPlainText));
		nLength = RSADecryption(prikeyName, szCipherText, nLength, 
				(unsigned char*) szPlainText, sizeof(szPlainText));

		cout << "plain length: " << nLength << endl;
		cout << "plain text  : " << szPlainText << endl;
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
 *		RSAES_PKCS1v15_Encryptor 
 *			the padding to use: PKCS#1 v1.5
 *			openssl rsautl -encrypt -pkcs -in origin -inkey pubkey.pem -pubin -out encrypt
 *		RSAES_OAEP_SHA_Encryptor 
 * 			the padding to use: PKCS#1 OAEP
 *			openssl rsautl -encrypt -oaep -in origin -inkey pubkey.pem -pubin -out encrypt
 * \help    http://cryptopp.com/wiki/RSA_Encryption_Schemes
 * \details could be private key and public key
 *
 */
int RSAEncryption(const std::string &pubkey, 
		const unsigned char *plain, unsigned int plainlen,
		unsigned char *cipher, unsigned int cipherlen) 
{
	////////////////////////////////////////////////
	// Load keys
	AutoSeededRandomPool rng;

	RSA::PublicKey  publicKey;
	LoadKey(pubkey, publicKey);

	////////////////////////////////////////////////
	// Secret to protect
	SecByteBlock plaintext(plain, plainlen);

	////////////////////////////////////////////////
	// Encrypt
	RSAES_PKCS1v15_Encryptor encryptor( publicKey );
	//RSAES_OAEP_SHA_Encryptor encryptor( publicKey );

	// Now that there is a concrete object, we can validate
	assert( 0 != encryptor.FixedMaxPlaintextLength() );
	assert( plaintext.size() <= encryptor.FixedMaxPlaintextLength() );

	// Create cipher text space
	size_t ecl = encryptor.CiphertextLength( plaintext.size() );
	assert( 0 != ecl );
	SecByteBlock ciphertext( ecl );

	// Paydirt
	encryptor.Encrypt( rng, plaintext, plaintext.size(), ciphertext );

	////////////////////////////////////////////////
	// Copy
	assert(cipherlen >= ciphertext.size());
	memcpy_s(cipher, cipherlen, static_cast<void*>(ciphertext), ciphertext.size());

	return static_cast<int>(ciphertext.size());
}

/*!
 * \author  chenyao
 * \mail    cheny@meizu.com
 * \padding
 *		RSAES_PKCS1v15_Decryptor 
 *			the padding to use: PKCS#1 v1.5
 *			openssl rsautl -decrypt -pkcs -in encrypt -inkey prikey.pem -out decrypt
 *		RSAES_OAEP_SHA_Decryptor 
 * 			the padding to use: PKCS#1 OAEP
 *			openssl rsautl -decrypt -oaep -in encrypt -inkey prikey.pem -out decrypt
 * \help    http://cryptopp.com/wiki/RSA_Encryption_Schemes
 * \details must be private key
 *
 */
int RSADecryption(const std::string &prikey, 
		const unsigned char *cipher, unsigned int cipherlen,
		unsigned char *plain, unsigned int plainlen) 
{
	////////////////////////////////////////////////
	// Load keys
	AutoSeededRandomPool rng;

	RSA::PrivateKey privateKey;
	LoadKey(prikey, privateKey);

	////////////////////////////////////////////////
	// Secret to protect
	SecByteBlock ciphertext(cipher, cipherlen);

	////////////////////////////////////////////////
	// Decrypt
	RSAES_PKCS1v15_Decryptor decryptor( privateKey );
	//RSAES_OAEP_SHA_Decryptor decryptor( privateKey );

	// Now that there is a concrete object, we can check sizes
	assert( 0 != decryptor.FixedCiphertextLength() );
	assert( ciphertext.size() <= decryptor.FixedCiphertextLength() );

	// Create recovered text space
	size_t dpl = decryptor.MaxPlaintextLength( ciphertext.size() );
	assert( 0 != dpl );
	SecByteBlock recovered( dpl );

	// Paydirt
	DecodingResult result = decryptor.Decrypt( rng,
		ciphertext, ciphertext.size(), recovered );

	// More sanity checks
	assert( result.isValidCoding );        
	assert( result.messageLength <= decryptor.MaxPlaintextLength( ciphertext.size() ) );

	// At this point, we can set the size of the recovered
	//  data. Until decryption occurs (successfully), we
	//  only know its maximum size
	recovered.resize( result.messageLength );

	////////////////////////////////////////////////
	// Copy
	assert(plainlen >= recovered.size());
	memcpy_s(plain, plainlen, static_cast<void*>(recovered), recovered.size());

	return static_cast<int>(recovered.size());
}

/*!
 * \author  chenyao
 * \mail    cheny@meizu.com
 * \padding
 *		RSAES_PKCS1v15_Encryptor 
 *			the padding to use: PKCS#1 v1.5
 *		RSAES_OAEP_SHA_Encryptor 
 * 			the padding to use: PKCS#1 OAEP
 * \help    http://cryptopp.com/wiki/RSA_Encryption_Schemes
 * \details could be private key and public key
 */
void RSAEncryption(const std::string &pubkey, 
		const std::string &plain, std::string &cipher) 
{
	////////////////////////////////////////////////
	// Generate keys
	AutoSeededRandomPool rng;

	RSA::PublicKey  publicKey;
	LoadKey(pubkey, publicKey);

	////////////////////////////////////////////////
	// Encryption
	RSAES_PKCS1v15_Encryptor e( publicKey );
	//RSAES_OAEP_SHA_Encryptor e( publicKey );

	StringSource ss1( plain, true,
		new PK_EncryptorFilter( rng, e, new StringSink( cipher ) ) // PK_EncryptorFilter
		); // StringSource
}

/*!
 * \author  chenyao
 * \mail    cheny@meizu.com
 * \padding
 *		RSAES_PKCS1v15_Decryptor 
 *			the padding to use: PKCS#1 v1.5
 *		RSAES_OAEP_SHA_Decryptor 
 * 			the padding to use: PKCS#1 OAEP
 * \help    http://cryptopp.com/wiki/RSA_Encryption_Schemes
 * \details must be private key
 */
void RSADecryption(const std::string &prikey, 
		const std::string &cipher, std::string &plain)
{
	////////////////////////////////////////////////
	// Generate keys
	AutoSeededRandomPool rng;

	RSA::PrivateKey privateKey;
	LoadKey(prikey, privateKey);

	////////////////////////////////////////////////
	// Decryption
	RSAES_PKCS1v15_Decryptor d( privateKey );
	//RSAES_OAEP_SHA_Decryptor d( privateKey );

	StringSource ss2( cipher, true,
		new PK_DecryptorFilter( rng, d, new StringSink( plain ) ) // PK_DecryptorFilter
		); // StringSource
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

