////////////////////////////////////////////////////////////////////////////////
// name  : hashclusters.cpp
// author: chenyao
// mail  : cheny@meizu.com
////////////////////////////////////////////////////////////////////////////////

#include <iostream>
#include <string>
#include <exception>
#include <iomanip>
#include <sstream>
using namespace std;

#include <Shlwapi.h>
#include <vector>
#pragma comment(lib, "Shlwapi.lib")

#include <openssl/md5.h>

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
#endif

#define OPENSSL_DYNAMIC
#if defined(OPENSSL_DYNAMIC) // dynamic library
#	pragma comment(lib, "libeay32.lib")
#else // static library
#	pragma comment(lib, "User32.lib")
#	pragma comment(lib, "Advapi32.lib")
#	pragma comment(lib, "libeay32_s.lib")
#endif

#endif

static const char *RANDOM_SEED = "df206683af322dfaace922f09658c257";
const int FILE_BLOCK_SIZE = 100*1024*1024; // 100M

typedef void (*PCALLBACK_PRINT)(const char* filepath);
std::string MD5String(const unsigned char *plain, int length);
std::string MD5File(const std::string &filename);
std::string MD5Dirent(const std::string &dirent, PCALLBACK_PRINT funcprint = NULL);

void output(const char* filepath) {
	cout << filepath << endl;
}

void outputstringhex(const std::string &input) {
	std::stringstream ss;
	for (size_t i = 0; i < input.size(); i++) {
		ss << std::hex << std::setw(2) << std::setfill('0') 
			<< static_cast<int>(static_cast<unsigned char>(input[i]));
	}
	cout << ss.str() << endl;
}

int main(int argc, char* argv[])
{
    try {
		outputstringhex(MD5String((unsigned char*) "123", 3));
		outputstringhex(MD5Dirent("", output));
    } catch ( ... ) {
        cerr << "Caught Exception..." << endl;
		return -1;
    }

	return 0;
}

std::string MD5String(const unsigned char* plain, int length)
{
	unsigned char md5value[MD5_DIGEST_LENGTH] = {0};
	MD5(plain, length, md5value);
	return std::string((char*) md5value, MD5_DIGEST_LENGTH);
}

#pragma warning(push)
#pragma warning(disable:4996)
std::string MD5File(const std::string &filename) 
{
	FILE* hDigestFile = NULL; 
	hDigestFile = fopen(filename.c_str(), "rb");
	if (NULL == hDigestFile)
		return "";

	unsigned char *pData = (unsigned char*) malloc(FILE_BLOCK_SIZE);  
	if (NULL == pData) {
		fclose(hDigestFile);
		return "";  
	}

	unsigned char md5value[MD5_DIGEST_LENGTH] = {0};  
	int nLength = 0;
	MD5_CTX state;

	MD5_Init(&state);
	while (0 != (nLength = fread(pData, 1, FILE_BLOCK_SIZE, hDigestFile))) {  
		MD5_Update(&state, pData, nLength);  
	}
	MD5_Final(md5value, &state);

	fclose(hDigestFile);
	free(pData);

	return std::string((char*) md5value, MD5_DIGEST_LENGTH);
}

static void IterateDirectory(const std::string &dirent, 
		std::vector<std::string> &dirvec, bool recursive = false) 
{
	char szPath[512] = {0};
	char szName[512] = {0};

	strcpy_s(szPath, sizeof(szPath), dirent.c_str());
	strcpy_s(szName, sizeof(szName), dirent.c_str());
	PathAppendA(szName, "*");

	WIN32_FIND_DATAA findFileData;
	HANDLE hFind = ::FindFirstFileA(szName, &findFileData);
	if (INVALID_HANDLE_VALUE == hFind)
		return;

	do {
		if (findFileData.cFileName[0] == L'.')
			continue;

		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (false == recursive)
				continue;

			strcpy_s(szPath, sizeof(szPath), dirent.c_str());
			PathAppendA(szPath, findFileData.cFileName);

			IterateDirectory(szPath, dirvec, true); // recursive
		} else {
			strcpy_s(szName, sizeof(szName), dirent.c_str());
			PathAppendA(szName, findFileData.cFileName);

			dirvec.push_back(szName);
		}
	} while (::FindNextFileA(hFind, &findFileData));

	::FindClose(hFind);

	return;
}

std::string MD5Dirent(const std::string &dirent, PCALLBACK_PRINT funcprint) 
{
	std::vector<std::string> dirvector;
	IterateDirectory(dirent, dirvector, true);

	if (dirvector.empty())
		return "";

	unsigned char md5value[MD5_DIGEST_LENGTH] = {0};  
	MD5_CTX state;
	MD5_Init(&state);
	MD5_Update(&state, RANDOM_SEED, strlen(RANDOM_SEED)); // custom

	for (std::vector<std::string>::iterator it = dirvector.begin();
				it != dirvector.end(); it++) {
		NULL != funcprint ? funcprint(it->c_str()) : 0; // print

		FILE* hDigestFile = NULL; 
		hDigestFile = fopen(it->c_str(), "rb");
		if (NULL == hDigestFile)
			return "";

		unsigned char *pData = (unsigned char*) malloc(FILE_BLOCK_SIZE);  
		if (NULL == pData) {
			fclose(hDigestFile);
			return "";
		}

		int nLength = 0;
		while (0 != (nLength = fread(pData, 1, FILE_BLOCK_SIZE, hDigestFile))) {  
			MD5_Update(&state, pData, nLength);  
		}

		fclose(hDigestFile);
		free(pData);
	}

	MD5_Final(md5value, &state);

	return std::string((char*) md5value, MD5_DIGEST_LENGTH);
}
#pragma warning(pop)
