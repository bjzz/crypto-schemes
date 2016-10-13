# 目录结构
```sh
    demo\               # 调用 demo
        encryption\     # 公钥加密、私钥解密
    include\            # cryptopp 头文件
        cryptopp\ 
    lib\                # cryptopp 库文件
        cryptopp.lib    # windows dynamic library
        cryptopp.dll    # windows dynamic library
        cryptlib.lib    # windows static library
    readme.md           # 说明文档
```


# 解决的 bug

调用 `cryptopp` 动态库，使用 `RSAES_PKCS1v15_Encryptor`时，vc10会出现连接错误：
```sh
error LNK2001: 无法解析的外部符号 "public: virtual struct CryptoPP::DecodingResult __thiscall CryptoPP::PKCS_EncryptionPaddingScheme::Unpad(unsigned char const *,unsigned int,unsigned char *,class CryptoPP::NameValuePairs const &)const " (?Unpad@PKCS_EncryptionPaddingScheme@CryptoPP@@UBE?AUDecodingResult@2@PBEIPAEABVNameValuePairs@2@@Z)
error LNK2001: 无法解析的外部符号 "public: virtual void __thiscall CryptoPP::PKCS_EncryptionPaddingScheme::Pad(class CryptoPP::RandomNumberGenerator &,unsigned char const *,unsigned int,unsigned char *,unsigned int,class CryptoPP::NameValuePairs const &)const " (?Pad@PKCS_EncryptionPaddingScheme@CryptoPP@@UBEXAAVRandomNumberGenerator@2@PBEIPAEIABVNameValuePairs@2@@Z)
error LNK2001: 无法解析的外部符号 "public: virtual unsigned int __thiscall CryptoPP::PKCS_EncryptionPaddingScheme::MaxUnpaddedLength(unsigned int)const " (?MaxUnpaddedLength@PKCS_EncryptionPaddingScheme@CryptoPP@@UBEII@Z)
```

需要修改 `cryptopp` 源码 `pkcspad.h`：
```c++
// chenyao add CRYPTOPP_DLL to export
class CRYPTOPP_DLL PKCS_EncryptionPaddingScheme : public PK_EncryptionMessageEncodingMethod
{
public:
    // chenyao add CRYPTOPP_API to export
	CRYPTOPP_CONSTEXPR static const char * CRYPTOPP_API StaticAlgorithmName() {return "EME-PKCS1-v1_5";}
    ...
};
```
