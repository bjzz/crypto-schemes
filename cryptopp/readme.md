# 编译安装 cryptopp

## windows 
我是用 `vs2010` 编译的，`cryptopp` 源码中已附带 `vs2010` 工程文件，没有什么需要另外增加的，很干净。

## linux
参考文档：[cryptopp linux wiki](http://www.cryptopp.com/wiki/Linux)，这里写的很详细。

去悼调试信息：
```sh
strip --strip-debug libcryptopp.a
strip --strip-debug libcryptopp.so
```
> 文件体积大大减少。


# 测试和使用 demo
我已经编译好了 `windows` 和 `linux` 下的 `cryptopp` 库文件，存放在 `lib` 目录下，直接使用即可。

demo 的编译：`windows` 下通过 `demo/cryptopp.sln` 编译，`linux` 下通过各 demo 中的 `makefile` 编译。

在 `linux` 下，编译使用 `cryptopp` 动态连接库，运行时会提示找不到库文件，就算将库文件拷贝到可执行程序同级目录，也不行。这是因此 `linux` 并不会主动去当前目录搜索动态库文件，需要将当前目录增加到库文件搜索路径中：
```sh
$ export LD_LIBRARY_PATH=./
```


# 目录结构
```sh
    demo\               # demo
        encryption\     # 公钥加密、私钥解密
    include\            # cryptopp 头文件
        cryptopp\ 
    lib\                # cryptopp 库文件
        cryptopp.lib    # windows dynamic library
        cryptopp.dll    # windows dynamic library
        cryptlib.lib    # windows static library
        libcryptopp.so  # linux dynamic library
        libcryptopp.a   # linux static library
    readme.md           # 说明文档
```


# 解决的 bug

windows 下调用 `cryptopp` 动态库，使用 `RSAES_PKCS1v15_Encryptor`时，vs2010会出现连接错误：
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
