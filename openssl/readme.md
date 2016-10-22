# 编译安装 openssl #
使用的 `openssl` 版本为： `openssl-1.0.2j`。

## windows 
参考 `openssl-1.0.2j/INSTALL.W32`， 要安装如下环境：
```sh
ActivePerl  # Perl 脚本解析器
nasm        # 汇编语言编译程序
```

## linux
参考 `openssl-1.0.2j/INSTALL`，同时编译出动态库和静态库文件：
```sh
cd openssl-1.0.2j
./config shared
make
# 生成文件存放在当前目录
```


# 测试和使用 `demo` #
我已经编译好了 `windows` 和 `linux` 下的 `openssl` 库文件，存放在 `lib` 目录下，直接使用即可。

`demo` 的编译：`windows` 下通过 `demo/openssl.sln` 编译，`linux` 下通过各 `demo` 中的 `makefile` 编译。

测试 `demo` 需要先创建 RSA 私钥和公钥，命令：
```sh
openssl genrsa -out prikey.pem 2048
openssl rsa -in prikey.pem -pubout -out pubkey.pem
```


# 目录结构 #
```sh
    demo\               # demo
        signature\      # 私钥加密、公钥解密
    include\            # openssl 头文件
        openssl\ 
    lib\                # openssl 库文件
        libeay32.lib    # windows dynamic library
        libeay32.dll    # windows dynamic library
        libcrypto.so    # linux dynamic library
        libcrypto.a     # linux static library
    readme.md           # 说明文档
```
