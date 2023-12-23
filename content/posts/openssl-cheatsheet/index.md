---
title: OpenSSL 常用命令速查表
date: 2019-09-02
tags:
  - 对称密码学
  - 公钥密码学
categories:
  - 安全工具
---

仅仅记录了一些较常用的命令实例，具体命令、选项与说明推荐查阅官方文档。

<!--more-->

注：本速查表由于篇幅限制，使用时需要读者举一反三。例如：不加 `-out` 选项会默认输出到 stdout。

## base64

```bash
# 复制文件
openssl enc -none -in file1 -out file2

# base64 编码
openssl enc -a -in plain -out plainb64
# base64 解码
openssl enc -a -d -in plainb64 -out plain
# 从 stdin 读入并 base64 编码，无 -n 默认添加新行
echo -n 'string' | openssl enc -a
```

## 对称密码

```bash
# 所有可用的密码算法
openssl ciphers -v
# 所有高强度 AES 加密算法
openssl ciphers -v 'AES+HIGH'

# 加密
openssl enc -aes-256-cbc -in plain -out cipher
# 加密并 base64 编码
openssl enc -a -aes-256-cbc -in plain -out cipher
# 加密，直接设置口令
openssl enc -aes-256-cbc -in plain -out cipher -pass pass:123456
# 加密，从文件中读取口令
openssl enc -aes-256-cbc -in plain -out cipher -pass file:/home/password.txt
# 加密，从环境变量中读取口令
openssl enc -aes-256-cbc -in plain -out cipher -pass env:mypass
# 加密，设置密钥和 IV
openssl enc -aes-256-cbc -in plain -out cipher -k deadbeef -iv deadbeef
# 加密，不使用盐
openssl enc -aes-256-cbc -in plain -out cipher -nosalt
# 加密，使用指定盐
openssl enc -aes-256-cbc -in plain -out cipher -S deadbeef
# 解密
openssl enc -d -aes-256-cbc -in cipher -out plain
```

## 公钥密码

### RSA 密钥管理

```bash
# 生成指定长度私钥
openssl genrsa -out privkey.pem 2048
# 生成私钥并加密
openssl genrsa -des3 -out privkey.pem
# 生成私钥并加密，直接设置口令
openssl genrsa -des3 -out privkey.pem -passout pass:123456
# 生成私钥，用文件作为随机种子
openssl genrsa -out privkey.pem -rand random.txt
# 根据私钥生成公钥
openssl rsa -in privkey.pem -out pubkey.pem -pubout

# 移除对私钥文件的加密
openssl rsa -in privkey.pem -out newkey.pem
# PKCS#12 私钥转 PEM
openssl rsa -in privkey.p12 -inform p12 -passin pass:123456 -out newkey.pem -passout pass:654321 -aes256

# 查看私钥内容
openssl rsa -in privkey.pem -passin pass:123456 -text -noout
# 查看公钥模数
openssl rsa -in pubkey.pem -pubin -modulus -noout
```

### RSA 加解密与签名

```bash
# 公钥加密
openssl rsautl -encrypt -in plain -out cipher -inkey pubkey.pem -pubin
# 私钥解密
openssl rsautl -decrypt -in cipher -out plain -inkey privkey.pem
# 用证书中公钥加密，加密前颠倒明文
openssl rsautl -encrypt -in plain -rev -out cipher -inkey cert.pem -certin

# 私钥签名
openssl rsautl -sign -in plain -out sig -inkey privkey.pem
# 私钥签名并显示十六进制数据
openssl rsautl -sign -in plain -inkey privkey.pem -hexdump
# 公钥验证
openssl rsautl -verify -in sig -inkey pubkey.pem -pubin
# 用 PKCS#12 证书中私钥签名
openssl rsautl -sign -in plain -out sig -inkey cert.pfx -certin -keyform pkcs12
# 用 PKCS#12 证书中公钥验证
openssl rsautl -verify -in sig -out plain -inkey cert.pfx -certin -keyform pkcs12
```

### 其它公钥密码

```bash
# 生成 DH 参数，5 为原根
openssl dhparam -outform d -out dh512.der -5 512
# 生成 DSA 风格 DH 参数
openssl dhparam -dsaparam -out dh512.pem 512

# 生成 DSA 密钥参数
openssl dsaparam -out dsa512.pem 512
# DSA 密钥参数文件转 C 代码
openssl dsaparam -C -noout -in dsa512.pem
# 查看 DSA 密钥参数内容
openssl dsaparam -text -noout -in dsa512.pem

# 生成 DSA 私钥并加密
openssl gendsa -out dsakey.pem -aes256 -passout pass:123456 dsa512.pem
# DSA 私钥，PEM 转 DER
openssl dsa -aes-256-cbc -in dsakey.pem -passin pass:123456 -out dsakey.der -outform d -passout pass:654321
# 根据 DSA 私钥生成公钥
openssl dsa -in dsakey.pem -passin pass:123456 -out dsapubkey.pem -pubout

# 所有可用的椭圆曲线
openssl ecparam -list_curves
# 生成 EC 密钥
openssl ecparam -out key.pem -name prime256v1 -genkey
```

## 哈希与摘要

```bash
# 所有可用的哈希算法
openssl -list-message-digest-commands

# RSA+SHA1 签名
openssl sha1 -sign privkey.pem -out sig plain
# DSA+DSS1 验证签名
openssl dgst -dss1 -verify dsapubkey.pem -signature sig plain

# RIPEMD-160 哈希文件
openssl rmd160 -out sig plain
# PKCS#12 格式的 RSA 私钥签名文件，并使用多个文件作为随机种子
openssl sha1 -sign -keyform pkcs12 privkey.pfx -out sig -rand file1;file2;file3 plain

# 加 2 字符盐哈希指定的口令
openssl passwd MyPassword
# 加 8 字符盐哈希指定的口令
openssl passwd -1 MyPassword
# 哈希指定的口令，使用指定的 8 字符盐
openssl passwd -1 -salt deadbeef MyPassword
```

## 证书

```bash
# 生成自签名证书，不加密，使用新生成的 RSA 密钥
openssl req -x509 -nodes -days 365 -sha256 -newkey rsa:2048 -keyout privkey.pem -out mycert.cer
# 生成证书请求并加密，使用已有的 RSA 密钥，加密方式限定 DES3-CBC，输出格式限定 PEM
openssl req -new -key privkey.pem -passout pass:123456 -out req.pem
# 生成自签名证书并加密，使用已有 DSA 密钥参数文件生成 DSA 密钥，限定同上
openssl req -new -newkey dsa:dsa512.pem -keyout dsakey.pem -passout pass:123456 -out req.pem
# 验证一个证书请求的签名
openssl req -verify -in req.pem -noout -verify -key privkey.pem

# 查看 X.509 证书的序列号，哈希值和摘要
openssl x509 -in mycert.pem -noout -serial -hash -fingerprint
# X.509 证书，PEM 转 DER
openssl x509 -in mycert.pem -inform p -out mycert.der -outform d

# X.509 转 PKCS#12，加密方式限定 DES3-CBC
openssl pkcs12 -export -in mycert.pem -out cert.pfx -name "My Certificate"
# PKCS#12 转 PEM，无加密
openssl pkcs12 -in cert.pfx -out mycert.pem -nodes
# 查看 PKCS#12 证书信息
openssl pkcs12 -in cert.pfx -noout -info

# 验证证书
openssl verify mycert.pem
```

## SSL/TLS

```bash
# 连接远程 SMTP 服务器的 25(TLS) 端口
openssl s_client -connect remote.host:25 -starttls smtp
# 连接远程 STMP 服务器的 465(SSL) 端口，并显示其证书链
openssl s_client -connect remote.host:465 -showcerts
# 连接远程服务器的 443(HTTPS) 端口并使用 TLS 协议的 SNI 扩展访问指定主机
openssl s_client -connect www.massivehost.com:443 -servername www.myhost.com
# 开启 SSL 服务器，默认监听 4433 端口，单 html 页面
openssl s_server -cert mycert.pem -www
# 开启 SSL 服务器，监听 443 端口，拥有类似反代服务器的 web 目录（即当前目录）
openssl s_server -cert mycert.pem -accept 443 -WWW
# 远程服务器 443 端口连接测速，用新 session 访问 test.html，且只使用 SSLv3 以及高强度加密算法，测试指标为 10 秒内连接次数
openssl s_time -connect remote.host:443 -www /test.html -new -ssl3 -time 10 -cipher HIGH
```

## 素数

```bash
# 素性判定
openssl prime 561
# 16 进制数素性判定
openssl prime -hex 2f
# 产生指定长度的素数
openssl prime -generate -bits 64
# 产生指定长度的 16 进制素数
openssl prime -generate -bits 64 -hex
```

## 其它

```bash
# 翻译 SSL 错误信息，最后的参数是错误码
openssl errstr 0407006A
# 产生 1024 字节随机数据，并 base64 编码
openssl rand -base64 -out random-data 1024
# RSA 算法测速
openssl speed rsa
```
