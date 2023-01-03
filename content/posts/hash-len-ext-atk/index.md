---
title: 画蛇添足：哈希长度扩展攻击
date: 2019-06-29 11:43:47
tags:
  - Hash
categories:
  - Web 安全
---

简单翻译了 `hash_extender` 的 README 文档。

<!--more-->

## 背景

哈希长度扩展攻击是对消息认证码 MAC 的攻击，我们令其中使用的哈希函数为 H，则该攻击针对的是形如 `H(secret || data)` 这类 MAC，其中 `||` 是连接符。容易受到攻击的哈希函数包括但不限于：

- MD4
- MD5
- RIPEMD-160
- SHA-0
- SHA-1
- SHA-256
- SHA-512
- WHIRLPOOL

然而，MD2/SHA-224/SHA-384 不会受到该攻击。

攻击者在不知道 `secret` 的情况下，仍能产生合法的 `H(secret || data || attacker_controlled_data)` 的值。这是由于上述易受攻击的哈希函数都拥有类似 “断点续传” 的能力：即上一轮哈希函数的输出所包含的信息，足以用来继续进行下一轮哈希计算。攻击者所做的，不过是接手了继续计算哈希的任务而已。

简而言之，给定一个 “一个未知前缀 + 一个字符串” 的哈希值，攻击者可以在字符串后加上任意后缀，生成新的哈希值而不改变原来的未知前缀。

## 例子

```python
secret = 'secret'
data = 'data'
H = md5()
signature = H(secret || data) = 6036708eba0d11f6ef52ad44e8b74d5b
append = 'append'
```

服务器将 `data` 和 `signature` 发送到客户端，攻击者可以猜测（或通过其他方式）使用的哈希函数为 MD5，因为返回的哈希值长 32 位，而 MD5 是最常用的 `128-bit` 哈希函数。

已知 `data`，`signature`，`H` 这三个参数，攻击者想要将 `append` 添加到 `data` 后面，然后生成新的合法哈希值，要怎么做呢？

## 填充

在讨论实际的攻击前，不得不先说说哈希函数中的填充问题。

计算 `H(secret || data)` 时，字符串 `secret || data` 会被填充，填充使用的是一位 `1` 和若干位 `0`，紧随其后的是十六进制表示的字符串的长度。也就是一个 `0x80` 字节，加上若干个 `0x00` 字节，再加上表示长度的若干字节。后两者的字节数，以及长度如何表示，取决于具体的哈希函数和分组的大小。

对于大多数哈希函数（包括 MD4,MD5,RIPEMD-160,SHA-0,SHA-1 和 SHA-256），字符串会被填充至长度 `len`，使得 `len===56(mod 64)` 字节，也就是比分组大小 64 字节少 8 字节。少掉的 8 字节用来存放长度。`hash_extender` 中有两个例外：SHA-512 分组大小为 128 字节、并用 16 字节表示长度；WHIRLPOOL 分组大小为 64 字节、并用 32 字节表示长度。

此外，MD4,MD5,RIPEMD-160 使用小端法表示长度，而 SHA 家族和 WHIRLPOOL 用大端法。

在我们的例子中，`len(secret || data) = len('secretdata') = 10` 字节，或者说 80(0x50) 位。于是我们有：10 字节的数据 `secretdata`，46 字节填充 `0x80 0x00 0x00 ...`，以及 8 字节小端法表示的长度字段 `50 00 00 00 00 00 00 00`，共 64 字节：

```
0000  73 65 63 72 65 74 64 61 74 61 80 00 00 00 00 00  secretdata......
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 00 00 00 00 00 00 50 00 00 00 00 00 00 00  ........P.......
```

## 攻击

现在我们有了要哈希的数据，我们来看看如何实现攻击。

首先我们把 `append` 加到后面，很简单：

```
0000  73 65 63 72 65 74 64 61 74 61 80 00 00 00 00 00  secretdata......
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 00 00 00 00 00 00 50 00 00 00 00 00 00 00  ........P.......
0040  61 70 70 65 6e 64                                append
```

这样一块数据的哈希值是我们最终想要：

- 计算出来的
- 让服务器计算的

要计算该哈希值，有两种方法：

- 放进一个 buffer 里，然后调用 `H(buffer)`
- 从第一个分组的末尾开始，使用我们从 `signature` 中已知的状态信息，然后从那个状态开始对 `append` 作哈希运算

第一种方法是服务器将采用的，而第二种就是攻击者要采用的。我们先看服务器端，因为更简单一点。

### 服务器端计算

我们知道服务器会把 `secret` 放到字符串前面，所以我们把去掉 `secret` 后的消息发过去：

```
0000  64 61 74 61 80 00 00 00 00 00 00 00 00 00 00 00  data............
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 50 00 00 00 00 00 00 00 61 70 70 65 6e 64  ..P.......append
```

注意到这里的数据正好 64 字节——不要被迷惑了，这只是因为 `secret` 和 `append` 正好长度相同的关系。或许我不应该选这个例子，但我懒得重来了。。

服务器把 `secret` 作为前缀：

```
0000  73 65 63 72 65 74 64 61 74 61 80 00 00 00 00 00  secretdata......
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 00 00 00 00 00 00 50 00 00 00 00 00 00 00  ........P.......
0040  61 70 70 65 6e 64                                append
```

然后计算得到哈希值：

```
6ee582a1669ce442f3719c47430dadee
```

你可以用如下代码验证：

```c
#include <stdio.h>
#include <openssl/md5.h>

int main(int argc, const char *argv[])
{
  MD5_CTX c;
  unsigned char buffer[MD5_DIGEST_LENGTH];
  int i;

  MD5_Init(&c);
  MD5_Update(&c,"secret", 6);
  MD5_Update(&c,"data"
                  "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00\x00\x00"
                  "\x50\x00\x00\x00\x00\x00\x00\x00"
                  "append", 64);
  MD5_Final(buffer, &c);

  for (i = 0; i < 16; i++) {
    printf("%02x", buffer[i]);
  }
  printf("\n");
  return 0;
}
```

运行：

```shell
$ gcc -o hash_extension_1 hash_extension_1.c -lssl -lcrypto
$ ./hash_extension_1
```

所以，服务器会检查我们发送的新数据，将它与上面的哈希值比对。现在，作为攻击者，我们要考虑的是如何生成这个值。

### 客户端计算

怎么在不知道 `secret` 的情况下计算出那个值呢？

首先，我们需要看一下我们要处理哪些数据：`data, append, H, H(secret || data)`.

我们需要定义新函数 H'，它与 H 使用同样的哈希函数，但开始状态是 `H(secret || data)` 的结束状态，即 `signature`。然后我们就只要计算 `H'(append)`，输出的就是我们要的哈希值。

```c
#include <stdio.h>
#include <openssl/md5.h>

int main(int argc, const char *argv[])
{
  int i;
  unsigned char buffer[MD5_DIGEST_LENGTH];
  MD5_CTX c;

  MD5_Init(&c);
  MD5_Update(&c,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 64);

  c.A = htonl(0x6036708e); /* <-- This is the hash we already had */
  c.B = htonl(0xba0d11f6);
  c.C = htonl(0xef52ad44);
  c.D = htonl(0xe8b74d5b);

  MD5_Update(&c,"append", 6); /* This is the appended data. */
  MD5_Final(buffer, &c);
  for (i = 0; i < 16; i++) {
    printf("%02x", buffer[i]);
  }
  printf("\n");
  return 0;
}
```

运行：

```shell
$ gcc -o hash_extension_2 hash_extension_2.c -lssl -lcrypto
$ ./hash_extension_2
```

结果与刚才的哈希值一致，但是区别在于，我们根本没有用到 `secret`。简单地说：这段代码本质上就是用从新哈希值中得到的状态（四个链变量的值）去覆盖了四个初始链变量，随后再继续进行正常的哈希函数计算。

### 结果

现在我们有字符串数据：

```
0000  64 61 74 61 80 00 00 00 00 00 00 00 00 00 00 00  data............
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 50 00 00 00 00 00 00 00 61 70 70 65 6e 64  ..P.......append
```

以及 `H(secret || data || append)` 的哈希值：

```
6ee582a1669ce442f3719c47430dadee
```

并且，产生这一哈希值并不需要知道 `secret` 的值！我们发送这一数据，以及我们算出的新哈希值。服务器就会把 `secret` 放到前面，计算哈希，然后得到一个完全一致的哈希值，攻击完成。

## 工具

使用方法：

```shell
$ ./hash_extender --data data --secret 6 --append append --signature 6036708eba0d11f6ef52ad44e8b74d5b --format md5
Type: md5
Secret length: 6
New signature: 6ee582a1669ce442f3719c47430dadee
New string: 64617461800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000000617070656e64
```

如果不清楚哈希函数的类型，可以尝试不同类型的函数，只要不设置 `--format` 参数即可。此时建议使用 `--table` 参数。

```shell
$ ./hash_extender --data data --secret 6 --append append --signature 6036708eba0d11f6ef52ad44e8b74d5b --out-data-format html --table
md4       89df68618821cd4c50dfccd57c79815b data80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000P00000000000000append
md5       6ee582a1669ce442f3719c47430dadee data80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000P00000000000000append
```

关于输入输出的格式有很多选项，包括 HTML（使用 `%NN` 表示法），C 字符串（使用 `\xNN` 表示法），十六进制表示等等。默认选项：

- 输入数据：raw
- 输入哈希值：hex
- 输出数据：hex
- 输出哈希值：hex

帮助页面供参考：

```
--------------------------------------------------------------------------------
HASH EXTENDER
--------------------------------------------------------------------------------

By Ron Bowes

See LICENSE.txt for license information.

Usage: ./hash_extender <--data=|--file=> --signature= --format= [options]

INPUT OPTIONS
-d --data=
      The original string that we're going to extend.
--data-format=
      The format the string is being passed in as. Default: raw.
      Valid formats: raw, hex, html, cstr
--file=
      As an alternative to specifying a string, this reads the original string
      as a file.
-s --signature=
      The original signature.
--signature-format=
      The format the signature is being passed in as. Default: hex.
      Valid formats: raw, hex, html, cstr
-a --append=
      The data to append to the string. Default: raw.
--append-format=
      Valid formats: raw, hex, html, cstr
-f --format= [REQUIRED]
      The hash_type of the signature. This can be given multiple times if you
      want to try multiple signatures. 'all' will base the chosen types off
      the size of the signature and use the hash(es) that make sense.
      Valid types: md4, md5, ripemd160, sha, sha1, sha256, sha512, whirlpool
-l --secret=
      The length of the secret, if known. Default: 8.
--secret-min=
--secret-max=
      Try different secret lengths (both options are required)

OUTPUT OPTIONS
--table
      Output the string in a table format.
--out-data-format=
      Output data format.
      Valid formats: none, raw, hex, html, html-pure, cstr, cstr-pure, fancy
--out-signature-format=
      Output signature format.
      Valid formats: none, raw, hex, html, html-pure, cstr, cstr-pure, fancy

OTHER OPTIONS
-h --help
      Display the usage (this).
--test
      Run the test suite.
-q --quiet
      Only output what's absolutely necessary (the output string and the
      signature)
```

其他工具有 [HashPump](https://www.cnblogs.com/pcat/p/5478509.html) 和 [Hexpand](https://www.cnblogs.com/pcat/p/7668989.html) 等，不过个人觉得不如 `hash_extender` 使用方便。

## 防御

所以我们要如何防御这种攻击？实际上很简单，有两种方法：

- 可以的话，尽可能不要使用加密的数据或签名来认证用户
- 如果必须使用，可以使用 HMAC 算法而不是自己写这种算法

HMAC 算法才是真正的解决之道，也就是将哈希值再哈希一次，如：`H(secret || H(secret || data))`。

此外，还可以将 `secret` 放在数据末尾，也就是 `H(data || secret)`。由于服务器端会在末尾加 `secret`，原来的 `attacker_controlled_data` 就变成了 `attacker_controlled_data || secret`，由于不知道 `secret`，攻击者也不能再控制哈希值。

## 参考资料

1. [哈希长度拓展攻击 (Hash Length Extension Attacks)](https://xz.aliyun.com/t/2563)
1. [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)