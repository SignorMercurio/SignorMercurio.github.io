---
title: 水漫金山：《二进制漏洞利用入门》课程总结
date: 2019-12-05 22:37:20
tags:
  - 整数溢出
  - 栈漏洞
  - fsb
categories:
  - 二进制安全
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/0.png
---

其实我也刚学。

<!--more-->

本课程主要介绍对于远程服务进行二进制层面的漏洞利用（也称 `Pwn`）的基础技巧，使用的编程语言主要包括 C 语言、汇编语言和 Python 语言，涉及的平台包括 32 位与 64 位 Linux 操作系统。内容包含：

- Pwn 简介
- 整型溢出漏洞
- Linux 基础
- C 程序运行机制
- C 语言函数调用栈
- 缓冲区溢出漏洞——栈溢出
- Pwn 相关工具
- x86(-64) 汇编基础
- 花式栈溢出与栈溢出保护
- 格式化字符串漏洞

时间有限，课程仅介绍了二进制安全中最基础的三类漏洞及其利用：整型溢出、栈溢出与格式化字符串漏洞。

## Pwn 简介

### 什么是 Pwn？

> "pwn" - means to compromise or control, specifically another computer (server or PC), web site, gateway device, or application. It is synonymous with one of the definitions of hacking or cracking, including iOS jailbreaking.  -  Wikipedia.

### Pwn 概览

- GLIBC Pwn
  - Linux 下内存管理相关
- Browser Pwn
  - 浏览器相关
- Kernel Pwn
  - Windows Kernel
  - Linux Kernel

### Pwn 实例

包括但不限于：Web 框架、OS 内核、浏览器、路由器等设备……

- CVE-2017-5638
  - Apache Struts2 远程代码执行
- CVE-2019-9213
  - Linux 内核用户空间 0 虚拟地址映射
- CVE-2019-11707
  - 64 位火狐浏览器任意读写 + 代码执行
- CVE-2018-5767
  - TENDA AC15 路由器权远程代码执行
- ……

## 整型溢出

例：

```c
unsigned char x = 0xff;
printf("%d\n", ++x);
```

考虑这里的 `++x`，二进制表示实际就是：

```
1111 1111 + 1 = 1 0000 0000
```

然而，`unsigned char` 是 1 字节即 8 比特的，上面的结果却是 9 比特，那么对于最高位的 `1` 只能舍弃，因此有：

```
(0xff+1) mod 256 = 0
```

也就是说，程序的执行结果为 0。`0xff` 这样的大数加 1 后变成了 0，显然不是我们预期的结果。类似地，对于：

```c
signed char x = 0x7f;
printf("%d\n", ++x);
```

这里的 `++x` 就是：

```
0111 1111 + 1 = 1000 0000
```

幸运的是，这次没有出现多出一比特的情况。然而对于 `signed char`，我们知道其最高位是符号位，换而言之我们的结果是一个负数。

```
0x7f+1 = 0x80 = -(unsigned char) 1000 0000 = -128
```

注意这里的补码运算。

整型溢出漏洞原理非常简单，其造成的危害却是十分隐蔽的，例如，我们有时会这样倒序遍历字符串：

```c
for (int i = strlen(s)-1; i >= 0; --i)
```

这样写会引起编译器 warning，因为将无符号类型转换到了有符号类型。为什么会这样？我们来看一下 `strlen` 函数的定义：

```
size_t strlen (const char * str)
```

返回值是 `size_t` 类型，我们可以将它等效为 `unsigned int` 类型。

现在考虑 `s` 是一个空串时的情况，这时 `i` 的初始值是什么？

你可能会认为是 - 1。实际上，由于 `strlen` 的返回值是无符号的，那么它减 1 的结果同样会被认为是无符号的，那么 `i` 被赋值的实际上是 `(size_t)(-1)`，也就是一个很大的正数。此时必然会发生数组越界。

一个更常见的错误是这样的：

```c
int binary_search(int a[], int len, int key)
{
    int low = 0;
    int high = len - 1;

    while (low<=high) {
        int mid = (low + high)/2;
        if (a[mid] == key) {
            return mid;
        }
        if (key < a[mid]) {
            high = mid - 1;
        }else{
            low = mid + 1;
        }
    }
    return -1;
}
```

这不就是最普通的二分查找写法吗？的确，但是即使我们确保 `low` 和 `high` 不溢出，`low+high` 的结果依然可能溢出，而此时 `mid` 会变成一个负数，造成越界。

而且，整型溢出不仅在 C 语言中存在。在最近的一次 [中科大比赛](https://blog.sigmerc.top/hackergame2019/) 中我们就遇到了对 js 整型溢出的利用。

## Linux 基础

课程的第二部分介绍了一些 Linux 相关基础。Linux 是一个开源的 OS 内核，基于 C 和汇编编写，可执行文件格式是 ELF 格式，这也是我们后面要主要研究的。这里附上一个非常有趣的 [Linux 练习网站](http://overthewire.org/wargames/bandit/)。

安装与配置请自行搜索，推荐使用虚拟机安装。课程使用的发行版是 `Ubuntu 16.04LTS`，不过最近发现哈佛的 [CS50 IDE](https://ide.cs50.io/) 也非常好用。

下面是一些基础 Linux 命令：

### 目录管理

- `ls`
  - 列出当前目录下文件
  - `-a` 列出所有文件（包括隐藏的）
  - `-l` 详细信息
- `cd [path]`
  - 改变目录到 `path`
  - `.` 当前目录
  - `..` 上级目录
- `pwd`
  - 显示当前目录

### 文件操作

- `cat [file]`
  - 显示文件 `file` 的内容
- `more [file]`
  - 类似 `cat`，但对于长文件可以分页显示
- `mv [file1] [file2]`
  - 把 `file1` 移动到 `file2`，如果后者已存在则覆盖
- `cp [file1] [file2]`
  - 将 `file1` 复制到 `file2`，如果后者已存在则覆盖
- `rm [file]`
  - 删除文件 `file`
- `touch [file]`
  - 创建文件 `file`，或更新文件 `file` 的修改时间
- `mkdir [directory]`
  - 创建目录 `directory`
- `chmod [file]`
  - 改变文件 `file` 的权限

### 用户管理

- `sudo`
  - 以管理员权限执行命令
- `su [user]`
  - 切换到用户 `user`
- `whoami`
  - 显示当前用户用户名
- `id`
  - 显示当前用户 ID 和所在用户组 ID
- `passwd`
  - 更改当前用户密码

### 工作命令

- `date`
  - 显示当前系统时间
- `ps`
  - 显示当前运行进程
- `uname`
  - 显示系统相关信息
- `echo "hello"`
  - 在终端中显示 `hello`
  - `echo $((0xDEADBEEF))`
- `grep "hello"`
  - 查找含有 `hello` 的行并显示

### 特性

- 管道：从一个程序中获取输出，作为另一个程序的输入
  - `echo "hello" | /usr/games/cowsay`
  - `echo "hello" | /usr/games/cowsay | grep "hello"`
- 重定向：指定输入输出的来源，而不是直接读 `stdin` 写 `stdout`
  - `echo "hello" | /usr/games/cowsay > cowsay`
  - `echo "hello" > cowsay`
  - `echo "hello" >> cowsay`
- `man [command]`
  - 显示命令 `command` 的说明
- 方向 ↑ 键：上一条命令
- Tab 键：自动补全命令

这里通过 pwnable.kr 上的 `cmd1`，`cmd2` 和 `blukat` 三题，演示了 Linux 下的一些小把戏。

## C 程序运行机制

以 `Hello World` 程序为例：

```c
#include <stdio.h>

int main(int argc, char *argv[])
{
  printf("Hello World!\n");
  return 0;
}
```

这个程序到底是怎么运行起来的？我们分三步介绍：

1. 源代码被编译为机器语言，随后汇编为目标文件
2. 目标文件中引入相关依赖，链接为可执行文件（ELF）
3. 可执行文件载入内存并运行

![图 1](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/1.png)

编译一个程序非常简单，如果你的源代码是 `1.c`，那么只需要 `gcc 1.c` 就能生成一个叫做 `a.out` 的 ELF 文件，你也可以用 `-o` 选项来设置 ELF 文件的名字。

我们所要研究的就是 ELF 文件中究竟有什么。首先是 ELF 文件头，包含了 ELF 文件的许多元数据，我们可以用 `readelf -h a.out` 来查看：

![图 2](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/2.png)

ELF 文件的内容则是由一个个段 (segment) 组成的，如：

- 文本段 text segment
  - 程序的代码就在这里
- 数据段 data segment
  - 存储了程序中变量的数据等等
- 重定位段 reloc
  - 包含重定位信息，之后会具体讨论
- 符号表 symbol table
  - 存储了变量名、函数名等信息
- 字符串表 string table
  - 存储了只读字符串等信息

`objdump -s a.out` 可以帮助我们查看这些段的信息：

![图 3](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/3.png)

而如果要查看其中的汇编代码，就需要靠 `objdump -d a.out` 了：

![图 4](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/4.png)

我们注意到，上图中 `put@plt` 的地址是 `ff ff`，这是因为程序还没有进行第二步——链接。现在的 C 程序默认采用动态链接的方式，是因为传统静态链接容易造成重复链接比较浪费，同时也十分难维护。而动态链接会在运行时才进行链接。

最后，当我们 `./a.out` 运行程序时，可执行文件会被载入内存，不同的段将被分配不同的虚拟地址，并映射到对应的物理地址。当程序计数器指向了代码段的起始位置之后，我们的程序也就准备好开始运行了。

![图 5](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/5.png)

上图展示了虚拟地址是如何映射到物理地址的，同时也展示出 ELF 文件中的两个特殊的段：`heap` 段与 `stack` 段的生长方式。可以看到，堆是从低地址向高地址生长的，而栈是从高地址向低地址生长。但是，数据的存储却是从低地址向高地址存储，这也是我们能够实施栈溢出攻击的基础。

## C 语言函数调用栈

C 程序运行过程中，会持续地维护这个 `stack` 段也就是栈，用来控制函数调用的流程。当发生函数调用时，栈的主要任务是保存调用者函数 caller 的状态，并创建被调用函数 callee 的状态，这里的 “状态” 在栈上被称为栈帧，每个栈帧之间是相互独立的。

![图 6](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/6.png)

### 调用

在调用一个函数时，首先会将函数的参数**按倒序**压入栈中：

![图 7](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/7.png)

注意图中栈是向下生长的，下面的 `esp` 寄存器指向**栈顶**，而上面的 `ebp` 寄存器指向当前运行函数的栈帧的**底部**，也就是栈帧开始的地方。

接下来压入函数返回地址。当函数调用结束后，函数必定需要返回到调用它的语句的下一句处，但是它怎么知道它要返回到哪里？这只能由我们告诉他，方式就是存储到栈上。

![图 8](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/8.png)

这里存储到栈上的值实际上就是 caller 的 `eip`。`eip` 寄存器保存了 CPU 当前执行的指令的**下一条指令**的地址。

随后，我们压入 caller 的 `ebp`，并更新 `ebp` 的值。后者很好理解，因为我们现在进入到了 callee 这个函数了，栈帧基址当然也要跟着变化，那么前者是为什么呢？我们会在函数返回时发现这样做的原因。

最后就是压入局部变量了，这一步没有太多可以解释的。

![图 9](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/0.png)

### 返回

函数返回的第一步就是弹出局部变量，依然很简单：

![图 10](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/9.png)

第二步，我们要取出 caller 的 `ebp` 值并赋值给 `ebp`：

![图 11](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/10.png)

这里就可以很清晰地看到，我们在调用时为何要保存这个值了，如果不保存，那么返回的时候 `ebp` 不知道应该返回到哪里。而保存了 caller 的 `ebp` 实际上就是保存了 `caller` 栈帧的基址。

第三步弹出返回地址，第四步依次弹出参数。

为了让大家能对函数调用栈有一个更直观的认识，我演示了 pwnable.kr 上的 `random` 这题的解法，而为了解决这题，就不得不用到调试工具 gdb。

## gdb 简介

这里仅仅列出了一些最常用的 gdb 命令：

- `b 12` 在第 12 行下断点
- `b 1.c:12` 在 `1.c` 的 12 行下断点
- `b main` 在 `main` 函数下断点
- `b *0x8048abc` 在 `0x8048abc` 地址处下断点
- `r` 执行程序
- `c` 执行到下一个断点
- `s` 单步调试，遇到函数则进入
- `n` 单步调试，遇到函数不进入
- `until` 运行到退出循环
- `until 12` 运行到 12 行
- `q` 退出
- `info b` 查看所有断点
- `info func` 查看所有函数
- `p var` 打印出 C 语言变量 `var` 的值
- `bt` 查看函数调用栈
- `x/8xw 0x8048abc` 以 16 进制显示 `0x8048abc` 地址后 8 个内存单元的值，每个内存单元大小 4 字节
- `x/4ch 0x8048abc` 以字符格式显示 `0x8048abc` 地址后 4 个内存单元的值，每个内存单元大小 2 字节
- `help x` 查看关于命令 x 的帮助

## 缓冲区溢出漏洞——栈溢出

至此，可以介绍栈溢出了。栈溢出即通过覆盖栈上的数据，控制程序执行流程的一种攻击手段。攻击成功至少需要两个前提：

1. 程序必须向栈上写数据
2. 写入的数据大小没有被良好地控制

关于栈溢出，有这样一些 “危险函数” 是我们可以利用的：

- `gets`
- `scanf`
- `read`
- `sprintf`
- `strcpy`
- `strcat`

## Pwn 相关工具

为了真正实施攻击，一些辅助工具是必不可少的，例如：

- checksec 检查程序
- gdb 调试并分析程序
- peda 一个 gdb 的可视化插件
- pwndbg 另一个 gdb 的可视化插件
- IDA 著名的反编译工具
- pwntools 用于方便地编写攻击脚本的 python 库
- LibcSearcher 用于实施 ret2libc 攻击的 python 库
- ROPgadgets 用于实施 ROP 攻击的 python 库
- (netcat) 连接到远程主机上开放的服务的命令行工具
- (ssh) 登录远程主机的命令行工具

介绍完了这些，我演示了对于 pwnable.kr 的 `bof` 这题的攻击，通过溢出局部变量来覆盖函数参数的值。

## 花式栈溢出

栈溢出之所以值得开一门课来讲授，正是因为这种攻击有很多玩法，例如：

- Basic
  - ret2text
  - ret2shellcode
  - ret2syscall
  - ret2libc
  - ROP
  - GOT Hijacking
- Intermediate
  - ret2csu
  - ret2reg
  - BROP
- Advanced
  - ret2dl_runtime_resolve
  - SROP
  - ret2VDSO
  - JOP
  - COP
  - ...

本课程只介绍 Basic 部分。

### ret2text

首先介绍了 `ret2text`，即通过栈溢出覆盖函数的返回地址，以控制程序的控制流。在例题 bugku 的 `pwn2` 中，就是利用 `ret2text` 返回到了 `text` 段已经存在的一个后门函数来获取 shell。

### ret2shellcode

但不是什么时候程序中都会有一个现成的后门函数，因此有时我们需要自己创造条件。`ret2shellcode` 就是这样的攻击方法。我们向栈上写入一段恶意的汇编代码，随后利用程序中的漏洞执行栈上的这段代码即可完成攻击。Hackergame 的 `ShellHacker` 这道题就是一个很好的例子。

然而上面的两种攻击依然太过理想化了，现实中的程序往往不会那么容易被栈溢出攻击，因为开启了各种保护措施。

## 栈溢出保护

课程介绍了 4 种常见的栈溢出保护。其中，NX 使栈上的数据不可被执行；Canary 在局部变量和 caller's ebp 之间插入了一个随机值，并在函数返回时检查随机值是否被修改；PIE 将使整个进程中的数据地址变得随机，每次运行时都不相同；RELRO 使重定向段不可写。

- NX (No eXecution) 默认开启
  - Windows: DEP (Data Execution Prevention)
  - `gcc –z execstack` 禁用 NX
  - `gcc –z noexecstack` 启用 NX
- Canary 默认不开启
  - `gcc –fno-stack-protector` 禁用 canary
  - `gcc –fstack-protector` 只为局部变量中含有 char 数组的函数插入 canary
  - `gcc –fstack-protector-all` 为所有函数插入 canary
- PIE (Position-Independent Executables) 默认不开启
  - Windows: ASLR (Address Space Layout Randomization)
  - Level 0 - 表示关闭进程地址空间随机化
  - Level 1 - 表示将 mmap 的基址、栈和 VDSO 页面随机化
  - Level 2 - 表示在 1 的基础上增加堆的随机化
  - `gcc –fpie –pie` 开启 1 级 PIE
  - `gcc –fPIE –pie` 开启 2 级 PIE
- RELRO (RELocation Read Only) 默认 Partial
  - `gcc –z norelro` 关闭 RELRO
  - `gcc –z lazy` 部分开启 RELRO，GOT 表可写
  - `gcc –z now` 全部开启 RELRO

这些保护机制并不是那么容易绕过。为了突破这些保护，我们需要了解 32 位与 64 位汇编语言的知识。

## x86 汇编

汇编语言是 Intel 推出的一系列汇编的指令集合，有两种语法：

1. Intel 语法：`operand destination, source`

- `mov eax, 5`

2. AT&T 语法：`operand source, destination`

- `mov $5, %eax`

本课程将使用更简单的 Intel 语法（CSAPP 使用 AT&T 语法）。

### 重要寄存器

- eax ebx ecx edx 泛用型寄存器（eax 通常存储函数返回值）
- esp 指向栈帧顶部
- ebp 指向栈帧底部
- eip 指向下一条 CPU 将要执行的指令
- eflags 存储标志位
  - ZF 运算结果为 0 时置 1
  - CF 运算结果最高有效位发生进位或借位时置 1
  - SF 运算结果为负时置 1

![图 12](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/11.png)

### 数据操作

```asm
mov ebx, eax
mov eax, 0XDEADBEEF
mov edx, DWORD PTR [0x41424344]
mov ecx, DWORD PTR [edx]
mov eax, DWORD PTR [ecx+esi*8]

sub edx, 0x11
add eax, ebx
inc edx
dec ebx
xor eax, eax
or edx, 0x1337
```

写成类似的 C 伪代码即：

```c
ebx = eax;
eax = 0xDEADBEEF;
edx = *0x41424344;
ecx = *edx;
eax = *(ecx+esi*8);

edx -= 0x11;
eax += ebx;
edx++;
ebx--;
eax ^= eax;
edx |= 0x1337;
```

这里的 `DWORD PTR` 指 4 字节指针，相应的有 `BYTE PTR/WORD PTR/QWORD PTR` 表示 1/2/8 字节指针。注意 `[0x41424344]` 表示取地址 `0x41424344` 位置的值，如果里面是寄存器同理。

### 条件跳转

```asm
jz $LOC
jnz $LOC
jg $LOC
jle $LOC
```

分别表示，当上一条语句执行结果为：

- 0
- 非 0
- 目标操作数大于源操作数
- 目标操作数小于等于源操作数
  时，跳转到 `$LOC` 的位置。

### 函数调用

```asm
push ebx ; is equal to:
sub esp, 4
mov DWORD PTR [esp], ebx

pop ebx ; is equal to:
mov ebx, DWORD PTR [esp]
add esp, 4

call some_function ; is equal to:
push eip
mov eip, some_function ; actually invalid

ret ; is equal to:
pop eip ; actually invalid

nop ; do nothing
```

### 例：计算字符串长度

```asm
0x08048624: "MERCURY\0"
  mov ebx, 0x08048624
  mov eax, 0
LOOPY:
  mov cl, BYTE PTR [ebx]
  cmp cl, 0
  jz end
  inc eax
  inc ebx
  jmp LOOPY
end:
  ret
```

等效于下面的 C 代码：

```c
char *name = "MERCURY";
int len = 0;

while (*name != 0) {
  len++;
  name++;
}
return len;
```

## x86-64 汇编

再放一次这张图。
![图 13](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/11.png)

64 位架构下，新增了寄存器 `r8-r15`，用 `xmm0-xmm7` 存储浮点参数，同时原来的 `eax` 变成了 `rax` 等。但最重要的，还是传参方式的变化：函数前 6 个参数会被依次存储在寄存器 rdi, rsi, rdx, rcx, r8, r9 中，之后的参数才遵循栈上约定。

## 花式栈溢出：续

### 泄露 canary

介绍了这么多，终于可以演示一些保护机制的绕过方法了，首先是绕过 canary，这里采用了泄露 canary 的方式，实际上还有很多其他方式。前面提到过，canary 在栈上大概在这个位置：

```
| args       |
 ------------
| ret addr   |
 ------------  <- ebp
| saved ebp  |
 ------------
| padding    |
 ------------  <- ebp-0x??
| canary     |
 ------------
| local vars |
```

那么我们栈溢出时，从局部变量出发向上走，必定要经过 canary 并覆盖其值，那么函数返回时就会检测到，并终止程序。

然而，canary 在设计时规定末尾的字节必为 `00`，也就是 C 语言中的 `\0`，这是因为当我们打印栈信息时（从低地址向高地址打印），遇到 `00` 字节就会认为是字符串结束符，因此停止打印，这样 canary 的值就不会泄露。然而这同时也是我们可以利用的点。如果我们覆盖掉 canary 的最后一个字节为 `0a` 或者别的什么值，那么打印栈时就不会在 canary 处停下来，从而打印出 canary 的值。这是我们再将 `0a` 恢复为 `00` 便得到了完整的 canary 值。

得到 canary 后，我们只需要在栈溢出时注意，溢出到 canary 的位置的时候插入刚才得到的 canary 值，随后继续正常溢出，那么函数返回时就会认为 canary 未被修改，绕过了检查。

### GOT & PLT

为了更好地理解接下来的攻击技术，这里主要介绍了 Linux 中函数调用时的延迟绑定规则，这就涉及到 ELF 文件中的两个段：`.plt` 段与 `.got.plt` 段（实际上，GOT 表被分成 `.got` 与 `.got.plt` 两个段，前者与函数无关），分别对应我们的 Procedure Linkage Table 和 Global Offset Table。所谓延迟绑定，即一个函数的真实地址直到其第一次被调用时才会确定。

我们以 Hello World 程序的 `puts` 函数调用为例，调用语句是 `call <puts@plt>`。我们假设 `.plt` 结构如下：

![图 14](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/12.png "图 14")

称 `.plt` 开头的三条指令为 `.plt[0]`，`puts` 的 PLT 表是 `.plt[1]`，那么第一次调用 `puts` 时会访问 `puts@plt` 也就是 `.plt[1]`。`.plt[1]` 会跳转到 `puts` 对应的 GOT 表条目 `.got.plt[3]`。为什么下标是 3？这是因为 `.got.plt` 段是长这样的：

![图 15](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/BinaryExp/13.png "图 15")

可以看到，`.got.plt` 的前三条指令不属于任何函数，他们分别存储着：

- `.dynamic` 动态链接信息
- 模块 ID
- 动态链接器中的 `dl_runtime_resolve_avx()` 函数地址

于是 `puts` 的 GOT 表项就被挤到下标为 3 的地方去了。

在第一次调用前，`.got.plt[3]` 指向 `.plt[1]` 的下一条指令的地址，也就是说直接让 `.plt[1]` 继续执行下去，就好像它没有访问过 `.got.plt[3]` 一样。

随后，我们的 `.plt[1]` 的第二条指令会跳转到 `.plt[0]`，后者再跳转到 `.got.plt[2]`，也就是 `dl_runtime_resolve_avx()` 函数的地址去调用该函数，该函数从 `libc.so` 中拿到 `puts` 的真实地址，并写入 `.got.plt[3]` 中。至此，`puts` 函数的延迟绑定工作完成了。

接下来，在第 `n>=1` 次调用中，当我们再次访问 `.plt[1]` 时，又会去取 `.got.plt[3]` 中的地址，注意此时这里已经存好了 `puts` 的真实地址，那么我们就调用成功了。

### ret2libc

这样以后就能介绍 `ret2libc` 了，这是在没有诸如 `system` 和 `/bin/sh` 字符串的情况下，通过返回到 `libc` 动态链接库中查找 `system` 函数地址和 `/bin/sh` 字符串地址，来执行 `system("/bin/sh")` 的攻击。为此，我们需要通过栈溢出泄露出 `libc` 中某个函数的真实地址，例如 `__libc_start_main` 等，随后使用 `LibcSearcher` 搜索出程序使用的 `libc` 版本，从而获得 `libc` 基址，以及 `system` 和 `/bin/sh` 的偏移量。将基址和偏移相加就可以得到两者的真实地址。这种攻击不仅可以绕过 NX 保护，同时由于 PIE 不会随机化函数地址的低 12 位，而泄露出 `__libc_start_main` 的低 12 位就可以确定 `libc` 版本，`ret2libc` 攻击在 PIE 保护下也不会失效。

### ROP & ret2syscall

同样我们还可以 `ret2syscall`。我们想做的就是构造系统调用 `execve("/bin/sh",NULL,NULL)`。为此，我们需要：

1. 让 `eax` 等于 `0xb`（`execve` 的系统调用号）
2. 找到 `/bin/sh` 字符串的地址
3. 让 `ebx` 等于 `/bin/sh` 字符串的地址
4. 让 `ecx` 和 `edx` 等于 0
5. 找到 `int 0x80` 语句的地址，并返回到这句语句上

可以发现，这里我们需要控制寄存器的值，但是我们是无法直接控制的，而是需要通过一些 `gadgets` 来控制。

回顾 x86 汇编部分，我们介绍了 `push` 和 `pop` 两种对称的操作。然而，没有人规定这两个操作必须成对出现。如果我们先布置好栈顶的值，然后跳转到 `pop eax` 指令所在的地址并执行，那么栈顶的值就会被赋值给 `eax`，这样，我们相当于控制了寄存器的值。

但是，跳转到 `pop eax` 后，我们还需要控制 `ebx` 等寄存器，还需要跳转到别的地方，此时的跳转我们同样要通过修改返回地址实现，因此我们必须要有返回语句，也就是 `ret`。因此 `pop eax; ret` 这样的语句我们就称之为一个 `gadget`。

我们可以通过栈溢出先在栈上布置好我们想 `pop` 出去的值，通过 `ROPgadget` 工具寻找一些这样的 `gadgets`（还可以找 `/bin/sh` 地址和 `int 0x80` 地址）也依次放到栈上，那么我们就构造了一条 ROP(Return Oriented Programming) 链：

```
| int 0x80                       |
 --------------------------------
| addr of /bin/sh                |
 --------------------------------
| 0                              |
 --------------------------------
| 0                              |
 --------------------------------
| pop edx; pop ecx; pop ebx; ret |
 --------------------------------
| 0xb                            |
 --------------------------------
| pop eax; ret                   |
```

### GOT Hijacking

栈溢出部分最后介绍的是 GOT Hijacking，也就是 GOT 表劫持。当程序开启 `Partial RELRO` 时，GOT 表是可写的，那么我们就可以将一个现有的普通函数例如 `fflush` 的 GOT 表地址放在栈上，随后利用程序漏洞（如 `scanf` 不加 `&` 等）向该地址写入另一个地址，如 `system("/bin/sh")` 的地址，那么当我们执行 `fflush()` 时，由于其 GOT 表已经被劫持到了 `system("/bin/sh")`，实际执行的是后者。

## 格式化字符串漏洞

课程最后介绍的是格式化字符串漏洞，大家都比较熟悉格式化字符串。其完整格式形如：

```
%[parameter][flags][field width][.precision][length]type
```

这里我们主要关注 `parameter` 和 `type`。`parameter` 处一个广为人知的攻击点是 `n$`，例如：

```c
printf("%2$d %2$#x; %1$d %1$#x",16,17)
```

这句语句中，`2$` 就是值格式化字符串后的第 2 个参数。

类似地，`type` 中的攻击点在于 `%n` 这个类型，指定为该类型时，不输出，而是将已成功输出的字符数写入对应的整型指针参数所指的变量。这可以用来写内存，不过课程并没有涉及这一点。

为了利用该漏洞，首先要理解格式化字符串的工作原理。对于语句；

```c
printf("Color %s, Number %d, Float %4.2f", "red", 123456, 3.1416);
```

会输出

```
Color red, Number 123456, Float 3.14
```

栈上布局为：

```
| 3.1416                  |
 -------------------------
| 123456                  |
 -------------------------
| addr of "red"           |
 -------------------------
| addr of "Color %s, ..." |
```

`printf` 函数在读格式化字符串时，如果遇到 `%`，那么就会去读取对应位置的参数并解析，这个参数位于栈上。那么，如果我的语句是：

```c
printf("Color %s, Number %d, Float %4.2f");
```

即参数个数不匹配，会怎么样呢？

答案是 `printf` 照常解析，此时栈上原本应该放参数的那个位置上的内容就会被读取并打印出来。利用这个漏洞，我们就可以泄露栈内存。实际上，可以泄露任意地址内存。

举个例子，当程序运行时我们发现用户输入的参数被存储在了栈上，并且栈上还有 `__libc_start_main` 的地址。那么我们可以计算两者在栈上的偏移量 `offset`，随后：

- 除以 4（32 位）
- 除以 8 后加 6（64 位，别忘了 6 个存参数的寄存器）

得到的就是，`__libc_start_main` 可以被认为是 `printf` 的第几个参数。假如是第 11 个参数，那么我们只要构造语句 `printf("%11$p");` 即可泄露 `__libc_start_main` 的地址，从而实施 `ret2libc` 攻击。

## 参考资料

- https://pwnable.kr/
- https://ctf-wiki.github.io/ctf-wiki/pwn/readme-zh/
- https://ctf.bugku.com/challenges
- https://zhuanlan.zhihu.com/p/25816426
- http://security.cs.rpi.edu/courses/binexp-spring2015/
- https://ropemporium.com/guide.html
- 所有使用的工具的官方文档
- 《深入理解计算机系统》（CS: APP）
