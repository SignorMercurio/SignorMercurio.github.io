---
title: Pwn 脚本模板
date: 2020-04-26 22:03:39
tags:
  - Python
  - 模版
categories:
  - 系统安全
---

其中从 `# start` 到 `# end` 中间的部分为核心代码。最近更新的博客中 Pwn 题脚本的代码仅包含核心代码。

<!--more-->

## 依赖

- 必需
  - pwntools
  - gdb
  - Python 2 / 3
  - Ubuntu 16.x / 18.x / 19.x
- 非必需（可将对应功能注释掉）
  - LibcSearcher
  - one_gadget
  - patchelf
  - glibc-all-in-one

## 说明

- `leak_libc` 函数可以选择使用指定 ELF 文件或是利用 LibcSearcher 搜寻 libc
- 使用不同于系统版本的 libc 时，需要用到 patchelf 工具
- 增删改查功能的序号以及发送内容的逻辑，请根据具体题目修改
- 主要代码放在 `# start` 和 `# end` 之间
- 远程运行时必须指定 `-p` 选项
- 其它功能请运行 `python exp.py -h` 查询

## 代码

```python
from pwn import  *
from LibcSearcher import LibcSearcher
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

s = lambda data: p.send(str(data))
sa = lambda delim,data: p.sendafter(delim,str(data))
sl = lambda data: p.sendline(str(data))
sla = lambda delim,data: p.sendlineafter(delim,str(data))
r = lambda num=4096: p.recv(num)
ru = lambda delims,drop=True: p.recvuntil(delims,drop)
uu64 = lambda data: u64(data.ljust(8,'\0'))
leak = lambda name,addr: log.success('{} = {:#x}'.format(name, addr))

def leak_libc(func,addr,elf=None):
    if elf:
        libc = elf
        base = addr-libc.sym[func]
        leak('base',base)
        system = base+libc.sym['system']
    else:
        libc = LibcSearcher(func,addr)
        base = addr-libc.dump(func)
        leak('base',base)
        system = base+libc.dump('system')

    return (base,libc,system)

parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
parser.add_argument('-b',help='binary file',required=True,metavar='BINARY')
parser.add_argument('-r',help='remote host',default='node3.buuoj.cn',metavar='RHOST')
parser.add_argument('-p',type=int,help='remote port',metavar='RPORT')
parser.add_argument('-l',help='libc - [xx] for v2.xx, or [/path/to/libc.so.6] to load a specific libc',default='23',metavar='LIBC')
parser.add_argument('-d',help='disable DEBUG mode',action='store_true')
args = parser.parse_args()
print(args)

binary = args.b
context.binary = binary
elf = ELF(binary,checksec=False)
if not args.d:
    context.log_level = 'DEBUG'

path_dict = {
    '23': '/lib/x86_64-linux-gnu/libc.so.6',
    '27': './glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so',
    '29': './glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc-2.29.so'
}
libc_path = path_dict.get(args.l, args.l)
libc = ELF(libc_path,checksec=False)
if args.p:
    p = remote(args.r, args.p)
else:
    p = process(binary,env={'LD_PRELOAD':libc_path})

def dbg():
    gdb.attach(p)
    pause()

_add,_free,_edit,_show = 1,4,2,3
def add(index,content='a'*8):
    sla(':',_add)
    sla(':',index)
    sa(':',content)

def free(index):
    sla(':',_free)
    sla(':',index)

def edit(index,content):
    sla(':',_edit)
    sla(':',index)
    sa(':',content)

def show(index):
    sla(':',_show)
    sla(':',index)

# start

# end

p.interactive()
```
