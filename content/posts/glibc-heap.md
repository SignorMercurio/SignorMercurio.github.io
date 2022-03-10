---
title: 盘根错节：GLibc 堆内存管理机制简介
date: 2019-12-08 16:53:39
tags:
  - C/C++
  - 堆漏洞
categories:
  - 二进制安全
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/GLibcHeap/0.png
---

The heap is a beautiful mess.

<!--more-->

本文将对 Glibc 堆上的内存管理作简要介绍，部分内容翻译自参考资料中的文章。略过了许多细节，主要是为了对新手友好。

默认读者熟悉操作系统、C 语言及其运行机制，并且对于 C 中的函数调用栈有所了解。

## 什么是堆？

堆是每个程序被分配到的一块内存区域，和栈的区别主要在于堆内存是动态分配的。也就是说，程序可以从 `heap` 段请求一块内存，或者释放一块内存。

另外，堆内存是全局的，即在程序的任意位置都可以访问到堆，并不一定要在调用 `malloc` 的那个函数里访问。这是因为 C 语言使用指针指向动态分配的内存。但相比访问栈上的静态局部变量，使用指针也带来了一定的开销。

## 使用动态分配的内存

GLibc 采用 ptmalloc2 内存分配器管理堆内存，相比前身 dlmalloc，它增加了对多线程的支持。多线程的好处就不多赘述了。

借助 `stdlib.h` 我们可以使用 `malloc` 和 `free` 函数来操作堆内存：

```c
char *buffer = (char *)malloc(10);

strcpy(buffer,"hello");
printf("%s\n", buffer);

free(buffer);
```

第一行分配了 10 字节给 `buffer`，注意这里的强制类型转换是必须的；第 2-3 行使用了 `buffer` 这块内存，并在最后一行释放。

下面是 `malloc` 和 `free` 函数的注释：

```c
/*
  malloc(size_t n)
  Returns a pointer to a newly allocated chunk of at least n bytes, or null
  if no space is available. Additionally, on failure, errno is
  set to ENOMEM on ANSI C systems.

  If n is zero, malloc returns a minumum-sized chunk. (The minimum
  size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
  systems.)  On most systems, size_t is an unsigned type, so calls
  with negative arguments are interpreted as requests for huge amounts
  of space, which will often fail. The maximum supported value of n
  differs across systems, but is in all cases less than the maximum
  representable value of a size_t.
*/

/*
  free(void* p)
  Releases the chunk of memory pointed to by p, that had been previously
  allocated using malloc or a related routine such as realloc.
  It has no effect if p is null. It can have arbitrary (i.e., bad!)
  effects if p has already been freed.

  Unless disabled (using mallopt), freeing very large spaces will
  when possible, automatically trigger operations that give
  back unused memory to the system, thus reducing program footprint.
*/
```

注意，即使申请 0 字节内存，`malloc` 依然会分配一个最小的 chunk；如果传给 `free` 的参数是空指针，`free` 不会做任何事，而如果传入的是一个已经 `free` 过的指针，那么后果是不可预期的。这里尤其需要注意的是，与 `Java` 等语言不同，C 语言中释放掉分配到的内存的责任在于程序员，并且分配到的内存只应使用*一次*。

这两个函数在更底层上是使用 `brk()` 和 `mmap()` 这两个系统调用来管理内存的。

## 两个系统调用

注意申请内存时，Linux 内核只会先分配一段虚拟内存，真正使用时才会映射到物理内存上去。

### brk()

`brk()` 通过增加 `break location` 来获取内存，一开始 `heap` 段的起点 `start_brk` 和 `heap` 段的终点 `brk` 指向同一个位置。

- ASLR 关闭时，两者指向 data/bss 段的末尾，也就是 `end_data`
- ASLR 开启时，两者指向 data/bss 段的末尾加上一段随机 brk 偏移

![图 1｜Process Virtual Memory Layout]({{< param cdnPrefix >}}/GLibcHeap/1.png)

> 注：注意与 `sbrk()` 的区别，后者是 C 语言库函数，`malloc` 源码中的 `MORECORE` 就是调用的 `sbrk()`。

### mmap()

用于创建私有的匿名映射段，主要是为了分配一块新的内存，且这块内存只有调用 `mmap()` 的进程可以使用，所以称之为私有的。与之进行相反操作的是 `munmap()`，删除一块内存区域上的映射。

## 多线程与 Arena

前面提到，ptmalloc2 的一大改进就在于多线程，那么他是如何做到的呢？不难猜到，每个线程必定要维护一些独立的数据结构，并且对这些数据结构的访问是需要加锁的。的确，在 ptmalloc2 中，每个线程拥有自己的 `freelist`，也就是维护空闲内存的一个链表；以及自己的 `arena`，一段连续的堆内存区域。特别地，主线程的 `arena` 叫做 `main_arena`。注意**只有 `main_arena` 可以访问 `heap` 段和 `mmap` 映射区域，`non_main_arena` 只能访问 `mmap` 映射区域**。

> 注：线程较多时，互斥锁机制会导致性能下降。

当我们在程序中第一次申请内存时还没有 `heap` 段，因此 132KB 的 `heap` 段，也就是我们的 `main_arena`，会被创建（**通过 `brk()`调用**），无论我们申请的内存是多大。对于接下来的内存申请，`malloc` 都会从 `main_arena` 中尝试取出一块内存进行分配。如果空间不够，`main_arena` 可以通过 `brk()` 扩张；如果空闲空间太多，也可以缩小。

那么对于 `non_main_arena` 呢？前面提到它只能访问 `mmap` 映射区域，因为在创建时它就是由 `mmap()` 创建的——1MB 的内存空间会被映射到进程地址空间，不过实际上只有 132KB 是可读写的，这 132KB 就是该线程的 `heap` 结构，或者叫 `non_main_arena`。

> 注：当然了，当申请的空间大于 128KB 且 `arena` 中没有足够空间时，无论在哪个 `arena` 里都只能通过 `mmap()` 分配内存。

`arena` 也不是和线程一对一的，实际上有数量限制：

```
For 32 bit systems:
     Number of arena = 2 * number of cores.
For 64 bit systems:
     Number of arena = 8 * number of cores.
```

而当我们 `free` 一小块内存时，内存也不会直接归还给内核，而是给 ptmalloc2 让他去维护，后者会将空闲内存丢入 bin 中，或者说 `freelist` 中也可以。如果过了一会我们的程序又要申请内存，那么 ptmalloc2 就会从 bin 中找一块空闲的内存进行分配，找不到的话才会去问内核要内存。

## 维护多个堆

前面提到，`main_arena` 只有一个堆，并且可以灵活地放缩；`non_main_arena` 则只能通过 `mmap()` 获得一个堆。那么如果 `non_main_arena` 里分配的堆内存不够了怎么办？很简单，再 `mmap()` 一次，创建一个新的堆。

所以，在 `non_main_arena` 里，我们必须考虑如何维护多个堆的问题。这里我们会涉及三个头部：

- `heap_info`：每个堆的头部，`main_arena` 是没有的
- `malloc_state`：`arena` 的头部，`main_arena` 的这个部分是**全局变量**而不属于堆段
- `malloc_chunk`：每个 chunk 的头部

具体一点，`heap_info` 完整定义如下：

```c
typedef struct _heap_info
{
  mstate ar_ptr; /* Arena for this heap. */
  struct _heap_info *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected
                           PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;
```

而 `malloc_state` 的完整定义如下：

```c
struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```

其中 `INTERNAL_SIZE_T` 默认和 `size_t` 相同：

```c
#ifndef INTERNAL_SIZE_T
#define INTERNAL_SIZE_T size_t
#endif
```

在后面介绍 chunk 和 bin 的时候，我们会发现其中几个字段的作用，`malloc_chunk` 我们也会在后面看到。

对于 `arena` 中只有单个堆的情况：

![图 2｜Single Heap]({{< param cdnPrefix >}}/GLibcHeap/2.png)

对于 `non_main_arena` 中有多个堆的情况：

![图 3｜Multiple Heap]({{< param cdnPrefix >}}/GLibcHeap/3.png)

注意到有多个堆的情况下，旧的堆的 Top chunk 会被认为是普通的空闲块。

## Chunk 的结构

通俗地说，一块由分配器分配的内存块叫做一个 chunk，包含了元数据和用户数据。具体一点，chunk 完整定义如下：

```c
struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;                /* double links -- used only if free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

typedef struct malloc_chunk* mchunkptr;
```

这里出现的 6 个字段均为元数据。

一个 chunk 可以是以下几种类型之一：

- 已分配的（Allocated chunk）
- 空闲的（Free chunk）
- Top chunk
- Last Remainder chunk

我们一个一个来看。

### Allocated chunk

![图 4｜Allocated chunk]({{< param cdnPrefix >}}/GLibcHeap/4.png)

第一个部分（32 位上 4B，64 位上 8B）叫做 `prev_size`，只有在前一个 chunk 空闲时才表示前一个块的大小，否则这里就是无效的，可以被前一个块征用（存储用户数据）。

> 这里的前一个 chunk，指内存中相邻的前一个，而不是 freelist 链表中的前一个。`PREV_INUSE` 代表的 “前一个 chunk” 同理。

第二个部分的高位存储当前 chunk 的大小，低 3 位分别表示：

- P: `PREV_INUSE` 之前的 chunk 已经被分配则为 1
- M: `IS_MMAPED` 当前 chunk 是 `mmap()` 得到的则为 1
- N: `NON_MAIN_ARENA` 当前 chunk 在 `non_main_arena` 里则为 1

对应源码如下：

```c
/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->size & PREV_INUSE)


/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)


/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
#define NON_MAIN_ARENA 0x4

/* check for chunk from non-main arena */
#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)
```

你可能会有几个困惑：

1. `fd`、`bk`、`fd_nextsize`、`bk_nextsize` 这几个字段去哪里了？
   对于已分配的 chunk 来说它们没用，所以也被征用了，用来存储用户数据。

2. 为什么第二个部分的低 3 位就这么被吞了而不会影响 `size`？
   这是因为 `malloc` 会将用户申请的内存大小转化为实际分配的内存，以此来满足（至少）8 字节对齐的要求，同时留出额外空间存放 chunk 头部。由于（至少）8 字节对齐了，低 3 位自然就没用了。在获取真正的 `size` 时，会忽略低 3 位：

```c
/*
   Bits to mask off when extracting size

   Note: IS_MMAPPED is intentionally not masked off from size field in
   macros for which mmapped chunks should never be seen. This should
   cause helpful core dumps to occur if it is tried by accident by
   people extending or adapting this malloc.
 */
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

/* Get size, ignoring use bits */
#define chunksize(p)         ((p)->size & ~(SIZE_BITS))
```

3. `malloc` 是如何将申请的大小转化为实际分配的大小的呢？
   核心在于 `request2size` 宏：

```c
/* pad request bytes into a usable size -- internal version */

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK <MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
```

其中用到的其它宏定义：

```c
#  define MALLOC_ALIGNMENT       (2 *SIZE_SZ)

/* The corresponding bit mask value */
#define MALLOC_ALIGN_MASK      (MALLOC_ALIGNMENT - 1)

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))

/* The smallest size we can malloc is an aligned minimal chunk */
#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
```

4. 这里还有一个 `mem` 指针，是做什么用的？
   这是调用 `malloc` 时返回给用户的指针。实际上，真正的 chunk 是从 `chunk` 指针开始的。

```c
/* The corresponding word size */
#define SIZE_SZ                (sizeof(INTERNAL_SIZE_T))

/* conversion from malloc headers to user pointers, and back */

#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char*)(mem) - 2*SIZE_SZ))
```

5. 用户申请的内存大小就是用户数据可用的内存大小吗？
   不一定，原因还是字节对齐问题。要获得可用内存大小，可以用 `malloc_usable_size()` 获得，其核心函数是：

```c
static size_t
musable (void *mem)
{
  mchunkptr p;
  if (mem != 0)
    {
      p = mem2chunk (mem);

      if (__builtin_expect (using_malloc_checking == 1, 0))
        return malloc_check_get_size (p);

      if (chunk_is_mmapped (p))
        return chunksize (p) - 2 * SIZE_SZ;
      else if (inuse (p))
        return chunksize (p) - SIZE_SZ;
    }
  return 0;
}
```

### Free chunk

![图 5｜Free chunk]({{< param cdnPrefix >}}/GLibcHeap/5.png)

首先，`prev_size` 必定存储上一个块的用户数据，因为 Free chunk 的上一个块必定是 Allocated chunk，否则会发生合并。

接着，多出来的 `fd` 指向同一个 bin 中的前一个 Free chunk，`bk` 指向同一个 bin 中的后一个 Free chunk。

这里提到了 bin，我们将在后面介绍。

此外，对于 large bins 中的 Free chunk，`fd_nextsize` 与 `bk_nextsize` 会生效，分别指向 large bins 中前一个（更大的）和后一个（更小的）空闲块。

### Top chunk

一个 `arena` 顶部的 chunk 叫做 Top chunk，它不属于任何 bin。当所有 bin 中都没有空闲的可用 chunk 时，我们切割 Top chunk 来满足用户的内存申请。假设 Top chunk 当前大小为 N 字节，用户申请了 K 字节的内存，那么 Top chunk 将被切割为：

- 一个 K 字节的 chunk，分配给用户
- 一个 N-K 字节的 chunk，称为 Last Remainder chunk

后者成为新的 Top chunk。如果连 Top chunk 都不够用了，那么：

- 在 `main_arena` 中，用 `brk()` 扩张 Top chunk
- 在 `non_main_arena` 中，用 `mmap()` 分配新的堆

> 注：Top chunk 的 PREV_INUSE 位总是 1

### Last Remainder chunk

当需要分配一个比较小的 K 字节的 chunk 但是 small bins 中找不到满足要求的，且 Last Remainder chunk 的大小 N 能满足要求，那么 Last Remainder chunk 将被切割为：

- 一个 K 字节的 chunk，分配给用户
- 一个 N-K 字节的 chunk，成为新的 Last Remainder chunk

它的存在使得连续的小空间内存申请，分配到的内存都是相邻的，从而达到了更好的局部性。

## Bin 的结构

bin 是实现了空闲链表的数据结构，用来存储空闲 chunk，可分为：

- 10 个 fast bins，存储在 `fastbinsY` 中
- 1 个 unsorted bin，存储在 `bin[1]`
- 62 个 small bins，存储在 `bin[2]` 至 `bin[63]`
- 63 个 large bins，存储在 `bin[64]` 至 `bin[126]`

还是一个一个来看。

### fast bins

非常像高速缓存 cache，主要用于提高小内存分配效率。相邻空闲 chunk 不会被合并，这会导致外部碎片增多但是 `free` 效率提升。注意 fast bins 是 10 个 **LIFO 的单链表**。最后三个链表保留未使用。

chunk 大小（含 chunk 头部）：0x10-0x40（64 位 0x20-0x80）B，相邻 bin 存放的大小相差 0x8（0x10）B。

![图 6｜fast bins]({{< param cdnPrefix >}}/GLibcHeap/6.png)

> 注：加入 fast bins 的 chunk，它的 `IN_USE` 位（准确地说，是下一个 chunk 的 `PREV_INUSE` 位）依然是 1。这就是为什么相邻的 “空闲”chunk 不会被合并，因为它们根本不会被认为是空闲的。

关于 fastbin 最大大小，参见宏 `DEFAULT_MXFAST`：

```c
#ifndef DEFAULT_MXFAST
#define DEFAULT_MXFAST     (64 * SIZE_SZ / 4)
#endif
```

在初始化时，这个值会被赋值给全局变量 `global_max_fast`。

申请 fast chunk 时遵循 `first fit` 原则。释放一个 fast chunk 时，首先检查它的大小以及对应 fastbin 此时的第一个 chunk `old` 的大小是否合法，随后它会被插入到对应 fastbin 的链表头，此时其 `fd` 指向 `old`。

### unsorted bin

非常像缓冲区 buffer，大小超过 fast bins 阈值的 chunk 被释放时会加入到这里，这使得 ptmalloc2 可以复用最近释放的 chunk，从而提升效率。

unsorted bin 是一个双向循环链表，chunk 大小：大于 `global_max_fast`。
![图 7｜unsorted bin]({{< param cdnPrefix >}}/GLibcHeap/0.png)

当程序申请大于 `global_max_fast` 内存时，分配器遍历 unsorted bin，每次取最后的一个 unsorted chunk。

1. 如果 unsorted chunk 满足以下四个条件，它就会被切割为一块满足申请大小的 chunk 和另一块剩下的 chunk，前者返回给程序，后者重新回到 unsorted bin。

   - 申请大小属于 small bin 范围
   - unosrted bin 中只有该 chunk
   - 这个 chunk 同样也是 last remainder chunk
   - 切割之后的大小依然可以作为一个 chunk

2. 否则，从 unsorted bin 中删除 unsorted chunk。
   - 若 unsorted chunk 恰好和申请大小相同，则直接返回这个 chunk
   - 若 unsorted chunk 属于 small bin 范围，插入到相应 small bin
   - 若 unsorted chunk 属于 large bin 范围，则跳转到 3。
3. 此时 unsorted chunk 属于 large bin 范围。
   - 若对应 large bin 为空，直接插入 unsorted chunk，其 `fd_nextsize` 与 `bk_nextsize` 指向自身。
   - 否则，跳转到 4。
4. 到这一步，我们需按大小降序插入对应 large bin。
   - 若对应 large bin 最后一个 chunk 大于 unsorted chunk，则插入到最后
   - 否则，从对应 large bin 第一个 chunk 开始，沿 `fd_nextsize`（即变小）方向遍历，直到找到一个 chunk `fwd`，其大小小于等于 unsorted chunk 的大小
     - 若 `fwd` 大小等于 unsorted chunk 大小，则插入到 `fwd` 后面
     - 否则，插入到 `fwd` 前面

直到找到满足要求的 unsorted chunk，或无法找到，去 top chunk 切割为止。

### small bins

小于 0x200（0x400）B 的 chunk 叫做 small chunk，而 small bins 可以存放的就是这些 small chunks。chunk 大小同样是从 16B 开始每次 + 8B。

small bins 是 62 个双向循环链表，并且是 FIFO 的，这点和 fast bins 相反。同样相反的是相邻的空闲 chunk 会被合并。

chunk 大小：0x10-0x1f0B（0x20-0x3f0），相邻 bin 存放的大小相差 0x8（0x10）B。

释放非 fast chunk 时，按以下步骤执行：

1. 若前一个相邻 chunk 空闲，则合并，触发对前一个相邻 chunk 的 `unlink` 操作
2. 若下一个相邻 chunk 是 top chunk，则合并并结束；否则继续执行 3
3. 若下一个相邻 chunk 空闲，则合并，触发对下一个相邻 chunk 的 `unlink` 操作；否则，设置下一个相邻 chunk 的 `PREV_INUSE` 为 `0`
4. 将现在的 chunk 插入 unsorted bin。
5. 若 `size` 超过了 `FASTBIN_CONSOLIDATION_THRESHOLD`，则尽可能地合并 fastbin 中的 chunk，放入 unsorted bin。若 top chunk 大小超过了 `mp_.trim_threshold`，则归还部分内存给 OS。

```c
#ifndef DEFAULT_TRIM_THRESHOLD
#define DEFAULT_TRIM_THRESHOLD (128 * 1024)
#endif

#define FASTBIN_CONSOLIDATION_THRESHOLD  (65536UL)
```

### large bins

大于等于 0x200（0x400）B 的 chunk 叫做 large chunk，而 large bins 可以存放的就是这些 large chunks。

large bins 是 63 个双向循环链表，插入和删除可以发生在任意位置，相邻空闲 chunk 也会被合并。chunk 大小就比较复杂了：

- 前 32 个 bins：从 0x200B 开始每次 + 0x40B
- 接下来的 16 个 bins：每次 + 0x200B
- 接下来的 8 个 bins：每次 + 0x1000B
- 接下来的 4 个 bins：每次 + 0x8000B
- 接下来的 2 个 bins：每次 + 0x40000B
- 最后的 1 个 bin：只有一个 chunk，大小和 large bins 剩余的大小相同

注意同一个 bin 中的 chunks 不是相同大小的，按大小降序排列。这和上面的几种 bins 都不一样。而在取出 chunk 时，也遵循 `best fit` 原则，取出满足大小的最小 chunk。

## 内存分配流程

我觉得这类复杂的流程比较需要靠流程图来理解，因此我画了一下：

![图 8｜Procedure of malloc()]({{< param cdnPrefix >}}/GLibcHeap/7.png)

相关宏：

```c
#define NBINS             128
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT> 2 * SIZE_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)

#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) <(unsigned long) MIN_LARGE_SIZE)

#ifndef DEFAULT_MMAP_THRESHOLD_MIN
#define DEFAULT_MMAP_THRESHOLD_MIN (128 * 1024)
#endif

#ifndef DEFAULT_MMAP_THRESHOLD
#define DEFAULT_MMAP_THRESHOLD DEFAULT_MMAP_THRESHOLD_MIN
#endif
```

## 内存释放流程

![图 9｜Procedure of free()]({{< param cdnPrefix >}}/GLibcHeap/8.png)

## 参考资料

- [Heap Exploitation](https://heap-exploitation.dhavalkapil.com/)
- [Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)
- [Syscalls used by malloc](https://sploitfun.wordpress.com/2015/02/11/syscalls-used-by-malloc/)
- [glibc 内存管理 ptmalloc 源代码分析](https://paper.seebug.org/papers/Archive/refs/heap/glibc内存管理ptmalloc源代码分析.pdf)
- [Painless intro to the Linux userland heap](https://sensepost.com/blog/2017/painless-intro-to-the-linux-userland-heap/)
