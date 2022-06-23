---
title: 星罗棋布：《分布式系统与安全》课程笔记
date: 2021-10-18 11:04:07
lastmod: 2022-03-10 12:16:42
tags:
  - Linux
  - 分布式系统
categories:
  - 探索
featuredImage: 0.png
---

COMP0133《分布式系统与安全》是我从本科到硕士期间最有价值的课。

<!--more-->

{{< katex >}}

## 序

我最初因为选了《恶意软件》这门课，没敢选同一学期同样硬核的《分布式系统与安全》。后来一方面是因为《恶意软件》过于形式化、一方面是因为接触了分布式系统的生态，我选择了换课。第一节课开始没多久，我便确信自己做出了明智的（或许还是影响深远的）决定。

Brad Karp 老师讲解清晰又不失风趣，硬是把线上课上出了线下课的体验。尽管才上了两周的课，我相信这门课会让我受益匪浅。

> 一开始给我留下比较好的印象的就是老师摒弃了学校的课程平台 Moodle，转而使用 GitHub Classroom 和 Piazza。众所周知，所谓学校的课程平台并不会给师生带来什么好的体验。
>
> 此外，GitHub Classroom 还能自动测试和批改作业，很有意思，使用体验也很好。

这门课是没有教材的，这实际上对老师的水平提出了很高的要求：他必须自己四处收集资源备课、讲述自己的理解，而非将教材上的内容略作修改、照本宣科。取而代之的阅读材料是一系列经典论文。

## 背景

### 中心化系统面临的问题

- 单节点故障
- 难以支撑流量较大的应用
- 易受攻击，且受到攻击后损失较大（这其实也应该算到单节点故障里？可能不能算故障）
- 难以伸缩以提高资源利用率
- 升级与维护时必须中止服务
- 地理距离带来的网络延迟

### 分布式系统引入的问题

- 数据一致性
- 节点间的网络延迟、网络错误
- Heterogeneity 异质性，不同节点可能使用不同语言、接口、API 等
- 节点间并发问题
- Partition resilience，不知道怎么翻译，弹性划分问题？

> 关于 Partition resilience 问题：假设两个用户在两个不同的服务节点上同时购买了最后一张机票，这张机票就会被卖出两次。有点像数据一致性问题。

### OS 相关

这个部分基本是本科《操作系统》课的内容，记录时顺便复习下。

#### Syscall

例如，应用通过 `close(3)` 关闭文件。而在 C 函数库中是这样调用 syscall 的：

```c
close(x) {
  R0 <- 73
  R1 <- x
  TRAP
  RET
}
```

TRAP 实际上做的是：

```c
XP <- PC
// switch to kernel address space
// set privileged flag (to enter high privilege mode)
PC <- address of kernel trap handler
```

这里的 XP 是某个用来暂时存放 PC 的寄存器。我们容易想到，之后就要在内核中运行代码了，这其实是十分危险的操作。怎么保证应用不会在内核里乱搞呢？答案是 Protected Transfer 机制。

为了避免用户在内核里随便运行代码，只有通过 kernel entrypoint 进入内核才能运行代码，而这个 entrypoint 就是 trap handler。至于具体跳到内核的什么位置则由硬件决定，而不能由应用来指定。这个具体位置则**只能通过在启动时运行的内核态代码来决定**，确保了用户态程序无法随意跳转到内核任意位置。

接着，在内核的 trap handler 中：

```c
// save regs to this process' PCB
SP <- kernel stack
sys_close()
// executing in "kernel half" of process
// restore regs from PCB
TRAPRET
```

最后的 TRAPRET 的流程就比较简单了：

```c
PC <- XP
// clear privileged flag
// switch to process address space
// continue execution
```

可以看到，TRAP 和 TRAPRET 要保存 / 恢复 PC、切换地址空间、切换用户态 / 内核态，而 trap handler 要保存 / 恢复寄存器，这些过程是必需的但又并没有产生实际的价值，还相对比较耗时。

### 并发 IO

而且，Syscall 常常涉及阻塞 IO 操作，很大程度上降低了资源利用率。一般来说有如下三种解决方法：

- 多进程
- 单进程、多线程
- 事件驱动 IO

但首先，OS 本身对单进程单线程也提供了一定程度的并发 IO，比如：

- 在文件系统中，会进行 read-ahead 和 write-behind 预读写磁盘数据
- 类似地，`read()` 接收网络包时也会拷贝到 kernel socket buffer，`write()` 发送数据包时也会拷贝到 kernel socket buffer

#### 多进程

多进程很容易理解：当一个进程阻塞后，切换到另一个进程运行。优点在于：

- 进程间本身就相互隔离，不会互相影响
- （如果有多个 CPU）同时还自动获得了 CPU 并发

不过 CPU 并发没有 IO 并发那么重要，且相对 IO 并发而言更难实现，两者对速度的提升也是 2 倍和 100 倍的数量级。此时，氪金多买几台机器显然是更好的选择。

然而，多进程也有缺点：

- `fork()` 调用本身比较耗时、耗内存，300 微秒左右的耗时并不能通过提升机器配置来缩短
- 隔离性同时也是缺点，不共享内存意味着构建缓存或是记录统计数据比较麻烦

#### 多线程

另一种方法是使用更轻量级的线程，此时线程们共享内存且分别拥有自己的栈，维持了一定的独立性。这一好处带来的是非常棘手的问题，那就是线程之间本身会互相影响、线程对数据的读写同样如此，使得我们不得不引入锁的机制来避免这些问题。但是引入新机制又会带来新问题，比如饥饿、死锁等。

> 这很像之前看到的火箭工程：要让火箭飞起来就需要带足够的燃料，但这些燃料本身也有重量，于是需要更多的燃料让整个火箭飞起来……~~（坎巴拉太空计划核心玩法）~~

几乎所有现代操作系统都对多线程有原生支持，这一般是通过内核线程实现的。这种实现下，内核清楚地知道每个线程的状态，也可以亲自调度线程到 CPU 上，非常灵活且同时支持 CPU 并发和 IO 并发。对于线程来说，每个线程不仅需要原有的用户态栈，还需要维护自己的内核栈和寄存器表。

这么做的代价就是：

- 创建线程要内核干涉
- 线程上下文切换要内核干涉
- 加锁解锁也要内核干涉
- 实现起来很大程度上依赖于 OS，难以移植

至于用户线程，对内核来说就是不可见的，内核只负责调度进程。此时，进程内部就需要一个线程调度器，清晰地知道每个线程的状态如何并及时调度。这样我们就可以进行非阻塞式 Syscall 了：

```c
read() {
  // tell kernel to start read
  // mark thread waiting for read
  sched();
}

sched() {
  // ask kernel for IO completion events
  // mark corresponding threads runnable
  // find runnable thread
  // restore regs and return
}
```

看起来很不错，但是仔细想想，这中间涉及的事件通知机制，需要我们的调度器具备相当强大的能力。它需要让内核通知它：

- 创建网络连接事件
- 数据到达 socket 事件
- 磁盘读取完成事件
- socket 能够继续被 `write()` 事件

……这基本上就是在组装一个小型 OS 了。更不用说，事件通知机制在 OS 里一般也没有完整的支持，比如在 Unix 中就没有文件系统操作完成事件的通知机制。Syscall 也并不总是能完全不进行阻塞等待，比如 `open()` 和 `stat()` 等。

最后，非阻塞式 Syscall 还很难实现。例如可以看下 `sys_read()` 的大致实现：

```c
sys_read(fd, user_buffer, n) {
  // read the file's i-node from disk
  struct inode *i = alloc_inode();
  start_disk(..., i);
  wait_for_disk(i);
  // the i-node tells us where the data are; read it
  struct buf *b = alloc_buf(i->...);
  start_disk(..., b);
  wait_for_disk(b);
  copy_to_user(b, user_buffer);
}
```

这个函数分为两步，先获取 inode，再写入 buffer，期间都需要 `wait_for_disk()`，使得程序在内核中被挂起。这种情况下，非阻塞式的 Syscall 此时需要从内核中返回防止阻塞，但这样内核就无从知晓 `sys_read()` 刚才执行到哪里了，`sys_read()` 也没法继续执行下去了。

因此，如果要使用用户线程，我们要么只能使用一个支持不那么完整的实现，要么就是重写底层的 Syscall 使得一个 Syscall 内部执行一个非阻塞的过程。这会导致一个 `open()` 的系统调用可能会被拆成几十个小系统调用，比如通过 `lookup_one_path_component()` 查找**一层**目录。毫无疑问，这会导致代码极其繁琐。

总的来说，可能只有对性能有苛刻要求的情况下才会使用用户线程，以节省掉用户态 / 内核态切换的开销。

> 现在有 goroutine 了。

## NFS

这里主要讨论 NFS v2。

### 设计目标

- 应当能够用于现存的应用，即提供与 Unix 文件系统相同的语义
- 应当能够简单地部署
- 应当支持多种平台
- 应当足够高效，但不需要和 Unix 本地文件系统一样高效

### 远程文件与目录的命名

NFS Client 使用 mounter 将远程目录挂载到本地目录。mounter 向指定的 NFS Server 发送 RPC 请求并获得一个 32 字节的 file handle 用于后续请求，可以将 file handle 理解为 inode。对 NFS Server 而言，file handle 实际上由 fs identifier、inode number 和 generation number 三部分组成。

为什么 NFS 不直接用常规的文件路径来标识文件呢？当然是为了处理数据一致性的问题。假设一个 Client 打开了 `dir1` 下的文件正准备读取，此时另一个 Client 却重命名了这个目录为 `dir2`，那么根据 Unix 规范最终读取的路径是 `dir2/xxx` 。如果 NFS 直接用文件路径标识文件，就无法与 Unix 文件系统的行为保持一致，这也是 file handle 中引入 inode 的原因。

那么 generation number 又有什么用？假设一个 Client 打开了一个文件正准备读取，此时另一个 Client 却删除了这个文件，创建了新的同名文件，那么根据 Unix 规范最终读取的是旧文件的内容。如果 NFS 恰好将旧文件的 inode 分配给新创建的文件，就会导致读到的是新文件的内容。generation number 则会在重用 inode 时 +1，确保读到的是原来的旧文件。解决了重用 inode 的风险，NFS Server 就能立刻回收 inode。

即使 Client 打开文件获得 file handle 后 Server 宕机，这个 file handle 在 Server 恢复后依然有效。

### RPC

以读文件为例：

{{< mermaid >}}
sequenceDiagram
participant A as Application
participant C as Client
participant S as Server
A->>C: OPEN("f",0)
C->>S: LOOKUP(dirfh,"f")
S->>S: Look up "f" in directory dirfh
S->>C: fh and file attributes
C->>A: fd
A->>C: READ(fd,buf,n)
C->>S: READ(fh,0,n)
S->>S: Read from fh
S->>C: Data and file attributes
C->>A: Data
A->>C: CLOSE(fd)
{{< /mermaid >}}

图中的 `fh` 指 file handler，并且默认 Application 之前已经获得了目录的 file handler 即 `dirfh`。

从图中可以看到，Server 并不需要维护任何客户端状态，每次 RPC 请求中带着读文件所需要的全部信息，也就是说 Server 是一个无状态服务。无状态服务的好处在于：

- 对 Server 来说，从故障中恢复并不需要做任何额外的事，就好像故障从来没发生过一样
- 对 Client 来说，如果请求没有得到响应，只要不断重试即可

重试导致的结果是，同一个请求可能被 Server 执行多次，如果是类似删除文件等请求，就会出现奇怪的结果。后来，NFS 通过让 Server 维护一个 transaction ID 和 reply cache 来避免这一问题，不过 reply cache 就会在重启后失效了。换而言之，如果 Client 在 Server 正常时删除了文件，Server 重启后再次删除，依然会得到“文件不存在”的错误，但这种情况已经是小概率事件了。

如果使用一种更健全的方案，就需要持久化到磁盘上，这会带来很大的开销和实现复杂度。NFS 选择不这么做，就是为了确保系统的内部实现足够简单，同时保持了无状态的特性。这种为了实现简单而有意牺牲一小部分正确性、一致性和完备性的做法正是 [Worse is Better](https://www.jwz.org/doc/worse-is-better.html) 的设计思想。

### 扩展 Unix 文件系统

为了更无缝地适配到 Unix 文件系统，NFS 引入了 vnode 的概念，这实际上是对 inode 的一层抽象，使得 vnode 既可标识本地文件，又可标识远程文件。同时，vnode 还可以标识同一台机器上几种不同文件系统中的文件。

vnode 提供的接口使得开发者无需关心操作的文件来自哪里，许多现有程序代码也更容易迁移。

例如，当应用程序调用 `open` 系统调用时，会通过 `File syscall layer->Vnode layer->Client->Server->Vnode layer->File system` 的路径一步步 `LOOKUP` 并最终打开文件。

Client 也会对最近使用的 vnode 进行缓存以减少 RPC 请求。然而，多个 Client 缓存了同一个文件时，就会出现缓存一致性的问题。

### 缓存一致性

如果一个应用写了本地文件，文件的改动通常会写入缓存而不是立刻写入 Server。在这段时间里，另一个 Client 读取到的文件就是尚未更新的文件，引起缓存一致性问题。

NFS 提供了两种保证缓存一致性的方法：

- close-to-open consistency
  - 如果先 `CLOSE `后 `OPEN`，就能保证 `READ` 读到的数据一定是 `WRITE` 操作之后的
  - 如果在 `CLOSE` 前 `OPEN`，则**无法保证这一点**，这也是缓存一致性和数据一致性的区别所在
- read-write consistency：如果 `OPEN` 了同一文件，则 `READ` 读到的数据一定是 `WRITE` 操作之后的，显然这样更能保证一致性但开销更大

close-to-open consistency 的具体原理，是每次应用 `OPEN` 文件时，都会检查本地缓存中文件的修改时间和 `GETATTR` RPC 请求所获得的 vnode 修改时间，如果不一致，则删除缓存重新获取文件。而 `WRITE` 则只会写到本地缓存，直到 `CLOSE` 后改动才会写到 Server 中。

### 局限性

- 安全性：NFS 并没有把安全性放在一个重要的地位，未授权访问、中间人攻击都是可行的
- 可伸缩性：NFS Server 承受的流量压力较大，无法支持过多 NFS Client
- 因为性能、丢包处理等原因，难以在大规模复杂网络中使用

> 为什么 NFS 安全措施极弱，但却没有受到严重的攻击？主要原因可能是 file handle 难以猜解。

## RPC 透明性

### 设计目标

编写分布式系统代码时，尽可能减少对客户端和服务端的代码和行为上的改动，并使得开发者无需关心网络带来的问题。也就是说，RPC 希望能让分布式编程写起来就像在单点系统中一样，提供“透明性”。

### 抽象

首先面临的问题就是，在不同机器上对数据的表示不同，例如 32 位 / 64 位、小端法 / 大端法等等。因此，在数据传递时，必须使用一种和机器无关的数据表示方式，即 Interface Description Language。

IDL 所做的事不外乎两件：

- 将不同编程语言原生的数据类型，序列化为机器无关的字节流以在网络上传递（反之同理）
- 在客户端上使用 stub 将请求发送至服务端

例如，对于 Sun RPC 来说，IDL 就是 XDR，也是在 CW1 中使用的 IDL。首先在 `proto.x` 中编写 API 定义，随后 `rpcgen proto.x` 自动生成代码。

### 🌰 NFS

在 NFS 中，Client 本质上就是针对文件 syscall 的一个 RPC stub。此时，syscall 的参数、返回值都没有受到影响，提供了一定程度的透明性。

然而，这种透明性仅仅是形式上的。如果只有形式上的透明性而没有语义上的透明性，现有的代码尽管能够运行，却会产生错误的结果。所谓语义透明性，即同样的调用是否在 NFS 和 Unix 本地文件系统上表现一致。显然，NFS 没能完全提供这种语义透明性：

- 在 Unix 上，只有文件不存在时 `open()` 才会失败；在 NFS 上，如果服务器宕机，`open()` 也会失败，甚至可能一直挂起
- 在 Unix 上，`close()` 不可能失败；在 NFS 上，调用 `close()` 时会触发批量写操作（也就是含有隐式的 `write()` ），在 Server 空间不足时可能失败
- 在 NFS 上，假如 Client 发送重命名请求，Server 完成了重命名但未能发送响应就宕机了，那么在 Server 恢复后 Client 的重传会得到“文件不存在”的响应；这在 Unix 上不可能发生
- 在 Unix 上，如果 A 打开文件后该文件被 B 删除，A 依然能继续读文件；在 NFS 上，A 则无法再读该文件

第一个问题并不是 NFS 特有的，而是分布式系统均面临的问题；而后三个问题虽然可以修复以提升语义透明性，但都需要付出性能的代价。同理，提升性能也常常需要牺牲一部分一致性，例如上文提及的 close-to-open consistency，并不是什么时候都能提供足够强的一致性。

### 异常处理

RPC 需要处理类似服务端宕机、网络丢包等单点系统中不存在的异常，并采用 At-most-once 的执行策略。这是因为，如果响应丢包了，客户端会重传已经执行过的请求，此时如果操作具有幂等性则不会出问题，但如果是类似于充值 / 收费等请求，再次执行显然会带来大麻烦。因此，服务端可以维护 replay cache，使得收到重复请求时直接返回 cache 中的值，而不是再执行一次。

## Ivy

RPC 对于提升透明性的尝试基本失败了，它显式的通信方式需要开发者小心地定义节点间的通信接口，没能提升太多透明性。我们转而思考，能不能使用一种隐式的通信方式来达到这一目的呢？分布式共享内存提供了这样一种可能性。

Ivy 创建了一种所有节点共享同一块内存的幻象，隐藏了在访问其他节点内存时底层的网络传输，从而实现隐式的通信。当然，既然用到网络，就要面临网络带来的性能、正确性、一致性等问题……

因为 Ivy 让分布式系统的节点“共享”同一内存，我们不妨将各节点具象为 CPU。首先需要解决的问题就是怎么把程序的不同部分交给不同 CPU 去执行，并确保正确性。

> 现代 CPU 并不会按指令顺序来逐条执行指令。所谓正确性，即执行结果看起来就像是指令逐条执行后产生的结果一样。

如果我们让每个 CPU 都持有一份全部共享内存的复制，那么读内存会非常快。然而，写内存则需要将写操作引入的改变传播到其他 CPU，而网络延迟在这里是不可忽视的。本地读和异地写的时间差，以及节点间网络延迟的差异，都会使得变量值的变化在时间上不一致，从而破坏正确性。因此，这种方案不可行，每个 CPU 必须持有共享内存的一部分而不是全部。

这就引出了如何划分内存给 CPU 的问题。容易想到，固定的划分方法无法顾及局部性，势必会效率低下。而动态的划分方法——比如 CPU 对某个页进行读写时将其移动到 CPU 上——不能处理多个 CPU 读同一个页的情况。

因此，我们可以考虑仅仅在写时移动页。而当 CPU 需要读异地内存时，只需要找到最后写该页的 CPU 并复制一份只读的拷贝。

### 机制简介 - 中心化 Manager

Ivy 就采用了类似的思想，用中心化的 Manager 管理页的分配，下面用例子阐释其中的机制。假设存在三个 CPU，其中第三个 CPU 同时还是 Manager。每个 CPU 维护自己的 page table，Manager 则额外维护一个 info table。

| ptable | lock | access | owner |
| ------ | ---- | ------ | ----- |
| CPU0   |      |        |       |
| CPU1   |      |        |       |
| CPU2   |      |        |       |

| info    | lock | copy_set | owner |
| ------- | ---- | -------- | ----- |
| Manager |      |          |       |

`lock` 列用来锁定表的编辑权限，`access` 可以为 `R` / `W` / `nil` 表示 CPU 对该页有读 / 读写 / 无权限，`owner` 则标志当前 CPU 是否为最后写该页的 CPU。最后，info 表中 `copy_set` 维护了该页的所有只读拷贝，`owner` 保存了最后写该页的 CPU 名称。

注意这里每个 CPU 的 ptable 和 Manager 的 info table 都被简化到了一行，即对应某一特定的页。

#### CPU1 读 CPU0 的页

假设初始状态如下，页为 CPU0 所拥有：

| ptable | lock | access | owner |
| ------ | ---- | ------ | ----- |
| CPU0   |      | W      | ✅    |
| CPU1   |      | nil    |       |
| CPU2   |      | nil    |       |

| info    | lock | copy_set | owner |
| ------- | ---- | -------- | ----- |
| Manager |      | {}       | CPU0  |

现在，CPU1 想要读取该页。于是它首先 lock 了自己 ptable 中对应的行，向 Manager 发送 read query。Manager 接收后，lock 自己 info 中对应的行，将 CPU1 加入 `copy_set`。

| ptable | lock | access | owner |
| ------ | ---- | ------ | ----- |
| CPU0   |      | W      | ✅    |
| CPU1   | ✅   | nil    |       |
| CPU2   |      | nil    |       |

| info    | lock | copy_set | owner |
| ------- | ---- | -------- | ----- |
| Manager | ✅   | {CPU1}   | CPU0  |

随后，Manager 向 Owner 也就是 CPU0 发送 read forward。CPU0 接收后，lock ptable，将 `access` 改为 `R`。

| ptable | lock | access | owner |
| ------ | ---- | ------ | ----- |
| CPU0   | ✅   | R      | ✅    |
| CPU1   | ✅   | nil    |       |
| CPU2   |      | nil    |       |

| info    | lock | copy_set | owner |
| ------- | ---- | -------- | ----- |
| Manager | ✅   | {CPU1}   | CPU0  |

随后，CPU0 向 CPU1 发送 read data 后 unlock ptable。CPU1 接收后，向 Manager 发送 read confirm，并将 `access` 改为 `R`，最后 unlock ptable。Manager 收到后，也 unlock info。

| ptable | lock | access | owner |
| ------ | ---- | ------ | ----- |
| CPU0   |      | R      | ✅    |
| CPU1   |      | R      |       |
| CPU2   |      | nil    |       |

| info    | lock | copy_set | owner |
| ------- | ---- | -------- | ----- |
| Manager |      | {CPU1}   | CPU0  |

#### CPU2 写 CPU0 的页

书接上回，此时 CPU2 想写 CPU0 的页，那么它会 lock ptable，向 Manager 发送 write query。Manager 接收后，lock info，并向 `copy_set` 中的 CPU1 发送 invalidate，以撤销 CPU1 的读权限。CPU1 接收后，lock ptable 并将 `access` 改为 `nil`。

| ptable | lock | access | owner |
| ------ | ---- | ------ | ----- |
| CPU0   |      | R      | ✅    |
| CPU1   | ✅   | nil    |       |
| CPU2   | ✅   | nil    |       |

| info    | lock | copy_set | owner |
| ------- | ---- | -------- | ----- |
| Manager | ✅   | {CPU1}   | CPU0  |

随后，CPU1 向 Manager 发送 invalidate confirm 并 unlock ptable。Manager 接收后，从 `copy_set` 中移除 CPU1，向 Owner 即 CPU0 发送 write forward。

| ptable | lock | access | owner |
| ------ | ---- | ------ | ----- |
| CPU0   |      | R      | ✅    |
| CPU1   |      | nil    |       |
| CPU2   | ✅   | nil    |       |

| info    | lock | copy_set | owner |
| ------- | ---- | -------- | ----- |
| Manager | ✅   | {}       | CPU0  |

CPU0 接收后，lock ptable，将 `access` 设为 `nil` 并放弃 Owner 身份，最后向 CPU2 发送 write data。

| ptable | lock | access | owner |
| ------ | ---- | ------ | ----- |
| CPU0   | ✅   | nil    |       |
| CPU1   |      | nil    |       |
| CPU2   | ✅   | nil    |       |

| info    | lock | copy_set | owner |
| ------- | ---- | -------- | ----- |
| Manager | ✅   | {}       | CPU0  |

随后，CPU0 unlock ptable。CPU2 接收后，将 `access` 设为 `W` 并成为新的 Owner，最后向 Manager 发送 write confirm 并 unlock ptable。

| ptable | lock | access | owner |
| ------ | ---- | ------ | ----- |
| CPU0   |      | nil    |       |
| CPU1   |      | nil    |       |
| CPU2   |      | W      | ✅    |

| info    | lock | copy_set | owner |
| ------- | ---- | -------- | ----- |
| Manager | ✅   | {}       | CPU0  |

Manager 接收后，将 `owner` 设为 CPU2，最后 unlock info。

| ptable | lock | access | owner |
| ------ | ---- | ------ | ----- |
| CPU0   |      | nil    |       |
| CPU1   |      | nil    |       |
| CPU2   |      | W      | ✅    |

| info    | lock | copy_set | owner |
| ------- | ---- | -------- | ----- |
| Manager |      | {}       | CPU2  |

可以注意到，ptable 的锁的存在本质上防止了并发写的发生，使得写操作必须是原子的。

我们也可以将 `copy_set` 移动至每个 CPU 上而不是放在 Manager 上，使得 confirm 类的消息不需要再被发送。此外，还可以使用分布式 Manager 进一步提升性能。

#### 两个 CPU 同时写同一页

根据上面的写操作流程，不难发现同时写同一页是不被允许的（例如，不能有两个 Owner / copy_set 一致性等等），因此写操作必须是原子的。这种原子性实际上得益于 Ivy 的循序一致性。

### 循序一致性

所谓满足循序一致性，即在多 CPU 环境下存在一种包含所有 CPU 的指令的序列使得：

- 所有 CPU 看到的结果与序列的顺序是一致的，例如对一个地址的读操作一定会读取到对该地址最近一次写操作所写入的值；
- 在序列中，每个 CPU 的指令维持原顺序

这两个要求都十分符合直觉。如果上面的定义不便于理解，可以简单理解为在一个 CPU 上的多个线程的预期行为，两者是类似的。

Lamport 则证明，只要满足以下两个条件，就能满足循序一致性：

- 每个 CPU 按指令顺序，依次执行读写指令
- 对内存中的每个位置的读写指令，也按指令顺序依次执行

根据这两个条件，我们可以发现 Ivy 是满足循序一致性的。

### 与 RPC 对比

相比 RPC，分布式共享内存的优点在于：

- 提供了更强的透明性
- 使得分布式系统编程更为容易

然而，RPC 同样具备分布式共享内存欠缺的优点：

- 更好的隔离性
- 对通信更可控
- 对网络延迟容忍度更高
- 更容易移植到不同平台

## 2PC

NFS 和 Ivy 都没有处理系统中节点故障的问题。在一些场景下（比如银行转帐），我们希望当参与的节点故障时，所有参与的节点要么都完成状态变更，要么都没有状态变更。比如，我们显然不希望发起转账的节点被扣除了余额，而收到转账的节点没有增加余额。

2PC（Two-Phase Commit）即两阶段提交，通过一种非常简单的思路来确保系统中的节点能达成**共识**。如果这种 all-or-nothing 的语义能够被正确执行，即要么全 commit 要么全 abort，那么就达成了 Safety 的目标；如果在没有故障的情况下能尽快全 commit，并在出现故障的情况下尽快决定是 commit 还是 abort，那么就达成了 Liveness 目标。显然，Safety 和 Liveness 两者之间需要权衡。

为此，我们需要引入交易协调者 TC。假设系统中只有两个节点 A 和 B，那么 TC 先向两者发送 prepare 消息。A 和 B 随后回复他们是否能够 commit。如果 TC 收到了两个 Yes，那么就会向两者发送 commit 消息；如果 TC 收到了至少一个 No，那么就会向两者发送 abort 消息。最后，A 和 B 根据 TC 的指令完成相应动作。

我们可以很容易看出，上述做法一定能保证 Safety。但是，如果：

- 任意节点（TC / A / B）接收消息时超时了（宕机、丢包种种原因）
- 任意节点重启了

我们都无法保证 Liveness 了，因为 TC 可能在能够 commit 的情况下选择了 abort。

### 超时的情况

为了处理超时的情况，确保 Safety 的前提下尽量保证 Liveness：

1. 我们可以让 TC 等待 Yes / No 消息超时的时候选择 abort 来尽快作出决定，但此时依然有可能在能 commit 的情况下选择了 abort，过于保守。

2. 我们可以让 A / B 等待 commit / abort 消息超时的时候自动选择 commit，但由于另一方可能回复了 No，这样很可能失去 Safety。

3. 我们可以让 A / B 等待 commit / abort 消息超时的时候自动选择 abort。不失一般性，假如 B 之前回复了 No，那么超时自动 abort 不会出问题，也能保证 Liveness；但如果 B 之前回复了 Yes，那么 TC 就有可能收到两个 Yes，然后给 A 发送 commit，而给 B 发送的 commit 没有送达。此时 A 选择 commit 而 B 自动 abort 了，失去了 Safety！

至此，我们解决了问题的一半：B 如果之前回复了 No，那么只要超时自动 abort 就好了。

而如果 B 之前回复了 Yes，那么它可以向 A 发送 status 消息，询问 A 的状态：

- 如果 A 没有回复，B 无法决定，只能继续永远等 TC 的消息；
- 如果 A 收到了 commit / abort 并回复给了 B ，B 就做相同的决定；
- 如果 A 还没有回复 Yes / No，两者都 abort（此时 TC 不可能决定全 commit）；
- 如果 A 没收到 commit / abort 但之前回复了 No，两者都 abort；
- 如果 A 没收到 commit / abort 但之前回复了 Yes，B 同样无法决定，因为无法判断 TC 是不是收到了两者的 Yes 并决定 commit 了。

因此，我们发现即使采用了这样的终止协议并保证了 Safety，Liveness 依然无法保证，TC 宕机 / TC 的消息丢了的情况下，A / B 依然需要永远等待 TC。

### 重启的情况

重启的 TC 可能不知道自己发送过 commit，重启的 A / B 可能不知道自己发送过 Yes，结合丢包的可能性，这使得作出能保证 Safety 的决定也不那么容易了。

对于这类问题，分布式系统采用的一种通用方案就是借助持久化存储。TC 发送 commit 前先写一条记录到磁盘，A / B 在发送 Yes 前也先写一条记录到磁盘，就能使状态被保留下来。

因此，只需要：

- TC 重启后，如果磁盘上没有 commit 消息，就 abort；
- A / B 重启后，如果磁盘上没有 Yes 消息，就 abort；
- A / B 重启后，如果磁盘上有 Yes 消息，就使用上述的终止协议作决定

### FLP Result

分析了 2PC 协议之后，我们发现尽管它能保证 Safety，但却不能在所有情况下保证 Liveness。实际上，根据 [FLP Result](https://www.the-paper-trail.org/post/2008-08-13-a-brief-tour-of-flp-impossibility/)，异步消息传递式的分布式系统中，只要有一台机器存在宕机且不恢复的可能（crash-failure），就不存在确定性的共识算法，也就是说不可能同时保证 Safety 和 Liveness。

## Paxos

称 Paxos 为分布式领域最重要的算法应该不会有太大争议。Paxos 实际上可以认为是 2PC 的升级版，因为两者都是为了解决**共识**问题，只不过 Paxos 通过更复杂的机制获得了更高的可用性。在之前介绍的案例中（NFS、Ivy、2PC）其实都没有将可用性纳入考量。

### 共识算法

需要注意的是，Paxos 是共识算法而不是一致性算法，尽管这两个概念很相似。共识指的是系统中的节点对某个 / 某些变量的值、或者是某个概念、某个行动能够达成共识，而一致性则指的是不同的分布式数据库节点上，存储的数据是否一致。

### 🌰 Primary 选举

假如有这样一个场景：我们要选择一个节点作为 primary，负责接收客户端请求并分发给其他 backup 节点。但是 primary 的引入同时也会引入单点故障问题，此时可能就需要选出一个新的 primary，这时就会极易产生多于一个 primary。在这个场景下，Paxos 要解决的问题就是：确保所有节点最终只会选出一个 primary。而对于其他不同场景，Paxos 解决的问题也可以不同。

一个很自然的想法是给每个节点预先编号，当前存活的节点中编号最小的当选。这就需要所有节点对“当前存活的节点集合”这个值达成共识。然而未必所有节点都能够正常地给出自己的反馈，因此只需要某个值被**超过半数**节点同意，我们就认为节点关于这个值达成了共识。

> 这实际上表明，Paxos 能成功执行必须要至少半数以上的节点存活。

### 共识协商

由于可能出现网络丢包和网络分区，单纯的互 ping 来确定哪些节点存活是行不通的。为此，Paxos 引入了 Leader 机制。当一个节点决定成为 Leader 后，它会向包括自身在内的所有节点广播一个 proposal，其中包含一个 proposal 序号 n 和相应的值 value（在这个例子里，是存活节点集合，下不赘述）。n 必须是全局唯一的，一般取目前存在的最大的 n 的值 + 1。

每个节点维护三个变量：

- `n_a` 表示节点**已经接受过的** proposal 中最大的 n
- `v_a` 表示 `n_a` 对应 proposal 的 value
- `n_h` 记录节点所收到的 proposal 中最大的 n

当节点收到一个 proposal，并发现其序号 `n'` 大于 `n_h` 时，就将 `n_h` 设为 `n'`，并向 Leader 回复 `(n_a, v_a)`。

Leader 收到了超过半数的这样的消息后，就可以查看其中是否有某个 `v_a` 非空：

- 如果所有 `v_a` 都是空的，那么就自己选择一个值作为 value
- 否则，就选择 `n_a` 最大的那个消息中的 `v_a` 作为 value

随后，向**这次回复过自己的节点**广播 `(n = 最大的 n_a, v = 选择的 value)`。

节点收到后，如果发现 `n` 大于等于 `n_h`，那就接受这个 proposal。所谓接受 proposal，就是设置 `n_h = n_a = n`，`v_a = v` 来更新这几条记录，随后回复一条没有内容的消息。

Leader 收到超过半数的这样的消息后，就可以认为节点达成了共识，并向这次回复过自己的节点广播一条没有内容的消息，表示共识已达成。节点收到消息后，就知道最终达成的共识的值为 `v_a`。在选 primary 的例子里，`v_a` 集合里序号最小的节点就是公认的 primary 了。

那么，一个节点怎么决定自己要成为 Leader 呢？很简单，只要为每个节点设置一个随机的超时时间，一旦过了这个时间依然没有来自 Leader 的消息，节点就会自己成为 Leader。

### Safety

Paxos 能保证 Safety 的关键在于：

- 任何节点收到一个 `n' < n_h` 的消息后，都会直接无视，这使得即使出现多个 Leader，节点最终也只会接受那个序号最大的 proposal（注意 n 是全局唯一的）
- 任意两个“超过半数”的集合之间必定存在交集，这是由“超过半数”的定义得来的。这使得即使出现多个 Leader，并且都几乎获得了超过半数的支持，最终也会由这个交集中的节点（哪怕只有一个）决定要接受的 proposal
- 新的 proposal 会沿用现存的 `n_a` 最大的 proposal 对应的 value，这使得不同 Leader 发起的处于不同阶段的 proposal，无法影响到最终达成共识的 value

## Lamport Clock

### 定义

Lamport Clock 主要用于在没有物理时钟的情况下决定事件发生的顺序。由于没有物理时钟，不存在一个大家都认可的时间标准，因此只能使用相对的时间。Lamport 首先定义了“在……之前发生”的偏序关系，用 $\rightarrow$ 表示：

- 如果 $a$ 和 $b$ 是同一进程中的不同事件，且 $a$ 在 $b$ 之前发生，那么 $a\rightarrow b$
- 如果 $a$ 是一个进程发送某消息的事件，而 $b$ 是另一进程接收该消息的事件，那么 $a\rightarrow b$
- 如果 $a\rightarrow b$ 且 $b\rightarrow c$，那么 $a\rightarrow c$
- 对 $\forall a$，有 $a\nrightarrow a$
- 如果 $a\nrightarrow b$ 且 $b\nrightarrow a$，那么称 $a$ 和 $b$ 是并发的

随后，对于进程 $P_i$，定义其逻辑时钟 $C_i$。事件 $a$ 发生的时间可以表示为 $C_i\langle a\rangle$ 或 $C\langle a\rangle$。对于 $\forall a,b$，逻辑时钟定义为：如果 $a\rightarrow b$，那么 $C\langle a\rangle < C\langle b\rangle$。注意因为并发事件的存在，其逆命题不成立。

为了让时钟系统满足逻辑时钟的定义，每个进程 $P_i$ 都需要在事件发生时让 $C_i$ 加一。同时，我们要求 $P_i$ 发送的消息（发送事件为 $a$）中带有时间戳 $T_m=C_i\langle a\rangle$，而 $P_j$ 收到消息后，将 $C_j$ 设为 $max(C_j,T_m+1)$，从而使得在 $T_m$ 大于等于本地时钟时间时重新同步本地时钟（同步为 $T_m+1$，因为接收消息也是需要耗时的事件）。

有了逻辑时钟，我们就可以决定事件发生的顺序，也就是定义“在……之前发生”的全序关系，记作 $\Rightarrow$。对于进程 $P_i$ 和 $P_j$，事件 $a$ 和 $b$，如果 $C_i\langle a\rangle < C_j\langle b\rangle$，那么 $a\Rightarrow b$；如果 $C_i\langle a\rangle = C_j\langle b\rangle$，我们进一步比较 $P_i$ 和 $P_j$，此时只需要有一个固定的顺序即可。例如，我们可以定义 pid 小的进程中的事件优先发生，那么假如 $P_i$ 的 pid 小于 $P_j$，则 $a\Rightarrow b$。

### 实例

我们可以使用 Lamport Clock 来解决分布式系统中的诸多问题。例如，假设有一种资源被一系列进程共享，且同一时间只能有一个进程获得该资源，那么我们自然希望：

- 获得资源的进程必须释放资源。释放后，其他进程才能获得该资源
- 进程按请求资源的顺序依次获得资源
- 如果每个获得资源的进程最终都释放了资源，那么所有对资源的请求最终都能被满足

这里第二点的“依次”尤为重要，这也导致中心化管理机制在这里失效，因为无法准确判断请求到达的先后顺序。为了满足上述三个条件，我们可以利用 Lamport Clock 设计算法：

- 每个进程维护自己的请求队列
- 请求资源时，$P_i$ 向所有进程发送 $T_m:P_i$ 请求消息，并将其放入请求队列
- $P_j$ 收到请求消息后，将其放入请求队列并向 $P_i$ 回复一个 ACK
- 释放资源时，$P_i$ 将所有 $T_m:P_i$ 请求消息从请求队列中移除，并向所有进程发送 $T_m:P_i$ 释放消息
- $P_j$ 收到释放消息后，将所有 $T_m:P_i$ 请求消息从请求队列中移除
- $P_i$ 只有在满足如下两个条件时会获得资源：
  - 请求队列中存在一个 $T_m:P_i$ 请求消息，并排在所有其他消息前（按全序关系 $\Rightarrow$ 排序）
  - $P_i$ 已经从所有其他进程接收了时间戳大于 $T_m$ 的 ACK

## Bayou

Bayou 是为了移动设备构建成的分布式系统设计的，而移动设备经常会遇到没有网络或者网络质量差的情况，这使得很多问题，比如数据一致性，看起来非常困难甚至不可解。Bayou 解决这些问题的手段主要是通过节点间通信，比如通过蓝牙之类的协议使得两部手机交换数据来达成一致性。这是因为 Bayou 主要想解决的问题就是**严重网络分区**情况下的数据读写可用性。

### 🌰 会议室预订系统

Bayou 使用了一个会议室预订系统的例子来说明协议的运作原理和场景。最终，系统需要确保同一时间段同一会议室不会被两个用户预订。为此，需要一种自动解决冲突的机制，使得不同节点上的数据同步之后能像 git 那样 merge 掉冲突。为了实现这个机制，需要节点维护一个更新操作的有序列表，并确保节点收到的更新操作是一致的、以及确保节点会按相同的顺序逐个应用这些更新操作。这样一来，数据同步就只需要像归并排序那样，合并两个有序列表即可。

### 冲突合并

不过 Bayou 并不是仅仅用于会议室预订系统，而是一个通用的协议，因此需要考虑的问题是：什么才算冲突？这个问题的答案对于不同应用是不同的。同理，合并操作也是类似的。举个例子，对于会议室预订系统，假如我们想预订从下午一点半开始持续一小时的会议，我们会在写操作里添加这样的依赖检查和合并算法：

```
query = "SELECT key FROM Meetings WHERE day=12/18/95 AND start < 2:30pm AND end > 1:30pm"
expected_result = EMPTY
merge_proc = ......
```

随后，Bayou 就会检查 `query` 的结果是否等于 `expected_result` ，是的话可以直接更新，否则就需要调用 `mergeproc` 来合并冲突。需要注意的是，依赖检查和合并算法需要是确定性的。这样一来，由于每个服务器都会按照相同顺序解决冲突，每个服务器最终获得的结果也是相同的。

### 写操作

当一个写操作被接收时，它首先处于 tentative 状态，并且会根据其 timestamp 被排序；最终，写操作会变成 commited 状态，同样根据其被 commit 时的 timestamp 进行排序，并且必定排在 tentative 写操作的前面。这里 Bayou 使用了 Lamport Clock 来避免解决不同设备上的时钟同步问题。

一个让人不爽但又无可奈何的事情是，当 Bayou 服务器接收到新的写操作时，之前的写操作可能不得不被撤销，然后根据新的顺序重新执行。因为新的写操作的加入，旧的写操作甚至可能出现和之前不同的执行结果。当一个写操作最后一次被执行完毕，我们就称该操作已经是稳定的了。对于预订会议室的用户来说，了解自己的预订是否已经稳定显然十分重要。

### 判断稳定状态

那么，Bayou 服务器如何确定一个写操作是否已经稳定了呢？一种办法是用 Lamport Clock 里的 timestamp，如果一个写操作的 timestamp 已经小于任何服务器收到的新的写操作的 timestamp，那说明在这个写操作之前已经没有其他写操作了，所以一定是稳定的。但是，如果一个服务器长期断线，那么它上线的时候就会导致大量写操作重新执行。

Bayou 采用的方法是 primary commit 方法。因为 commited 排在 tentative 前面，我们可以说一个写操作被 commit 之后，只要节点已经获得了之前所有 commited 的写操作（必然成立，这是由 Bayou 按顺序传播写操作的机制决定的），那么这次就是已经是稳定的了。primary commit 即选择一个服务器作为 primary，由它来执行 commit 的操作，并将数据同步给其他服务器。这样做的好处有：

- 即使 primary 出现单点故障，影响的也只是 commit，而不是正常的读写操作。
- 即使某些节点长期断线，也不影响 commit，因为只有 primary 能 commit。
- 节点接收到来自 primary 的数据同步后，就不再需要最新 commit 之前的任何记录了，因为那些记录都不可能再改变了。

最后，必须注意的是，primary 在决定 commit 顺序的时候，对于来自同一节点的若干次写操作，其原顺序必须被保留。如果在某个节点上先执行了 create，然后执行 modify，那么让 modify 在 create 前面 commit 是毫无意义的。

可以看到，Bayou 的问题主要在于实现依赖检查和合并算法，很大程度上增加了开发 / 使用一个应用的复杂度，也并不是对所有应用都适合用这种办法。

## GFS

GFS 是谷歌设计的分布式存储系统，其设计基于如下前提：

1. 系统组件失效是常态，而非异常情况
2. 从传统标准来看，需要存储的文件十分巨大，往往是 GB 级和 TB 级的
3. 相比覆盖文件中已有的内容，在文件后追加内容更为频繁
4. 协同设计应用程序和文件系统的 API 能提高灵活性

同时，也要考虑到所需要的文件系统的行为模式：

- 由于容易出现组件失效，因此需要迅速地自动检测、容忍和恢复故障
- 主要存储大文件，如大于 100 M 的
- 读操作往往是大规模的流式读取，如大于 1 M 的；一般不会重复读取，即 Read once
- 写操作往往是大规模的顺序写入，而且是追加写入；一般不会重复写入，即 Write once
- 需要原子的并行追加写入机制，避免引入锁等开销较大的同步机制

### 架构

一个 GFS 集群中只有一个 Master 节点（可能包含多个 Master 服务器），这种中心化的方式正是为了简化整个系统的管理。Master 节点上只有文件的元数据，而多个 Chunkserver 上则是文件实际存储的地方。

文件被分割为 64 M 的 Chunk，每个 Chunk 被 Master 分配一个 64 位的 ID。Master 节点上的元数据包括：

- Namespace
- 针对文件的访问控制信息
- 文件到 Chunk 的映射
- Chunk 当前所处的 Chunkserver

值得一提的是，这些元数据都保存在 Master 的内存中，又快又简单。此外，Master 节点还负责管理 Chunk 租用、垃圾回收、Chunk 迁移等等，并通过心跳信息确认 Chunkserver 状态。

Chunk 一般会在若干个 Chunkserver 上保存一份冗余，默认是 3 个。保存的方式就是放在 Linux 文件系统里。然而，GFS 并没有像 NFS 一样尽量模仿 Unix 文件系统 API，而是自己实现了 create、delete、open、close、read、write 等常用操作。此外，还有 snapshot 和 record append 两个特有的操作，分别用于文件备份和对文件并行追加写入。

> record append 和常规追加写入的主要区别在于，它遵循 at least once 语义，并且追加的位置未必是文件尾部，而是由 GFS 计算决定。

由于利用了 Linux 文件系统，Chunkserver 上不需要缓存机制；而由于流式的读取模式，GFS 客户端也不需要本地缓存文件，只需要缓存元数据即可。这使得缓存一致性不再是问题。

### 读操作

![图 1｜读操作流程](1.png)

1. 客户端向 Master 发送 read 请求，包含文件名和 Chunk index
2. Master 回复元数据：Chunk ID、Chunk 版本号以及副本所处的位置
3. 客户端向最近的副本所处的 Chunkserver 发送 read 请求，包含 Chunk ID 和读取的字节范围
4. Chunkserver 回复实际的文件数据

可以看到，客户端和 Master 之间只有控制信息的交互，而实际的数据交互仅仅发生在客户端和 Chunkserver 之间。

### 写操作

![图 2｜写操作流程](2.png)

对于每个 Chunk 来说，某个存放了该 Chunk 副本的 Chunkserver 会成为 primary（其余均为 secondary），由 Master 向 primary 提供 60s 的租约（并更新 Chunk 版本号）。租约通过心跳信息延续，也可以被 Master 主动取消。

1. 客户端首先向 Master 询问 primary 和 secondary 的位置
2. Master 回复 primary 和 secondary 所处的位置
3. 客户端向最近的副本所处的 Chunkserver（可能是 primary 或 secondary）发送要写入的数据，数据通过 daisy chain 的方式在 Chunkserver 间传递
4. 当所有副本都确认接收到了数据后，客户端向 primary 发送 write 请求
5. primary 给该请求分配一个序号（用于在本地对写操作顺序进行排序），并通知所有 secondary 执行该 write 请求
6. secondary 执行后向 primary 回复执行结果
7. primary 向客户端回复执行结果

所谓 daisy chain，即数据在不同 Chunkserver 之间类似流水线一样一一传递的方式。这种方式不仅利用了现代网线全双工的特性，更重要的是可以配合流式传输，在尚未完全接收到全部数据时就开始向下传递数据，提高传输速率。

### record append 操作

record append 操作的流程和写操作基本一致，在 primary 的逻辑上略有区别。在上述第 4 步中，primary 接收到来自客户端的请求后，会检查这次 record append 操作是否会导致 Chunk 超出最大尺寸 64 M。

- 大多数情况下不会超过，因此 primary 把数据追加到自己的副本内，通知 secondary 也这么做，然后通知客户端执行结果
- 而如果超过了，那么 primary 会将当前 Chunk 先填满，通知 secondary 也这么做，然后通知客户端重新发送 record append 请求。这样，当客户端第二次发送请求时，就不会再出现超出最大尺寸的情况了

那么，如果一部分 secondary 在追加写入时成功了，另一部分失败了呢？毫无疑问，这会使得 primary 通知客户端执行失败了，从而让客户端再次发送 record append 请求。此时就可能会出现一种现象，即有些副本上该数据已经被写入了多次，而在有些副本上则只写入了一次。这看起来很混乱，但实际上就是 at least once 的语义。

### 一致性模型

首先可以肯定的是，元数据的变更是原子的，毕竟只有一个 Master 节点。由于 Master 会维护元数据变更的日志并同步到远程服务器，即使 Master 重启之后依然可以重放日志来恢复元数据，从而恢复整个文件系统。

但对于数据变更而言就要复杂很多。GFS 定义了两个一致性指标：

- consistent 意味着，一个文件区域上的内容对任何客户端而言都是相同的，无论它们是从哪个副本中读取的
- defined 意味着，在写操作或 record append 操作后，一个文件区域不仅是 consistent 的，而且任何客户端都能看到对其的所有修改操作

根据这两个指标，我们可以得到：

|              | Write                 | Record Append                          |
| ------------ | --------------------- | -------------------------------------- |
| 串行修改成功 | defined               | defined interspersed with inconsistent |
| 并行修改成功 | consistent, undefined | defined interspersed with inconsistent |
| 修改失败     | inconsistent          | Inconsistent                           |

对于成功的并行写操作，尽管 GFS 可以保证文件区域内容一致，但由于 primary 对并行操作的排序未必和实际发起操作的顺序一致，客户端未必能看到一致的修改操作记录，因此 defined 是无法保证的。因此 GFS 设计者不建议使用 concurrent write。

而对于成功的串行或并行 record append 操作，GFS 能通过 at least once 语义和 primary 对操作的排序保证存在 defined 区域，但 defined 区域之间可能会存在 inconsistent 的区域。这其实就是上文 record append 操作流程中介绍的部分副本上写入失败引起的混乱结果导致的。

这种语义看起来相当奇怪，因此应用程序在编写时也需要针对这种语义进行特殊处理。

### 应用程序

在执行 record append 时，应用程序需要包含一个 checksum。这样在读取数据时，就可以比较容易地分辨哪些数据是填充数据、哪些数据是有效数据。而如果应用程序不能容忍重复读取到同一份数据，就需要在 record append 时包含一个 unique ID 来辅助去重。

### 组件失效

如果 Master 失效，那么如上文所述，它会在重启时重放日志来恢复 Namespace 信息以及文件到 Chunk 的映射信息。随后，它询问 Chunkserver 其持有的 Chunk，从而恢复 Chunk ID 到 Chunkserver 的映射信息。这一映射信息是通过询问 Chunkserver 恢复的，因为它本来就没必要存在 Master 上。

根据版本号不同，Chunkserver 上可能会存在更旧或更新的 Chunk 副本。更旧的副本会被认为是过期的，会被忽略，且会在垃圾回收时被移除；更新的副本则会使得 Master 也采用该副本的版本号。

而如果 Chunkserver 失效，Master 因为收不到心跳信息会发现这一点并减少对应的副本数量。随后，Master 在后台重新复制缺少的这些副本，缺少的越多优先级越高。

### 文件删除

当客户端删除文件时，Master 记录删除日志并将文件重命名为“文件名-删除时间戳”的形式，从而避免向多个副本发起多个删除请求，影响性能。同时，Master 在后台扫描文件 Namespace，当扫描到已经被删除超过 3 天的文件时才会真正执行删除操作，并删除对应的元数据。同理，Master 也会扫描 Chunk 的 Namespace，并通知 Chunkserver 删除未被引用的 Chunk。

## Receive Livelock

影响性能的因素有很多。硬件常常能决定性能的上限，而不当的软件层面的设计却无法使硬件充分发挥其性能。相反，良好的设计则能使性能尽可能逼近这一上限。

这里讨论的 Receive Livelock，就是在中断驱动的系统中，当过量的请求到达时，系统忙于通过中断处理请求，而无法执行真正有用的其他操作。和 Deadlock 相反，系统并没有卡死在一个状态上，但两者的效果是相同的。

### 轮询与中断

在介绍 Receive Livelock 的例子前，我们需要先了解一些背景知识。当 IO 设备完成一些工作时、或是发生一些事件时，需要通知 CPU：比如收到网络包、完成磁盘读取、收到键盘输入等等。这种“通知”通常是通过两种方式实现：

- 轮询：CPU 每隔一段时间就询问 IO 设备是否有事件发生，这是一种同步的方式
- 中断：发生事件时，IO 设备向 CPU 发送信号，这是一种异步的方式

乍一看，似乎显然是后者效率更高，然而实际上未必如此。要判断需要使用哪种方式，我们需要考虑两点：处理事件的延迟时间和 CPU 的负载。

对于轮询来说，要降低处理延迟，就需要提高轮询频率，但这会增加 CPU 负载。因此，使用轮询的场景，是处理那些经常发生、并对处理延迟要求较高的事件。注意这里的“经常”采用的是 CPU 的时间尺度，也就是微秒至毫秒级的。

而中断相反，适合处理发生不频繁、且处理延迟要求不高的事件。中断发生时，如果中断优先级 IPL 高于 CPU 优先级，那么 CPU 会保存当前运行程序的上下文、跳转到内核中的中断处理程序 ISR 对中断进行处理、最后恢复运行程序的上下文并继续。可以发现，中断带来的潜在问题就是对其他系统任务的抢占，也就是引起 Receive Livelock 的根因。

我们知道，磁盘 IO 必定是由 CPU 自己发起的，因此磁盘 IO 导致的中断频率实际上是 CPU 可控的，然而网络 IO 则没有这一限制。而且，许多应用使用的多媒体传输协议或是 RPC 协议往往基于 UDP 等没有流量控制的协议以提高实时性，这使得网络负载能够达到极高的水平，进而导致系统将全部时间花费在通过中断接收网络包上，导致 Receive Livelock。

### 网络 IO 机制

我们设计网络 IO 系统时，想要达到的目标主要有：

- 低延迟，即尽可能快地处理 IO 事件
- 低抖动，即延迟的变化幅度较小
- 公平性，即不同任务都能得到执行，不会出现饥饿的情况
- 高吞吐量，如收发网络包的吞吐量

而一个网络 IO 系统需要完成的任务则可以分为这几类：

- 接收网络包
- 传输网络包
- 处理协议数据（通常在内核中执行）
- 处理其他 IO 事件
- 应用层面的事件处理

由于任务种类和预期目标都比较复杂，我们需要先了解传统中断驱动系统中的网络 IO 机制。

当一个网络包到达网卡时，会产生一个高 IPL 的中断。对应的 ISR 查看以太网包头后就放入 input queue 并返回。这是因为高 IPL 的中断不能花费太多时间，否则会影响其他正常任务的运行。之后，一个较低 IPL 的软件中断会从 input queue 中读取数据包并处理 IP / TCP / UDP 包头，再将数据包放入 socket buffer 供目标应用程序使用。而目标应用程序运行在用户态，通过 `read()` 系统调用读取数据包，因此拥有更低的 IPL。

![图 3｜网络 IO 机制](3.png)

而发送数据包时，大致就是相反的流程，只不过 input queue 变成了 output queue，而 传输包的 IPL 是略低于接收包的 IPL 的。可以看到，这种设计将接收数据包放在最优先的位置，这是因为早期网卡缓冲区较小，如果不尽快接收数据包，缓冲区满后就会丢弃后续到达的数据包。

如今已经不存在网卡缓冲区较小的问题了，但这种设计导致诸多问题依然存在，例如：

- 当网络包到达速率超过“最大无丢包接收速率”时，本应保持不变的网络包发送速率会逐步下降至 0
- 系统浪费 CPU 去接收大量数据包放入队列，而队列中许多来不及被处理的包最终都会被丢弃
- 大量网络包在极短时间内到达时，只有接收完全部包之后才能将第一个包发送给用户态的应用程序
- 由于发送的 IPL 小于接收，发送包的操作会饥饿

### 避免 Receive Livelock

为了避免 Receive Livelock，首先很容易想到的办法就是限流，不是限制数据包到达的流量，而是限制中断触发的“流量”。只要在接收包的 ISR 里：

- 设置标志位，表示该网卡收到了一个或多个数据包
- 调度内核线程，用轮询网卡的方式接收数据包
- 不重新打开接收数据包的中断开关

这样一来，后续接收数据包都不会采用中断的方式，而是通过轮询来接收包，因为在高频 IO 的情况下轮询的表现更优。类似地，我们不仅仅可以根据系统中的各项指标动态控制接收数据包的中断开关，也可以动态控制多个其他中断的开关来让渡 CPU 给用户态程序，例如在 socket buffer 接近满时。

那么内核线程是怎么轮询网卡的呢？当内核线程被调度时，它会检查哪些网卡上设置了“收到数据包”的标志位，对这些网卡上的数据包，它会一直处理 IP / TCP / UDP 包头直到将这些包放入 output queue 或是 socket buffer。对于每次调度，内核线程中设置了一个 quota 来限制单次调度中在一个网卡上最多能处理多少数据包，以保证公平性。同时，内核线程不仅采用 round-robin 的方式轮询网卡，也用同样的方式轮询接收操作与发送操作，避免饥饿现象。最后，只有一个网卡上没有待处理的包时，该网卡的接收数据包的中断开关才会被打开。

采用这种方式，当过量流量到达时，即使要丢弃数据包也不再需要中断、不再需要 CPU 参与了，而是直接在网卡处就被丢弃。

## Kerberos

在讲 Kerberos 之前先讲了一些信息安全相关的基础知识，没有什么记录的必要。Kerberos 是 MIT 研发的一种开放环境下的认证协议，最初认识这个协议还是在 Windows 的域里。

> 这里介绍的 Kerberos 版本是原始论文中的版本。

### 基础概念

在 Kerberos 中，一个要使用服务的用户通过客户端向服务器发起请求，由服务器提供服务并完成对应的作业。一个要使用 Kerberos 服务的实体被称为 principal，可以是一个用户或者一个服务器。

每个 principal 都有自己的对称密钥，只有 principal 自己和 Kerberos 系统本身知道。如果 principal 是一个用户，那么这个密钥一般就是该用户密码的哈希。

最后，所谓“开放环境”，即网络中的机器并不是由某个组织控制，而是用户自己能够完全控制的（用户拥有机器的管理员权限），并且用户还可能能够访问多台机器。这种情况下，不仅需要认证机器、还需要认证用户本身。

### 架构

Kerberos 协议依赖于中心化的 Kerberos 数据库，里面存放了 principal 和对应的密钥。Kerberos 数据库一般由一个 Master 和多个只读的拷贝 Slave 构成。每隔一段时间，Master 数据会更新到 Slave 上。

KDBM 系统可以读写这个数据库，必须和 Master 运行在同一机器上；Kerberos 系统只负责认证，所以只有数据库读权限，可以运行在任意拥有 Slave 的机器上。

无论是服务本身还是使用服务的 principal，都需要在 Kerberos 系统中注册并协商一个密钥。Kerberos 系统还会生成临时的 session key，用于加密某次服务请求过程中的通讯。

Kerberos 采用当时依然安全的 DES-CBC 加密，如今 DES 已经不再安全了。好在加密模块是独立的，可以轻松被 AES 之类的加密算法替换。

### 主体名称

每个主体在认证时都有自己的名称，格式形如：`$primaryName.$instance@$realm`，例如 `rlogin.priam@ATHENA.MIT.EDU`。

`primaryName` 是用户或服务的名称，`instance` 一般表示该用户在哪台服务器上操作、或是该服务在哪台服务器上运行。`realm` 则表示维护认证信息的管理实体，比如一个组织、一个部门等。

### 原理

用户请求服务的过程可以分为两步：

1. 请求一个用于请求其他服务的 credential
2. 用这个 credential 请求对应的服务

credential 又分为 ticket 和 authenticator。ticket 用于传递关于用户的认证信息，而 authenticator 用于传递关于用户所处客户端的认证信息。一个 ticket 通常长这样：

$$
\\{s,c,addr,timestamp,ttl,K_{s,c}\\}K_s
$$

| 符号         | 含义                         |
| ------------ | ---------------------------- |
| s            | 服务器（的名称）             |
| c            | 客户端（的名称）             |
| addr         | 客户端 IP 地址               |
| timestamp    | 时间戳                       |
| ttl          | ticket 有效时长              |
| $K_{s,c}$    | s 和 c 的 session key        |
| $K_s$        | s 的密钥                     |
| $\\{abc\\}K$ | 用 $K$ 加密 $abc$ 得到的密文 |

ticket 颁发后能被用多次，但 authenticator 只能用一次；ticket 由服务器生成，而 authenticator 由客户端生成。一个 authenticator 通常长这样：

$$
\\{c,addr,timestamp\\}K_{s,c}
$$

#### 获取 TGS ticket

最初，用户只能通过密码来证明身份。因此用户首先要输入用户名，此时客户端向 Kerberos 系统发送：

$$
c,tgs
$$

| 符号 | 含义                             |
| ---- | -------------------------------- |
| tgs  | ticket-granting 服务器（的名称） |

表示想要使用 ticket-granting 服务器上的服务。Kerberos 系统检查 c 后生成 c 和 tgs 的 session key。随后回复：

$$
\\{\ K_{c,tgs},\\{T_{c,tgs}\\}K_{tgs}\ \\}K_c
$$

| 符号        | 含义                     |
| ----------- | ------------------------ |
| $T_{c,tgs}$ | c 使用 tgs 服务的 ticket |

用户收到后，输入密码。此时密码被转化为密钥并解密这个消息。这样，用户就可以访问 tgs 了。

#### 获取服务 ticket

如果用户还没有获取过这个服务的 ticket 或者 ticket 已经过期了，那么就需要从 tgs 那里获取服务 ticket。客户端向 tgs 发送：

$$
s,\\{T_{c,tgs}\\}K_{tgs},\\{A_c\\}K_{c,tgs}
$$

| 符号  | 含义               |
| ----- | ------------------ |
| $A_c$ | c 的 authenticator |

tgs 随后解密并检查 ticket 和 authenticator，并生成 c 和 s 的 session key。随后回复：

$$
\\{\ \\{T_{c,s}\\}K_s,K_{c,s}\ \\}K_{c,tgs}
$$

用户收到后，不需要再次输入密码就可以自动使用 $K_{c,tgs}$ 解密消息，获得 c 使用 s 服务的 ticket。这样，用户就可以访问 s 了。

#### 访问服务

客户端向 s 发送：

$$
\\{A_c\\}K_{c,s},\\{T_{c,s}\\}K_s
$$

s 随后解密并检查 ticket 和 authenticator，如果合法则认证成功，开始提供服务。为了防止重放攻击，服务器会丢弃 timestamp 来自未来的、或者和已接收 timestamp 重复的那些请求。

最后，如果客户端也需要服务器证明身份，s 只需要回复：

$$
\\{timestamp+1\\}K_{c,s}
$$

![图 4｜Kerberos 认证过程](4.png)

### 局限性

- 要求系统中所有系统时钟同步
- 中心化存储敏感信息，容易单点故障
- 难以更改密码、升级密钥数据库
- authenticator 默认 5 分钟后过期，依然存在重放攻击可能
- ticket 过期机制导致无法长时间运行后台任务

## TAOS

在讲 TAOS 前讲了关于 SSL/TLS 协议的知识，因为已经比较熟悉了，也没什么记录的必要。

TAOS 的论文中提供了一种基于公钥密码体制和证书的分布式认证协议，以及对应的形式化的理论基础。其最重要的贡献是解决了认证委托的问题，这是专注于两方认证的 SSL/TLS 所不能支持的。

### 符号

- $A\ \texttt{says}\ S$：表示主体 $A$ 支持声明 $S$
- $A\Rightarrow B$ 或 $A\ \texttt{speaks for}\ B$：表示主体 $A$ 发布的任意声明都可以认为是 $B$ 发布的
- 也就是说，如果 $A\Rightarrow B$ 且 $A\ \texttt{says}\ S$，那么 $B\ \texttt{says}\ S$

这里的主体包括：

- 简单主体：如用户和机器等。
- 信道：指网络地址和加密密钥。如果声明 $S$ 出现在了信道 $C$ 上，那么 $C\ \texttt{says}\ S$；如果用 $K$ 签名一张包含 $S$ 的证书，那么 $K\ \texttt{says}\ S$。需要注意，只有信道可以直接发布一个声明，因为声明只能出现在信道上。
- 组：一组主体。如果 $A$ 在组 $G$ 中，那么 $A\Rightarrow G$。
- 代表某一角色的主体：例如 $Bob$ 以 $Admin$ 的身份执行操作时，我们说 $Bob\ \texttt{as}\ Admin$。此时 $Bob\Rightarrow (Bob\ \texttt{as}\ Admin)$。
- 主体的逻辑与。
- 引用某一主体的主体：我们用 $B|A$ 表示 $B$ 引用了 $A$，即 $B\ \texttt{says}\ A\ \texttt{says}\ S$ 等于 $(B|A)\ \texttt{says}\ S$。
- 代表某一主体的主体：我们用 $B\ \texttt{for}\ A$ 表示 $B$ 代表了 $A$，这比 $B|A$ 更强，因为此时 $B$ 已经获得了 $A$ 的授权。

### 公理

1. handoff 公理：如果 $A\ \texttt{says}\ (B\Rightarrow A)$，那么 $B\Rightarrow A$。
2. delegation 公理：如果 $A\ \texttt{says}\ ((B|A)\Rightarrow (B\ \texttt{for}\ A))$，那么 $(B|A)\Rightarrow (B\ \texttt{for}\ A)$。

注意到 delegation 和 handoff 看起来差不多，但重要的是在 delegation 中额外记录了被授权的主体 $B$。如果 $B$ 发布的声明出现了问题，这一特性结合日志审计使得我们不必再向很可能是无辜的 $A$ 追责，而是直接向 $B$ 追责。

### 🌰 认证复合主体

一台机器 $Vax4$ 运行了操作系统 $OS$，两者形成了一个节点 $WS$。用户 $Bob$ 登陆了 $WS$，现在需要向远程文件服务器 $FS$ 发送认证请求。为此，$Vax4$ 必须有自己的密钥对，不妨令其公钥为 $K_{vax4}$，私钥为 $K_{vax4}^{-1}$，其中私钥仅仅对 $Vax4$ 的启动固件可见，对 $OS$ 是不可见的。

$Vax4$ 启动时，用私钥签名一个启动证书，将权限移交给新生成的节点公钥 $K_{ws}$。这个证书可以表示为：

$$
(K_{vax4}\ \texttt{as}\ OS)\ \texttt{says}\ (K_{ws}\Rightarrow(K_{vax4}\ \texttt{as}\ OS))\tag{1}
$$

> 1. 为什么不直接使用 $K_{vax4}$？
>
>    一方面，我们不希望机器私钥被窃取；另一方面，我们也**不希望这些涉及的声明在机器重启后依然有效**。
>
> 2. 那为什么不直接使用 $K_{ws}$ 作为机器的标识？
>
>    因为我们**希望机器的标识在重启后依然有效**。
>
> 3. 所以到底为什么需要机器的标识？
>
>    因为我们希望 $Bob$ 能将权限委托给特定的机器。

因此，启动后 $WS$ 获得了启动证书、节点私钥 $K_{ws}^{-1}$，但无法知道 $K_{vax4}^{-1}$。

登陆操作可以看作一种特殊的 delegation。$Bob$ 登陆时，用自己的私钥 $K_{bob}^{-1}$ 签名一个 delegation 证书，将权限委托给 $WS$：

$$
K_{bob}\ \texttt{says}\ ((K_{ws}|K_{bob})\Rightarrow(K_{ws}\ \texttt{for}\ K_{bob}))\tag{2}
$$

现在，需要向 $FS$ 发送请求。首先需要一个发送请求的信道 $C_{bob}$，以及请求本身 $RQ$。发送请求可以写作：

$$
C_{bob}\ \texttt{says}\ RQ\tag{3}
$$

并且 $WS$ 需要签名一个信道证书，将权限移交给信道：

$$
(K_{ws}|K_{bob})\ \texttt{says}\ (C_{bob}\Rightarrow(K_{ws}|K_{bob}))\tag{4}
$$

结合 (4) 和 (2)，使用 delegation，$FS$ 可以推出：

$$
(K_{ws}\ \texttt{for}\ K_{bob})\ \texttt{says}\ (C_{bob}\Rightarrow(K_{ws}\ \texttt{for}\ K_{bob}))\tag{5}
$$

结合 (5) 和 (3)，使用 handoff，$FS$ 可以推出：

$$
(K_{ws}\ \texttt{for}\ K_{bob})\ \texttt{says}\ RQ\tag{6}
$$

结合 (6) 和 (1)，使用 handoff，$FS$ 可以推出：

$$
((K_{vax4}\ \texttt{as}\ OS)\ \texttt{for}\ K_{bob})\ \texttt{says}\ RQ\tag{7}
$$

最后，$FS$ 还需要证明 $K_{vax4}$ 和 $K_{bob}$ 确实代表了 $Vax4$ 和 $Bob$。为此，必须引入受信任的第三方机构 $CA$，也就是说相信 $K_{ca}\Rightarrow$ 任意的主体。因此，$FS$ 可以使用如下证书：

$$
K_{ca}\ \texttt{says}\ (K_{vax4}\Rightarrow Vax4)\\\\
K_{ca}\ \texttt{says}\ (K_{bob}\Rightarrow Bob)
$$

结合 (7)，使用 handoff，最终得到：

$$
((Vax4\ \texttt{as}\ OS)\ \texttt{for}\ Bob)\ \texttt{says}\ RQ
$$

其语义是：$FS$ 得知运行着 $OS$ 的机器 $Vax4$ 代表用户 $Bob$ 发送了请求 $RQ$。

## ASLR

在讲 ASLR 前讲了关于栈溢出漏洞和格式化字符串漏洞的利用，因为已经比较熟悉了，也没什么记录的必要。

在 ret2Shellcode、ret2Libc 等攻击中，一个必要的条件是攻击者必须知道栈地址、 libc 基地址、写入的字符串地址等等。ASLR 尝试随机化进程的地址空间来阻止这些利用，使得程序直接崩溃。主要随机化的内存区域包括：

- 可执行区域，如 text 段等，随机化 16 bits
- mapped 区域，如堆、动态链接库等，随机化 16 bits
- 栈区域，随机化 24 bits

mapped 区域只能随机化 16 bits，因为第 28-31 bits 如果随机，会影响 `mmap()` 申请大块内存；0-11 bits 如果随机，会影响 `mmap()` 申请到的页的对齐。

由于 16 bits 并不多，ASLR 的随机化是可以被暴力猜解的。在攻击 ASLR 的论文中使用了猜测的 `usleep()` 地址覆盖返回地址。这样，如果猜对了，就会成功调用 `usleep()`，产生非常明显的延迟；而如果猜错了，程序会立即崩溃。成功猜到随机偏移后，就是正常的 ret2Libc 流程了。

> 这里传入给 `usleep()` 的参数是 `0x01010101`，也就是最小的不包括 `0x00` 字节的数字，大约等于 16 秒。

这种暴力攻击平均只需要 216 秒和 6.4 MB 流量，非常高效。即使每次崩溃后重新随机化地址空间，需要的尝试次数也只会变为原来的 2 倍，影响不大。当然，防御方式也非常简单，升级到 64 位系统即可，此时随机化的 bits 至少能达到 40 个（然而，64 位 ASLR 同样有不同的攻击方式）。

## TaintCheck

TaintCheck 则提供了一种无需源码，直接作用于二进制文件的漏洞利用检测方式，并且这种方式极少产生假阳性结果，还能追踪漏洞利用的数据流。

我们知道，大多数漏洞利用都需要修改程序的控制流，这就需要控制类似于返回地址、关键参数之类的值。TaintCheck 所做的事就是给用户输入的数据标记一个污点，如果这些数据被复制或者被用于产生新的数据，那么新的数据也会被标记上污点。这样，如果最终发现一些控制数据（如返回地址）上存在污点，立刻中止程序并可以确认遭受了攻击。

为了直接作用于二进制文件，TaintCheck 使用 Valgrind 来将程序的指令翻译成 UCode，随后插入用于标记污点的代码，并将 UCode 翻译回去。这个过程是针对每个基本块执行的，因此在 `jmp` / `ret` / `call` 等指令前都会检查要跳转的地址是否有污点。

对存在污点的内存区域，TaintCheck 维护了一份 shadow memory 来记录污点状态。Fast 模式下，对于每个内存中的字节只使用 1 bit 来记录是否有污点；Detailed 模式下，则使用 4 字节的指针，指向一个污点的结构体，记录了详细的 syscall、栈等信息，用于追踪漏洞利用数据流。

不过，TaintCheck 并不会为 condition flags 加污点，即使它会直接受到用户输入影响。这么做是因为这会极大提高假阳性率，但这样做也导致了一些假阴性的情况出现，例如：

```c
if (x == 0)
  y = 0;
else
  y = 1;
```

如果 `x` 是用户输入，那么这里的 `y` 实际上是和 `x` 一致的，然而 `y` 却不会被标记。如果攻击者知道这一点，就可以用 `y` 来修改控制数据同时绕过检测。这个例子比较极端，但确实展示了假阴性的可能性。

此外，TaintCheck 性能堪忧，在服务器返回数据较少时，响应时间甚至可以达到原来的 20 - 30 倍。这要部分归功于 Valgrind，毕竟只跑 Valgrind 就会慢 5 倍左右了。但就结果而言，这让 TaintCheck 难以部署到生产服务器上，更多情况下更适合在旁路进行流量采样。

## SFI

我们经常会使用一些预编译的二进制包，比如浏览器插件、内核插件等等，这些包有时候来自于不受信任的来源，但是却加载到应用程序的内存里。我们如何保证这些插件对我们应用本身产生负面影响，比如恶意调用应用中的函数、覆盖应用中的数据？即使这些插件本身不是恶意软件，我们如何避免攻击者利用插件漏洞访问到应用程序本身的内存，从而攻击应用程序？

很显然，我们需要一种机制，使得不受信任的代码只能读写自己的那块内存，运行自己的代码，并通过正确的入口来调用应用程序中的指定函数。一个简单的方法是直接进程隔离，相互之间通过 RPC 来调用，这当然达到了目的，然而这也使得“插件”的失去了透明性，并引入了巨大的进程切换开销。

SFI 则将插件的代码和数据放在了一个沙盒中。沙盒中的内存写入和跳转指令都会被检查，防止写入或跳转到非法内存区域。开发者通过 sandboxer 把代码打包进沙盒，而用户则通过 verifier 检查沙盒的有效性。这样的好处在于，用户不需要关心较为复杂的 sandboxer 是否可信任，只需要确保较简单的 verifier 可信即可。

### Fault Domain

SFI 将不受信任的代码限制在一个 Fault Domain 中，一个 Fault Domain 包括：

- 唯一的 ID，用于 syscall 访问控制
- 代码段
- 数据段

一般长这样：

```
0x10000000 --------------  --
          |              |   |
          | Code Segment |   |
          |              |   |
0x100fffff --------------    |
0x10100000 --------------     } Fault Domain
          |              |   |
          | Data Segment |   |
          |              |   |
0x101fffff --------------  --
0x10200000 ⬇️ app memory
```

在这个例子中，段 ID 为前三位，即前 12 bits，代码段和数据段的段 ID 是不同的。不受信任的代码只能在代码段内跳转，在数据段内写入。对于静态的跳转和写入，例如 `JUMP 0x10030000`，只要检查目标地址就行，很容易做到。而对于动态的情况，就需要详细讨论了。

### 间接内存访问

比如我们现在有一条指令：

```asm
STORE R0, R1 ; write R1 to Mem[R0]
```

Sandboxer 会利用受信任的专用寄存器 `Ra`,`Rc`,`Rd`，重写指令为：

```asm
MOV Ra, R0     ; copy R0 into Ra
SHR Rb, Ra, Rc ; Rb = Ra >> Rc, to get segment ID
CMP Rb, Rd     ; Rd holds correct data segment ID
BNE fault      ; wrong data segment ID
STORE Ra, R1   ; Ra in data segment, so do write
```

我们知道，当执行到最后一行时 R0 已经通过了检查。为什么最后还是用 `STORE Ra, R1` 而不是直接像原来那样 `STORE R0, R1` 呢？因为第二种情况下，攻击者完全可以跳过中间的检查直接写入，而第一种情况下攻击者无法篡改专用寄存器 `Ra` 的值。

此时，沙盒的引入对于每条间接内存访问指令而言，额外增加了四条指令，并使用了 6 个寄存器，其中 5 个是专用寄存器（例子中使用了三个专用寄存器，此外还需要两个专用寄存器来 sanbox 不安全的代码地址），开销很大。能不能减小一点开销呢？

方法也比较简单，不检查目标地址是否在合法段中，直接强行让它处于合法段中：

```asm
AND Ra, R0, Re ; clear segment ID bits in Ra
OR Ra, Ra, Rf  ; set segment ID to correct value
STORE Ra, R1   ; do write to safe target address
```

此时只需要增加 2 条额外指令，使用 5 个专用寄存器。同理，间接跳转指令 `JR R0` 也类似：

```asm
AND Rg, R0, Re ; clear segment ID bits in Rg
OR Rg, Rg, Rh  ; set segment ID to correct value
JR Rg          ; do jump to safe target address
```

### Guard Zones

有时，我们还会遇到寄存器+偏移量类型的地址，这时 SFI 就需要多一步 `ADD` 操作。为了省去这一操作并确保结果仍然在合法段中，我们观察到偏移量的大小受到指令长度影响（在论文中的 MIPS 架构下是 64K），因此我们在段两端填上 unmapped 的 Guard Zone 就可以巧妙解决这一问题：

```
0x0fff0000 --------------  --
          | Guard Zone   |   |
0x10000000 --------------    |
          |              |   |
          | Code Segment |   |
          |              |   |
0x100fffff --------------    |
          | Guard Zone   |   |
0x1010ffff --------------     } Fault Domain
0x101f0000 --------------    |
          | Guard Zone   |   |
0x10200000 --------------    |
          |              |   |
          | Data Segment |   |
          |              |   |
0x102fffff --------------    |
          | Guard Zone   |   |
0x1030ffff --------------  --
0x10310000 ⬇️ app memory
```

在 sanboxing 的时候，直接无视偏移量，省去一次 `ADD` 指令，而后访问到 Guard Zone 时则触发 Trap。

### 局限性与拓展

论文中 SFI 应用于 MIPS 指令集，一个最重要的好处是 MIPS 指令集指令长度是固定的。然而，x86 架构下指令长度不固定，意味着跳转操作可能跳转到指令中间部分，造成难以预期的结果。同时，x86 也只有 4 个通用寄存器，很难满足那么多专用寄存器的要求。

Google 的 NativeClient 可以看作是 SFI 在 x86, x86-64 和 ARM 架构上的实现，目的就是为了让浏览器能执行浏览器插件的代码。如今 NativeClient 已经被 Web Assembly 取代。

另一种类似的技术 CFI 则可以在 x86 上运行，但是原理和 SFI 很不一样，主要是检查控制流图 CFG 判定跳转是否合法，因此也不需要专用寄存器。clang / LLVM 现在就包括了 CFI 的实现。

## OKWS

研究了这么多防御机制后，终于有人意识到防是防不住的，我们需要的是在遭受成功的攻击之后将损失降到最低。因此，需要遵循最小特权原则、需要将系统划分为子系统、需要严格定义接口的范围、需要严格控制授权的粒度。

对于暴露在外的易受攻击的服务，应尽可能减少其所能拥有的权限。例如 SSH 应配置为禁止 root 登陆。那么如何将系统划分为子系统？这就需要运行多个进程，每个进程由不同的用户运行，拥有不同的权限，借助 Unix 隔离机制防止用户读取 / 修改其他用户的数据。

Unix 也提供了这样的一个工具：`chroot`。它将进程视角中的根目录改为某个特定的目录，这样进程就无法访问那个目录以上的任何目录了。这样也导致一些系统文件必须预先放到要 `chroot` 的目录下，比如共享库，比较麻烦。

一种避免这类麻烦的方法是在高权限父进程中 `open` 文件，将 fd 传递给低权限的、被 `chroot` 的子进程。这样子进程不需要 `open` 文件也能读写该文件。很容易想到，socket 也是一种文件，因此网络连接也可以用同样的方式处理。

OKWS 的入口就是低权限的 okd，它在 chroot jail 里接收用户输入的 HTTP 请求，处理并传递到系统内部。内部的调用则主要通过 RPC 通信，因为这样能更严格地定义通信接口。换而言之，内部的组件即使以 root 运行也无需担心，因为子系统间的通信受到了严格管控。当然，这一定程度上也降低了透明性。

## Meltdown

学期最后一个主题被老师称为“甜点”，介绍了一种有趣的硬件层面的侧信道攻击 Meltdown。在 Meltdown 出现前，我们知道每个进程之间的内存是隔离的，OS 的内存和进程之间也是隔离的，因此恶意进程无法读取其他进程 / OS 的内存，现代容器技术的隐私保护也依赖于这一点。然而 Meltdown 出现后，这一切都不成立了。

Meltdown 是存在于 CPU 硬件层面的漏洞，使得恶意程序可以读取内核的内存。而内核内存中又保存了全部物理内存的映射，这又使得恶意程序可以读取任意进程的内存。对于容器来说，容器中的恶意程序可以读取其他容器的内存。

为了理解 Meltdown，需要一些前置知识。这些前置知识基本都在操作系统课上了解过，所以只作一些简单记录。

### 存储层级

![图 5｜存储层级示意图](5.png)

计算机中的存储单元分为多个层级，其中速度越快的单元容量越小，CPU 则优先从高速单元中读取数据。这种多级缓存的思想大概是计算机存储中最基本的原则之一。

当 CPU 从缓存中读取数据时，如果命中，速度会很快；如果没能命中，那就不得不从 DRAM 中读取数据并放到缓存中，不过缓存容量有限，因此会驱逐缓存中的一块数据。关于把新块放到哪里、以及选择哪个块驱逐，有各种不同的策略，不在这里的讨论范围内。

### 物理内存映射

![图 6｜物理内存映射](6.png)

我们知道，每个进程的虚拟地址空间中都包含了进程地址空间和内核地址空间两部分。对于进程来说，只能访问前者。进程所看到的虚拟地址空间仿佛是整个物理内存，尽管实际上并非如此。内核会将虚拟地址映射到不同的物理地址上。

为了提高性能和方便开发，内核地址空间中存在一段连续的内存区域，存放了物理内存的映射。可以想像，如果进程能够访问自己虚拟地址空间中的内核部分，就能够访问到物理内存从而访问其他进程的地址空间。

### CPU 流水线

所谓流水线，或者说 Pipelining，就是将一个过程分为独立的不同阶段，随后让对象按顺序经过这些阶段，这样同一时间里就可以有多个对象被同时处理。这种方式不像并行那样需要多个核，也不像顺序执行那样一次只能做一件事，一定程度上提高了效率。

为了进一步提高效率，还可以使用多个流水线并发执行，此时依然只需要单核：

```
1  2  3  4  5  6  7  8  9
A  B  C  D  E
   A  B  C  D  E
      A  B  C  D  E
         A  B  C  D  E
            A  B  C  D  E
```

在这个例子中，在时刻 5，CPU 可以并发处理 E D C B A 五阶段的任务。

### 乱序执行

然而，并不是每个阶段在轮到它执行时就能够立即执行，此时 CPU 就会空闲。为了避免空闲，CPU 可能会先执行那些后面的、已经准备好立即执行的步骤，并确保乱序执行不会影响最终结果。这一机制的引入极大幅度地提升了 CPU 性能。

### Flush + Reload

介绍完了背景，我们先来看看 Meltdown 使用的核心技术，即 Flush + Reload。首先，假如我们的目标是确定一个进程在一段时间内是否访问过其地址空间中的某个目标地址。为此，我们首先利用 `clflush` 清空缓存，随后等待一段时间后，尝试触发一次对目标地址的访问操作。

如果用时很短，这说明缓存命中。因为事先已经清空了缓存，所以进程一定在我们等待的这段时间里已经访问过目标地址了。反之，用时较长则说明在此期间没有访问过目标地址。

### Meltdown 概述

Meltdown 的目标则和上述目标不同：我们想要在一个用户态非 root 的进程中，从另一个进程的地址空间中读取数据。如上文所述，要达到这一目的，我们只要读取内核地址空间中存放物理内存映射的那一块地址上的值，具体读哪里只要经过一些计算就可以知道了。图 6 中的实线箭头就体现了这一过程。

同样利用 Flush + Reload：

- 分配 256 页（1 MB）进程地址空间，清空其对应的缓存
- 让 OS 不要在发生段错误的时候 kill 掉自己，这可以通过自己捕获 SIGSEGV 来做到
- 根据想要读取的另一个进程地址空间中的目标地址，计算出内核地址空间中对应的目标地址并读取（当 CPU 发现读取的地址非法时，会触发段错误，停止执行后续指令）
- 根据上面读取的结果计算出合法的、位于进程地址空间中的地址并读取（由于乱序执行，此时可能还没有触发段错误）
- 最后，我们依次读每一页，其中有一页上的读取速度比其他页都快，说明该页的序号就是第三步中读取到的内核地址上的值

这一概述还是比较抽象的，因此最好通过一个具体的例子来理解 Meltdown。

### Byte-at-a-Time

假设我们已经完成了前两步，此时 `rcx` 存放了我们想读取的内核地址，`rbx` 存放了 256 页地址空间的基地址。

```asm
xorq %rax, %rax
retry:
movb (%rcx), %al
shl %rax, $0xc
jz retry
movq (%rbx,%rax,1), %rbx
```

首先将 `rax` 置 0，接着尝试从 `rcx` 中读取一字节到 `al`，也就是 `rax` 低位。这一步最终一定会引发段错误，但由于乱序执行的存在，CPU 此时可能还没有意识到问题的严重性。CPU 按顺序执行第三行和第四行，但第四行可能在第三行之前执行完。

在第四行，我们执行 `rax = rax<<12`，就是将读取到的字节乘以页的大小 4K。如果运气不好，在执行第四行前就段错误了，那么就会在第五行 `jz` 到前面重试，最终一定能成功。

到了第六行，我们先计算 `rbx + rax`，这是第 `rax` 页的起始地址；然后从这个地址上读取一个值给 `rbx`，为的就是让这一页进入缓存。第四行和第六行对应了上文的第四步。

最后，只要依次读每一页，在缓存里的那页必定会快很多，从而可以由其序号推出 `rax>>12` 的值，也就是地址 `rcx` 上被读取的那一字节的值。

### Bit-at-a-Time

可以看到，为了获取内核中的一字节，Byte-at-a-Time 需要扫 256 页的内存，这所需要的时间远远大于运行 Meltdown 核心代码的时间。Bit-at-a-Time 改进了这一点，在读到内核内存中的一字节后，将其分为 8 个 bit。对每个 bit 执行类似的操作，这样如果该位是 0，那么第 0 页进入缓存；如果该位是 1，那么第 1 页进入缓存。

在每次扫描时，我们就只需要读一下第一页：如果较快，那么该位就是 1，否则就是 0。针对每个 bit 做类似扫描，使得读取内核内存中的一字节只需要 8 次扫描而不是 256 次。

### 防御

- 软件方法：通过 KPTI 修改内核，不再将内核地址空间映射到进程内存中，而是只在 syscall 时这么做，性能开销浮动较大
- 硬件方法：修改 CPU，使得读取内存时检查目标地址是否合法，这一方法依然会遭受一种类似的名为 Fallout 的攻击

## 参考资料

- [Design and Implementation of the Sun Network Filesystem](https://inst.eecs.berkeley.edu/~cs262/sp02/Papers/nfs.pdf)
- [Memory coherence in shared virtual memory systems](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.14.3607&rep=rep1&type=pdf)
- [Paxos Made Simple](https://lamport.azurewebsites.net/pubs/paxos-simple.pdf)
- [Time, Clocks, and the Ordering of Events in a Distributed System](https://lamport.azurewebsites.net/pubs/time-clocks.pdf)
- [Managing Update Conflicts in Bayou, a Weakly Connected Replicated Storage System](https://people.cs.umass.edu/~mcorner/courses/691M/papers/terry.pdf)
- [The Google File System](https://static.googleusercontent.com/media/research.google.com/zh-CN//archive/gfs-sosp2003.pdf)
- [Eliminating Receive Livelock in an Interrupt-driven Kernel](https://web.stanford.edu/class/cs240/readings/p217-mogul.pdf)
- [Kerberos: An Authentication Service for Open Network Systems](https://www3.nd.edu/~dthain/courses/cse66771/summer2014/papers/kerberos.pdf)
- [Authentication in the Taos Operating System](https://pdos.csail.mit.edu/archive/6.824-2001/papers/taos-sosp.pdf)
- [Smashing The Stack For Fun And Profit](http://phrack.org/issues/49/14.html#article)
- [Exploiting Format String Vulnerabilities](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)
- [Once upon a free()](http://phrack.org/issues/57/9.html#article)
- [Dynamic Taint Analysis for Automatic Detection, Analysis, and Signature Generation of Exploits on Commodity Software](https://valgrind.org/docs/newsome2005.pdf)
- [PaX Overview](http://pax.grsecurity.net/docs/pax.txt)
- [ASLR Overview](http://pax.grsecurity.net/docs/aslr.txt)
- [On the Effectiveness of Address-Space Randomization](https://benpfaff.org/papers/asrandom.pdf)
- [Efficient Software-Based Fault Isolation](https://courses.cs.washington.edu/courses/cse551/15sp/papers/sfi-sosp93.pdf)
- [Building Secure High-Performance Web Services with OKWS](https://vm-web.pdos.csail.mit.edu/papers/okws-usenix04.pdf)
- [Meltdown: Reading Kernel Memory from User Space](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-lipp.pdf)
