---
title: 风雨无阻：crontab + at 实现随机定时任务
date: 2020-01-23
tags:
  - Linux
  - 实践记录
categories:
  - 自动化
---

定时任务相关的命令，使用起来坑非常多。

<!--more-->

## 需求

需要在每日 9-12 时中的某个随机时间执行 python 脚本 `cron.py`。这个需求非常简单，然而实现起来却很容易踩坑。

## 实现与踩坑

首先可以创建一个文件编写 crontab 任务，例如我创建了 `merccron` 这个文件：

```
0 9 * * * sudo ./cron.sh >> ./cron.log 2>&1
```

我们之后编写 `cron.sh`。这里从左到右分别可以设置执行任务的分钟、小时、日、周、月、以及执行的具体命令。最后的 `2>&1` 将标准错误流重定向到标准输出流。

然而这样是不会成功执行的，因为 crontab 不会自动设置环境变量，因此**涉及到的文件路径需要使用绝对路径**，也就是：

```
0 9 * * * sudo /root/cron.sh >> /root/cron.log 2>&1
```

我们提交 crontab 任务：

```shell
$ crontab merccron
```

随后 `crontab -l` 即可看到自己的 crontab 任务，并且可以通过 `crontab -e` 修改。

随后，考虑到随机性的要求，我们可以使用 `at` 命令。`at` 命令可以指定在多久之后执行某一命令，例如：

```shell
$ at now+10year
echo 'Hello World' > hello.log
```

就会在十年后输出 `Hello World` 到 `hello.log` 文件。然而这里是需要我们从标准输入流输入命令的，这不利于我们进行自动化。幸运的是 `at` 命令提供了 `-f` 选项，可以指定从一个文件中读取命令。需要注意的是，这里 `-f` 的参数**只能是文件**，尝试 `at -f "python3 cron.py>> cron.log" now+10year` 并不会成功。

那么我们先编写 `cron.sh`：

```bash
#!/bin/bash
min=$((3*60))
rmin=$(($RANDOM%$min))
at -f /root/1.sh now+${rmin}min
```

由于需要位于 9-12 时之间，而 crontab 任务在 9 时整执行，我们产生一个 `0-180` 之间的随机整数 `rmin`，然后在 `now+rmin` 分钟后执行，就会落在 9-12 时区间内。由于吃了 crontab 的亏，这里 `1.sh` 也用了绝对路径。

最后，`1.sh` 只需要一条命令：

```shell
$ python3 cron.py >> cron.log
```

这里首先是没有使用绝对路径，这是因为与 crontab 不同，`at` 命令会在执行用户命令前**自动设置好环境变量与工作目录**；其次是缺少了 `#!/bin/bash` 这行，这同样是因为 `at` 命令会自动在用户命令前加一大串初始化脚本，而脚本的开头就有 `#!/bin/sh` 这行（注意是用 `sh` 而不是用 `bash` 执行）。这点可以通过 `at -c 任务编号 ` 查看所要执行的完整命令得知。而要获取任务编号，只需要在定时任务已经设置但还未执行完毕时，运行 `atq` 查看任务队列即可。

在完成 `crontab` 文件、`cron.py`、`cron.sh`、`1.sh` 四个文件之后，最后一件事是确保**当前用户对后三个文件拥有可执行权限**。只有避过了以上所有坑，这个简单的需求才能算做完了。

## 有趣的网站

- [Crontab.guru](https://crontab.guru/)
