---
title: "命令交互：Shell 备忘录"
date: 2022-04-30T17:13:19+08:00
tags:
  - Linux
categories:
  - 编程语言
---

记录一些之前不太了解的 Shell 的用法。

<!--more-->

## 常用快捷键
- <kbd>Ctrl+A</kbd> 回到本行起始位置
- <kbd>Ctrl+U</kbd> 清空本行
- <kbd>Ctrl+L</kbd> 清屏并回到顶部

## 引号
`"` 字符串会替换变量值，而 `'` 字符串不会：
```shell
$ foo=bar
$ echo "$foo"
# bar
$ echo '$foo'
# $foo
```

## 特殊变量
-   `$0` - 脚本名
-   `$1` 到 `$9` - 脚本的参数， `$1` 是第一个参数，依此类推
-   `$@` - 所有参数
-   `$#` - 参数个数
-   `$?` - 上一个命令的返回值
-   `$$` - 当前进程 PID
-   `!!` - 完整的上一条命令（含参数）
	- 常见应用：当因权限不足而执行命令失败时，可以使用 `sudo !!` 再尝试一次
-   `$_` - 上一条命令的最后一个参数
	- 交互式 shell 中也可以通过按下 `Esc` 之后键入 `.` 来获取这个值

## 通配符
- `?` 只匹配单个字符，如 `foo?` 可以匹配 `foo1`，但不能匹配 `foo42`
- `image.{jpg,png}` 扩展为 `image.jpg image.png`
- `touch {foo,bar}/{a..j}` 扩展为 `foo/a foo/b ... foo/j bar/a bar/b ... bar/j`

## Shebang
- `#!/bin/bash` 使用 bash 执行脚本
- `#!/usr/local/bin/python` 使用 python 执行脚本，可以 `./script.py`
- 推荐在 shebang 中使用 `env` 来解析环境变量，如 `#!/usr/bin/env python`
- `source script.sh` 在当前 shell 进程中生效，`./script.sh` 则启动新进程

## 重定向
- `<(CMD)` 会执行 `CMD` 并将结果输出到一个临时文件中，并用文件名替换 `<(CMD)` 本身
	- 例如 `diff <(ls foo) <(ls bar)` 可以对比两个目录的区别
- `>` 标准输出重定向（`1>`），`2>` 标准错误输出重定向，`&>` 标准输出和标准错误输出重定向
- `nohup [cmd] >logs 2>&1 &`

例：有如下脚本，需要一直运行直到出错并记录运行次数、输出日志：
```shell
#!/usr/bin/env bash

n=$(( RANDOM % 100 ))

if [[ n -eq 42 ]]; then
   echo "Something went wrong"
   >&2 echo "The error was using magic numbers"
   exit 1
fi

echo "Everything went according to plan"
```

解答：
```shell
#!/usr/bin/env bash

cnt=1

while true
do
    ./script.sh 2> out.log
    if [[ $? -ne 0 ]]; then
        echo "failed after $cnt times"
        cat out.log
        break
    fi
    ((cnt++))
done
```

## 查找
```shell
# 查找所有名称为 src 的目录
$ find . -name src -type d
# 查找所有路径中包含 test 的 python 文件
$ find . -path '**/test/*.py' -type f
# 查找前一天修改的所有文件
$ find . -mtime -1
# 查找所有大小在 500k 至 10M 的 tar.gz 文件
$ find . -size +500k -size -10M -name '*.tar.gz'
# 删除全部扩展名为.tmp 的文件
$ find . -name '*.tmp' -exec rm {} \;
# 查找全部的 PNG 文件并将其转换为 JPG
$ find . -name '*.png' -exec convert {} {}.jpg \;
# 查找命令历史中包含 find 的命令
$ history | grep find
```

此外，<kbd>Ctrl+R</kbd> 也可以直接查找命令历史。

例：递归地查找文件夹中所有的 HTML 文件，并将它们压缩成 zip 文件。文件名中可能包含空格。

```shell
$ mkdir html_root && cd html_root
$ touch {1..10}.html
$ mkdir html
$ touch "html/1 1.html"
$ find . -type f -name "*.html" | xargs -d '\n' tar -zcvf html.zip
```

## 数据处理
查看非法 SSH 登录：
```shell
$ ssh server 'journalctl | grep sshd | grep "Disconnected from"' > ssh.log
$ less ssh.log
```
提取用户名：
```shell
$ cat ssh.log | sed -E 's/.*Disconnected from (invalid |authenticating )?user (.*) [^ ]+ port [0-9]+( \[preauth\])?$/\2/'
```
[这一网站](https://regex101.com) 可以在线测试正则表达式。

去除重复的用户名，注意使用 `uniq` 去重前需要先确保相同的行是相邻的。这里可以用 `sort` 做到：
```shell
$ cat ssh.log | sed -E 's/.*Disconnected from (invalid |authenticating )?user (.*) [^ ]+ port [0-9]+( \[preauth\])?$/\2/' | sort | uniq -c
```
随后对第一列（`-k1`），也就是出现次数再按数字序（`-n`）降序（`-r`）排序，打印前 10 位：
```shell
$ cat ssh.log | sed -E 's/.*Disconnected from (invalid |authenticating )?user (.*) [^ ]+ port [0-9]+( \[preauth\])?$/\2/' | sort | uniq -c | sort -rnk1 | head -n10
```
只打印用户名：
```shell
$ cat ssh.log | sed -E 's/.*Disconnected from (invalid |authenticating )?user (.*) [^ ]+ port [0-9]+( \[preauth\])?$/\2/' | sort | uniq -c | sort -rnk1 | head -n10 | awk '{ print $2 }'
```
awk 中，`$0` 表示整行内容，`$1` 到 `$n` 表示该行的第 n 个区域，分隔符通过 `-F` 指定，默认为空格。

统计所有登录超过 1 次的登录次数之和：
```shell
$ cat ssh.log | sed -E 's/.*Disconnected from (invalid |authenticating )?user (.*) [^ ]+ port [0-9]+( \[preauth\])?$/\2/' | sort | uniq -c | awk '$1 != 1 { print $1 }' | paste -sd+ | bc -l
```

杀死指定进程：

```shell
$ ps -ef | grep [key] | awk '{print $2}' | xargs kill -9
```

## 非预装工具

- 语法错误检查 [shellcheck](https://github.com/koalaman/shellcheck)
- 简短帮助信息 [tldr](https://github.com/tldr-pages/tldr)
- find 改良 [fd](https://github.com/sharkdp/fd)
- grep 改良 [ripgrep](https://github.com/BurntSushi/ripgrep)
- top 改良 [htop](https://htop.dev)
- 目录跳转 [z](https://github.com/rupa/z)
- 历史命令模糊查找 [fzf](https://github.com/junegunn/fzf)
- 打印目录结构 [tree](https://linux.die.net/man/1/tree)
- 终端多路复用 [tmux](https://www.man7.org/linux/man-pages/man1/tmux.1.html) [screen](https://www.man7.org/linux/man-pages/man1/screen.1.html)
- 压力测试 [stress](https://linux.die.net/man/1/stress)
- [dotfiles 工具](https://dotfiles.github.io/utilities/)
