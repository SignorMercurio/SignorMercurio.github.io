---
title: 自动装弹：快速搭建通用命令行环境
date: 2022-10-24
tags:
  - Linux
categories:
  - 自动化
---

面对一台新的 Linux 机器时，不用为了重搭环境头疼了。

<!--more-->

## 背景

我们在拿到一台新的 Linux 机器（物理机、虚拟机、云服务器、Docker 等）时，往往会有些束手无策，因为我们平时所习惯的环境在这台机器上都还没有配置，最典型的莫过于 zsh 以及相应的主题和插件。幸运的事，许多命令行工具都会提供一个以 `.` 开头的配置文件，我们将配置写入其中，就可以把配置文件传到新机器里来实现对该工具的统一配置。

然而，这种做法存在诸多缺陷：

1. 对于每一台新机器，都需要手动传配置文件过去
2. 对于每一种需要使用的工具，都需要管理一份对应的配置文件，不同工具的配置文件路径可能千差万别
3. 配置文件更新后，需要再次传输，缺少同步机制
4. 配置文件更新出错后无法回滚，即缺少修改历史信息
5. 系统不自带的工具依然需要重复输入相同的命令进行安装

为了解决以上问题，我们可以创建一个 dotfiles 仓库用于统一存放我们的配置文件，并为这个仓库加上版本控制。为了让这些配置文件能方便地生效并安装一些其他工具，我们引入 [dotbot](https://github.com/anishathalye/dotbot) 来实现对 dotfiles 的管理。

## 开始上手

我们可以使用 [init-dotfiles](https://github.com/Vaelatern/init-dotfiles) 脚本自动生成 dotfiles 仓库，其中包含了一个名称为 dotbot 的 git submodule。随后就可以在仓库内编写 dotfiles 了，为了和真正的配置文件区别并方便查看，可以去掉开头的 `.`，例如在 `zshrc`（而不是 `.zshrc`）中编写 zsh 配置，随后用软链接来链接到配置文件的默认位置。

我们不修改工具读取配置文件的位置，主要是因为修改方式因工具而异，不利于自动化。因此，全部采用默认的配置文件位置，然后在 `install.conf.yaml` 中设置软链接的映射：

```yaml
- link:
    ~/.config:
    ~/.shell:
    ~/.gitconfig:
    ~/.npmrc:
    ~/.ssh/config: ssh_config
    ~/.tmux.conf:
    ~/.vimrc:
    ~/.yarnrc:
    ~/.zshrc:
```

不填时则默认映射到去除开头 `.` 的文件，如 `~/.zshrc` 映射到 `zshrc`。以上面的配置为例，dotfiles 仓库下的 `ssh_config` 文件会软链接到 `~/.ssh/config`。

## 简单配置

设置了映射后，我们可以对 dotbot 进行进一步配置，例如 `defaults.link.create` 可以在目标文件不存在时自动创建文件，而 `defaults.link.relink` 则可以自动删除已经存在的目标文件并重新进行软链接。因为这些值在 `defaults` 下，所以我们可以在 `link` 下的每一项里单独覆盖掉这些值。`clean` 则会自动删除指定目录下的无效软链接。这种设计使得 dotbot 可以多次运行而不出现问题，即确保了幂等性。

```yaml
- defaults:
    link:
      create: true
      relink: true

- clean: ["~"]
```

## 安装工具

我们还可以设置 dotbot 运行时需要额外运行的命令，默认命令是：

```yaml
- shell:
    - [git submodule update --init --recursive, Installing submodules]
```

这样可以确保 dotbot 是最新的。接下来我们就可以自己编写脚本放到这里：

```yaml
- shell:
    - [git submodule update --init --recursive, Installing submodules]
    - command: ~/.dotfiles/scripts/all.sh
      stdout: true
      description: Preparing dev environment
```

> 注意在 shell 脚本（非交互式环境）中使用别名需要运行 `shopt -s expand_aliases` 来扩展别名。

dotbot 还支持更多细粒度的配置，可以参考 [dotbot 的 README](https://github.com/anishathalye/dotbot)。

## 差异化配置

有时，我们希望一个工具的一部分配置是在各个机器上通用的，而另一部分配置仅对本机适用。此时我们需要将配置文件分为两个文件，例如像这样在 `zshrc` 末尾添加：

```shell
# Allow local customizations in the ~/.zshrc_local file
if [ -f ~/.zshrc_local ]; then
    source ~/.zshrc_local
fi
```

这样 `zshrc` 中的内容是通用的，而 `~/.zshrc_local` 中的内容则只会在本地生效。同理，对于 `ssh_config` 而言，我们可以在开头包含一个本地的配置文件：

```
Include ~/.ssh/config_local
```

此时 `ssh_config` 中的内容是通用的，而 `~/.ssh/config_local` 中的内容只在本地生效。

另外，由于有时我们会软链接整个目录，有些工具会在目标目录中创建配置文件从而使得我们的版本控制中也出现这些配置文件。例如，当 macOS 和 Linux 共用一套 dotfiles 时，显然 `~/.config/iTerm2` 是 Linux 无需关心的配置文件，此时可以将这些目录加入 `.gitignore`。

## 运行 dotbot

在完成了配置以后，我们就可以在新机器上通过简单的命令来搭建环境了：

```bash
$ git clone https://github.com/SignorMercurio/dotfiles.git
$ mv dotfiles .dotfiles
$ .dotfiles/install
```

得益于版本控制的存在，我们可以方便地查看/回滚历史、以及在不同机器上同步配置。因为软链接的特性，在更新配置文件时只需要更新 dotfiles 仓库内的配置文件而无需关心配置文件的实际位置。而由于运行 dotbot 的幂等性，即使添加新配置文件也只需要再次运行 `install`，十分方便。
