---
title: 持戈试马：在 MacBook Pro M1 上运行 Windows 11
date: 2021-08-26 22:57:42
tags:
  - ARM
  - 实践记录
categories:
  - 探索
---

拖了很久才来尝鲜。

<!--more-->

借助 Parallels Desktop 17，搭载 M1 芯片的 MBP 也可以运行 **ARM 版**的 Windows 了。很想尝试一下最新的 Win11，但却发现不满足需要 TPM 芯片的要求，因此想办法绕过了这一限制。

## 获取系统 ISO

为了绕过 TPM，需要采用从 Win10 升级的方法。首先在 [UUP dump](https://uupdump.net/) 下载 Win10 arm64 及 Win11 arm64 的脚本（测试时采用的均为最新的 Insider Preview 版本），在一台 Windows 电脑上运行 `uup_download_windows.cmd` 即可打包好两个 ISO。

> 之所以需要 Windows 电脑来运行脚本，是因为需要在 ISO 中包含 Windows 更新。如果无视更新，也可以在 Linux 或 macOS 上运行相应平台的脚本。

## 手动制作升级包

通过正常流程在 Parallels 中安装好 Win10 虚拟机，随后将两个 ISO 拖入虚拟机中。将 Win10 的 ISO 中的全部文件复制到虚拟机中的一个目录下，随后用 Win11 的 ISO 中的如下三个文件，替换该目录下的同名文件：

1. `sources/install.wim`
2. `sources/boot.wim`
3. `sources/winsetupboot.sys`

这样升级包就做完了。可以发现，这样做本质上是为了在安装 Win 11 时，让安装向导认为安装的系统版本是 Win10。

## 升级到 Windows 11

运行上述目录下的 `setup` 程序，耐心等待即可。

## 后续版本升级

由于 Windows 11 ARM 还在预览体验阶段，需要拥有一个注册了 Windows 预览体验计划的账号并在虚拟机里登录。登录后就可以在设置中方便地进行后续更新了。

## 激活

经过粗略调查，目前唯一比较可靠的非正规方法是使用 HEU KMS 24 这款激活工具，使用前需要关闭 Windows 安全中心的病毒防护相关功能。
