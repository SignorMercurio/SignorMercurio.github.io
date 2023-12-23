---
title: 舍近求远：开通 IPv6 隧道
date: 2019-09-26
tags:
  - 网络
  - 实践记录
categories:
  - 探索
---

喜迎国庆。

<!--more-->

新配置的代理服务器访问谷歌时，有时会遇到要求人机身份验证的问题。查找了一些资料后，发现应该是谷歌 ban 了对应的 IPv4 地址所导致的（说到这里，记录一个 [好用的网站](https://www.whatismyip.com/)）。

最简单的解决办法就是使用 IPv6 进行访问，为此我们需要开通一个 IPv6 隧道。在这个 [良心网站](https://www.tunnelbroker.net) 上注册个账号，然后 `Create Regular Tunnel`，填写服务器 IPv4 地址并选择隧道服务器后，就能看到隧道的详细信息了。例如，`Client IPv6 Address` 显示了我们的服务器的 IPv6 地址。

接下来，在 `Example Configurations` 中选择自己服务器的 OS，并根据提示在服务器上完成相应配置即可。Debian 和 Ubuntu 有自己的选项，CentOS 及其它常用 Linux 系统可以选择 `Linux-net-tools`。

至此，服务器已经可以通过 IPv6 访问谷歌了，测试：

```shell
$ ping6 ipv6.google.com
```

注：可能需要在 `/etc/hosts` 中加入部分 [谷歌相关 IPv6 地址](https://raw.githubusercontent.com/lennylxx/ipv6-hosts/master/hosts)。
