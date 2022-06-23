---
title: Beef 加载 Metasploit 插件 & Metasploit 连接 PostgreSQL
date: 2019-07-21 12:17:14
tags:
  - Kali
  - 实践记录
categories:
  - 安全工具
featuredImage: 0.png
---

没有什么坑点。

<!--more-->

## Beef 加载 Metasploit 插件

修改 beef 的配置文件 `/usr/share/beef-xss/config.yaml`，找到 `extension` 下的 `metasploit` 字段，修改为 `true`。此外，建议修改 `credentials` 下的密码字段。

随后修改 `/usr/share/beef-xss/extensions/metasploit/config.yaml`，找到 `beef->extension->metasploit` 下的 `host` 和 `callback_host` 字段，都改为虚拟机的内网 IP。最后，在倒数第二行找到：

```json
{ "os": "custom", "path": "" }
```

改为：

```json
{ "os": "custom", "path": "/usr/share/metasploit-framework/" }
```

配置文件修改完后，启动 `msfconsole`，输入：

```shell
$ load msgrpc ServerHost=192.168.159.135 Pass=abc123
```

来启用 `msgrpc` 插件。其中 `ServerHost` 字段是本机内网 IP，`Pass` 字段默认是 `abc123`，可以在上面的 `/usr/share/beef-xss/extensions/metasploit/config.yaml` 里修改。

回到 `beef-xss` 目录里运行 `./beef -x`，使得修改后的配置文件生效。至此，MSF 插件已经加载完毕。

## Metasploit 连接 PostgreSQL

```shell
$ service postgresql start
$ msfdb init
```

这样两步就够了，检查是否成功：

```shell
$ msfconsole
$ db_status
```

连接以后就可以使用 PostgreSQL 存储我们收集到的信息了，例如在 msfconsole 中执行 `nmap` 不会影响数据库，但 `db_nmap` 的结果则会存到数据库里。
