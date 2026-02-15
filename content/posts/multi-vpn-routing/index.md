---
title: "殊途迷归：多 VPN 共存环境下的内网路由排查"
date: 2026-02-15
tags:
  - 网络
categories:
  - 探索
---

记录一次 Tailscale 与公司 VPN 路由冲突的排查过程。

<!--more-->

## 前言

日常开发中，不少人会在工作电脑上同时运行多个 VPN 或虚拟网络工具。当这些工具管理的网段发生重叠时，就可能出现"明明网络通着，某些内网网站就是打不开"的诡异现象。这类问题的排查思路与安全应急响应有相似之处：线索零散、现象误导性强，需要逐步缩小范围、验证假设。

本文记录了一次在 macOS 上排查内网网站无法访问的完整过程。问题的根源在于 Tailscale 与阿里 VPN 两套虚拟网络对 `100.64.0.0/10` 网段的路由冲突，但在排查过程中经历了数次方向调整。希望这个案例能为遇到类似多 VPN 共存问题的人提供一些参考。

## 环境背景

主机上同时运行着以下网络组件：

+ **en0**：本地办公网络，IP 为 `10.70.33.180/21`，默认网关 `10.70.39.254`
+ **AliLang VPN (utun5)**：阿里内网 VPN，IP 为 `30.69.177.237`，负责路由阿里内网流量
+ **Tailscale (utun6)**：个人虚拟组网工具，IP 为 `100.109.0.41`，用于点对点连接个人设备

问题表现为：运行了一个手写的路由脚本 `setRoute.sh` 后，仍然无法访问公司内网中 `100.64.x.x` 网段的网站（如 `[REDACTED].aliyun-inc.com`）。但关闭 Tailscale 后，这些网站可以正常访问。

## 排查过程

### 检查路由脚本

首先检查 `setRoute.sh` 的内容：

```bash
#!/bin/sh
sudo route -n delete -net 100.64.0.0/10
sudo route -n add -net 100.64.0.0/10 -interface en0
```

这个脚本试图将 `100.64.0.0/10` 网段直接路由到 `en0` 网卡接口，是之前解决 Tailscale 和阿里内网网段冲突时写的脚本。检查路由表时发现一个关键细节：

```
100.64/10          link#14            UCSc                  en0      !
```

末尾的 `!` 标志表示该路由处于**拒绝状态**。这是因为 `-interface en0` 指令告诉系统在本地链路上直接寻找 `100.64.x.x` 的主机（类似 ARP 广播），但这些主机显然不在本地局域网中，系统无法完成地址解析，路由因此被标记为拒绝。

> 使用 `-interface` 参数适用于目标主机与本机在同一个二层网络的场景（如直连网段）。对于需要经过三层转发才能到达的网段，应当指定下一跳网关地址。

### 第一次修正：指定网关

将脚本修改为通过默认网关 `10.70.39.254` 转发：

```bash
sudo route -n add -net 100.64.0.0/10 10.70.39.254
```

路由表中 `!` 标志消失了，看起来一切正常：

```
100.64/10          10.70.39.254       UGSc                  en0
```

但依然无法访问内网网站。后来意识到，`10.70.39.254` 是办公网络的出口网关，它并不知道如何将流量转发到阿里内网的 `100.64.x.x` 网段——这是公司内部网络的地址段，需要通过专门的 VPN 通道才能到达。

### 排查 Tailscale 干扰

既然关闭 Tailscale 就能访问，问题大概率与 Tailscale 有关。检查 Tailscale 配置：

```bash
$ tailscale debug prefs 2>&1 | grep -i "route"
	"RouteAll": true,
```

`RouteAll: true` 意味着 Tailscale 会接管所有流量的路由决策。同时路由表中存在 Tailscale 的默认路由：

```
default            link#24            UCSIg               utun6
```

这条默认路由会与 en0 的默认路由竞争，可能导致 `100.64.x.x` 的流量被错误地送入 Tailscale 网络。

关闭路由接管：

```bash
$ tailscale set --accept-routes=false
```

> `accept-routes` 控制的是 Tailscale 是否接受其他节点共享的路由（即 subnet routes），关闭后**不影响**直接访问 Tailscale 网络中的设备。每个 Tailscale 设备都有独立的主机路由（`/32`），优先级高于网段路由（`/10`），因此即使存在同网段的路由规则，Tailscale 设备仍然可达。

但关闭后依然无法访问，看来 Tailscale 不是唯一的问题。

### DNS 验证

通过 DNS 解析确认目标网站的 IP 地址：

```bash
$ nslookup [REDACTED].aliyun-inc.com
Server:		100.100.100.100
Address:	100.100.100.100#53

Non-authoritative answer:
[REDACTED].aliyun-inc.com	canonical name = [REDACTED].aliyun-inc.com.
...
Address: 100.67.17.239
Address: 100.64.26.230
Address: 100.67.96.137
```

DNS 解析正常，返回的 IP 均在 `100.64.0.0/10` 范围内。用 `curl` 测试连接：

```bash
$ curl -v --connect-timeout 5 https://[REDACTED].aliyun-inc.com
* IPv4: 100.64.26.230, 100.67.17.239, 100.67.96.137
*   Trying 100.64.26.230:443...
* ipv4 connect timeout after 2442ms, move on!
*   Trying 100.67.17.239:443...
* ipv4 connect timeout after 1219ms, move on!
* Failed to connect to [REDACTED].aliyun-inc.com port 443 after 5005 ms: Timeout was reached
```

三个 IP 全部超时。`route -n get` 确认流量走的是 en0 + 默认网关，路径看似正确但根本不通。到这里可以确定，**办公网络的默认网关无法转发 `100.64.x.x` 的流量**。

### 发现 AliLang VPN

在继续排查时，注意到路由表中还有一组路由指向 `utun5` 接口：

```
10                 30.69.177.237      UGSc                utun5
11                 30.69.177.237      UGSc                utun5
30                 30.69.177.237      UGSc                utun5
33                 30.69.177.237      UGSc                utun5
42.120/16          30.69.177.237      UGSc                utun5
...
```

检查进程列表确认了 `utun5` 的身份：

```bash
$ ps aux | grep -i vpn
root  1911  ... /Applications/AliLang.app/.../ALiLangVPN -v6 -user /Users/merc
```

这是阿里的 VPN。它为阿里内网的多个网段（`10/8`、`11/8`、`30/8`、`33/8` 等）配置了路由，**但唯独缺少 `100.64.0.0/10` 网段的路由**。

到这里，所有现象都说得通了：

+ **关闭 Tailscale 时**：`100.64.x.x` 走默认路由 `10.70.39.254`，而此时没有 Tailscale 的默认路由干扰，办公网关通过某种方式（可能是内部路由协议）将流量转发到了正确的目的地
+ **开启 Tailscale 时**：Tailscale 的默认路由与 en0 的默认路由竞争，`100.64.x.x` 的流量被送入 Tailscale 网络，自然无法到达阿里内网

### 最终修复

将 `100.64.0.0/10` 路由到阿里 VPN 的网关地址：

```bash
$ sudo route -n add -net 100.64.0.0/10 30.69.177.237
add net 100.64.0.0: gateway 30.69.177.237
```

验证连接：

```bash
$ curl -v --connect-timeout 5 https://[REDACTED].aliyun-inc.com
*   Trying 100.67.96.137:443...
* Connected to [REDACTED].aliyun-inc.com (100.67.96.137) port 443
* ALPN: curl offers h2,http/1.1
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
...
```

连接成功，TLS 握手正常完成。

最终的路由脚本修改为：

```bash
#!/bin/sh
# Route 100.64.0.0/10 network to AliLang VPN (utun5)
sudo route -n delete -net 100.64.0.0/10 2>/dev/null || true
sudo route -n add -net 100.64.0.0/10 30.69.177.237
```

## 复盘

回顾整个排查过程，走了不少弯路。几个值得反思的点：

**先搞清楚网络拓扑，再动手改配置。** 一开始在不清楚 `100.64.x.x` 应该走哪条链路的情况下，就尝试修改路由的下一跳地址，导致了无效的修复尝试。如果一开始就列出主机上所有的网络接口和对应的路由规则，很容易发现 AliLang VPN 缺少了这个网段的路由。

**"关掉 X 就好了"是最重要的线索。** 其实一开始就注意到关闭 Tailscale 后内网可以正常访问，这条信息本应直接指明问题方向，但排查时反而绕了远路。网络问题中，环境的增减变化（关闭某个服务、断开某个连接）往往是最有价值的对照实验，值得优先深挖。

**多 VPN 共存时，关注路由优先级和网段重叠。** `100.64.0.0/10` 是 IANA 分配的 Carrier-Grade NAT 地址段（RFC 6598），Tailscale 和阿里内网恰好都在使用这个地址空间。当多个 VPN 管理的网段存在重叠时，路由表中的条目优先级和覆盖关系往往是问题的根源。排查时可以用 `route -n get <target_ip>` 精确查看某个目标 IP 实际会走哪条路由，比直接看路由表更直观。

**`-interface` 与网关路由的区别。** 原始脚本使用 `-interface en0` 是一个基础性错误。`-interface` 适用于直连网段（目标在同一个二层域），而需要三层路由转发的场景必须指定网关地址。这个区别一开始就该意识到，可以少走一步弯路。


## 参考资料

1. 本文排查过程中使用了 Claude Code 协助分析路由表、梳理排查思路、编写详细文档，在此致谢。
