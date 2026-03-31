---
title: "殊途迷归：多 VPN 共存环境下的内网路由排查"
date: 2026-03-31
tags:
  - 网络
categories:
  - 探索
---

记录一次 Tailscale 与公司 VPN 路由冲突的排查过程。

<!--more-->

## 前言

日常开发中，不少人会在工作电脑上同时运行多个 VPN 或虚拟网络工具。当这些工具管理的网段发生重叠时，就可能出现"明明网络通着，某些内网网站就是打不开"的诡异现象。更棘手的是，修好一边又可能搞坏另一边——跷跷板式的故障最难定位。

本文记录了一次在 macOS 上排查这类问题的完整过程。问题的根源在于 Tailscale 与阿里 VPN 两套虚拟网络对 `100.64.0.0/10` 网段的路由冲突，而且这个冲突是**双向**的：不论把这个网段的路由指向哪一方，另一方就会断。

## 环境背景

主机上同时运行着以下网络组件：

+ **en0**：本地办公网络，IP 为 `30.221.130.169/19`，默认网关 `30.221.128.1`
+ **AliLang VPN (utun20)**：阿里内网 VPN，IP 为 `30.42.89.162`，负责路由阿里内网流量
+ **Tailscale (utun24)**：个人虚拟组网工具，IP 为 `100.109.0.41`，用于点对点连接个人设备

问题表现为一个跷跷板：

+ **启动 Tailscale** 后，无法访问部分阿里内网地址（如 `[REDACTED].aliyun-inc.com`）
+ **运行 `setRoute.sh`** 把 `100.64.0.0/10` 路由到 AliLang VPN 后，阿里内网恢复，但 Tailscale 组网中的设备又访问不了了（如 `airship.tailnet-xxxx.ts.net`）

之前的排查止步于"把路由指向 AliLang VPN"，以为问题解决了，实际上只修了一半。

## 排查过程

### 症状确认

先确认两边的连通性。当前已运行过 `setRoute.sh`，路由表中 `100.64/10` 指向 AliLang VPN：

```
100.64/10          30.42.89.162       UGSc               utun20
```

测试连接：

```bash
$ curl -sSo /dev/null -w "%{http_code} %{time_total}s" --connect-timeout 5 https://[REDACTED].aliyun-inc.com/
302 0.186s    # 阿里内网正常

$ curl -sSko /dev/null -w "%{http_code} %{time_total}s" --connect-timeout 5 https://airship.tailnet-xxxx.ts.net:6443/
000 0.320s    # Tailscale 节点不通，SSL_ERROR_SYSCALL
```

果然，修好了阿里内网就搞坏了 Tailscale。

### DNS 解析：揭示网段重叠

分别解析两个域名，看它们的 IP 落在什么范围：

```bash
$ nslookup [REDACTED].aliyun-inc.com
Server:		100.100.100.100
Address:	100.100.100.100#53

Non-authoritative answer:
...
Address: 100.67.201.67
Address: 100.67.183.169
Address: 100.67.202.232
Address: 100.64.29.27

$ nslookup airship.tailnet-xxxx.ts.net
Server:		100.100.100.100
Address:	100.100.100.100#53

Name:	airship.tailnet-xxxx.ts.net
Address: 100.109.15.92
```

关键发现：**两者的 IP 都落在 `100.64.0.0/10` 范围内**。阿里内网用的是 `100.64.x.x` ~ `100.67.x.x`，Tailscale 节点用的是 `100.109.x.x`。这个网段是 IANA 分配的 Carrier-Grade NAT 地址段（RFC 6598），两套系统恰好都在使用这个地址空间，路由上无法简单地"二选一"。

### 路由表的假象

接下来的发现更有意思。用 `netstat -rn` 看路由表，Tailscale 确实注册了一些 `/32` 主机路由：

```
100.64/10          30.42.89.162       UGSc               utun20
100.100.100.100/32 link#49            UCS                utun24
100.109.0.41       100.109.0.41       UH                 utun24
100.109.15.92      link#49            UHWIig             utun24
```

表面上看，`100.109.15.92` 有一条指向 `utun24`（Tailscale）的主机路由，按照最长前缀匹配原则，`/32` 应该优先于 `/10`。但实际用 `route get` 检查真正的路由决策：

```bash
$ route get 100.109.15.92
   route to: airship.tailnet-xxxx.ts.net
destination: 100.64.0.0
       mask: 255.192.0.0
    gateway: 30.42.89.162
  interface: utun20
```

**流量实际走了 `100.64/10` 的广播路由，而不是 `/32` 的主机路由。** 这就是 Tailscale 节点不可达的直接原因。

### 根因：macOS Network Extension 的路由机制

注意路由表中 `100.109.15.92` 那条条目的标志位：

```
100.109.15.92      link#49            UHWIig             utun24
```

其中 `W` 标志表示 `wasCloned`——这条路由是系统从其他路由"克隆"出来的**缓存条目**，并非独立的静态路由。

Tailscale 在 macOS 上通过 Network Extension 框架运行，它在内核层面拦截和处理数据包，路由表中看到的这些 `/32` 条目只是 Network Extension 工作的副产品。当我们用 `route -n add` 手动添加了一条同网段的显式静态路由（`100.64/10 → utun20`）后，系统在路由决策时优先选择**显式静态路由**而非 Network Extension 产生的缓存条目，`/32` 的最长前缀匹配优势被绕过了。

> 这是 macOS 路由实现的一个细节：`route get` 展示的是内核的实际路由决策，而 `netstat -rn` 展示的路由表包含各类条目（静态路由、克隆缓存、接口路由等），并非所有条目都参与转发决策。排查路由问题时，**始终以 `route get` 为准**。

### 验证修复思路

既然 Tailscale 的隐式路由不够权威，那就手动添加显式的 `/32` 主机路由：

```bash
$ sudo route -n add -host 100.109.15.92 -interface utun24
add host 100.109.15.92: gateway utun24
```

再次检查路由决策：

```bash
$ route get 100.109.15.92
   route to: airship.tailnet-xxxx.ts.net
destination: airship.tailnet-xxxx.ts.net
  interface: utun24
      flags: <UP,HOST,DONE,STATIC>

$ route get 100.67.201.67
destination: 100.64.0.0
       mask: 255.192.0.0
    gateway: 30.42.89.162
  interface: utun20
```

这次 `/32` 静态路由正确地覆盖了 `/10` 的广播路由。验证两边的连通性：

```bash
$ tailscale ping airship
pong from airship (100.109.15.92) via 101.132.17.38:41641 in 11ms   # Tailscale 正常

$ curl -sSo /dev/null -w "%{http_code}" --connect-timeout 5 https://[REDACTED].aliyun-inc.com/
302   # 阿里内网正常
```

两边同时可达。

### 最终方案

将修复逻辑写成脚本，自动检测接口并为所有 Tailscale 节点添加路由：

```bash
#!/bin/bash
# Fix routing conflict between AliLang VPN and Tailscale.
# Both use the 100.64.0.0/10 (CGNAT) range:
#   - AliLang: internal services resolve to 100.64-100.67.x.x
#   - Tailscale: peers use 100.64-100.109.x.x
#
# Strategy: broad 100.64/10 → AliLang VPN, specific /32 → Tailscale peers.

set -euo pipefail

# Detect AliLang VPN interface (30.42.x.x address)
ALILANG_IF=$(ifconfig -l | tr ' ' '\n' | while read iface; do
    ifconfig "$iface" 2>/dev/null | grep -q 'inet 30\.42\.' && echo "$iface" && break
done)

if [ -z "$ALILANG_IF" ]; then
    echo "Error: AliLang VPN interface not found" >&2
    exit 1
fi

ALILANG_GW=$(ifconfig "$ALILANG_IF" | grep 'inet 30\.42\.' | awk '{print $2}')

# Detect Tailscale interface (100.x.x.x address on utun)
TS_IF=$(ifconfig -l | tr ' ' '\n' | while read iface; do
    ifconfig "$iface" 2>/dev/null | grep -q 'inet 100\.' && echo "$iface" && break
done)

if [ -z "$TS_IF" ]; then
    echo "Error: Tailscale interface not found" >&2
    exit 1
fi

echo "AliLang VPN: $ALILANG_IF (gateway $ALILANG_GW)"
echo "Tailscale:   $TS_IF"

# Step 1: Route broad 100.64.0.0/10 to AliLang VPN
sudo route -n delete -net 100.64.0.0/10 2>/dev/null || true
sudo route -n add -net 100.64.0.0/10 "$ALILANG_GW"

# Step 2: Add /32 host routes for all Tailscale peers
tailscale status --json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for p in data.get('Peer', {}).values():
    for addr in p.get('TailscaleIPs', []):
        if ':' not in addr:
            print(addr)
" | while read -r ip; do
    sudo route -n delete -host "$ip" 2>/dev/null || true
    sudo route -n add -host "$ip" -interface "$TS_IF" 2>/dev/null
    echo "  $ip → $TS_IF"
done

# Step 3: Ensure Tailscale MagicDNS stays reachable
sudo route -n delete -host 100.100.100.100 2>/dev/null || true
sudo route -n add -host 100.100.100.100 -interface "$TS_IF"
```

脚本的策略很简单：**广播路由兜底，精确路由优先**。`100.64.0.0/10` 整体指向 AliLang VPN，保证阿里内网可达；每个 Tailscale 节点的 `/32` 路由指向 Tailscale 接口，保证组网设备可达。接口名和网关地址都是动态检测的，不怕 `utun` 编号在重启后变化。

## 复盘

回顾整个排查过程，有几个值得记住的点：

**"修好 A 就坏 B"意味着问题不在 A 也不在 B，而在它们的交集。** 如果只盯着"阿里内网不通"这一个症状，很容易把 Tailscale 当作干扰项一关了事。反过来也一样。真正的问题在于两个系统共用了 `100.64.0.0/10` 这个地址空间，必须在路由层面做精确切分。

**`netstat -rn` 会骗人，`route get` 不会。** 路由表里看到了 Tailscale 节点的 `/32` 条目，按最长前缀匹配原则理应生效，但实际上这些条目带有 `W`（wasCloned）标志，是 macOS Network Extension 产生的缓存，在与显式静态路由竞争时会输。排查路由问题时，永远用 `route get <target_ip>` 确认内核的真实路由决策。

**CGNAT 地址段冲突比想象中常见。** `100.64.0.0/10` 是 RFC 6598 定义的 Carrier-Grade NAT 地址段，本意是给运营商用的过渡地址。但 Tailscale 选择了这个段作为组网地址（因为它不太可能与常见的 `10/8`、`172.16/12`、`192.168/16` 冲突），企业内网也可能使用这个段。当两者共存时，"按网段切路由"这种常规方案会失效，需要退化到"按主机切路由"的粒度。

**动态检测优于硬编码。** macOS 的 `utun` 接口编号在每次 VPN 重连或系统重启后都可能变化。脚本中通过 IP 地址特征识别接口（`30.42.x.x` → AliLang，`100.x.x.x` → Tailscale），通过 `tailscale status --json` 获取节点列表，避免了硬编码带来的维护负担。


## 参考资料

1. [RFC 6598 - IANA-Reserved IPv4 Prefix for Shared Address Space](https://datatracker.ietf.org/doc/html/rfc6598)
2. [Tailscale · How Tailscale assigns IP addresses](https://tailscale.com/kb/1015/100.x-addresses)
3. 本文排查过程中使用了 Claude Code 协助分析路由表和编写修复脚本，在此致谢。
