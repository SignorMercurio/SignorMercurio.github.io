---
title: 风谲云诡：云原生技术原理
date: 2021-09-10 09:27:59
tags:
  - Docker
  - Kubernetes
  - ARM
categories:
  - 云
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/CloudNative/0.png
---

精密而复杂。

<!--more-->

## 容器

### Namespace

Linux 采用 Namespace 技术进行资源隔离，可以为不同进程分配不同的 Namespace，有点类似沙箱的概念。在 Linux 进程的数据结构中，`nsproxy` 结构体负责管理 Namespace：

```c
struct nsproxy {
  atomic_t             count;
  struct uts_namespace *uts_ns;
  struct ipc_namespace *ipc_ns;
  struct mnt_namespace *mnt_ns;
  struct pid_namespace *pid_ns_for_children;
  struct net           *net_ns;
}
```

默认情况下父子进程共享 Namespace，但也可以通过调用 `clone`、`setns`、`unshare` 等方法手动指定和修改 Namespace。

以上面结构体的 `pid_namespace` 为例，两个不同的 PID Namespace 下的进程之间是互不影响的。类似的，网络、文件系统、用户、挂载点等的 Namespace 之间也同理。

可以看到，Docker 实际上就是对 Namespace 的一次封装，因此在宿主机上调试 Docker 内部程序时，也可以借助 Namespace 的命令行工具。先获取对应容器的 PID：

```shell
$ docker inspect [docker id] | grep pid
```

再用 `nsenter` 进入对应的 Namespace，例如进入网络 Namespace 使用 `-n`：

```shell
$ nsenter -t [pid] -n [cmd]
```

### Cgroups

Cgroups 对进程使用的计算资源进行管控，对不同类型的资源采用不同子系统，并在子系统中采用层级树结构（`/sys/fs/cgroup`）。

#### 🌰 限制进程使用的 CPU 资源

首先进入 cpu 子系统，将进程加入 cgroup：

```shell
$ cd /sys/fs/cgroup/cpu
$ echo [pid] > cgroup.procs
```

随后关注 `cpu.cfs_quota_us` 和 `cpu.cfs_period_us`，两者的比值即进程能占用 CPU 资源的最高比例，默认值为 `-1`（无限制） 和 `100000`。

例如，设置最多占用 25% CPU 资源：

```shell
$ echo 25000 > cpu.cfs_quota_us
```

### UnionFS

顾名思义，UnionFS 可以对文件系统 “取并集”，也就是将不同目录挂载到同一个虚拟文件系统下。

经典的 Linux 系统中，使用 bootfs 中的 BootLoader 引导加载 Kernel 到内存中，然后 `umount` 掉 bootfs。Kernel 加载完成后，就会使用我们熟悉的 rootfs 文件系统。启动时先将 rootfs 设为 readonly 进行检查，随后再设为 readwrite 供使用。

而在 Docker 启动时，检查完 readonly 的 rootfs 后会再 union mount 一个 readwrite 的文件系统，称为一个 FS 层。后续会继续添加 readwrite 的 FS 层，每次添加时将当前最顶层的 FS 层设为 readonly。这实际上就是 `docker build` 根据 Dockerfile 中每一行的指令堆叠 FS 层的过程。

那么如果要修改下层 readonly FS 层的文件怎么办呢？只需要 Copy-on-Write，将文件复制到可写的顶层并修改即可。这样能成功是因为 Docker 采用的 OverlayFS 在合并上下层同名文件时，优先选择上层文件。

最后，FS 层可以在不同镜像之间复用，节省镜像构建时间和硬盘占用。

## Serverless

### FaaS

Serverless 并不是指不需要服务器，而是指对服务器运维的极端抽象。我们知道，在程序设计领域发生的抽象，都是为了降低开发难度和成本、让开发者更专注于真正有价值的工作。因此，Serverless 主要是针对后端运维进行的一种优化。

Serverless 首先提出的概念是函数即服务 FaaS，大体可以分成函数代码、函数服务、触发器三个部分。

- 触发器接收用户请求并通知函数服务。实际上是对负载均衡、反向代理等中间件工作的抽象
- 函数服务收到消息后，检查是否有可用的函数实例，没有则通过函数代码来初始化一个新的函数实例；最后将用户请求作为函数参数，执行函数，返回的结果将原路返回。实际上是对代码运行环境的抽象
- 函数代码一般在 git 之类的版本控制仓库。实际上是对代码上传和部署的抽象

#### 弹性伸缩

值得一提的是，FaaS 能根据目前负载对占用资源进行弹性伸缩，无负载时甚至可以不占用资源。这能够很大程度上提升资源利用率。

#### 冷启动

冷启动和热启动相反，从一个未初始化的服务开始，直到函数实例执行完毕结束。由于可能涉及比较繁琐的初始化工作，传统服务也许能够在热启动上达到很快的速度，但在冷启动上不行。

FaaS 则通过容器、运行环境、代码三者分层并分别缓存，获得了较快的冷启动速度，一般大约在几百毫秒内。显然，这是牺牲了用户对底层环境的可控性换来的。

#### 语言无关性

FaaS 可以替换传统前后端分离开发中的后端服务、可以用来请求公开的 Web API、更重要的是可以和其他云服务商提供的服务进行联动。由于前端只在意最后返回的数据，我们的函数服务完全可以混合采用多种不同的语言来编写，以适应不同的需求。

#### 数据库？

FaaS 中的函数实例都活不了太久，有的执行完就被销毁了，而有的可能能在内存中多待一会儿，但云服务商经过一小段时间后仍会销毁它们，这是因为 FaaS 需要弹性伸缩，它的核心是无状态的函数（就像 HTTP 协议是无状态的一样）。

这就给数据持久化带来了问题，比如数据库就不能放在 FaaS 的主进程中。但把数据库单独拿出来，再通过一个进程去连接并访问它，这样又会显著增加冷启动的时间。

解决办法就是不再连接数据库，而是通过 RESTful API 访问数据库。这里的 RESTful API 实际上就是一种后端即服务 BaaS 了，它提供了访问后端数据库的接口，使得 FaaS 不再需要考虑数据持久化的问题。

### BaaS

后端 BaaS 化为了降低运维成本，往往会将复杂业务逻辑拆分成单一职责的微服务，形成微服务架构。这就要求各微服务之间相对独立，意味着每个服务的数据库也需要解耦合。对这类分布式数据库而言，最重要的就是解决数据一致性的问题，例如通过消息队列或是 Raft 协议等。

值得一提的是，FaaS 和 BaaS 的底层实际上使用容器技术实现，所以我们可以在本地用 Kubernetes 搭建自己的 Serverless 平台（见后文 Kubernetes 部分）。

### 缺点

- 技术尚不成熟，许多云服务商提供的 Serverless 服务存在不少 bug
- Serverless 平台对开发者来说是个黑盒子，想在上面调试代码、排查问题，需要付出极大成本
- 同理，Serverless 平台上的运行时环境只支持部分定制
- 每次部署代码都需要压缩代码后上传，较繁琐
- 云服务商提供的生态（如代码调试工具）都是封闭的，形成 Vendor-lock；这一点可能可以通过 Serverless、Midway FaaS 等框架解决

## Kubernetes

### 架构

K8s 用来管理容器集群，它的好处在 [官方文档](https://kubernetes.io/zh/docs/concepts/overview/what-is-kubernetes/#%E4%B8%BA%E4%BB%80%E4%B9%88%E9%9C%80%E8%A6%81-kubernetes-%E5%AE%83%E8%83%BD%E5%81%9A%E4%BB%80%E4%B9%88) 里已经写得很清楚了，而它的原理大致可以概括为一张架构图：

![图 1｜K8s 架构](https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/CloudNative/1.png)

通过 CLI 工具 kubectl，我们可以访问到运行在 K8s Master Node 上的 API Server，也是整个集群的核心。Node 实际上是对计算资源的一种抽象，每个 Node 上运行一个或多个 Pod，即应用实例。一般情况下，一个 Pod 上推荐运行一个容器。

在 Master Node 上还有键值数据库 etcd、监视 Pod 的调度器 Scheduler、不同类型的控制器 Controller Manager 以及连接云服务厂商 API 的 Cloud Controller Manager。

而在普通 Node 上则运行了一个 kubelet，负责通知 API Server 容器运行状态。此外，为了让外界能够访问到容器运行的服务，需要用 K8s Service 通过 kube-proxy 暴露该服务。

最后，不同的 K8s 集群之间通过 Namespace 隔离，注意这和上文写容器技术时提到的 Linux Namespace 并非同一概念，尽管思想是相似的。

### 安装

K8s 的安装令人惊讶地简单。就像我们在架构图中看到的那样，安装 K8s 主要分为安装 kubectl 和 安装 K8s 集群两个步骤。

#### 安装 K8s 集群

第一种方式是通过 Docker Desktop 安装。实际上 Docker Desktop 自带了 K8s（不是最新版本，但也比较新），在设置里勾选即可。

第二种方式是通过 kubeadm、minikube、kind 等工具安装，无论哪种方式都比较简单，这里以 minikube 为例。

> minikube 内置了 kubectl，所以之后可以选择不另外安装 kubectl。

按照 [官方文档](https://minikube.sigs.k8s.io/docs/start/)，直接 `install` 二进制文件即可。

```shell
$ curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-darwin-amd64
$ sudo install minikube-darwin-amd64 /usr/local/bin/minikube
```

#### 安装 kubectl

`brew install kubectl`，没了。

然而需要注意的是，kubectl 版本和 K8s 集群版本之间相差不能超过 _0.0.2_，否则容易出现不兼容的情况。例如，如果用 Docker Desktop 安装的 1.21.4 版本的集群，则需要手动安装：

```shell
$ curl -LO "https://dl.k8s.io/release/v1.21.4/bin/darwin/arm64/kubectl"
$ chmod +x ./kubectl
$ sudo mv ./kubectl /usr/local/bin/kubectl
$ sudo chown root: /usr/local/bin/kubectl
```

### 实践

首先设置好别名，方便后续操作（这里直接使用了 minikube 内置的 kubectl）：

```bash
alias k="minikube kubectl --"
alias dps="docker ps -a"
alias dr="docker rm -f"
alias dil="docker image ls"
alias dir="docker image rm"
alias ds="docker start"
alias dx="docker exec -it"
alias mk="minikube"
```

启动 minikube：

```shell
$ mk start
```

部署应用并检查：

```shell
$ k create deploy echo-server --image=k8s.gcr.io/echoserver-arm:1.8
$ k get deploy
# result:
NAME          READY   UP-TO-DATE   AVAILABLE   AGE
echo-server   1/1     1            1           1m
```

因为是 M1 芯片，所以用的 ARM 镜像。

检查 Pod 情况：

```shell
$ k get po
# result:
NAME                          READY   STATUS    RESTARTS   AGE
echo-server-9f4db688c-r288r   1/1     Running   0          89
```

暴露服务并检查：

```shell
$ k expose deploy echo-server --type=LoadBalancer --port=8080
$ k get svc
# result:
NAME          TYPE           CLUSTER-IP       EXTERNAL-IP   PORT(S)          AGE
echo-server   LoadBalancer   10.111.217.237   <pending>     8080:31389/TCP   1m
kubernetes    ClusterIP      10.96.0.1        <none>        443/TCP          100m
```

这里暴露了一个 LoadBalancer 类型的服务，也可以换成 NodePort 类型服务。8080 是我们的 echoserver 容器内的服务端口。

此外，可以发现还有一个 `kubernetes` 服务，这就是 K8s 集群的 API Server。

为了访问暴露的服务，可以手动端口转发，也可以通过 minikube 自动访问：

```shell
$ mk service echo-server
```

注意到上面 `echo-server` 的 `EXTERNAL-IP` 还在等待分配，我们还可以用 `mk tunnel` 建立隧道从而分配外部访问的 IP。

上述信息也可以通过 Dashboard 图形化界面查看：

```shell
$ mk dashboard
```

有趣的是，K8s 服务也是由 K8s 自己管理的，它运行在 `kube-system` 的 Namespace 中。

```shell
$ k get po,svc -n kube-system
# result:
NAME                                   READY   STATUS    RESTARTS       AGE
pod/coredns-78fcd69978-xlh28           1/1     Running   0              141m
pod/etcd-minikube                      1/1     Running   0              142m
pod/kube-apiserver-minikube            1/1     Running   0              142m
pod/kube-controller-manager-minikube   1/1     Running   0              142m
pod/kube-proxy-gblfw                   1/1     Running   0              141m
pod/kube-scheduler-minikube            1/1     Running   0              142m
pod/storage-provisioner                1/1     Running   1 (141m ago)   142m

NAME               TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)                  AGE
service/kube-dns   ClusterIP   10.96.0.10   <none>        53/UDP,53/TCP,9153/TCP   142m
```

对于其他平台，`kubectl` 命令不变，替换上述 `mk` 相关命令即可。

## Service Mesh

微服务架构中，微服务之间必须要通信，导致微服务通信相关代码和业务代码的强耦合。Service Mesh 正是为了抽离出微服务通信的逻辑，让开发者专注于业务代码编写。它在数据面板中通过 Sidecar 劫持微服务 Pod 的流量，从而接管了整个网络通信的功能。

### Istio 安装

Kubernetes 采用 Istio 作为 Server Mesh，首先下载并安装，安装前记得给 Docker Desktop 或 minikube 分配 8 - 16 G 内存：

```shell
$ curl -L https://istio.io/downloadIstio | sh -
$ mv istio-1.11.2/bin/istioctl /usr/local/bin
$ istioctl install --set profile=demo -y
```

令人痛心的是，Istio 官方 [并不支持](https://github.com/istio/istio/issues/30829)、也 [不打算支持](https://github.com/istio/istio/issues/29596) ARM 架构，因此在 M1 下安装时不能直接使用最后一行命令自动化安装，而需要借助 [这个社区版镜像](https://github.com/querycap/istio)，自己编写 Operator 进行安装：

```yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  namespace: istio-system
  name: arm-istiocontrolplane
spec:
  hub: docker.io/querycapistio
  profile: demo
  components:
    pilot:
      k8s: # each components have to set this
        affinity: &affinity
          nodeAffinity:
            preferredDuringSchedulingIgnoredDuringExecution:
              - preference:
                  matchExpressions:
                    - key: beta.kubernetes.io/arch
                      operator: In
                      values:
                        - arm64
                        - amd64
                weight: 2
            requiredDuringSchedulingIgnoredDuringExecution:
              nodeSelectorTerms:
                - matchExpressions:
                    - key: beta.kubernetes.io/arch
                      operator: In
                      values:
                        - arm64
                        - amd64
    egressGateways:
      - name: istio-egressgateway
        k8s:
          affinity: *affinity
        enabled: true
    ingressGateways:
      - name: istio-ingressgateway
        k8s:
          affinity: *affinity
        enabled: true
```

将这个 Operator 保存为 `install-istio.yml`，随后 `istioctl install -f ./install-istio.yml` 完成安装。

### 应用部署

安装完成后，记得开启 Sidecar 注入来劫持流量：

```shell
$ k label ns default istio-injection=enabled
```

随后即可部署应用并查看状态：

```shell
$ k apply -f samples/bookinfo/platform/kube/bookinfo.yaml
$ k get po
# result:
NAME                              READY   STATUS    RESTARTS   AGE
details-v1-79f774bdb9-ns6gl       2/2     Running   0          76s
productpage-v1-6b746f74dc-qp7mg   2/2     Running   0          76s
ratings-v1-b6994bb9-mflsk         2/2     Running   0          76s
reviews-v1-545db77b95-24tsl       2/2     Running   0          76s
reviews-v2-7bf8c9648f-b8bq4       2/2     Running   0          76s
reviews-v3-84779c7bbc-hxkxg       2/2     Running   0          76s

$ k get svc
# result:
NAME          TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)    AGE
details       ClusterIP   10.102.117.210   <none>        9080/TCP   105s
kubernetes    ClusterIP   10.96.0.1        <none>        443/TCP    27m
productpage   ClusterIP   10.101.203.214   <none>        9080/TCP   105s
ratings       ClusterIP   10.105.60.88     <none>        9080/TCP   105s
reviews       ClusterIP   10.100.137.99    <none>        9080/TCP   105s
```

最后，检查实际应用是否正常运行：

```shell
$ k exec "$(k get po -l app=ratings -o jsonpath='{.items[0].metadata.name}')" -c ratings -- curl -sS productpage:9080/productpage | grep -o "<title>.*</title>"
# result:
<title>Simple Bookstore App</title>
```

上述命令的意思是：在 ratings 对应的 pod 中的 ratings 容器里运行 `curl -sS productpage:9080/productpage` 发起请求，并在返回的 html 中查找标题。需要这么复杂是因为此时我们的服务还没有外部 IP，只能在集群内部访问。

### 通过 Ingress 网关让应用能够从外部访问

首先部署好设置了网关的应用并检查：

```shell
$ k apply -f samples/bookinfo/networking/bookinfo-gateway.yaml
$ istioctl analyze
```

获取主机、http2 端口和 https 端口：

```shell
$ export INGRESS_HOST=$(k -n istio-system get svc istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
$ export INGRESS_PORT=$(k -n istio-system get svc istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')
```

如果设置完后 `$INGRESS_HOST` 为空，说明 LoadBalancer 此时的地址为主机名而不是 IP，只需要修改一下设置即可：

```shell
$ export INGRESS_HOST=$(k -n istio-system get svc istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
```

随后访问 `http://$INGRESS_HOST:$INGRESS_PORT` 即可。

### 通过 Kiali 查看图形化界面

安装 Kiali、Prometheus、Grafana、Jarger 等插件，检查部署状态：

```shell
$ k apply -f samples/addons/
$ k rollout status deploy kiali -n istio-system
```

随后就可以查看图形化界面了：

```shell
$ istioctl dashboard kiali
```

编写脚本产生流量：

```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null "http://localhost/productpage";
done
```

最后就可以看到整个 Service Mesh 的架构、以及网络请求数据流了，非常清晰。
