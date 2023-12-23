---
title: 乘风破浪：Kubernetes 笔记
date: 2021-10-10
tags:
  - Kubernetes
categories:
  - 云
---

在了解了 Kubernetes 为什么叫 K8s 之后，才明白 internationalization 为什么叫 i18n。

<!--more-->

在 [云原生技术原理](https://blog.sigmerc.top/posts/cloud-native) 一文中我记录了一些 K8s 基础知识和操作，这篇笔记里就不多赘述了。文章中涉及的资源名称、镜像名称、镜像标签等均为虚构。

## 操作现有服务

### 扩缩容

```bash
k scale deploy/nginx --replicas=4 # scale up
k scale deploy/nginx --replicas=2 # scale down
```

### 滚动更新

```bash
k set image deploy/nginx nginx=docker.io/nginx:v2
```

滚动更新会重新创建 ReplicaSet 进而创建新的 Pod。关于滚动更新，有两个重要参数 `maxSurge` 和 `maxUnavailable` ，参见 [后文](# 滚动更新检查)。

### 版本回退

在创建 / 修改资源时，记得添加 `--record`，这样就可以留下 revision 记录并查询：

```bash
k rollout history deploy/nginx
```

随后就能回退到某个特定版本：

```bash
k rollout undo deploy/nginx --to-revision=1
```

如果不加参数，则回退到上一个版本。

## 基础概念

### 创建 Deployment 的过程

`kubectl` 这个 CLI 本质上就是一个 REST 客户端，主要任务是向 Kubernetes API Server 发送请求。

> 实际上，不少 CLI 都是这样的，例如 `docker` 和 `gcloud` 等。

API Server 随后通知 Deployment Controller 创建 ReplicaSet，再通过 ReplicaSet 创建多个 Pod，这一点也可以从三种资源的命名方式中发现。

例如，如果 Deployment 叫做 `nginx`，那么 ReplicaSet 名称则形如 `nginx-7848d4b86f`，而 Pod 名称则形如 `nginx-7848d4b86f-2ht2l`。

另一种验证这一点的方法是查看 `describe` 命令返回的 `Controlled By` 字段。

> 同一个 Pod 中的容器联系非常紧密，并且需要共享资源，比如网络和 volume。

Pod 创建后，Scheduler 将 Pod 的副本分配到不同的 Node 上运行。当我们用 `kubectl` 查询部署的服务信息时，也是通过请求 API Server 从 etcd 中读取服务的信息。

### 访问 Service 的方式

如果未指定 `type`，则 Service 只能从 Cluster 内部通过 ClusterIP 访问。访问 Service 的流量通过 iptables 规则轮询转发到 Pod。

除了 IP，也可以使用 Kubernetes 提供的 DNS 服务从 Cluster 内部访问 Service。例如，启动一个临时的 Pod：

```bash
k run busybox --rm -it --image=busybox /bin/sh
```

在容器内部运行 `wget nginx-svc.default:8080`，可以获取到网页内容；如果容器与 Service 同处于一个 Namespace（如 `default`），那么可以省略掉 `.default` 这一 Namespace 声明。

而如果要从 Cluster 外部访问 Service，就需要设置 `type` 为 `NodePort` 或 `LoadBalancer`。前者通过 iptables 将端口映射到所在 Node 的端口上，后者则使用云服务商的 Load Balancer 对流量进行负载均衡。

### DaemonSet

DaemonSet 部署的 Pod 在每个 Node 上最多只能运行一个副本，适合监控和日志收集等类似守护进程的服务。需要注意的是，DaemonSet 部署的 Pod 会绕过调度器并忽略节点的 Unschedulable 属性。

### Job

Job 中配置的任务在容器中只会运行一次，完成之后容器就会停止。

## 常用资源 YAML

### Deployment 和 Service

更常用也更方便的创建 / 修改服务的方法是使用 yaml 文件，例如：

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: # metadata for deployment
  name: nginx # required metadata
spec: # specification for deployment
  selector:
    matchLabels:
      app: nginx
  replicas: 3
  template: # pod template
    metadata: # metadata for pod
      labels:
        app: nginx # at least one label required
    spec: # specification for pod
      containers:
        - name: nginx
          image: nginx
          ports:
            - containerPort: 80
```

然后运行 `k apply -f nginx-deploy.yml` 就可以创建 Deployment，或是修改现有的 Deployment。删除的话，把 `apply` 换成 `delete` 即可。

对于 Service 来说同理，可以编写 `nginx-service.yml`：

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-svc
spec:
  type: NodePort # map to a port on the Node
  selector:
    app: nginx # select pods according to labels
  ports:
    - protocol: TCP
      nodePort: 30000 # Node:30000
      port: 8080 # ClusterIP:8080
      targetPort: 80 # pod:80
```

可以发现，Service 通过 `labels` 来筛选 Pod。同样地，Pod 也可以通过 `labels` 来筛选 Node：

```bash
k label node node1 disktype=ssd
k get node --show-labels
```

随后在 `nginx-deploy.yml` 下的 `.spec.template.spec` 下添加：

```yaml
nodeSelector:
  diskType: ssd
```

就可以确保该 Deployment 的所有 Pod 都被分配到指定 Node 上。当然也可以删除 Node 上的 `labels`：

```bash
k label node node1 disktype-
```

### Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: pi
spec:
    completions: 4
    parallelism: 2
  template: # pod template
    spec:
      containers:
      - name: pi
        image: perl
        command: ["perl",  "-Mbignum=bpi", "-wle", "print bpi(2000)"]
      restartPolicy: Never
  backoffLimit: 4
```

Job 语法大同小异，`parallelism` 控制并行 Pod 数量，`completions` 控制任务总共需要完成多少次， `restartPolicy` 对 Job 而言只能是 `Never` 或 `OnFailure`，`backoffLimit` 限制了最大的重试次数。

> `restartPolicy` 对 Deployment 而言还可以是 `Always`，此时即使容器进程返回了 0 也依然会重启容器。

如果任务运行失败，由于 `restartPolicy` 为 `Never`，容器不会被重启，但会不断创建新的 Pod 重新运行；如果 `restartPolicy` 为 `OnFailure` ，由于容器会被重启，因此不会创建新的 Pod。

要查看已完成 Job 的执行结果，假设 Pod 名称为 `pi-trvkr`，可以使用命令 `k logs pi-trvkr`。

值得注意的是，和 Istio 一起使用时会受到 Sidecar 注入影响，Kubernetes 会认为 Job 没有执行完成，但实际上 Job 的执行并没有受到影响。为了解决这一问题，可以在 Pod 模版中关闭 Sidecar 注入，即在 `.spec.template` 下添加：

```yaml
metadata:
  annotations:
    sidecar.istio.io/inject: "false"
```

### CronJob

定时任务实际上是在 Job 外面套了一层 `spec`，主要是为了增加 `schedule` 字段，其格式和 crontab 的格式相同：

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "*/1 * * * *"
  jobTemplate:
    spec:
      template: # pod template
        spec:
          containers:
            - name: hello
              image: busybox
              imagePullPolicy: IfNotPresent
              command:
                - /bin/sh
                - -c
                - date; echo Hello from the Kubernetes cluster
          restartPolicy: OnFailure
```

同理，CronJob 也存在和 Sidecar 冲突的问题，解决方法和上述一致，插入位置是 `.spec.jobTemplate.spec.template` 下。

从资源名称同样可以看出这里的层级关系：CronJob（`hello`）-> Job（`hello-27231469`）-> Pod（`hello-27231469-bjbjw`）。

## Health Check

默认情况下，容器运行的进程返回非 0 时，Kubernetes 会认为出现了错误，此时 Health Check 不通过。然而出现错误时容器内进程未必会返回，因此我们可以自定义 Health Check 的规则。

例如，创建一个带 `livenessProbe` 的 Pod：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: liveness
  labels:
    test: liveness
spec:
  restartPolicy: OnFailure
  containers:
    - name: liveness
      image: busybox
      args:
        - /bin/sh
        - -c
        - touch /tmp/healthy; sleep 30; rm -rf /tmp/healthy; sleep 600
      livenessProbe:
        exec:
          command:
            - cat
            - /tmp/healthy
        initialDelaySeconds: 10 # start probing after 10s
        periodSeconds: 5 # probe every 5s
```

这里就是通过 `exec` 了 `cat /tmp/healthy` 返回值是否为 0 来判断容器是否存活，如果三次探测均失败，则会认为发生了 `Failure`，触发 `OnFailure` 重启容器。可以查看日志确认这一点：

```
Warning  Unhealthy  2s (x3 over 12s)  kubelet            Liveness probe failed: cat: can't open'/tmp/healthy': No such file or directory
Normal   Killing    2s                kubelet            Container liveness failed liveness probe, will be restarted
```

Liveness 探测主要用来通知 Kubernetes 尝试重启容器，而另一种 Health Check 机制 Readiness 探测则用来通知 Kubernetes 容器已经可以正常提供服务了。和 Liveness 探测语法上的唯一区别就是把 `livenessProbe` 改成 `readinessProbe`。Readiness 探测，从现象上看，影响的是 Pod 的 `READY` 状态。

而 Startup 探测适用于启动时间较长的应用，在 `READY` 前以一个更低的频率进行 Readiness Check，避免高频检测影响应用启动。

这三种 Pod 都支持三种检测方法：执行命令、探测 TCP 端口以及发送 HTTP GET 请求。

### 扩容应用检查

一个典型的使用场景就是在扩容应用时，检查新增加的 Pod 是否能正常工作。例如对于一个 Web 服务，可以这样写探测器：

```yaml
readinessProbe:
  httpGet:
    scheme: HTTP
    path: /healthy
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 5
```

此时 Kubernetes 会判断返回的状态码是否在 200 - 400 之间。

### 滚动更新检查

另一个更实用的场景是在滚动更新时，确保新上线的 Pod 能正常工作，避免更新后全线宕机不得不回滚的状况。

我们知道，滚动更新过程中会逐步增加新的 Pod，删除旧的 Pod。`maxSurge` 和 `maxUnavailable` 分别是对这两个过程的量化。

- `maxSurge` 控制 `副本总数 - 预期副本数` 的最大值
  - 可以为具体数字
  - 默认为 `预期副本数` 的 25% 向上取整
  - 确保不会增加太多新 Pod
- `maxUnavailable` 控制 `不可用副本数` 的最大值
  - 可以为具体数字
  - 默认为 `预期副本数` 的 25% 向下取整
  - 确保不会删除太多旧 Pod

这里的 `Unavailable`，便是通过 `readinessProbe` 来探测的。我们可以在 Deployment 的 `.spec` 下添加内容来自定义这两个值：

```yaml
strategy:
  rollingUpdate:
    maxSurge: 30%
    maxUnavailable: 30%
```

## Volume

和 Docker 中的 Volume 类似，用于提供持久化存储。同一个 Pod 中所有容器都可以访问 Mount 到这个 Pod 上的 Volume。

### emptyDir Volume

这种 Volume 在 Pod 被删除时也会被删除，不过不受容器被删除的影响。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: producer-consumer
spec:
  containers:
    - name: producer
      image: busybox
      volumeMounts:
        - mountPath: /producer_dir
          name: shared-volume
      args:
        - /bin/sh
        - -c
        - echo "hello" > /producer_dir/hello; sleep 30000

    - name: consumer
      image: busybox
      volumeMounts:
        - mountPath: /consumer_dir
          name: shared-volume
      args:
        - /bin/sh
        - -c
        - cat /consumer_dir/hello; sleep 30000

  volumes:
    - name: shared-volume
      emptyDir: {}
```

上述 yaml 会创建一个含 `producer` 和 `consumer` 两个容器的 Pod，前者向 `shared-volume` 也就是容器内的 `/producer_dir` 写数据，后者从 `shared-volume` 也就是容器内的 `/consumer_dir` 读数据，最终可以通过 `k logs producer-consumer consumer` 查看读取到的数据。

这种 Volume 由于在 Pod 被删除后就会消失，比较适合在容器间临时共享存储。但在创建时建议设置 sizeLimit 防止占用空间过大。可以认为，emptyDir 是一种不能指定 `path` 和 `type` 的 hostPath。

### hostPath Volume

这个也比较好理解，就是把容器所处的宿主机 `host` 上的某个 `path` 作为 Volume 进行挂载，好处是目录并不会受到 Pod 删除的影响，并且能够更方便地访问宿主机上的文件——这也是这种方式的坏处，即增加了 Pod 和 Node 的耦合度。语法一般如下：

```yaml
volumes:
  - hostPath:
      path: /etc/ssl/certs
      type: DirectoryOrCreate
    name: ca-certs
```

可以想到，如果 Pod 被调度到了其他 Node 上，那么 hostPath 很可能就失效了。

### 外部存储

如果需要持久化的存储，可以使用各种外部存储例如 AWS、GCP、Azure 提供的存储服务，或是使用 Ceph 等分布式存储，语法各不相同，可以参考对应的文档。

### PV 和 PVC

PersistentVolume 也是持久化的存储，通过 PersistentVolumeClaim 来申请，Kubernetes 会根据条件分配适合的 PV。这实际上就是对 Volume 作了一层封装，使得用户不需要关心所获得的存储空间的底层信息。

创建 PV：

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv1
spec:
  capacity:
    storage: 1Gi
  accessModes:
    - ReadWriteOnce # mount to a single node
  persistentVolumeReclaimPolicy: Recycle
  storageClassName: nfs # like label selector
  nfs:
    path: /nfs/pv1
    server: 1.1.1.1 # nfs server
```

其中 `accessModes` 指定了访问模式为可读写且只能挂载到单个 Node 上，对应的还有 `ReadOnlyMany`、`ReadWriteMany` 等模式。`persistentVolumeReclaimPolicy` 指定了回收机制，`Retain` 需要手工回收，`Recycle` 会清除 PV 中所有数据，而 `Delete` 则会删除外部存储（一般是云平台）中的存储资源本身。

然后创建 PVC，过程类似：

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pvc1
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  storageClassName: nfs
```

成功创建后，`pv1` 和 `pvc1` 的状态会变为 `BOUND`。之后如果需要在 Pod 中使用存储，只需要修改 `.spec.volumes` 如下：

```yaml
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: pvc1
```

使用完毕后，用 `k delete pvc pvc1` 删除 PVC 来回收 PV，此时 PV 状态会变成 `Released`，随后 Kubernetes 会启动一个 `recycler` Pod 进行内容清除工作并将 PV 状态重新设为 `Available`。如果是 `Retain` 模式则不会启动 `recycler`，PV 始终处于不可用的 `Released` 状态，但即使此时删除 PV 并重新创建，PV 中的数据也依然存在。

此外，还可以使用外部的 StorageClass 以实现 PV 的动态供给，此时创建 PVC 时如未找到合适的 PV 就会自动创建。

要实现动态供给，在 PVC 的 `.spec.storageClassName` 中指定 StorageClass 的 `.metadata.name` 即可。

## 配置管理

### Secret

说到配置管理，首先不得不提的就是如何管理配置中的敏感信息。在 GitHub 中这是通过 Repo 的 Secrets 来管理的，Kubernetes 中也同理，通过 Secret 管理。Secret 可以作为一种特殊的 Volume 并挂载到 Pod 上供读取。

首先创建 Secret：

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: secret
data:
  username: YWRtaW4=
  password: MTIzNDU2
```

需要注意的是，Secret 的 key-value 中 value 必须经过 Base64 编码。

创建后就可以用 `k get secret` 和 `k describe secret` 查看了。

之后创建对应的 Volume，就可以挂载到 Pod 了：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
    - name: secret-container
      image: busybox
      volumeMounts:
        - name: secret-volume
          mountPath: /etc/secret
          readOnly: true
      args:
        - /bin/sh
        - -c
        - sleep 10; touch /tmp/healthy; sleep 30000
  volumes:
    - name: secret-volume
      secret:
        secretName: secret
```

之后 `k exec -it secret-pod -- sh` 并 `ls /etc/secret` 就可以看到每个 key 都是一个文件，内容就是 Base64 解码后的 value。当 Secret 本身更新时，文件的内容也会自动更新。

另一种方法是用 Secret 配置环境变量，只需要在 `.spec.containers[i]` 下添加：

```yaml
env:
  - name: USERNAME
    valueFrom:
      secretKeyRef:
        name: secret
        key: username
```

这种方式更为方便，但是不支持同步更新 Secret。

而对于剩余的不那么敏感的信息，就不需要使用 Secret 了，而是使用 ConfigMap 来配置。

### ConfigMap

ConfigMap 与 Secret 的 YAML 格式非常相似，区别在于：

- 数据不需要 Base64 编码
- `.kind` 改为 `ConfigMap`

通过 Volume 挂载与配置环境变量的过程也完全一致：

```yaml
volumes:
  - name: configmap-volume
    configMap:
      name: configmap
```

```yaml
env:
  - name: USERNAME
    valueFrom:
      configMapKeyRef:
        name: configmap
        key: username
```

## etcd

etcd 通过 key-value 对存储来自 API Server 的数据，其最重要的特性是可以监测数据的变更，因此可以当成消息队列来用。etcd 也可以用于服务发现和配置共享，其中 key 在经过一段时间（TTL）后可能失效，因此存在对应的续约机制，而这种机制恰好可以作为服务发现中的心跳来使用。

为保障数据一致性，etcd 采用了 Raft 协议。Raft 协议遵循 quorum 机制，也就是多数同意的规则，具体原理在 [The secret lives of data](http://thesecretlivesofdata.com/raft/) 上有非常生动的解释。

在 4.2.1 版本中引入了新角色 Learner，使得新节点加入时只接收数据而不投票，因此不影响 quorum，防止过度消耗 Leader 带宽。

### 安装

在 [Release 页面](https://github.com/etcd-io/etcd/releases) 有详尽且稳定的安装步骤。

### 启动

为了防止和 k8s 的 etcd 容器端口冲突，我们可以手动指定监听端口。其中 `listen-client-urls` 和 `listen-peer-urls` 是 etcd 服务器监听客户端和其他服务器请求的地址，而 `advertise-client-urls` 和 `initial-advertise-peer-urls` 是 etcd 客户端和其他服务器向 etcd 服务器发起请求所使用的端口。

```shell
$ etcd --initial-cluster "default=http://localhost:12380" \
       --listen-client-urls "http://localhost:12379" \
       --listen-peer-urls "http://localhost:12380" \
       --advertise-client-urls "http://localhost:12379" \
       --initial-advertise-peer-urls "http://localhost:12380"
```

### 常用操作

```bash
# list all members in table
etcdctl --endpoints=localhost:12379 member list --write-out=table
# put data
etcdctl --endpoints=localhost:12379 put /a b
etcdctl --endpoints=localhost:12379 put /c d
# read keys and values in /
etcdctl --endpoints=localhost:12379 get --prefix /
# read keys in /
etcdctl --endpoints=localhost:12379 get --prefix / --keys-only
# watch changes in /
etcdctl --endpoints=localhost:12379 watch --prefix /
# put new data in /a
etcdctl --endpoints=localhost:12379 put /a e
# get old data
etcdctl --endpoints=localhost:12379 get /a --rev=2
```

这里查询历史版本的原理涉及到 etcd 底层的存储机制。etcd 采用 kvindex 作内存索引，boltdb 进行存储。其中 kvindex 的 key 存储实际数据的 key，而 value 则存储 revision 信息。而 boltdb 中 key 存储的是 revision 信息，而 value 则是实际数据的 key-value 对。这样对数据的读写就遵循 `key->kvindex->boltdb->value` 的路径操作指定版本的数据。

> Kubernetes 各种 API Resources 中的 `resourceVersion` 的值就来自于 etcd 的 revision 信息。

### 灾备

```bash
# backup
etcdctl --endpoints=localhost:12379 snapshot save snapshot.db
# restore
etcdctl --endpoints=localhost:12379 snapshot restore snapshot.db
      # --initial-cluster=...
```

### 🌰：启动三节点 HTTPS 集群

```bash
# each etcd instance name need to be unique
# x380 is for peer communication
# x379 is for client communication
# dir-data cannot be shared
nohup etcd \
--name infra0 \
--data-dir=/tmp/etcd/infra0 \
--listen-peer-urls https://127.0.0.1:3380 \
--initial-advertise-peer-urls https://127.0.0.1:3380 \
--listen-client-urls https://127.0.0.1:3379 \
--advertise-client-urls https://127.0.0.1:3379 \
--initial-cluster-token etcd-cluster-1 \
--initial-cluster infra0=https://127.0.0.1:3380,infra1=https://127.0.0.1:4380,infra2=https://127.0.0.1:5380 \
--initial-cluster-state new \
--client-cert-auth --trusted-ca-file=/tmp/etcd-certs/certs/ca.pem \
--cert-file=/tmp/etcd-certs/certs/127.0.0.1.pem \
--key-file=/tmp/etcd-certs/certs/127.0.0.1-key.pem \
--peer-client-cert-auth --peer-trusted-ca-file=/tmp/etcd-certs/certs/ca.pem \
--peer-cert-file=/tmp/etcd-certs/certs/127.0.0.1.pem \
--peer-key-file=/tmp/etcd-certs/certs/127.0.0.1-key.pem 2>&1 > /var/log/infra0.log &

nohup etcd \
--name infra1 \
--data-dir=/tmp/etcd/infra1 \
--listen-peer-urls https://127.0.0.1:4380 \
--initial-advertise-peer-urls https://127.0.0.1:4380 \
--listen-client-urls https://127.0.0.1:4379 \
--advertise-client-urls https://127.0.0.1:4379 \
--initial-cluster-token etcd-cluster-1 \
--initial-cluster infra0=https://127.0.0.1:3380,infra1=https://127.0.0.1:4380,infra2=https://127.0.0.1:5380 \
--initial-cluster-state new \
--client-cert-auth --trusted-ca-file=/tmp/etcd-certs/certs/ca.pem \
--cert-file=/tmp/etcd-certs/certs/127.0.0.1.pem \
--key-file=/tmp/etcd-certs/certs/127.0.0.1-key.pem \
--peer-client-cert-auth --peer-trusted-ca-file=/tmp/etcd-certs/certs/ca.pem \
--peer-cert-file=/tmp/etcd-certs/certs/127.0.0.1.pem \
--peer-key-file=/tmp/etcd-certs/certs/127.0.0.1-key.pem 2>&1 > /var/log/infra1.log &

nohup etcd \
--name infra2 \
--data-dir=/tmp/etcd/infra2 \
--listen-peer-urls https://127.0.0.1:5380 \
--initial-advertise-peer-urls https://127.0.0.1:5380 \
--listen-client-urls https://127.0.0.1:5379 \
--advertise-client-urls https://127.0.0.1:5379 \
--initial-cluster-token etcd-cluster-1 \
--initial-cluster infra0=https://127.0.0.1:3380,infra1=https://127.0.0.1:4380,infra2=https://127.0.0.1:5380 \
--initial-cluster-state new \
--client-cert-auth --trusted-ca-file=/tmp/etcd-certs/certs/ca.pem \
--cert-file=/tmp/etcd-certs/certs/127.0.0.1.pem \
--key-file=/tmp/etcd-certs/certs/127.0.0.1-key.pem \
--peer-client-cert-auth --peer-trusted-ca-file=/tmp/etcd-certs/certs/ca.pem \
--peer-cert-file=/tmp/etcd-certs/certs/127.0.0.1.pem \
--peer-key-file=/tmp/etcd-certs/certs/127.0.0.1-key.pem 2>&1 > /var/log/infra2.log &
```

## API Server

任何请求到达 API Server 后首先都必须经过认证、鉴权、准入控制、限流等阶段，之后才会被接受。

### 认证

Kubernetes 支持多种认证方式：

- 证书（`--client-ca-file`）
- 静态 token（`--token-auth-file`，csv 文件）
- Bootstrap Token（`kube-system` 中的 Secret）
- 静态口令（`--basic-auth-file`，csv 文件）
- ServiceAccount
- OpenID（OAuth 2.0）
- Webhook（`--authtication-token-webhook-config-file`）
- 匿名访问（`--anonymous-auth`）

其中 Webhook 需要用户自己编写认证服务，使用 TokenReview 进行认证和返回结果。

### 鉴权

Kubernetes 支持的鉴权方式包括：

- ABAC（不推荐）
- RBAC
- Webhook
- Node

例如，要使用 RBAC，首先要创建相应的角色，如 Role 和跨 Namespace 的 ClusterRole：

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "watch", "list"]
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "watch", "list"]
```

随后，通过 RoleBinding（或 ClusterRoleBinding） 将 Role 绑定到具体的 subject（用户、组、ServiceAccount 等） 上：

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: dev # only grant perm in dev namespace
  name: read-secrets
subjects:
  - kind: User
    name: dave
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
```

### 准入

准入控制在授权后对请求进一步验证，粒度更细。准入控制由多个插件共同决定，通过了所有插件的检查，请求才会最终被接受。常见的插件包括：

- AlwaysAdmit 接受任意请求
- AlwaysPullImages 总是拉取最新镜像，无论本地是否已存在
- SecurityContextDeny 拒绝包含非法 SecurityContext 的请求
- ResourceQuota 用来限制 Pod 请求的配额
- DefaultStorageClass 为 PVC 设置默认的 StorageClass

一个有用的场景就是创建一个 ResourceQuotaController，当 Namespace 创建时自动创建 ResourceQuota，使得 ResourceQuota 插件生效，从而能够限制用户的资源配额。

毫无疑问，准入插件能做到非常多的事情，因此 Kubernetes 一定会允许我们自定义这样的插件。如果我们只对准入对象进行校验而不作修改，那么可以配置 ValidatingWebhookConfiguration；反之，如果需要修改准入对象，就需要 MutatingWebhookConfiguration 了。

一个简单的 MutatingWebhook 的例子可以在 [这里](https://github.com/stackrox/admission-controller-webhook-demo) 找到。

### 限流

API Server 使用 `max-requests-inflight` 限制给定时间内最大 non-mutating 请求数，用 `max-mutating-requests-inflight` 限制给定时间内最大 mutating 请求数。这两个值会随着节点数的增加而增加。

然而，这类传统限流方式存在诸多局限性：

- 粒度较粗，无法为不同场景设置不同限流策略
- 单一队列，使得恶意流量能够影响正常流量
- 容易产生饥饿问题
- 缺少优先级，系统指令同样被限流

因此，API Server 使用 API Priority and Fairness 在更细粒度上分类请求并分别限流。每一个分类对应一种 FlowSchema，同一 FlowSchema 内的请求又会被 distinguisher 分到不同的 Flow 中。最后，APF 使用混洗分片技术将请求分配到不同队列中。这种排队机制既防止了饥饿问题，又能一定程度上应对突发流量。

```yaml
apiVersion: flowcontrol.apiserver.k8s.io/v1beta1
kind: FlowSchema
metadata:
  name: kube-scheduler
spec:
  distinguisherMethod:
    type: ByNamespace # A FlowSchema and a distinguisher identify a flow
  matchingPrecedence: 800 # rule priority
  priorityLevelConfiguration:
    name: workload-high # queue priority
  rules:
    - resourceRules:
        - resources:
            - "*"
          verbs:
            - "*"
      subjects:
        - kind: User
          user:
            name: system:kube-scheduler
```

在另一个维度上，Priority 设置了请求的优先级。不同优先级之间的请求同样相互隔离，并且拥有独立的并发限制。对于系统指令类的流量，还可以设置为豁免流量，不受到限流的限制。

```yaml
apiVersion: flowcontrol.apiserver.k8s.io/v1beta1
kind: PriorityLevelConfiguration
metadata:
  name: global-default
spec:
  limited:
    assuredConcurrencyShares: 20 # max concurrent requests allowed
    limitResponse:
      queuing:
        handSize: 6 # number of queues per flow
        queueLengthLimit: 50 # max queue length
        queues: 128 # queue number
      type: Queue
  type: Limited
```

## Scheduler

### 资源需求

如上文所述，调度器可以使用 nodeSelector 调度 Pod 到指定的 Node 上，也可以通过 Pod 的资源需求来调度 Pod。此时，调度器关注的是 `.spec.resources.requests` ，而 cgroups 则使用 `.spec.resources.limits` 限制 Pod 中的 container 能使用的资源上限。例如，`cpu: 1` 意味着容器可以获得一个 CPU 的全部时间片，而 `cpu: 1m` 则表示一个 CPU 的全部时间片的千分之一。

根据 `resources` 字段的设置，container 的资源需求可以分为三种 `qosClass`（对应的 QoS 从高到低）：

- Guarantee：`resources` 下的 `request` 等于 `limit`
- Burstable：`resources` 下的 `request` 小于 `limit`
- BestEffort：不设置 `resources` 字段

当节点资源不足时，会按 BestEffort、Burstable、Guarantee 的顺序依次驱逐 Pod。

同时，也可以使用 LimitRange 来给所有没有设置 `resources` 的 container（包括 `initContainers`）加上默认的 `resources` 字段：

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: mem-limit-range
spec:
  limits:
    - default:
        memory: 512Mi
      defaultRequest:
        memory: 256Mi
      type: Container
```

### Affinity

另一种调度方式是根据 Pod 的 `nodeAffinity` 和 `nodeAntiAffinity`。`requiredDuringSchedulingIgnoredDuringExecution` 和 `preferredDuringSchedulingIgnoredDuringExecution` 分别表示强亲和性和弱亲和性，前者在找不到亲和的 Node 时不会运行。

强亲和性 Pod 语法如下：

```yaml
template:
  metadata:
    labels:
      app: nginx
  spec:
    affinity:
      nodeAffinity:
        requiredDuringSchedulingIgnoredDuringExecution:
          nodeSelectorTerms:
            - matchExpressions:
                - key: disktype
                  operator: In
                  values:
                    - ssd
    containers:
      - name: nginx
        image: nginx
```

弱亲和性：

```yaml
spec:
  affinity:
    nodeAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
        - weight: 1
          preference:
            matchExpressions:
              - key: disktype
                operator: In
                values:
                  - ssd
```

同理，可以用 `podAffinity` 和 `podAntiAffinity` 指定 Pod 间亲和性，即判断某一个范围内（由 `topologyKey` 指定）现有的 Pod 是否满足相应条件来进行调度。

### Taint 和 Toleration

Taint 会给 Node 加污点，来防止任意 Pod 被调度到该 Node 上。同时，我们可以给部分 Pod 指定 Toleration，使得这些 Pod 能够容忍这些污点并被调度到该 Node 上。

存在三种污点类型：

- NoSchedule 会使得新 Pod 不再调度到该 Node 上，但现有 Pod 不受影响
- PreferNoSchedule 会使得新 Pod 尽量不调度到该 Node 上，但现有 Pod 不受影响
- NoExecute 会使得新 Pod 不再调度到该 Node 上，且对于现有 Pod，会在 Pod 的 `tolerationSeconds ` 秒后，驱逐对应的 Pod

例如，先给某个 Node 加污点：

```shell
$ k taint no node0 key=value:NoSchedule
```

随后创建 Pod，会发现无法调度到该 Node 上，直到我们取消这个污点：

```shell
$ k taint no node0 key=value:NoSchedule-
```

或是给新的 Pod 添加 Toleration：

```yaml
template:
  metadata:
    labels:
      app: nginx
  spec:
    containers:
      - name: nginx
        image: nginx
    tolerations:
      - key: key
        operator: Equal
        value: value
        effect: NoSchedule
```

### PriorityClass

最后，可以为 Pod 设置调度优先级。首先定义 PriorityClass：

```yaml
apiVersion: v1
kind: PriorityClass
metadata:
  name: high-priority
value: 1000000
globalDefault: false
description: "the greater the value, the higher the priority"
```

随后在 Pod 中设置该 PriorityClass：

```yaml
template:
  metadata:
    labels:
      app: nginx
  spec:
    containers:
      - name: nginx
        image: nginx
    priorityClassName: high-priority
```

## CRI / CNI / CSI

### CRI

常见的容器运行时接口包括 Docker、containerd、CRI-O 等，采用的是主流的 runc 规范。由于 Docker 本身是一个独立的产品，用在 Kubernetes 里显得较重。而 containerd 则在实现上和使用上都更为轻量——实际上，即使使用 Docker 作为 CRI，Kubernetes 底层依然是经由 Docker，从而在 containerd 中运行容器的。

因此，可以说目前 Kubernetes 最合适的 CRI 是 containerd。

### CNI

在 Kubernetes 中，网络模型是非常直观、符合直觉的：

- 每个 Pod 都有自己的 IP 地址，但每次重建后可能发生变化
- 同一个 Pod 中的容器共享网络 Namespace，因此可直接通过 localhost 通信
- Pod 的 IP 对整个集群可见，集群中任意 Pod 或 Node 访问一个 Pod 都无需经过 NAT
- 由于 Pod 的 IP 地址不稳定，可以通过 Service 来访问 Pod，同时 Service 本身具备负载均衡功能

为了让各厂商不同的网络标准和工具都能符合这种网络模型，也为了让网络能与各种 CRI 兼容，Kubernetes 采用容器网络接口规范，通过插件的形式构建网络。插件中一般会定义如何分配 IP、如何设置网卡、如何限流、如何设置防火墙、如何端口转发等等。常见的插件包括 Flannel、Calico、Cilium 等。

例如，Calico 对同网段通信采用 BGP 协议来路由数据包，此时不需要封包；对跨网段通信，则使用 IPinIP 封装 IP 数据包。此外，Calico 支持使用 ACLs 协议和 kube-proxy 来创建 iptables 过滤规则，从而隔离容器网络。

在调用任何插件前，CRI 必须先创建一个网络 Namespace。这也是为什么一个运行的 Pod 中即使只声明了一个容器，也会出现另外一个 pause 容器（这一步称为 `createPodSandbox`）。pause 容器只运行 `sleep infinity` ，几乎不占 CPU 和内存，主要作用就是为了为当前 Pod 创建好网络 Namespace 供同一 Pod 中其他容器，也就是我们声明的容器使用。

### CSI

容器存储接口方面，选择就比较单一了，因为 OverlayFS 性能过于强势。Docker 和 containerd 也默认使用 OverlayFS 作为运行时存储驱动。上文提到的 emptyDir、hostPath、PV 和 PVC、外部存储等，都实现了 CSI 接口，因此可以在不同场景下为 Pod 所挂载并使用。CSI 也同样支持插件系统。

kubelet 创建 Pod 时首先会调用 CSI 接口，初始化容器存储，比如挂载 Volume 等；随后 `createPodSandbox` 准备好 pause 容器并运行；接着调用 CRI 的接口，启动容器、创建好 Pod 的网络 Namespace，为构建网络作好准备；最后才调用 CNI 的接口真正构建容器网络。

## Pod 生命周期钩子

和 Vue 里的生命周期钩子类似，Pod 中的 container 也可以定义 postStart 钩子和 preStop 钩子。postStart 钩子在容器启动后运行，但无法保证其和容器 Entrypoint 谁先执行，运行完 postStart 后容器才会被标记为 Running。

preStop 则只有在 Pod 被删除时（而不是完成时 / 容器退出时）才会执行，执行完毕后 Kubernetes 会向容器发送 SIGTERM 信号。如果 preStop 执行时间和容器收到 SIGTERM 后花费的时间加起来超过了 `terminationGracePeriodSeconds`，那么容器就会收到 SIGKILL 信号强制退出。

值得注意的是，bash / sh 会忽略 SIGTERM 信号，这使得 `terminationGracePeriodSeconds` 失去意义。因此，用 bash / sh 作为容器 Entrypoint 时，应设置尽量小的超时时间。

## 服务发现与负载均衡

### Endpoint

当我们创建一个 selector 不为空的 Service 时，Endpoint Controller 会监听到这一事件并创建同名的 Endpoint 对象。满足 selector 要求的所有 Pod 的 IP 都会被配置到 Endpoint 的地址列表中。例如，通过 `k get po -owide` 查看一个 Deployment 中一组 Pod 的 IP，分别为 `10.1.1.114`、`10.1.1.111`、`10.1.1.112`。随后查看对应 Service 所对应的 Endpoint：

```shell
$ k describe ep nginx-svc
Name:         nginx-svc
Namespace:    default
Labels:       <none>
Annotations:  endpoints.kubernetes.io/last-change-trigger-time: 2021-11-26T12:37:50Z
Subsets:
  Addresses:          10.1.1.111,10.1.1.112,10.1.1.114
  NotReadyAddresses:  <none>
  Ports:
Name     Port  Protocol
----     ----  --------
<unset>  80    TCP

Events:  <none>
```

可以在 `Subsets` 下的 `Addresses` 里发现这三个地址，说明实际进行流量转发的是 Service 底层的 Endpoint 对象。

如果不为 Service 定义 selector，那么就不会创建对应的 Endpoint。此时可以手动创建 Endpoint 指向指定的地址。

### kube-proxy

流量的转发是 kube-proxy 的主要任务之一。kube-proxy 使用 iptables 中配置的转发规则，以 `1/n` 的概率转发到 n 个 IP 中的某一个上。为了解决在转发规模较大时 iptables 的性能问题、以及基于概率的伪负载均衡问题，目前可以采用 ipvs 配置更简洁的规则和更丰富的负载均衡类型，如 round-robin 等。

总的来说，外部流量从 API Server 进入，经过 Service Controller -> 外部 Load Balancer（如果存在） -> kube-proxy -> NodePort IP（如果存在） -> ClusterIP（如果存在） 的顺序最终到达 Pod IP。

### CoreDNS

CoreDNS 就是 Kubernetes 内部的 DNS 服务器。对于包含 ClusterIP 的 Service，CoreDNS 都会创建 `$svcName.$namespace.svc.$clusterdomain: clusterIP` 的 A 记录和 PTR 记录，并为端口创建 SRV 记录。如果 Service 显式指定了 `.spec.ClusterIP` 为 `None`，那么 CoreDNS 会创建多条 A 记录，分别指向每个 Ready 的 Pod IP，格式类似 `$podName.$svcName.$namespace.svc.$clusterdomain`。而如果 Service 指定了 `.spec.externalName`，那么 CoreDNS 只会创建对应的 CNAME 记录。

在每个 Pod 的 `/etc/resolv.conf` 中，都可以看到 nameserver 地址（也就是 CoreDNS 服务的地址）和搜索规则，CoreDNS 依次尝试在要解析的域名后添加这些域名来拼凑出完整的域名。

```shell
$ cat /etc/resolv.conf
nameserver 10.96.0.10
search default.svc.cluster.local svc.cluster.local cluster.local
options ndots:5
```

### Ingress

上面提到的 Service 设置的外部 LoadBalancer、和 kube-proxy 利用 iptables / ipvs 提供的负载均衡功能，都属于 L4 负载均衡，工作在传输层。而 Ingress 则提供了 L7 负载均衡，作为工作在应用层的代理服务来实现负载均衡的功能。Ingress 主要采用 TLS Termination 技术，我们可以在 Ingress 层面配置 HTTPS 证书来提供给内部的多个服务使用。

一个比较简单的方法是通过 Secret 配置证书：

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: httpserver-tls
type: kubernetes.io/tls
data:
  tls.crt: # Base64(PEM format file)
  tls.key: # Base64(PEM format file)
```

随后配置 Ingress 对象：

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: httpserver-gateway
  annotations:
    kubernetes.io/ingress.allow-http: "false"
spec:
  tls:
    - hosts:
        - sigmerc.top
      secretName: httpserver-tls
  rules:
    - host: sigmerc.top
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: httpserver-service
                port:
                  number: 80
```

注意证书和域名的匹配问题。这里可以指定多个 path，每个 path 对应一个 backend service。一些特性则可以在 `.metadata.annotations` 中声明，例如禁止 HTTP 等。

## 节点管理

### OS

节点可以选择安装类似 CentOS、Ubuntu、Debian 等通用操作系统，也可以选择为容器优化的最小化操作系统，如 CoreOS、RedHat Atomic 等。后者的主要优势在于体积更小、安全性更高、以及原子的升级和回退操作。例如，Atomic 就是基于 rpm-ostree 灵活地构建、升级、回退操作系统镜像的。

### 资源管理

kubelet 基于 cAdvisor，周期性向 API Server 上报节点状态，作为调度器在调度节点时的参考。Kubernetes 采用 Lease 机制，在 `nodeLeaseDurationSeconds` 时间内，如果节点的 Lease 对象没有更新，就认为节点不健康。

同时，kubelet 也可以为节点 OS 中其他系统进程预留资源，通过 `k describe node` 可以查看节点的总资源量 `capacity` 和可分配额 `allocatable`。磁盘同样被分为系统分区 nodefs 和容器运势分区 imagefs。

在节点资源不够时，kubelet 会终止部分 Pod 中的容器进程以回收资源，保证节点稳定性，但不会删除 Pod，这一过程称为驱逐。由于被驱逐的 Pod 已经停止却不会被删除，需要注意定期清理这些 Pod。根据进程内存使用情况，甚至可能发生 OOM Kill。

存储方面，需要注意日志的定时 rotate，防止大量日志占用磁盘。网络方面，则可以使用 `kubernetes.io/ingress-bandwidth` 和 `kubernetes.io/egress-bandwidth` 来控制出入流量。

### 异常检测

node-problem-detector 是 Kubernetes 中检测节点异常信息并上报的工具，通过设置 NodeCondition 改变节点状态来处理永久性故障、通过 Event 对象来通知其他对象临时性故障。

不过 NodeCondition 的变化不会影响调度器逻辑，而是需要我们自己编写控制器，监听 NodeCondition 变化并做污点标记。

## 运维相关

### 镜像管理

我们还可以自行构建私有镜像仓库，增强安全性和可达性，只要遵循 OCI 的 Distribution Spec 就可以像使用公有镜像仓库一样使用自己的镜像仓库。例如，Harbor 就可以用来构建一个功能丰富的镜像仓库，还提供了自动化的日志收集、垃圾回收等功能。当然，镜像仓库同样需要高可用部署。私有镜像仓库配合 Dragonfly ，可以大大加速镜像的拉取。

镜像本身也可能存在安全问题，在构建镜像时应注意减少不必要依赖、避免直接在构建指令中引用敏感信息等。部署为 Pod 前，应通过准入控制对镜像进行安全漏洞扫描。

### CI/CD

在 Kubernetes 中当然也要把 CI/CD 自动化、容器化。这方面现有的成熟工具都可以比较方便地使用：

- Jenkins
- GitOps
- GitHub Actions

除此之外，还有基于声明式 API 的 Tekton、ArgoCD 等等，这些工具都与本身采用声明式 API 的 Kubernetes 高度兼容。

### 监控和日志

分布式系统中日志查看较为复杂，因此需要工具将日志收集汇总，便于查看。例如，我们可以采用 Loki-stack 子系统，通过运行在节点上的 Promtail 将容器日志发送到 Loki，由 Loki 聚合日志并发送到 Grafana，最终呈现可视化日志观测的效果。

监控方面则通常使用 Prometheus 从节点上拉取监控指标（往往需要在应用代码中暴露相应的指标），并由 Grafana 展示。为了更高效地查看监控数据，需要了解 PromQL 查询语言。除此之外，Prometheus 还支持告警、断言等操作。可以想象，Prometheus 对内存和存储的要求较高。

## 应用迁移

### 应用容器化

将应用容器化，需要从两方面考虑，一是应用本身的启动速度、参数、健康检查，而是 Dockerfile 的编写，例如使用尽可能小的基础镜像、安装尽可能少的依赖、进程数控制、代码和配置分离、镜像分层等等。

尤其需要注意的是，容器和宿主机共用内核，因此系统参数配置、fd 数、进程数、主机磁盘都是共享的。这意味着使用 `top` / `cat /proc/cpuinfo` / `cat /proc/meminfo` / `df -k` 等命令看到的资源都是主机资源。那么如何判断应用当前运行在 Kubernetes 上还是主机上呢？一种办法是查看 `/proc/1/cgroup` 中是否包含 `kubepods` 关键字。

至于 CPU 和内存的配额及用量，可以参考上文 cgroups 部分的内容。

### Pod 配置

在应用容器化之后，需要配置 Pod spec，比如值得注意的有用于初始化的 init container、权限相关的 SecurityContext、共享哪些 Namespace、如何优雅终止、健康检查、DNS 策略、镜像拉取策略等等。

一个典型的例子是如下的一个 readiness probe：

```yaml
readinessProbe:
  exec:
    command:
      - /opt/rprobe.sh
  failureThreshold: 3
  initialDelaySeconds: 30
  periodSeconds: 10
  successThreshold: 1
  timeoutSeconds: 1
```

由于 `command` 是一个 bash 脚本，Entrypoint 进程会 `fork()` 出新进程来执行脚本进行健康检查。然而，这里的超时时间只有一秒，如果检查没有正常执行完成而是超时退出，并且 Entrypoint 没有清理子进程的能力的话，就会导致每次健康检查都会留下一个僵尸进程，造成 PID 泄漏。

Tini 项目很好地解决了这一问题：

```dockerfile
ENTRYPOINT ["/tini", "--"]

# Run your program under Tini
CMD ["/your/program", "-and", "-its", "arguments"]
```

此时，PID 为 1 的 Entrypoint 进程为 Tini，后续容器中的僵尸进程的父进程会被设为 1，最后被 Tini 清理。当然，除了使用 Tini 外，设置合理的超时时间也是需要的。

为了保障应用高可用，还可以设置 PodDisruptionBudget 指定 `minAvailable` 或 `maxUnavailable` 数量，这和滚动更新的配置有些类似。

### Helm

Kubernetes 中拥有各种各样的 API Resources，一个完整的服务可能就需要用到其中的好几种，在服务数量较多时较难管理。因此可以使用类似包管理器的 Helm 来实施对服务层面而不是 API Resources 层面的管理。

Helm chart 就像 apt 中的 package，是 Helm 部署应用的单元。Helm 客户端将 Helm chart 安装到 Kubernetes 并生成 release。

Helm 拥有相当清晰详细的[文档](https://helm.sh/zh/docs/)，感觉自己写得不如文档好，具体的使用这里就不写了。

### CRD

应用迁移过程中，难免遇到需要扩展 Kubernetes 对象以满足业务需求的场景，此时我们可以编写 CRD 来达到这一目标。一般可以采用 kubebuilder 搭建脚手架，先利用 RBAC 机制保障安全性和设立访问控制机制，随后将扩展的资源数据存储到 etcd，然后最关键的是要实现 Controller，借助 APIServer 监听其他对象或资源的状态变化并作出反应。编写 CRD 就类似于编写 Kubernetes 插件，十分灵活。

### 自动扩缩容

#### metrics-server

Kubernetes 使用 metrics-server 监控集群，从 kubelet 中收集数据并通过 kube-aggregator 进行聚合，并在 APIServer 中通过 `/api/metrics.k8s.io` 暴露指标数据。安装了 metrics-server 后，就可以通过 `k top` 来查看资源信息了。

#### HPA

自动横向扩缩容 HPA 也依赖于 metrics-server 提供的数据，例如根据资源使用量动态调整 Deployment 中的 `replicas` 字段等等。例如，我们可以为已有的 Deployment `php-apache` 创建如下 HPA：

```yaml
apiVersion: autoscaling/v1
kind: HorizontalPodAutoscaler
metadata:
  name: php-apache
  namespace: default
spec:
  maxReplicas: 10
  minReplicas: 1
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: php-apache
  targetCPUUtilizationPercentage: 50
```

表示最少 1 个副本，最多 10 个副本，当 CPU 利用率超过 50% 时扩容。在 `autoscaling/v2beta2` 中，则使用 `metrics` 字段细化指标类型：

```yaml
apiVersion: autoscaling/v2beta2
kind: HorizontalPodAutoscaler
metadata:
  name: php-apache
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: php-apache
  minReplicas: 1
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 50
```

随后，对服务加压：

```shell
$ k run -i --tty load-generator --rm --image=busybox --restart=Never -- /bin/sh -c "while sleep 0.01; do wget -q -O- http://php-apache; done"
```

此时 HPA 会在 Pod CPU 利用率达到 50% 时扩容，直到创建了 10 个副本。停止加压一段时间后，副本数会慢慢下降，直至只剩一个。

HPA 的动态调整是有效的，但是却存在滞后性，面对突发流量时从负载超出阈值到 HPA 完成扩容需要较长的时间，这是 HPA 的主要缺点。

#### VPA

垂直自动扩缩容则根据每个 Pod 的资源利用情况（同样来自 metrics-server），调整 `requests` 字段，从而允许 Pod 被调度到合适的节点上。Recommender 收集指标后给出资源请求限制的建议，由 Admission Plugin 将 Pod 变形，Updater 监听建议，最终删除旧 Pod，由 Deployment 创建新 Pod。

遗憾的是，VPA 成熟度不足，尚不能用于生产环境，这主要是因为：

- VPA 会导致 Pod 的重建和重启，而且 Pod 可能被调度到其他节点上
- VPA 无法驱逐不在副本控制器下的 Pod
- VPA 无法和 HPA 同时使用
- VPA 修改 `requests` 后，结果可能超出实际的节点资源上限导致 Pod 无法被调度

## Istio

在微服务架构中，除了业务本身的微服务，也就是数据面之外，我们还需要负载均衡、认证授权、服务发现、熔断限流、TLS 加密、日志监控等控制面功能，以及相应的服务注册中心、认证服务器、API 网关等控制面组件。然而在传统微服务架构中，控制面和数据面混合在一起，不便于维护。

服务网格则通过在每个业务微服务旁加入 Sidecar 劫持出入流量，控制面的功能由 Sidecar 来处理，因此负责与控制面组件或是其他微服务通信的也是 Sidecar。这使得业务微服务无需再关心控制面逻辑，也能够自由选择技术栈。

然而，Sidecar 本身是一个容器，更多的运行实例意味着更复杂的架构。由于每个服务调用都必须经过 Sidecar，必定会引入额外的网络跳转，带来一定性能开销，因此需要慎重考虑是否真的需要服务网格。

Istio 的控制平面 istiod 如今是一个单体应用，数据平面 Envoy 则担任了 Sidecar 的角色。

### Envoy

相比 Nginx 和 HA Proxy，Envoy 支持 HTTP/2 和不丢失连接的热重启，并且依然能保持高性能。而高度可扩展性（Filter 插件）和 API 可配置性使得它能够比较轻松地与复杂控制面结合，成为了更为通用的数据面。

Envoy 基于 epoll，采用单进程多线程模式，在 v1 版本中仅使用 REST+JSON 轮询的方式，到了 v2 则增加了 proto3+gRPC 的支持，这使得 Envoy 能够真正应用于生产环境。

### 流量劫持机制

当我们给 Namespace、Deployment 等对象打上 `istio-injection=enabled` 标签时，对应 Pod 的流量就会被 Sidecar 劫持，原本只运行一个容器的 Pod 会多出一个 Sidecar，运行 `istio/proxyv2` 镜像（实际上就是 envoy），这是由 Istio 的 mutating webhook 插入的。同时，通过 init container 修改了原容器的 iptables，使得出方向的 TCP 流量：

1. 被重定向到虚拟监听器监听的 15001 端口
2. 由 15001 端口转到 80 端口
3. 通过路由规则找到目标 FQDN 和 Endpoint
4. 转发到目标 Endpoint

然而，在转发到目标 Endpoint 的过程中依然会受到 iptables 规则约束，这样是不是会回到第一步，又被转发到 15001 端口呢？为了避免这种情况，iptables 中配置了一条特殊的规则，放行特定用户（UID=1337）的流量，而 Sidecar 容器正是通过这个用户运行的 istio-proxy，因此第四步的流量不会被 iptables 拦截。

而对于入方向的 TCP 流量，流程是一致的，区别仅在于 15001 变成了 15006 端口。

### 流量管理

Istio 能提供更精细化的流量管理，例如将 95% 的流量负载均衡给生产环境的服务、将 5% 的流量发送到金丝雀发布的服务，或是将来自不同客户端的流量转发到不同版本的服务等等。不过，虽然 Envoy 支持多种负载均衡算法，Istio 目前只支持轮询、随机和带权重的最少请求算法。

除了负载均衡之外，Istio 和 Envoy 结合还支持健康检查、超时处理、细粒度熔断机制、重试机制、流量控制、错误注入等丰富功能。

### VirtualService

例如，我们将 25% 流量分给 v2 版本，剩余 75% 给 v1 版本，并引入超时、重试、错误注入机制：

```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: reviews
spec:
  hosts:
    - reviews # FQDN
  http:
    - route:
        - destination:
            host: reviews
            subset: v1
          weight: 75
        - destination:
            host: reviews
            subset: v2
          weight: 25
      timeout: 10s
      retries: # retry if upstream server send 5xx
        attempts: 3
        perTryTimeout: 2s
      fault: # send 500 to 80% client
        abort:
          httpStatus: 500
          percentage:
            value: 80
```

一个常见的用法是配合 Gateway 发布服务：

```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: simple
spec:
  gateways:
    - simple
  hosts:
    - simple.com
  http:
    - match:
        - port: 80
      route:
        - destination:
            host: simple.simple.svc.cluster.local
            port:
              number: 80
---
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: simple
spec:
  selector:
    istio: ingressgateway
  servers:
    - hosts:
        - simple.com
      port:
        name: http-simple
        number: 80
        protocol: HTTP
```

或者使用条件规则，配合 `DestinationRule` 设置灵活的负载均衡策略：

```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: canary
spec:
  hosts:
    - canary
  http:
    - match: # if header["user"]=="merc", go to v2
        - headers:
            user:
              exact: merc
      route:
        - destination:
            host: canary
            subset: v2
    - route:
        - destination:
            host: canary
            subset: v1
---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: canary
spec:
  host: canary
  trafficPolicy: # default to RANDOM
    loadBalancer:
      simple: RANDOM
  subsets:
    - name: v1 # RANDOM inside v1
      labels:
        version: v1
    - name: v2
      labels:
        version: v2
      trafficPolicy: # RR inside v2
        loadBalancer:
          simple: ROUND_ROBIN
```

除了这些之外，还可以使用 `mirror` 字段实现流量镜像、`delegate` 字段进行规则委托等、为 Gateway 配置 TLS、用 DestinationRule 实现断路器等。更多用法可以参考 [官方文档](https://istio.io/latest/docs/)。

## 安全

### 容器运行时安全

一般不允许使用 root 用户运行容器，防止权限过高。集群中也需要保证容器与容器间、容器与主机间隔离，并遵循最小特权原则。为了达到这一目标，常用的手段包括 Pod 安全上下文（Pod Security Context）、API Server 的认证、授权、审计、准入、以及数据加密等机制。

### 集群安全

- Kubernetes 的 API 通信都基于 TLS，实现了传输过程中的加密
- 定义 EncryptionConfiguration 对象可以对存储进行加密
- 使用 NodeRestriction 准入控制插件可以防止 kubelet 修改带 `node-restriction.kubernetes.io/` 标签的节点，降低 kubeconfig 泄露造成的危害
- Pod 安全策略则更细粒度地限制了用户对 Pod 的操作：
  - Container-level Security Context 仅应用到指定的容器
  - Pod-level Security Context 应用到 Pod 内所有容器（和 Volume）
  - Pod Security Policies 则应用到整个集群内部的所有 Pod（和 Volume）

例如，可以在 Container-level Security Context 中禁止特权运行，也可以将 `securityContext` 字段提到和 `containers` 同级作为 Pod-level Security Context：

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
        - name: nginx
          image: nginx
          securityContext:
            privileged: false
```

Pod Security Policies 则需要作为一个单独的对象编写，例如限制端口范围：

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  privileged: false
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  hostPorts:
    - min: 8000
      max: 8080
  volumes:
    - "*"
```

最后，之前提到的 Taint 机制也可以用于集群节点间的安全隔离。

### NetworkPolicy

Kubernetes 默认提供了 NetworkPolicy 对象实现三层/四层网络流量的控制，概念上类似防火墙。不过，要使用 NetworkPolicy，我们必须使用支持 NetworkPolicy 的 CNI。NetworkPolicy 的语义非常直观，和防火墙规则类似：

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      role: db
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - ipBlock:
            cidr: 172.17.0.0/16
            except:
              - 172.17.1.0/24
        - namespaceSelector:
            matchLabels:
              project: myproject
        - podSelector:
            matchLabels:
              role: frontend
      ports:
        - protocol: TCP
          port: 6379
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/24
      ports:
        - protocol: TCP
          port: 5978
```

上面的 NetworkPolicy 会应用到 default Namespace 下带 `role=db` 标签的所有 Pod 上，允许来自除 172.17.1.0/24 外所有 172.17.0.0/16 的入站流量、允许来自带 `project=myproject` 标签的所有 Namespace 的入站流量、允许 default Namespace 下带 `role=frontend` 标签的所有 Pod 的 入站流量发送到 TCP 6379 端口上。同时允许访问 10.0.0.0/24 网段 TCP 5978 端口的出站流量。

如果 `podSelector` 设为 `{}`，则会应用到所有 Pod 上；如果 `ingress` 或 `egress` 字段设为 `{}`，则会允许所有入站/出站流量。

Calico 在此基础上，开发了自己的 NetworkPolicy 扩展了其功能。需要注意的是，Calico 的 NetworkPolicy 和默认 NetworkPolicy 同名但并非同一个对象。例如，我们可以编写如下规则允许集群内所有 ping 请求：

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-ping-in-cluster
spec:
  selector: all()
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: ICMP
      # notProtocol: TCP     # do not match this protocol
      source:
        # nets:              # IP range
        # namespaceSelector: # namespace label selector
        # ports:
        #   - 80             # single port
        #   - 6040:6050      # port range
        # destination:       # target address
        selector: all() # pod label selector
      icmp:
        type: 8 # Ping request
    - action: Allow
      protocol: ICMPv6
      source:
        selector: all()
      icmp:
        type: 128 # Ping request
  # serviceAccountSelector: # apply rules to this SA
```

上述规则只展示了 `ingress` 规则，同理可以运用于 `egress`。此外，还可以配置 GlobalNetworkPolicy 应用于集群中所有 Namespace，并且能限制 Pod 和主机之间的流量，这是默认 NetworkPolicy 做不到的。可以想到，Calico 的 NetworkPolicy 也是基于 iptables 实现的。

### Istio 安全保证

Istio 拥有自己的 CA 以支持 TLS 双向认证，这是通过 Sidecar 上的 Envoy 实现的。Istio 通过 Service Identity 确定一个请求源的身份，在 Kubernetes 中对应 Service Account。

当工作负载启动时，Envoy 通过 Secret Discovery Service 向 istio-agent 发送证书和密钥请求，后者交由 istiod CA 签名生成证书后返回。后续的证书有效期更新则由 istio-agent 负责。

例如，在 DestinationRule 中可以开启 TLS 双向认证：

```yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: ratings-istio-mtls
spec:
  host: ratings.prod.svc.cluster.local
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL # SIMPLE / MUTUAL / ISTIO_MUTUAL
```

工作负载间的通信主要通过 PeerAuthentication 认证，默认使用 Permissive 模式，即优先使用 mTLS，但同样支持明文通信，方便服务迁移。Strict 和 Disable 模式则对应强制 mTLS 和强制明文两个极端。此外，mTLS 模式选择可以细化到端口级别。

```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: example-peer-policy
  namespace: foo
spec:
  selector:
    matchLabels:
      app: reviews
  mtls:
    mode: STRICT # PERMISSIVE / STRICT / DISABLE
  # portLevelMtls:
  #   80:
  #     mode: DISABLE
```

RequestAuthentication 则是用户请求到服务的认证，主要基于 JWT。我们可以配置规则对请求携带的 JWT 进行检查并拒绝无效请求。

```yaml
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  selector:
    matchLabels:
      istio: ingress-gateway
  jwtRules:
    - issuer: "testing@secure.istio.io"
      jwksUri: "https://raw.githubusercontent.com/istio/istio/release-1.12/security/tools/jwt/samples/jwks.json"
```

同样地，授权也是类似的，通过 AuthorizationPolicy 配置 `rules` 字段来 ALLOW 或 DENY 相应的请求。

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: httpbin
  namespace: foo
spec:
  selector:
    matchLabels:
      app: httpbin
      version: v1
  action: ALLOW # default value: DENY
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/default/sa/sleep"]
        - source: # OR
            namespaces: ["dev"]
      to:
        - operation:
            methods: ["GET"]
      when:
        - key: request.auth.claims[iss]
          values: ["https://accounts.google.com"]
```

需要注意的是，`source` 字段下的 `principals` 如果设为 `[*]`，则代表只允许经过认证的用户。如果需要公开访问，可以不写 `source` 字段。

## 其他尚未学习的方面

- Extended Resource
- 集群自动化管理、集群高可用、节点生命周期管理
- Cluster API、K8s in K8s
- Cluster Autoscaler
- 多租户管理、多集群管理
- 部署有状态应用
