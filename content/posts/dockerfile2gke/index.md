---
title: 再探 GitHub Actions：从 Dockerfile 到 GKE
date: 2021-09-25 18:44:35
tags:
  - Docker
  - GCP
  - Kubernetes
  - CI/CD
  - ARM
  - 实践记录
categories:
  - 云
---

GitHub Actions 还可以配合 Issue 用来做开源社区的无聊小游戏，这就留到《三探 GitHub Actions》再说了。

<!--more-->

## 背景

和 [上回](/github-actions-cd) 类似，我这次又遇到了一些机械重复的操作。当我写完一个 Go 应用，想发布在公网上供访问、同时保证高可用性时，我需要：

1. 运行 `go build`，附带一堆参数
2. 运行 `docker build` 打包 Docker 镜像
3. 运行 `docker run` 测试镜像是否可用，存在问题则回到第 1 步之前
4. 运行 `docker ps ` 和 `docker rm` 清理容器
5. 运行 `docker push` 发布镜像
6. 运行 `docker image ls` 和 `docker image rm` 清理镜像
7. 在 Google Kubernetes Engine 里打开 Cloud Shell
8. 运行 `kubectl create deploy` 创建 deploy
9. 运行 `kubectl expose deploy` 创建 service

这实在是太麻烦了。不过和上次不同，这次的步骤和参数都复杂了许多，因此多花了些时间。

## 编写 Dockerfile

我这里使用了 Muti-stage 的方式，先编译后部署，实际上也可以写一个脚本，本地编译后直接运行第二阶段。

```dockerfile
FROM golang:1.17.1 AS builder

RUN mkdir /app
ADD . /app
WORKDIR /app
RUN mkdir bin && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-w -s" -gcflags "-N -l" -o bin/httpserver

FROM alpine AS production
COPY --from=builder /app/bin/* .
CMD ["./httpserver", ":8080"]
```

需要注意的是，`alpine` 所采用的 musl libc 会影响到使用默认配置编译的 go 二进制文件，因此必须设置 `CGO_ENABLED=0`。

写好上面的 Dockerfile 后，x64 机器就可以直接打包镜像了，但 M1 不行，因为 M1 上的 Docker 无论 `pull` 还是 `build` 都默认用 ARM 版本的镜像。为了解决这个问题，可以用 [buildx](https://docs.docker.com/buildx/working-with-buildx/) 辅助编译：

```shell
$ docker buildx build --platform linux/amd64 --push -t httpserver .
```

`buildx` 还可以声明多个平台，用逗号隔开。当然此时也需要 go 编译多个平台的二进制文件。

不过最方便的办法当然是使用 GitHub Actions 啦。由于和 GCP 融合，我们选择把镜像上传到 Google Container Registry，因此 Actions 脚本会有些变化：

```yaml
name: Build and Deploy to GKE

on:
  push:
    branches:
      - main

env:
  PROJECT_ID: ${{secrets.GKE_PROJECT}}
  GKE_CLUSTER: cluster-1
  GKE_ZONE: us-central1-c
  DEPLOYMENT_NAME: httpserver
  IMAGE: httpserver

jobs:
  setup-build-publish-deploy:
    name: Setup, Build, Publish and Deploy
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v2

      # Setup gcloud CLI
      # ...

      # Configure Docker to use the gcloud command-line tool as a credential
      # helper for authentication
      # ...

      # Get the GKE credentials so we can deploy to the cluster
      # ...

      # Build the Docker image
      - name: Build
        run: |-
          docker build \
            --tag "gcr.io/$PROJECT_ID/$IMAGE:$GITHUB_SHA" \
            --build-arg GITHUB_SHA="$GITHUB_SHA" \
            --build-arg GITHUB_REF="$GITHUB_REF" \
            .

      # Push the Docker image to Google Container Registry, maybe need storage admin role?
      - name: Publish
        run: |-
          docker push "gcr.io/$PROJECT_ID/$IMAGE:$GITHUB_SHA"

      # Set up kustomize
      # ...

      # Deploy the Docker image to the GKE cluster
      # ...
```

上面省略了 GKE 相关的一些配置，我们会在下面介绍。可以看到，此时我们用 `$GITHUB_SHA$` 作为我们镜像的 tag，这是因为部署到 Kubernetes 时需要明确指定一个 tag 而不是用默认的 `latest`。

## 配置 GCP

首先安装好 `gcloud`：

```yaml
# Setup gcloud CLI
- uses: google-github-actions/setup-gcloud@v0.2.0
  with:
    service_account_key: ${{secrets.GKE_SA_KEY}}
    project_id: ${{secrets.GKE_PROJECT}}
```

这里的 `GKE_PROJECT` 就是 GKE 所在的项目的 Project ID，`GKE_SA_KEY` 是在 GCP 上执行后续操作的 Service Account 的密钥。这个密钥可以在创建 Service Account 后在 “密钥” 选项卡生成，需要的是 JSON 格式的密钥，且需要进行 Base64 编码后填入 `secrets`。

随后登录 Container Registry：

```yaml
# Configure Docker to use the gcloud command-line tool as a credential
# helper for authentication
- run: |-
    gcloud --quiet auth configure-docker
```

这一步会利用上面的 Service Account 登录 Container Registry。由于后续要上传镜像，涉及到了 `create bucket` 的操作，我们需要在创建 Service Account 时授予 `Storage Admin` 或类似的拥有 `create bucket` 权限的角色（`Storage Admin` 权限很高，这样做并不符合最小特权原则）。除此之外，显然 Service Account 还需要 `Kubernetes Engine Developer` 角色才能在后面管理 K8s 集群。

最后获取 GKE 权限：

```yaml
# Get the GKE credentials so we can deploy to the cluster
- uses: google-github-actions/get-gke-credentials@v0.2.1
  with:
    cluster_name: ${{env.GKE_CLUSTER}}
    location: ${{env.GKE_ZONE}}
    credentials: ${{secrets.GKE_SA_KEY}}
```

随后就是上面看到的 `Build` 和 `Publish` 操作了。

## Customize kustomize

最后一步就是使用 `kustomize` 来搭建 deploy。在打包镜像时有一个很明显的问题，那就是镜像的 tag 在每次 Actions 执行时都是动态的，我们并不清楚其具体值，也无法把他写进 `deployment.yml` 里。因此我们可以先这样写：

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: httpserver
spec:
  replicas: 3
  selector:
    matchLabels:
      app: httpserver
  strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 1
  minReadySeconds: 5
  template:
    metadata:
      labels:
        app: httpserver
    spec:
      containers:
        - name: httpserver
          image: gcr.io/PROJECT_ID/IMAGE:TAG
          ports:
            - containerPort: 8080
          resources:
            requests:
              cpu: 100m
            limits:
              cpu: 100m
---
apiVersion: v1
kind: Service
metadata:
  name: httpserver-service
spec:
  type: LoadBalancer
  ports:
    - port: 80
      targetPort: 8080
  selector:
    app: httpserver
```

可以看到 `image` 部分留了一些像环境变量一样的东西，这就相当于 `kustomize` 的模版字符串，之后 `kustomize` 做的事情其实就类似于一个模版引擎。我们编写 `kustomization.yml` 来让它找到文件的位置：

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - deployment.yml
```

这样，配置文件就写好了，最后再加上 Actions 的步骤：

```yaml
# Set up kustomize
- name: Set up Kustomize
  run: |-
    curl -sfLo kustomize https://github.com/kubernetes-sigs/kustomize/releases/download/v3.1.0/kustomize_3.1.0_linux_amd64
    chmod u+x ./kustomize

# Deploy the Docker image to the GKE cluster
- name: Deploy
  run: |-
    ./kustomize edit set image gcr.io/PROJECT_ID/IMAGE:TAG=gcr.io/$PROJECT_ID/$IMAGE:$GITHUB_SHA
    ./kustomize build . | kubectl apply -f -
    kubectl rollout status deployment/$DEPLOYMENT_NAME
    kubectl get services -o wide
```

大功告成，可以 push 一下看看 Actions 的运行结果了。运行完成之后，也可以在 GKE 上看到对应的信息。
