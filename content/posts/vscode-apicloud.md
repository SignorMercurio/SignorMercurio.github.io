---
title: VSCode + APICloud + GitHub 开发环境配置
date: 2019-01-17 14:22:32
tags:
  - VSCode
categories:
  - 前端
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/VSCodeAPICloud/0.jpg
---

不是很懂为什么 APICloud 没有官方的 VSCode 插件。

<!--more-->

在 APICloud 上进行开发时，有很多代码编辑器可以选择：APICloud Studio, Sublime Text, Atom, Eclipse 等等，对于这些工具，APICloud 都提供了官方的插件以方便开发与调试。然而，我最喜欢的编辑器 VSCode 却没有这样的待遇。好在 [这里](https://community.apicloud.com/bbs/thread-48763-1-1.html) 提供了这样的插件，尽管它有诸多瑕疵。

## 插件配置

按上述链接装好插件后，在 APICloud 云端创建一个 app，就能得到一个 ID，这个 ID 在部署 GitHub 时会用到。

在本地新建一个项目的目录，用 VSCode 的**文件 -> 打开文件夹**命令打开这个目录。如果没有这一步，在后面新建项目时就会出错。

随后就可以 `Ctrl+Shift+P` 并输入 `apicloud`，选择相应的命令了。例如可以新建一个项目模板，随后在目录下会出现一个新的目录 `HelloAPICloud`，包含了项目模板的所有文件。

## Wifi 真机调试

在进行真机调试前，首先需要做一些配置。这个插件最大的瑕疵就在这里。

**文件 -> 首选项 -> 设置 -> 扩展 ->APICloud** 中就能进行配置，首先是端口号，默认是 23456，可以不用改；后两个选项随意，最大的坑点在最后，一张图就能说明了：

![图 1]({{< param cdnPrefix >}}/VSCodeAPICloud/1.jpg)

因为我们后面要部署到 GitHub，所以我先**把所有文件转移到了新建的 widget 目录**，并删除了原来的 HelloAPICloud 目录。随后，当我在这一栏输入 `/widget` 并启动 wifi 全量更新时，控制台却提醒我当前目录不是一个有效的 APICloud 项目。这里显示的当前目录，并不是 widget 目录，而是它的上一级，也就是项目目录。

这就是说，我添加的这个路径没有被正确识别。为什么呢？看上图就明白了，Windows 下是使用 `\` 而不是 `/` 来表示目录的（后者是 Linux 的习惯），而在这一字段的提示中，却分明写着：

> 放到根目录的 '/widget' 里

……

如上图一般配置后，先在右键菜单中启动 Wifi 服务。在此之前，手机上应已装好 AppLoader，并配置好端口号和 IP 地址。其中，端口号来自刚才的配置，默认是 23456；IP 地址的话在启动 Wifi 服务后的控制台里就可以看到。如果有多个 IP 地址，填以 `192.168` 开头的那个地址（或其它内网地址）。

这样以后再进行 Wifi 全量更新或 Wifi 增量更新，手机上闪过一段进度条后，就可以看到 app 的界面了。

关于这个插件的其它功能我还在研究中。

## GitHub 部署

新建个 repo。在本地的项目根目录下（和 widget 所在目录同目录）`git init` 并关联到远程仓库，随后和常规 GitHub 仓库的操作一样了。

但是，我们还需要在 `widget/config.xml` 里，修改第二行的 `widget` 的 `id` 属性，改为刚才我们获得的 app 的 ID。并且，在 app 页面 “端开发” 的“代码”选项里，更改代码位置为 “Git 平台”，填入代码地址、用户名和密码并保存，最后打开“启用 Git 平台” 开关。这样，每次我们推送最新代码后就可以在 APICloud 上云编译了，尽管 APICloud 上无法看到你的最新推送。

> 希望这篇文章不要最后也变成 “踩坑记”。
