---
title: 信手拈来：Joplin 使用小记
date: 2021-07-17 21:00:31
tags:
  - 实践记录
categories:
  - 探索
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/Joplin/0.png
---

折腾笔记软件。

<!--more-->

## 背景

说是要找一款笔记软件，实际上我最主要的需求还是剪藏网页离线浏览、全文搜索、本地和云端同步这些功能，因为自己写的笔记主要靠 Typora + Hexo + ghPages 放在这个博客里。由于不是特别刚需，就没有什么付费的意愿。在 Big Sur 11.4 M1 上经过了一番折腾，发现以下软件都不能很好的契合需求：

- **印象笔记**：剪藏功能非常好用，效果也是能找到的工具中最佳的，然而有时候排版效果不怎么样；免费版每月 60M 上传限制有点少；最让人不能忍受的则是其 bug 频出的桌面客户端。
- **有道云笔记**：剪藏效果不佳，整体使用体验也一般。
- **为知笔记 / Baklib** 等：没有长期可用的免费版。
- **OneNote**：对我来说笔记自由度有点太高了；同步速度问题比较大。
- **Notion**：同类天花板，不过学习成本有点高，相当多的强大功能对我而言也不太必要；同样面临剪藏效果和同步速度的尴尬问题。
- **wolai**：Notion 本地化的版本，没有同步速度的问题，其他问题依然存在，且 bug 不少。依赖 [web-clipper](https://github.com/webclipper/web-clipper)，虽然很多人都说好用，但是这个适配了很多笔记软件的工具的剪藏效果对我来说依然不够好。
- **Bear**：依赖 web-clipper；非会员无法导出 PDF。目前对 Typora 很满意，以后可能会入手会员。
- **语雀**：依赖 web-clipper；和石墨文档很像，感觉更适合团队用来写共享的技术文档，对个人来说有点太重了。
- **蚂蚁笔记**：开源，依赖 web-clipper；界面、功能都相当简陋，bug 较多。
- **专注笔记**：依赖 web-clipper；功能比较少。
- **Cubox**：免费版 200 条剪藏有点不够用。
- **Obisidian / Roam Research** 等：功能很强大但似乎确实用不上。
- **Flomo / Google Keep / Pocket / Instapaper / Pinbox / 方片**等：感觉产品定位不太符合自己的需求。

最后选择了开源的 Joplin，相比同样开源的蚂蚁笔记，使用体验明显要好很多。最重要的是，其剪藏效果我认为是仅次于、甚至部分情况下优于印象笔记剪藏的。

## 基础配置

[官网](https://joplinapp.org/) 下载后，可以进行一些简单配置：

- **通用选项**：修改语言、日期格式和使用的外部 Markdown 编辑器，这里可以直接用 `/Applications/Typora.app`。
- **同步**：修改云同步的选项。
- **外观**：修改主题、字体大小和自定义 css。我不怎么用 Dracula 配色，不过这个软件里的 Dracula 还算挺好看的。后文会阐述如何通过配置自定义 css 实现侧边栏目录的功能。
- **笔记**：可以选择不把地理位置信息保存到笔记中。
- **插件**：可以搜索安装插件，当然也能自己开发一个装上去，这是开源软件的最大优势了。
- **Markdown**：可以开关各种 Markdown 的功能，这里可以发现 Joplin 相比部分同类产品在 Markdown 支持上的优势。
- **笔记历史**：修改笔记历史的保留期限，直接影响 Joplin 记录的笔记占用的磁盘空间大小。
- **加密**：这个部分建议参考 [官方文档](https://joplinapp.org/e2ee/)，否则可能在解密时遇到问题。
- **网页剪辑器**：在客户端启用网页剪辑服务，随后在 Chrome 应用商店可以下载安装 [Joplin Web Clipper](https://chrome.google.com/webstore/detail/joplin-web-clipper/alofnhikmmkdbbbgpnglcpdollgjjfek)，首次启动该插件需要回到 Joplin 客户端授予权限；如果使用类似 web-clipper 的第三方剪藏工具，则可以复制该页下方的授权令牌。

## 侧边栏目录

Joplin 默认没有这个功能，但是支持 Markdown 的目录扩展，所以在笔记任意位置插入 `[toc]` 即可生成目录。为了让这个目录悬浮到右边，参考 [官方论坛上的一个回答](https://discourse.joplinapp.org/t/incomplete-toc-sidebar/10458/3) 简单写个 css（这里的背景色是根据 Dracula 主题设置的，可自行修改）：

```css
/* For styling the rendered Markdown */
:root {
  /*TOCsidebar 的相关变量 , Toc SideBar variables definition */
  --tocsidebar-fontsize: 16px;  /*TocSideBar 的字体大小，TocSideBar's fontsize*/
  --tocsidebar-bg: #313640;  /*TocSideBar 的面板背景色 , TocSideBar's panel color*/

  --tocsiderbar-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.2);   /*TocSideBar 的阴影设置 , TocSideBar's shadow */
  --tocsiderbar-radius:10px;        /*TocSideBar 的圆角度 , TocSideBar's radius */


  --tocsiderbar-leftline: 1px solid rgba(255, 255, 255, 0.5);  /*TocSideBar 左边竖线线颜色和不透明度，0 为全透明，1 为不透明, TocSideBar's left line for Classification befor link*/

  --tocsidebar-linkcolor: #FFFFFF;    /*TocSideBar 链接颜色 , link color*/
  --tocsidebar-linkcolor-opacity: 0.8;   /*TocSideBar 链接颜色的不透明度, link color's opacity */

  --tocsidebar-linkhovercolor: #E71B64;  /*TocSideBar 链接悬停时的颜色 #E71B64 - 玫红色, link color when cursor hovering */
  --tocsidebar-linkhovercoloropacity: 1; /*TocSideBar 链接悬停时的颜色的不透明度,  link color's opacity  when cursor hovering */
}

/**************************************************************************************************
 *  TABLE OF CONTENTS
 *  Based on the idea from here:
 *  -https://discourse.joplinapp.org/t/toc-as-the-sidebar/5979/8
 *  -https://discourse.joplinapp.org/t/toc-as-the-sidebar/5979/34
 *  -https://discourse.joplinapp.org/t/share-your-css/1730/192
 *************************************************************************************************/

nav.table-of-contents > ul {
  /*面板固定在右上角,  fix Toc panel on the right of the window , this panel is used for activing toc sidebar */
  position: fixed;
  top: 0;
  right: 6px;
  z-index: 10;

  font-size: var(--tocsidebar-fontsize);  /*目录字体大小，可设置为 16PX 或 small,16px 比较合适， toc sidebar's fontsize, 16px is  better for our eyes*/
  height: 85%;
  padding: 5px;
  overflow: hidden;

  min-width: 20px;   /* 右侧面板宽度, 也可用 width: 20px; 设置在鼠标到达右侧 20px 范围内时激活 TocSideBar, 20px means the Toc sidebar will be active when cursor within 20px on the right side of the window */
  background: none;  /* 面板无背景色填充 */
}

nav.table-of-contents ul {
  /*所有目录 li 的父框 ul 设置，即所有目录父框的设置*/
  list-style-type: none;
  margin-bottom: 0;
  margin-left: 8px;  /*分类距离 tocsidebar 边缘，8px*/
  margin-top: 0;
}

nav.table-of-contents > ul:hover {
  /*TocSideBar 弹出时，背景底框的设置 所以用 > 只选择一级目录 li 的父框 ul ，填充背景色和阴影以显示 TocSideBar*/
  background-color: var(--tocsidebar-bg);
  border-radius: var(--tocsiderbar-radius);
  box-shadow: var(--tocsiderbar-shadow);
  overflow: scroll;
  width: auto;  /*根据内容自动调整宽度 , 但会导致字体加粗显示时跳动, Automatically adjust width according to content */
}

nav.table-of-contents > ul:hover li {
  display: list-item;
  min-width: 120px;    /*Toc SideBar 最小宽度，Toc SideBar 's minimum width*/
}

nav.table-of-contents li {
  display: none;
  line-height: 1.8em;
  margin-bottom: 0;
  white-space: nowrap;
}

nav.table-of-contents > ul > li > ul li {
/*设置目录前的分类线，也可以这样 (空格表示所有子孙代 li) 写 nav.table-of-contents ul li ul li */
  border-left: var(--tocsiderbar-leftline); !important;
}

nav.table-of-contents li a {
  color: var(--tocsidebar-linkcolor);
  opacity: var(--tocsidebar-linkcolor-opacity);
  padding: 5px;
}

nav.table-of-contents a {
  /*去掉下划线, remove  link's underline */
  text-decoration: none !important;
}

nav.table-of-contents li a:hover {
    /*悬停时，改变字体样式，change font style when cursor hovering*/
   color:  var(--tocsidebar-linkhovercolor);  /*link color when cursor hovering */
   opacity: var(--tocsidebar-linkhovercoloropacity);
}
```

保存到 `~/.config/joplin-desktop/userstyle.css` 并重启客户端即可。

## 修改 Markdown 展示字体大小

在配置里可以直接修改 Markdown 编辑时的字体大小，而展示时的字体大小则需要修改之前提到的 `userstyle.css`：

```css
body,
th,
td,
.inline-code {
  font-size: 18px;
}
```

## 配合简悦使用

[简悦](https://chrome.google.com/webstore/detail/simpread-reader-view/ijllcpnolfcooahcekpamkbidhejabll) 也提供了 Chrome 插件，主要是提供纯净阅读视图的。虽然的确是很优秀的软件，也能做到开箱即用，但是过多的配置项总会让人感到有些无所适从（即使是在简洁模式下）。

在剪藏微信公众号文章时无意中发现，Joplin 的剪藏工具对其中图片的处理有些问题（老封闭平台了），而经过简悦处理后再用 Joplin 剪藏则效果完美，因此将 `mp.weixin.qq.com` 加入到了简悦白名单里，反正本来读公众号文章也要开阅读模式的。

此外，简悦也支持绑定 Joplin 并在阅读模式下直接 “保存到 Joplin”，然而我并不推荐这样做。简悦对不少非中文网站以及小众站点的支持相当有限，阅读模式也经常会出现一些格式错误，和 web-clipper 剪藏效果是类似的。因此，还是使用 Joplin Web Clipper 做剪藏能保证最佳的效果。

## 清理无用图片

剪藏网页时，剪藏图片是非常重要的，但文章中间或者末尾总会出现我们不怎么需要的图片。由于 Joplin 缓存历史的机制，在笔记中删除了这些图片后不会在本地立即清理掉这些无用的图片。因此找到了一款工具 [jnrmor](https://github.com/tessus/joplin-scripts) 来辅助实现该功能，不太清楚 Joplin 的官方 CLI 或者 API 能不能实现。

下载 jnrmor 脚本后，首先安装新的 `get-opt`：

```shell
$ brew install gnu-getopt
```

随后将新的 `get-opt` 添加到环境变量，避免使用自带的 `get-opt`。在 `.zshrc` 或 `.bashrc` 末尾写入：

```bash
export PATH="/opt/homebrew/opt/gnu-getopt/bin:$PATH"
```

接下来编辑配置文件 `.jnrmor.conf`：

```bash
# Joplin profile directory (where the database is located)
JOPLIN_DIR=~/.config/joplin-desktop

# TOKEN for Joplin Web Clipper (can be found in'Web clipper options')
CLIPPER_TOKEN=xxxxxxxx

# Web Clipper Port (can be found in'Web clipper options')
CLIPPER_PORT=41184
```

注意将 `xxxxxxxx` 替换为自己的授权令牌。最后运行 `./jnrmor` 即可。

## 自建 Joplin Server 进行云同步

参考 [官方文档](https://github.com/laurent22/joplin/tree/dev/packages/server) 和 [这篇文章](https://zhuanlan.zhihu.com/p/352413230)，既可以用其内置 SQLite 的 docker 来测试，又可以用 docker-compose 同时启动 PostgreSQL 和 Joplin Server。

`.env` 文件：

```bash
APP_BASE_URL=http://ip:port # modify ip and port
APP_PORT=22300
```

随后运行：

```shell
$ docker volume create joplin
$ docker run -d --name joplin_server -v joplin:/home/joplin --env-file ~/joplin/.env -p port:22300 joplin/server:2.2.7-beta # modify port
```

注意使用 `latest` 镜像可能导致出现 `Not allowed: PUT` 的问题，需要使用最新的 `beta` 镜像确保升级到 v2，参考 [官方论坛](https://discourse.joplinapp.org/t/not-allowed-put/18166/2)。

登录 Joplin Server 后修改邮箱和密码，将相同配置填入客户端的**同步**选项中即可。

## Joplin 缺点

- 英文标签只能使用小写字母（如果这也算缺点的话）
- 云同步接口不多
- 剪藏墙外文章速度会有点慢，还没研究过怎么给它配代理
- UI 可以更好看