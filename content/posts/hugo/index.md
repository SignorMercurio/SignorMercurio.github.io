---
title: 乔迁新居：Hugo 博客的配置与部署
date: 2022-03-11T13:10:42Z
lastmod: 2022-06-23
tags:
  - 实践记录
  - CI/CD
categories:
  - 前端
featuredImage: 0.jpg
---

博客从 Hexo 迁移到了 Hugo。在静态网站生成器中，Hugo 的优势主要在于其性能和简单易用的配置。

<!--more-->

## 安装

### 安装 Hugo

直接用包管理器安装，这种方式安装的是 Hugo Extended，可以支持更多功能如自定义 css 等[^1]。

```shell
$ brew install hugo
```

### 创建网站

```shell
$ hugo new site blog.sigmerc
$ cd blog.sigmerc
```

### 安装主题

推荐通过 git 子模块的方式安装，方便后续更新主题与 actions 部署。

我这里使用了 LoveIt 主题[^2]：

```shell
$ git init
$ git submodule add https://github.com/dillonzq/LoveIt.git themes/LoveIt
```

## 配置

所有配置都在 `config.toml` 中，下文记录一些值得注意的点。

### 基础配置

```toml
baseURL = "https://blog.sigmerc.top"
# [en, zh-cn, fr, ...] 设置默认的语言
defaultContentLanguage = "zh-cn"
# 网站语言, 仅在这里 CN 大写
languageCode = "zh-CN"
# 是否包括中日韩文字
hasCJKLanguage = true
# 网站标题
title = "Lab on Mercury"

# 更改使用 Hugo 构建网站时使用的默认主题
theme = "LoveIt"
```

这里需要注意的是设置 `hasCJKLanguage = true`，才能使后续许多功能针对中文正确生效。

### 菜单配置

```toml
[menu]
  [[menu.main]]
    identifier = "posts"
    # 你可以在名称 (允许 HTML 格式) 之前添加其他信息, 例如图标
    pre = "<i class='fas fa-archive fa-fw'></i>"
    # 你可以在名称 (允许 HTML 格式) 之后添加其他信息, 例如图标
    post = ""
    name = "文章"
    url = "/posts/"
    # 当你将鼠标悬停在此菜单链接上时, 将显示的标题
    title = ""
    weight = 1
  [[menu.main]]
    identifier = "tags"
    pre = "<i class='fas fa-tags fa-fw'></i>"
    post = ""
    name = "标签"
    url = "/tags/"
    title = ""
    weight = 2
  [[menu.main]]
    identifier = "categories"
    pre = "<i class='fas fa-th fa-fw'></i>"
    post = ""
    name = "分类"
    url = "/categories/"
    title = ""
    weight = 3
```

这里通过 `pre` 在菜单项前加了图标，注意只能使用 font awesome 免费图标。`weight` 决定了菜单项的顺序，数值越小越靠前。

### 基础参数配置

```toml
[params]
  #  LoveIt 主题版本
  version = "0.2.X"
  # 网站描述
  description = "Lab on Mercury"
  # 网站关键词
  keywords = ["Blog", "Technology"]
  # 网站默认主题样式 ("light", "dark", "auto")
  defaultTheme = "auto"
  # CDN 前缀
  cdnPrefix = "https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn"
```

随后是一系列参数的设置，这里额外设置了 `cdnPrefix`，这样在文章里就可以通过 shortcode 形式插入图片了[^3]。

### 应用图标配置

```toml
  # 应用图标配置
  [params.app]
    # 当添加到 iOS 主屏幕或者 Android 启动器时的标题, 覆盖默认标题
    title = "Lab on Mercury"
    # 是否隐藏网站图标资源链接
    noFavicon = false
    # 更现代的 SVG 网站图标, 可替代旧的 .png 和 .ico 文件
    svgFavicon = ""
    # Android 浏览器主题色
    themeColor = "#ffffff"
    # Safari 图标颜色
    iconColor = "#5bbad5"
    # Windows v8-10磁贴颜色
    tileColor = "#da532c"
```

通过 Favicon Generator[^4] 可以方便地生成各类浏览器上的图标，随后将这些图标以及相应的配置文件放入 `/static` 目录下即可。最后在 `site.webmanifest` 中填一下 `name` 和 `short_name`。

### 搜索配置

```toml
  #  搜索配置
  [params.search]
    enable = true
    # 搜索引擎的类型 ("lunr", "algolia")
    type = "algolia"
    # 文章内容最长索引长度
    contentLength = 4000
    # 搜索框的占位提示语
    placeholder = ""
    #  最大结果数目
    maxResultLength = 10
    #  结果内容片段长度
    snippetLength = 50
    #  搜索结果中高亮部分的 HTML 标签
    highlightTag = "em"
    #  是否在搜索索引中使用基于 baseURL 的绝对路径
    absoluteURL = false
    [params.search.algolia]
      index = ""
      appID = ""
      searchKey = ""
```

尝试了一下通过 `lunr` 搜索，不用配任何东西很方便，但每次搜索都延迟比较高，体验不太好。于是首先注册了 algolia，填入 `index`, `appID`, `searchKey`，随后安装 atomic-algolia[^5] 用于自动将 `index.json` 上传给 algolia：

```shell
$ npm install atomic-algolia
```

在 `package.json` 中定义脚本：

```json
 "scripts": {
   "algolia": "atomic-algolia"
 },
```

在 `.env` 中设置环境变量：

```bash
ALGOLIA_APP_ID=xxxx
ALGOLIA_ADMIN_KEY=xxxx
ALGOLIA_INDEX_NAME=xxxx
ALGOLIA_INDEX_FILE=public/index.json
```

注意这里因为需要上传，所以用的是 admin key，和上面填的 search key 不同。

为了生成 `public/index.json`，在 `config.toml` 的最后 `outputs` 部分需要确保有 `JSON` 这一项。此时运行 `hugo` 命令就可以看到 `public/index.json` 了，最后运行 `algolia` 即可上传。

```toml
# 用于 Hugo 输出文档的设置
[outputs]
  home = ["HTML", "RSS", "JSON"]
  page = ["HTML"]
  section = ["HTML", "RSS"]
  taxonomy = ["HTML", "RSS"]
  taxonomyTerm = ["HTML"]
```

### 头部、底部、页面、社交信息配置

```toml
  # 页面头部导航栏配置
  [params.header]
    # 桌面端导航栏模式 ("fixed", "normal", "auto")
    desktopMode = "fixed"
    # 移动端导航栏模式 ("fixed", "normal", "auto")
    mobileMode = "auto"
    #  页面头部导航栏标题配置
    [params.header.title]
      # LOGO 的 URL
      logo = ""
      # 标题名称
      name = "Lab on Mercury"
      # 你可以在名称 (允许 HTML 格式) 之前添加其他信息, 例如图标
      pre = "<i class='fas fa-meteor fa-fw'></i>"
      # 你可以在名称 (允许 HTML 格式) 之后添加其他信息, 例如图标
      post = ""
      #  是否为标题显示打字机动画
      typeit = false

  # 页面底部信息配置
  [params.footer]
    enable = true
    #  自定义内容 (支持 HTML 格式)
    custom = ''
    #  是否显示 Hugo 和主题信息
    hugo = true
    #  是否显示版权信息
    copyright = true
    #  是否显示作者
    author = true
    # 网站创立年份
    since = 2017
    # ICP 备案信息，仅在中国使用 (支持 HTML 格式)
    icp = ""
    # 许可协议信息 (支持 HTML 格式)
    license = '<a rel="license external nofollow noopener noreffer" href="https://creativecommons.org/licenses/by-nc/4.0/" target="_blank">CC BY-NC 4.0</a>'

  # Section (所有文章) 页面配置
  [params.section]
    # section 页面每页显示文章数量
    paginate = 20

  # List (目录或标签) 页面配置
  [params.list]
    # list 页面每页显示文章数量
    paginate = 20

  # 主页配置
  [params.home]
    #  RSS 文章数目
    rss = 10
    # 主页个人信息
    [params.home.profile]
      enable = true
      # Gravatar 邮箱，用于优先在主页显示的头像
      gravatarEmail = ""
      # 主页显示头像的 URL
      avatarURL = "my_avatar.png"
      #  主页显示的网站标题 (支持 HTML 格式)
      title = "Mercury"
      # 主页显示的网站副标题
      subtitle = "A student"
      # 是否为副标题显示打字机动画
      typeit = false
      # 是否显示社交账号
      social = true
      #  免责声明 (支持 HTML 格式)
      disclaimer = ""
    # 主页文章列表
    [params.home.posts]
      enable = true
      # 主页每页显示文章数量
      paginate = 10
      #  被 params.page 中的 hiddenFromHomePage 替代
      # 当你没有在文章前置参数中设置 "hiddenFromHomePage" 时的默认行为
      defaultHiddenFromHomePage = false

  # 作者的社交信息设置
  [params.social]
    GitHub = "SignorMercurio"
    Email = "signormercurio@gmail.com"
    RSS = true
```

和菜单配置类似，头部标题前也可以通过 `pre` 添加元素。`params.home.profile` 中的 `avatarURL` 我使用了本地资源，存放在 `/assets/my_avatar.png` 中。这里没有放在 `/static` 下是因为切换页码后 URL 会由 `/` 变成 `/page/2`，此时如果图片放在了 `/static` 则会依然尝试去根目录找图片，导致无法找到。

### 文章页面配置

```toml
  #  文章页面配置
  [params.page]
    #  是否在主页隐藏一篇文章
    hiddenFromHomePage = false
    #  是否在搜索结果中隐藏一篇文章
    hiddenFromSearch = false
    #  是否使用 twemoji
    twemoji = false
    # 是否使用 lightgallery
    lightgallery = true
    #  是否使用 ruby 扩展语法
    ruby = false
    #  是否使用 fraction 扩展语法
    fraction = false
    #  是否使用 fontawesome 扩展语法
    fontawesome = false
    # 是否在文章页面显示原始 Markdown 文档链接
    linkToMarkdown = false
    #  是否在 RSS 中显示全文内容
    rssFullText = false
    #  目录配置
    [params.page.toc]
      # 是否使用目录
      enable = true
      #  是否保持使用文章前面的静态目录
      keepStatic = false
      # 是否使侧边目录自动折叠展开
      auto = true
    #  代码配置
    [params.page.code]
      # 是否显示代码块的复制按钮
      copy = true
      # 默认展开显示的代码行数
      maxShownLines = 30
    #  KaTeX 数学公式
    [params.page.math]
      enable = true
      # 默认块定界符是 $$ ... $$ 和 \\[ ... \\]
      blockLeftDelimiter = ""
      blockRightDelimiter = ""
      # 默认行内定界符是 $ ... $ 和 \\( ... \\)
      inlineLeftDelimiter = ""
      inlineRightDelimiter = ""
      # KaTeX 插件 copy_tex
      copyTex = false
      # KaTeX 插件 mhchem
      mhchem = false
    #  评论系统设置
    [params.page.comment]
      enable = true
      # Disqus 评论系统设置
      [params.page.comment.disqus]
        #
        enable = false
        # Disqus 的 shortname，用来在文章中启用 Disqus 评论系统
        shortname = ""
      # Valine 评论系统设置
      [params.page.comment.valine]
        enable = true
        appId = ""
        appKey = ""
        placeholder = ""
        avatar = "mp"
        meta= ""
        pageSize = 10
        lang = ""
        visitor = true
        recordIP = false
        highlight = true
        enableQQ = false
        serverURLs = ""
        #  emoji 数据文件名称, 默认是 "google.yml"
        # ("apple.yml", "google.yml", "facebook.yml", "twitter.yml")
        # 位于 "themes/LoveIt/assets/data/emoji/" 目录
        # 可以在你的项目下相同路径存放你自己的数据文件:
        # "assets/data/emoji/"
        emoji = ""
    #  第三方库配置
    [params.page.library]
      [params.page.library.css]
        # someCSS = "some.css"
        # 位于 "assets/"
        # 或者
        # someCSS = "https://cdn.example.com/some.css"
      [params.page.library.js]
        # someJavascript = "some.js"
        # 位于 "assets/"
        # 或者
        # someJavascript = "https://cdn.example.com/some.js"
    #  页面 SEO 配置
    [params.page.seo]
      # 图片 URL
      images = []
      # 出版者信息
      [params.page.seo.publisher]
        name = "Mercury"
        logoUrl = "my_avatar.png"
```

这个部分的配置都可以被文章里的 front matter 覆盖，所以这里设置的是默认值。因此关闭了大部分不必要功能，只保留了 lightgallery 即点击放大图片的功能、代码复制功能、基础的公式渲染功能和评论系统默认开启。目录的 `keepStatic` 如果开启则会显示在文章上方而不是侧边栏，我觉得不太方便就关闭了。评论采用了 LeanCloud + Valine，需要填 appId 和 appKey。

### 其他配置

```toml
# Hugo 解析文档的配置
[markup]
  # 语法高亮设置
  [markup.highlight]
    codeFences = true
    guessSyntax = true
    lineNos = true
    lineNumbersInTable = true
    # false 是必要的设置
    # (https://github.com/dillonzq/LoveIt/issues/158)
    noClasses = false
  # Goldmark 是 Hugo 0.60 以来的默认 Markdown 解析库
  [markup.goldmark]
    [markup.goldmark.extensions]
      definitionList = true
      footnote = true
      linkify = true
      strikethrough = true
      table = true
      taskList = true
      typographer = true
    [markup.goldmark.renderer]
      # 是否在文档中直接使用 HTML 标签
      unsafe = true
  # 目录设置
  [markup.tableOfContents]
    startLevel = 2
    endLevel = 5

# 作者配置
[author]
  name = "Mercury"
  email = ""
  link = ""

# 网站地图配置
[sitemap]
  changefreq = "weekly"
  filename = "sitemap.xml"
  priority = 0.5

# Permalinks 配置
[Permalinks]
  posts = ":filename"
```

根据个人习惯配置，比较重要的是 `markup.goldmark.renderer` 里的 `unsafe` 选项，开启后可以比较方便地混排 Markdown 和 HTML。`markup.tableOfContents` 中，`2-5` 的配置意味着一级标题、五级标题和六级标题不会在目录中显示。`Permalinks` 的 `posts` 则直接决定了一篇文章的永久链接格式。

## 文章迁移

总的来说区别不太大，主要是 front matter 中：

- `tag` 变成 `tags`
- `cover` 和 `thumbnails` 变成 `featuredImage` 和 `featuredImagePreview`
- 摘要分隔符从 `<!-- more -->` 变成 `<!--more-->`

一个简单的模版：

```markdown
---
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
tags:
  - t
categories:
  - c
---

a

<!--more-->

p

## 参考资料

[^1]: r
```

如果文中含公式，则在 front matter 中加一行 `math: true` 即可。

## 预览

在本地 1313 端口打开测试服务器：

```shell
$ hugo server
```

默认为 development 模式，评论、CDN、fingerprint 都被关闭，可以手动指定 production 模式：

```shell
$ hugo server -e production
```

## 公式渲染

KaTeX[^6] 虽然比 mathjax 好点，但在 Markdown 中依然面临着渲染问题，例如多行公式中换行时需要 `\\\\ `（末尾有空格） 而不是 `\\` 等[^7]。一个更简洁的办法是用 `\cr` 换行。同理在输入转义字符时也需要对 `\` 进行二次转义[^8]。

## Mermaid 图表渲染

采用了主题提供的扩展 shortcode：

```markdown
{{</* mermaid */>}}
...
{{</* /mermaid */>}}
```

## 自定义样式

### 添加数量统计

通过 Hugo 统计了文章数量、标签数量、分类数量等信息并通过 `<sup>` 标签展示[^9]。需要修改的文件有：

- `/layouts/taxonomy/list.html`
- `/layouts/taxonomy/terms.html`
- `/layouts/_default/section.html`

从主题目录中复制这些文件到根目录，随后在想要添加上标的地方插入 `<sup>{{ len .Pages }}</sup>` 即可。这里利用了 Hugo 中根目录下文件渲染优先级高于主题目录下同名文件的机制，便于维护。同理，也可以新建 `/assets/css/_custom.scss` 来自定义样式（需要 Hugo Extended）。

### 补充代码类型

原主题虽然能正确高亮汇编和 Dockerfile 代码，但并不会在代码类型上正确显示对应的类型。对此，我们可以新建 `/assets/css/_override.scss` 覆盖 `code-type-map` 变量：

```scss
// Code type map
$code-type-map: (
  // Custom code type
  language-asm: "Assembly",
  language-bash: "Bash",
  language-c: "C",
  language-cs: "C#",
  language-cpp: "C++",
  language-clojure: "Clojure",
  language-coffeescript: "CoffeeScript",
  language-css: "CSS",
  language-dart: "Dart",
  language-diff: "Diff",
  language-dockerfile: "Dockerfile",
  language-erlang: "Erlang",
  language-go: "Go",
  language-go-html-template: "Go HTML Template",
  language-groovy: "Groovy",
  language-haskell: "Haskell",
  language-html: "HTML",
  language-http: "HTTP",
  language-xml: "XML",
  language-java: "Java",
  language-js: "JavaScript",
  language-javascript: "JavaScript",
  language-json: "JSON",
  language-kotlin: "Kotlin",
  language-latex: "LaTeX",
  language-less: "Less",
  language-lisp: "Lisp",
  language-lua: "Lua",
  language-makefile: "Makefile",
  language-markdown: "Markdown",
  language-matlab: "Matlab",
  language-objectivec: "Objective-C",
  language-php: "PHP",
  language-perl: "Perl",
  language-python: "Python",
  language-r: "R",
  language-ruby: "Ruby",
  language-rust: "Rust",
  language-scala: "Scala",
  language-scss: "Scss",
  language-shell: "Shell",
  language-sql: "SQL",
  language-swift: "Swift",
  language-tex: "TeX",
  language-toml: "TOML",
  language-ts: "TypeScript",
  language-typescript: "TypeScript",
  language-vue: "Vue",
  language-yml: "YAML",
  language-yaml: "YAML"
);
```

注意将最后原有的 `!default` 去掉，否则无法覆盖默认值。

### 修改代码字体

在 `/assets/css/_override.scss` 中添加：

```scss
// Font family of the code
$code-font-family: JuliaMono, Monaco, Fira Code, Jetbrains Mono, Hack, Noto Mono,
  Menlo, Droid Sans Mono, DejaVu Sans Mono, Consolas, monospace, $global-font-family;
```

### 图片圆角化

在 `/assets/css/_custom.scss` 中添加：

```scss
img {
  border-radius: 0.5rem;
}
```

### 图片无法使用 lightgallery 浏览 bug

参考了别人的做法[^10]，在 `layouts/_default/_markup/render-image.html` 中添加：

```html
{{ $figcap := or .Title .Text }} {{ $caption := or .Text " " }} {{- if eq
$figcap $caption -}} {{ $caption = " " }} {{- end -}} {{- if $figcap -}}
<figure>
  {{- dict "Src" .Destination "Title" $figcap "Caption" $caption "Linked" true
  "Resources" .Page.Resources | partial "plugin/img.html" -}}
  <figcaption class="image-caption">{{- $figcap | safeHTML -}}</figcaption>
</figure>
{{- else -}} {{- dict "Src" .Destination "Title" (path.Base .Destination)
"Resources" .Page.Resources | partial "plugin/img.html" -}} {{- end -}}
```

## 自动化部署到 GitHub Pages

编写 `.github/workflows/gh-pages.yml`：

```yaml
name: github pages

on:
  push:
    branches:
      - main
  pull_request:

jobs:
  deploy:
    runs-on: ubuntu-20.04
    steps:
      - uses: actions/checkout@v2
        with:
          submodules: true # Fetch Hugo themes (true OR recursive)
          fetch-depth: 0 # Fetch all history for .GitInfo and .Lastmod

      - name: Setup Hugo
        uses: peaceiris/actions-hugo@v2
        with:
          hugo-version: "latest"
          extended: true

      - name: Build
        run: hugo --minify

      - name: Deploy
        uses: peaceiris/actions-gh-pages@v3
        if: github.ref == 'refs/heads/main'
        with:
          github_token: ${{ secrets.TOKEN }}
          publish_dir: ./public
```

然后在 `/static` 创建 `CNAME` 文件，内容是自己的自定义域名，使得生成的 `public` 根目录下就包含这个 `CNAME`。最后确保 push 到 `main` 分支，actions 运行成功后会在 `gh-pages` 分支生成网站静态资源，在 GitHub Pages 里设置部署 `gh-pages` 的 `/` 目录即可。

## 参考资料

[^1]: [Hugo 文档](https://gohugo.io/documentation/)
[^2]: [LoveIt 主题文档](https://hugoloveit.com/zh-cn/posts/)
[^3]: [Hugo 系列(3.0) - LoveIt 主题美化与博客功能增强 · 第一章](https://lewky.cn/posts/hugo-3.html)
[^4]: [Favicon Generator](https://realfavicongenerator.net/)
[^5]: [atomic-algolia](https://github.com/chrisdmacrae/atomic-algolia)
[^6]: [Supported Functions - KaTeX](https://katex.org/docs/supported.html)
[^7]: [Hugo/Katex failed to render multi-line Latex](https://github.com/dillonzq/LoveIt/issues/402)
[^8]: [常用数学公式排版 KaTex 语法总结](https://kissingfire123.github.io/2022/02/18_%E6%95%B0%E5%AD%A6%E5%85%AC%E5%BC%8Fkatex%E5%B8%B8%E7%94%A8%E8%AF%AD%E6%B3%95%E6%80%BB%E7%BB%93/)
[^9]: [Hugo 系列(3.2) - LoveIt 主题美化与博客功能增强 · 第三章](https://lewky.cn/posts/hugo-3.2.html/)
[^10]: [Hugo 系列(4) - 从 Hexo 迁移至 Hugo 以及使用 LoveIt 主题的踩坑记录](https://lewky.cn/posts/hugo-4.html/)
