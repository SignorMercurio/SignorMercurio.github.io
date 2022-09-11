---
title: 又见 LAMP：用 Flarum 搭建功能强大的在线论坛
date: 2022-03-13T18:28:09Z
tags:
  - PHP
  - 实践记录
categories:
  - 探索
featuredImage: 0.png
---

完全出于巧合和心血来潮搭建的一个论坛。

<!--more-->

## 准备 LAMP 环境

### 安装 PHP 7.4

```shell
$ sudo apt update
$ sudo apt install php-fpm php-mbstring php-curl php-dom php-gd php-json php-mysql php-zip php-tokenizer
```

### 安装 Composer

> 更新：目前部署到了香港服务器上，可直接运行 
>
> ```shell
> $ curl -sS https://getcomposer.org/installer | php

因为要部署在国内服务器上，可以使用国内的安装脚本镜像[^1]：

```shell
$ php -r "copy('https://install.phpcomposer.com/installer', 'composer-setup.php');"
$ php composer-setup.php
$ php -r "unlink('composer-setup.php');"
```

然后移动到环境变量包含的路径下：

```shell
$ sudo mv composer.phar /usr/local/bin/composer
```

最后换源：

```shell
$ composer config -g repo.packagist composer https://mirrors.aliyun.com/composer/
```

### 安装 MariaDB 10.5.12

```shell
$ sudo apt install mariadb-server
```

### 创建需要的用户和数据库[^2]

```shell
$ mysql -uroot -p
```

数据库名、用户名和密码任意，注意使用兼容性更好的 `utf8mb4` 字符集。

```sql
create database flarum character set utf8mb4 collate utf8mb4_unicode_ci;
create user 'flarum'@'localhost' identified by '[your password]';
grant all privileges on flarum.* to 'flarum'@'localhost';
```

### 安装 Apache2

```shell
$ sudo apt install apache2
```

### 开启 PHP 解析和 `mod_rewrite`[^3]

```shell
$ sudo apt install libapache2-mod-php
$ sudo a2enmod php7.4
$ sudo a2enmod rewrite
```

## 安装 Flarum

> 版本： 1.2.1

```shell
$ composer create-project flarum/flarum .
```

假设创建的项目目录为 `/path/to/flarum`。

### 允许 URL 重写

编辑 Apache 配置文件，例如 `/etc/apache2/apache2.conf`，添加：

```
<Directory "/path/to/flarum/public">
    AllowOverride All
</Directory>
```

从而允许 Flarum 覆盖 `.htaccess` 文件。

### 设置网站根目录

随后编辑 `/etc/apache2/sites-enabled/000-default.conf`，设置 `ServerName` 为域名，`DocumentRoot` 为 `/path/to/flarum/public`。

### 调整目录权限

```shell
$ chmod 755 -R /path/to/flarum/public
$ chmod 755 -R /path/to/flarum/storage
$ chmod 755 -R /path/to/flarum/vendor
$ chown -R www-data:www-data /path/to/flarum
```

最后重启 Apache2：

```shell
$ sudo systemctl restart apache2
```

## 配置 Flarum

初始化时需要用到前面的数据用户名、密码等。

### 自定义域名

将域名指向 Flarum 地址，然后修改 `/path/to/flarum/config.php`，设置 `url` 字段。错误设置会导致请求被 CORS 拦截。

### 中文语言包[^4]

在 `/path/to/flarum` 下运行：

```shell
$ composer require flarum-lang/chinese-simplified
$ php flarum cache:clear
```

### 验证邮件

> 更新：目前已采用阿里邮件推送服务，通过 SMTP 发信。配置方法也是类似的。

这里选择通过 mailgun 发送验证邮件，首先需要安装插件：

```shell
$ composer require guzzlehttp/guzzle:^7.0
```

然后注册 mailgun，注意使用 custom domain 而不是 sandbox domain，后者只能发送给白名单中的邮件地址。之后按照 mailgun 的指导配置一堆 DNS 解析记录，最后把相应配置填入 Flarum 即可。

### 图片上传

> 更新：目前已采用腾讯云 COS 作为图床[^6]，基于 AWS S3 协议，因此需要插件 `league/flysystem-aws-s3-v3`。

imgur 和 Amazon S3 在国内都较难访问，因此采用七牛云存储图片。先安装插件，其中后者是七牛云存储需要的插件[^5]：

```shell
$ composer require fof/upload
$ composer require overtrue/flysystem-qiniu:^1.0
```

随后配置允许的 MIME 类型的正则，例如只允许图片：`^image\/.*`。在“存储设置”中填写七牛的 CDN 地址，然后在“七牛存储设置”中填写 AK、SK 和空间名。

## 站点数据迁移

插件直接 composer 重装即可，数据方面主要包括两者：

- 数据库数据
- 静态资源
  - 用户自定义头像
  - 网站 logo 和图标

### 迁移数据库

旧站上运行：

```shell
$ mysqldump -uroot -pxxxx flarum > backup.sql
```

将 `backup.sql` 传到新站，在新站 MySQL 中运行：

```sql
mysql> use flarum;
mysql> source backup.sql;
```

### 迁移静态资源

将旧站的 `/path/to/flarum/public/assets/avatars` 以及 `/path/to/flarum/public/assets/*.png` 传到新站即可。务必注意迁移前后的文件权限问题。

如果在不同版本迁移，那么最好是迁移整个 `assets` 目录。

## 开启 HTTPS

编写 `conf-enabled/ssl-params.conf`：

```
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLHonorCipherOrder on

Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff

SSLCompression off

SSLUseStapling on
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"

SSLSessionTickets Off
```

修改 `sites-enabled/000-default.conf`，开启 443 监听并重定向 HTTP 至 HTTPS[^7]：

```
<VirtualHost *:80>
    RewriteEngine on
    RewriteCond %{HTTPS} !=on
    RewriteRule ^/?(.*) https://%{SERVER_NAME}$1 [R=301,L]
</VirtualHost>

<IfModule mod_ssl.c>
    <VirtualHost *:443>
        ServerName [your domain]
        ServerAdmin webmaster@localhost
        DocumentRoot /path/to/flarum/public

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        SSLEngine on

        SSLCertificateFile    /path/to/[your domain].crt
        SSLCertificateKeyFile /path/to/[your domain].key
        SSLCertificateChainFile /path/to/[your domain]_chain.crt

        <FilesMatch "\.(cgi|shtml|phtml|php)$">
                SSLOptions +StdEnvVars
        </FilesMatch>
        <Directory /usr/lib/cgi-bin>
                SSLOptions +StdEnvVars
        </Directory>
    </VirtualHost>
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

注意替换对应的域名和路径。最后打开 `ssl` 和 `headers` 模块即可。

```shell
$ sudo a2enmod ssl
$ sudo a2enmod headers
$ sudo systemctl restart apache2
```

## 实用插件记录

来自 Extiverse[^8]，插件下的二级列表记录了已知的 bug 和论坛自用的一些 tweaks：

- 移动端底部导航 `acpl/mobile-tab`
  - iOS 微信浏览器底部 Safe Area 显示异常

- 论坛统计小部件 `afrux/forum-stats-widget`
- 论坛公告小部件 `afrux/news-widget`
  - tweak：取消了闪烁动画

- 论坛自动管理 `askvortsov/flarum-auto-moderator`
  - 条件满足时，有时不会触发动作

- 支持插入表格 `askvortsov/flarum-markdown-tables`
- 站务警告 `askvortsov/flarum-moderator-warnings`
- 所见即所得的富文本编辑器 `askvortsov/flarum-rich-text`
- 用户组头像框 `clarkwinkelmann/flarum-ext-circle-groups`
- Emoji 选择框 `clarkwinkelmann/flarum-ext-emojionearea`
- 个人资料卡展示被点赞次数 `clarkwinkelmann/flarum-ext-likes-received`
- 链接预览 `datlechin/flarum-link-preview`
  - B 站某些链接在预览时无法加载预览图，因为 Safari 默认不自动升级 HTTP 请求为 HTTPS
  - 会尝试预览邮件，产生错误导致后续 js 无法运行
  - 会尝试加载非网页链接，例如大文件链接
  - 无法预览的网址也无法打开
  - 对预览内容没有字数限制，容易占用过大空间

- 图片 Fancybox `darkle/fancybox`
  - 戳表情会触发 fancybox

- 楼主标识 `dem13n/topic-starter-label`
  - 没有 i18n
  - 进入主题后一楼不显示楼主标识，但刷新后显示
  - 一楼被删除后二楼变成了楼主

- 炫酷的后台管理面板 `ecnu-im/asirem-admin`
- 固定可滚动的标签导航 `ecnu-im/sticky-sidenav`
- 基于 Extiverse 的插件版本管理 `extiverse/mercury`
- 简体中文语言包 `flarum-lang/chinese-simplified`
- FoF 系列 `fof/`
  - 私密主题 `byobu`
  - 草稿 `drafts`
  - 关注标签 `follow-tags`
  - 链接自动转图片 `formatting`
  - 导航栏链接 `links`
  - 扩展个人资料字段 `masquerade`
  - 合并主题 `merge-discussions`
  - 日间/夜间模式切换 `nightmode`
    - 注意调整论坛 Logo 适配夜间模式
  - 自定义页面 `pages`
    - 直接写 Markdown 行距过大
  - 发起投票 `polls`
    - “暂无投票”字体颜色未适配夜间模式
  - 戳表情 `reactions`
  - 注册验证码 `recaptcha`
    - 不支持 recaptcha v3
  - 注册时勾选同意服务条款 `terms`
  - 文件上传 `upload`
  - 个性签名 `user-bio`
- 邮件发送 `guzzlehttp/guzzle`
- 自定义 HTML `<head>` 标签 `ianm/html-head`
- 信息流显示主题摘要 `ianm/synopsis`
  - tweak：增加摘要字体颜色对比度

- 登录可见 `jslirola/flarum-ext-login2seeplus`
- 热门主题 `justoverclock/hot-discussions`
  - 在移动端也会显示

- 设置 OpenGraph `<meta>` 标签 `justoverclock/og-meta-tag`
- AWS S3 协议支持 `league/flysystem-aws-s3-v3`
- 图片布局 `malago/flarum-ext-fancybox`
- 主题浏览次数统计 `michaelbelgium/flarum-discussion-views`
  - 移动端浏览次数未适配夜间模式

- 禁止给自己点赞 `nearata/flarum-ext-no-self-likes`
- 注册时确认密码 `nearata/flarum-ext-signup-confirm-password`
- 自动加载更多 `noriods/auto-more`
- 邮件黑白名单过滤 `nyu8/flarum-email-filter`
- slug 统一使用 id `pipecraft/flarum-ext-id-slug`
- 超级置顶 `the-turk/flarum-stickiest`
- 用户徽章 `v17development/flarum-user-badges`
  - 拖动徽章时容易出现小问题

- 卡片主题 `yannisme/oxotheme`
  - tweak：减小头像字体大小至正常值
  - tweak：去除帖子内容卡片

- 在新标签页中打开外部链接 `zerosonesfun/elint`
- “回到顶部”按钮 `zerosonesfun/flarum-up` 

## 自定义样式

这里给出两个简单的例子，更多调整都可以通过类似方法改 CSS/Less 实现。

### 自定义页面 CSS 调整

自定义页面支持 Markdown，但因为直接套用了论坛里帖子的 CSS 导致间距过大，因此可以在页面中添加[^9]：

```html
<style>
.Pages-container {
white-space: normal !important;
}
</style>
```

### “回到顶部”按钮 Less 调整

在 `外观->自定义样式` 中写 Less[^10]：

```css
#Up {
    position: fixed;
    bottom: 30px;
    right: 10px;
}
```

### 插件开发

对于一些可复用的较复杂的样式，可以提取出来写成插件并发布到社区。Flarum 提供了 flarum-cli[^11] 来快速创建插件模版，只需运行 `flarum init`，随后根据插件涉及的更改选择需要的模版项即可，十分方便。

> 注意手动修改 README，以及 `composer.json` 里的 `keywords`,`extra.flarum-extension.category` 和 `extra.flarum-extension.icon`。

一个最简单的插件[^12]可以只修改前台样式，也就是只编写 `less/forum.less` 文件；而复杂的插件可以修改前/后台的样式、组件、JS 代码、以及后端的 PHP 代码等等。关于插件开发，可以参考 Flarum 插件开发文档[^13]。

## 参考资料

[^1]: [Packagist / Composer 中国全量镜像](https://pkg.xyz/)
[^2]: [Flarum 安装指南](https://discuss.flarum.org.cn/d/1246)
[^3]: [Flarum 官方文档](https://docs.flarum.org/zh/install)
[^4]: [Simplified Chinese Language Pack / 简体中文语言包 - Flarum Community](https://discuss.flarum.org/d/22690-simplified-chinese-language-pack)
[^5]: [FoF 文件上传](https://discuss.flarum.org.cn/d/1292/150)
[^6]: [Flarum 使用腾讯云COS对象存储](https://jacobruan.com/flarum-uses-tencent-cloud-cos-storage/)
[^7]: [How to enable HTTPS with Apache 2 on Ubuntu 20.04](https://www.arubacloud.com/tutorial/how-to-enable-https-protocol-with-apache-2-on-ubuntu-20-04.aspx#GettinganSSLCertificate)

[^8]: [Extiverse](https://extiverse.com/)

[^9]: [FriendsOfFlarum Pages: Page 21 - Flarum Community](https://discuss.flarum.org/d/18301-friendsofflarum-pages/413)

[^10]: [Up (A back to top button) - Flarum Community](https://discuss.flarum.org/d/29223-up-a-back-to-top-button/5)
[^11]: [flarum/cli](https://github.com/flarum/cli)
[^12]: [ECNU-Forum/sticky-sidenav](https://github.com/ECNU-Forum/sticky-sidenav)
[^13]: [Flarum 插件开发文档](https://docs.flarum.org/extend)