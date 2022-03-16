---
title: 又见 LAMP：用 Flarum 搭建功能强大的在线论坛
date: 2022-03-13T18:28:09Z
tags:
  - PHP
  - 实践记录
categories:
  - 探索
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/Flarum/0.png
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

> 后来部署到了香港服务器上，可直接运行 `curl -sS https://getcomposer.org/installer | php`.

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

修改 `/path/to/flarum/config.php`，设置 `url` 字段。错误设置会导致请求被 CORS 拦截。

### 中文语言包[^4]

在 `/path/to/flarum` 下运行：

```shell
$ composer require flarum-lang/chinese-simplified
$ php flarum cache:clear
```

### 验证邮件

这里选择通过 mailgun 发送验证邮件，首先需要安装插件：

```shell
$ composer require guzzlehttp/guzzle:^7.0
```

然后注册 mailgun，注意使用 custom domain 而不是 sandbox domain，后者只能发送给白名单中的邮件地址。之后按照 mailgun 的指导配置一堆 DNS 解析记录，最后把相应配置填入 Flarum 即可。

### 图片上传

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

修改 `sites-enabled/000-default.conf`，开启 443 监听并重定向 HTTP 至 HTTPS[^6]：
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

		SSLCertificateFile	/path/to/[your domain].crt
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

## 其他实用插件

```shell
$ composer require clarkwinkelmann/flarum-ext-emojionearea # emoji 选择框
$ composer require fof/forum-statistics-widget             # 论坛统计
$ composer require fof/nightmode:"*"                       # 日间/夜间模式切换
$ composer require fof/user-bio:"*"                        # 用户个性签名
$ composer require fof/reactions:"*"                       # 戳表情
$ composer require fof/recaptcha                           # 验证码，不支持 v3
$ composer require fof/links                               # 导航栏链接
$ composer require fof/pages                               # 自定义页面
$ composer require fof/byobu:"*"                           # 私密主题
$ composer require the-turk/flarum-stickiest:^2.0.1        # 永久置顶
$ composer require nyu8/flarum-email-filter                # 邮件黑白名单
$ composer require zerosonesfun/flarum-up:"*"              # “回到顶部”按钮
$ composer require acpl/mobile-tab:"*"                     # 移动端底部导航
```

### 自定义页面 CSS 调整

使用自定义页面写更新日志。自定义页面支持 Markdown，但因为直接套用了论坛里帖子的 CSS 导致间距过大，因此可以在页面中添加：

```html
<style>
.Post-body h2, .Post-body h4{line-height:0.1}
.Post-body ul{margin-block-start:0;margin-bottom:0}
.Post-body{line-height:1}
</style>
```

然后用 `h2`, `h4`, `ul`, `li` 等标签即可。

### “回到顶部”按钮 CSS 调整

在 `外观->自定义样式` 中写 CSS：

```css
#Up {
    position: fixed;
    bottom: 30px;
    right: 10px;
}
```


## 参考资料

[^1]: [Packagist / Composer 中国全量镜像](https://pkg.xyz/)
[^2]: [Flarum 安装指南](https://discuss.flarum.org.cn/d/1246)
[^3]: [Flarum 官方文档](https://docs.flarum.org/zh/install)
[^4]: [Simplified Chinese Language Pack / 简体中文语言包 - Flarum Community](https://discuss.flarum.org/d/22690-simplified-chinese-language-pack)
[^5]: [FoF 文件上传](https://discuss.flarum.org.cn/d/1292/150)
[^6]: [How to enable HTTPS with Apache 2 on Ubuntu 20.04](https://www.arubacloud.com/tutorial/how-to-enable-https-protocol-with-apache-2-on-ubuntu-20-04.aspx#GettinganSSLCertificate)