---
title: "按图索骥：osquery 探索"
date: 2025-10-19
tags:
  - 应急响应
categories:
  - 安全工具
---

用 SQL 语法查询系统信息。

<!--more-->

> 由于相比直接执行命令缺少必要的灵活性（例如：查看指定文件内容），使用 osquery 进行排查的方案暂时搁置。

## 安装

```bash
wget https://pkg.osquery.io/linux/osquery-5.15.0_1.linux_x86_64.tar.gz
tar -zxvf osquery-5.15.0_1.linux_x86_64.tar.gz -C / --skip-old-files --no-overwrite-dir
```

### 避免性能问题

```bash
systemctl mask --now systemd-journald-audit.socket
```

### 启动 osqueryd

应急响应手动排查中通常只使用 osqueryi，但如果需要启动 osqueryd：

```bash
sudo cp /opt/osquery/share/osquery/osquery.example.conf /etc/osquery/osquery.conf
sudo systemctl start osqueryd
```

## 卸载

```bash
rm -rf /var/osquery /var/log/osquery /opt/osquery /etc/osquery /usr/bin/osquery*
```

## 查询示例

### 用户

#### 非默认、可登录用户

```sql
SELECT
  uid,
  gid,
  username,
  description,
  directory,
  shell
FROM
  users
WHERE
  shell NOT IN ('/bin/false', '/sbin/nologin')
  AND username NOT IN ('root','sync','shutdown','halt');
```

#### 当前登录用户

```sql
SELECT
  user,
  tty,
  host,
  datetime(time, 'unixepoch', 'localtime') as login_time
FROM
  logged_in_users
WHERE
  type = 'user';
```

#### 登录历史

```sql
SELECT
  username,
  tty,
  pid,
  host,
  datetime(time, 'unixepoch', 'localtime') as login_time
FROM
  last
WHERE
  type = 7
  AND time >= strftime('%s', 'now', '-6 months')
ORDER BY
  time DESC;
```

### 进程

#### CPU 占用前 20 进程

```sql
SELECT
  pid,
  parent,
  u.username,
  name,
  CONCAT(
    ROUND(
      (
        (user_time + system_time) / (cpu_time.tsb - cpu_time.itsb)
      ) * 100,
      2
    ),
    '%'
  ) AS cpu,
  CONCAT(ROUND((total_size * '10e-7'), 2), 'MB') AS mem,
  datetime(start_time, 'unixepoch', 'localtime') as start_time,
  cwd,
  path,
  cmdline
FROM
  processes p
  JOIN users u ON p.uid = u.uid,
  (
    SELECT
      (
        SUM(user) + SUM(nice) + SUM(system) + SUM(idle) * 1.0
      ) AS tsb,
      SUM(COALESCE(idle, 0)) + SUM(COALESCE(iowait, 0)) AS itsb
    FROM
      cpu_time
  ) AS cpu_time
ORDER BY
  user_time + system_time DESC
LIMIT
  20;
```

#### 内存占用前 20 进程

```sql
SELECT
  pid,
  parent,
  u.username,
  name,
  CONCAT(
    ROUND(
      (
        (user_time + system_time) / (cpu_time.tsb - cpu_time.itsb)
      ) * 100,
      2
    ),
    '%'
  ) AS cpu,
  CONCAT(ROUND((total_size * '10e-7'), 2), 'MB') AS mem,
  datetime(start_time, 'unixepoch', 'localtime') as start_time,
  cwd,
  path,
  cmdline
FROM
  processes p
  JOIN users u ON p.uid = u.uid,
  (
    SELECT
      (
        SUM(user) + SUM(nice) + SUM(system) + SUM(idle) * 1.0
      ) AS tsb,
      SUM(COALESCE(idle, 0)) + SUM(COALESCE(iowait, 0)) AS itsb
    FROM
      cpu_time
  ) AS cpu_time
ORDER BY
  total_size DESC
LIMIT
  20;
```

#### 可执行文件已不存在的进程

注意针对部分 python 进程存在误报：

```sql
SELECT
  pid,
  parent,
  u.username,
  name,
  CONCAT(
    ROUND(
      (
        (user_time + system_time) / (cpu_time.tsb - cpu_time.itsb)
      ) * 100,
      2
    ),
    '%'
  ) AS cpu,
  CONCAT(ROUND((total_size * '10e-7'), 2), 'MB') AS mem,
  datetime(start_time, 'unixepoch', 'localtime') as start_time,
  cwd,
  path,
  cmdline
FROM
  processes p
  JOIN users u ON p.uid = u.uid,
  (
    SELECT
      (
        SUM(user) + SUM(nice) + SUM(system) + SUM(idle) * 1.0
      ) AS tsb,
      SUM(COALESCE(idle, 0)) + SUM(COALESCE(iowait, 0)) AS itsb
    FROM
      cpu_time
  ) AS cpu_time
WHERE
  on_disk = 0
  AND name <> 'tuned'
ORDER BY
  start_time DESC;
```

#### 非默认、用户态进程

```sql
SELECT
  pid,
  parent,
  u.username,
  name,
  CONCAT(
    ROUND(
      (
        (user_time + system_time) / (cpu_time.tsb - cpu_time.itsb)
      ) * 100,
      2
    ),
    '%'
  ) AS cpu,
  CONCAT(ROUND((total_size * '10e-7'), 2), 'MB') AS mem,
  datetime(start_time, 'unixepoch', 'localtime') as start_time,
  cwd,
  path,
  cmdline
FROM
  processes p
  JOIN users u ON p.uid = u.uid,
  (
    SELECT
      (
        SUM(user) + SUM(nice) + SUM(system) + SUM(idle) * 1.0
      ) AS tsb,
      SUM(COALESCE(idle, 0)) + SUM(COALESCE(iowait, 0)) AS itsb
    FROM
      cpu_time
  ) AS cpu_time
WHERE
  parent <> 2
  AND name NOT IN(
    'kthreadd',
    'tuned',
    'aliyun-service',
    'AliYunDunUpdate',
    'AliYunDun',
    'AliYunDunMonito'
  )
  AND path NOT IN(
    '/usr/lib/systemd/systemd',
    '/usr/sbin/chronyd',
    '/usr/lib/polkit-1/polkitd',
    '/usr/sbin/gssproxy',
    '/usr/sbin/rpcbind',
    '/usr/bin/dbus-daemon',
    '/usr/lib/systemd/systemd-logind',
    '/usr/sbin/auditd',
    '/usr/lib/systemd/systemd-udevd',
    '/usr/lib/systemd/systemd-journald',
    '/usr/sbin/dhclient',
    '/usr/sbin/agetty',
    '/usr/sbin/crond',
    '/usr/sbin/atd',
    '/usr/sbin/rsyslogd',
    '/usr/libexec/postfix/qmgr',
    '/usr/libexec/postfix/master',
    '/usr/libexec/postfix/pickup',
    '/usr/sbin/sshd',
    '/usr/local/cloudmonitor/bin/argusagent',
    '/usr/local/share/assist-daemon/assist_daemon'
  )
ORDER BY
  start_time DESC;
```

### 网络

#### 开放端口

```sql
SELECT
	(
    CASE
      l.family
      WHEN 2 THEN 'IPv4'
      WHEN 10 THEN 'IPv6'
      ELSE l.family
    END
  ) AS family,
  (
    CASE
      l.protocol
      WHEN 6 THEN 'TCP'
      WHEN 17 THEN 'UDP'
      ELSE l.protocol
    END
  ) AS protocol,
  l.port,
  p.name,
  p.path,
  p.pid
FROM
  listening_ports l
  JOIN processes p ON l.pid = p.pid
WHERE
  l.address IN ('0.0.0.0', '::')
  AND p.path NOT IN(
    '/usr/sbin/rpcbind',
    '/usr/sbin/dhclient'
  );
```

#### 非默认网络连接

```sql
SELECT
  (
    CASE
      l.family
      WHEN 2 THEN 'IPv4'
      WHEN 10 THEN 'IPv6'
      ELSE l.family
    END
  ) AS family,
  (
    CASE
      l.protocol
      WHEN 6 THEN 'TCP'
      WHEN 17 THEN 'UDP'
      ELSE l.protocol
    END
  ) AS protocol,
  l.local_address,
  l.local_port,
  l.remote_address,
  l.remote_port,
  l.state,
  p.name,
  p.path,
  p.pid
FROM
  process_open_sockets l
  LEFT JOIN processes p ON l.pid = p.pid
WHERE
	l.protocol <> 0
  AND l.state <> 'LISTEN'
  AND l.remote_address NOT LIKE '140.205.11.%'
  AND p.path NOT IN('/usr/sbin/rpcbind', '/usr/sbin/dhclient', '/usr/sbin/chronyd')
  AND p.name <> 'AliYunDun';
```

#### 网卡地址

```sql
SELECT * FROM interface_addresses;
```

#### DNS 解析

```sql
SELECT * FROM dns_resolvers;
```

#### /etc/hosts

```sql
SELECT * FROM etc_hosts;
```

### 文件

#### 文件属性

以 `/etc/hosts` 为例：

```sql
SELECT
	path,
  f.directory,
  u.username AS own_user,
  g.groupname AS own_group,
  mode,
  (
    CASE
      WHEN size < 1024 THEN printf ('%.2f B', size)
      WHEN size < 1048576 THEN printf ('%.2f KB', size / 1024.0)
      WHEN size < 1073741824 THEN printf ('%.2f MB', size / 1048576.0)
      ELSE printf ('%.2f GB', size / 1073741824.0)
    END
  ) AS readable_size,
  datetime(atime, 'unixepoch', 'localtime') as last_access_time,
  datetime(mtime, 'unixepoch', 'localtime') as last_modify_time,
  datetime(ctime, 'unixepoch', 'localtime') as last_change_time,
  datetime(btime, 'unixepoch', 'localtime') as birth_time
FROM
  file f
  JOIN users u ON f.uid = u.uid
  JOIN groups g ON f.gid = g.gid
WHERE
  path = '/etc/hosts';
```

#### 非默认 SUID 二进制文件

```sql
SELECT
  *
FROM
  suid_bin
WHERE
  path NOT IN(
    '/bin/atq',
    '/bin/gpasswd',
    '/bin/fusermount',
    '/bin/pkexec',
    '/bin/write',
    '/bin/sudo',
    '/bin/chsh',
    '/bin/su',
    '/bin/mount',
    '/bin/wall',
    '/bin/at',
    '/bin/passwd',
    '/bin/sudoedit',
    '/bin/sg',
    '/bin/umount',
    '/bin/chfn',
    '/bin/newgrp',
    '/bin/crontab',
    '/bin/chage',
    '/bin/atrm',
    '/bin/ssh-agent',
    '/sbin/umount.nfs4',
    '/sbin/mount.nfs4',
    '/sbin/postqueue',
    '/sbin/unix_chkpwd',
    '/sbin/netreport',
    '/sbin/postdrop',
    '/sbin/umount.nfs',
    '/sbin/pam_timestamp_check',
    '/sbin/mount.nfs',
    '/sbin/usernetctl',
    '/usr/bin/atq',
    '/usr/bin/gpasswd',
    '/usr/bin/fusermount',
    '/usr/bin/pkexec',
    '/usr/bin/write',
    '/usr/bin/sudo',
    '/usr/bin/chsh',
    '/usr/bin/su',
    '/usr/bin/mount',
    '/usr/bin/wall',
    '/usr/bin/at',
    '/usr/bin/passwd',
    '/usr/bin/sudoedit',
    '/usr/bin/sg',
    '/usr/bin/umount',
    '/usr/bin/chfn',
    '/usr/bin/newgrp',
    '/usr/bin/crontab',
    '/usr/bin/chage',
    '/usr/bin/atrm',
    '/usr/bin/ssh-agent',
    '/usr/sbin/umount.nfs4',
    '/usr/sbin/mount.nfs4',
    '/usr/sbin/postqueue',
    '/usr/sbin/unix_chkpwd',
    '/usr/sbin/netreport',
    '/usr/sbin/postdrop',
    '/usr/sbin/umount.nfs',
    '/usr/sbin/pam_timestamp_check',
    '/usr/sbin/mount.nfs',
    '/usr/sbin/usernetctl'
  );
```

### SSH

#### 所有用户公钥文件

```sql
SELECT
  *
FROM
  authorized_keys a
  JOIN users u ON a.uid = u.uid;
```

### 计划任务

#### 非默认 crontab

```sql
SELECT
  *
FROM
  crontab
WHERE
  command NOT IN(
    'root run-parts /etc/cron.hourly',
    'root /usr/lib64/sa/sa1 1 1',
    'root /usr/lib64/sa/sa2 -A'
  );
```

### 服务

#### 运行中的非默认 systemd 服务

```sql
SELECT
  id,
  description,
  unit_file_state,
  fragment_path,
  source_path
FROM
  systemd_units
WHERE
	sub_state='running'
  AND id NOT IN (
    'chronyd.service',
    'aliyun.service',
    'systemd-udevd.service',
    'polkit.service',
    'systemd-logind.service',
    'systemd-journald.socket',
    'rsyslog.service',
    'tuned.service',
    'proc-sys-fs-binfmt_misc.automount',
    'cloudmonitor.service',
    'gssproxy.service',
    'dbus.socket',
    'serial-getty@ttyS0.service',
    'rpcbind.service',
    'crond.service',
    'postfix.service',
    'sshd.service',
    'systemd-udevd-kernel.socket',
    'dbus.service',
    'systemd-journald.service',
    'rpcbind.socket',
    'network.service',
    'aegis.service',
    'auditd.service',
    'systemd-udevd-control.socket',
    'atd.service',
    'AssistDaemon.service',
    'getty@tty1.service'
  );
```

### 其他

#### 内核模块

```sql
SELECT * FROM kernel_modules;
```
