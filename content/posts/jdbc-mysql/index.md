---
title: 通过 JDBC 连接 MySQL
date: 2019-03-25 23:11:05
tags:
  - Java
  - 实践记录
categories:
  - 后端
---

大概是第二次被 MySQL 玩了，也可能是第三次。

<!--more-->

## 使用环境

- Java 开发环境：Win10 + JDK1.8 + Idea
- MySQL 版本：8.x（其实用的是 MariaDB，不过差不多）
- MySQL 的 JDBC 驱动版本：8.x（事实证明，这个和 MySQL 版本号至少最高位必须是一样的）
- MySQL 运行环境：VMware WorkStation 15 Player + Kali Linux 2.0

## 流程

1. 在 MySQL 中新建数据库，例如叫 test，可以新建一些数据表并插入一些数据，使得在 Java 中可以操作它们并看到结果。
2. 在 Idea 中新建项目，导入 MySQL 驱动并编写程序。
3. 打包成 jar 包，放到虚拟机里用 `java -jar xxx.jar` 运行。

就这么简单。然而如此简单的三步中居然还能有那么多的坑点。

## Idea 导入 MySQL 驱动

这里并不坑。Idea 还是很友好的。

```
File -> Project Structure -> Modules -> Dependencies -> Module Source -> 绿色加号
-> JARs or Directories -> 后面应该不用说了
```

搞定。

## 坑点

其实在我把 jar 包放到服务器上运行后，自始至终只遇到了这种错误：

```java
java.sql.SQLNonTransientConnectionException: Could not create connection to database server.
Attempted reconnect 3 times. Giving up.
```

这个错误似乎非常常见，因为能引起这个错误的因素太多了。[StackOverflow 中的一个超有料的问题](https://stackoverflow.com/questions/6865538/solving-a-communications-link-failure-with-jdbc-and-mysql) 里的一些回答给出了非常多的解决方法。我强烈建议读者点进链接看一下尤其是第一个回答，感受一下 MySQL 的坑点之多、之恐怖。其中很多原因是来源于 MySQL 8.x 与 5.x 的巨大差异。

我据此对程序进行了许多修改，包含的坑点有（粗体为可能导致**这次**错误的原因）：

- Java 可能将 `localhost` 解析为 IPv6 地址 `::1`，而不是 IPv4 的 `127.0.0.1`，然而 MySQL 只认后者；解决方法是把 `localhost` 换成 `127.0.0.1`。
- 确保连接时的用户名与密码正确，为此我重设了下密码。
- 在 url 中设置参数 `autoReconnect=true` 防止意外断连。
- 在 url 中设置参数 `useUnicode=true`。
- 在 url 中设置参数 `characterEncoding=utf-8`。
- **在 url 中设置参数 `useSSL=false`。** 不使用 SSL。（似乎是 8.x 新要求）
- **在 url 中设置参数 `serverTimezone=GMT%2B8`。** 设置时区为东 8 区，当然服务器也要设置 `set global time_zone='+8:00'`。（似乎是 8.x 新要求）
- **`Class.forName("com.mysql.cj.jdbc.Driver");` 而不是 `Class.forName("com.mysql.jdbc.Driver");`**（8.x 新特性，很重要）
- 注释掉配置文件中的 `bind-address` 一行，放行来自所有 IP 的连接。
- **在 MySQL 中运行命令 `GRANT ALL PRIVILEGES ON *.* TO 'user'@'%' IDENTIFIED BY 'password';`**。
- 别忘了重启 MySQL 服务。

## 吐槽

没花太多时间解决这个问题，不过中间一度想在虚拟机上搭个 LAMP 当服务器用（等等，IP 地址怎么办？），以为那样就可以不用踩这些坑了。有机会试试用 Maven 项目连数据库。

另外，我记得上次被 MySQL 玩是因为 5.x 和 8.x 版本对密码的哈希方式不一样吧？

## 2019.4.1 更新

对于上面 “虚拟机 IP 地址” 的回答：内网 IP。是我当时蠢了。把 IP 地址换成内网 IP（如下方代码）可以直接在 Idea 下调试，方便多了。

顺手贴个代码：

```java
import java.sql.*;
import java.util.ArrayList;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        String url = "jdbc:mysql://192.168.30.128:3306/test?" +
                "autoReconnect=true&useUnicode=true&characterEncoding=utf-8&" +
                "useSSL=false&serverTimezone=GMT%2B8";
        String userName = "root";
        String password = "celine";
        Connection conn;
        PreparedStatement stmt = null;
        ResultSet rs = null;
        String sql;
        Scanner sc = new Scanner(System.in);
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection(url, userName, password);

            System.out.println("Connected to MySQL via JDBC.\n");
            System.out.println("Enter: [0] to get metadata, [1-9] to perform 9 tasks on the Movie database, [-1] to quit.");

            int op;
            while((op = sc.nextInt()) != -1) {
                switch (op) {
                    case 0:
                        //display metadata
                        sql = "show tables";
                        stmt = conn.prepareStatement(sql);
                        rs = stmt.executeQuery(sql);
                        ArrayList<String> tables = new ArrayList<>();
                        while (rs.next()) {
                            tables.add(rs.getString(1));
                        }
                        for(String table: tables) {
                            sql = "select * from" + table + "limit 1;";
                            rs = stmt.executeQuery(sql);
                            ResultSetMetaData metaData = rs.getMetaData();
                            System.out.println("table name:" + table);
                            System.out.println("columns:\n");
                            for(int i = 1; i <= metaData.getColumnCount(); ++i) {
                                System.out.println("\t" + metaData.getColumnName(i) +
                                        "\t" + metaData.getColumnTypeName(i));
                            }
                            System.out.println();
                        }
                        break;
                    case 1:
                        sql = "select count(*) from Movies;";
                        stmt = conn.prepareStatement(sql);
                        rs = stmt.executeQuery(sql);
                        while (rs.next()) {
                            System.out.println("1. Number of movies:" + rs.getInt("count(*)"));
                        }
                        break;
                    case 2:
                        sql = "select title from Movies;";
                        stmt = conn.prepareStatement(sql);
                        rs = stmt.executeQuery(sql);
                        System.out.println("2. All titles:");
                        while (rs.next()) {
                            System.out.println(rs.getString("title"));
                        }
                        break;
                    case 3:
                        sql = "select min(year) from Movies;";
                        stmt = conn.prepareStatement(sql);
                        rs = stmt.executeQuery(sql);
                        while (rs.next()) {
                            System.out.println("3. Min year:" + rs.getInt("min(year)"));
                        }
                        break;
                    case 4:
                        sql = "select count(*) from Actors;";
                        stmt = conn.prepareStatement(sql);
                        rs = stmt.executeQuery(sql);
                        while (rs.next()) {
                            System.out.println("4. Number of actors:" + rs.getInt("count(*)"));
                        }
                        break;
                    case 5:
                        sql = "select givenNames, familyName from Actors where familyName='Zeta-Jones';";
                        stmt = conn.prepareStatement(sql);
                        rs = stmt.executeQuery(sql);
                        System.out.println("5. Who's Zeta-Jones:");
                        while (rs.next()) {
                            System.out.println(rs.getString("givenNames") +" " +
                                    rs.getString("familyName"));
                        }
                        break;
                    case 6:
                        sql = "select distinct(genre) from BelongsTo;";
                        stmt = conn.prepareStatement(sql);
                        rs = stmt.executeQuery(sql);
                        System.out.println("6. Genres:");
                        while (rs.next()) {
                            System.out.println(rs.getString("genre"));
                        }
                        break;
                    case 7:
                        sql = "select m.title, m.year from Movies m" +
                                "join Directs s on (s.movie = m.id) " +
                                "join Directors d on (s.director = d.id) " +
                                "where d.familyName ='Spielberg';";
                        stmt = conn.prepareStatement(sql);
                        rs = stmt.executeQuery(sql);
                        System.out.println("7. Spielberg has directed:");
                        while (rs.next()) {
                            System.out.println("Title:" + rs.getString("title") + "|" +
                                    "Year:" + rs.getString("year"));
                        }
                        break;
                    case 8:
                        sql = "select a.givenNames, a.familyName from Actors a" +
                                "where not exists (select id from Movies" +
                                "except (select movie as id from AppearsIn where actor = a.id));";
                        stmt = conn.prepareStatement(sql);
                        rs = stmt.executeQuery(sql);
                        System.out.println("8. Super actor:");
                        while (rs.next()) {
                            System.out.println(rs.getString("givenNames") +" " +
                                    rs.getString("familyName"));
                        }
                        break;
                    case 9:
                    /*
                    sql = "create view nDirected as" +
                    "select d.id as director, count(s.movie) as ntimes " +
                    "from Directors d left outer join Directs s on (d.id = s.director) " +
                    "group by d.id;";
            stmt.execute(sql);
                    */
                        sql= "select d.givenNames, d.familyName as name" +
                                "from nDirected nd join Directors d on (nd.director = d.id) " +
                                "where ntimes = 0;";
                        stmt = conn.prepareStatement(sql);
                        rs = stmt.executeQuery(sql);
                        System.out.println("9. Lazy Director:");
                        while (rs.next()) {
                            System.out.println(rs.getString("givenNames") +" " +
                                    rs.getString("familyName"));
                        }
                        break;
                }
                System.out.println();
            }

            rs.close();
            stmt.close();
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) { } // ignore
            }

            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException sqlEx) { } // ignore
            }
        }
    }
}
```
