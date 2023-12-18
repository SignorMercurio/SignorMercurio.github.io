---
title: zkw 线段树
date: 2018-03-08
tags:
  - 线段树
  - 模版
categories:
  - 算法
---

%。

<!--more-->

关于 zkw 线段树是啥，参见他本人的 PPT：[统计的力量](https://wenku.baidu.com/view/f27db60ee87101f69e319544.html)

相比递归版线段树：

- 优点：代码量较少、空间需求略少（实际上不需要 4 倍）、运行效率较高（非递归）
- 缺点：应用范围有限制。尽管可以稍加修改就支持单点更新 / 单点查询 / 区间更新 / 区间求和 / 区间 RMQ 等，但其中部分功能似乎不能同时实现

总体来说，无论是代码量还是应用范围都介于树状数组和递归版线段树之间。

关于这个数据结构还在摸索……下面是两个栗子:

## HDU 1166 敌兵布阵

[https://cn.vjudge.net/problem/HDU-116](https://cn.vjudge.net/problem/HDU-1166)

```cpp
#include <iostream>
#include <cstdio>
#include <cstring>
using namespace std;

const int maxn = 5e5+5;
int T[maxn<<2], n, M;

inline void pushup(int x)
{
    T[x] = T[x<<1] + T[x<<1|1];
}

inline void build()
{
    for (M = 1; M <= n+1; M <<= 1);
    for (int i = M+1; i <= M+n; ++i)
        scanf("%d", T+i);
    for (int i = M-1; i; --i) pushup(i);
}

inline void add(int x, int y)
{
    for (T[x+=M] += y, x>>=1; x; x>>=1) pushup(x);
}

inline void sub(int x, int y)
{
    for (T[x+=M] -= y, x>>=1; x; x>>=1) pushup(x);
}

inline int query(int s, int t)
{
    int ans = 0;
    for (s += M-1, t += M+1; s^t^1; s>>=1, t>>=1)
    {
        if (~s&1) ans += T[s^1];
        if (t&1) ans += T[t^1];
    }
    return ans;
}

int main()
{
    int t, a, b, k = 0;
    char op[10];
    cin >> t;
    while (t--)
    {
        printf("Case %d:\n", ++k);
        memset(T, 0, sizeof T);
        scanf("%d", &n);
        build();
        while (~scanf("%s", op) && strcmp(op,"End"))
        {
            if (!strcmp(op,"Query")) {scanf("%d%d", &a, &b); printf("%d\n", query(a,b));}
            else if (!strcmp(op,"Add")) {scanf("%d%d", &a, &b); add(a,b);}
            else {scanf("%d%d", &a, &b); sub(a,b);}
        }
    }
    return 0;
}
```

## EOJ 3389 线段树：点增加

[http://acm.ecnu.edu.cn/problem/3389/](http://acm.ecnu.edu.cn/problem/3389/)

微坑的模板题。

```cpp
#include <bits/stdc++.h>
using namespace std;

#define pushup(x) T[x]=T[x<<1]+T[x<<1|1]
const int maxn = 500005;
int n, m, M;
long long T[maxn<<4];

inline void build()
{
    for (M = 1; M <= n+1; M <<= 1);
    for (int i = M+1; i <= M+n; ++i) scanf("%lld", T+i);
    for (int i = M-1; i; --i) pushup(i);
}

inline void update(int x, int y)
{
    for (T[x+=M] += y, x>>=1; x; x>>=1) pushup(x);
}

inline void query(int s, int t)
{
    long long ans = 0;
    for (s += M-1, t += M+1; s^t^1; s>>=1, t>>=1)
    {
        if (~s&1) ans += T[s^1];
        if (t&1) ans += T[t^1];
    }
    printf("%lld\n", ans);
}

int main()
{
    int op, x, y;
    scanf("%d", &n);
    build();
    scanf("%d", &m);
    while (m--)
    {
        scanf("%d%d%d", &op, &x, &y);
        (op == 1) ? update(x, y) : query(x, y);
    }
    return 0;
}
```
