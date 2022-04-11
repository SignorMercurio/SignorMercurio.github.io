---
title: 简单 DP 题合集
date: 2017-12-23 16:51:29
tags:
  - 动态规划
categories:
  - 算法
---

经典之所以能被称为经典，是因为其中蕴含的无限可能。

<!--more-->

## 1075 庆祝迎评成功

> 一个蛋糕切 n 刀，求最多可以切成几块。

### 说明

对三维问题，降维处理不失为一种好方法。我们先考虑二维情况：

- n 条直线分割一个平面，最多可以分割成几块？

假设 n-1 条直线已经确定（并且已经是最优解，下同），那么第 n 条直线需要与前 n-1 条直线交于 n-1 个不同的点，这使第 n 条直线被分为 n 份，平面则将被多分出 n 个区域。

我们设二维情况的答案为 `f(n)`，则 `f(n)=f(n-1)+n`，推得通项公式 `f(n)=1+n(n+1)/2`。

推广到三维，设此时答案为 `s(n)`。n-1 个平面已经确定，第 n 个平面需要与前 n-1 个平面有 n-1 条交线，这使第 n 个平面被分为 `f(n-1)` 份，空间则将被多分出 `f(n-1)` 个区域。我们得到：`s(n)=s(n-1)+f(n-1)=s(n-1)+1+n(n-1)/2`。

边界条件为 `s(0)=1`。

```c
#include <stdio.h>

int main(){
    int a, i;
    long long s[1001];
    s[0] = 1;
    for (i = 1; i < 1001; ++i)
        s[i] = s[i - 1] + i * (i - 1) / 2 + 1;
    while (scanf("%d", &a) && a)
        printf("%lld\n", s[a]);
    return 0;
}
```

## 1015 核电站

> 一个核电站有 N 个放核物质的坑，坑排列在一条直线上。
> 如果连续 M 个坑中放入核物质，则会发生爆炸，于是，在某些坑中可能不放核物质。
> 任务：对于给定的 N 和 M，求不发生爆炸的放置核物质的方案总数。

### 说明

设第 n 个坑不发生爆炸的方案数为 `f(n)`，我们假设前 n-1 个坑已经确定。分两种情况：

1. 已经有连续 m-1 个核物质，那么第 n 个坑只能不放核物质，且这 m-1 个坑前的那个坑也不能放核物质。方案数为 `f((n-1)-(m-1)-1)=f(n-m-1)`。
2. 否则，第 n 个坑可以选择放或不放。方案数为 `2*[f(n-1)-f(n-m-1)]`。

边界条件 `f(0)=1`。

具体计算时可以用 DP 的递推形式写，也可以像如下代码中用 2 的幂计算：

```c
#include <stdio.h>
#include <math.h>

int main(void)
{
    int n, m, i;
    long long nuc[60];
    nuc[0] = 1;
    while (~scanf("%d%d", &n, &m)){
        for (i = 1; i <= 50; ++i){
            if (i < m) nuc[i] = (long long)pow(2, i);
            else if(i == m) nuc[i] = (long long)pow(2, m) - 1;
            else nuc[i] = 2 * nuc[i - 1] - nuc[i - m - 1];
        }
        printf("%I64d\n", nuc[n]);
    }
    return 0;
}
```

> 这里不能预处理 `nuc` 数组，因为 m 未知。

## 3267 足球锦标赛

> 计分板上的每一位都按顺序挂了 0 到 9 这 10 个牌子，所以可以表示 000 至 999。当其中一个队的得分从 010 变成 011 时，计分员只要将最后一位的最前面的牌子向后翻即可，共需翻动一块牌子；当得分从 019 变成 020 是，由于 9 后面已经没有牌子了，所以计分员要将 0 到 9 全部翻到前面，并将倒数第二位的牌子 1 翻到后面，所以共需翻动 10 块牌子。
> 现场的计分牌和图中所示还是存在差异的，现场的计分牌会很大，很重，所以翻每块牌子都要消耗 1 点体力。
> 你是计分员，现在比赛还剩下最后十分钟。现在有一个预言家告诉你在这十分钟里，双方得分共计多少；但他没有告诉你双方得分各是多少。所以你想要知道你要花费的体力值最多是多少。

### 说明

先模拟翻牌，预处理记录体力的数组。然后枚举双方得分情况，求最大值。

```c
#include <stdio.h>

int dp[1001]={0};

void init()
{
    int i;
    for (i = 1; i <= 999; ++i){
        if (i % 100 == 0) dp[i] = dp[i - 1] + 19;
        else if (i % 10 == 0) dp[i] = dp[i - 1] + 10;
        else dp[i] = dp[i - 1] + 1;
    }
    return;
}

int main(void)
{
    int t, i, a, b, sc, j;
    scanf("%d", &t);
    init();
    for (i = 1; i <= t; ++i){
        scanf("%3d %3d %d", &a, &b, &sc);
        int ans = 0, now = 0;
        for (j = 0; j <= sc; ++j){
            now = dp[a + j] - dp[a] + dp[b + sc - j] - dp[b];
            if (now> ans) ans = now;
        }
        printf("Case %d: %d\n", i, ans);
    }
    return 0;
}
```

## 1052 0-1 背包问题

> 已知 n 个物体 `1,2,3,…,n` 与一个背包。物体 `i` 的重量为 `Wi>0`，价值为 `Pi>0 (i=1,2,…,n)`，背包容量为 `M>0`。
> 求在不超过背包容量的情况下，使得装进去的物体的价值最高。

### 说明

经典入门 DP 题。用一维数组实现时需要注意 `j` 需要从 `m` 到 `w` 递减，这与动规的 bottom-up 思路是一致的。

```c
#include<stdio.h>

int main()
{
    int t;
    scanf("%d", &t);
    while(t--)
    {
        int n, m, i, j, w, v, a[100001] = {0};
        scanf("%d%d", &n, &m);
        for(i = 0; i < n; ++i){
            scanf("%d%d", &w, &v);
            for(j = m; j>= w; --j)
                if (a[j - w] + v > a[j]) a[j] = a[j - w] + v;
        }
        printf("%d\n",a[m]);
    }
    return 0;
}
```

## 3302 打印

> 打印 n 个相同的字符，插入或删除一个字符花费的时间为 x，复制当前整个文本并且粘贴在后面的时间花费为 y，求完成 n 个字符的打印所需的最小花费时间。

### 说明

`dp[i]` 表示打印 `i` 个字符需要的最小时间。

1. `i` 为偶数时，可能是 `(i-1 个字符 + 插入一个字符) / (i/2 个字符复制一次)` 两种操作之一产生的，取它们的最小值。
2. `i` 为奇数时，可能是 `(i-1 个字符 + 插入一个字符) / ((i+1)/2 个字符复制一次)` 两种操作之一产生的，取它们的最小值。

写的时候用的 C，还并不会定义宏，导致代码看起来比较繁琐。

```c
#include <stdio.h>
#include <memory.h>
typedef long long LL;

LL dp[10000001];

LL printing(int n, int x, int y)
{
    int i;
    if (n == 0) return 0;
    if (n == 1) return x;
    memset(dp, 0, sizeof(dp));
    for (i = 1; i <= n; ++i){
        if (i % 2)
            dp[i] = (dp[i-1]+x <dp[(i+1)/2]+y+x)?dp[i-1]+x:dp[(i+1)/2]+y+x;
        else
            dp[i] = (dp[i-1]+x <dp[i/2]+y)?dp[i-1]+x:dp[i/2]+y;
    }
    return dp[n];
}

int main()
{
    int n,x,y;
    scanf("%d%d%d",&n, &x, &y);
    LL ans = printing(n, x, y);
    printf("%lld", ans);
    return 0;
}
```

## 数塔系列

### 最小和

> 从顶部出发，在每一结点可以选择向左走或是向右走，一直走到底层，要求找出一条路径，使路径上的数字和最小。

自下向上更新每一层的最小值。

```c
#include <stdio.h>
#include <memory.h>
#define min(a, b) ((a) <(b) ? (a) : (b))

int dp[101], a[101][101];

int main(void)
{
    int t, n, i, j;
    scanf("%d", &t);
    while(t--){
        scanf("%d", &n);
        memset(dp, 0, sizeof(dp));
        for (i = 0; i < n; ++i)
            for (j = 0; j <= i; ++j) scanf("%d", &a[i][j]);
        for (i = n - 1; i>= 0; --i)
            for (j = 0; j <= i; ++j)
                dp[j] = min(dp[j], dp[j + 1]) + a[i][j];
        printf("%d\n", dp[0]);
    }
    return 0;
}
```

### 最大和

> 从第一行的数开始，除了某一次可以走到下一行的任意位置外，每次都只能左下或右下走一格，直到走到最下行，把沿途经过的数全部加起来。如何走，使得这个和尽量大？

数组多建一维，值只有 0 和 1，表示是否还有传送机会剩余。
对于每次更新，如果还有传送机会，考虑是否传送。用 `maxn` 记录第 n 层的最大值。这次没有额外用 `dp` 数组而是直接覆盖 `a` 数组。

```cpp
#include <cstdio>
#include <cstring>
#include <algorithm>
using namespace std;

int a[502][502][2], maxn[502];

int main()
{
    int t, n, i, j;
    scanf("%d", &t);
    while(t--){
        scanf("%d", &n);
        memset(maxn, 0, sizeof(maxn));
        for (i = 1; i <= n; ++i)
            for (j = 1; j <= i; ++j){
                scanf("%d", &a[i][j][0]);
                a[i][j][1] = a[i][j][0];
            }
        for (j = 1; j <= n; ++j)
            maxn[n] = max(maxn[n], a[n][j][0]);

        for (i = n-1; i>= 1; --i)
            for (j = 1; j <= i; ++j){
                a[i][j][0] += max(a[i+1][j][0], a[i+1][j+1][0]);
                maxn[i] = max(maxn[i], a[i][j][0]);
                a[i][j][1] += max(max(a[i+1][j][1], a[i+1][j+1][1]), maxn[i+1]);
            }
        printf("%d\n", a[1][1][1]);
    }
    return 0;
}
```

### 个位数最大和

> 从第一行的数开始，每次都只能左下或右下走一格，直到走到最下行，把沿途经过的数全部加起来。如何走，使得这个和的个位数尽量大？

多建一维来记录个位数，最后枚举个位数即可。

```c
#include <stdio.h>
#include <memory.h>

int dp[101][101][11], a[101][101];

int main(void)
{
    int t, n, i, j, k;
    scanf("%d", &t);
    while(t--){
        memset(dp, 0, sizeof(dp));
        scanf("%d", &n);
        for (i = 0; i < n; ++i)
            for (j = 0; j <= i; ++j) scanf("%d", &a[i][j]);
        for (i = 0; i < n; ++i)
            dp[n - 1][i][a[n - 1][i] % 10] = 1;
        for (i = n - 2; i>= 0; --i)
            for (j = 0; j <= i; ++j)
                for (k = 0; k < 10; ++k)
                    if (dp[i + 1][j][k] || dp[i + 1][j + 1][k])
                        dp[i][j][(k + a[i][j]) % 10] = 1;
        for (i = 9; i>= 0; --i)
            if (dp[0][0][i]){printf("%d\n", i); break;}
    }
    return 0;
}
```

### 个位数最大积

> 从第一行的数开始，每次都只能左下或右下走一格，直到走到最下行，把沿途经过的数全部乘起来。如何走，使得个位数的积尽量大 ?

和上一题同理，将加法换成乘法。

```cpp
#include <cstdio>
#include <cstring>

int dp[101][101][11], a[101][101];

int main(void)
{
    int t, n, i, j, k;
    scanf("%d", &t);
    while(t--){
        memset(dp, 0, sizeof(dp));
        scanf("%d", &n);
        for (i = 0; i < n; ++i)
            for (j = 0; j <= i; ++j) scanf("%d", &a[i][j]);
        for (i = 0; i < n; ++i)
            dp[n - 1][i][a[n - 1][i] % 10] = 1;
        for (i = n - 2; i>= 0; --i)
            for (j = 0; j <= i; ++j)
                for (k = 0; k < 10; ++k)
                    if (dp[i + 1][j][k] || dp[i + 1][j + 1][k])
                        dp[i][j][(k * a[i][j]) % 10] = 1;
        for (i = 9; i>= 0; --i)
            if (dp[0][0][i]){printf("%d\n", i); break;}
    }
    return 0;
}
```