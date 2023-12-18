---
title: 欧拉筛法求素数
date: 2017-12-04
tags:
  - 数学
categories:
  - 算法
---

我最喜欢的求素数方法。这也是我最常回顾（抄代码）的一篇文章。

<!--more-->

## C 代码

```c
#include <stdio.h>
#include <stdbool.h>

bool flag[10001] = {0};
int p[10001] = {0};

int main()
{
    int i, n, cnt = 0, j;
    scanf("%d", &n);

    for (i = 2; i <= n; ++i){
        if (flag[i] == 0)
            p[cnt++] = i;
        for (j = 0; j < cnt && i * p[j] <= n; ++j){
            flag[i * p[j]] = 1;
            if (i % p[j] == 0) break;
        }
    }

    for (i = 0; i < cnt; ++i)
        i == cnt - 1 ? printf("%d\n", p[i]) : printf("%d", p[i]);
    return 0;
}
```

## 说明

- `flag` 标记下标是否为合数
- `p` 按顺序存放素数
- `flag[i * p[j]] = 1` 筛掉 `i` 这一素数的 ** 素数倍数 **。
- 若 `i` 能整除 `p[j]` 则跳出循环，等到 `p[j]==i` 时再筛去 `i*p[j]` 这个数。即仅在合数的最大因子作为乘数时筛去这一合数。
- 时间复杂度 `O(n)`

## C++ 版本

实现上有所改动。

```cpp
#include <bits/stdc++.h>
using namespace std;

const int maxn = 1e7+5;
bool np[maxn]{true,true};
vector<int> prime;

int main()
{
    int n, m, x;
    cin >> n >> m;
    for (int i = 2; i <= n; ++i)
    {
        if (!np[i]) prime.push_back(i);
        for (int j = 0; j < prime.size() && i*prime[j] <= n; ++j)
        {
            np[i*prime[j]] = true;
            if (i % prime[j] == 0) break;
        }
    }
    for (int i = 1; i <= m; ++i)
    {
        scanf("%d", &x);
        printf("%s\n", np[x] ? "No" : "Yes");
    }
    return 0;
}
```
