---
title: DP 题练习记录
date: 2018-01-30
tags:
  - 动态规划
categories:
  - 算法
---

对我而言不那么简单的 DP 题目。

<!--more-->

## 1009 整数的拆分

> 将正整数 n 表示成一系列正整数之和 : `n=n1+n2+…+nk`，其中 `n1≥n2≥…≥nk≥1(k≥1)`
> 正整数 n 的这种表示称为正整数 n 的拆分。求正整数 n 的不同拆分个数。
> 例如，正整数 6 有如下 11 种不同的拆分 :
> 6；
> 5+1；
> 4+2，4+1+1；
> 3+3，3+2+1，3+1+1+1；
> 2+2+2，2+2+1+1，2+1+1+1+1；
> 1+1+1+1+1+1。
> 例如，正整数 3 有如下 3 种不同的拆分 :
> 3;
> 2+1;
> 1+1+1。

### 说明

`dp[i][j]` 表示数 `i` 划分为 `j` 份的方案数。显然对任意 `i`，有 `dp[i][1]=1`。

当 `i <j ` 时，不会出现新的划分方案，`dp[i][j]=dp[i][j-1]`;

当 `i == j ` 时，新的划分方案只有一种，那就是原数本身划为一份（即 `dp[i][1]`），`dp[i][j]=dp[i][j-1]+1`;

当 `i > j` 时：

1. 每个划分数都小于 `j`，则总数 `dp[i][j-1]`;
2. 划分数中包含了 `j`，则需要从 `i` 中减去 `j` 再划分，总数 `dp[i-j][j]`;

所以状态转移方程 `dp[i][j]=dp[i][j-1]+dp[i-j][j]`。

```cpp
#include <cstdio>
using namespace std;

int dp[101][101];

int main(void)
{
    int n, i, j;
    for (i = 1; i <= 100; ++i) dp[i][1] = 1;
    while(~scanf("%d", &n)){
        for (i = 1; i <= n; ++i)
            for (j = 2; j <= n; ++j){
                dp[i][j] = dp[i][j - 1];
                if (i == j) ++dp[i][j];
                else if(i> j) dp[i][j] += dp[i - j][j];
            }
        printf("%d\n", dp[n][n]);
    }
    return 0;
}
```

## 3034 数字拆分

> 将一个正整数拆分为成 2 的幂的和，例如：
> 7=1+2+4
> 7=1+2+2+2
> 7=1+1+1+4
> 7=1+1+1+2+2
> 7=1+1+1+1+1+2
> 7=1+1+1+1+1+1+1
> 总共有六种不同的拆分方案。
> 再比如：4 可以拆分成：4 = 4，4 = 1 + 1 + 1 + 1，4 = 2 + 2，4 = 1 + 1 + 2。
> 函数 `f(n)` 表示 n 的不同拆分的方案数，例如 `f(7)=6`。
> 请编写程序，读入一个正整数 n (1≤n≤1000000)，输出 `f(n)%1000000000`。

### 说明

如果 n 为奇数，那么每种划分只会相对于前一个偶数的划分各多出一个 1，因此划分数相等，`dp[n]=dp[n-1]`。

如果 n 为偶数，那么对于含有 1 的情况可以拿出 2 个 1 转化为 `n-2` 的情况，而对不含 1 的情况可以直接除以 2 变成 `n/2` 的情况，`dp[n]=dp[n-2]+dp[n>>1]`。

```cpp
#include <cstdio>
#define MAX 1000000
#define mod 1000000000

int dp[1000001] = {0, 1, 2};

int main()
{
    int cas, n;
    scanf("%d", &cas);
    for (int i = 3; i <= 1000000; ++i){
        if (i & 1) dp[i] = dp[i-1] % mod;
        else dp[i] = (dp[i-2] + dp[i>>1]) % mod;
    }
    for (int t = 0; t < cas; ++t){
        scanf("%d", &n);
        printf("case #%d:\n%d\n", t, dp[n]);
    }
    return 0;
}
```

## 3029 不重复正整数

> 整数拆分是把一个正整数（简称为和数）拆分为一个或若干个指定正整数（简称为零数，通常不区别式中各零数的排列顺序）之和，这是一个有趣的计算问题。通常拆分式中的零数有重复和不重复（即拆分式中各零数互不相同）两种情况。
> 如果我们打算将一个给定的正整数 N（N≤50）拆分为若干个不重复的正整数（`a1,a2,…,ai,…`）（i≥1）之和，其中每个零数的取值不大于给定的正整数 M（M≤20），即 `1≤ai≤M`，请问共有多少种不同的拆分方案。

### 说明

本质还是 01 背包，注意第二层循环倒序枚举，否则一个数可以取多次。

注：`dp[j] += dp[j-i]` 其实是 `dp[j] = max(dp[j], dp[j-i]+dp[j])` 的简化形式。

```cpp
#include <bits/stdc++.h>
using namespace std;

int main()
{
    int cas, n, m, dp[55];
    cin >> cas;
    for (int t = 0; t < cas; ++t) {
        cin >> n >> m;
        memset(dp, 0, sizeof(dp));
        dp[0] = 1;
        for (int i = 1; i <= m; ++i)
            for (int j = n; j>= i; --j)
                dp[j] += dp[j-i];
        printf("case #%d:\n%d\n", t, dp[n]);
    }
    return 0;
}
```

## 2857 编辑距离

> 有两个字符串（仅有英文小写字母组成） A，B。我们可以通过一些操作将 A 修改成 B。操作有三种：1 修改一个字母，2 删除一个字母，3 插入一个字母。现在定义编辑距离为将 A 通过上述操作修改成 B 的最少次数。

### 说明

有点像 LCS 的题，`dp[i][j]` 表示 a 的前 `i` 个字符转为 b 的前 `j` 个字符所需要的最少操作次数。

如果 `a[i-1]==b[j-1]` 那么不需要额外操作，`dp[i][j]=dp[i-1][j-1]`;

否则，我们可以选择：

1. 修改：`dp[i][j]=dp[i-1][j-1]+1`;
2. 增加：`dp[i][j]=dp[i][j-1]+1`；
3. 删除：`dp[i][j]=dp[i-1][j]+1`。

三者取 min。

```cpp
#include <cstdio>
#include <cstring>
#include <algorithm>
#define INF 999999
using namespace std;

int main()
{
    int cas, i, j, lena, lenb, dp[501][501];
    char a[501], b[501];
    scanf("%d\n", &cas);
    while(cas--) {
        gets(a); lena = strlen(a);
        gets(b); lenb = strlen(b);
        memset(dp, INF, sizeof(dp));
        for (i = 0; i <= lena; ++i) dp[i][0] = i;
        for (j = 0; j <= lenb; ++j) dp[0][j] = j;
        for (i = 1; i <= lena; ++i)
            for (j = 1; j <= lenb; ++j){
                dp[i][j] = min(dp[i-1][j] + 1, dp[i][j-1] + 1);
                dp[i][j] = min(dp[i][j], dp[i-1][j-1] + (a[i-1] != b[j-1]));
            }
        printf("%d\n", dp[lena][lenb]);
    }
    return 0;
}
```

## 1029 走道铺砖

> `n*m ` 的走道铺满 `1*2` 的地砖，求铺设方案数。
> 1 <= N,M <= 11

状压 DP……

我们知道这题中上一行的状态可以一定程度上决定下一行，且铺一块砖的方式只有两种：竖放和横放。

不妨用 `1 1` 表示横放的砖块，上 0 下 1 来表示竖放的砖块。为什么这样表示？

1. 横放砖块对下一行完全没有影响
2. 竖放砖块的下半部分**填充**了下一行的一个格子。
3. 竖放砖块的上半部分对下一行有影响：如果上一行某一位是 0，那么下一行这位只能是 1。
4. 为了保证最后一行没有竖放的砖块，我们只需要保证最后一行都是 1。

用 `dp[i][j]` 表示第 i 行状态为 j 的方案数，那么 `dp[n][2^m-1] ` 就是答案。

之后就是 bottom-up 过程了，值得注意的是有许多非法情况需要判断。

1. 例如第 `i` 行第 `k` 位已经是 0，那么 `i-1` 行对应位一定是 1，否则非法。如果合法继续检测 `(i,k+1)`。
2. `(i,k)=1`，那么继续分类：
   1. `(i-1,k)=0`，合法，继续检测 `(i,k+1)`。
   2. `(i-1,k)=1`，则只可能是 `(i,k+1)=(i-1,k+1)=1`，否则非法。如果合法继续检测 `(i,k+2)`。
3. 对于第一行：
   1. `(0,k)=0`，继续检测 `(0,k+1)`。
   2. `(0,k)=1`，则 `(0,k+1)=1`，继续检测 `(0,k+2)`。
4. 任意需要检测 `(0,k+2)` 且 `k==m-1` 的情况，都是非法的。

嗯，就这么多。

```cpp
#include <bits/stdc++.h>
using namespace std;

const int maxrow = 11;
const int maxstat = 1<<11;
int h, w;
long long dp[maxrow][maxstat];

inline bool first_ok(int stat)
{
    for (int i = 0; i < w;)
        if (stat & (1<<i))
        {
            if (i == w-1 || !(stat & (1<<(i+1))) )
                return 0;
            i += 2;
        }else ++i;
    return 1;
}

inline bool judge(int a, int b)
{
    for (int i = 0; i < w;)
    {
        if (!(a & (1<<i)))
        {
            if (!(b & (1<<i))) return 0;
            ++i;
        }else
        {
            if (!(b & (1<<i))) ++i;
            else if (i == w-1 || !(( a & (1<<(i+1)) ) && (b & (1<<(i+1)) )))
                return 0;
            else i += 2;
        }
    }
    return 1;
}

int main()
{
    while (cin>> h >> w)
    {
        if (!h && !w) break;
        if (w> h) swap(w, h);
        int all = 2 <<(w-1);
        memset(dp, 0, sizeof dp);
        for (int i = 0; i < all; ++i)
            if (first_ok(i)) dp[0][i] = 1;
        for (int i = 1; i < h; ++i)
            for (int j = 0; j < all; ++j)
                for (int k = 0; k < all; ++k)
                    if (judge(j, k)) dp[i][j] += dp[i-1][k];
        printf("%lld\n", dp[h-1][all-1]);
    }
    return 0;
}
```
