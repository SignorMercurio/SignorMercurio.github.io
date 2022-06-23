---
title: 简单 DFS 题合集
date: 2018-01-04 13:29:20
tags:
  - 搜索
  - 模版
categories:
  - 算法
---

题目全部来自 EOJ。新年开始用 C++ 了。

<!--more-->

## 1012 The 3n+1 Problem

> 对一个数，如果是奇数则乘 3 加 1，是偶数则除以 2。重复直至变为 1，总操作次数记为 `c`。给定区间 `[i,j]`，求区间内最大可能取到的 `c` 的值。

### 说明

按照题意，**离线** DFS 即可。

```cpp
#include <stdio.h>
#define MAX 1000000

int sum[MAX + 1], m, n;

int dfs(long long k)
{
    if (k <= MAX && sum[k]) return sum[k];
    int ans = 1;
    if (k % 2) ans += dfs(3 * k + 1);
    else ans += dfs(k / 2);
    if (k <= MAX) sum[k] = ans;
    return ans;
}

int main()
{
    int i, j, k, max;
    sum[1] = 1;
    for (i = 2; i <= MAX; ++i) sum[i] = dfs(i);
    while(~scanf("%d%d", &i, &j)){
        printf("%d %d", i, j);
        if (i> j){int tmp = i; i = j; j = tmp;}
        max = 0;
        for (k = i; k <= j; ++k) if (sum[k] > max) max = sum[k];
        printf("%d\n", max);
    }
    return 0;
}
```

## 1114 素数环

> 一个由自然数 1…n (n≤18) 素数环就是如下图所示，环上任意两个节点上数值之和为素数。
>    1
>   / \\
> 4   2
>   \ /
>    3
> 要求建立一个从 1 到 n 的素数环。

### 说明

考虑到数据范围较小，我们先用 `prime` 数组存放素数。然后 DFS 与相邻数之和是否为素数，最后特判头和尾之和的情况。

```cpp
#include<bits/stdc++.h>
using namespace std;

int n, prime[50] = {0,0,1,1,0,1,0,1,0,0,0,1,0,1,0,0,0,1,
0,1,0,0,0,1,0,0,0,0,0,1,0,1,0,0,0,0,0,1,0,1,0,1,0,1,0}, vis[50], a[50] = {1};

void dfs(int now)
{
    if (now == n && prime[a[0]+a[n-1]]) {
        for (int i = 0; i < n - 1; ++i)
            printf("%d", a[i]);
        printf("%d\n", a[n-1]);
    }
    else
        for (int i = 2; i <= n; ++i)
            if (!vis[i] && prime[i+a[now-1]]) {
                a[now] = i;
                vis[i] = 1;
                dfs(now+1);
                vis[i] = 0;
            }
}

int main()
{
    cin >> n;
    dfs(1);
    return 0;
}
```

## 1130 n 皇后问题

> 利用回溯法计算 `n*n` 棋盘中摆放 n 个皇后的方案数。

### 说明

规则是两个皇后不能在同一直线 / 斜线上。注意好 if 语句的条件以及行列关系。

```cpp
#include <cstdio>
#include <cmath>
using namespace std;

int n, cnt, pos[10];

bool ok(int row)
{
    for (int i = 0; i < row; ++i)
        if((pos[row] == pos[i]) || (abs(row-i) == abs(pos[row]-pos[i])))
            return false;
    return true;
}

void queen(int row)
{
    int col;
    if (row == n) ++cnt;
    else
        for (col = 0; col < n; ++col){
            pos[row] = col;
            if (ok(row)) queen(row+1);
        }
}

int main()
{
    int t;
    while(~scanf("%d", &t)){
        while(t--){
            cnt = 0;
            scanf("%d", &n);
            queen(0);
            printf("%d\n", cnt);
        }
    }
    return 0;
}
```

## 2457 Expressions

> 给出后缀表达式，调换次序使得用队列计算所得结果与用栈计算相同。其中小写字母是操作数，大写字母是运算符。如：

```
Input:
2
xyPzwIM
abcABdefgCDEF

Output:
wzyxIPM
gfCecbDdAaEBF
```

### 说明

从后往前读，遇到操作数就存入数组，遇到运算符就继续 DFS 两次（对应这一运算符的两个操作数）。最后倒序输出数组。

```cpp
#include <bits/stdc++.h>
using namespace std;

string s;
vector<string> v;
int pos;

void dfs(int d)
{
    if (pos < 0) return;
    v[d] += s[pos--];
    if (islower(s[pos+1])) return;
    dfs(d+1);
    dfs(d+1);
}

int main()
{
    int t;
    cin >> t;
    while (t--) {
        cin >> s;
        v.assign(s.size(), "");
        pos = s.size()-1;
        dfs(0);
        for (vector<string>::reverse_iterator it = v.rbegin(); it != v.rend(); ++it)
            cout << *it;
        cout << endl;
    }
    return 0;
}
```

## 2856 仰望星空

> 用邻接矩阵的方式给出图，求图中八连通块个数。

### 说明

各大 OJ 上都有的经典 DFS 入门题。
一种类似模板的写法（稍加改动可以求四连通块、最大连通块、次大连通块等等）：
遍历所有不为空的点，向四个方向 DFS 并把走过的地点标记为空。DFS 次数即为连通块个数。

```cpp
#include <cstdio>

int row, col, a[1005][85];

void dfs(int x, int y)
{
    a[x][y] = 0;
    for (int dx = -1; dx <= 1; ++dx)
        for (int dy = -1; dy <= 1; ++dy) {
            int nx = x + dx, ny = y + dy;
            if (0 <= nx && nx < row && 0 <= ny && ny <= col && a[nx][ny])
                dfs(nx, ny);
        }
}

int main(void)
{
    char tmp;
    int i, j;
    while(~scanf("%d%d\n", &col, &row)){
        int cnt = 0;
        for (i = 0; i < row; ++i){
            for (j = 0; j < col; ++j){
                scanf("%c", &tmp);
                if (tmp =='*') a[i][j] = 1;
            }
            getchar();
        }
        for (i = 0; i < row; ++i)
            for (j = 0; j < col; ++j)
                if (a[i][j]){
                    dfs(i, j);
                    ++cnt;
                }
        printf("%d\n", cnt);
    }
    return 0;
}
```

## 2859 表达式的个数

> 给定 `123456789`，在 **数字中** 添加 `+` 和 `-`，或者什么都不加，会得到一个表达式，当然你肯定会算这个表达式的值。然后如果给你这个表达式的值，你会求有多少个不同的表达式能够得到这个值呢？

### 说明

由于本题数字特殊，可以用数字本身来移动要 DFS 的位置。位置确定后对加号减号分别 DFS。由于需要加在数字中，所以减号不能加在开头。

```cpp
#include <cstdio>
#include <map>
using namespace std;

map<int, int> ans;
typedef long long ll;

void dfs(ll sum, int cnt)
{
    if (cnt> 9){
        ++ans[sum];
        return;
    }
    ll ret = 0;
    for (int i = cnt; i <= 9; ++i){
        ret = ret * 10 + i;
        dfs(sum + ret, i + 1);
        if (cnt> 1) dfs(sum - ret, i + 1);
    }
}

int main(void)
{
    int n;
    dfs(0, 1);
    while(~scanf("%d", &n)) printf("%d\n", ans[n]);
    return 0;
}
```

## 2912 放书

> 在书架上放有编号为 `1,2,…,n` 的 n 本书。现将 n 本书全部取下然后再放回去，当放回去时要求每本书都不能放在原来的位置上。
> 例如 `n=3` 时：原来位置为：`1,2,3`。放回去时只能为：`3,1,2` 或 `2,3,1` 这两种。
> 对于每一个 n，求满足上面的条件的放法有多少？
> 对于每组测试数据，如果 `n<8`，输出每种放法（每种放法占一行，放法按照字典序从小到大排列），如果 `n>=8`，只需要输出放法总数。

### 说明

如果只需要输出放法总数，那么可以直接套用错排公式 `D(n)=(n-1)[D(n-2)+D(n-1)]` 或者 `D(n)=[n!/e+0.5]`。不过本题对于 `n<8` 的情况需要输出具体方法，所以依然得靠 DFS 来实现。

```cpp
#include<bits/stdc++.h>
using namespace std;

int v[11], a[11], n, cnt;

void dfs(int d)
{
    if (d == n+1) {
        if (n < 8) {
            for (int i = 1; i <= n; ++i)
                cout <<a[i];
            cout << endl;
        }else ++cnt;
        return;
    }
    for (int i = 1; i <= n; ++i) {
        if (!v[i]) {
            v[i] = 1;
            if (i != d) {
                if (n < 8) a[d] = i;
                dfs(d+1);
            }
            v[i] = 0;
        }
    }
}

int main()
{
    int t;
    cin >> t;
    while (t--) {
        cin >> n;
        cnt = 0;
        memset(v, 0, sizeof(v));
        dfs(1);
        if (n>= 8) cout << cnt << endl;
    }
    return 0;
}
```

## 3279 爱狗狗的两个 dalao

> n 只重量为 `w1...wn` 的狗装入载重为 M 的缆车，求最少需要多少缆车。
> `1<=n<=18`
> `1<=M<=1e9`

### 说明

由于 M 较大，难以用上背包 DP，只能搜索来做。

```cpp
#include<bits/stdc++.h>
using namespace std;

const int maxn = 20;
int w[maxn], dp[maxn], n, m, ans;

bool dfs(int x)
{
    if (x> n) return 1;
    for (int i = 1; i <= x && i <= ans; ++i)
        if (dp[i] + w[x] <= m) {
            dp[i] += w[x];
            if(dfs(x+1)) return 1;
            dp[i] -= w[x];
        }
    return 0;
}

int main()
{
    cin >> n >> m;
    for (int i = 1; i <= n; ++i) cin >> w[i];
    sort(w+1, w+n+1, greater<int>());
    for (ans = 1; ans <= n; ++ans) {
        memset(dp, 0, sizeof(dp));
        if (dfs(1)) break;
    }
    cout << ans << endl;
    return 0;
}
```