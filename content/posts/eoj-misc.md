---
title: EOJ 杂题合集
date: 2018-02-02 15:49:41
tags:
  - 正则表达式
  - 搜索
  - 最大区间和
  - 线段树
  - 矩阵
  - 快速幂
  - 数学
  - 图论
  - 模版
categories:
  - 算法
math: true
---

整理了 EOJ 中遇到的一些值得一记的题目。

<!--more-->

## EOJ1424 Hard to Believe, but True!

> 给定一个等式，问等式从右往左读是否正确。

题目不难，不过用到了一些有趣的字符串处理，所以记录下来。

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void rev_str(char s[]){
    int c,i,j, len = strlen(s);
    for (i = 0, j = len - 1; i < j; i++, j--){
        c = s [i];
        s[i] = s[j];
        s[j] = c;
    }
}

int main()
{
    char str1[8]={0},str2[8]={0},str3[8]={0};
    while (~scanf("%[^+]+%[^=]=%s", str1, str2, str3)){
        rev_str(str1);rev_str(str2);rev_str(str3);
        if (atoi(str3) == atoi(str2) + atoi(str1))
	        printf("True\n");
        else printf("False\n");

        if (atoi(str3) == 0 && atoi(str2) == 0 && atoi(str1) == 0) break;
    }
    return 0;
}
```

## EOJ3322 万年历

> 给定一个日期，输出该日期是星期几。

这是个历史题，就是所谓 OEIS 题的同类。

### 为什么说是历史题？

> 罗马教皇格里高利十三世在 1582 年组织了一批天文学家，根据哥白尼日心说计算出来的数据，对儒略历作了修改。将 1582 年 10 月 5 日到 14 日之间的 10 天宣布撤销，继 10 月 4 日之后为 10 月 15 日。后来人们将这一新的历法称为 “格里高利历”，也就是今天世界上所通用的历法，简称格里历或公历。

### 所以怎么算星期几？

1. _蔡勒公式 (Zeller formula)：_

   - **1582.10.4 后：**
     $$ w=(y+[\frac{y}{4}]+[\frac{c}{4}]-2c+[\frac{13(m+1)}{5}]+d-1)\%7 $$
   - **1582.10.4 及之前：**
     $$ w=(y+[\frac{y}{4}]+[\frac{c}{4}]-2c+[\frac{13(m+1)}{5}]+d+2)\%7 $$

   其中 m, d 对应月日，c 为年份前两位（世纪数 ** 减 1**），y 为年份后两位。

2)  _基姆拉尔森公式 (Kim larsson calculation formula)：_
    $$ w=(d+2m+[\frac{3(m+1)}{5}]+y+[\frac{y}{4}]-[\frac{y}{100}]+[\frac{y}{400}]+1)\%7 $$

    需要注意的是，基姆拉尔森公式的结果为 0 时表示周一，6 表示周日，以此类推。

### 注意事项

- 两个公式都需要把每年的 1，2 两月看作上一年的 13，14 两月。
- 另有一种需要事先计算年月基数表的计算方法，由于较繁琐这里不再赘述。

### 代码

（仅以蔡勒公式为例）

```c
#include <stdio.h>

void calc_day(int y, int m, int d)
{
    if (m == 1 || m == 2){                                              // 1 月 2 月情况特判
        --y;
        m += 12;
    }
    int c = y / 100;                                                    // 取年份前两位
    int yy = y - c * 100;                                               // 取年份后两位
    int day = yy + yy / 4 + c / 4 - 2 * c + 13 * (m + 1) / 5 + d - 1;   // 蔡勒公式
    if (y <= 1582 && m <= 10 && d <= 4) day += 3;                       // 判断是否在 1582 年 10 月 4 日前

    while (day < 0) day += 7;                                           // 结果可能为负，这里避免了容易出错的负数取模运算
    day %= 7;

    switch(day){
    case 1: printf("Monday\n");break;
    case 2: printf("Tuesday\n");break;
    case 3: printf("Wednesday\n");break;
    case 4: printf("Thursday\n");break;
    case 5: printf("Friday\n");break;
    case 6: printf("Saturday\n");break;
    default: printf("Sunday\n");
    }
    return;
}

int main(void)
{
    int y, m, d;
    scanf("%d-%d-%d", &y, &m, &d);
    calc_day(y, m, d);
    return 0;
}
```

## EOJ1224 简单迷宫问题

> 一天，sunny 不小心进入了一个迷宫，不仅很难寻找出路，而且有的地方还有怪物，但是 sunny 有足够的能力杀死怪物，但是需要一定的时间，但是 sunny 想早一点走出迷宫，所以请你帮助他计算出最少的时间走出迷宫，输出这个最少时间。
我们规定每走一格需要时间单位 1, 杀死怪物也需要时间 1, 如果不能走到出口，则输出 impossible. 每次走只能是上下左右 4 个方向。

先四面造墙，省去判断是否出界的函数。之后对于有怪物的格子，新状态再搜索树中是当前状态的下两层的，因此不能走过之后直接 `step+2` 标记掉，而是要记录下这个状态 (`cnt=1`)。很容易 WA 的点。

```cpp
#include <cstdio>
#include <queue>
using namespace std;
#define NEXT mp[p.x+dx[i]][p.y+dy[i]]
struct node{int x, y, step, cnt;};

char mp[202][202];
int sx, sy, n, m, i;
const int dx[4] = {-1, 0, 1, 0};
const int dy[4] = {0, 1, 0, -1};

void bfs()
{
    queue<node> q;
    q.push({sx, sy, 0, 0});
    mp[sx][sy] = '#';
    while (!q.empty()){
        node p = q.front();
        q.pop();
        if (p.cnt == 1){
            p.cnt = 0;
            q.push(p);
            continue;
        }
        for (i = 0; i < 4; ++i)
            switch(NEXT){
                case '.': NEXT = '#'; q.push({p.x+dx[i], p.y+dy[i], p.step+1, 0}); break;
                case 'X': NEXT = '#'; q.push({p.x+dx[i], p.y+dy[i], p.step+2, 1}); break;
                case 'T': printf("%d\n", p.step+1); return;
            }
    }
    printf("impossible\n");
}

void init()
{
    sx = sy = 0;
    for (i = 1; i <= n; ++i){
        for (int j = 1; j <= m; ++j){
            scanf("%c", &mp[i][j]);
            if (mp[i][j] == 'S') sx = i, sy = j;
        }
        getchar();
    }
    for (i = 0; i <= m+1; ++i)
        mp[0][i] = mp[n+1][i] = '#';
    for (i = 0; i <= n+1; ++i)
        mp[i][0] = mp[i][m+1] = '#';
}

int main()
{
    while (~scanf("%d%d\n", &n, &m)){
        init();
        bfs();
    }
    return 0;
}
```

## EOJ3367 咸鱼翻身

> 给定 01 序列，选择一个区间，对区间中每个数取反（0 变 1，1 变 0），求 1 最多能有多少个。

最大区间和问题。对于 1，翻转后收益（1 的个数）为 -1；对于 0，翻转后收益为 +1。方便起见，读入时直接把数字转换为收益。最后求最大区间和，加上原来 1 的个数就是答案。由于和最大的区间中不会有 -1 出现，区间所覆盖的位置也不会包括原来 1 所在的位置，因此不会重复。

```c
#include <stdio.h>

int a[100001];

int main()
{
    int n,i,j,sum = 0,tot = 0,ans;

    scanf("%d", &n);
    for (i = 0; i < n; ++i){
        scanf("%d", &j);
        if (j){
            a[i] = -1;
            sum++;
        }
        else a[i] = 1;
    }
    ans = a[0];
    for (i = 0; i < n; ++i){
        if (tot> 0) tot += a[i];
        else tot = a[i];
        ans = (tot>ans)?tot:ans;
    }
    printf("%d\n", ans + sum);
    return 0;
}
```

## EOJ3388 Balanced Lineup

> 给定一个数列，求询问区间中的最大最小值之差。

普通方法用线段树或 ST 算法，对这题来说区间 RMQ 就可以了。时间复杂度 `O(nlogn)`。

```cpp
#include <cstdio>
#include <algorithm>
#include <cmath>
using namespace std;

int linemax[50001][20], linemin[50001][20];

void rmq(int n)
{
    for (int j = 1; j < 20; ++j)
        for (int i = 1; i <= n; ++i)
            if (i + (1 << j) - 1 <= n){
                linemax[i][j] = max(linemax[i][j - 1], linemax[i + (1 << (j - 1))][j - 1]);
                linemin[i][j] = min(linemin[i][j - 1], linemin[i + (1 << (j - 1))][j - 1]);
            }
}

int main(void)
{
    int n, len, a, b, x, maxc, minc;
    scanf("%d%d", &n, &len);
    for (int i = 1; i <= n; ++i){
        scanf("%d", &linemax[i][0]);
        linemin[i][0] = linemax[i][0];
    }
    rmq(n);
    while(len--){
        scanf("%d%d", &a, &b);
        x = (int)(log(b - a + 1) / log(2));
        maxc = max(linemax[a][x], linemax[b - (1 << x) + 1][x]);
        minc = min(linemin[a][x], linemin[b - (1 << x) + 1][x]);
        printf("%d\n", maxc - minc);
    }
    return 0;
}
```

## EOJ1499 矩阵快速幂求斐波那契数列

> 给定 n，求斐波那契数列前 n 项和。
> `0 < n < 1e9`

快速幂实现方式和整数差不多，没什么好讲的。而对于斐波那契数列，不难发现：

$$
\begin{pmatrix}
F_{n+2} & a\cr
F_{n+1} & b
\end{pmatrix}{=}
\begin{pmatrix}
1 & 1\cr
1 & 0
\end{pmatrix}
\begin{pmatrix}
F*{n+1}\cr
F_n
\end{pmatrix}
$$

我们记
$$
\begin{pmatrix}
1 & 1\cr
1 & 0
\end{pmatrix}
$$

为 $A$，由此我们可以推得：
$$
\begin{pmatrix}
F*{n+1}\cr
F_n
\end{pmatrix}{=}
A^n
\begin{pmatrix}
1\cr
0
\end{pmatrix}
$$
于是对 $A^n$ 求解就很容易得到答案了。

```cpp
#include <iostream>

#define MOD 100000000
using namespace std;

typedef long long ll;

struct Mat{
    ll m[2][2];
};

Mat MatMul(Mat A, Mat B)
{
    Mat ret;
    for (int i = 0; i < 2; ++i)
        for (int j = 0 ; j < 2; ++j){
            ret.m[i][j] = 0;
            for (int k = 0; k < 2; ++k)
                ret.m[i][j] += A.m[i][k] * B.m[k][j] % MOD;
        }
    return ret;
}

Mat MatPow(Mat A, ll n)
{
    Mat ret;
    ret.m[0][0]=1;
    ret.m[0][1]=0;
    ret.m[1][0]=0;
    ret.m[1][1]=1;
    while (n){
        if (n & 1)
            ret = MatMul(ret, A);
        A = MatMul(A, A);
        n >>= 1;
    }
    return ret;
}

int main()
{
    ll n;
    while(cin>> n){
        Mat ans, A;
        ans.m[0][0]=1;
        ans.m[0][1]=0;
        A.m[0][0]=1;
        A.m[0][1]=1;
        A.m[1][0]=1;
        A.m[1][1]=0;
        ans = MatMul(ans, MatPow(A, n + 1));
        cout <<ans.m[0][0] - 1 << endl;
    }
    return 0;
}
```

## EOJ3006 计算多项式的系数

> 给定一个多项式 $(ax+by)^k$，计算多项式展开后 $x^ny^m$ 项的系数，结果对 1000000007 取模
> 0≤k≤1,000,000，0≤n,m≤k，且 n+m=k，0≤a,b≤10^9。

由于 n, m 过大不能直接预处理组合数；又因为 p 过大 Lucas 定理的递归形式在这里也不能直接使用。后来才发现原来只要预处理阶乘 + 快速幂 + 逆元求组合数就可以了。

```cpp
#include <bits/stdc++.h>
#define p 1000000007
#define K 1000000

typedef long long ll;
ll a, b, k, n, m, fac[K+1];

void init()
{
    fac[0] = 1;
    for(int i = 1; i <= K; ++i)
        fac[i] = fac[i-1]*i % p;
}

ll pow_mod(ll a, ll x)
{
    ll ret = 1;
    while (x) {
        if (x & 1) ret = (ret * a) % p;
        a = (a * a) % p;
        x >>= 1;
    }
    return ret;
}

ll C(ll n, ll m)
{
    if(m> n) return 0;
    return fac[n] * pow_mod((fac[m]*fac[n-m])%p, p-2) % p;
}

int main()
{
    int cas;
    ll ans;
    scanf("%d", &cas);
    init();
    for (int t = 0; t < cas; ++t) {
        scanf("%lld%lld%lld%lld%lld", &a, &b, &k, &n, &m);
        ans = pow_mod(a, n);
        ans = (ans * pow_mod(b, m)) % p;
        ans = (ans * C(k, m)) % p;
        printf("case #%d:\n%lld\n", t, ans);
    }
    return 0;
}
```

顺便放个 Lucas 模板备用，n, m 较大而 p 较小时可用：

```cpp
#include<bits/stdc++.h>
#define P 10007
using namespace std;

typedef long long ll;

ll pow_mod(ll a, ll x, int p)
{
    ll ret = 1;
    while(x) {
        if (x & 1) ret = ret * a % p;
        a = a * a % p;
        x >>= 1;
    }
    return ret;
}

ll comb(ll a, ll b, int p)
{
    if (a < b) return 0;
    if (a == b) return 1;
    if (b> a - b) b = a - b;
    ll ans = 1, ca = 1, cb = 1;
    for (ll i = 0; i < b; ++i) {
        ca = (ca * (a - i)) % p;
        cb = (cb * (b - i)) % p;
    }
    ans = (ca * pow_mod(cb, p-2, p)) % p;
    return ans;
}

ll lucas(ll n, ll m, int p)
{
    ll ans = 1;
    while(n && m && ans) {
        ans = (ans * comb(n%p, m%p, p)) % p;
        n /= p;
        m /= p;
    }
    return ans;
}

int main()
{
    int cas, k;
    ll a, b, n, m;
    cin >> cas;
    for (int t = 0; t < cas; ++t) {
        cin >> a >> b >> k >> n >> m;
        printf("case #%d:\n", t);
        if (n + m != k) cout <<"0" << endl;
        else {
            ll ans = pow_mod(a, n, P);
            ans = (ans * pow_mod(b, m, P)) % P;
            ans = (ans * lucas(k, n, P)) % P;
            cout << ans << endl;
        }
    }
	return 0;
}
```

## EOJ3458 Cards Game

> 每次从 N 张牌中选择两张，代价为 `min(r[i]^b[j], r[j]^b[i])`, 然后从两张中选择一张删去进入下一轮，循环直至只剩一张牌，求最小代价和。

来自 Google Kickstart Round G 2017 的 B 题。MST 的奇怪用法。

可以发现有 N 张牌，N-1 次操作。在扔掉的牌与留下的牌之间连边，则边的权值 == 题目中的代价。这样求最小代价和就转化成求图的最小生成树问题，Prim 或者 Kruskal（如下代码）直接过。

```cpp
#include <bits/stdc++.h>
using namespace std;

typedef long long ll;
const int N = 101;
int r[N], b[N];
int fa[N];

int union_find(int x)
{
	return fa[x] == x ? x : fa[x] = union_find(fa[x]);
}

bool unite(int a, int b)
{
	a = union_find(a);
	b = union_find(b);
	if (a != b) {
		fa[a] = b;
		return 1;
	}
	return 0;
}

vector<tuple<int, int, int> > v;

ll kruskal()
{
    sort(v.begin(), v.end());
    ll ans = 0;
    for (auto i : v) {
        int u, v, w;
        tie(w, u, v) = i;
        if (unite(u, v))
            ans += w;
    }
    return ans;
}

int main()
{
	int cas, n, i;
	cin >> cas;
	for (int t = 1; t <= cas; ++t) {
        cin >> n;
        v.clear();
        for (i = 0; i < n; ++i) cin >> r[i];
        for (i = 0; i < n; ++i) cin >> b[i];
        for (i = 0; i < n; ++i) {
            for (int j = i+1; j < n; ++j)
                v.emplace_back(min(r[i]^b[j], r[j]^b[i]), i, j);
            fa[i] = i;
        }
		printf("Case #%d: %lld\n", t, kruskal());
	}
    return 0;
}
```

## EOJ2069 Asteroids

> N×N 网格中有若干个小行星，武器每次发射可以清除一行或一列，问最少需要发射多少次才能清除全部小行星。

所有小行星横坐标为一个点集，纵坐标为另一个点集。对于每个小行星，在其横坐标与纵坐标之间连一条边，则问题转化为求二分图最小点覆盖。又因为二分图最小点覆盖 == 二分图最大匹配，所以直接跑匈牙利就行。

```cpp
#include <bits/stdc++.h>
using namespace std;

bool path[505][505], v[505];
int ast[505], n, k;

bool dfs(int x)
{
    for (int i = 1; i <= n; ++i)
        if (!v[i] && path[x][i]) {
            v[i] = 1;
            if (!ast[i] || dfs(ast[i])) {
                ast[i] = x;
                return 1;
            }
        }
    return 0;
}

int main()
{
    int x, y, ans = 0;
    cin >> n >> k;
    while (k--) {
        scanf("%d%d", &x, &y);
        path[x][y] = 1;
    }
    for (int i = 1; i <= n; ++i) {
        memset(v, 0, sizeof(v));
        if (dfs(i)) ++ans;
    }
    printf("%d\n", ans);
    return 0;
}
```

## EOJ3384 食物链

> 动物王国中有三类动物 A,B,C，这三类动物的食物链构成了有趣的环形。A 吃 B，B 吃 C，C 吃 A。
> 现有 N 个动物，以 1－N 编号。每个动物都是 A,B,C 中的一种，但是我们并不知道它到底是哪一种。
> 有人用两种说法对这 N 个动物所构成的食物链关系进行描述：
> 第一种说法是 1 X Y，表示 X 和 Y 是同类。
> 第二种说法是 2 X Y，表示 X 吃 Y。
> 此人对 N 个动物，用上述两种说法，一句接一句地说出 K 句话，这 K 句话有的是真的，有的是假的。当一句话满足下列三条之一时，这句话就是假话，否则就是真话：
> 当前的话与前面的某些真的话冲突，就是假话；
> 当前的话中 X 或 Y 比 N 大，就是假话；
> 当前的话表示 X 吃 X，就是假话。
> 你的任务是根据给定的 N (1≤N≤50 000) 和 K 句话 (0≤K≤100 000)，输出假话的总数。

经典并查集（对我来说还是太难了）。代码中 `kind` 数组为 0 表示与父节点同类，1 表示被父节点吃，2 表示吃父节点。
初始化时，每个节点自身成为一个集合，并且父节点也是自身（0：同类）。路径压缩的时候可以顺便更新掉 `kind` 数组的状态。

`Union` 函数中：

1. 如果 `x,y` 不在一个集合中，关于合并之后 `kind` 要怎么变化，这个式子我纯粹靠找规律写了，可能网上有更靠谱的解法。
2. 如果 `x,y` 同属一个集合，那么只需要验证这句话是不是对的就可以了。

```cpp
#include <iostream>
using namespace std;

int father[50005], kind[50005];

int Find(int x)
{
    if (x == father[x]) return father[x];
    int y = Find(father[x]);
    kind[x] = (kind[x] + kind[father[x]]) % 3;
    return father[x] = y;
}

int Union(int op, int sp1, int sp2)
{
    int x = Find(sp1), y = Find(sp2);
    if (x == y){
        if ((kind[sp1] - kind[sp2] + 3) % 3 == op - 1) return 0;
        return 1;
    }
    father[x] = y;
    kind[x] = (-kind[sp1] + op - 1 + kind[sp2] + 3) % 3;
    return 0;
}

int main()
{
    int n, k, op, sp1, sp2, cnt = 0, i;
    cin >> n >> k;
    for (i = 1; i <= n; ++i){
        father[i] = i;
        kind[i] = 0;
    }
    for (i = 0;i < k; ++i){
        cin >> op >> sp1 >> sp2;
        if (op == 2 && sp1 == sp2) ++cnt;
        else if (sp1> n || sp2 > n) ++cnt;
        else cnt += Union(op, sp1, sp2);
    }
    cout << cnt << endl;
    return 0;
}
```

