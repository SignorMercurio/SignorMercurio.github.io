---
title: EOJ 新生训练
date: 2018-02-13 15:21:35
tags:
  - 数学
  - 快速幂
  - 搜索
  - Hash
categories:
  - 算法
---

记录了新生训练上遇到的一些奇怪题，主要是 Week2 遇到的。

<!--more-->

{{< katex >}}

## Week 2

总体来说不好做…… 但是确实也不难。

### A

> 给定正整数 n，k，求 $f(n,k)=\sum^n_{i=1}i^k$，结果对 19260817 取模。
> 1 <= n <= 1e7, 0 <= k <= 1e9
> 时限 0.698s（？？？）

上来用拉格朗日插值法直接 WA。。正解其实比想象的简单。先欧拉筛出素数，对素数用快速幂求出 $i^k$ 存起来。然后对合数的 $i^k$ 只要用素数的结果求就可以了。

```cpp
#include<bits/stdc++.h>
using namespace std;

typedef long long ll;
const int p = 19260817;
const int maxn = 1e7+5;

bool flag[maxn];
ll f[maxn], prime[maxn], n, k, cnt;

inline ll pow_mod(ll a, ll b)
{
    ll res = 1;
    while (b)
    {
        if (b & 1) res = res * a % p;
        a = a * a % p;
        b >>= 1;
    }
    return res;
}

inline void sieve()
{
    for (int i = 2; i <= n; ++i)
    {
        if (!flag[i])
        {
            prime[cnt++] = i;
            f[i] = pow_mod(i, k);
        }
        for (int j = 0; j < cnt && i * prime[j] <= n; ++j)
        {
            flag[i * prime[j]] = 1;
            f[i * prime[j]] = f[i] * f[prime[j]] % p;
            if (i % prime[j] == 0) break;
        }
    }
}

int main()
{
    scanf("%lld%lld", &n, &k);
    ll sum = 1;
    sieve();
    for (ll i = 2; i <= n; ++i)
        sum = (sum + f[i]) % p;
    printf("%lld\n", sum);
    return 0;
}
```

### B

> 给出一个长度为 N 的整数数列 A，对于这个数列进行任意多操作。每次选择一个任意的整数，并将任意 P 个数字加上这个数字。输出 YES 或 NO，表示能否通过这种方法将这个数列中每个数字同时变成零。
> 1 ≤ P ≤ N ≤ 1e5, |Ai| <= 1e6

结论题。显然当 `n==p` 时只有所有数字相等时才是 YES；`n>p` 时，数字总和如果是 p 的倍数则 YES。其实凭感觉可以想到：要把所有数字变成 0，和必须是 p 的倍数。不过严格的证明则是将所有 `n>p` 的情况转化为 `n==p+1` 的情况。

```cpp
#include <bits/stdc++.h>
using namespace std;

int n, p, i, tmp, sum;

int main()
{
    cin >> n >> p;
    if (n == p)
    {
        scanf("%d", &tmp);
        for (i = 1; i < n; ++i)
        {
            scanf("%d", &sum);
            if (sum != tmp) break;
        }
        printf("%s\n", i == n ? "YES" : "NO");
    }else
    {
        for (i = 0; i < n; ++i)
        {
            scanf("%d", &tmp);
            sum += tmp;
        }
        printf("%s\n", sum % p ? "NO" : "YES");
    }
    return 0;
}
```

### C

> 给任意一个大于 1 的正整数 N, 输出 N 可以分解成最少几个质数 (可以相同) 的和。
> 2 ≤ N ≤ 1e15

据说是 Codeforces 原题。
如果本身是质数那么直接输出 1。
运用哥德巴赫猜想，任何大于 2 的偶数可以被分解为两个质数之和。也就是偶数输出 2。
如果 n 是奇合数但还可以被分解为两个质数，那只可能是一奇一偶。偶质数只能是 2，也就是说 n-2 必须是质数。
其他情况输出 3。

```cpp
#include <bits/stdc++.h>
using namespace std;

typedef long long ll;
ll n;

inline bool isprime(ll m)
{
    for (ll i = 2; i * i <= m; ++i)
        if (!(m % i)) return 0;
    return 1;
}

int main()
{
    cin >> n;
    if (n == 2) printf("1\n");
    else if (!(n&1)) printf("2\n");
    else if (isprime(n)) printf("1\n");
    else if (isprime(n-2)) printf("2\n");
    else printf("3\n");
    return 0;
}
```

### D

> 给出 n 个正整数，问有多少种方法在这 n 个数字的中取其中一些数字，使得这些数字之和超过 k。若答案超过 20 000 000，输出 -1。
> 1 ≤ n ≤ 1e4
> 1 ≤ ai ≤ 1e8
> 1 ≤ k ≤ 1e10

降序排序，预处理前缀和，然后 dfs + 剪枝。
最优性剪枝：如果当前和已经大于 k 则剪枝，`ans` 要加上 `2^(剩余数字个数)`——这一步还可以剪枝：由于 `2^25>2e7`，所以一旦剩余数字个数大于等于 25 也剪枝。
可行性剪枝：如果当前和加上后面所有数（用前缀和）都不大于 k 那么剪枝。

```cpp
#include <bits/stdc++.h>
using namespace std;

typedef long long ll;
const int maxn = 1e4+5;
int a[maxn], n, ans;
bool flag;
ll k, suma[maxn];

inline void dfs(int dep, ll sum)
{
    if (flag || sum + suma[n]-suma[dep-1] <= k) return;
    if (sum> k)
    {
        n-dep+1 >= 25 ? flag = 1 : ans += 1<<(n-dep+1);
        return;
    }
    dfs(dep+1, sum + a[dep]);
    dfs(dep+1, sum);
}

int main()
{
    cin >> n >> k;
    for (int i = 1; i <= n; ++i)
        scanf("%d", a+i);
    sort(a+1, a+1+n, greater<int>());
    for (int i = 1; i <= n; ++i)
        suma[i] = suma[i-1] + a[i];
    dfs(1, 0);
    printf("%d\n", flag ? -1 : ans);
    return 0;
}
```

### E

> 给出整数数列 $\{an\}$，对整个数列进行尽可能少的次数操作，每次操作可以将数列中任意一项加 1 或者减 1，使得最终的数列 $b_1,b_2,b_3,…,b_n$ 满足对数列中的任一项 $b_i(i>=2)$，有 $b_i=b_{i−1}+i$。
> 求最少的操作次数。1 ≤ n ≤ 1e5，1 ≤ $a_i$ ≤ 1e10

设 $\{c_n\}=\{a_1,a_2-2,a_3-5,a_4-9...\}$，这题等价于求 $|c_1-x|+|c_2-x|+...+|c_n-x|$ 的最小值。根据高中函数知识，$x$ 应该取 $\{c_n\}$ 的中位数。那么我们构造出 $\{c_n\}$ 然后排下序取中间下标，这题就做完了……

```cpp
#include <bits/stdc++.h>
using namespace std;

typedef long long ll;
const int maxn = 1e5+5;
ll a[maxn], b[maxn], ans;
int n;

inline ll fun(ll mid)
{
    ll ret = 0;
    for (int i = 1; i <= n; ++i)
        ret += abs(mid - a[i]);
    return ret;
}

int main()
{
    cin >> n;
    b[2] = 2;
    for (int i = 3; i <= n; ++i)
        b[i] = b[i-1] + i;
    for (int i = 1; i <= n; ++i)
    {
        scanf("%lld", a+i);
        a[i] -= b[i];
    }
    sort(a+1, a+1+n);
    printf("%lld\n", fun(a[(n+1)>>1]));
    return 0;
}
```

### F

> 对于给定的数字串 $a_1,a_2,a_3,…,a_n$，每次可以进行如下操作: 选择一个数 i (1 < i < n)，将 $a_i$ 变成 $a_{i+1}+a_{i−1}−a_i$。问在经过任意多次的操作后，该数列的数字总和最小为多少？
> 1 ≤ n ≤ 1e5，0 ≤ $a_i$ ≤ 1e10

令 $c_i=a_{i+1}-a_i$，这样 c 数列有 n-1 项。注意到对 $a_i$ 的操作等价于交换 $c_i$ 与 $c_{i+1}$，那么通过将 c 升序排序后反构造出的 a 数列就是总和最小的数列啦。

```cpp
#include <bits/stdc++.h>
using namespace std;

typedef long long ll;
const int maxn = 1e5+5;
ll a[maxn], c[maxn], sum;

int main()
{
    int n;
    cin >> n;
    for (int i = 0; i < n; ++i)
        scanf("%lld", a+i);
    for (int i = 0; i < n-1; ++i)
        c[i] = a[i+1] - a[i];
    sort(c, c + n-1);
    sum = a[0];
    for (int i = 1; i < n; ++i)
    {
        a[i] = a[i-1] + c[i-1];
        sum += a[i];
    }
    printf("%lld\n", sum);
    return 0;
}
```

## Week 3

### D

> n 个椅子，c 种颜色排成一圈，间隔 1m。随机选一种颜色，你要马上移动到这种颜色的椅子上（原本颜色相同则不动）。求走动距离的最小期望（输出最简分数）。
> 1 ≤ c ≤ n ≤ 1e6

据说暴力模拟 + 优化（$O(n^2)\rightarrow O(nlogn)$？）2.5s 内可过…… 不过这里用了一些数学知识，复杂度降到 $O(n)$。
首先肯定是常规的环拆链操作：复制一份放到后面去。这样就可以规定正方向为向右，从左往右扫描了。
要求出答案，关键在于求出要坐的这个位置。要求出这个位置，无疑需要求出位置 i 到各个颜色椅子的最短期望距离和 $d(i)$。
设 $D(i,k)$ 为椅子 i 到颜色为 k 的椅子的最短期望距离。即：$$d(i)=\sum_{k=1}^cD(i,k)$$
我们发现，对每一个 k，$D(i,k)$ 是一个关于 i 的分段函数：

1. i 在距离最近的颜色为 k 的椅子左边，则 i 每右移一次，离该椅子的距离 - 1，此时 $D'(i,k)=-1$；
2. 同理，i 在距离最近的颜色为 k 的椅子右边，则 i 每右移一次，离该椅子的距离 + 1，此时 $D'(i,k)=+1$；
3. 于是在中间某个时刻，我们移动到了这张椅子上，此时 $D'(i,k)=0$，这里是函数的驻点。再求（伪）二阶导，由于一阶导在这个点从 -1 变成了 + 1，我们可以认为（伪）二阶导 $D''(i,k)=+2$。（这样设定二阶导是为了方便后面求一阶导和答案）

再考虑两个相邻的同色（k）椅子：当经过两者中点前，我们离左边椅子的距离小于离右边椅子的距离，反之亦然。也就是说，在经过两者中点时，$D'(i,k)$ 由 + 1 变为了 - 1（中间的椅子数为奇时，会在中点处变为 0）。
因此，需要对 $\text{ceil}((i+j)/2)$ 和 $\text{floor}((i+j)/2)$ 这两个点（中间的椅子数为奇时，一个点）的二阶导分别减 1。

综上，二阶导处理完毕。对二阶导求前缀和并且每项减 c，得到一阶导。再对一阶导求前缀和（注意特判，第 0 个位置就是 -c），得到每个位置的 $d(i)$，最后取最小值，这题就终于做完了……

```cpp
#include <bits/stdc++.h>
using namespace std;

typedef long long ll;
const int maxn = 2e6+5;
int n, c, a[maxn], nxt[maxn];
ll d[maxn];

ll gcd(ll a, ll b)
{
    return b ? gcd(b, a%b) : a;
}

int main()
{
    cin >> n >> c;
    for (int i = 1; i <= n; ++i)
        scanf("%d", a+i);
    for (int i = n+1; i <= (n<<1); ++i)
        a[i] = a[i-n];
    n <<= 1;
    for (int i = n; i>= 1; --i)
    {
        d[i] += 2;
        int &j = nxt[a[i]];
        if (j)
        {
            d[(i+j)>>1] -= 1;
            d[(i+j+1)>>1] -= 1;
        }
        j = i;
    }
    for (int i = 1; i <= n; ++i)
        d[i] += d[i-1];
    d[0] = -c;
    for (int i = 1; i <= n; ++i)
        d[i] += -c;
    ll sum = 0;
    for (int i = 1; i <= n; ++i)
    {
        int &j = nxt[a[i]];
        if (j)
        {
            sum += i;
            j = 0;
        }
    }
    ll ans = (ll)n * n;
    for (int i = 1; i <= n; ++i)
    {
        sum += d[i-1];
        if (sum < ans) ans = sum;
    }
    ll g = gcd(ans, c);
    ans /= g;
    c /= g;
    printf("%lld/%d\n", ans, c);
}
```

### E

> EOJ 的登录系统爆出了一个重大问题，当正确的密码是你输入的密码的子串时，就可以成功登录！
> 例如你的密码是 abc，则你输入 abcc，aabc，甚至 dfjklsdfabcsdjfkl，都可以成功登录！
> 出现了这么大的问题，那就一定要有人来背锅，管理员们希望在背锅之前先衡量一下锅的大小。
> 现在有一份 EOJ 用户的密码表，里面包含了 n 个用户的密码，第 i 个用户的密码是 pwdi。我们定义锅的大小为所有有序对 (i,j) (i≠j) 的数量，使得用户 i 能够输入他的密码 pwdi 成功登陆用户 j 的账户。
> 换句话说，我们现在需要知道，有多少有序对 (i,j) (i≠j) 使得 pwdj 是 pwdi 的子串。
> 第 1 行包含一个整数 n，1≤n≤20 000，表示密码表中密码的数量。
> 第 1+i (1≤i≤n) 行包含一个长度不超过 10 且由小写字母组成的字符串，表示 pwdi。

因为长度太短了，所以可以直接枚举子串（每个密码最多 55 个子串），hash 一下存进 `map` 里统计子串的出现次数。然后对于每个密码，计算其在子串中出现的次数。记得要减去 n，因为每个密码也一定是自己的子串。

```cpp
#include <bits/stdc++.h>
using namespace std;

const int maxn = 20005;
typedef long long ll;
ll SS[maxn];
set<ll> S[maxn];
map<ll, int> m;
char s[15];
int n, ans, len;

int main()
{
    cin >> n;
    for (int i = 0; i < n; ++i)
    {
        scanf("%s", s);
        len = strlen(s);
        for (int j = 0; j < len; ++j)
        {
            ll h = 0;
            for (int k = j; k < len; ++k)
            {
                h = h * 29 + s[k]-'a'+1;
                S[i].insert(h);
                if (!j && k+1 == len) SS[i] = h;
            }
        }
        for (auto x: S[i]) ++m[x];
    }
    for (int i = 0; i < n; ++i)
        ans += m[SS[i]];
    printf("%d\n", ans-n);
    return 0;
}
```

## Week 4

### D

有一个数列 $A_n$，其中 $A_1=1,A_2=2,A_{n+2}=A_{n+1}+A_n$。
给你一个数字，问他是这个数列的第几项。
每行包括数列中的一项 $A_k$ (k≤100000)。
总行数 T≤100。

看到标题以为是很水的题……
实际上，斐波那契数列的 100000 项是一个超出 `long long` 范围的数，因此一开始考虑用高精度。后来发现数据加强了，时限和内存又比较紧 (卡掉了我的 python 预处理算法 && python 滚动暴力算法 && C++ 高精度 + 二分查找算法)，只能使用一些技巧。
类似 hash，用一个大质数（比如 19260817）将斐波那契数列的各项 hash 掉，再利用同余定理查找答案，就做完了……？

```cpp
#include <bits/stdc++.h>
using namespace std;

const int maxn = 1e5+5;
const int p = 19260817;
int now, f[maxn];
map<int, int> m;
string s;

int main()
{
    f[0] = f[1] = 1;
    m[1] = 1;
    for (int i = 2; i < maxn; ++i)
    {
        f[i] = (f[i-1] + f[i-2]) % p;
        m[f[i]] = i;
    }
    while (cin>> s)
    {
        now = 0;
        for (auto &i: s)
            now = (now*10 + i-'0') % p;
        printf("%d\n", m[now]);
    }
    return 0;
}
```
