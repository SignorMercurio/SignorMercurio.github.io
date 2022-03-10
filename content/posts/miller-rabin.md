---
title: Miller-Rabin 素性测试与二次探测
tags:
  - 数学
date: 2018-01-19 16:34:53
categories:
  - 算法
math: true
---

贴定理和模板的，不是教程。

<!--more-->

## 算法简介

首先是一些概念：

- *费马小定理*：对于素数 p 和任意整数 a，有 $a^p ≡ a(mod\ p)$.
- 反之，对于一个数 p，如果满足 $a^p ≡ a(mod\ p)$，则 p **很可能**是素数。
- *伪素性测试*：瞎猜若干个 x，只要不满足上式，那么 p 就不是素数。看起来没毛病了。
- *Carmichael 数*：对于合数 n，如果对所有正整数 b（b 和 n 互素）都有 $b^{n-1}≡ 1 (mod\ n)$ 成立，则合数 n 为 Carmichael 数。比如 561。这种数的存在使得上面的方法沦为 “伪素性测试”。
- *二次探测定理*：如果 p 是奇素数，x 是小于 p 的正整数，则 $x^2 ≡ 1(mod\ p)$ 的解为 $x = 1$ 或 $x = p - 1(mod\ p)$，这是由模运算的循环特性导致的。

利用二次探测定理，只需要探测 s 次就可以将错误率降到 $2^{-s}$（好像是这样吧。。反正很低就对了），因此也不会多花多少时间。
记得判素时的细节处理以及快速幂取模。

## 代码

很简洁的模板：

```cpp
#include <cstdio>
using namespace std;

typedef long long ll;

ll prime[5] = {2, 3, 5, 233, 331};

ll pow_mod(ll a, ll n, ll mod)
{
    ll ret = 1;
    while (n) {
        if (n & 1) ret = ret * a % mod;
        a = a * a % mod;
        n >>= 1;
    }
    return ret;
}

int miller_rabin(ll n)
{
    if (n < 2 || (n != 2 && !(n & 1))) return 0;
    ll s = n - 1;
    while (!(s & 1)) s >>= 1;
    for (int i = 0; i < 5; ++i) {
        if (n == prime[i]) return 1;
        ll t = s, m = pow_mod(prime[i], s, n);
        while (t != n - 1 && m != 1 && m != n - 1) {
            m = m * m % n;
            t <<= 1;
        }
        if (m != n - 1 && !(t & 1)) return 0;
    }
    return 1;
}

int main()
{
    ll n;
    while (~scanf("%lld", &n))
        printf("%s\n", miller_rabin(n) ? "YES" : "NO");
    return 0;
}
```
