---
title: 巧算数学问题
date: 2017-11-08
tags:
  - 数学
categories:
  - 算法
---

总是让人头疼又令人着迷的数学问题。

<!--more-->

{{< katex >}}

## 求 $n!$ 首位数

使用斯特林公式得到近似结果：

$$
\lim_{n\to+\infty} {n!\over{\sqrt {2 \pi n}} ({n\over e})^n} = 1
$$

之后用 10 的幂计算取首位即可，注意数字较小时特判，代码如下：

```c
#include <stdio.h>
#include <math.h>

const double PI = 3.14159265358979;
const double E = 2.718281828;

int main()
{
    int n,fn;
    double log_n_fac;
    while (scanf("%d", &n) != EOF){
        log_n_fac = 0.5 * log10(2 * PI *(double)n) + (double)n * log10((double)n / E);
        log_n_fac -=(int)log_n_fac;
        fn = pow(10, log_n_fac);//Stirling's approximation
        switch(n){
            case 0:printf("1\n");break;
            case 1:printf("1\n");break;
            case 2:printf("2\n");break;
            case 3:printf("6\n");break;
            case 7:printf("5\n");break;
            case 8:printf("4\n");break;
            default:printf("%d\n", fn);
        }
    }
    return 0;
}
```

## 求 $n^n$ 首位

方法类似，代码：

```c
#include <stdio.h>
#include <math.h>

int main()
{
    int n;
    scanf("%d",&n);
    while(n != 0){
        printf("%d\n",(int)pow(10,n*log10(n)-(int)(n*log10(n))));
        scanf("%d",&n);
    }
    return 0;
}
```

## 整数质因子分解

从小到大枚举因数，如果这个因数不是素数（如 15），那么之前枚举过的素数已经消耗掉了这个因数（如 3 和 5），因此 `n%15` 不会为 0。所以这题并不需要筛选素数。

```c
#include <stdio.h>

int n;

void solve(){
    int i;
    int m = n;
    for (i = 2; i <= n; i++){
        int cnt = 0;
        if (m % i) continue;
        while (m % i == 0){
            m /= i;
            cnt++;
        }
        printf("(%d,%d)", i, cnt);
        if (m == 1) break;
    }
    printf("\n");
}

int main(void)
{
    int t,i;
    scanf("%d", &t);
    for (i = 0; i < t; i++){
        scanf("%d", &n);
        solve();
    }
    return 0;
}
```

## $n!$ 右端的 0 的个数

令 $n!=5^m 2 ^p x$，$m,p,x$ 为非负整数。同时由于 $n!$ 中 2 的倍数远多于 5 的倍数，即 $p > m$，所以 m 即为答案。要得到 m，首先找从 1 到 n 中 5 的倍数，即 $\frac{n}{5}$，而 $25=5^2$，一个数就含有两个 5 在内，因此第二轮我们找从 1 到 $\frac{n}{5}$ 中 5 的倍数。由于第一轮中已经被拿掉了一个 5，第二轮 25 就只需再拿出一个 5 即可，$\frac{n}{25}$。第三轮则 $\frac{n}{125}$，第 $i$ 轮 $\frac{n}{5^i}$，以此类推：

```c
#include <stdio.h>

int main()
{
    int t,i,n,m,z;
    scanf("%d", &t);
    for (i = 0; i < t; i++){
        scanf("%d", &n);
        m = 5;z = 0;
        while (n>= m){
            z += n / m;
            m *= 5;
        }
        printf("case #%d:\n%d\n", i, z);
    }
    return 0;
}
```
