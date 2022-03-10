---
title: Paillier 同态加密方案实现
date: 2019-12-26 21:08:46
tags:
  - 公钥密码学
  - 同态加密
categories:
  - 密码学
---

最后一次抽代课的上机练习。

<!--more-->

## 方案介绍

详见 [wiki](https://en.wikipedia.org/wiki/Paillier_cryptosystem)。

## 练习内容

我忘记了……凭借代码想起来一点：

- 生成 10bit 的大素数 `p,q`，输出公钥与私钥。
- 令明文 `m1 = 15, m2 = 20`，输出加密后的密文 `c1, c2`。
- 对密文 `c1, c2` 解密，输出解密结果 `m1', m2'`。
- 对 `c1 * c2` 解密，输出解密结果 `m'`，以验证 `m' = m1'+ m2'`。

最后一步就是验证该方案是一种同态加密方案。

## 代码

生成 10bit 大素数偷了个懒。剩余的过程主要参考了维基上的方法，依旧离不开熟悉的快速幂、扩展欧几里得、求逆元三大算法。

```python
from Crypto.Util import number
import math
import random

# constants
n_length = 10
p = number.getPrime(n_length)
q = number.getPrime(n_length)
n = p*q
n2 = n**2
m1 = 15
m2 = 20

# general funcs
def L(x):
  global n
  return (x-1) // n

def lcm(a,b):
  return abs(a*b) // math.gcd(a,b)

def egcd(a, b):
  if a == 0:
    return (b, 0, 1)
  else:
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
  g, x, y = egcd(a, m)
  if g != 1:
    #raise Exception('Modular inverse does not exist')
    return -1
  else:
    return x % m

def quick_pow(a, b, p):
  ret = 1
  a %= p
  while b:
    if b&1:
      ret = (ret * a) % p
    b >>= 1
    a = (a * a) % p
  return ret

random.seed()
lamb = lcm(p-1, q-1)
mu = -1

while mu == -1:
  g = random.randint(0, n2-1)
  mu = modinv(L(quick_pow(g,lamb,n2)), n)

print('PubKey: (n={},g={})'.format(n,g))
print('PrivKey: (lambda={},p={},q={})'.format(lamb,p,q))
print('mu: {}'.format(mu))

r1 = random.randint(0,n-1)
r2 = random.randint(0,n-1)
c1 = quick_pow(g,m1,n2) * quick_pow(r1,n,n2) % n2
c2 = quick_pow(g,m2,n2) * quick_pow(r2,n,n2) % n2
print('c1: {}'.format(c1))
print('c2: {}'.format(c2))

m1_ = L(quick_pow(c1,lamb,n2)) * mu % n
m2_ = L(quick_pow(c2,lamb,n2)) * mu % n
print("m1': {}".format(m1_))
print("m2': {}".format(m2_))

m_ = L(quick_pow(c1*c2,lamb,n2)) * mu % n
print("m': {}".format(m_))
```

