---
title: 模 p 平方根算法
date: 2019-05-22 17:02:49
tags:
  - 数学
  - 快速幂
categories:
  - 密码学
math: true
---

参考了陈恭亮《信息安全数学基础》第二版上的算法。

<!--more-->

囊括了快速幂运算（模重复平方计算法）和求逆元（扩展欧几里得算法）两个经典的初等数论算法。模 p 平方根算法是用来求解形如 $x^2 \equiv a (mod\ p)$ 的二次同余式，其中 $p$ 为素数，且 $(\frac{a}{p}) = 1$。

```python
def quick_pow(a, b, p):
  ret = 1
  a %= p
  while b:
    if b&1:
      ret = (ret * a) % p
    b >>= 1
    a = (a * a) % p
  return ret

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m


a, p = map(int, input('Please input a, p such that x^2 = a (mod p). Input \'-1 -1\' to use default values: ').split())
if a == -1 and p == -1:
  a, p = 315, 907

if quick_pow(a, (p-1) // 2, p) != 1:
  print('No valid solution.')
  exit(1)

s, t = p-1, 0
while (s&1) == 0:
  t += 1
  s >>= 1

print('p-1 = %d = 2^%d * %d' % (p-1, t, s))
b = quick_pow(3, s, p)
print('t = %d, s = %d, b = 3^s (mod p) = %d (mod p)'% (t, s, b))

_a = modinv(a, p)
x = quick_pow(a, (s+1) // 2, p)
print('x_%d = %d (mod p), inv(a) = %d (mod p)'% (t-1, x, _a))
print()

for k in range(1, t):
  res = 1 if quick_pow(_a * x ** 2, 2 ** (t-k-1), p) == 1 else -1
  print('(inv(a) * (x_%d)^2) ^ (2^%d) = %d (mod p)'% (t-k, t-k-1, res))
  j = 0 if res == 1 else 1
  x = (x * b**(j * 2**(k-1))) % p
  print('j_%d = %d, x_%d = x_%d * b ^ (j_%d * 2^(%d)) = %d (mod p)'% (k-1, j, t-k-1, t-k, k-1, k-1, x))
  print()

print('x_0 = %d (mod p), x_0\'= %d (mod p)'% (x, p-x))
```
