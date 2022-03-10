---
title: ElGamal 密码方案的椭圆曲线形式实现
date: 2019-12-20 13:00:34
tags:
  - 公钥密码学
categories:
  - 密码学
math: true
---

抽代课的上机练习。

<!--more-->

## 方案简述

- 设 $E$ 为 $F_q$ 上的椭圆曲线，一般记为 $E(F_q)$，设 $P=(x_p,y_p)\in E(F_q)$，且 $P$ 的次数足够大，
  任取 $1<s<ord(P)$，令 $Q=(x_q,y_q)=sP$，则 $(E(F_q),P,Q)$ 为公钥，$s$ 为私钥。
- 消息 $m$ 满足 $0\leq m<F_q$，任取 $1<r<F_q$，计算 $(x_1,y_1)=𝑟𝑃,(x_2,y_2)=rQ,c=m\cdot x_2$，
  则密文为 $(x_1,y_1,c)$。
- 解密时，计算 $(x',y')=s(x_1,y_1)$，再计算 $m'=c\cdot x'^{-1}$，解得明文。

## 正确性证明

- 因为 $(x',y')=s(x_1,y_1)=srP=rsP=rQ=(x_2,y_2)$，所以 $x'=x_2$，
  因此 $m'=c\cdot x'^{-1}=c\cdot x_2^{-1}=m$，得证。
- 方案的安全性依赖于椭圆曲线上的离散对数问题。

## 练习内容

- 令 $E:y^2=x^3+x+6$ 为 $F_{11}$ 上的一条椭圆曲线，求 $E$ 上的所有点
- 令 $P=(2,7)$，取 $s=5$，求公钥
- 设消息 $m=3$，取 $r=7$，求 $m$ 的密文 $(x_1,y_1,c)$
- 对 $(x_1,y_1,c)$ 做解密运算，求 $(x',y')$，并进一步求其明文 $m'$

## 代码

$F_{11}$ 比较小就直接硬编码了，也可以利用 [模 p 平方根算法](/mod-p-sqrt) 来求解二次剩余对应的平方根。

需要注意的地方是不要对负数求逆元，因此做减法时可以额外加一个 `+p`。

```python
# general funcs
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

# constants
p = 11
a,b,c,d = 1,0,1,6 # y^2 = ax^3 + bx^2 + cx + d
sqrt = [-1,1,-1,5,2,4,-1,-1,-1,3,-1]

def E(x):
  return (a*x**3 + b*x**2 + c*x + d) % p

# dy/dx
def dE(x, y):
  return (3*a*x**2 + 2*b*x + c) * modinv(2*y, p)

def add(P, Q):
  x1,y1,x2,y2 = P[0],P[1],Q[0],Q[1]
  if x1==x2 and y1==y2:
    K = dE(x1,y1)
  else:
    K = (y2-y1) * modinv(x2-x1+p, p)
  x0 = (K**2 - x1 - x2) % p
  y0 = (K * (x1 - x0) - y1) % p
  return (x0, y0)

def mul(P, x):
  Q = P
  for i in range(x-1):
    Q = add(Q, P)
  return Q

def init():
  for i in range(p):
    y2 = E(i)
    print('x={}, y^2={}'.format(i, y2), end='')
    if sqrt[y2] != -1:
      print((i, sqrt[y2]), (i, p-sqrt[y2]))
    else:
      print()


init()
P = (2,7)
s = 5
Q = mul(P,s) # Q = sP
Estr = '{}x^3 + {}x^2 + {}x + {}'.format(a,b,c,d)
print('Pubkey: ({},{},{})'.format(Estr,P,Q))

m = 3
r = 7
c1 = mul(P,r) # (x1,y1)
c2 = mul(Q,r) # (x2,y2)
C = m * c2[0] % p
print('Ciphertext: {}'.format(c1+(C,))) # (x1,y1,C)

C_ = mul(c1,s) # (x',y')
print("(x',y'): {}".format(C_))
m_ = C * modinv(C_[0],p) % p # C * (x')^(-1)
print('Plaintext: {}'.format(m_))
```
