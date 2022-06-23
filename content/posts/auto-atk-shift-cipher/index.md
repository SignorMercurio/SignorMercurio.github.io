---
title: 对移位密码的自动化攻击
date: 2019-09-13 15:46:43
tags:
  - 古典密码与编码
categories:
  - 密码学
---

《密码学基础》小作业。

<!--more-->

{{< katex >}}

## 背景

对常见的移位密码的攻击，一般是穷举密钥和可能的明文，然后判断其中哪个明文有意义。然而，对于 “有意义” 的判断是基于人的主观意志，对计算机而言很难自动化。因此引入破解替换密码时常用的词频分析法，来实现对移位密码的自动化攻击。

## 攻击简介

用 $p_i$ 表示第 $i$ 个字母在正常英文文本中出现的概率，$0<=i<=25$。根据统计数据，有：

$$
\sum_{i=0}^{25}p_i^2\approx 0.065
$$

用 $q_i$ 表示第 $i$ 个字母在**密文**文本中出现的概率（准确地说，频率），$0<=i<=25$。如果密钥为 $k$，则对于每个 $i$ 而言，$q_{i+k}$ 应约等于 $p_i$。

如果对于每个 $j\in\lbrace 0,...,25\rbrace$，我们计算 $I_j$ 的值：

$$
I_j=\sum_{i=0}^{25}p_i\cdot q_{i+j}
$$

那么对于实际使用的密钥 $k$，应有 $I_k\approx 0.065$。

## 代码

```python
import math

key_space = 26
c = 'OVDTHUFWVZZPISLRLFZHYLAOLYL'
lenc = len(c)
std = 0.065
dev = 99
k = 0

# from wikipedia
p = [0.08167,0.01492,0.02782,0.04253,0.12702,
     0.02228,0.02015,0.06094,0.06966,0.00153,
     0.00772,0.04025,0.02406,0.06749,0.07507,
     0.01929,0.00095,0.05987,0.06327,0.09056,
     0.02758,0.00978,0.02360,0.00150,0.01974,
     0.00074]
q = []

def num2ord(num):
    return ord('A') + num

def ord2num(i):
    return i - ord('A')


for i in range(key_space):
    q.append(c.count(chr(num2ord(i)) ) * 1.0 / lenc)

for j in range(key_space):
    Ij = 0
    for i in range(key_space):
        Ij += p[i] * q[(i+j) % key_space]
    cur_dev = math.fabs(Ij - std)  # deviation
    if (cur_dev < dev):
        dev = cur_dev
        k = j

print('Key: %d' % k)

m = ''
for i in range(lenc):
    m += chr(num2ord(ord2num(ord(c[i])-k) % key_space))

print('Plaintext: %s' % m)
# Key: 7
# Plaintext: HOWMANYPOSSIBLEKEYSARETHERE
```
