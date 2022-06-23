---
title: 扑朔迷离：隐私增强技术实践
date: 2022-02-04 09:23:11
tags:
  - 对称密码学
  - 公钥密码学
  - 同态加密
categories:
  - 密码学
featuredImage: 0.png
---

Privacy Enhancing Technologies (PET)，实际上还是密码学。

<!--more-->

{{< katex >}}

## 隐私与隐私侵犯

隐私可以看作是对数据的控制的一种准许：

- 机密性 - 保证一个人的秘密不被泄漏
- 控制 - 给个人控制自己个人信息的权利
- 自我实现 - 允许个人使用这些信息来达成自己的目的

Solove 分类将隐私侵犯分为 4 类：

- 信息收集
- 信息处理
- 信息传播
- 入侵（即干扰个人的活动与决策）

## 隐私增强技术分类

根据不同的假设，隐私增强技术可以分为 Soft PET 和 Hard PET。前者主要关注合规性，假设处理用户数据的第三方服务是合法可信的，因此侧重于建立安全信道、强化访问控制策略等等。

后者则假设任一第三方服务均不可信，因此注重完整性、审计、不泄漏数据给第三方等等。

举个例子，如果 Alice 和 Bob 要通过一台服务器（第三方服务）进行通信，那么在 Soft PET 中，双方都会与服务器建立 TLS 连接传输加密数据。服务器可以看到数据明文，不过监听者看不到。

而在 Hard PET 中，Alice 和 Bob 不信任服务器。此时 Alice 可能使用 Bob 的公钥加密后经服务器传输给 Bob，这一过程中服务器就无法看到明文了。

## 通信隐私 Communications Privacy

这个部分比较简单，即密码学中的混合加密机制。

### 对称加密

首先是对称加密部分，现在通常采用 AEAD 方式同时确保机密性和完整性，最著名的算法莫过于 AES-GCM 了。

> 需要注意的是，对于同一密钥不能重复使用相同的 IV。

我们需要实现 `encrypt_message` 和 `decrypt_message` 两个函数，在实现前先利用 pytest 写好测试，以 AES-128-GCM 为例：

```python
@pytest.mark.task2
def test_gcm_encrypt():
    """ Tests encryption with AES-GCM """
    from os import urandom
    key = urandom(16)
    message = b"Hello World!"
    iv, ciphertext, tag = encrypt_message(key, message)

    assert len(iv) == 16
    assert len(ciphertext) == len(message)
    assert len(tag) == 16


@pytest.mark.task2
def test_gcm_decrypt():
    """ Tests decryption with AES-GCM """
    from os import urandom
    key = urandom(16)
    message = b"Hello World!"
    iv, ciphertext, tag = encrypt_message(key, message)

    assert len(iv) == 16
    assert len(ciphertext) == len(message)
    assert len(tag) == 16

    m = decrypt_message(key, iv, ciphertext, tag)
    assert m == message


@pytest.mark.task2
def test_gcm_fails():
    from pytest import raises

    from os import urandom
    key = urandom(16)
    message = b"Hello World!"
    iv, ciphertext, tag = encrypt_message(key, message)

    with raises(Exception) as excinfo:
        decrypt_message(key, iv, urandom(len(ciphertext)), tag)
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        decrypt_message(key, iv, ciphertext, urandom(len(tag)))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        decrypt_message(key, urandom(len(iv)), ciphertext, tag)
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        decrypt_message(urandom(len(key)), iv, ciphertext, tag)
    assert 'decryption failed' in str(excinfo.value)
```

函数实现部分则利用 petlib，注意捕获异常：

```python
def encrypt_message(key, message):
    """ Encrypt a message under a key given as input """
    length = len(key)
    iv = urandom(length)

    aes = Cipher("aes-128-gcm")
    ciphertext, tag = aes.quick_gcm_enc(key, iv, message)

    return iv, ciphertext, tag


def decrypt_message(key, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key given as input
        In case the decryption fails, throw an exception.
    """
    aes = Cipher("aes-128-gcm")
    try:
        plain = aes.quick_gcm_dec(key, iv, ciphertext, tag)
    except:
        raise Exception("decryption failed")
    return plain
```

### 非对称加密

非对称部分采用 ECDH 来减小密钥长度，考虑到 Forward Secrecy 的要求，可以升级成 ECDHE。在此之前，先复习一下椭圆曲线算术。

假设曲线为 $y^2\equiv x^3+ax+b\ (mod\ p)$，首先需要一个判断点是否在曲线上的函数。我们用封装好的 `petlib.ec` 写测试，但只使用 `petlib.Bn` 来计算椭圆曲线算术：

```python
@pytest.mark.task3
def test_on_curve():
    """
    Test the procedues that tests whether a point is on a curve.
    """
    # Example on how to define a curve
    from petlib.ec import EcGroup, EcPt
    group = EcGroup(713)  # NIST curve
    d = group.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = group.generator()
    gx, gy = g.get_affine()

    from Lab01Code import is_point_on_curve
    assert is_point_on_curve(a, b, p, gx, gy)

    assert is_point_on_curve(a, b, p, None, None)


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) \
        or (x is None and y is None)

    if x is None and y is None:
        return True

    lhs = (y * y) % p
    rhs = (x * x * x + a * x + b) % p
    on_curve = (lhs == rhs)

    return on_curve
```

随后，对于 $(x_r,y_r)=(x_p,y_p)+(x_q,y_q)$，我们有：

$$
\lambda=(y_q-y_p)(x_q-x_p)^{-1}\ (mod\ p)\\\\
x_r=\lambda^2-x_p-x_q\ (mod\ p)\\\\
y_r=\lambda(x_p-x_r)-y_p\ (mod\ p)
$$

```python
@pytest.mark.task3
def test_point_addition():
    """
    Test whether the EC point addition is correct.
    """
    from pytest import raises
    from petlib.ec import EcGroup, EcPt
    group = EcGroup(713)  # NIST curve
    d = group.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = group.generator()
    gx0, gy0 = g.get_affine()

    r = group.order().random()
    gx1, gy1 = (r * g).get_affine()

    assert is_point_on_curve(a, b, p, gx0, gy0)
    assert is_point_on_curve(a, b, p, gx1, gy1)

    # Test a simple addition
    h = (r + 1) * g
    hx1, hy1 = h.get_affine()

    x, y = point_add(a, b, p, gx0, gy0, gx1, gy1)
    assert is_point_on_curve(a, b, p, x, y)
    assert x == hx1
    assert y == hy1

    # Ensure commutativity
    xp, yp = point_add(a, b, p, gx1, gy1, gx0, gy0)
    assert is_point_on_curve(a, b, p, xp, yp)
    assert x == xp
    assert y == yp

    # Ensure addition with neutral returns the element
    xp, yp = point_add(a, b, p, gx1, gy1, None, None)
    assert is_point_on_curve(a, b, p, xp, yp)
    assert xp == gx1
    assert yp == gy1

    xp, yp = point_add(a, b, p, None, None, gx0, gy0)
    assert is_point_on_curve(a, b, p, xp, yp)
    assert gx0 == xp
    assert gy0 == yp

    # An error is raised in case the points are equal
    with raises(Exception) as excinfo:
        point_add(a, b, p, gx0, gy0, gx0, gy0)
    assert 'EC Points must not be equal' in str(excinfo.value)


@pytest.mark.task3
def test_point_addition_check_inf_result():
    """
    Test whether the EC point addition is correct for pt - pt = inf
    """
    from petlib.ec import EcGroup
    group = EcGroup(713)  # NIST curve
    d = group.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = group.generator()
    gx0, gy0 = g.get_affine()
    gx1, gy1 = gx0, p - gy0

    assert is_point_on_curve(a, b, p, gx0, gy0)
    assert is_point_on_curve(a, b, p, gx1, gy1)

    x, y = point_add(a, b, p, gx0, gy0, gx1, gy1)
    assert is_point_on_curve(a, b, p, x, y)
    assert (x, y) == (None, None)


def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition by
    implementing the above pseudocode.
    Raises an Exception if the points are equal.
    """

    if x0 is None and y0 is None:
        return x1, y1
    if x1 is None and y1 is None:
        return x0, y0
    if x0 == x1 and y0 == y1:
        raise Exception("EC Points must not be equal")

    assert (isinstance(x0, Bn) and isinstance(
        y0, Bn))
    assert (isinstance(x1, Bn) and isinstance(
        y1, Bn))

    inv = 0
    try:
        inv = (x1-x0).mod_inverse(p)
    except:
        return None, None

    lamb = (y1-y0).mod_mul(inv, p)
    xr = lamb.mod_pow(2, p).mod_sub(x0+x1, p)
    yr = lamb.mod_mul(x0-xr, p).mod_sub(y0, p)

    return xr, yr
```

特别地，当两个加数相同时：

$$
\lambda=(3x_p^2+a)(2y_p)^{-1}\ (mod\ p)\\\\
x_r=\lambda^2-2x_p\ (mod\ p)\\\\
y_r=\lambda(x_p-x_r)-y_p\ (mod\ p)
$$

```python
@pytest.mark.task3
def test_point_doubling():
    """
    Test whether the EC point doubling is correct.
    """

    from petlib.ec import EcGroup
    group = EcGroup(713)  # NIST curve
    d = group.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = group.generator()
    gx0, gy0 = g.get_affine()

    gx2, gy2 = (2 * g).get_affine()

    x2, y2 = point_double(a, b, p, gx0, gy0)
    assert is_point_on_curve(a, b, p, x2, y2)
    assert x2 == gx2 and y2 == gy2

    x2, y2 = point_double(a, b, p, None, None)
    assert is_point_on_curve(a, b, p, x2, y2)
    assert x2 is None and y2 is None


def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """

    if x is None and y is None:
        return x, y

    assert (isinstance(x, Bn) and isinstance(
        y, Bn))

    inv = (2*y).mod_inverse(p)
    lamb = (3*x**2+a).mod_mul(inv, p)
    xr = lamb.mod_pow(2, p).mod_sub(x*2, p)
    yr = lamb.mod_mul(x-xr, p).mod_sub(y, p)

    return xr, yr
```

而对于乘法，我们可以使用快速幂的方法：

```python
@pytest.mark.task3
def test_point_scalar_mult_double_and_add():
    """
    Test the scalar multiplication using double and add.
    """

    from petlib.ec import EcGroup
    group = EcGroup(713)  # NIST curve
    d = group.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = group.generator()
    gx0, gy0 = g.get_affine()
    r = group.order().random()

    gx2, gy2 = (r * g).get_affine()

    x2, y2 = point_scalar_multiplication_double_and_add(a, b, p, gx0, gy0, r)
    assert is_point_on_curve(a, b, p, x2, y2)
    assert gx2 == x2
    assert gy2 == y2


def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q
    """
    Q = (None, None)
    P = (x, y)

    assert isinstance(x, Bn)
    assert isinstance(y, Bn)
    assert isinstance(scalar, Bn)

    for i in range(scalar.num_bits()):
        if scalar.is_bit_set(i):
            Q = point_add(a, b, p, Q[0], Q[1], P[0], P[1])
        P = point_double(a, b, p, P[0], P[1])

    return Q
```

在后续实验中需要注意的是，整数域上的运算“迁移”到椭圆曲线上时会降阶，即乘法变为加法，幂运算变为乘法。

### 签名

在我们的混合加密体制中还可以加入数字签名，这里用 ECDSA：

```python
@pytest.mark.task4
def test_key_gen():
    """ Tests the key generation of ECDSA"""
    from Lab01Code import ecdsa_key_gen
    ecdsa_key_gen()
    assert True


@pytest.mark.task4
def test_produce_signature():
    """ Tests signature function """
    msg = b"Test" * 1000
    from Lab01Code import ecdsa_key_gen, ecdsa_sign

    group, priv, pub = ecdsa_key_gen()
    ecdsa_sign(group, priv, msg)
    assert True


@pytest.mark.task4
def test_check_signature():
    """ Tests signature and verification function """
    msg = b"Test" * 1000

    group, priv, pub = ecdsa_key_gen()

    sig = ecdsa_sign(group, priv, msg)
    assert ecdsa_verify(group, pub, msg, sig)


@pytest.mark.task4
def test_check_fail():
    """ Ensures verification fails when it should """
    msg = b"Test" * 1000
    msg2 = b"Text" * 1000

    group, priv, pub = ecdsa_key_gen()

    sig = ecdsa_sign(group, priv, msg)

    assert not ecdsa_verify(group, pub, msg2, sig)


def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing
        and the corresponding public key for verification"""
    group = EcGroup()
    priv_sign = group.order().random()
    pub_verify = priv_sign * group.generator()
    return group, priv_sign, pub_verify


def ecdsa_sign(group, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    digest = sha256(message).digest()
    kinv_rp = do_ecdsa_setup(group, priv_sign)
    sig = do_ecdsa_sign(group, priv_sign, digest, kinv_rp)

    return sig


def ecdsa_verify(group, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    digest = sha256(message).digest()
    res = do_ecdsa_verify(group, pub_verify, sig, digest)
    return res
```

### 完整的加密通信实现

将上面实现的部分组合到一起，加上 DH 密钥交换，就是完整的加密通信过程了。在下面的代码里假设 Alice 发送 Bob 接收，但因为通信的对称性，对于相反的情况也同样适用。

```python
@pytest.mark.task5
def test_encrypt():
    ecdsa_group, ecdsa_priv_alice, ecdsa_pub_alice = ecdsa_key_gen()
    alice_sig = (ecdsa_group, ecdsa_priv_alice)

    dh_group, dh_priv_bob, dh_pub_bob = dh_get_key()
    message = b"Hello World!"

    iv, ciphertext, tag, sig, dh_pub_alice = dh_encrypt(
        dh_pub_bob, message, alice_sig)

    assert len(iv) == 16
    assert len(ciphertext) == len(message)
    assert len(tag) == 16


@pytest.mark.task5
def test_decrypt():
    ecdsa_group, ecdsa_priv_alice, ecdsa_pub_alice = ecdsa_key_gen()
    alice_sig = (ecdsa_group, ecdsa_priv_alice)
    alice_ver = (ecdsa_group, ecdsa_pub_alice)

    dh_group, dh_priv_bob, dh_pub_bob = dh_get_key()
    message = b"Hello World!"

    iv, ciphertext, tag, sig, dh_pub_alice = dh_encrypt(
        dh_pub_bob, message, alice_sig)

    assert len(iv) == 16
    assert len(ciphertext) == len(message)
    assert len(tag) == 16

    encrypted = (iv, ciphertext, tag, sig)
    m = dh_decrypt(dh_priv_bob, dh_pub_alice, encrypted, alice_ver)
    assert m == message


@pytest.mark.task5
def test_fails():
    ecdsa_group, ecdsa_priv_alice, ecdsa_pub_alice = ecdsa_key_gen()
    alice_sig = (ecdsa_group, ecdsa_priv_alice)
    alice_ver = (ecdsa_group, ecdsa_pub_alice)

    dh_group, dh_priv_bob, dh_pub_bob = dh_get_key()
    message = b"Hello World!"

    iv, ciphertext, tag, sig, dh_pub_alice = dh_encrypt(
        dh_pub_bob, message, alice_sig)

    assert len(iv) == 16
    assert len(ciphertext) == len(message)
    assert len(tag) == 16

    # Random ciphertext
    with raises(Exception) as excinfo:
        encrypted = (iv, urandom(len(ciphertext)), tag, sig)
        dh_decrypt(dh_priv_bob, dh_pub_alice, encrypted, alice_ver)
    assert 'decryption failed' in str(excinfo.value)

    # Random AES-GCM tag
    with raises(Exception) as excinfo:
        encrypted = (iv, ciphertext, urandom(len(tag)), sig)
        dh_decrypt(dh_priv_bob, dh_pub_alice, encrypted, alice_ver)
    assert 'decryption failed' in str(excinfo.value)

    # Random IV
    with raises(Exception) as excinfo:
        encrypted = (urandom(len(iv)), ciphertext, tag, sig)
        dh_decrypt(dh_priv_bob, dh_pub_alice, encrypted, alice_ver)
    assert 'decryption failed' in str(excinfo.value)

    encrypted_normal = (iv, ciphertext, tag, sig)
    group_rand, priv_rand, pub_rand = dh_get_key()

    # Random DH private key of Bob
    with raises(Exception) as excinfo:
        dh_decrypt(priv_rand, dh_pub_alice, encrypted_normal, alice_ver)
    assert 'decryption failed' in str(excinfo.value)

    # Random DH public key of Alice
    with raises(Exception) as excinfo:
        dh_decrypt(dh_priv_bob, pub_rand, encrypted_normal, alice_ver)
    assert 'decryption failed' in str(excinfo.value)

    ecdsa_group_rand, ecdsa_priv_rand, ecdsa_pub_rand = ecdsa_key_gen()
    alice_ver_rand = (ecdsa_group_rand, ecdsa_pub_rand)

    # Random ECDSA verificaiton key
    with raises(Exception) as excinfo:
        dh_decrypt(dh_priv_bob, dh_pub_alice, encrypted_normal, alice_ver_rand)
    assert 'verification failed' in str(excinfo.value)

    # Random signature
    with raises(Exception) as excinfo:
        encrypted = (iv, ciphertext, tag, (Bn(100), Bn(200)))
        dh_decrypt(dh_priv_bob, dh_pub_alice, encrypted, alice_ver)
    assert 'verification failed' in str(excinfo.value)


def dh_get_key():
    """ Generate a DH key pair """
    group = EcGroup()
    priv_dec = group.order().random()
    pub_enc = priv_dec * group.generator()
    return group, priv_dec, pub_enc


def dh_encrypt(pub, message, alice_sig=None):
    """ Assume you know the public key of someone else (Bob),
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message with Alice's key.
    """
    assert isinstance(pub, EcPt)

    group, priv_dh, pub_dh = dh_get_key()
    secret = priv_dh * pub
    assert isinstance(secret, EcPt)

    key = sha256(secret.export()).digest()[:16]
    iv, ciphertext, tag = encrypt_message(key, message)

    sig = None
    if alice_sig is not None:
        group, priv_sign = alice_sig
        sig = ecdsa_sign(group, priv_sign, message)

    return iv, ciphertext, tag, sig, pub_dh


def dh_decrypt(priv, pub, ciphertext, alice_ver=None):
    """ Decrypt a received message encrypted using your public key,
    of which the private key is provided.
    Optionally verify the message came from Alice using her verification
    key."""
    assert isinstance(priv, Bn)
    assert isinstance(pub, EcPt)

    secret = priv * pub
    assert isinstance(secret, EcPt)

    key = sha256(secret.export()).digest()[:16]

    iv, cipher, tag, sig = ciphertext
    plain = decrypt_message(key, iv, cipher, tag)

    if alice_ver is not None:
        group, pub_verify = alice_ver
        if not ecdsa_verify(group, pub_verify, plain, sig):
            raise Exception("verification failed")

    return plain
```

### 侧信道攻击

最后，我们编写函数测试椭圆曲线点乘法所消耗的时间：

```python
def time_scalar_mul(f):  # pragma: no cover
    start = time.perf_counter()

    group = EcGroup(713)
    d = group.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = group.generator()
    gx0, gy0 = g.get_affine()
    r = group.order().random()

    f(a, b, p, gx0, gy0, r)
    return r, time.perf_counter()-start


def time_double_add(times):  # pragma: no cover
    for _ in range(times):
        r, time_double_add = time_scalar_mul(
            point_scalar_multiplication_double_and_add)
        print(r, time_double_add)
```

> Python3.8 移除了 `time.clock()`，使用 `time.perf_counter()` 替代。

运行后可以发现，快速幂的方式花费时间浮动很大，可能导致基于时间的侧信道攻击。为了防止这一攻击，我们可以采用 Montgomerry Ladder 算法重新实现乘法：

```python
def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0
    """
    R0 = (None, None)
    R1 = (x, y)

    assert isinstance(x, Bn)
    assert isinstance(y, Bn)
    assert isinstance(scalar, Bn)

    for i in reversed(range(0, scalar.num_bits())):
        # TODO: ADD YOUR CODE HERE
        if not scalar.is_bit_set(i):
            R1 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R0 = point_double(a, b, p, R0[0], R0[1])
        else:
            R0 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R1 = point_double(a, b, p, R1[0], R1[1])

    return R0


def time_montgomery(times):
    for _ in range(times):
        r, time_montgomery = time_scalar_mul(
            point_scalar_multiplication_montgomerry_ladder)
        print(r, time_montgomery)
```

此时的计时结果非常稳定，因为 Montgomerry Ladder 算法确保了对不同输入的处理花费大致相同的时间。

## 匿名通信 Anonymous Communications

匿名通信的匿名性大概有如下几种：

- 发送者匿名：Alice 发送消息给 Bob，Bob 并不知道发送者是谁
- 接收者匿名：Alice 发送消息给 Bob，但不知道 Bob 是谁
- 双向匿名：Alice 与 Bob 通信，但不知道对方身份
- 第三方匿名：Alice 与 Bob 通信并知道对方身份，但第三方并不知道

为了满足匿名性，我们常常需要满足：

- 不可观测性：Alice 与 Bob 通信，而其他人并不知道他们各自在发送还是接收消息
- 不可关联性：Alice 发送（或 Bob 接收）的任意两条消息无法被关联到同一个发送者（或接收者）
- 伪匿名性：Alice 的所有行为都可以被关联到一个实体，但实体的身份无法确定

实现匿名通信有多种方法，其中最简单的莫过于所有发送的消息都通过广播的方式，如果接收到消息的人发现可以成功解密，说明消息是发送给自己的，否则丢弃。这当然不是好办法，但如果我们要自己设计匿名通信机制，需要注意不能比这一办法更差。

### 高延迟匿名通信

Mix 是一种高延迟匿名通信机制，实际上就是发送者将消息都发到一个叫做 Mix 的黑盒子里，随后消息从黑盒子里出来，再发送到接收者。如果 Mix 可以抵抗流量分析并提供比特级的不可关联性，那么就能保证匿名性了。

Alice 用 Mix 公钥加密消息后发送给 Mix，随后 Mix 解密并发送给 Bob。由于任何人都可以给 Mix 发消息，而 Mix 的模式实际上为攻击者提供了一个解密 Oracle，因此攻击者可以通过修改输入来进行选择密文攻击，这就要求加密机制是 IND-CCA 的。否则，攻击者就可以关联输入和输出，破坏比特不可关联性。

另一方面，如果 Mix 采用 FIFO 方式接收和发送消息，那么攻击者只需要进行流量分析就能简单地关联输入和输出了，此时 Mix 是不能抵抗流量分析的。可以看到，抗流量分析保护元数据，而比特不可关联性保护数据。

因此，顾名思义，Mix 需要像洗牌一样打乱收到的消息并随机输出，在 Mix 内部也需要一个消息池来暂存还没有发出去的消息，通过延迟、故意插入无用包、故意丢包等手段抵抗流量分析，这就是高延迟的由来。

#### 单个 Mix

接下来来构建这样的黑盒子，首先是 Mix Server 部分：

```python
def aes_ctr_enc_dec(key, iv, message):
    """ A helper function that implements AES Counter (CTR) Mode encryption and decryption.
    Expects a key (16 byte), and IV (16 bytes) and an input plaintext / ciphertext.

    If it is not obvious convince yourself that CTR encryption and decryption are in
    fact the same operations.
    """
    aes = Cipher("AES-128-CTR")

    enc = aes.enc(key, iv)
    output = enc.update(message)
    output += enc.finalize()

    return output


# This is the type of messages destined for the one-hop mix
OneHopMixMessage = namedtuple('OneHopMixMessage', ['ec_public_key',
                                                   'hmac',
                                                   'address',
                                                   'message'])


def mix_server_one_hop(private_key, message_list):
    """ Implements the decoding for a simple one-hop mix.

        Each message is decoded in turn:
        - A shared key is derived from the message public key and the mix private_key.
        - the hmac is checked against all encrypted parts of the message
        - the address and message are decrypted, decoded and returned
    """
    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        # Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
                not len(msg.hmac) == 20 or \
                not len(msg.address) == 258 or \
                not len(msg.message) == 1002:
            raise Exception("Malformed input message")

        # First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # Check the HMAC
        h = Hmac(b"sha512", hmac_key)
        h.update(msg.address)
        h.update(msg.message)
        expected_mac = h.digest()

        if not secure_compare(msg.hmac, expected_mac[:20]):
            raise Exception("HMAC check failure")

        # Decrypt the address and the message
        iv = b"\x00" * 16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        # Decode the address and message
        address_len, address_full = unpack("!H256s", address_plaintext)
        message_len, message_full = unpack("!H1000s", message_plaintext)

        output = (address_full[:address_len], message_full[:message_len])
        out_queue += [output]

    return sorted(out_queue)
```

根据 Mix Server 逻辑编写 Mix Client 的逻辑：

```python
def mix_client_one_hop(public_key, address, message):
    """
    Encode a message to travel through a single mix with a set public key.
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'OneHopMixMessage' with four parts: a public key, an HMAC (20 bytes),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes).
    """

    G = EcGroup()
    assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # Use those as the payload for encryption
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    # Generate a fresh public key
    private_key = G.order().random()
    client_public_key = private_key * G.generator()

    # First get a shared key
    shared_element = private_key * public_key  # client's priv and mix's pub
    key_material = sha512(shared_element.export()).digest()

    # Use different parts of the shared key for different operations
    hmac_key = key_material[:16]
    address_key = key_material[16:32]
    message_key = key_material[32:48]

    # Encrypt the address and the message
    iv = b"\x00"*16

    address_cipher = aes_ctr_enc_dec(address_key, iv, address_plaintext)
    message_cipher = aes_ctr_enc_dec(message_key, iv, message_plaintext)

    # Generate HMAC tag
    h = Hmac(b"sha512", hmac_key)
    h.update(address_cipher)
    h.update(message_cipher)
    expected_mac = h.digest()[:20]

    return OneHopMixMessage(client_public_key, expected_mac, address_cipher, message_cipher)
```

测试消息能否正常发送和接收：

```python
@pytest.fixture
def encode_Alice_message():
    """
    Encode a single message
    """

    G = EcGroup()
    g = G.generator()
    o = G.order()

    private_key = o.random()
    public_key = private_key * g

    m1 = mix_client_one_hop(public_key, b"Alice", b"Dear Alice,\nHello!\nBob")
    return private_key, m1


@pytest.mark.task2
def test_Alice_message_overlong():
    """
    Test overlong address or message
    """

    from os import urandom

    G = EcGroup()
    g = G.generator()
    o = G.order()

    private_key = o.random()
    public_key = private_key * g

    with raises(Exception) as excinfo:
        mix_client_one_hop(public_key, urandom(1000), b"Dear Alice,\nHello!\nBob")

    with raises(Exception) as excinfo:
        mix_client_one_hop(public_key, b"Alice", urandom(10000))


@pytest.mark.task2
def test_simple_client_part_type(encode_Alice_message):
    private_key, Alice_message = encode_Alice_message

    # Ensure the client encodes a NamedTuple of type "OneHopMixMessage"
    assert isinstance(Alice_message, tuple)
    assert len(Alice_message) == 4
    assert Alice_message.ec_public_key
    assert Alice_message.hmac
    assert Alice_message.address
    assert Alice_message.message


@pytest.mark.task2
def test_simple_client_decode(encode_Alice_message):
    private_key, Alice_message = encode_Alice_message

    # Ensure the mix can decode the message correctly
    res1 = mix_server_one_hop(private_key, [Alice_message])

    assert len(res1) == 1
    assert res1[0][0] == b"Alice"
    assert res1[0][1] == b"Dear Alice,\nHello!\nBob"


@pytest.mark.task2
def test_simple_client_decode_many():
    from os import urandom

    G = EcGroup()
    g = G.generator()
    o = G.order()

    private_key = o.random()
    public_key = private_key * g

    messages = []
    for _ in range(100):
        m = mix_client_one_hop(public_key, urandom(256), urandom(1000))
        messages += [m]

    # Ensure the mix can decode the message correctly
    res1 = mix_server_one_hop(private_key, messages)

    assert len(res1) == 100
```

#### 多个 Mix

为了分散负载和信任，我们可以使用多个 Mix。可以用级联方式增强匿名性（弱负载均衡），也可以用自由路由方式随机选一些 Mix 来传递消息，此时安全性取决于路径长度。

既然目的之一是分散信任，就要考虑如果某个 Mix 被 corrupt 了怎么办。也就是说，我们要不仅要对监听者、还要对 Mix 本身隐藏路径长度以及当前步数。一个比较简单的方法就是嵌套加密，使得 Mix 使用自己的私钥解密时只能知道消息从哪来到哪去，无法了解全局的路径信息。

在代码实现中，我们采用 blinding factor 隐藏公钥信息，并采用级联 HMAC 来检测消息篡改，尤其需要注意的是 blinding factor 和 HMAC 的处理顺序：

```python
# This is the type of messages destined for the n-hop mix
NHopMixMessage = namedtuple('NHopMixMessage', ['ec_public_key',
                                               'hmacs',
                                               'address',
                                               'message'])


def mix_server_n_hop(private_key, message_list, final=False):
    """ Decodes a NHopMixMessage message and outputs either messages destined
    to the next mix or a list of tuples (address, message) (if final=True) to be
    sent to their final recipients.

    Broadly speaking the mix will process each message in turn:
        - it derives a shared key (using its private_key),
        - checks the first hmac,
        - decrypts all other parts,
        - either forwards or decodes the message.
    """

    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        # Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
                not isinstance(msg.hmacs, list) or \
                not len(msg.hmacs[0]) == 20 or \
                not len(msg.address) == 258 or \
                not len(msg.message) == 1002:
            raise Exception("Malformed input message")

        # First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # Extract a blinding factor for the public_key
        blinding_factor = Bn.from_binary(key_material[48:])
        new_ec_public_key = blinding_factor * msg.ec_public_key

        # Check the HMAC
        h = Hmac(b"sha512", hmac_key)

        for other_mac in msg.hmacs[1:]:
            h.update(other_mac)

        h.update(msg.address)
        h.update(msg.message)

        expected_mac = h.digest()

        if not secure_compare(msg.hmacs[0], expected_mac[:20]):
            raise Exception("HMAC check failure")

        # Decrypt the hmacs, address and the message
        aes = Cipher("AES-128-CTR")

        # Decrypt hmacs
        new_hmacs = []
        for i, other_mac in enumerate(msg.hmacs[1:]):
            # Ensure the IV is different for each hmac
            iv = pack("H14s", i, b"\x00" * 14)

            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
            new_hmacs += [hmac_plaintext]

        # Decrypt address & message
        iv = b"\x00" * 16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        if final:
            # Decode the address and message
            address_len, address_full = unpack("!H256s", address_plaintext)
            message_len, message_full = unpack("!H1000s", message_plaintext)

            out_msg = (address_full[:address_len], message_full[:message_len])
            out_queue += [out_msg]
        else:
            # Pass the new mix message to the next mix
            out_msg = NHopMixMessage(
                new_ec_public_key, new_hmacs, address_plaintext, message_plaintext)
            out_queue += [out_msg]

    return out_queue


def mix_client_n_hop(public_keys, address, message):
    """
    Encode a message to travel through a sequence of mixes with a sequence public keys.
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'NHopMixMessage' with four parts: a public key, a list of hmacs (20 bytes each),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes).

    """
    G = EcGroup()
    # assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # use those encoded values as the payload you encrypt!
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    # Generate a fresh public key
    private_key = G.order().random()
    client_public_key = private_key * G.generator()

    hmacs = []
    hmac_keys, address_keys, message_keys = [], [], []
    blinding_factor = 1

    # Preprocess the keys
    for i, pubkey in enumerate(public_keys):
        # First get a shared key
        shared_element = private_key * blinding_factor * pubkey
        key_material = sha512(shared_element.export()).digest()
        # Use different parts of the shared key for different operations
        hmac_keys.append(key_material[:16])
        address_keys.append(key_material[16:32])
        message_keys.append(key_material[32:48])
        # Update blinding factor for next round
        blinding_factor = blinding_factor * Bn.from_binary(key_material[48:])

    n = len(hmac_keys)
    iv = b"\x00"*16

    # Traverse the mix server in reversed order
    for i in range(n-1, -1, -1):
        # Encrypt address & message
        address_cipher = aes_ctr_enc_dec(
            address_keys[i], iv, address_plaintext)
        message_cipher = aes_ctr_enc_dec(
            message_keys[i], iv, message_plaintext)

        # Encrypt other HMAC tags, each with a different IV
        for j, other_mac in enumerate(hmacs):
            iv = pack("H14s", j, b"\x00"*14)
            hmacs[j] = aes_ctr_enc_dec(hmac_keys[i], iv, other_mac)

        # Generate HMAC tag and insert to the beginning of hmacs
        h = Hmac(b"sha512", hmac_keys[i])

        for other_mac in hmacs:
            h.update(other_mac)

        h.update(address_cipher)
        h.update(message_cipher)

        expected_mac = h.digest()[:20]
        hmacs.insert(0, expected_mac)

        # Update address & message for next round
        address_plaintext = address_cipher
        message_plaintext = message_cipher

    return NHopMixMessage(client_public_key, hmacs, address_cipher, message_cipher)
```

然后测试一下 1 跳和 3 跳两种情况下的正确性：

```python
@pytest.mark.task3
def test_Alice_encode_1_hop():
    """
    Test sending a multi-hop message through 1-hop
    """
    from os import urandom

    G = EcGroup()
    g = G.generator()
    o = G.order()

    private_key = o.random()
    public_key = private_key * g

    address = b"Alice"
    message = b"Dear Alice,\nHello!\nBob"

    m1 = mix_client_n_hop([public_key], address, message)
    out = mix_server_n_hop(private_key, [m1], final=True)

    assert len(out) == 1
    assert out[0][0] == address
    assert out[0][1] == message


@pytest.mark.task3
def test_Alice_encode_3_hop():
    """
    Test sending a multi-hop message through 1-hop
    """
    from os import urandom

    G = EcGroup()
    g = G.generator()
    o = G.order()

    private_keys = [o.random() for _ in range(3)]
    public_keys = [pk * g for pk in private_keys]

    address = b"Alice"
    message = b"Dear Alice,\nHello!\nBob"

    m1 = mix_client_n_hop(public_keys, address, message)
    out = mix_server_n_hop(private_keys[0], [m1])
    out = mix_server_n_hop(private_keys[1], out)
    out = mix_server_n_hop(private_keys[2], out, final=True)

    assert len(out) == 1
    assert out[0][0] == address
    assert out[0][1] == message
```

#### 流量分析

我们通过例子来看如何通过简单的流量分析来推断一个发送者发送消息的目标。首先随机生成大量发送/接收消息的 trace：

```python
def generate_trace(number_of_users, threshold_size, number_of_rounds, targets_friends):
    """ Generate a simulated trace of traffic. """
    target = 0
    others = range(1, number_of_users)
    all_users = range(number_of_users)

    trace = []
    # Generate traces in which Alice (user 0) is not sending
    for _ in range(number_of_rounds // 2):
        senders = sorted(random.sample(others, threshold_size))
        receivers = sorted(random.sample(all_users, threshold_size))

        trace += [(senders, receivers)]

    # Generate traces in which Alice (user 0) is sending
    for _ in range(number_of_rounds // 2):
        senders = sorted([0] + random.sample(others, threshold_size - 1))
        # Alice sends to a friend
        friend = random.choice(targets_friends)
        receivers = sorted(
            [friend] + random.sample(all_users, threshold_size - 1))

        trace += [(senders, receivers)]

    random.shuffle(trace)
    return trace
```

这里 Alice 也就是 user0 会发送一些消息给她的好友，而其他用户之间的消息收发是完全随机的。我们不难发现，Alice 的好友应当比其他用户接收到了更多消息，这就是这次流量分析的关键：

```python
def analyze_trace(trace, target_number_of_friends, target=0):
    """
    Given a trace of traffic, and a given number of friends,
    return the list of receiver identifiers that are the most likely
    friends of the target.
    """
    max_users = 100
    rcv_cnt = dict.fromkeys(range(max_users), 0)

    for round in trace:
        senders, receivers = round
        for user in receivers:
            rcv_cnt[user] += 1

    # sort in descending order according to occurence
    occur = sorted(rcv_cnt.items(), key=lambda d: (d[1], d[0]), reverse=True)
    # select the top [target_number_of_friends] users
    return list(map(lambda x: x[0], occur[:target_number_of_friends]))
```

这里我们根据接收消息次数对用户进行排序，并选择了前 `target_number_of_friends` 个用户，推断是 Alice 的好友。进行测试：

```python
@pytest.mark.task4
def test_trace_static():
    # A fixed set and number of friends
    trace = generate_trace(100, 10, 1000, [1, 2, 3])
    friends = analyze_trace(trace, 3)
    assert len(friends) == 3
    assert sorted(friends) == [1, 2, 3]


@pytest.mark.task4
def test_trace_variable():
    # A random number of friends and random contacts
    friend_number = random.choice(range(1, 10))
    friends = random.sample(range(100), friend_number)

    trace = generate_trace(100, 10, 1000, friends)
    TA_friends = analyze_trace(trace, len(friends))
    assert len(TA_friends) == len(friends)
    assert sorted(TA_friends) == sorted(friends)
```

经多次实验，均可以通过这两个测试。

### 低延迟匿名通信

也就是 Onion 路由，最著名的例子是 Tor 网络。如果 Alice 要发送消息给 Bob，那么 Alice 会选择 3 个 Tor 节点，将消息经由这 3 个节点发送到 Bob，这样任意节点都不知道消息是从 Alice 到 Bob 的。

上述方法提供了发送者匿名性，但需要 Alice 知道 Bob 身份。如果要双向匿名，则需要 6 个 Tor 节点，两边对称。

Tor 节点将 IP、公钥等信息公开到 Directory Authorities 上，后者则生成一个 Consensus 供 Tor 客户端下载，从而获取 Tor 节点的信息。

对于攻击者来说，依然可以用类似侧信道的方式攻击 Onion 路由。一种方法是将输入和输出放到桶中，计算两者关联，但桶的存在会降低精确度。更好的方法是根据输入和包延迟的概率分布构建模版，并用输出去匹配模版。因此，低延迟匿名通信更容易受到被动攻击。

而如果攻击者能控制部分 Tor 节点，也不一定能控制某次通信的整条路径。如果攻击者控制了 Tor 网络中的 c 个节点，那么整条路径被控制的概率为 O(c^2)，因为攻击者必须控制第一个和最后一个节点才行。

## 隐私友好型计算 Privacy-friendly Computation

在前两部分，我们介绍了如何向第三方隐藏隐私信息，如通信内容、身份等，并且已经有类似 TLS 和 Tor 这类成熟的解决方案。但是，如果是要向通信的对方隐藏信息呢？

例如，我们想计算 $y=f(x_1,...,x_n)$，其中涉及的输入 $x_i$ 来自 n 个不同的主体，并且每个主体都不希望别人知道自己的 $x_i$。最简单的办法是引入可信第三方（TTP）来计算 y，然而且不论 TTP 未必存在，我们必须得考虑 4C 问题：

- Cost：TTP 要花多少钱？
- Corruption：TTP 真的可信吗？
- Compulsion：TTP 有没有可能受到不可抗力影响（如法律）泄露隐私？
- Compromise：TTP 有没有可能被入侵从而泄露隐私？

可以看到，寄希望于 TTP 并不明智，不过这可以作为一个很好的比较标准，即我们设计的方案应尽可能接近引入 TTP 所能达到的效果。

### 同态加密

一种方法是同态加密，即对密文的运算等同于对明文的运算，此时可以在不知道明文的情况下计算出经过运算的明文所对应的密文。以 ElGamal 为例，我们选择群 $G$ 中的两个元素 $g,h$，随机生成 $x\in(0,ord(G))$ 作为私钥，那么公钥就是 $g^x$。随后再选择随机的 $k\in(0,ord(G))$，计算密文 $E(m,k)=(g^k,g^{xk}h^m)$。

解密时，对于密文 $(a,b)$，只需计算 $m=log_h(b(a^x)^{-1})$。然而离散对数问题是困难的，因此可以先离线计算一张 $log_h$ 表格（这就要求明文空间不能太大）。正确性易证，同态性则包含加法和常数乘法同态：

$$
E(m_0,k_0)=(a_0,b_0)\\\\
E(m_1,k_1)=(a_1,b_1)\\\\
E(m_0+m_1,k_0+k_1)=(a_0a_1,b_0b_1)=(g^{k0+k1},g^{x(k0+k1)}h^{m0+m1})\\\\
E(cm_0, ck_0)=((a_0)^c,(b_0)^c)
$$

> 只满足常数乘法同态，不满足乘法同态。

接下来，我们在椭圆曲线上实现 Elgamal。需要注意上文提到的运算降阶问题，公钥变成了 $xg$，密文为 $(kg,kxg+mh)$，解密时计算 $log_h(b-xa)$。

```python
@pytest.mark.task1
def test_encrypt():
    params = setup()
    priv, pub = keyGen(params)
    assert encrypt(params, pub, 0)
    assert encrypt(params, pub, 10)
    assert encrypt(params, pub, -10)
    with raises(Exception) as excinfo:
        encrypt(params, pub, -1000)
    with raises(Exception) as excinfo:
        encrypt(params, pub, 1000)


@pytest.mark.task1
def test_decrypt():
    params = setup()
    priv, pub = keyGen(params)
    assert decrypt(params, priv, encrypt(params, pub, 0)) == 0
    assert decrypt(params, priv, encrypt(params, pub, 2)) == 2
    assert decrypt(params, priv, encrypt(params, pub, -2)) == -2
    assert decrypt(params, priv, encrypt(params, pub, 99)) == 99


def setup():
    """Generates the Cryptosystem Parameters."""
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    o = G.order()
    return G, g, h, o


def keyGen(params):
    """ Generate a private / public key pair """
    G, g, h, o = params

    priv = G.order().random()
    pub = priv * g

    return priv, pub


def encrypt(params, pub, m):
    """ Encrypt a message under the public key """
    if not -100 < m < 100:
        raise Exception("Message value to low or high.")

    G, g, h, o = params
    k = o.random()
    # (g^k, (pub^k)*(h^m))
    c = (k*g, k*pub + m*h)

    return c


def isCiphertext(params, ciphertext):
    """ Check a ciphertext """
    (G, g, h, o) = params
    ret = len(ciphertext) == 2
    a, b = ciphertext
    ret &= G.check_point(a)
    ret &= G.check_point(b)
    return ret


_logh = None


def logh(params, hm):
    """ Compute a discrete log, for small number only """
    global _logh
    G, g, h, o = params

    # Initialize the map of logh
    if _logh is None:
        _logh = {}
        for m in range(-1000, 1000):
            _logh[(m * h)] = m

    if hm not in _logh:
        raise Exception("No decryption found.")

    return _logh[hm]


def decrypt(params, priv, ciphertext):
    """ Decrypt a message using the private key """
    assert isCiphertext(params, ciphertext)
    a, b = ciphertext

    # b * (a^priv)^(-1)
    hm = b - priv*a

    return logh(params, hm)
```

随后，编写同态加密函数：

```python
@pytest.mark.task2
def test_add():
    params = setup()
    priv, pub = keyGen(params)
    one = encrypt(params, pub, 1)
    two = encrypt(params, pub, 2)
    three = add(params, pub, one, two)
    assert decrypt(params, priv, three) == 3

    # Try it for a range of numbers
    for x in range(-10, 10):
        Ex = encrypt(params, pub, x)
        E2x = add(params, pub, Ex, Ex)
        assert decrypt(params, priv, E2x) == 2 * x


@pytest.mark.task2
def test_mul():
    params = setup()
    priv, pub = keyGen(params)
    two = encrypt(params, pub, 2)
    three = mul(params, pub, two, 2)
    assert decrypt(params, priv, three) == 4

    # Try it for a range of numbers
    for x in range(-10, 10):
        Ex = encrypt(params, pub, x)
        E2x = mul(params, pub, Ex, 20)
        assert decrypt(params, priv, E2x) == 20 * x


def add(params, pub, c1, c2):
    """ Given two ciphertexts compute the ciphertext of the
        sum of their plaintexts.
    """
    assert isCiphertext(params, c1)
    assert isCiphertext(params, c2)

    a1, b1 = c1
    a2, b2 = c2
    c3 = (a1+a2, b1+b2)

    return c3


def mul(params, pub, c1, alpha):
    """ Given a ciphertext compute the ciphertext of the
        product of the plaintext time alpha """
    assert isCiphertext(params, c1)

    a1, b1 = c1
    c3 = (alpha * a1, alpha * b1)

    return c3
```

现在，我们来解决多方参与计算的问题。我们根据多方公钥，生成公共公钥。在整数域表示为 $g^{x_1+...+x_n}$，在椭圆曲线上则是 $x_1g+...+x_ng$。

```python
@pytest.mark.task3
def test_groupKey():
    params = setup()
    (G, g, h, o) = params

    # Generate a group key
    priv1, pub1 = keyGen(params)
    priv2, pub2 = keyGen(params)
    pub = groupKey(params, [pub1, pub2])

    # Check it is valid
    priv = (priv1 + priv2) % o
    assert decrypt(params, priv, encrypt(params, pub, 0)) == 0


def groupKey(params, pubKeys=None):
    """ Generate a group public key from a list of public keys """
    if pubKeys is None:
        pubKeys = []
    G, g, h, o = params

    pub = G.infinite()  # 0 elem
    for pubKey in pubKeys:
        pub = pubKey + pub

    return pub
```

随后进行部分解密，最后一个解密的人输出明文。在整数域表示为 $b\cdot a^{-x_1}\cdot ...\cdot a^{-x_n}$，在椭圆曲线上表示为 $b-x_1a-...-x_na$。

```python
@pytest.mark.task3
def test_partial():
    params = setup()
    (G, g, h, o) = params

    # Generate a group key
    priv1, pub1 = keyGen(params)
    priv2, pub2 = keyGen(params)
    pub = groupKey(params, [pub1, pub2])

    # Each authority decrypts in turn
    c = encrypt(params, pub, 0)
    cprime = partialDecrypt(params, priv1, c)
    m = partialDecrypt(params, priv2, cprime, True)
    assert m == 0


def partialDecrypt(params, priv, ciphertext, final=False):
    """ Given a ciphertext and a private key, perform partial decryption.
        If final is True, then return the plaintext. """
    assert isCiphertext(params, ciphertext)

    a1, b1 = ciphertext
    b1 = b1 - priv*a1

    if final:
        return logh(params, b1)
    else:
        return a1, b1
```

现在假设某一方想要让生成的公共公钥等于自己的公钥，这样自己一个人就能解密密文了。那么他只需要提交一个自己构造的公钥即可，在整数域是 $\frac{g^{x_j}}{\Pi_{i\neq j}\ g^{x_i}}$，这样生成公共公钥 $\Pi_{i\neq j}\ g^{x_i}\cdot \frac{g^{x_j}}{\Pi_{i\neq j}\ g^{x_i}}=g^{x_j}$。在椭圆曲线上则是 $x_jg-\Sigma_{i\neq j}\ x_ig$。

```python
@pytest.mark.task4
def test_badpub():
    params = setup()
    (G, g, h, o) = params

    # Four authorities generate keys
    priv1, pub1 = keyGen(params)
    priv2, pub2 = keyGen(params)
    priv3, pub3 = keyGen(params)
    priv4, pub4 = keyGen(params)

    # Derive a bad key
    x = o.random()
    badpub = corruptPubKey(params, x, [pub1, pub2, pub3, pub4])

    # Derive the group key including the bad public key
    pub = groupKey(params, [pub1, pub2, pub3, pub4, badpub])

    # Check that the corrupt authority can decrypt a message
    # encrypted under the group key with its secret only.
    assert decrypt(params, x, encrypt(params, pub, 0)) == 0


def corruptPubKey(params, priv, OtherPubKeys=None):
    """ Simulate the operation of a corrupt decryption authority.
        Given a set of public keys from other authorities return a
        public key for the corrupt authority that leads to a group
        public key corresponding to a private key known to the
        corrupt authority. """
    if OtherPubKeys is None:
        OtherPubKeys = []
    G, g, h, o = params

    pub = priv*g
    for pubkey in OtherPubKeys:
        pub = pub - pubkey

    return pub
```

### 秘密分享

秘密分享采用了另一种思路，将秘密拆分成若干碎片提供给不同 authorities，从而在避免 authorities 得知秘密的同时，能够让 authorities 进行协同计算。这个“协同计算”部分实际上是依赖于加法同态加密的，例如我们用 `<a>` 表示 a 的碎片集合，那么 `<a+b>=<a>+<b>`，此时计算出的是一个新的秘密的一个碎片。加常数和乘常数也是类似的。

不过，如果是秘密碎片之间的乘法就比较复杂了，这需要一些预计算的值以及 authorities 之间的交互。例如，要计算 `<x>` 和 `<y>` 的积，我们需要先预计算 `<a>,<b>,<c>` 使得 `<c>=<ab>`，其中 `<a>,<b>` 是随机的，这样才能隐藏 `<x>` 和 `<y>`。

接下来，计算 `<e>=<x>+<a>`，`<d>=<y>+<b>`，公开 `<e>,<d>` 获得 `e,d`。此时方能计算 `<z>=<xy>=<c>-e<b>-d<a>+ed`。

秘密分享相对于同态加密的优势在于可以加入机制确保完整性。传统方法是 authorities 进行零知识证明，表明其公开的值是合法的，但性能堪忧。SPDZ 则引入 MAC 并将 MAC 也拆成碎片，并通过并行验证提高性能，使得完整性检查较为廉价。

综合来看，秘密分享额外增加了网络负担，而同态加密额外增加了计算负担，对于大规模计算而言总体性能较差。目前两者都依然处于研究阶段，尚不成熟。

### 私密投票

最后我们实现一个私密投票的场景：

```python
@pytest.mark.task5
def test_poll():
    votes = [1, 0, 1, 0, 1, 1, 0, 1, 1, 1]
    v0, v1 = simulate_poll(votes)
    assert v0 == 3
    assert v1 == 7
```

我们需要在不知道明文的情况下，统计 0 和 1 的个数。首先为 authorities 生成密钥对并生成公共公钥，用 `encode_vote()` 来加密投票情况。随后调用 `process_votes()` 针对密文统计个数，最后 `partialDecrypt()` 解密个数信息并返回。

```python
def encode_vote(params, pub, vote):
    """ Given a vote 0 or 1 encode the vote as two
        ciphertexts representing the count of votes for
        zero and the votes for one."""
    assert vote in [0, 1]

    v0, v1 = encrypt(params, pub, vote)

    return v0, v1


def process_votes(params, pub, encrypted_votes):
    """ Given a list of encrypted votes tally them
        to sum votes for zeros and votes for ones. """
    assert isinstance(encrypted_votes, list)

    tv1 = encrypt(params, pub, 0)  # 0 elem

    for c in encrypted_votes:
        tv1 = add(params, pub, tv1, c)

    total = len(encrypted_votes)
    # total + (-1)*tv1
    tv0 = encrypt(params, pub, total)
    tv0 = add(params, pub, tv0, mul(params, pub, tv1, -1))

    return tv0, tv1


def simulate_poll(votes):
    """ Simulates the full process of encrypting votes,
        tallying them, and then decrypting the total. """

    # Generate parameters for the crypto-system
    params = setup()

    # Make keys for 3 authorities
    priv1, pub1 = keyGen(params)
    priv2, pub2 = keyGen(params)
    priv3, pub3 = keyGen(params)
    pub = groupKey(params, [pub1, pub2, pub3])

    # Simulate encrypting votes
    encrypted_votes = []
    for v in votes:
        encrypted_votes.append(encode_vote(params, pub, v))

    # Tally the votes
    total_v0, total_v1 = process_votes(params, pub, encrypted_votes)

    # Simulate threshold decryption
    privs = [priv1, priv2, priv3]
    for priv in privs[:-1]:
        total_v0 = partialDecrypt(params, priv, total_v0)
        total_v1 = partialDecrypt(params, priv, total_v1)

    total_v0 = partialDecrypt(params, privs[-1], total_v0, True)
    total_v1 = partialDecrypt(params, privs[-1], total_v1, True)

    # Return the plaintext values
    return total_v0, total_v1
```

## 零知识证明 ZKP

零知识证明中，prover 向 verifier 证明关于 secret 的一个命题，并且不泄露任何 secret 的信息。一个典型的例子就是数字签名，prover 证明他拥有私钥而不泄露私钥信息。

### Schnorr Identification 协议

- 公共参数：群 $G$，$q=ord(G)$，生成元 $g$
- Prover 拥有私钥 $x$，公钥 $pub=g^x$。选择随机的 $w$，计算 $W=g^w$ 发送给 Verifier
- Verifier 返回随机的挑战值 $c$
- Prover 计算 $r=w-cx\ (mod\ q)$ 发送给 Verifier
- Verifier 验证 $g^r\cdot pub^c=W$

我们来看一下这个协议是否满足零知识证明的几条性质：

- Completeness：即正确性
- Integrity / Soundness：即这样做是否就能证明 Prover 真的知道 x
- Privacy / Zero-knowledge：即这样做是否会泄露 x 的信息

Completeness 很容易证明：$g^r\cdot (g^x)^c=g^{w-cx}g^{cx}=g^w=W$。

为了证明 Soundness，我们假设可能的挑战值只有两个：$c$ 和 $c'$。如果要成功证明，Prover 要以大于二分之一的概率给出正确的 $r$ 或 $r'$，$r=w-cx$，$r'=w-c'x$。然而如果 Prover 不知道 $x$，那么这两个等式均为线性等式且有两个未知数 $w$ 和 $x$，此时 Prover 不可能以大于二分之一的概率给出正确答案。

Zero-knowledge 的证明方式则比较奇怪。我们看到上述协议的 transcript 是 $(W,c,r)$。假如任何人都能构造这样的三元组使得其能通过 Verifier 检查，那么这就说明 $x$ 的信息不可能被泄露，因为这里根本没有用到 $x$。而要构造这样的三元组，只需要随机选择 $r'',c''$，计算 $W''=g^{r''}pub^{c''}$（注意 $pub=g^x$ 是公钥，并没有用到 $x$），那么 $(W'',c'',r'')$ 就能通过检查。

### Fiat-Shamir 启发式技术

实际运用中我们更多时候希望能有一种非交互式的零知识证明，而 Fiat-Shamir 启发式技术就是一种将 Schnorr Identification 协议转化为非交互式的通法。

- 公共参数：群 $G$，$q=ord(G)$，生成元 $g$
- Prover 拥有私钥 $x$，公钥 $pub=g^x$。选择随机的 $w$，计算 $W=g^w$
- 计算 $c=H(pub,W,m)$ ，$r=w-cx\ (mod\ q)$，发送 $m,(c,r)$ 给 Verifier
- Verifier 验证 $H(pub,g^rpub^c,m)=c$

如果攻击者要伪造证明，需要先设置 $r,c$ 再计算 $W$。然而在第三步中 $c$ 依赖于 $W$ 的哈希，因此不能这样计算。

下面用非交互式零知识证明来证明知道 DH 私钥的信息：

```python
@pytest.mark.task1
def test_provekey_correct():
    params = setup()

    # Correct proof
    priv, pub = keyGen(params)
    proof = proveKey(params, priv, pub)
    assert verifyKey(params, pub, proof)


@pytest.mark.task1
def test_provekey_incorrect():
    params = setup()

    priv, pub = keyGen(params)

    # Incorrect proof
    priv2, pub2 = keyGen(params)
    proof2 = proveKey(params, priv2, pub2)
    assert not verifyKey(params, pub, proof2)


def to_challenge(elements):
    """ Generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash = sha256(Cstring).digest()
    return Bn.from_binary(Chash)


def proveKey(params, priv, pub):
    """ Uses the Schnorr non-interactive protocols produce a proof
        of knowledge of the secret priv such that pub = priv * g.
        Outputs: a proof (c, r)
                 c (a challenge)
                 r (the response)
    """
    G, g, hs, o = params

    w = o.random()
    W = w * g
    c = to_challenge([g, W])
    r = w - c*priv

    return c, r


def verifyKey(params, pub, proof):
    """ Schnorr non-interactive proof verification of knowledge of a secret.
        Returns a boolean indicating whether the verification was successful.
    """
    G, g, hs, o = params
    c, r = proof
    gw_prime = c * pub + r * g
    return to_challenge([g, gw_prime]) == c
```

类似地，我们同样可以证明关于一个 Commitment 的离散对数表示：

```python
@pytest.mark.task2
def test_proveCommit_correct():
    params = setup()

    # Correct proof
    secrets = [10, 20, 30, 40]
    C, r = commit(params, secrets)
    proof = proveCommitment(params, C, r, secrets)
    assert verifyCommitments(params, C, proof)


@pytest.mark.task2
def test_proveCommit_incorrect():
    params = setup()

    # Correct proof
    secrets = [10, 20, 30, 40]
    C, r = commit(params, secrets)
    proof = proveCommitment(params, C, r, secrets)

    # Incorrect proof
    secrets2 = [1, 20, 30, 40]
    C2, r2 = commit(params, secrets2)
    proof2 = proveCommitment(params, C2, r2, secrets2)
    assert not verifyCommitments(params, C, proof2)
    assert not verifyCommitments(params, C2, proof)


def commit(params, secrets):
    """ Produces a commitment C = r * g + Sum xi * hi,
        where secrets is a list of xi of length 4.
        Returns the commitment (C) and the opening (r).
    """
    assert len(secrets) == 4
    G, g, (h0, h1, h2, h3), o = params
    x0, x1, x2, x3 = secrets
    r = o.random()
    C = x0 * h0 + x1 * h1 + x2 * h2 + x3 * h3 + r * g
    return C, r


def proveCommitment(params, C, r, secrets):
    """ Prove knowledge of the secrets within a commitment,
        as well as the opening of the commitment.

        Args: C (the commitment), r (the opening of the
                commitment), and secrets (a list of secrets).
        Returns: a challenge (c) and a list of responses.
    """
    G, g, (h0, h1, h2, h3), o = params
    x0, x1, x2, x3 = secrets

    w = o.random()
    w0 = o.random()
    w1 = o.random()
    w2 = o.random()
    w3 = o.random()

    W = w * g + w0 * h0 + w1 * h1 + w2 * h2 + w3 * h3
    c = to_challenge([g, h0, h1, h2, h3, W])

    rr = w - c*r
    r0 = w0 - c*x0
    r1 = w1 - c*x1
    r2 = w2 - c*x2
    r3 = w3 - c*x3

    responses = (r0, r1, r2, r3, rr)

    return c, responses


def verifyCommitments(params, C, proof):
    """ Verify a proof of knowledge of the commitment.
        Return a boolean denoting whether the verification succeeded. """
    (G, g, (h0, h1, h2, h3), o) = params
    c, responses = proof
    (r0, r1, r2, r3, rr) = responses

    Cw_prime = c * C + r0 * h0 + r1 * h1 + r2 * h2 + r3 * h3 + rr * g
    c_prime = to_challenge([g, h0, h1, h2, h3, Cw_prime])
    return c_prime == c
```

### 相等性证明

实际上，零知识证明不仅可以用于证明知道某个秘密，还可以证明任意关于某个秘密的逻辑表达式。以相等性证明为例，假如有 $P_1=g^x,P_2=h^x$，$g,h$ 是群 $G$ 的生成元，而 Prover 想证明两个 $x$ 相等，那么可以结合 2 次 Schnorr 协议，采用 Fiat-Shamir 技术实现 NIKP。

- Prover 选择随机 $w$，$W_1=g^w,W_2=h^w$
- 计算 $c=H(g,h,P_1,P_2,W_1,W_2)$，$r=w-cx$，发送 $(c,r)$ 给 Verifier
- Verifier 验证 $H(g,h,P_1,P_2,g^rP_1^c,h^rP_2^c)=c$

```python
@pytest.mark.task3
def test_proveEquality_correct():
    params = setup()

    x, K, L = gen2Keys(params)
    proof = proveDLEquality(params, x, K, L)

    assert verifyDLEquality(params, K, L, proof)


@pytest.mark.task3
def test_proveEquality_incorrect():
    params = setup()

    x, K, L = gen2Keys(params)
    _, _, L2 = gen2Keys(params)

    proof = proveDLEquality(params, x, K, L)

    assert not verifyDLEquality(params, K, L2, proof)


def gen2Keys(params):
    """ Generate two related public keys K = x * g and L = x * h0. """
    G, g, (h0, h1, h2, h3), o = params
    x = o.random()

    K = x * g
    L = x * h0

    return x, K, L


def proveDLEquality(params, x, K, L):
    """ Generate a ZK proof that two public keys K, L have the same secret private key x,
        as well as knowledge of this private key. """
    G, g, (h0, h1, h2, h3), o = params
    w = o.random()
    Kw = w * g
    Lw = w * h0

    c = to_challenge([g, h0, Kw, Lw])

    r = (w - c * x) % o
    return c, r


def verifyDLEquality(params, K, L, proof):
    """ Return whether the verification of equality of two discrete logarithms succeeded. """
    G, g, (h0, h1, h2, h3), o = params
    c, r = proof

    k_prime = c*K + r*g
    l_prime = c*L + r*h0

    return to_challenge([g, h0, k_prime, l_prime]) == c
```

## 安全多方计算 MPC

在安全多方计算中，多个实体希望能利用自己私有的输入一起计算出一个输出，但不希望泄露私有输入的信息。

一个常见的使用 MPC 的例子是 Oblivious Transfer，此时发送者拥有多个信息，接收者发送一个数值 b，此时发送者的其中一条信息（例如下标为 b 的信息）会被发送给接收者。在此过程中，发送者不知道 b，接收者也不知道其他没接收到的信息。其他 MPC 相关例子包括 E-Voting、Proof-of-Stake、私有集合交集等等。

### 安全定义

存在两种方法来对一个协议的安全作出定义：启发式方法和严谨方法。前者尝试对协议进行攻击，如果攻击成功则改进协议，直到无法攻击为止。这种方法无法考虑到所有攻击、或是未来的新的攻击，因此并不推荐。严谨方法则可以分为如下步骤：

1. 定义攻击者的类型和能力
   1. 被动 / 主动？
   2. 计算能力有限 / 无限？
   3. 能否与系统中其他实体合作？
2. 定义网络模型
   1. 实体间通信是否使用安全信道？
   2. 攻击者能否修改消息顺序？
3. 定义“安全”的语义
   1. 通过游戏定义（密码学常用方法）
   2. 通过模拟定义（MPC 所用的方法）
4. 设计协议
5. 证明协议在上述条件下是安全的

游戏定义的安全我们在密码学中已经很熟悉了，而模拟定义的安全则基于两个模型：理想模型和现实模型。在理想模型中，参与者将输入发送给一个可信第三方，由它来计算结果并输出；而在现实模型中，由于并不存在这样的 TTP，会实际运行这个 MPC 协议来获得输出。

如果任意针对现实模型的攻击都同样能针对理想模型，那么协议就是安全的，因为理想模型下无法开展攻击。这里用了一点反证法，实际上就是密码学中常用的那种套壳归约的方法（经典例子：将 DH 密钥交换协议归约到 DDH 问题上）。一言以蔽之，如果攻击者无法区分它处于理想模型中还是现实模型中，那么协议就是安全的。

### 涉及技术

- 同态加密
  - 全同态加密（支持任意运算，开销较大）
  - 部分同态加密
- Commitment Scheme
- 秘密分享
- 可信执行环境 TEE
- 区块链

## 私有集合交集 PSI

顾名思义，PSI 旨在计算多个集合的交集而不泄露集合的信息。可以看到，如果把每个参与者的私有集合作为输入，集合交集作为运算，那么 PSI 就是 MPC 的一种特例。面对被动攻击者时，PSI 只需要满足机密性即可；而面对主动攻击者，PSI 需要确保交集运算的结果正确，即能检测对结果的篡改。

### 涉及技术

- 安全性

  - 同态加密

  - 表示为有限域上的多项式

    - $p(x)=\Sigma_{i=1}^d(x-s_i)\ for\ S=\{s_1,...,s_d\}$
    - 多项式的根即集合元素，多项式之和的根即为交集（或求 GCD）
    - 对于 d 次多项式 $p_A,p_B$（代表 $S^{(A)},S^{(B)}$），以及随机的 d 次多项式 $\gamma_A,\gamma_B$，令 $\theta=\gamma_A\cdot p_A+\gamma_B\cdot p_B=\mu\cdot gcd(p_A,p_B)$，$\mu$ 为随机多项式，此时 $\theta$ 仅包含 $S^{(A)}\cap S^{(B)}$ 的信息而不包含任一集合其余元素的信息

  - 哈希函数

  - 伪随机函数

- 性能

  - 数据结构
    - 哈希表：将集合元素哈希到表中，在表上计算
    - 布隆过滤器：状态压缩后进行传输和计算
  - 将 ZKP 替换为一些特殊的方法，如在输入中设置陷阱来防篡改
  - Horner 方法

### 分类

在传统 PSI 中，参与者交互式地执行协议以计算结果，每次计算都要使用本地的集合数据。然而在委托式 PSI 中，参与者可以将数据编码后上传至云服务商，委托云服务商进行 PSI 计算：这种委托可以是一次性的，即每次计算都要重新将数据编码上传；也可以是重复的，一次上传多次使用。

### 应用场景

- 在线游戏作弊检测
- 疫情接触者追踪
- Chrome 扩展检查密码是否在泄露数据库中
- SNS 查找共同好友

### 🌰 Apple PSI

Apple 使用 PSI 技术来检测用户的 iCloud 中是否存储了非法的儿童色情图片，同时避免泄露用户 iCloud 中的正常图片。

假设 $X$ 是服务器中非法图片的哈希值集合，客户端中的图片集合可以用 $Y=((y_1,id_1,ad_1),...,(y_m,id_m,ad_m))$，其中 $id$ 是每个元素的标识符，$y$ 是该图片的哈希值，$ad$ 是附加信息。现在，如果客户端拥有超过阈值 $t$ 张照片满足其对应的 $y_i$ 位于 $X$ 集合中，那么我们希望能获得所有的对应的 $(id_i,ad_i)$ 集合。

> 例如，$X=(y_1,y_2,y_3,y_4,y_5),Y=((y_1,id_1,ad_1),(y_3,id_3,ad_3),(y_8,id_8,ad_8)),t=1$，由于符合条件的照片数超过了阈值 1，服务器应该能且只能收到 $(id_1,ad_1),(id_3,ad_3)$，并且无法获得任何关于 $(y_8,id_8,ad_8)$ 的信息。

那么这一目标是如何达到的呢？首先，我们需要：

- 哈希表 $T$，其对应的哈希函数是 $h$，容量为 $n'$
- 密钥生成函数 $H'$
- 对称加密机制 $(Enc,Dec)$
- 另一个哈希函数 $H$
- 阈值为 t 的秘密分享机制：至少需要 t+1 份秘密碎片才能重建秘密

整个协议是这样运行的：

1. 服务端根据 $X$ 计算出 `pdata` 和服务端密钥，发送 `pdata` 给客户端

2. 客户端检查 `pdata` 中元素两两不同且非空，生成客户端密钥 `adkey`

3. 客户端利用客户端密钥、`pdata`、客户端的一张照片计算出对应的 `voucher` 发送给服务器

4. 服务器利用服务端密钥、`voucher` 计算出最终结果

在第一步中，服务器先将 $X$ 中的值插入到 $T$ 中，选择随机值 $\alpha$ 和有限域生成元 $G$，计算 $L=G^\alpha$（为了隐藏 $\alpha$，类似非对称密码）。对于每个 $T$ 中元素，如果该元素非空，计算 $P_i=(H(T[i]))^\alpha$；否则，设置 $P_i$ 为随机值。最后，`pdata` 被设置为 $(L,P_1,...,P_{n'})$ 并发送。

到了第三步，客户端首先加密附加信息：$adct=Enc_{adkey}(ad)$，生成 $adkey$ 的秘密碎片 $sh$，随后随机选择新的密钥 $rkey$，计算 $rct=Enc_{rkey}((adct,sh))$。

接下来，客户端需要对这张照片的 $y$ 进行编码，首先决定其在哈希表的位置：$w=h(y)$，随后加密 $y$ 得到 $Q$ 并生成 tag $S$：选择随机的 $\beta,\gamma$，计算 $Q=(H(y))^\beta\cdot G^\gamma$。从 `pdata` 中取 $P_w,L$，计算 $S=(P_w)^\beta\cdot L^\gamma$。接着生成新密钥 $S'=H'(S)$，用来加密 $rkey$：$ct=Enc_{S'}(rkey)$。最后，`voucher` 被设置为 $(id,Q,ct,rct)$ 并发送。

第四步，服务器首先初始化空列表 `SHARES`。从 `voucher` 中读取 $Q$，计算 $\hat{S}=Q^\alpha$。

> 如果照片在 $X$ 中，那么 $\hat{S}=Q^\alpha=(H(y))^{\beta\alpha}\cdot G^{\gamma\alpha}=(P_w)^\beta\cdot L^\gamma=S$。

然后，服务器生成新密钥 $\hat{S'}=H'(\hat{S})$，提取 $rkey=Dec_{\hat{S'}}(ct)$，如果解密失败则中止。下一步则是提取 $adct$ 和 $sh$，只需要 $(adct,sh)=Dec_{rkey}(rct)$，如果解密失败同样中止。解密完成后，将 $(id,adct,sh)$ 加入到 `SHARES` 中。此时我们成功匹配到了非法图片。

如果 `SHARES` 中存在至少 t+1 份碎片，那么就可以重建 $adkey$ 了。最后一步就是利用 $adkey$ 提取 $ad$：$ad=Dec_{adkey}(adct)$。

## Selective Disclosure

传统认证系统往往将身份和属性绑定，这会导致一定程度的隐私泄露。而在 Selective Disclosure 中，Verifier 不会获得任何关于 Prover 的非必要的信息。首先 Issuer 给 Prover 一个类似证书的 credential，随后 Prover 对自身的属性进行断言发给 Verifier，最后 Verifier 和 Issuer 交互来验证 Prover 的断言是否合法。

这里介绍一种基于 MAC 的方案，该方案假设 Issuer 和 Verifier 是同一主体。

传统方式中，Prover 将断言发给 Verifier 时由于用到了 MAC，无法破坏完整性，但 MAC 并不提供机密性。但如果加入零知识证明和匿名通信机制，那么 Prover 就可以通过匿名通信信道和 Verifier 交互，并通过零知识证明来证明断言、以及对应的 MAC。

### Algebraic MAC

Algebraic MAC 提供了两个很好的性质：

- 在可行时间里证明 MAC 的正确生成（Issuing）
- 在可行时间里证明 MAC 的持有（Showing）

首先需要一个素群 G，生成元 g 和 h，随后生成私钥 $sk=\{x_0,x_1,...,x_k\}$，其中 k 是要编码的属性个数。随后公布 Issuer 参数 $\texttt{iparams=}\{X_i=h^{x_i}\} \texttt{ for }i>0$。

Algebraic MAC 以私钥和 k 个属性 $m=\{m_i\}\texttt{ for }1<=i<=k$，选择一个 $u\in G/\{1\}$,计算 $u'=u^{H_{sk}(m)}$，其中 $H_{sk}(m)=x_0+\Sigma m_ix_i$。最后输出 tag：$(u,u')$

验证的过程则是反过来，验证 $u'$ 是否等于 $u^{H_{sk}(m)}$。这里可以注意到，MAC 的生成和验证都需要私钥。

### aMAC + ZKP

在 Selective Disclosure 方案中，我们要让 Prover 零知识证明它知道关于这些属性的合法的 aMAC。整个方案分四阶段：

- Setup 初始化参数 （G，p，g，h）
- CredKeyGen 生成 Issue 密钥和公钥
- Credential Issuance Protocol
- Credential Showing Protocol

在 CredKeyGen 中，首先初始化 aMAC 的参数，随后在 $Z_p$ 中随机选择 $o_{xo}$，计算 Commitment $C_{xo}=g^{x_0}h^{o_{xo}}$。输出公钥 $(\texttt{iparams}, C_{xo})$，私钥 $(sk,o_{xo})$。

Credential Issuance 中 Issuer 将属性编码成消息 $m_i$，计算 $Tag(u,u')=MAC(sk,\{m_i\})$，然后计算证明 $\pi_0=NIZK\\{(sk,o_{xo}):u',C_{xo},X_i\\}$。Prover 获得 $(u,u')$ 后，验证 $\pi_0$。

Credential Showing 中 Prover 在 $Z_p$ 中随机选择 $a,z_i,r$，计算：

- $u_a,u_a'=(u^a,u'^a)$
- $C_{mi}=u^{m_i}h^{z_i}$
- $C_{u'}=u_a'g^r$

随后产生证明 $\pi_1=NIZK\\{(z_i,r,m_i):C_{mi},V=g^{-r}\Pi X_i^{z_i}+...\\}$， `...` 处是其他关于属性的声明。输出 $(u_a,C_{mi}, C_{u'}),\pi_1$.

> 选择这么多随机数都是为了让属性匿名化。

最后，Verifier 计算 $V=u_a^{x_0}\Pi C_{mi}^{x_i}/C_{u'}$，并利用 V 来验证 $\pi_1$.

### 应用

- 基于属性的访问控制
- 分布式身份管理
- 隐私友好的电子身份信息
