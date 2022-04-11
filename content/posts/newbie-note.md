---
title: 问题笔记
date: 2017-11-08 10:49:05
tags:
  - C/C++
  - 实践记录
categories:
  - 编程语言
---

第一篇博文。

<!--more-->

## 关于类型

- CodeBlocks 使用 MinGW 编译器，`long long` 类型输出表示为 `"%I64d"`，且 `__int64` 合法；
- EOJ 使用的似乎是 g++ 的 Linux 版本编译器，`long long` 类型输出表示为 `"%lld"`， 且 `__int64` 不合法；
- `long double` 类型是合法的，但是在 MinGW 编译器中不能格式化输入 / 输出。`%llf`，`%Lf` 这些都不行。

## 关于 ILE

`Idleness Limit Exceeded` 常见于交互题。

在使用多个输出函数连续输出时，有可能产生输出错误，因为在上一个数据还在输出缓冲区中时，下一个 `printf` 就把另一个数据加入输出缓冲区，冲掉了原来的数据，造成输出错误。

解决方案：

- 在 `printf` 后加上 `fflush(stdout)`；
- 使用 `cout<<endl` 输出似乎效果等同？

## 关于其他注意事项

- 变量 / 数组的初始化
- `scanf` 后回车符的吸收
- `gets` 的不安全性
- `getline` 多次使用注意添加 `str = "\n"; getline(cin, str);`
- EOJ 编译器对 `getchar(); ... gets();` 的支持似乎不太好？
- 经常把 `==` 写成 `=`
- 尽量避免使用非 C 标准库函数，如 `itoa`, `strlwr`, `strupr` 之类
- RTE 主要原因：数组越界、指针越界、除以 0、栈溢出……