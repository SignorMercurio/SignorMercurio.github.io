---
title: 一点 C 语言的经验
date: 2018-10-17
tags:
  - C/C++
categories:
  - 编程语言
---

被邀请分享 C 语言学习经验，于是写了点东西给学生会做推送。

<!--more-->

## Q&A

> Q1: 大家一开始初学的时候程序里有很多很多的 bug，大多是语法符号规范的错误，如何避免这些问题呢？

A1: 答案很可能要令人失望：**多写代码**。尽管听起来老生常谈，但是当代码量达到一定水平后，忘加分号或是把 `==` 写成 `=` 之类的语法错误几乎不会在你的代码中出现，也不需要再刻意去规避。

不过，在多写的基础上，仍有一些小技巧或许能有帮助：

0. **认真阅读编译器给出的警告（warning）信息**，明白其中的缘由，并且（如果不是有意为之）消除它们，尽管有时 warning 不会影响程序正确性。

1. 还是让聪明的编译器来帮忙：对于把 `==` 写成 `=` 的问题，可以考虑写 `if (true == flag)` 而不是 `if (flag == true)`。这样，当你写成 `=` 号时，第一种形式会导致编译错误。当然，如果做到了第一条，你不会需要这个技巧。

2. 部分 IDE 或文本编辑器插件支持即时错误提示功能，这样可以在你写出错误语法的第一时间提醒你改正。不过不要太依赖这种功能。

3. 与上一条相反，如果觉得自己足够熟练了，试着离开 IDE 写代码，并用命令行下的 gcc 编译运行。由于这样做不如在 IDE 内运行方便，你也许会在写代码时十分小心，并在写完代码后反复检查来减少重复编译运行的次数（也许不会）。

> Q2: 作为萌新的我们，不知道怎么着手学习 C 语言，对于基础知识这块非常的薄弱，书上的内容感觉不是很系统，有什么好方法呢？能不能给我们推荐一些有用的参考资料呢？

A2: 老实说，我觉得学校用的 _K&R_ 足够好了，并且也不太可能有什么 C 语言书籍能超越它。不过如果觉得看得很累的话，不妨试试国内的任意一本豆瓣评分较高的 C 语言书籍。虽然它可能没那么好，甚至会误导人，但至少能够帮助没有基础的同学建立一些基本概念。

当然，如果你不屑看国内的书籍，这两本书也可以作为参考：

0. _C Programming: A Modern Approach_ K.N.King 著

1. _C Traps and Pitfalls_ Andrew Koenig 著

（对任何国外的专业书籍请尽可能**阅读原版**）

最重要的是，在阅读时必须**完成一部分书上的习题**（乐意的话做 OJ 也行），通过实践进步是最快的。但是如果你真的想精通 C 语言而不是为了通过考试，仅仅快还不够——在代码量达到，比如 300 行左右时，请回头**认真阅读 _K&R_**。

> Q3: 理论课上学到的知识，在实践课上不是很会操作，怎么尽快地能够应用呢？

A3: 要 “尽快” 的话，无疑需要：

0. 多看别人的优质代码；

1. 自己多写代码。

学校的 OJ 平台提供了一些相当有用的功能，如将题目按 Reward 排序，在 AC 后可以查看他人代码等等。利用这些功能从低难度题开始练习，并且在自己完成后观赏（嗯，观赏）优秀的代码（如 Fastest，Shortest 等），往往会有新的体会。另外，务必**学会使用搜索引擎**，但同样不要太依赖。

如果做 OJ 题让你感到很无趣，不妨试试**小项目驱动**的方法：学完结构体后，你差不多就可以写一个控制台里的文字 RPG 游戏了（好吧，可能还是不那么有趣）；或者，可以写一些小的实用工具（科学计算器，xx 管理系统，文件批处理工具，表白程序等等）；你甚至可以尝试去写一个伪 Shell。

> Q4: 我们怎么才能判断什么时候该用什么函数？

A4: 我猜这里的 “函数” 是指“库函数”。

要背出所有库函数的功能显然不太现实，那么范围缩小到 “常用” 的会怎样？实际上，一个好用的方法是在做题时（或者做小项目时），当你需要一个功能，试着描述这个功能，打到搜索框里，并在前面加上“C”（不带引号）。可以选择看国内的博文，但我推荐查阅 **C 标准库的官方文档**。

有一次我忘记了 `strcpy` 函数的参数顺序了，于是我很快查到了并关掉了网页。突然我因为别的事离开了电脑几分钟，回来时我又一次忘了那个顺序。这是在查阅资料时必须杜绝的现象，解决方法是：**不要只看对你有用的部分**，而是每次查阅都尽量深入地了解这个函数——一些用法也许很难一次记住，但经过多次查阅和实践后，也许你就能对 C 标准库中的常用函数如数家珍了。

> Q5: 拿到一个问题我们该怎么着手处理呢？步骤是什么呢？

A5: 每个人都有不同的方法，我仅提供我自己的作为参考，未必适合每一个同学：

0. 确保正确**理解了题意**。读完题就开始写，写到一半发现题意理解错的体验，包括我在内的很多人都有过。

1. **由易到难**。不要先考虑问题的最优解法，而是先从思维难度低的，或许看起来有点 low 的做法开始，设法改进你的算法。你甚至可以写一个正确性可以保证但速度较慢的版本，与你写的更优解法的版本进行对拍（请自行搜索如何对拍）。

2. **想好完整的思路后再碰键盘**。也就是说，一旦你开始写代码，尽量减少停下来长时间思考的时间。这很难，所以不强求。

3. 最重要的，**熟悉常用思路 / 算法**。例如穷举、模拟、贪心、排序、字符串处理、二分、递归 - 记忆化搜索 - DP 等等。在许多 OJ 上，题目会按它所用到的思路 / 算法来分类（如 EOJ 上叫做 tag）。当你足够熟悉这些常用思路 / 算法后，许多题可以匆匆一瞥就想到算法了——而这时，可能已经成功了 50%（也可能只成功了 5%）。

4. **学会调试程序（debugging）**。绝大多数情况下程序不可能一次运行就得到正确结果，花在查错改错上的时间往往比思考时间 + 实际编写程序的时间更长。而至少在查错上，**gdb **可以帮助我们节省不少时间。通常 C 语言 IDE 都带有 gdb 调试器，**一定要学会使用它！**另外可以配合 printf 变量的值进行调试。

> Q6: 对于 OJ 这个系统，我们怎么利用它呢？

A6: 取决于你的目标。

0. ACMer
   默认已经有一定基础（比如：能轻松解决 EOJ 上大部分 Reward <= 4 的题）。买本书学算法（比如 “紫书”、“挑战” 等），做书上练习，并在各大 OJ 上进行专题练习。多打比赛（CF / EOJ 月赛），**怎么样都别抄代码**。之后就看自己了，我不打 ACM 所以不能给出有用的建议。

1. 对程序设计与算法很感兴趣，想要深入学习的同学
   **巩固好基础（多写题 + 读 K&R）**。推荐读紫书（《算法竞赛入门经典》），能认真读完并且每章多少做掉一部分习题的话，你的水平应该已经超过一部分 ACMer 了。之后可以选择**专题练习（别抄代码）**，数学好的也可以选择去读《算法导论》一类的书。

2. 想实践课和实训课拿高绩点的同学
   到 EOJ 的 Gym 里找实训题库，做题、总结思路 / 算法，后者更重要。看完题就知道怎么做的题（指代码结构在脑子里都组织好了），不做；想了半小时没思路可以查题解但是不要看代码，依然不会做的话，也放弃。一天就能做十题和十天只能做一题的那种题，对实力的提升都没有太大帮助。
   另外，实训 4.0 可遇不可求，不要为此花费太多时间在 OJ 上，即使你像我一样喜欢做题而完全不觉得累，因为其他课程也是很重要的。

3. 想通过实践课和实训课考试的同学
   听课，做 OJ 上老师布置的题。有时间的话，从 Reward 较低的题开始做起，提升熟练度。百题过后，通过应该没有难度了。

4. 所有人
   优雅的 EOJ 提供了用户手册，如果你真的想好好利用这个平台的话，请阅读一下。一些其它 OJ 也有类似的文档。但是 Online Judge 只是平台，Coding 才是关键。必须在最后强调的一点是：**尽力独立思考，绝对不抄代码**。

## 经验分享

宽泛的内容上面的回答已经基本涵盖了，下面是 30 条具体的东西，请结合搜索引擎食用。

### 编译与链接

0. 一个编译单元中定义的全局变量初始值不要依赖定义在另一个编译单元中的全局变量初始值。（链接器不保证初始化顺序）

### 数据类型

1. 一个 `void *` 类型的指针是一个合法的指针，常用于函数参数中用来传递一个函数与其调用者之间约定好类型的对象地址；而一个值等于 `NULL` 的指针虽然也是一个合法的指针，但不是一个有效的指针。

2. 标准 C 语言允许任何非 `void *` 类型指针和 `void *` 类型指针之间进行直接的相互转换，如 `int *` 转换为 `void *` 再转换为 `double *`，然而这样做存在不易察觉的安全问题（内存扩张 / 截断）。

3. 强制转换时必须同时确保内存访问的安全性和转换结果的安全性，并且尽量用显式的转换。

### 标识符与表达式

4. 避免用前导 `_` 和 `__` 定义标识符，因为一些内部名称和预定义的宏是这样命名的。

5. 标识符命名应该遵循 KISS 原则（Keep It Simple & Stupid），并且应该能自说明。

6. 别记运算符优先级，用括号。

7. 用 `&&` 时把最可能 `false` 的子表达式放左边，用 `||` 时把最可能 `true` 的子表达式放左边。（短路原则）同理，`if/else` 结构中把最可能 `true` 的条件放前面。

8. 浮点数比较不要用 `==` 和 `!=`，而是像这样：

   ```c
   #define EPS 1e-6              // 设置要求的精度
   if (fabs(x - y) <= EPS);      //x 等于 y
   if (fabs(x - y) > EPS);       //x 不等于 y
   /*
   * 其中 x,y 是浮点数。fabs 函数在 math.h 中，计算浮点数绝对值。
   * 不过对浮点数用>和 <是可以的，不过不建议用!(x>y) && !(x<y) 来判断相等，因为这和 x==y 语义等价。
   */
   ```

9. 看到表达式里出现 error / warning 时，想想运算符两端是不是类型一致。不要把指针和 0 比较，也不要把数值和 `NULL` 比较。

### 循环

10. C 按先行后列的顺序存储数组元素，所以两层 `for` 遍历时，先行后列比先列后行快几十倍。这听起来不可思议（总循环次数是一样的），不妨写两个程序试试？（原理见神书 CSAPP）

11. 循环体内存在逻辑判断，并且循环次数很多时，试试把逻辑判断移到外面。

12. 少用 `goto`，除非要从多层循环里直接跳出来。

### 函数

13. 函数调用中参数传递的本质就是用实参来初始化形参而不是替换形参。

14. 如果参数是指针，且仅做输入用，则应在类型前加 `const`，防止该指针指向的内存单元被无意修改。

15. 不要省略返回值类型，没返回值就用 `void`。标准 C 语言中，不加类型说明的函数一律按 `int` 类型处理。

16. 函数名和返回值在语义上不可冲突。不要将正常值和错误标志混在一起返回。建议正常值用输出参数获得，而错误标志用 `return` 返回。强调这个是因为 C 标准库中典型的反面教材：`getchar()`。看函数名似乎应该返回 `char` 类型，实际上它却返回 `int` 类型，只因为要返回错误标志 `EOF`，也就是 -1。

17. `return ` 语句不可返回指向堆栈（如函数内局部变量）的指针，因为该内存单元在函数体结束时被自动释放。

18. 尽管语法允许，不要在内层程序块中定义会屏蔽外层程序块中同名标识符的标识符，否则会损害程序的清晰性。

19. 学用 `assert` 宏。

### 指针

20. 不管什么指针变量都要在声明的时候就初始化它，`NULL` 也行。

21. 将指针加 / 减正整数 `i` 等价于加 / 减 `i*sizeof(指针所指数据类型)`。

22. 传指针本质上是传地址。

23. 表示 `a` 数组第 4 个元素 `a[3]` 居然还可以写成 `3[a]`，这是为什么？（我开始写数组相关的内容了，却还是在指针板块，这又是为什么？）

24. 多维数组作为函数参数时，为什么不需要说明第一维的大小而必须说明后面所有维的大小？

25. 即使你觉得自己不会忘记字符数组末尾的 `\0`，你还是会忘记。（有些库函数不会自动加 `\0`）

26. 对下面的代码，输出 `p` 和 `*p` 有什么不同？

    ```c
    char ch = 'a';
    char *p = &ch;
    ```

27. 函数指针了解一下。

### 结构体

28. 你可以用 “位域” 指定 `struct` 中成员变量所占的 `bit` 数（而不是 `byte`），只不过成员类型必须是 `int/unsigned int/signed int` 之一。

29. 根据自然对齐的原理，合理安排成员变量的声明顺序。（详见神书 CSAPP）

---

最后提醒大家，程序的正确性固然重要，但是一定不要轻视其可读性、可维护性、健壮性、时空效率等等。不过也不用纠结大括号换不换行，缩进用 Tab 还是空格的问题。祝大家都能写出清晰、高效的优质代码！
