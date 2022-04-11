---
title: 走远了的词法分析器
date: 2019-04-11 20:56:28
tags:
  - C/C++
  - 编译原理
categories:
  - 编程语言
---

奇怪的思路果然总是通向奇怪的出路。

<!--more-->

## 概述

编译原理课的实训题，难度是不大的，然而我自作聪明地用 `stringstream` 强行给自己增加了难度……

实际上，即使增加了这点难度，这次实训依然不难，然而有两个天坑：

- 对于格式化字符串里诸如 `%d` 的字符，需要将其视为一个词素
- 注释也被算作词素，需要被打印出来

这两条都是实训题人为规定的。第一条或许还能理解，但是真正实现起来会是代码复杂很多，因此我在代码里暴力绕过了这个限制。

> 注：为什么说实现第一条比较复杂？
> 这不仅是因为 C 语言中存在 `%` 运算符，即取模，还因为格式化字符串本身十分灵活。不妨考虑遇到如下六种模式时如何匹配：
> 
> 1. `printf("%d, i")` 普通情况
> 2. `printf("%-5d", i)` 右对齐，或者高位补 0 等操作
> 3. `printf("%.2f", i)` 浮点数精度
> 4. `printf("%d %d %d", i, j, k)` 多个空格隔开的 %d 使得识别 % 前面的 " 来判断是否在字符串内变得不可行
> 5. `printf("50%% %d", i)` 取模符号本身的转义
> 6. `a = a % d` 字符串外的取模符号
> 
> 解决方法还是有的：记录 `"` 的开闭状态来判断当前的 `%` 是否在字符串中，对 `%-`，`%.` 和 `%%` 特判。但是这样就有点复杂了。

第二条就恶心得多了。众所周知，处理注释的最好方法是在一开始就删掉它（我最初也是这么做的），然而由于第二条规定的存在，我不得不使用一些小技巧来达到要求。这也是这次走远了的主要原因，为此我多花了一个小时。关于这些技巧会在后面详述。

## 思路

代码的主要思想是用 `map` 存词素对应编号，借助 `stringstream` 对象按空白符分隔程序语句逐条处理（然而这并没有多大用，因为 C 语言很多地方是允许不空格的，我最后还是得逐字符分析）。

1. 对于数字开头的一段字符，可以确定直到非数字字符之前都是同一个数字，算作一个词素。
2. 如果我们运气足够好（编译代码风格较好的 C 代码），`stringstream` 分出来的语句大多能匹配上 `map` 里的词素。不过实际情况中我们可以认为这是小概率事件，所以放在了 else 而不是 if 里。
3. 接下来就是针对分离出来的这一小段 `cur` 作扫描了，本来可以用递归优雅地扫描，然而如果出现很长一段没有空格的语句，递归可能使栈溢出，因此这里采用循环来替代。先从左至右匹配 `map` 里的词素，直到第一次匹配成功。
4. 匹配成功并没有结束，我们还需要进行**贪婪匹配**。举个栗子，`<<=` 可以匹配 `<`，`<<` 和 `<<=` 三个词素，显然我们应匹配最后一个，也就是尽可能长的那个词素。匹配完成后输出，并跳过已匹配的那一段继续。
5. 也有可能我们在第 3 步根本无法匹配成功，这说明该串**以标识符开头**，例如 `main()`，因此我们把标识符名拿出来以后再继续。方法是扫描至第一个不是下划线 / 字母 / 数字的字符为止。

本来这样就结束了，我可以高高兴兴地删掉注释、trim 掉两边空格、处理下最后一行不能换行的无聊问题后就搞定的。然而。。。为什么注释要被当作词素打印出来？？这种做法完全是不合理而低效的。

## 注释的处理

代码长度因为处理毫无处理必要的注释增加了许多。首先在清除注释时（对，我一定要清除注释）先把注释内容按单行 / 多行保存到两个数组里，随后是杂技表演时间：

- 对于单行注释，用 `@n` 替换原注释，因为 `@` 这个符号在 C 源代码里没有什么特殊含义，也不能在标识符中出现（`$ ` 是可以的，有点奇怪）。其中 `n` 表示这是第 `n` 个单行注释。
- 对于多行注释同理，用 <code>`n</code> 替换原注释。

于是扫描时，当我们发现一个语句无法匹配词素、且截取标识符也没有变动下标时，只可能是遇到了单字母变量，或者是我们作的这两个标记之一。`isalpha` 排除掉前者情况，这时拿出刚才数组里存的对应注释内容，打印输出即可。

这种杂技看似好玩，实际上也是走远了之后的无奈之举，我觉得肯定是存在隐患的，也并不利于维护。因此强烈不推荐用这种方法，直接清除注释的办法高到不知道哪里去了。

## C++ 代码

不到 200 行。

```cpp
// C 语言词法分析器
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
using namespace std;
/* 不要修改这个标准输入函数 */
void read_prog(string& prog)
{
    char c;
    while(scanf("%c",&c)!=EOF){
        prog += c;
    }
}
/* 你可以添加其他函数 */

map<string, int> tokens = {
    {"auto", 1},
    {"break", 2},
    {"case", 3},
    {"char", 4},
    {"const", 5},
    {"continue", 6},
    {"default", 7},
    {"do", 8},
    {"double", 9},
    {"else", 10},
    {"enum", 11},
    {"extern", 12},
    {"float", 13},
    {"for", 14},
    {"goto", 15},
    {"if", 16},
    {"int", 17},
    {"long", 18},
    {"register", 19},
    {"return", 20},
    {"short", 21},
    {"signed", 22},
    {"sizeof", 23},
    {"static", 24},
    {"struct", 25},
    {"switch", 26},
    {"typedef", 27},
    {"union", 28},
    {"unsigned", 29},
    {"void", 30},
    {"volatile", 31},
    {"while", 32},
    {"-", 33},
    {"--", 34},
    {"-=", 35},
    {"->", 36},
    {"!", 37},
    {"!=", 38},
    {"%", 39},
    {"%=", 40},
    {"&", 41},
    {"&&", 42},
    {"&=", 43},
    {"(", 44},
    {")", 45},
    {"*", 46},
    {"*=", 47},
    {",", 48},
    {".", 49},
    {"/", 50},
    {"/=", 51},
    {":", 52},
    {";", 53},
    {"?", 54},
    {"[", 55},
    {"]", 56},
    {"^", 57},
    {"^=", 58},
    {"{", 59},
    {"|", 60},
    {"||", 61},
    {"|=", 62},
    {"}", 63},
    {"~", 64},
    {"+", 65},
    {"++", 66},
    {"+=", 67},
    {"<", 68},
    {"<<", 69},
    {"<<=", 70},
    {"<=", 71},
    {"=", 72},
    {"==", 73},
    {">", 74},
    {">=", 75},
    {">>", 76},
    {">>=", 77},
    {"\"", 78},
  {"%d", 81},
  {"%s", 81},
  {"%c", 81},
  {"%f", 81},
  {"%lf", 81}
};
string cur, tmp;
int len, cnt;
bool show_time;
vector<string> annos[2];

/* 打印常数，输出至非数字字符 */
void print_num(int &idx) {
    if (show_time) cout << endl;
    cout <<++cnt <<": <" << cur[idx++];
    while (isdigit(cur[idx])) {
        cout <<cur[idx++];
    }

    cout <<",80>";
}

/* 打印非常数词素 */
inline void print_token(const string &token, const int &id) {
    if (show_time) cout << endl;  // 处理最后换行问题
    cout <<++cnt <<": <" << token <<","<< id <<">";
}

/* 清除所有注释 */
void rip_anno(string& prog) {
    int pos = 0, from, to;

    while ((from = prog.find("//", pos)) != string::npos) {
        to = prog.find('\n', from);
        annos[0].push_back(prog.substr(from, to-from));  // 先保存注释内容
        prog.erase(from, to-from);
        prog.insert(from,"@"+ to_string(annos[0].size()));  // 插入单行注释标记 @
    }
    pos = 0;
    while ((from = prog.find("/*", pos)) != string::npos) {
        to = prog.find("*/", from);
        annos[1].push_back(prog.substr(from, to-from+2));
        prog.erase(from, to-from+2);
        prog.insert(from,"`"+ to_string(annos[1].size()));  // 插入多行注释标记 `
    }
    prog.erase(prog.find_last_not_of(" \n\r\t") + 1);  // 删除尾部空格
}

void Analysis()
{
    string prog = "int main()\n{\nprintf(\"HelloWorld\");\nreturn 0;\n}";
    //read_prog(prog);
    rip_anno(prog);

    istringstream ss(prog);  // 用空格分隔每次读入

    while (!ss.eof()) {
        ss >> cur;
        len = cur.length();

        for (int i = 0; i < len;) {
            /* 每次 for 循环开始时，必定是新词素 */
            if (isdigit(cur[i])) {
                print_num(i);
            } else {
                if (tokens[cur] == 0) {  // 用空格分隔出的串不能直接匹配词素
                    // 极端情况如：for(var=0;var<10;++var){...;...;}，递归处理可能爆栈，因此用循环
                    int j = 1, k;

                    while (i + j <= len && tokens[cur.substr(i, j)] == 0) ++j;  // 从左至右尝试匹配词素，直到第一次匹配成功

                    if (i + j> len) {  // 整个串都无法匹配，因此串以标识符开头
                        for (k = i; k < len && (cur[k] == '_' || isalnum(cur[k])); ++k);  // 截取标识符名

                        if (k == i && !isalpha(cur[k])) {  // 特判：这里可能是单字母变量，或我们加的注释标记
                            print_token(annos[cur[k] == '@' ? 0 : 1][cur[k+1]-1 - '0'], 79);
                            i = min(len, k + 2);  // 为什么词法分析器要把注释当词素处理而不是直接清除注释？多此一举
                        }
                        else {
                            print_token(cur.substr(i, k - i), 81);
                            i = k;
                        }
                    } else {
                        while (i + j <= len && tokens[cur.substr(i, j)] != 0) ++j;  // 成功匹配后，进行贪婪匹配

                        tmp = cur.substr(i, j - 1);
                        print_token(tmp, tokens[tmp]);
                        i += j - 1;  // 跳过已被贪婪匹配的词素并继续
                    }

                } else {
                    print_token(cur, tokens[cur]);
                    show_time = true;
                    break;
                }
            }
            show_time = true;  // 第一个词素已经打印了！
        }
    }
}
```
