---
title: LL 语法分析器
date: 2019-05-09 23:15:47
tags:
  - C/C++
  - 编译原理
  - 项目
categories:
  - 编程语言
---

这次繁杂了许多，我有点害怕接下来的 LR(1) 语法分析器了。

<!--more-->

## 概述

这次需要用 LL(1) 方法也就是自顶向下方法实现语法分析器，并且需要识别并改正简单的语法错误（这里只出现了漏分号的错误）。举个栗子，输入：

```c
{
while (ID == NUM)
{
ID = NUM
}
}
```

需要按这个格式输出：

```
语法错误, 第 4 行, 缺少 ";"
program
    compoundstmt
        {
        stmts
            stmt
                whilestmt
                    while
                    (
                    boolexpr
                        arithexpr
                            multexpr
                                simpleexpr
                                    ID
                                multexprprime
                                    E
                            arithexprprime
                                E
                        boolop
                            ==
                        arithexpr
                            multexpr
                                simpleexpr
                                    NUM
                                multexprprime
                                    E
                            arithexprprime
                                E
                    )
                    stmt
                        compoundstmt
                            {
                            stmts
                                stmt
                                    assgstmt
                                        ID
                                        =
                                        arithexpr
                                            multexpr
                                                simpleexpr
                                                    NUM
                                                multexprprime
                                                    E
                                            arithexprprime
                                                E
                                        ;
                                stmts
                                    E
                            }
            stmts
                E
        }
```

遵循的规则，也就是 CFG 的产生式是：

```
program -> compoundstmt
stmt ->  ifstmt  |  whilestmt  |  assgstmt  |  compoundstmt
compoundstmt ->  {stmts}
stmts ->  stmt stmts   |   E
ifstmt ->  if (boolexpr) then stmt else stmt
whilestmt ->  while (boolexpr) stmt
assgstmt ->  ID = arithexpr ;
boolexpr  ->  arithexpr boolop arithexpr
boolop ->   <|>  |  <=  |>=  | ==
arithexpr  ->  multexpr arithexprprime
arithexprprime ->  + multexpr arithexprprime  |  - multexpr arithexprprime  |   E
multexpr ->  simpleexpr  multexprprime
multexprprime ->  * simpleexpr multexprprime  |  / simpleexpr multexprprime  |   E
simpleexpr ->  ID  |  NUM  |  (arithexpr)
```

注意到这里面已经消除了左递归，也没有公共左因子（最后发现也没有二义性），非常舒服。

起始符是 `program`，保留字有：

```
{ }
( )
if then else
while
ID NUM
> <=>= <= ==
+ -
* /
E 是 '空'
```

## 思路与代码

其实坑不多，但是容易自己给自己挖坑，例如抄规则把规则抄错等，其实很难发现。

### 准备工作

首先我们需要将产生式存下来。由于产生式本身是一种映射关系，容易想到用 `map` 存储。因为懒得处理 `|`，直接把用 `|` 分隔的产生式拆开。这样一来，产生式左边的非终结符就可能出现多次，因此最终使用了 `multimap`。

```cpp
const multimap<string, string> rules = {
    {"program", "compoundstmt"},
    {"stmt", "ifstmt"},
    {"stmt", "whilestmt"},
    {"stmt", "assgstmt"},
    {"stmt", "compoundstmt"},
    {"compoundstmt", "{ stmts}"},
    {"stmts", "stmt stmts"},
    {"stmts", "E"},
    {"ifstmt", "if ( boolexpr) then stmt else stmt"},
    {"whilestmt", "while ( boolexpr) stmt"},
    {"assgstmt", "ID = arithexpr ;"},
    {"boolexpr", "arithexpr boolop arithexpr"},
    {"boolop", "<"},
    {"boolop", ">"},
    {"boolop", "<="},
    {"boolop", ">="},
    {"boolop", "=="},
    {"arithexpr", "multexpr arithexprprime"},
    {"arithexprprime", "+ multexpr arithexprprime"},
    {"arithexprprime", "- multexpr arithexprprime"},
    {"arithexprprime", "E"},
    {"multexpr", "simpleexpr multexprprime"},
    {"multexprprime", "* simpleexpr multexprprime"},
    {"multexprprime", "/ simpleexpr multexprprime"},
    {"multexprprime", "E"},
    {"simpleexpr", "ID"},
    {"simpleexpr", "NUM"},
    {"simpleexpr", "( arithexpr)"}

    /*{"e","t e'"},
    {"e'","+ t e'"},
    {"e'","E"},
    {"t", "f t'"},
    {"t'","* f t'"},
    {"t'","E"},
    {"f", "( e)"},
    {"f", "id"}*/
};
```

最后被注释掉的部分是一个更简单的 CFG，在后面检验 FIRST 集、FOLLOW 集和分析表时，我们会看到先处理这个简单 CFG 的情况要容易得多。

接下来是存储终结符与非终结符。原本的想法是采用数组，但是仔细想一想，我们存储所有终结符和非终结符是为了做什么？

因为这些符号需要作为 LL 分析表的行和列，这意味着对于任意一个符号，我们将需要确定它在对应集合中的位置，以便在分析表中插入条目。而分析表采用什么数据结构最合适？简便起见，我们采用了二维数组，这样方便我们用 `table[non_terminal_pos][terminal_pos]` 来唯一确定表的条目。也就是说，这个集合需要是有序的，因为分析表是有序的。此外，我们还知道：数组下标必须是数字；终结符和非终结符都是唯一的。

用 `set` 和 `map` 都可以满足有序性（偷懒起见，我当然不想在插入时自己考虑顺序问题，而优先队列并不适合随机访问）和唯一性。然而，二者都会基于终结符和非终结符的字典序排序，要找到一个符号我们必须使用 `find` 方法。这样也许不会有什么效率问题，但不够优雅。

但我们其实可以强行规定一个顺序，从而无视原来的排序，像这样：

```cpp
map<string, int> nt = { // non-terminals, the map below is terminals
    {"program", 0},
    {"stmt", 1},
    {"compoundstmt", 2},
    {"stmts", 3},
    {"ifstmt", 4},
    {"whilestmt", 5},
    {"assgstmt", 6},
    {"boolexpr", 7},
    {"boolop", 8},
    {"arithexpr", 9},
    {"arithexprprime", 10},
    {"multexpr", 11},
    {"multexprprime", 12},
    {"simpleexpr", 13}
    /*{"e", 0},
    {"e'", 1},
    {"t", 2},
    {"t'", 3},
    {"f", 4}*/
};

map<string, int> t = {
    {"{", 0},
    {"}", 1},
    {"(", 2},
    {")", 3},
    {"if", 4},
    {"then", 5},
    {"else", 6},
    {"while", 7},
    {"ID", 8},
    {"=", 9},
    {">", 10},
    {"<", 11},
    {">=", 12},
    {"<=", 13},
    {"==", 14},
    {"+", 15},
    {"-", 16},
    {"*", 17},
    {"/", 18},
    {"NUM", 19},
    {"E", 20},
    {";", 21},
    {"$", 22}
    /*{"+", 0},
    {"*", 1},
    {"(", 2},
    {")", 3},
    {"id", 4},
    {"E", 5},
    {"$", 6}*/
};
```

好吧，这样也算不上优雅。

最后是存储分析表，如上文所述，我采用了二维 `string` 数组的方式，数组内只存储**产生式右边**的字符串，因为产生式左边必定是该行对应的非终结符。

### 计算 FIRST 集和 FOLLOW 集

首先要考虑的问题依然是，用什么数据结构存储这两个集合？

以 FIRST 集为例，我们知道一个符号的 FIRST 集是由多个终结符组成的集合。同一集合中，这些终结符不会重复，而且我们并不关心它们的顺序。各种操作的复杂度为 `O(1)` 的 `unordered_set` 无疑是最佳选择了。随后再利用 `map` 建立符号与其 FIRST 之间的联系。

```cpp
typedef unordered_set<string> str_set;

map<string, str_set> FIRST, FOLLOW;
```

FIRST 集和 FOLLOW 集的具体计算方法这里不再赘述。但值得一提的是，它们的共通之处是都通过循环来更新集合本身，直到集合不再发生变化。而在这里的代码中，我不知道为什么写了个递归版本。

FIRST 集：

```cpp
/* Whether there's a rule lhs -> rhs */
bool exist_rule(const string &lhs, const string &rhs) {
    for (auto iter = rules.lower_bound(lhs); iter != rules.upper_bound(lhs); ++iter) {
        if (iter->second == rhs) {
            return true;
        }
    }
    return false;
}

/* Compute FIRST[expr] recursively */
str_set compute_first(const string &expr) {
    if (!FIRST[expr].empty()) { // Already calculated
        return FIRST[expr];
    }

    if (exist_rule(expr,"E")) {
        FIRST[expr].insert("E");
    }

    string y_n; // X -> y_1 y_2 ... y_n ...
    stringstream ss;
    str_set tmp;
    for (auto iter = rules.lower_bound(expr); iter != rules.upper_bound(expr); ++iter) {
        ss.clear();
        ss.str(iter->second);
        while (ss>> y_n) {
            tmp = compute_first(y_n);
            if (!tmp.count("E")) {
                FIRST[expr].insert(tmp.begin(), tmp.end()); // the same as set_union() in std::set
                break;
            }
        }
    }

    return FIRST[expr];
}
```

`lowerbound` 和 `upperbound` 真的好用。另外要注意的是 `unordered_set` 不能用 `set_union` 方法，只能从头到尾全部 `insert`。主函数中计算代码：

```cpp
// Init FIRST
str_set tmp;
for (const auto &expr: t) {
    tmp.clear();
    tmp.insert(expr.first);
    FIRST.insert(make_pair(expr.first, tmp));
}
for (const auto &expr: nt) {
    compute_first(expr.first);
}
```

FOLLOW 集：

```cpp
/* Starting from start_pos, return the next consecutive substr without ws */
string next_str(string str, string::size_type start_pos) {
    if (start_pos> str.size()) {
        return "E"; // for FIRST["E"] = {"E"}
    }

    string::size_type end_pos = str.find_first_of(" \n\t", start_pos);
    if (end_pos == string::npos) {
        end_pos = str.size();
    }
    return str.substr(start_pos, end_pos - start_pos);
}

/* Compute FOLLOW[expr] recursively */
str_set compute_follow(const string &expr) {
    if (follow_visited.count(expr)) {
        return FOLLOW[expr];
    }
    follow_visited.insert(expr); // mark as visited

    string::size_type pos, end;
    str_set tmp, first_beta;

    for (const auto &sspair: rules) {
        for (pos = 0; (pos = sspair.second.find(expr, pos)) != string::npos; pos = end) { // expr found in rhs
            end = pos + expr.size();
            if ((end == sspair.second.size() || sspair.second[end] == '') &&
                (pos == 0 || sspair.second[pos-1] == '')) { // for u-know-y
                if (end == sspair.second.size()) { // At tail
                    tmp = compute_follow(sspair.first);
                    FOLLOW[expr].insert(tmp.begin(), tmp.end());
                }
                else {
                    // Not at tail, but E is in FIRST[string that follows]
                    first_beta = FIRST[next_str(sspair.second, end+1)];
                    if (first_beta.count("E")) {
                        tmp = compute_follow(sspair.first);
                        FOLLOW[expr].insert(tmp.begin(), tmp.end());
                    }
                    // Everything in FIRST[beta] is in FOLLOW[expr] except E(see outside the loop)
                    FOLLOW[expr].insert(first_beta.begin(), first_beta.end());
                }
            }
        }
    }
    FOLLOW[expr].erase("E");

    return FOLLOW[expr];
}
```

FOLLOW 集的递归边界不能像 FIRST 集一样简单粗暴，所以我设置了：

```cpp
str_set follow_visited; // if FOLLOW[str] has been computed
```

来记录该符号的 FOLLOW 集是否已经被计算过。这是因为存在这样一组略有些棘手的 “右递归” 的文法：

```cpp
stmt ->  ifstmt  |  whilestmt  |  assgstmt  |  compoundstmt
ifstmt ->  if (boolexpr) then stmt else stmt
```

于是，相应的主函数计算代码也要改：

```cpp
prog += "$";
// Init FOLLOW
tmp.clear();
tmp.insert("$");
FOLLOW.insert(make_pair("program", tmp));
for (int i = 0; i < 2; ++i) {
    follow_visited.clear();
    for (const auto &expr: nt) {
        compute_follow(expr.first);
    }
}
```

其中 `prog` 是读入的程序字符串。

我们可以测试一下计算是否正确：

```cpp
/* Test if FIRST and FOLLOW are correct */
void ff_test() {
    for (const auto &expr: nt) {
        cout << expr.first <<"  ::  ";
        for (const string &s: FIRST[expr.first]) {
            cout << s <<", ";
        }
        cout <<"  ::  ";
        for (const string &s: FOLLOW[expr.first]) {
            cout << s <<", ";
        }
        cout << endl;
    }
}
```

### 构造 LL 分析表

处理好下标，直接套算法就完成了。这里就凸显出前面 `nt` 和 `t` 采用 `map<string, int>` 存储的优势，使得由一个符号找到它对应于表中的位置十分方便。

注意：在 `nt` 中我把 `$` 也当作终结符处理，这样在代码中的 `step 3` 就不用拆成两步了，比较方便。但实际上 `$` 既不是终结符也不是非终结符。

```cpp
/* Construct the LL parsing table */
void construct_table() {
    str_set first_alpha, follow_alpha;
    int A; // for all rules A -> alpha

    for (const auto &sspair: rules) {
        first_alpha = FIRST[next_str(sspair.second, 0)];
        follow_alpha = FOLLOW[sspair.first];
        A = nt[sspair.first];
        // step 2(unfortunately index must be number)
        for (const auto &terminal: t) {
            if (first_alpha.count(terminal.first) && terminal.first != "E") {
                table[A][t[terminal.first]] = sspair.second;
            }
        }
        if (first_alpha.count("E")) {
            // step 3
            for (const string& b: follow_alpha) {
                table[A][t[b]] = sspair.second;
            }
        }
    }
}
```

测试一下（针对较简单 CFG 情况写的）：

```cpp
/* Test if the parsing table is correct */
void table_test() {
    cout <<"+  *  ()  id  E  $" << endl;
    for (int i = 0; i < 5; ++i) {
        for (int j = 0; j < 7; ++j) {
            cout <<table[i][j] <<" | ";
        }
        cout << endl;
    }
}
```

### 进行语法分析

本来是想用 `stack` 实现的，但是一看需要的输出，很显然用等价的递归是更方便的。

随后，注意到语法错误需要在一开始输出，而如果递归处理是会边处理边输出的，因此考虑扫描两次，第一次不输出，但当发现语法错误后输出提示信息并不再扫描；第二次才边处理边输出。所以加了 `bool scan` 参数，`scan == true ` 表示处于第一次的 “扫描模式”。

```cpp
/* This func can both scan the prog to find mistakes and do the parsing */
void parse(const string top, int tab_cnt, bool scan) {
    if (!scan) {
        if (top !="program") {
            cout << endl;
            for (int i = 0; i < tab_cnt; ++i) {
                cout <<"\t";
            }
        }
        cout << top;
    }
    else {
        if (flag) return;
    }

    string input_top = next_str(input, 0);
    if (top == input_top) {
        string::size_type start = input.find_first_not_of(" \n\t", input_top.size());
        if (scan && input.substr(0, start).find('\n') != string::npos) {
            // in scan mode, when we're bypassing a \n
            ++line;
        }
        // get rid of input_top
        input = input.substr(start);
        return;
    }
    else if (top =="E") { // in case of unnecessary trouble
        return;
    }
    else if (scan && t.count(top)) {
        // in scan mode, top is a terminal but cannot match input_top, indicating a mistake
        cout <<" 语法错误, 第 "<< line-1 <<" 行, 缺少 \"" << top <<"\"" << endl;
        string::size_type ins = prog.find(input); // find the insertion point
        prog.insert(ins," "+ top +" "); // fix the mistake
        flag = true; // stop scanning
        return;
    }

    string rhs = table[nt[top]][t[input_top]];
    string cur;
    stringstream ss(rhs);
    while (ss>> cur) {
        parse(cur, tab_cnt + 1, scan);
    }
}
```

需要全局变量：

```cpp
string input;
int line = 1;
bool flag; // if the scanning is over
```

主函数中，就只需要：

```cpp
// Scan, then parse
input = prog;
parse("program", 0, true);
input = prog;
parse("program", 0, false);
```

## 坑点

- 如果不从较简单的情况开始，会很容易出错
- 空白符（`\n \t`）的处理，一定要复制输入而不是手打，不然会像我一样被坑两三个小时
- “右递归” 的存在使得 FOLLOW 集计算很容易出错，而看起来像是对的（这里感觉递归的方法不如循环）
- 行数统计
- 定位错误在原来程序字符串中的位置，并修复
