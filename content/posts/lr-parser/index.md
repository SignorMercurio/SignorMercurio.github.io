---
title: LR 语法分析器
date: 2019-05-15
tags:
  - C/C++
  - 编译原理
categories:
  - 编程语言
---

天 坑 预 警

<!--more-->

## 概述

这次需要用 SLR(1) 方法也就是自底向上的方法实现语法分析器，并且需要识别并改正简单的语法错误（这里只出现了漏分号的错误）。举个栗子，输入：

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
语法错误，第 4 行，缺少 ";"
program =>
compoundstmt =>
{stmts} =>
{stmt stmts} =>
{stmt} =>
{whilestmt} =>
{while ( boolexpr) stmt } =>
{while ( boolexpr) compoundstmt } =>
{while ( boolexpr) {stmts} } =>
{while ( boolexpr) {stmt stmts} } =>
{while ( boolexpr) {stmt} } =>
{while ( boolexpr) {assgstmt} } =>
{while ( boolexpr) {ID = arithexpr ;} } =>
{while ( boolexpr) {ID = multexpr arithexprprime ;} } =>
{while ( boolexpr) {ID = multexpr ;} } =>
{while ( boolexpr) {ID = simpleexpr multexprprime ;} } =>
{while ( boolexpr) {ID = simpleexpr ;} } =>
{while ( boolexpr) {ID = NUM ;} } =>
{while ( arithexpr boolop arithexpr) {ID = NUM ;} } =>
{while ( arithexpr boolop multexpr arithexprprime) {ID = NUM ;} } =>
{while ( arithexpr boolop multexpr) {ID = NUM ;} } =>
{while ( arithexpr boolop simpleexpr multexprprime) {ID = NUM ;} } =>
{while ( arithexpr boolop simpleexpr) {ID = NUM ;} } =>
{while ( arithexpr boolop NUM) {ID = NUM ;} } =>
{while ( arithexpr == NUM) {ID = NUM ;} } =>
{while ( multexpr arithexprprime == NUM) {ID = NUM ;} } =>
{while ( multexpr == NUM) {ID = NUM ;} } =>
{while ( simpleexpr multexprprime == NUM) {ID = NUM ;} } =>
{while ( simpleexpr == NUM) {ID = NUM ;} } =>
{while ( ID == NUM) {ID = NUM ;} }
```

CFG、起始符、保留字与上一篇 [LL 语法分析器](https://signormercurio.me/post/LLparser/) 相同。

## 思路与代码

很容易发现，LL 语法分析器中的一些已经确认正确的函数在这里可以使用，例如 `compute_first` 和 `compute_follow` 等。因此这次我们将基于 LL 语法分析的代码进行修改。

### 准备工作

存储上不需要太多变化。对于规则的存储，因为这次在推导 `LR(0)` 项目集时，规则需要是**有序的**（为什么？），因此 `multimap` 可以换成 `vector<pair<string, string> >`。

```cpp
const vector<pair<string, string> > rules = {
    {"program'","program"},
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

    /*{"e'","e"},
    {"e", "e + t"},
    {"e", "t"},
    {"t", "t * f"},
    {"t", "f"},
    {"f", "( e)"},
    {"f", "id"}*/
};
```

与 LL 语法分析类似，由易到难总是能减轻一些工作量，因此最后被注释掉的部分是我们引入的一个更简单的 CFG，用于方便地进行正确性测试。注意这次多了一条规则 `program'-> program`，这是 LR 分析需要的增广文法。

终结符与非终结符的存储不变，除了增加了一个非终结符 `program'`。

FIRST 集和 FOLLOW 集的存储不变。

最后是存储 LR 分析表，分为 `action` 表和 `goto` 表。`goto` 表由于只有需要 `goto` 的状态的数字，用二维 `int` 数组是很自然的想法。而 `action` 表需要存储 `s_n` 和 `r_n` 这两种表项（`n` 为数字），如果用字符串存储那么在查询表项时还需要进行一次字符串处理（找出是 `shift` 还是 `reduce`，以及对应的数字），十分麻烦。

但是由于只有 `shift` 和 `reduce` 两种操作，我们可以全部采用 `int` 存储，然后借助数字的**正负**判断该操作是 `shift` 还是 `reduce`。

### 计算 FIRST 集和 FOLLOW 集

在 SLR(1) 语法分析中只需要 FOLLOW 集，然而要计算 FOLLOW 集是需要一部分特定的 FIRST 集的。因此我们还是两者都要算。

原理没有变，代码其实也没有太大的变化。唯一需要注意的是，由于 LR 分析中可能遇到**左递归文法**（例如用来测试的 CFG），相应 FIRST 集的计算会陷入死循环。解决方法是**懒计算** FIRST 集，即并不对 FIRST 集进行预计算，而是在计算 FOLLOW 集过程中需要对应 FIRST 集时才做计算，这样可以有效避开死循环的问题。

因此，FIRST 集在主函数中只做基本的初始化：

```cpp
// Init FIRST
str_set tmp;
for (const auto &expr: t) {
    tmp.clear();
    tmp.insert(expr.first);
    FIRST.insert(make_pair(expr.first, tmp));
}
```

FOLLOW 集中的变化：

```cpp
//first_beta = FIRST[next_str(sspair.second, end+1)];
first_beta = compute_first(next_str(sspair.second, end+1));
```

测试函数不变。

### 闭包函数

闭包有两种计算方法：循环和递归。在被看似优雅的递归坑过后，我知道为什么推荐的方法是循环了。<del> 可能是被 FIRST 集和 FOLLOW 集的递归算法坑得还不够惨。</del>

我们知道，状态 `I` 的闭包首先包括本身，随后对于 `I` 中任意的规则 `A -> aa.Bbb`，`B` 是非终结符且 `B -> y1 | y2 | ... | yn`，有 `B -> .y1 | .y2 | .... | .yn` 也属于 `I` 的闭包。那么问题来了，`A` 能否等于 `B`？

最初，我以为是不可以的，因为我忽略了 `aa` 的存在，认为这种规则存在左递归，因此应该立即停止递归运算。然而，`aa ` 的存在允许了 `A = B` 的成立，此时继续递归并不会无限循环。

排掉这个雷后，代码没什么难的了：

```cpp
/* Compute the closure of a state recursively */
State closure(State I) {
    State ret = I;

    State tmp;
    string non_terminal;
    for (const Rule &rule: I) {
        // A -> xx.Bxx exists in I, and ". is at head while A = B" is not true in case of right recursive CFG
        if (nt.count(non_terminal = next_str(rule.rhs, rule.point_pos))
        && !(non_terminal == rule.lhs && rule.point_pos == 0)) {
            tmp.clear();
            for (const auto &sspair: rules) {
                if (sspair.first == non_terminal) {// put in B -> y1, B -> y2, ...
                    tmp.emplace_back(sspair.first, sspair.second);
                }
            }
            tmp = closure(tmp);
            ret.insert(ret.end(), tmp.begin(), tmp.end());
        }
    }

    return ret;
}
```

这里就需要用到特地为 LR 分析写的 `Rule` 对象：

```cpp
class Rule {
public:
    string::size_type point_pos; // position of the point
    string lhs, rhs;

    Rule() {}
    Rule(string _lhs, string _rhs, string::size_type _point_pos=0):lhs(_lhs), rhs(_rhs), point_pos(_point_pos) {}

    bool operator == (const Rule &r) const {
        return (lhs == r.lhs && rhs == r.rhs && point_pos == r.point_pos);
    }
};

typedef vector<Rule> State; // I_0, I_1, ...
vector<State> graph; // DFA graph
```

闭包函数的测试比较麻烦，最好多测几个状态，这样才能发现潜在的问题。注意：闭包函数如果存在问题，很有可能导致后面分析表正确的情况下依然得到错误的结果或陷入死循环。

### 构造 DFA 与分析表

这一步需要一边构造 DFA，一边填 `action` 和 `goto` 表。手动画下图，可以发现这里构造 DFA 的算法无非是一个 BFS。

但是和 BFS 不同，这里不需要用队列实现，因为需要存好已经计算出的状态（而不是舍弃），在后面状态的计算中与之比对，防止重复状态带来的冗余。所以数组存下来就好。

从起始符开始逐状态计算，对于已计算的状态（往往只有 1-2 个规则），只有求过一次闭包后才能说这个状态是**完整的**（可能拓展到近 10 条规则）。但有趣的是，只要判断两个状态的第一条规则是否**完全相同**（包括点的位置），就可以判断两个状态是否是重复的（为什么？）。这样就舒服了很多。

剩余的内容就是套路了。在下面的代码中用到了 `goto` 这个饱受诟病的关键字（**不是 `goto` 表！**），然而在跳出多层循环时，必须承认使用 `goto` 绝对是利大于弊的。

```cpp
/* Construct the DFA graph of States */
void build_graph() {
    State I0;
    I0.emplace_back(start_symbol +"'", start_symbol);
    graph.push_back(I0);

    string pointed; // the symbol being pointed at
    State new_state;
    for (int cur = 0; cur != graph.size(); ++cur) { // every State in graph
        graph[cur] = closure(graph[cur]); // now we can say graph[cur] is complete

        for (int i = 0; i < graph[cur].size(); ++i) {// every Rule in graph[cur]
            Rule &rule = graph[cur][i];
            pointed = next_str(rule.rhs, rule.point_pos);
            if (pointed =="E") { // . is at the tail, reduce
                if (rule.lhs == start_symbol +"'") {
                    action[cur][t["$"]] = acc;
                }
                else {
                    for (const string &expr: FOLLOW[rule.lhs]) { // SLR: consider every terminal in FOLLOW
                        action[cur][t[expr]] = -1 * distance(rules.begin(),
                            find(rules.begin(), rules.end(), make_pair(rule.lhs, rule.rhs)));
                    }
                }
                continue;
            }
            int &target = nt.count(pointed) ? go_to[cur][nt[pointed]] :
                action[cur][t[pointed]]; // the target blank we're filling

            if (target == 0) { // the blank is not already filled
                target = graph.size();
                for (int j = 1; j < graph.size(); ++j) {
                    if (graph[j][0] == Rule(rule.lhs, rule.rhs, rule.point_pos + pointed.size() + 1)) {
                        target = j; // replace the target by the real State
                        goto dup;
                    }
                }
                graph.emplace_back(new_state); // create the new empty state
            }
            graph[target].emplace_back(rule.lhs, rule.rhs, rule.point_pos + pointed.size() + 1);
dup:
            ;
        }
    }
}
```

### 进行语法分析

这次的输出，和 LL 语法分析不同，对循环结构更友好。果断用 `stack` 实现。

需要注意的就是行数统计不要重复统计，我这里放在了 `shift` 情况里。至于 `reduce` 中要注意的就是 `E` 这个代表 `ε` 的字符，在考虑规则右边的符号个数时，它是不能被算作一个符号的，这一度让我对着死循环迷惑了很久。

其余的依旧是套路，最后在遇到为 0 的表项时说明发生了语法错误，这里错误处理偷了个懒。

```cpp
void parse() {
    stack<string> s;
    s.push("0");

    int num, len, tmp;
    string input_top;
    string::size_type start;
    out.clear();
    while (!(s.top() == "1" && input == "$")) {
        input_top = next_str(input, 0);

        if ((num = action[stoi(s.top())][t[input_top]]) > 0) { // shift
            start = input.find_first_not_of(" \n\t", input_top.size());
            if (input.substr(0, start).find('\n') != string::npos) {
                // when we're bypassing a \n
                ++line;
            }

            s.push(input_top);
            s.push(to_string(num));

            input = input.substr(start); // get rid of input_top
        }
        else if (num < 0) { // reduce
            num = -num;
            out.push_back(num);
            len = count(rules[num].second.begin(), rules[num].second.end(),' ') + 1; // num of symbols
            if (rules[num].second == "E") { // but!!! E is special
                len = 0;
            }
            for (int i = 0; i < (len<<1); ++i) {
                s.pop();
            }
            tmp = go_to[stoi(s.top())][nt[rules[num].first]];
            s.push(rules[num].first);
            s.push(to_string(tmp));
        }
        else { // mistake
            cout <<" 语法错误，第 "<< line-1 <<" 行，缺少 \";\"" << endl;
            input = ";" + input;
        }
    }
}
```

### 输出

相对简单，但也有坑。首先 `E` 依然要特判，输出时不能输出，而且还要 “倒扣” 一个字符。

然后是这里在替换（也就是归约）子串时，用了 `rfind` 方法定位而不是 `find`，因为是最右推导嘛。

```cpp
void output() {
    string output = start_symbol;
    pair<string, string> rule;
    cout <<output <<" => ";

    for (string::size_type i = out.size()-1; i > 0; --i) {
        rule = rules[out[i]];

        string new_str = (rule.second =="E"?"": rule.second); // deal with E and ws
        output.replace(output.rfind(rule.first), rule.first.size() + (rule.second =="E"), new_str);

        cout <<endl << output <<" => ";
    }
    rule = rules[out[0]];
    cout <<endl << output.replace(output.rfind(rule.first), rule.first.size(), rule.second) <<" ";
}
```

## 坑点

都是能让人迷惑一段时间的坑，这就是 LR 语法分析更难的地方吧：

- 左递归文法 FIRST 集的懒计算处理
- 闭包函数左右非终结符相同的情况处理
- 状态去重
- `E` 不能算作一个符号
- 输出时 `E` 的特判
- 替换最右端的那个子串
