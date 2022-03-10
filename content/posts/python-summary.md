---
title: 《Python 编程技术》期末作业
date: 2019-01-06 16:08:24
tags:
  - 项目
  - Python
categories:
  - 编程语言
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/PythonSummary/0.png
---

期末作业居然是写综述。。有点无聊啊。**这不是 Python 教程。**

<!--more-->

## 入门

本学期学习了 Python 语言。由于之前已经学习过 C, C++, Java（以及 VB, Pascal, 前端三件套）等较难的编程语言，Python 语言的学习没有太多挑战性。容易注意到，Python 语言最大的特点是**现成的可方便调用的库很丰富**，语言本身对于一些底层操作的封装也做得很好，因此常常可以看到效果相同的程序，用 Python 编写比用 C/C++（不用提 Java）要短很多。

然而，代价是**性能的大幅降低**。好在常用 Python 实现的程序体量都不会太大，因此速度的问题并不突出。此外，Python 语言作为解释型语言，一旦发布程序即**开源**。不过如今，这恐怕并不是什么缺点了。

首先我们学习了 Python3 的安装与配置。过程非常简单：从官网下载安装包，配好环境变量后在命令行验证即可。编写和运行 Python 程序也极其简单：课上的第一个例子便是输出 Hello World 语句。为此，老师提供了两种方法，一是 Python 交互模式下直接输入 `print(‘Hello World’)` 并回车；二是在一个形如 `1.py` 文件中输入上述语句，并在命令行中输入 `python 1.py` 来执行。

![图 1]({{< param cdnPrefix >}}/PythonSummary/0.png)
![图 2]({{< param cdnPrefix >}}/PythonSummary/1.png)

一般来说，后一种方法使用较多。因此，我们需要称手的代码编辑器。老师推荐我们使用 Sublime Text 和 VS Code。实际操作中，我发现对于体积稍大一点的程序（例如上百行），使用 IDE 是更为明智的选择。因此，对于短小的代码我是用 VS Code 来编辑，而较长的代码我选择了用 PyCharm 编辑。

在刚开始学习编程时，我曾使用记事本编辑代码——众所周知，记事本保存的文件会**莫名其妙地在开头加上特殊字符**，这曾使得作为初学者的我十分困惑。因此，使用记事本（甚至 Word）写代码绝对是错误的选择。

接下来我们进入了正式的 Python 语法的学习。

## 基础特性与语法规则

首先是带我们入门的老朋友 `print()` 函数。

```python
print('11', '22') # 11 22
print(1 + 2) # 3
print('11', end = '')
print('22', end = '') # 1122
```

1. 可以接收用逗号隔开的字符串，这些字符串输出时中间会加上 **1 个空格**；
2. 可以接收数学表达式；
3. 可以用参数 `end` 指定其结尾字符，默认为换行符；

与输出对应的是输入函数 `input()`。

```python
name = input('Enter your name:')
print('Hello,', name)
# Enter your name:
# > Mercury
# Hello, Mercury
```

1. 整行读取，返回读取到的字符串；
2. 可以拥有一个字符串作为参数，表示提示信息。

这两个函数十分简单。随后老师介绍了一些**语法**，与 C/C++ 重复的语法规则将不再赘述：

```python
PI =  3.14
 print(r'\n\n\n') # (indent error)
print(r'\n\n\n') # \n\n\n
print('''
line1
line2
line3
''')
```

1. 注释以 `#` 开头；
2. 强制要求代码块缩进；
3. 数据类型有整数、浮点数、字符串、布尔、空等等；
4. 字符串：既可以用单引号又可以用双引号括起来；
5. 字符串：引号前加 `r` 表示 raw，既取消转义；
6. 字符串：`'''…'''` 可以表示多行字符串；
7. **字符串是不可变类型**；
8. 布尔：只有 `True/False` 两个值，逻辑运算 `and,or,not`；
9. 空值：`None`，并不是 `0`；
10. 变量使用前不需要声明，变量类型不固定（动态语言）；
11. 没有机制保证常量不被修改；
12. `/` 是浮点除法、`// ` 是整除；
13. `** ` 表示乘方；
14. 整数、浮点数没有范围限制，浮点数超出一定范围会显示 `inf`。

然后是一些**常用函数**：

```python
ord('A') # 65
chr(66) # B
s = 'H e l l o'
len(s) # 5
s.encode('utf-8')
lst = s.split('') # ['H', 'e', 'l', 'l', 'o']
','.join(lst) # 'H,e,l,l,o'
print('{name} does {thing}'.format(name='s.b.', thing='s.th.'))
# s.b does s.th.
print('%s does it %d times' % ('s.b.', 6))
# s.b. does it 6 times
```

1. `ord()` 字符变整数编码，`chr()` 整数编码变字符；
2. bytes 类型在引号前加 b，str 转 bytes 用 `encode()` 方法，如 `s.encode('utf-8')`，`decode()` 反之。
3. `len()` 接收一个序列（列表、元组、字符串等）参数，返回其长度；
4. 格式化字符串：字符串内和 C 语言一样，后接 `% (值 0, 值 1, 值 2…)`；或用 `'{0}：{1:.2f}'.format('abc', 0.254)`，输出为 `abc：0.25`。大括号中的数字并不是必须的；
5. ` 字符串. split(' ')` 用空格分割字符串形成列表；`','.join(列表)` 用逗号连接列表形成字符串；

关于**控制流**：

```python
for i in range(5):
	print(i)
else:
	print('Done')
# 0
# 1
# 2
# 3
# 4
# Done
while True:
	print('Reached')
	break
else:
	print('Not reached')
print('Done')
# Reached
# Done
```

1. 条件两边都不用括号，但右边要冒号，下面的语句块需要缩进；
2. `if->elif->else`；
3. `while->else`（`else` 有必要吗？）；
4. `for->else`；
5. `for i in range(a, b)`，左闭右开，`range` 第三个参数表示步长；
6. `break` 会跳过循环的 `else`；

**函数与模块**：

```python
def func(a, b=5, c=10):
	print('a is', a, 'and b is', b, 'and c is', c)

func(3, 7) # a is 3 and b is 7 and c is 10
func(25, c=24) # a is 25 and b is 5 and c is 24
func(c=50, a=100) # a is 100 and b is 5 and c is 50

def add_end(L=[]):
	L.append('END')
	return L

add_end([1, 2, 3]) # [1, 2, 3,'END']
add_end() # ['END']
add_end() # ['END','END']

def calc(*numbers):
	sum = 0
	for n in numbers:
		sum = sum + n * n
	return sum

calc(1, 2, 3) # 14
calc() # 0

from math import sqrt
sqrt(9) # 3
```

1. `def` 定义函数；
2. `global` 声明全局变量；
3. **默认参数必须指向不可变对象**；
4. 关键字参数：调用函数时，参数列表中用参数名 = 值的方式指定部分参数的值；
5. 可变参数：`*arg` 表示元组，`**arg` 表示字典，可直接传参；
6. 可以返回多个返回值，**实际上是返回元组**；
7. 代码重用：`import 库；from 库 import …`；
8. `dir()` 返回当前模块的名称列表，或给定参数模块的名称列表；
9. 独立运行模块时，`__name__==’__main__’`；

**数据结构**：

```python
lst = ['a', 'b', 'c']
len(lst) # 3
lst.append('d') # ['a', 'b', 'c', 'd']
lst.insert(1,'e') # ['a','e','b','c','d']
lst.sort() # ['a','b','c','d','e']
lst.pop(1) # ['a', 'b', 'c', 'd']
lst[0] = 11 # [11,'b','c','d']

tup = (2) # 2
tup = (2,) # (2,)

d = {'a': 97, 'b': 98, 'c': 99}
d['b'] == 98 # True
d['c'] = 100 # {'a': 97, 'b': 98, 'c': 100}
'cc' in d # False
d.get('bb', -1) # -1
d.pop('c') # {'a': 97, 'b': 98}

s = set([1, 1, 2, 2, 3, 3])
s.add(4) # {1, 2, 3, 4}
s1 = set([1, 2, 3])
s1.remove(1) # {2, 3}
s & s1 # {2, 3}

'abcdefg'[::2] # 'aceg'
'abcdefg'[1:-1] # 'bcdef'
```

1. 列表：`[]` 括起来，可变，可以索引，可以用 `len()` 取长度;
2. 列表：`append() ` 追加元素（来自参数）；
3. 列表：`insert(i, s)` 在索引 `i` 处插入元素 `s`；
4. 列表：`pop() ` 删除末尾元素，或接收参数 `i` 删除索引为 `i` 的元素；
5. 列表：元素类型可以互不相同；
6. 元组：`( )` 括起来，不可变，可以索引；
7. 元组：只有一个元素 `1` 的元组：`(1,)` 而不是 `(1)`；
8. 字典：`{}` 括起来，`{key0: value0, key1: value1}` 形式，**键值必须是不可变对象**；
9. 字典：` 字典变量 [键]` 来得到对应的值，或用 ` 字典变量. get(键)` 得到，`get()` 的第二个参数是没找到时的返回值，默认为 `None`；
10. 字典：删除键值对：` 字典变量. pop(键)`；
11. 集合：用一个列表初始化，无重复元素，`add()` 添加元素，`remove()` 删除元素；
12. 集合：元素必须是不可变对象；
13. 序列：如列表、元组、字符串，主要功能是 `in` 判断和切片；
14. 切片：`[-2]` 倒数第 2 个；`[2:]` 第 2 个到最后；有冒号时左闭右开；第 2 个冒号后是步长。

随后的课程内容包括了一部分 Python 高级特性，包括迭代器、生成器、异常处理、面向对象编程、匿名函数等等。

## 高级特性与 OOP

首先，我们需要理解**迭代**的概念：所谓迭代，即用循环来遍历**可迭代对象**。判断对象是否可迭代：

```python
from collections import Iterable
isinstance('123', Iterable) # True
isinstance(123, Iterable) # False
```

迭代的一般形式是 `for 变量 in 可迭代对象:`，例如：

```python
d = {'a': 97, 'b': 98, 'c': 99}
for key, val in d.items():
	print(key +'='+ val)
# b = 98
# a = 97
# c = 99 (unordered)

# Or instead:
[key +'='+ val for key, val in d.items()]
# ['b=98', 'a=97', 'c=99']
```

上面的第二种方法用到了**列表生成式**，它还可以这样用，来把列表中的字符串全部变成小写：

```python
L = ['RESTful', 'LaTeX', 'GitHub', 'iPhone']
[s.lower() for s in L]
# ['restful', 'latex', 'github', 'iphone']
```

可以想到，在生成方法已知的情况下，直接求出整个列表常常是没有必要的。为了边循环边计算，Python 提供了生成器对象：

```python
g = (s.lower() for s in L)
next(g) # 'restful'
next(g) # 'latex'

# Generate Fibonacci sequence(less than 2000)
def fib():
    prev, curr = 0, 1
    while True:
        yield curr
        prev, curr = curr, curr + prev

f = fib()

for i in f:
    if i > 2000:
        break
    print(i)
```

生成器对象可以用 `next()` 来生成下一个元素，但由于它是**可迭代**的，我们通常习惯用循环来遍历其元素。此外，在上面的例子中，`fib()` **并不是一个函数**，而是一个生成器，因为其定义中带有 `yield` 关键字。

那么，为什么 `next()` 可以返回生成器生成的下一个元素呢？通过查阅文档发现，`next()` 的参数需要是一个**迭代器**对象。因此我们知道，生成器是一种迭代器。

然而，`isinstance([], Iterator)` 语句的结果却是 `False`，意味着列表（字典、字符串）并不是迭代器对象，尽管可以用 `iter()` 进行强制转换。这揭示了迭代器对象作为流对象的最大优点，即**惰性计算**。

同时，迭代器迭代完毕后，我们注意到 Python 解释器会抛出 `StopIteration` 的错误。这是一个典型的**异常**，而接下来我们要做的就是处理这一异常。异常处理语法有点类似 Java，这里我们用一个常规的文件处理（这里没有介绍，因为比较简单，而且和 C++ 太相似了）的例子来说明：

```python
import sys
import time

f = None
try:
    f = open("poem.txt")
    while True:
        line = f.readline()
        if len(line) == 0:
            break
        print(line, end='')
        sys.stdout.flush()
        print("Press ctrl+c now")
        time.sleep(2)
except IOError:
    print("Could not find file poem.txt")
except KeyboardInterrupt:
    print("!! You cancelled the reading from the file.")
finally:
    if f:
        f.close()
    print("(Cleaning up: Closed the file)")

# Or use instead:
with open("poem.txt") as f:
    for line in f:
        print(line, end='')
```

这里将可能产生异常的代码块放在了 `try:` 后面，并在 `except:` 后捕获并处理异常，`finally:` 进行善后工作。另一种方案是用 `with...as...` 语句来简化资源的获取与释放。

我们也可以自己定义一种异常，并在 `try:` 语句块中用 `raise 异常名 ` 抛出异常。这里就需要我们定义一种异常类，并产生一个异常对象。于是我们接下来学习了**面向对象编程**。

对于面向对象程序设计，经过 C++ 与 Java 两门语言的学习，我再熟悉不过了，因此许多 OOP 中重要的概念，如封装、继承、多态等这里不会再赘述。

1. 在任何类的对象方法的参数列表开头都会有一个 `self` 参数，引用对象本身，作用相当于 `this` 指针；
2. 类的构造函数名称为 `__init__`；
3. 私有变量以 `__` 开头（**但是不能以 `__` 结尾！**），从外部访问这一变量只会新增一个同名变量；本质：Name-mangling
4. 继承：`class 派生类 (基类):`；**继承元组**中也可以有多个基类，即多重继承；
5. 所有方法都是**虚拟的**（C++ `virtual` 关键字）；
6. `type(对象)` 返回对象类型；`isinstance()` 对于继承的类更方便；`dir()` 获取一个对象的所有属性和方法；
7. 可以定义**类属性**和**类方法**，后者需要装饰器（不在课程范围内）`@classmethod`

最后以一个简单的例子结束 OOP 部分：

```python
class Fib:
    def __init__(self):
        self.prev = 0
        self.curr = 1

    def __iter__(self):
        return self

    def __next__(self):
        val = self.curr
        self.curr += self.prev
        self.prev = val

        if self.prev > 2000:
            raise StopIteration
        return val


f = Fib()
for i in f:
    print(i, end=' ')
```

最后一点额外的内容是**匿名函数**，简单来说就是 `lambda 参数: 表达式 ` 的形式，其中 “参数” 可选，“表达式”即返回值。另外，lambda 表达式本身也可以作为函数的返回值。

## 图形化编程

在课程最后我们学习了基于 tkinter 的图形化编程, 为此我们需要 import tkinter 模块。从一个简单的例子开始：

```python
from tkinter import *

def showPosEvent(event):
    print('Widget=%s X=%s Y=%s' % (event.widget, event.x, event.y))

def onLeftClick(event):
    print('Got left mouse button click:', end='')
    showPosEvent(event)

tkroot = Tk()
labelfont = ('courier', 20, 'bold')
widget = Label(tkroot, text='Hello bind world')
widget.config(bg='red', font=labelfont)
widget.config(height=5, width=20)
widget.pack(expand=YES, fill=BOTH)

widget.bind('<Button-1>',  onLeftClick)
widget.focus()
tkroot.title('Click Me')
tkroot.mainloop()
```

我们用 `Tk` 创建主窗体，`Label` 创建一个标签，通过其 `config` 方法设置各种属性后，用 `pack` 方法装入主窗体中。

为了让控件能响应事件，使用 bind 方法，第一个参数表示事件类型，可以有 `<Button-1>(鼠标左键), <Button-2>(鼠标中键), <Button-3>(鼠标右键), <Double-1>(左键双击), <B1-Motion>(左键拖动), <Key-Press>, <Up>, <Return>` 等等; 第二个参数是检测到事件发生时的行为，用一个函数名表示（类似 Java 的 EventListener）。该函数的参数是一个 `event` 对象，其属性 `widget` 表示事件作用的控件，`x` 和 `y` 表示坐标（如果有的话）。

最后，这里用 `focus` 方法设置焦点，`mainloop` 使窗体开始循环等待，也就是真正运行起来。运行效果：
![图 3]({{< param cdnPrefix >}}/PythonSummary/2.jpg)

这里用的控件是 Label，对于其它控件同理，如 Button, Frame, Entry, Checkbutton, Radiobutton, Scale 等等。

除此之外，tkinter 也提供了一些封装好的对话框供我们调用。例如：

```python
from tkinter.filedialog   import askopenfilename
from tkinter.colorchooser import askcolor
from tkinter.messagebox   import askquestion, showerror
from tkinter.simpledialog import askfloat
from tkinter import *

demos = {
    'Open':  askopenfilename,
    'Color': askcolor,
    'Query': lambda: askquestion('Warning', 'You typed"rm *"\nConfirm?'),
    'Error': lambda: showerror('Error!', "He's dead, Jim"),
    'Input': lambda: askfloat('Entry', 'Enter credit card number')
}

class Demo(Frame):
    def __init__(self, parent=None, **options):
        Frame.__init__(self, parent, **options)
        self.pack()
        Label(self, text="Basic demos").pack()
        for (key, value) in demos.items():
            Button(self, text=key, command=value).pack(side=TOP, fill=BOTH)

if __name__ == '__main__': Demo().mainloop()
```

点击 Open 按钮，会出现文件选择的对话框；Color 则对应颜色选择对话框；Query 对应消息提示框 (带问号 + 是 / 否选项)；Error 出现错误提示框；Input 则弹出带文本框的对话框，允许用户进行输入。

从这个例子我们也可以发现，tkinter 和面向对象的结合同样十分便捷。运用这种面向对象的思想，我们实现一个按钮类，用于在退出时弹出确认对话框：

```python
from tkinter import *
from tkinter.messagebox import askokcancel

class Quitter(Frame):
    def __init__(self, parent=None):
        Frame.__init__(self, parent)
        self.pack()
        widget = Button(self, text='Quit', command=self.quit)
        widget.pack(side=LEFT, expand=YES, fill=BOTH)

    def quit(self):
        ans = askokcancel('Verify exit', "Really quit?")
        if ans:
            quit()

if __name__ == '__main__':  Quitter().mainloop()
```

此外，除了用上面提到的 `pack` 方法可以管理控件布局外，我们还可以使用 grid 布局管理器。它将控件放置到一个二维的表格里，主控件被分割成一系列的行和列，表格中的每个单元（cell）都可以放置一个控件。例如：

```python
from tkinter import *

master = Tk()

Label(master, text="First").grid(row=0,column=0, sticky=W)
Label(master, text="Second").grid(row=1,column=0, sticky=W)

e1 = Entry(master)
e2 = Entry(master)

e1.grid(row=0, column=1,sticky=(E, S))
e2.grid(row=1, column=1,sticky=(E, S))

master.mainloop()
```

效果：

![图 4]({{< param cdnPrefix >}}/PythonSummary/3.jpg)

需要注意的是，pack 布局管理器与 grid 布局管理器不应在一个窗口中混合使用。

如果我们想在窗体中显示图片也同样可行。这需要用到 `Canvas` 对象：

```python
picdir = "pic.gif"
from tkinter import *
win = Tk()
img = PhotoImage(file=picdir)
can = Canvas(win)
can.pack(fill=BOTH)
can.create_image(20, 20, image=img, anchor=NW)
win.mainloop()
```

这是最简单的在窗体中显示一张图片的方法，同样我们可以给 Button 的 img 属性赋值来在按钮上显示图片。

所谓 `Canvas` 对象，即画布对象，其功能远不止于绘制一张已有的图片。它不仅拥有其它控件类似的属性与方法，还有自带的许多绘图方法，如 `create_line, create_oval, create_rectangle, create_arc, create_image, create_text,` `create_window ` 等。根据其参数列表传入适当的参数，可以完成大部分基本的绘图功能。结合前面提到的鼠标拖动事件与面向对象编程，完全可以让用户自己在窗体内创作图像。

tkinter 同样支持 listbox 控件，下拉菜单与窗体菜单，带滚动条的文本框等等, 他们的方法多样，但也有许多相似之处。下面是两个简单的示例：

![图 5]({{< param cdnPrefix >}}/PythonSummary/4.png)

![图 6]({{< param cdnPrefix >}}/PythonSummary/5.png)

第一个是菜单栏的测试，第二个是一个简单的文本编辑器。

到这里，这门课程的内容差不多结束了。然而 Python 的功能远远不止这些，课程的结束也并不意味着 Python 学习的结束。在学习完课程之后，我又尝试写了基于 Python 的爬虫——根据豆瓣电影排行来自动推荐电影，并通过微信自动回复的接口实现交互。

项目地址：https://github.com/SignorMercurio/WechatFilmRecommender

## 参考资料

- [Python 教程 - 廖雪峰的官方网站](https://www.liaoxuefeng.com/wiki/0014316089557264a6b348958f449949df42a6d3a2e542c000)
- [简明 Python 教程](https://bop.mol.uno/)
- 教学课件
