---
title: 温故知新：Javascript 杂记
date: 2021-07-29
tags:
  - Javascript
categories:
  - 前端
---

温故而知新，复习后才发现很多基础掌握得不牢固。

<!--more-->

## 数据类型

1. `typeof` 检查输入参数机器码后三位，`000` 代表 `object` 类型，而 `null` 恰好用全 0 表示。

```js
typeof null; // object
```

2. `typeof` 对于未实现 `[[Call]]` 方法的引用类型返回 `object` ，已实现该方法的则返回 `function`。

```js
typeof Array; // function
```

3. 简单类型和作为 `object` 的复杂类型：

```js
typeof "hello"; // string
typeof new String("hello"); // object
```

4. `instanceof` 判断实例时向上追踪原型链。

```js
[] instanceof Array
[] instanceof Object
```

5. 比 `typeof` 更准确的类型判断：

```js
Object.prototype.toString.call([]); // Array
```

6. 逻辑运算符与非布尔类型混用：

```js
5 || 0; // 5
0 || "a"; // 'a'
5 && 0; // 0
```

7. 拆箱时调用 `toPrimitive()` 方法：
   1. 如果是原始类型值则直接返回；
   2. 否则调用 `.valueOf()`，如果返回值是原始类型值则返回；
   3. 否则调用 `.toString()`，返回得到的 `string`。

```js
[].valueOf() // []
[].toString() // ''
{}.valueOf() // {}
{}.toString() // [object Object]
[] + [] // ''
[] + {} // [object Object]
```

8. 部分浏览器中将 `{}` 视作空代码块：

```js
{
}
+[]; // 0
```

## 深浅拷贝

### 浅拷贝

1. 遍历赋值

```js
for (var i in origin) {
  clone[i] = origin[i];
}
```

2. `Object.create`，实际会拷贝到 `clone` 的 `_proto_` 上：

```js
clone = Object.create(origin);
```

### 深拷贝

1. 借助 JSON：

```js
clone = JSON.parse(JSON.stringify(origin));
```

2. `Object.assign`，与空对象合并：

```js
clone = Object.assign({}, origin);
```

## 编码

1. `escape` 不会对字母、数字以及 `*@-_+./` 进行编码，对其他所有字符均进行编码，目前已废弃。
2. `encodeURI` 将输入参数视作完整的 URI，不会对字母、数字以及 `,/?:@&=+$#` 进行编码，对其他所有字符均进行编码。
3. `encodeURIComponent` 将输入参数视作 URI 的一部分，不会对字母、数字以及 `-_.!~*'()` 进行编码，对其他所有字符均进行编码。

## 函数与作用域

1. 函数与变量的声明会被提前到所在作用域最前面。**变量赋值不会被提前**。
2. 闭包：

```js
function foo() {
  var a = 2;
  function bar() {
    console.log(a);
  }
  return bar;
}

var baz = foo();
baz(); // 2
```

3. 一个经典例子，`timer` 访问到的 `i` 是循环结束后的全局作用域中的 `i`：

```js
for (var i = 1; i <= 5; ++i) {
  setTimeout(function timer() {
    console.log(i);
  }, i * 1000);
} // 6 6 6 6 6
```

解决方案：

- 用 IIFE 创建作用域

```js
for (var i = 1; i <= 5; ++i) {
  (function (j) {
    setTimeout(function timer() {
      console.log(j);
    }, j * 1000);
  })(i);
} // 1 2 3 4 5
```

- 借助 `let` 的特性

```js
for (let i = 1; i <= 5; ++i) {
  setTimeout(function timer() {
    console.log(i);
  }, i * 1000);
} // 1 2 3 4 5
```

4. 类数组转为 `Array`：

```js
arr = Array.prototype.slice.apply(args);
```

实际上，调用 `apply`、`call`、`bind` 等方法均会对 `this` 进行显式绑定。

5. `this` 的默认绑定：内部函数（或者其他类似的找不到 `this` 指向的情况）中的 `this` 指向 `window`（严格模式下指向 `undefined`）：

```js
var a = {
  b: 1,
  getB: function () {
    function c() {
      console.log(this.b); // undefined
    }
    c(); // window.c()
    console.log(this.b); // 1（隐式绑定）
  },
};

a.getB();
```

同理，回调函数也常常会丢失 `this`。

6. `new` 调用的所谓 “构造函数” 实际上是对新创建的对象进行初始化的一种“构造调用”，步骤如下：
   1. 创建新对象；
   2. 执行 `[[Prototype]]` 连接；
   3. 绑定 `this`，即所谓的 `new` 绑定；
   4. 如果调用的函数没有返回对象，则返回该新对象
7. 优先级：`new` 绑定 > 显式绑定 > 隐式绑定 > 默认绑定
8. 箭头函数自动继承外层作用域的 `this`，且无法修改。

## 其他

1. `sort` 默认将元素转为字符串后升序排序。

```js
var arr = [2, 13, 3, 11, 5, 7];
arr.sort(); // [11,13,2,3,5,7]
```
