---
title: jQuery 踩坑记
date: 2019-01-23 13:18:21
tags:
  - Javascript
categories:
  - 前端
---

开发项目时踩到的坑。

<!--more-->

## 包含 jQuery 库
可以下载到项目目录里通过相对路径调用，不过我更偏向于通过 cdn 来包含这些开源库：
```html
<script src="https://cdn.bootcss.com/jquery/3.3.1/jquery.min.js"></script>
```

## 新增元素 click 事件
对于通过 js 新增加到 html 中的元素，jQuery 原来的 ` 选择器. click()` 会失效。
解决方法是采用 `.on()` 方法绑定到 body。例如：

```js
$(document).on('click', '.exp', function() {...});
```
就相当于原来的 `$('.exp').click(function() {...});`。

## ajax 发送表单数据
发送**表单**数据（`FormData`）时，需要将 `processData` 和 `contentType` 设置为 `false`，否则无法正确传输。
```js
$.ajax({
	method: 'POST',
	url: url,
	dataType: 'JSON',
	data: fData,
	cache: false,
	processData: false,
	contentType: false,
	...
});
```

## ajax 异步修改变量值
由于 ajax 发送异步请求（相当于并行请求），在 ajax 的 success 方法里想要修改变量的值是比较困难的。如果想要修改变量值，一般都会设置 `async: false` 来强制发送同步请求，但这样也就让 ajax 失去了意义。

退而求其次的办法是，在 ajax 里只修改全局变量，并且**推迟使用**被修改变量的值。

## 通过循环绑定 click 事件
这里会遇到的问题是，所有的 click 事件都被绑定到了**最后绑定的那个函数**上。原因是 js 中的函数都是在**调用时**才被解析的。通过查阅 [资料](https://www.jb51.net/article/85680.htm)，得到的解决方法之一是采用 `.each()` 方法：
```js
$('img').each(function (index) {
	$(this).click(function () {
		//...
	});
}
```
这里的参数 `index` 表示符合选择器规则的元素的索引。例如本例中，在对应 html 中的第 3 个 `<img>` 标签，其 `index` 值就为 2。要引用索引为 `index` 的元素，在这里只需要 `$('img').eq(index)` 即可。