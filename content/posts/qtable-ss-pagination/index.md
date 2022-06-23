---
title: 术业专攻：QTable 服务端分页实践
date: 2019-12-12 21:16:51
tags:
  - Quasar
  - 实践记录
categories:
  - 前端
featuredImage: 0.png
---

QTable 是 Quasar Framework 的组件之一，功能比较复杂。这篇文章介绍了如何配合服务端分页来使用 QTable 组件。

<!--more-->

参考了 [Quasar 官方文档](https://quasar.dev/vue-components/table)。

## 背景

最近接的一个项目中有一个页面需要加载一个表格，表格的数据是通过异步调用从后端获取的。由于数据量较大，可能需要分页、排序等操作，我选择使用 `QTable` 组件，其核心属性包含：

- `data`：数组，按行存放表格数据，每个对象为一行
- `columns`：数组，每个元素表示一列的属性，例如列名、该列的样式、是否能够排序等等
- `row-key`：某一列的 `name` 属性，用来唯一标识一行
- `pagination.sync`：一个对象，包含了分页器的一些属性

这里因为要处理分页问题，我着重关注的是 `pagination.sync` 属性，官方文档中的例子显示它长这样：

```js
pagination: {
  sortBy: 'name',
  descending: false,
  page: 2,
  rowsPerPage: 3
  // rowsNumber: xx if getting data from a server
}
```

`sortBy` 字段表示排序的关键字，`descending` 表示是否是降序排序，`page` 表示当前所在页，`rowsPerPage` 表示当前选择的每页最大行数。用户操作分页器时，`pagination` 也会相应地改变。

## 问题

在后端，当我请求表格数据时，需要提供两个参数 `pageNum` 和 `pageSize`，含义与 `page` 和 `rowPerPage` 相同。我们考虑以下场景：

当前用户共有 11 条表格数据。假设用户选择每页显示 10 条数据，那么前端将发送请求 `?pageNum=1&pageSize=10` 并拿到第 1 页的 10 条数据。然而此时，`QTable` 会发现只获取了 10 条数据，因此分页器的 `下一页` 按钮处于不可用状态。这样一来，我们无法通过用户操作触发 `?pageNum=2&pageSize=10` 请求，因此无法获取第 11 条数据。

换而言之，`QTable` 的前端分页与后端分页无法兼容，但是后者是必须的，因为数据量非常大，不可能通过一次调用发送。

## 解决方案

幸运的是，在 [这里](https://quasar.dev/vue-components/table#Server-side-pagination%2C-filter-and-sorting) 我发现，Quasar 的开发者早就想到了这个问题，特地为服务端分页作了准备。回顾 `pagination` 的结构，我们还没有解释 `rowsNumber` 的作用：声明该字段代表我们将采用后端分页的方式，而它的含义就是表格数据的总行数（在上例中是 11）。这个值是后端返回给我们的。

同时，我们还需要给 `q-table` 组件添加属性 `@request`。如果由于页数切换 / 排序 / 搜索导致当前页表格数据变化，那么就会触发 `request` 事件，执行对应的函数。看起来非常容易理解，然而这里却有坑点。

在我的项目中设置了：

```js
:pagination.sync="pagination"
@request="getList"
```

那么 `getList` 函数将接收到参数 `props`。此时，我们拥有两个 `pagination`:

- `this.pagination` （用于设置 `pagination.sync` 属性）
- `props.pagination`

起初我采用了如下方式发送请求：

```js
pageNum=${this.pagination.page}&pageSize=${this.pagination.rowsPerPage}
```

结果发现切到下一页时，尽管请求成功但表格并不变化，调试发现 `this.pagination` 并没有变！真正变化的是 `props.pagination`，因此正解是将请求中的 `this` 替换为 `props`。

## 总结

所以，在 `QTable` 中使用服务端分页的正确姿势如下：

1. 设置 `q-table` 组件的 `pagination.sync` 属性，注意必须有 `rowsNumber` 字段
2. 设置 `q-table` 组件的 `@request` 属性，在这里执行异步调用获取数据

而在 `@request` 对应的函数中，需要：

1. 利用 `props.pagination` 发送请求获取数据
2. 用后端返回的值更新 `this.pagination`
3. 还可以加个 loading
