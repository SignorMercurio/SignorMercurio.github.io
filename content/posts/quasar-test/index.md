---
title: 胸有成竹：Quasar Testing 指南
date: 2021-03-21 11:36:12
tags:
  - Quasar
  - 实践记录
categories:
  - 前端
---

对 [Quasar 文档测试部分](https://next.quasar.dev/quasar-cli/testing-and-auditing#introduction) 和 [@quasar/testing 文档](https://testing.quasar.dev/) 部分内容进行了简单翻译，顺便记录了一些目前使用 Quasar 框架进行测试时存在的问题。

<!--more-->

Quasar v1 项目可以通过 `@quasar/testing` 模块添加多种单元测试和 e2e 测试套件。实际上做的事情就是装一些 node 模块、生成一些配置文件、最后在 `package.json` 里加点脚本。理论上还可以结合 CI 使用，不过我还没试。

> 截止目前，`@quasar/testing` 尚未迁移到 Quasar v2。

`@quasar/testing` 实际上是 Quasar 框架的一个 App Extension，所以只能结合 Quasar CLI 使用（一般也不会用别的），并且只能通过 `quasar ext add` 命令来安装。

## 软件测试

测试本身并不难，最困难的是搭测试的环境。测试的关键在于了解到底要测试什么。

> 测试功能（functionality），而不是函数（function）。

测试驱动开发能够让你写出更好的（以及更少的）测试。尽管这样看起来降低了效率，但长远来看能够极大减少项目中的 bug 和维护成本，就像买了必定赔付的保险一样。但并不是所有东西都值得被测试，或者值得在更高层面被测试。比如有些功能用 e2e 测试就好，不用单元测试。

## 安装

可以装测试套件管理工具来管理所有安装的测试套件，也可以单独安装某个特定的测试套件。没有太大的区别，前者可能更方便点。

### 测试套件管理工具

```shell
$ quasar ext add @quasar/testing
```

安装时会让你选择要安装的测试套件，并且会提供 `quasar test` 命令方便跑测试，比如：

```shell
# Execute Jest tests
$ quasar test --unit jest
# Execute Cypress tests
$ quasar test --e2e cypress
# Execute Jest, Cypress and Security tests
$ quasar test --unit jest --e2e cypress --security
```

这些命令的更底层的命令实际上写在了 `quasar.testing.json` 里，并且添加新套件之后这个配置文件也会更新。文件中的默认命令都可以在 CI 中使用。举个例子，如果装了 Jest 套件和 Cypress 套件，那配置文件就是这样的：

```json
// quasar.testing.json

{
  "e2e-cypress": {
    "runnerCommand": "yarn test:e2e:ci"
  },
  "unit-jest": {
    "runnerCommand": "yarn test:unit:ci"
  }
}
```

注意这里调用了 `package.json` 脚本，后者的底层命令就是套件本身的命令，比如 `jest --ci` 等。

另外，开发不同的 mode 时可能需要变更传给 `quasar dev` 的参数，如果想在测试的时候也这样做，可以用 `--dev` 选项，比如：

```shell
# Run jest && dev server in pwa mode
$ quasar test --unit jest --dev="-m pwa"
```

### 单独安装

以安装 Jest 套件为例：

```shell
$ quasar ext add @quasar/testing-unit-jest
```

此时没有 `quasar test` 命令，但还是可以用 `package.json` 脚本和套件本身的命令。

## 移除

要移除一个测试套件（例如 Jest），可以运行：

```shell
$ quasar ext remove @quasar/testing-unit-jest
```

此时会删除相应的 node 模块，然后调用 Quasar 的 App Extension 卸载钩子。

## 重置

不用移除，直接重新装一次：

```shell
$ quasar ext add @quasar/testing-unit-jest
```

注意这样会覆盖掉所有相关文件，包括配置文件，记得备份。同时也会升级对应的 node 模块。如果不想升级 node 模块，可以运行：

```shell
$ quasar ext invoke @quasar/testing-unit-jest
```

## 更新

直接升级 node 模块就可以了：

```shell
$ yarn add -D @quasar/quasar-app-extension-testing-unit-jest
```

这样不会影响现有的测试和配置文件。

### 更新大版本

由于大版本更新可能改变配置文件，建议移除后重装一下：

```shell
$ quasar ext remove @quasar/testing-unit-jest
$ quasar ext add @quasar/testing-unit-jest
```

安装时选 `Overwrite all`，最后 `git diff` 一下看看改了哪些地方以及需要还原哪些地方。

## 问题

`@quasar/testing` 是基于 Jest 26 和 `@vue/test-utils` 的，所以暂时不支持 Vue 3。编写测试时，首先需要用 `mountQuasar` 或者 `mountFactory` 提供一个 Quasar 框架的环境并挂载组件，然后在 `options` 参数中，指定组件需要用到的 Quasar 组件。比如测一个最简单的 404 页面：

```typescript
import { mountFactory } from "@quasar/quasar-app-extension-testing-unit-jest";
import { QBtn } from "quasar";
import Error404 from "pages/Error404.vue";

const factory = mountFactory(Error404, {
  quasar: {
    components: { QBtn },
  },
});

describe("Error404", () => {
  test("shows correct info", () => {
    const wrapper = factory();
    const info = wrapper.get('[dt="info"]');

    expect(info.text()).toContain(" 页面找不到了");
  });
});
```

需要注意的是，在测试使用 QPage 组件时，需要提供原本由上层 QLayout 提供的一些参数。这里可以用 `qLayoutInjections` 来实现：

```typescript
import {
  mountFactory,
  qLayoutInjections,
} from "@quasar/quasar-app-extension-testing-unit-jest";
import Login from "pages/Login.vue";

const factory = mountFactory(Login, {
  mount: {
    provide: qLayoutInjections(),
    // ...
  },
  // ...
});
```

随后，对于一些 Vue 插件比如 VueRouter、Vuex 还有 VueCompositionApi 等等，可以通过 `plugins` 引入。前两者还需要在 `mount` 中指定给当前的 `localVue`（这种方式不需要 `createLocalVue`）。

```typescript
import {
  mountFactory,
  qLayoutInjections,
} from "@quasar/quasar-app-extension-testing-unit-jest";
import VueCompositionApi from "@vue/composition-api";
import VueRouter from "vue-router";
import Vuex from "vuex";
import Router from "src/router";
import Store from "src/store";
import Login from "pages/Login.vue";

const factory = mountFactory(Login, {
  plugins: [VueCompositionApi, VueRouter, Vuex],
  mount: {
    router: Router,
    store: Store,
    provide: qLayoutInjections(),
    // ...
  },
  // ...
});
```

最后则是处理 `@quasar/testing` 的 [一个 bug](https://github.com/quasarframework/quasar-testing/issues/158)，将涉及到 Quasar Portal 的组件 mock 掉，否则会因为无法访问 `Vue` 实例上的 `$q` 而报 warning。

```typescript
import {
  mountFactory,
  qLayoutInjections,
} from "@quasar/quasar-app-extension-testing-unit-jest";
import VueCompositionApi from "@vue/composition-api";
import VueRouter from "vue-router";
import Vuex from "vuex";
import Router from "src/router";
import Store from "src/store";
import {
  // ...,
  Notify,
} from "quasar";
import Login from "pages/Login.vue";

Notify.create = jest.fn();

const factory = mountFactory(Login, {
  plugins: [VueCompositionApi, VueRouter, Vuex],
  mount: {
    router: Router,
    store: Store,
    provide: qLayoutInjections(),
    mocks: { Notify },
  },
  quasar: {
    components: {
      // ...
    },
  },
});

describe("Login", () => {
  // ...
});
```
