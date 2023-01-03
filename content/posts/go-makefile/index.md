---
title: 步步为营：在 Go 项目中编写 Makefile
date: 2022-06-22T15:09:26+08:00
tags:
  - Go
  - Makefile
categories:
  - 编程语言
featuredImage: 0.png
---

用古老的工具构建现代化的应用。

<!--more-->

Makefile 功能强大但语法复杂，而且通常会和语法同样令人困惑的 Shell 脚本混用，在编写 Makefile 进行项目管理时很容易写出一团乱麻。因此记录了一些目前收集到的编写可维护、可拓展 Makefile 的技巧和实践。

## 基础规则

```makefile
targets: prerequisites ｜ order-only-prerequisites
	commands
```

这表示构建 targets 需要先满足 prerequisites，因此如果 prerequisites 如果未满足/未被构建，则会先尝试构建 prerequisites，满足后才会执行 commands来构建 targets。order-only-prerequisites 则只有在第一次构建 targets 时才会被构建。

在 Go 项目中，我们通常不直接通过 Makefile 的 targets 构建目标文件，而是利用上述语法容易建立依赖关系的特性进行项目管理。因此通常会使用 `.PHONY` 来表示需要构建一个伪目标而非实际的目标文件：

```makefile
.PHONY: targets
targets: prerequisites
	commands
```

例如，我们希望运行 `make clean` 清除所有生成的文件：

```makefile
.PHONY: clean
clean:
	@echo "Cleaning all build output"
	@-rm -vrf $(OUTPUT_DIR)
```

这里用 `@` 开头避免输出命令本身，`-rm` 防止在没有目标目录的情况下报错中止。`$(OUTPUT_DIR)` 引用 Makefile 中定义的变量，通常通过 `OUTPUT_DIR=/path/to/_output` 的形式定义。同时也存在一些预定义的变量，例如 `$(MAKE)` 就指向 `make` 的二进制文件。

变量定义根据这里等号的不同，赋值方式也有所不同：

- `=` 直接赋值，但引用变量的值会在使用时才计算
- `:=` 直接赋值，引用变量的值在赋值时计算，比较类似常规编程语言的用法
- `?=` 如果变量没有值才会赋值，在用户自定义配置时很常用
- `+=` 在后面追加赋值，同样类似常规编程语言的 `+=`

需要注意，Makefile 中定义的变量只在当前 Makefile 有效，若要暴露给其他 Makefile 则需要 `export` 出来。

## 常见管理内容

在 Go 项目中，我们一般用 Makefile 来帮助自动化如下流程：

- 静态代码检查（lint）、格式化代码（format）
- 单元测试（test）、计算覆盖率（cover）
- 编译（build）、多平台编译（build.multiarch）
- 镜像构建（image）、镜像发布（push）
- 清理生成的文件（clean）
- 安装依赖的工具（tools）
- 代码/文档生成（gen）
- 部署（deploy）
- 发布（release）
- 打 Linux 平台包（package）
- 添加 license（add-license）、检查 license（verify-license）
- 关于本 Makefile 如何使用的帮助（help）

## 常用函数

作为 Makefile 语法的一部分，函数能实现许多巧妙的操作，我们会在后文看到这一点。

| 函数名                                | 功能描述                                                     |
| :------------------------------------ | :----------------------------------------------------------- |
| `$(origin <variable>)`                | 返回变量状态： undefined-未定义; default-默认的定义; environment-环境变量; file-被定义在 Makefile 中; command line-被命令行定义; override-被 override 定义; automatic-自动化变量 |
| `$(addsuffix <suffix>,<names...>)`    | 把 `<suffix>` 加到 `<names>` 中的每个单词后面，并返回加过后缀的文件名序列 |
| `$(addprefix <prefix>,<names...>)`    | 把 `<prefix>` 加到 `<names>` 中的每个单词前面，并返回加过前缀的文件名序列 |
| `$(wildcard <pattern>)`               | 扩展通配符，例如 `$(wildcard *.go)` 能匹配所有 go 文件       |
| `$(word <n>,<text>)`                  | 返回 `<text>` 的第 `<n>` 个单词。如 `<n>` 比 `<text>` 中的单词数要大，返回空字符串 |
| `$(subst <from>,<to>,<text>)`         | 把 `<text>` 中的 `<from>` 替换成 `<to>` 并返回               |
| `$(eval <text>)`                      | 将 `<text>` 的内容将作为 Makefile 的一部分而被 make 解析和执行 |
| `$(firstword <text>)`                 | 返回 `<text>` 的第一个单词                                   |
| `$(lastword <text>)`                  | 返回 `<text>` 的最后一个单词                                 |
| `$(abspath <text>)`                   | 将 `<text>` 中的路径转换成绝对路径并返回                     |
| `$(shell cat foo)`                    | 执行操作系统命令，并返回操作结果                             |
| `$(info <text ...>)`                  | 输出一段信息                                                 |
| `$(warning <text ...>)`               | 输出一段警告信息，但继续执行                                 |
| `$(error <text ...>)`                 | 输出一段错误信息，并停止执行                                 |
| `$(filter <pattern...>,<text>)`       | 以 `<pattern>` 过滤 `<text>` 中的单词，返回符合 `<pattern>` 的单词 |
| `$(filter-out <pattern...>,<text>)`   | 以 `<pattern>` 过滤 `<text>` 中的单词，返回不符合 `<pattern>` 的单词 |
| `$(dir <names...>)`                   | 从 `<names>` 中取出目录部分。目录部分是指最后一个 `/` 之前的部分。 |
| `$(notdir <names...>)`                | 从 `<names>` 中取出非目录部分。                              |
| `$(strip <text>)`                     | 去掉 `<text>` 中开头和结尾的空字符                           |
| `$(suffix <names...>)`                | 返回 `<names>` 中各个文件名的后缀。如果文件名没有后缀，则返回空字串 |
| `$(foreach <variable>,<list>,<text>)` | 把 `<list>` 中的单词逐一取出放到 `<variable>` 所指定的变量中，然后执行 `<text>`。每次 `<text>` 会返回一个字符串，返回循环结束后返回的字符串序列（以空格分隔）。 |

## 生成帮助信息

我们首先的是根据 Makefile 代码自动生成帮助信息，这一点可以参考 swagger，通过添加特殊注释的方式实现。以 `clean` 为例，我们可以在每一个伪目标前添加说明：

```makefile
## clean: Remove all files that are created by building.
.PHONY: clean
clean:
	@echo "Cleaning all build output"
	@-rm -vrf $(OUTPUT_DIR)
```

然后利用 sed 提取注释，并用 awk 或 column 来分列、着色显示：

```makefile
## help: Show this help info.
.PHONY: help
help: Makefile
	@echo -e "\nUsage: make <TARGETS> <OPTIONS> ...\n\nTargets:"
	@sed -n 's/^##//p' $< | awk -F':' '{printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' | sed -e 's/^/ /'
	@echo "$$USAGE_OPTIONS"
```

这里的 `USAGE_OPTIONS` 需要通过 `define` 定义（本质上是多行变量）并 `export` 到全局，随后就能全局通过 `$$USAGE_OPTIONS` 引用，其中可以添加一些支持用户自定义的配置说明。可以参考这个 `USAGE_OPTIONS`：

```makefile
define USAGE_OPTIONS

Options:
  DEBUG            Whether or not to generate debug symbols. Default is 0.
  CGO_ENABLED      Whether or not to use CGO. Default is 0.
  BINS             Binaries to build. Default is all binaries under cmd.
                   This option is available when using: make build/compress(.multiarch)
                   Example: make build BINS="server client"
  PACKAGES         Packages to build. Default is rpm and deb.
                   This option is available when using: make package/package.multiarch
                   Example: make package PACKAGES="rpm deb"
  PLATFORMS        Platforms to build for. Default is linux_amd64 and linux_arm64.
                   This option is available when using: make *.multiarch
                   Example: make build.multiarch PLATFORMS="linux_amd64 linux_arm64"
  V                Set to 1 enable verbose build. Default is 0.
endef
export USAGE_OPTIONS
```

随后，我们就可以根据用户定义的配置来更改 make 的行为：

```makefile
# verbose settings
ifndef V
MAKEFLAGS += --no-print-directory
endif
```

## 目录结构

实际项目中，为了便于维护，我们可以拆分 Makefile 为若干个更小的 `.mk` 文件，并根据项目目录结构将这些文件放入合适的目录。一个可以参考的结构如下：

```
Makefile
scripts
├── make-rules
│   ├── common.mk
│   ├── golang.mk
│   ├── ...
```

随后只需要在 Makefile 中 `include` 相应文件即可：

```makefile
include scripts/make-rules/common.mk
include scripts/make-rules/golang.mk
include ...
```

对应目录结构，我们可以用类似的方式命名伪目标。例如 `scripts/make-rules/golang.mk` 一律以 `go.` 开头来命名，如 `go.build`、`go.lint`、`go.test` 等；如果需要进一步细分伪目标，只需要加一个层级，如 `go.build.linux_amd64`、`go.build.linux_arm64` 等。

## 设计依赖关系

### 🌰 灵活编译

假设我们在项目中既需要编译多个平台的多个二进制文件用于发布、又需要编译单一平台的多个二进制文件用于测试，考虑到可扩展性，我们期望能设计出这样的命令，例如 `make build` 和 `make build.multiarch`，能灵活地编译出我们想要的二进制文件。

因此，我们自底向上设计命令间的依赖关系，在 `scripts/make-rules/golang.mk` 中编写编译指令。最底层的命令应形如 `go.build.[PLATFORM].[COMMAND]` 形式，例如 `go.build.linux_amd64.server`。为了避免冗余，可以结合使用通配符和自动变量：

```makefile
.PHONY: go.build.%
go.build.%:
	$(eval COMMAND := $(word 2,$(subst ., ,$*)))
	$(eval PLATFORM := $(word 1,$(subst ., ,$*)))
	$(eval OS := $(word 1,$(subst _, ,$(PLATFORM))))
	$(eval ARCH := $(word 2,$(subst _, ,$(PLATFORM))))

	@echo "Building binary $(COMMAND) for $(PLATFORM)"
	@mkdir -p $(BIN_DIR)/$(PLATFORM)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(OS) GOARCH=$(ARCH) $(GO) build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(PLATFORM)/$(COMMAND) $(ROOT_PACKAGE)/cmd/$(COMMAND)
```

注意在 targets 内部会执行 shell 命令，不能直接执行 Makefile 变量赋值，因此可以利用 `eval` 函数。此外还使用了 `word` 和 `subst` 函数来提取 PLATFORM 和 COMMAND 信息，自动变量 `$*` 指的就是 `%` 所匹配到的字符串。这样一来，我们就可以用 `go.build.[PLATFORM].[COMMAND]` 形式来编译任意平台的任意二进制文件了。

不妨假设这里的二进制文件包括 `cmd/server` 和 `cmd/client`，如何指定要编译的二进制文件呢？我们通过读取 `cmd` 目录下的目录名称来获得所有二进制文件的名称，赋值给 `BINS` 变量：

```makefile
COMMANDS ?= $(filter-out %.md, $(wildcard ${ROOT_DIR}/cmd/*))
BINS ?= $(foreach cmd,${COMMANDS},$(notdir ${cmd}))
```

随后利用底层 `go.build.%` 的能力，借助 `$(addprefix ...)` 函数拼接出要构建的 targets 名，作为 `go.build` 的依赖。同样作为依赖的还有 `go.build.verify`，确保安装了 `go`、或者是确保安装的 `go` 版本符合要求。

```makefile
.PHONY: go.build.verify
go.build.verify:
ifneq ($(shell $(GO) version | grep -q 'go version go' && echo 0 || echo 1), 0)
	$(error Go binary is not found. Please install Go first.')
endif

.PHONY: go.build
go.build: go.build.verify $(addprefix go.build., $(addprefix $(PLATFORM)., $(BINS)))
```

这样就会编译所有二进制文件。然后只需要在 `USAGE_OPTIONS` 中让用户能够覆盖 `BINS` 的值，即可指定要编译哪些二进制文件，所以上面 `BINS` 的赋值用了 `?=`。在多个平台上编译也类似：

```makefile
.PHONY: go.build.multiarch
go.build.multiarch: go.build.verify $(foreach p,$(PLATFORMS),$(addprefix go.build., $(addprefix $(p)., $(BINS))))
```

最后，我们将这两个命令暴露到根目录 `Makefile`，使得只要调用 `make build` 和 `make build.multiarch` 即可：

```makefile
## build: Build source code for host platform.
.PHONY: build
build:
	@$(MAKE) go.build

## build.multiarch: Build source code for multiple platforms.
.PHONY: build.multiarch
build.multiarch:
	@$(MAKE) go.build.multiarch
```

整个过程的调用链长这样：

```
build.multiarch
  -> go.build.multiarch
    -> go.build.verify
    -> go.build.linux_amd64.server
    -> go.build.linux_amd64.client
    -> go.build.linux_arm64.server
    -> go.build.linux_arm64.client
```

### 🌰 自动安装依赖工具

我们同样可以利用 Makefile 依赖关系来自动安装依赖工具、避免重复安装工具等。以检查 license 为例，这一操作需要安装 addlicense 工具。我们首先在 `scripts/make-rules/license.mk` 中，让 `license.verify` 依赖于 `tools.verify.addlicense`：

```makefile
.PHONY: license.verify
license.verify: tools.verify.addlicense
	@echo "Verifying the boilerplate headers for all files"
	@addlicense -check -f $(TEMPLATE) $(CODE_DIRS)
```

后者位于 `scripts/make-rules/tools.mk` 中，会检查工具是否已安装，如果没有则自动安装：

```makefile
.PHONY: tools.verify.%
tools.verify.%:
	@if ! which $* &>/dev/null; then $(MAKE) tools.install.$*; fi

.PHONY: tools.install.%
tools.install.%:
	@echo "Installing $*"
	@$(MAKE) install.$*
```

最后调用针对每个工具的 `install.%` 安装工具：

```makefile
.PHONY: install.addlicense
install.addlicense:
	@$(GO) install github.com/google/addlicense@latest
```

安装完后，第二次调用 `tools.verify.addlicense` 就会直接返回，不会重复安装工具。

考虑到 `verify-license` 也是常用功能，我们也可以将其暴露到根目录 Makefile 中。这不是必须的，调用 `make license.verify` 效果相同。

```makefile
## verify-license: Verify the license headers for all files.
.PHONY: verify-license
verify-license:
	@$(MAKE) license.verify
```

## 其他常用设置

`scripts/make-rules/common.mk`：

```makefile
SHELL := /bin/bash

# include the common makefile
COMMON_SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

ifeq ($(origin ROOT_DIR),undefined)
ROOT_DIR := $(abspath $(shell cd $(COMMON_SELF_DIR)/../.. && pwd -P))
endif

# Linux command settings
CODE_DIRS := $(ROOT_DIR)/pkg $(ROOT_DIR)/cmd $(ROOT_DIR)/test
FIND := find $(CODE_DIRS)
```

`scripts/make-rules/gen.mk`：

```makefile
.PHONY: gen.clean
gen.clean:
	@$(FIND) -type f -name '*_generated.go' -delete
```

`scripts/make-rules/golang.mk`：

```makefile
.PHONY: go.lint
go.lint: tools.verify.golangci-lint
	@echo "Run golangci to lint source codes"
	golangci-lint run -c $(ROOT_DIR)/.golangci.yml
```

`scripts/make-rules/tools.mk`：

```makefile
BUILD_TOOLS ?= golangci-lint goimports addlicense # ...
RELEASE_TOOLS ?= goreleaser upx nfpm # ...

.PHONY: tools.install
tools.install: $(addprefix tools.install., $(BUILD_TOOLS) $(RELEASE_TOOLS))
```

## 参考资料

1. [Makefile Tutorial By Example](https://makefiletutorial.com/#top)
1. [跟我一起写 Makefile](https://seisman.github.io/how-to-write-makefile/functions.html)

