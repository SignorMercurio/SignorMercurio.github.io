---
title: 迷途知返：Go Error 处理
date: 2021-09-08 08:50:13
tags:
  - Go
categories:
  - 编程语言
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/GoError/0.png
---

底层包装、中层传递、顶层处理。

<!--more-->

## Sentinel Errors

go 中存在一些预定义的错误，比如 `io.EOF`，在使用时通常用 `if err == io.EOF` 的形式来比较两个错误是否 “相等”。然而，如果错误中需要携带一些错误信息，就不得不采用如下两种方法之一：

1. 返回一个不同的、携带了错误信息的错误。这会儿导致在和 Sentinel Error 比较时， `==` 失效。
2. 用 `fmt.Errorf()`，同样会导致 `==` 失效。

此时，我们只能使用 `error.Error()` 来**在程序中判断错误类型**，然而这个方法设计初衷仅仅是为了**提供错误信息**。

除此之外，如果在编写 API 时使用 Sentinel Error，则该 Error 会成为 API 的公共部分。同时，也会仅仅因为需要判断一个错误而引入一个不必要的依赖。由于上述三个缺点，我们需要尽量避免使用 Sentinel Error。

## Custom Errors

通过实现 `error` 接口来自定义错误类型：

```go
type MyError struct {
  Msg string
  File string
  Line int
}

func (e *MyError) Error() string {
  return fmt.Sprintf("%s:%d %s", e.File, e.Line, e.Msg)
}

func test() error {
  return &MyError{"Somthing happened", "server.go", 42}
}

func main() {
  err := test()
  switch Err := err.(type) {
  case nil:
    // success
  case *MyError:
    fmt.Println("error in line:", err.Line)
  default:
    // unknown
  }
}
```

这种做法能够返回额外的错误信息，然而并没有解决 Sentinel Error 的第二个问题，因此也不推荐在编写 API 时过多使用。

## Opaque Errors

不透明就是指当前函数知道发生了错误，但并不清楚除此以外的任何细节。实际上就是：

```go
func fn() error {
  //...
  if err != nil {
    return err
  }
  // ...
}
```

但是如果我们确实需要在当前函数里获取错误的一些细节呢？此时我们不应该考虑去判断错误的类型或值，而是判断错误是否执行了某些行为：

```go
package net

type Error interface {
  error
  Timeout() bool
  Temporary() bool
}
```

```go
if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
  // handle error
}
```

实际应用中，可以单独编写函数来判断错误执行的行为：

```go
type temporary interface {
  Temporary() bool
}

func IsTemporary(err error) bool {
  te, ok := err.(temporary)
  return ok && te.Temporary()
}
```

这种做法使得我们不需要导入定义错误的包，也不需要了解错误的类型信息，相对灵活。只不过，它仍然不能解决如何返回错误信息的问题。

## Wrap Errors

为了彻底解决上述问题，我们可以使用 `github.com/pkg/errors` 包。它提供了：

- `Wrap()` 方法来包装错误、错误信息和堆栈信息
- `Cause()` 方法来解包装以得到原来的错误本身
- `WithMessage()` 方法仅包装错误和错误信息

这使得我们既能够获得错误本身、又能够获得错误信息，使用起来很方便：

1. 在业务代码中，一般使用 `errors.New()` 产生错误
2. 在业务代码中与其他包协作时，使用 `errors.Wrap()` 包装错误
3. 需要与 Sentinel Errors 比较时，调用 `errors.Cause()` 获取原始错误
4. 调用其他包中的方法时，直接返回错误本身
5. 在程序顶层处理捕获到的错误，例如可以用 `%+v` 打印堆栈信息
6. 在非业务代码中（如编写库时），只能返回原始错误
7. 错误被处理后，不能再被继续返回

简单来说，就是底层包装、中层传递、顶层处理。

## Go 1.13 Errors

Go 1.13 的 `errors` 标准库中引入了 `Is` 和 `As` 方法，只要错误类型中实现了 `Unwrap()` 方法返回原始错误，就可以用 `errors.Is(err, MyError)` 来代替 `==` 判断错误值，并通过 `errors.As(err, &myError)` 代替类型断言判断错误类型。

不过，`github.com/pkg/errors` 也兼容这一特性，因此可以替代标准库使用。

## Eliminate Errors

不停地写 `if err != nil` 挺烦的，所以我们想尽量少写点。比如在下面这个例子中，我们想要统计文件行数：

```go 
func CountLine(r io.Reader) (int, error) {
  var (
    br = bufio.NewReader(r)
    lines int
    err   error
  )

  for {
    _, err = br.ReadString('\n')
    lines++
    if err != nil {
      break
    }
  }

  if err != io.EOF {
    return 0, err
  }

  return lines, nil
}
```

在 for 循环中 `ReadString` 出错，或是无内容可读返回 `io.EOF`，都会跳出循环，这就要求我们捕获两次错误。

但如果我们借助 `Scanner` 的 `Scan()` 方法和 `Err()` 方法，就可以去掉错误捕获的代码：

```go
func CountLines(r io.Reader) (int, error) {
  sc := bufio.NewScanner(r)
  lines := 0

  for sc.Scan() {
    lines++
  }

  return lines, sc.Err()
}
```

可以发现，`Scanner` 在出错时会将错误暂存到 `sc.Err()` 的返回值中。我们也可以模仿这个思路，把一个 `error` 和一个容易产生错误的对象一起封装进一个结构体里，然后在方法内部直接捕获错误：

```go
type errWriter struct {
  io.Writer
  err error
}

func (e *errWriter) Write(buf []byte) (int, error) {
  if e.err != nil {
    return 0, e.err
  }

  var n int
  n, e.err = e.Writer.Write(buf)
  return n, nil
}
```

这样，在调用 `Write` 方法时（例如 `io.Copy`）就不再需要在外部处理错误了。
