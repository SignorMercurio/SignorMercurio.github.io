---
title: 闭门造车：腾讯生态的泥沼
date: 2021-08-21
tags:
  - 微信
  - 实践记录
categories:
  - 后端
---

记录了开发中遇到的和腾讯生态相关的一些问题。

<!--more-->

我曾经抱怨 QQ 的花里胡哨，后来出现了微信；我曾经抱怨微信的功能残疾，后来出现了微信小程序；我曾经抱怨小程序的生态封闭，现在发现原来 QQ 和微信的内置浏览器也是一样的。

## 腾讯云 COS

先记录一个无可厚非的小问题，出现在 [Go SDK 文档中 “预签名 URL” 部分](https://cloud.tencent.com/document/product/436/35059)。实际上，文档中并没有出现错误，只是对于初次接触的开发者来说可能造成误解。

开发中的一个常见需求就是向 COS 上传文件，然后获取对应的 URL 供前端下载该文件。因此在文档中，我首先看到了 “上传请求示例” 的代码：

```go
ak := "SECRETID"
sk := "SECRETKEY"

name := "exampleobject"
ctx := context.Background()
f := strings.NewReader("test")

// 1. 通过普通方式上传对象
_, err := client.Object.Put(ctx, name, f, nil)
if err != nil {
    panic(err)
}
// 获取预签名 URL
presignedURL, err := client.Object.GetPresignedURL(ctx, http.MethodPut, name, ak, sk, time.Hour, nil)
if err != nil {
    panic(err)
}
// 2. 通过预签名方式上传对象
data := "test upload with presignedURL"
f = strings.NewReader(data)
req, err := http.NewRequest(http.MethodPut, presignedURL.String(), f)
if err != nil {
    panic(err)
}
// 用户可自行设置请求头部
req.Header.Set("Content-Type", "text/html")
_, err = http.DefaultClient.Do(req)
if err != nil {
    panic(err)
}
```

显然，这里的 1、2 两点是两种不同的上传方式，我这里选择使用第一种方式，并通过第 14 行的代码获取了预签名 URL。然而，访问这一 URL 却会返回 “签名不一致” 的错误信息，无法下载文件。

继续向下看文档，可以看到 “下载请求示例” 的代码：

```go
ak := "SECRETID"
sk := "SECRETKEY"
name := "exampleobject"
ctx := context.Background()
// 1. 通过普通方式下载对象
resp, err := client.Object.Get(ctx, name, nil)
if err != nil {
    panic(err)
}
bs, _ := ioutil.ReadAll(resp.Body)
resp.Body.Close()
// 获取预签名 URL
presignedURL, err := client.Object.GetPresignedURL(ctx, http.MethodGet, name, ak, sk, time.Hour, nil)
if err != nil {
    panic(err)
}
// 2. 通过预签名 URL 下载对象
resp2, err := http.Get(presignedURL.String())
if err != nil {
    panic(err)
}
bs2, _ := ioutil.ReadAll(resp2.Body)
resp2.Body.Close()
if bytes.Compare(bs2, bs) != 0 {
    panic(errors.New("content is not consistent"))
}
```

如果使用第 13 行的代码来获取预签名 URL，则访问该 URL 可以成功下载文件，这也是这段代码叫 “下载请求示例” 的原因。不难发现，两种获取 URL 的方式唯一的区别在于第二个参数，下载采用 GET 方法，上传采用 PUT 方法。因此实际上 “获取预签名 URL” 的这段代码并不属于第一种方法，而是属于第二种方法。

我们可以修改注释来避免产生误解，如上传请求示例：

```go
ak := "SECRETID"
sk := "SECRETKEY"

name := "exampleobject"
ctx := context.Background()
f := strings.NewReader("test")

// 1. 通过普通方式上传对象
_, err := client.Object.Put(ctx, name, f, nil)
if err != nil {
    panic(err)
}
// 2. 通过预签名方式上传对象
// 获取预签名 URL
presignedURL, err := client.Object.GetPresignedURL(ctx, http.MethodPut, name, ak, sk, time.Hour, nil)
if err != nil {
    panic(err)
}
// 上传对象
data := "test upload with presignedURL"
f = strings.NewReader(data)
req, err := http.NewRequest(http.MethodPut, presignedURL.String(), f)
if err != nil {
    panic(err)
}
// 用户可自行设置请求头部
req.Header.Set("Content-Type", "text/html")
_, err = http.DefaultClient.Do(req)
if err != nil {
    panic(err)
}
```

下载请求示例：

```go
ak := "SECRETID"
sk := "SECRETKEY"
name := "exampleobject"
ctx := context.Background()
// 1. 通过普通方式下载对象
resp, err := client.Object.Get(ctx, name, nil)
if err != nil {
    panic(err)
}
bs, _ := ioutil.ReadAll(resp.Body)
resp.Body.Close()
// 2. 通过预签名 URL 下载对象
// 获取预签名 URL
presignedURL, err := client.Object.GetPresignedURL(ctx, http.MethodGet, name, ak, sk, time.Hour, nil)
if err != nil {
    panic(err)
}
// 下载对象
resp2, err := http.Get(presignedURL.String())
if err != nil {
    panic(err)
}
bs2, _ := ioutil.ReadAll(resp2.Body)
resp2.Body.Close()
if bytes.Compare(bs2, bs) != 0 {
    panic(errors.New("content is not consistent"))
}
```

最后，对于正常业务中先上传文件、后返回下载 URL 的需求，我们可以拼接两份示例代码：

```go
ak := "SECRETID"
sk := "SECRETKEY"

name := "exampleobject"
ctx := context.Background()
f := strings.NewReader("test")

// 通过普通方式上传对象
_, err := client.Object.Put(ctx, name, f, nil)
if err != nil {
    panic(err)
}
// 获取预签名 URL
presignedURL, err := client.Object.GetPresignedURL(ctx, http.MethodGet, name, ak, sk, time.Hour, nil)
if err != nil {
    panic(err)
}
// return presignedURL.String()
```

## 微信内置浏览器

以下问题在安卓 / 苹果手机自带的浏览器中均不存在：

1. 上传文件时，无法识别 `accept=".mp4,.mov"` 等扩展名限制，只能使用 `accept="video/*"` 等类型限制。
2. 上传多个文件时，无法同时使用多个类型限制（如 `accept="image/*, video/*"`）。于是只能将图片和视频上传分开了。
3. 下载文件时，无法调用标准 web api 中的对应接口。我在项目中是根据 [这个办法](https://cloud.tencent.com/developer/article/1654149) 判断是否在微信浏览器中，随后向后端传递不同的参数，使得后端返回不同类型的结果。
4. 打开外部 URL 时，无法调用标准 web api 中的对应接口。后来这个需求改了，绕过了这个问题。
5. 通过 URL 打开视频时，可以播放，右下角也有下载按钮，但无法下载。因为是后台的功能，主要使用平台是 PC Web 端，所以没解决。

解决上述问题的通用方案，是引导用户点击右上角并选择 “在浏览器中打开”，这个措施平时也见得很多了。

> 为什么微信内置浏览器如此特别？其实还是微信小程序一样的套路，强迫开发者使用 [自己的 SDK](https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/JS-SDK.html)。

总的来说，有意不遵循通用的 Web API、封闭自己的生态，无论是出于什么目的都让人相当不快。
