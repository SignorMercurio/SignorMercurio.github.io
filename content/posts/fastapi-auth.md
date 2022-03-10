---
title: 久仰大名：基于 FastAPI 实现 OAuth2 登录认证
date: 2021-01-10 16:34:22
tags:
  - Python
  - FastAPI
  - 认证
  - JWT
  - 项目
categories:
  - 探索
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/FastAPIAuth/0.png
---

写 Pianoforte 时第一个遇到的可复用模块。

<!--more-->

最近在通过项目学习 FastAPI，发现登录认证模块可以复用，于是记录一下。代码主要修改自 [官方文档](https://fastapi.tiangolo.com/)。

## 目录结构

```
.
|--app.db
|--requirements.txt
|--app/
|  |--__init__.py
|  |--config.py
|  |--db.py
|  |--main.py
|  |--models.py
|  |--projects/
|  |--users/
|  |  |--__init__.py
|  |  |--auth.py
|  |  |--config.py
|  |  |--crud.py
|  |  |--schemas.py
|  |  |--users.py
```

最外层是 sqlite 数据库文件和依赖，`projects/` 目录和主题无关因此未列出。

## 现有代码

### main.py

```python
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .db import engine
from . import models, config

from .users import users, auth
from .projects import projects

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title='Pianoforte',
    description='Pianoforte Is AN Offensive Framework Of Red TEam',
    version='0.1.0'
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.allow_origins,
    allow_credentials=True,
    allow_methods=config.allow_methods,
    allow_headers=['*']
)

app.include_router(users.router, prefix='/users', tags=['users'])

auth_needed = [Depends(auth.get_current_user)]

app.include_router(projects.router, prefix='/projects', tags=['projects'], dependencies=auth_needed)
```

首先根据 `models.py` 中的定义创建了数据库，数据库相关代码在 `db.py` 中。随后添加 CORS 中间件，并添加 `users` 路由和 `projects` 路由，后者需要认证后方能访问。我们通过 Dependency 的方式，要求 `auth.get_current_user` 函数运行正常才能访问 `projects` 路由，由此实现权限管理。

### db.py

```python
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./app.db"
# SQLALCHEMY_DATABASE_URL = "postgresql://user:password@postgresserver/db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

由于项目规模不大，选用 sqlite3 数据库配合 `sqlalchemy` 的 ORM 功能进行数据库操作。

> 此处 `yield` 方式返回数据库 `Session` 需要 Python 3.7 及以上。

### models.py

```python
from sqlalchemy import Column, Integer, String

from .db import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    password = Column(String)
```

这里仅展示了相关代码，即 `User` 类的字段。这一段代码在数据库中创建了 `users` 表来存放用户数据。

由于业务需要，限定 `username` 不能重复。

### users/schemas.py

上面的 `models.py` 定义了数据库中的 `User` 类，而在本文件中定义了两种语义下的 `User` 类：

```python
from pydantic import BaseModel


class UserBase(BaseModel):
    username: str


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int

    class Config:
        orm_mode = True
```

其一是在注册与登录时使用的 `UserCreate` 类，此时不需要传输 `id`；其二是在获取用户信息时返回的 `User` 类，此时不需要传输 `password` 但需要 `id`。

### users/crud.py

```python
from sqlalchemy.orm import Session

from ..models import User
from . import schemas


def get(db: Session, username: str):
    return db.query(User).filter_by(username=username).first()


def create(db: Session, param: schemas.UserCreate):
    target = User(**param.dict())
    db.add(target)
    db.commit()
    db.refresh(target)
    return target
```

关于数据库操作，这里只涉及到增和查操作。由于 `username` 唯一，可以使用 `username` 作为关键字查询。

在插入数据前，需要将用户传入的数据解构并构建 `User` 数据库对象。

## 认证功能实现

我们计划用 OAuth2 的用户名密码认证，并将用户密码哈希后存入数据库。为了维护登陆状态，这里采用 jwt 代替较为繁琐的 cookie 机制。

### 注册

注册部分较为简单（验证码等部分与主题无关，未展示），在 `users.py` 中编写路由函数：

```python
from fastapi import APIRouter, Depends, HTTPException

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from . import crud
from .auth import get_current_user, auth_user, gen_token, hash_password
from .schemas import User, UserCreate

from ..db import get_db

router = APIRouter()
# ...
@router.post('/')
def create(param: UserCreate, db: Session = Depends(get_db)):
    param.password = hash_password(param.password)
    try:
        target = crud.create(db=db, param=param)
    except IntegrityError:
        raise HTTPException(status_code=400, detail='Duplicate username')
    return 0
```

利用 `Depends(get_db)` 获取一个数据库 `Session`，然后借助 `crud.create` 插入密码被哈希后的用户数据。这里的 `hash_password` 来源于 `auth.py`：

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def hash_password(password):
    return pwd_context.hash(password)
```

我们采用了 `bcrypt` 算法进行哈希。同理，验证函数同样简单：

```python
def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)
```

### 登录：验证用户信息

对于给定的 `username` 和 `password`，我们需要通过数据库查询验证用户名和密码是否合法：

```python
from sqlalchemy.orm import Session
from . import crud

def auth_user(db: Session, username: str, password: str):
    user = crud.get(db=db, username=username)
    if user is None:
        return False
    if not verify_password(password, user.password):
        return False
    return user
```

根据 OAuth2 标准，接收用户名和密码时需要使用 `application/x-www-form-urlencoded` 格式，当用户名或密码错误时返回 401，且返回自定义 HTTP 头 `WWW-Authenticate: Bearer`，其中 `Bearer` 是我们这里使用的携带 token 的方式：

```python
from typing import Dict
from fastapi.security import OAuth2PasswordRequestForm

@router.post('/login', response_model=Dict[str, str])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = auth_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401, detail='Incorrect username or password', headers={'WWW-Authenticate': 'Bearer'})
    # ...
```

### 登录：生成 jwt

对于给定的数据以及 token 失效时间，借助 `python-jose` 库，参考 jwt 标准生成 jwt：

```python
from jose import JWTError, jwt
from datetime import datetime, timedelta

from .config import SECRET_KEY, ALGORITHM

def gen_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt
```

这里的 `data`，根据 jwt 标准可以设置 `sub` 字段为用户的 `username`，失效时间也可以在程序中自定义：

```python
from .config import ACCESS_TOKEN_EXPIRE_MINUTES

@router.post('/login', response_model=Dict[str, str])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = auth_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401, detail='Incorrect username or password', headers={'WWW-Authenticate': 'Bearer'})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = gen_token(
        data={'sub': user.username}, expires_delta=access_token_expires)

    return {
        'access_token': access_token,
        'token_type': 'bearer'
    }
```

最后根据 OAuth2 标准返回 `{access_token, token_type}` 对象。

### 根据 jwt 获取用户信息

先通过 `jwt.decode` 解码信息并验证签名，随后对得到的信息进行解析，最后回到数据库中验证解析后的信息：

```python
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

from ..db import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='users/login')

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401, detail='Could not validate credentials', headers={'WWW-Authenticate': 'Bearer'})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = crud.get(db=db, username=username)
    if user is None:
        raise credentials_exception

    return user
```

这里 `OAuth2PasswordBearer(tokenUrl='users/login')` 实际上和 `login` 函数的参数 `form_data: OAuth2PasswordRequestForm` 对应，形成完整的 OAuth2 password flow。

然后在 `users.py` 中暴露获取当前登陆用户信息的接口：

```python
@router.get('/', response_model=User)
async def get(current_user: User = Depends(get_current_user)):
    return current_user
```

## 测试

在 `app/` 所在目录运行：

```bash
python3 -m uvicorn app.main:app --reload
```

随后访问 http://localhost:8000/docs 即可看到 swagger 文档。

![图 1]({{< param cdnPrefix >}}/FastAPIAuth/1.png)

![图 2]({{< param cdnPrefix >}}/FastAPIAuth/2.png)
