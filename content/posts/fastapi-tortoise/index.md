---
title: 各司其职：FastAPI + TortoiseORM 实现异步 DB 操作
date: 2021-01-27
tags:
  - Python
  - FastAPI
  - 项目
categories:
  - 后端
---

参考了 [这个 repo](https://github.com/prostomarkeloff/fastapi-tortoise) 和 [官方文档](https://tortoise-orm.readthedocs.io/en/latest/)，踩了一些坑后觉得有必要记录下来。

<!--more-->

## 目录结构

```
app/
|--app.db
|--requirements.txt
|--initialize.py
|--main.py
|--Database/
|  |--models.py
|--Projects/
|  |--crud.py
|  |--projects.py
|  |--schemas.py
```

无关目录未列出。

## 初始化

首先在 `main.py` 中对初始化流程进行了封装：

```python
from fastapi import FastAPI

from Config.openapi import title, desc, version, docs_url
from initializer import init

app = FastAPI(
    title=title,
    description=desc,
    version=version,
    docs_url=docs_url
)

init(app)
```

在 `init()` 中会执行许多初始化操作：

```python
def init(app: FastAPI):
    init_middleware(app)
    init_db(app)
    init_routers(app)
    # ...
```

注意这里 `init_routers()` 在 `init_db()` 后面执行，之后会提到这样做的好处。而 `init_db()` 函数比较简单：

```python
from fastapi import FastAPI
from tortoise import Tortoise
from tortoise.contrib.fastapi import register_tortoise

from Config import tortoise

def init_db(app: FastAPI):
    register_tortoise(
        app,
        db_url=tortoise.db_url,
        generate_schemas=tortoise.gen_schemas,
        modules=tortoise.modules
    )
    Tortoise.init_models(['Database.models'],'models')
```

Tortoise ORM 提供了 `register-tortoise` 函数，方便我们在服务器启动和关闭时，对 ORM 服务进行启动、关闭。这里传入的配置如下：

```python
db_url = "sqlite://app.db"
gen_schemas = True
modules = {"models": ["Database.models"]}
```

测试环境下采用 sqlite3 作为数据库，并声明自动生成数据库 schemas。在 `modules` 中，指定 `app_name` 为 `models`，告诉 Tortoise 到 `Database.models` 文件中寻找需要的数据库模型。

最后，需要注意主动调用 `init_models` 方法进行 Early-init，这是为了保证 `Database.models` 中的模型都能被及时初始化。否则，生成的 Pydantic Models 极有可能会丢失 Relations 相关的字段。

> 关于这一点，文档中给出了 [更详尽的描述](https://tortoise-orm.readthedocs.io/en/latest/contrib/pydantic.html#relations-early-init)。

遗憾的是，文档中 [FastAPI Examples](https://tortoise-orm.readthedocs.io/en/latest/examples/fastapi.html) 部分并没有体现该问题，因为给出的例子没有用到 Relations 相关 API，不受影响。

## 定义数据库模型

Tortoise ORM 能够很好的支持 Pydantic，甚至可以直接通过定义的数据库模型生成 Pydantic Models，并提供额外的模型转换方法。

这里我们以比较简单的 `Project` 对象为例，在 `Database/models.py` 中创建模型：

```python
from tortoise.fields import IntField, CharField, DatetimeField, ForeignKeyField
from tortoise.models import Model

class Projects(Model):
    id = IntField(pk=True)
    name = CharField(255)
```

由于对于每个 `Project` 都可能发起多次 `Scan` ，定义 `Scan` 模型时可以使用一个外键约束：

```python
class Scans(Model):
    id = IntField(pk=True)
    type = CharField(30)
    target = CharField(255)
    status = CharField(10)
    created_at = DatetimeField(auto_now_add=True)

    project = ForeignKeyField('models.Projects', related_name='scans')
```

外键约束的格式是 `{app_name}.{model_name}`，参数 `related_name` 代表在 `Project` 中查询对应的 `Scan` 时所使用的名字。这样在查询中就可以用 `Scans.project` 和 `Projects.scans` 进行正反向引用了。

> 实际上，这里的 `project` 字段在数据库中被替代为 `project_id`，查询 `Scans` 时会根据得到的 `project_id` 继续在 `Projects` 表中查询结果，毫无疑问这会带来额外的开销，但同时也提高了开发效率。

## 定义 Pydantic Models

接下来在 `Projects/schemas.py` 中创建 Pydantic Models，`Scans` 同理：

```python
from Database.models import Projects
from tortoise.contrib.pydantic import pydantic_model_creator

Project = pydantic_model_creator(Projects, name='Project')
ProjectIn = pydantic_model_creator(
    Projects, name='ProjectIn', exclude_readonly=True)
```

为什么要在 `Projects.schemas` 下才创建 Pydantic Models？因为上文提到，我们必须确保在 `Tortoise.init_models()` 执行后，才执行 `pydantic_model_creator()`。由于 `Projects/` 目录下的内容会在 `init_router()` 中执行，因此将 `init_router()` 放在 `init_db()` 后就能够确保这一点。

这样以后，大概可以得到 `Project` 的结构如下：

```python
{
    id: int,
    name: str,
    scans: List[Scan]
}
```

而 `Scan` 的结构如下：

```python
{
    id: int,
    type: str,
    target: str,
    status: str,
    created_at: Datetime,
    project: Project
}
```

容易发现这里出现了一个递归引用的问题，好在 Tortoise ORM 会自动帮我们解决这类问题。真正的问题在于：虽然对 `Scan` 进行 CRUD 时，常常会需要其对应的 `Project`，但对 `Project` 进行 CRUD 时，通常不需要了解它对应着哪些 `Scan`，而是关心其本身的属性。

因此我们重新定义 `Database.models.Projects`，让它不再返回 `scans` 字段:

```python
class Projects(Model):
    id = IntField(pk=True)
    name = CharField(255)

    class PydanticMeta:
        exclude = ['scans']
```

这里的 `PydanticMeta` 类对于配置自动生成的 Pydantic Models 非常有用，然而目前文档尚不完善，因此记录一下可选的配置：

```python
class PydanticMeta:
    """
    The ``PydanticMeta`` class is used to configure metadata for generating the pydantic Model.

    Usage:

    .. code-block:: python3

        class Foo(Model):
            ...

            class PydanticMeta:
                exclude = ("foo", "baa")
                computed = ("count_peanuts",)
    """

    #: If not empty, only fields this property contains will be in the pydantic model
    include: Tuple[str, ...] = ()

    #: Fields listed in this property will be excluded from pydantic model
    exclude: Tuple[str, ...] = ()

    #: Computed fields can be listed here to use in pydantic model
    computed: Tuple[str, ...] = ()

    #: Use backward relations without annotations - not recommended, it can be huge data
    #: without control
    backward_relations: bool = True

    #: Maximum recursion level allowed
    max_recursion: int = 3

    #: Allow cycles in recursion - This can result in HUGE data - Be careful!
    #: Please use this with ``exclude``/``include`` and sane ``max_recursion``
    allow_cycles: bool = False

    #: If we should exclude raw fields (the ones have _id suffixes) of relations
    exclude_raw_fields: bool = True

    #: Sort fields alphabetically.
    #: If not set (or ``False``) then leave fields in declaration order
    sort_alphabetically: bool = False
```

## 编写简单 CRUD

正确进行配置后，可以尝试写 CRUD 来进行测试了：

```python
from Database.models import Projects
from .schemas import Project, ProjectIn


async def get_all():
    return await Project.from_queryset(Projects.all())


async def get(id: int):
    return await Project.from_queryset_single(Projects.get(id=id))


async def create(param: ProjectIn):
    target = await Projects.create(**param.dict())
    return await Project.from_tortoise_orm(target)


async def edit(id: int, param: ProjectIn):
    await Projects.get(id=id).update(**param.dict())
    return


async def delete(id: int):
    await Projects.get(id=id).delete()
    return
```

Tortoise ORM 生成的 Pydantic Models 可以使用类似 `from_queryset()` 之类的方法来转换数据库查询得到的结果，十分方便。
