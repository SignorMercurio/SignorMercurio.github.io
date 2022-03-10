---
title: 东方记者：新闻统计小工具 Newspaper
date: 2020-01-22 22:23:36
tags:
  - Python
  - 爬虫
  - 项目
categories:
  - 自动化
---

这下统计新闻要轻松多了。

<!--more-->

## 背景

每个月我都需要负责对部分学校二级网站进行例行检查并撰写报告，这并没有太大工作量。然而在 2020 年年初，我接到的任务是统计多个二级网站在过去一年内更新的新闻条数、点击量最高的新闻信息，并根据新闻点击量绘制散点图。一般而言，新闻条数都在 100 条以上，而许多二级网站的点击量需要点进新闻链接后才能看到，这样工作量一下子大了不少。我自然想到通过脚本来实现自动化统计。

## 思路

使用 `requests` 库发起请求。考虑到有些网站有微弱的反爬功能，需要注意设置 UA 以及 Referer，并尽可能按照正常访问的步骤发送请求。

找到新闻列表页面后，观察网页结构并由此撰写 `BeautifulSoup` 相关代码来点击新闻链接。这里我手动获取了 2019 年最早的一条新闻所在页数作为 `max_page`，但这些页中仍会包含 2018 与 2020 年的新闻，需要检查网页元素并通过正则筛选掉。故技重施来获取点击量数值。幸运的是，部分二级网站采用的模板相同，代码几乎不需要修改；此外，部分二级网站采用的 wordpress 模板中可以发现一个支持 POST 请求的点击量统计 url，这能为我们省去不少麻烦。

少量新闻链接会指向外部网站页面，这时去找点击量就没有一个统一的方法了，遇到这种情况可以直接跳过然后手动统计点击量，这个部分的工作量很小。

最后将数据按 `(点击量, 日期)` 数值对进行存储后调用 `pandas` 库写入 Excel 即可。

## 依赖

- `bs4`
- `requests`
- `pandas`（可选）

均可以通过 `pip install` 安装。

## 使用

根据具体的网站结构，修改：

- `base_url`
- `news_url`
- `headers`（可选）
- `max_page`
- `SoupStrainer` 过滤器
- 各个功能函数，如 `page2url, get*, fillTable` 等
- 其它函数，比如在访问新闻页面前先访问网站首页等（可选）

## 代码

给出两例代码，分别适用于社会发展学院与传播学院网站。


```python
# Newspaper-soci.py
from bs4 import BeautifulSoup, SoupStrainer
import requests
import re

# constants
base_url = 'http://www.soci.ecnu.edu.cn'
news_url = base_url + '/10658/list'
headers = {
  'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Mobile Safari/537.36',
  'Referer': 'http://www.soci.ecnu.edu.cn/2c/24/c10658a273444/page.htm'
}
max_page = 11

# for pandas
time = []
visit = []

# Filter the DOM first
only_news = SoupStrainer('div', id='wp_news_w3')

def page2url(i):
  return news_url + str(i+1) + '.htm'

def getNewsList(soup):
  return soup.select('div> table > tr')

def getDate(news):
  return news('div')[0].string

def getArticleURL(news):
  return news('a')[0]['href']

def getVisitCountURL(article_url):
  return base_url + '/_visitcountdisplay?siteId=295&type=3&articleId=' + article_url[-15:-9]

def fillTable(soup, date):
  global time, visit
  s = soup.find('p').string.strip()
  print(s)
  visit.append(int(s))
  time.append(date[5:])

def iterNews(news_list, r):
  date_regex = r'^2019-.*'
  for news in news_list:
    date = getDate(news)
    if re.match(date_regex, date):
      article_url = getArticleURL(news)
      if not article_url.startswith('http'):
        soup = BeautifulSoup(r.post(getVisitCountURL(article_url),headers=headers).text,'lxml')
        try:
          fillTable(soup, date)
        except:
          pass

def export2Excel():
  import pandas as pd
  writer = pd.ExcelWriter('output.xlsx')
  df = pd.DataFrame(data={'time':time,'visit':visit})
  df.to_excel(writer,'Sheet1', index=False)
  writer.save()

def crawl():
  r = requests.Session()
  for i in range(max_page):
    soup = BeautifulSoup(r.get(page2url(i),headers=headers).text, 'lxml', parse_only=only_news)
    news_list = getNewsList(soup)
    iterNews(news_list, r)


if __name__ == "__main__":
    crawl()
    export2Excel()
```

```python
# Newspaper-comm.py
from bs4 import BeautifulSoup, SoupStrainer
import requests
import re

# constants
base_url = 'http://www.comm.ecnu.edu.cn'
news_url = base_url + '/htmlaction.do?method=toGetSubNewsList&menuType=11&pageNo='
headers = {
  'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Mobile Safari/537.36'
}
max_page = 7

# for pandas
time = []
visit = []

# Filter the DOM first
only_news = SoupStrainer(class_='news_area_text')
only_detail = SoupStrainer('div',id='view_record')

def page2url(i):
  return news_url + str(i)

def getNewsList(soup):
  return soup('a', href=re.compile(r'.*htmlId=\d'))

def getDate(news):
  return news.select('.newsdate')[0].string

def getArticleURL(news):
  return news['href']

def getVisitCountURL(article_url):
  return base_url + article_url

def fillTable(soup, date):
  global time, visit
  s = soup.find('div').string[5:]
  print(s)
  visit.append(int(s))
  time.append(date[10:])

def iterNews(news_list, r):
  date_regex = r'.*2019-.*'
  for news in news_list:
    date = getDate(news)
    if re.match(date_regex, date):
      article_url = getArticleURL(news)
      if not article_url.startswith('http'):
        soup = BeautifulSoup(r.get(getVisitCountURL(article_url),headers=headers).text,'lxml', parse_only=only_detail)
        try:
          fillTable(soup, date)
        except:
          pass

def export2Excel():
  import pandas as pd
  writer = pd.ExcelWriter('output.xlsx')
  df = pd.DataFrame(data={'time':time,'visit':visit})
  df.to_excel(writer,'Sheet1', index=False)
  writer.save()

def crawl():
  r = requests.Session()
  r.get(base_url +'/htmlaction.do?method=toIndex')
  for i in range(max_page):
    soup = BeautifulSoup(r.get(page2url(i),headers=headers).text, 'lxml', parse_only=only_news)
    news_list = getNewsList(soup)
    iterNews(news_list, r)


if __name__ == "__main__":
    crawl()
    export2Excel()
```
