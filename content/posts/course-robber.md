---
title: 横行霸道：ECNU 第三轮课程掠夺者
date: 2019-02-10 21:36:21
tags:
  - Python
  - 爬虫
  - 项目
categories:
  - 自动化
featuredImage: https://cdn.jsdelivr.net/gh/SignorMercurio/blog-cdn/CourseRobber/0.png
---

用来在第三轮选课中抢课。

<!--more-->

## 背景介绍

众所周知，ECNU 将选课分为三轮——前两轮中，每人拥有 100 意愿值，并需要将意愿值合理地分配到想要选择的课程上。每轮结束后，系统按**意愿值优先**的规则进行筛选。而在第三轮，也就是接近开学时的最后一轮中，系统会按**时间优先**的规则进行筛选，即先到先得。与此同时，为了防止 “屯课” 的现象出现，系统只会在第三轮选课期间每天中午 12：00 放出退课后产生的名额。

毫无疑问，对于前两轮的倒霉蛋来说，要想在第三轮有所收获，这部分名额极为重要。于是*课程掠夺者*脚本应运而生。

## 技术要点

脚本由 Python 语言编写，主要用到的第三方库与辅助程序有：

- selenium
- chromedriver.exe
- Pillow
- Tesseract-OCR
- pytesseract
- retrying

## 技术原理

利用 `selenium` + `chromedriver` 控制 Chrome 浏览器自动执行命令，并访问 ECNU 公共数据库登录页面。根据用户输入的学号和公共数据库密码进行登录，用户也可以自行更改代码开头的信息来进一步简化操作。由于登录时要求输入验证码，利用 `Pillow` + `Tesseract-OCR` + `pytesseract` 库，先根据验证码在网页中的相对位置截取图片，随后转换为灰度图并用 `ImageEnhance` 增加图片对比度，最后自动识别图中的验证码并输入。

登录后依次点击相应的链接。因为在选课期间公共数据库响应速度往往非常慢，而脚本中利用 `driver` 的选择器定位要点击的链接，所以如果响应过慢将出现 `NoSuchElementException`。最初用 `time.sleep(足够长的时间)` 作为解决方案，但是这一时间并不容易设置。因此引入 `retrying` 库，利用 `@retry` 装饰器使得定位链接时，如果出现异常就等待 2 秒再重试。这样既不会让每次点击之前都等待 2 秒，又能保证加载过慢时程序不至于异常终止。

最后则在选课系统中重复输入课程序号（来自用户输入）并点击选课按钮，如果没有选上则刷新页面，直到选上为止。可以通过关闭脚本打开的 Chrome 浏览器，或是按下 `<Ctrl+C>` 来终止程序。

## 注意事项

1. 运行前请保证已经下载 `chromedriver.exe` 且其所在路径已添加到环境变量的 `Path` 中。同时，请保证已经安装 `selenium, Pillow, pytesseract, retrying` 四个 Python 第三方库（都可以通过 `pip install` 安装）以及 `Tesseract-OCR` 软件。
2. 安装 `Tesseract-OCR` 时需要在 `Path` 中添加软件根目录，并在**系统变量**中添加 `TESSDATA_PREFIX` 变量，值为软件根目录下的 `tessdata` 目录。
3. 本脚本文件仅支持 Chrome 浏览器。PhantomJS 和 Firefox 同理，只是驱动程序不同。
4. 使用时，打开命令行，切换到 `course.py` 文件所在目录，运行 `python course.py` 并按提示输入信息。随后可以最小化命令行和被打开的 Chrome 浏览器，进行其它工作。
5. 可以直接修改代码开头 `my_id`、`my_pswd`、`my_course_id` 三行内容以简化使用流程。
6. 使用本脚本并不能保证用户抢到心仪的课程。

## 代码

```python
from selenium import webdriver
from PIL import Image, ImageEnhance
import pytesseract
from retrying import retry

my_id = input('Your ID:')
my_pswd = input('Your password:')
my_course_id = input('ID of course you need:')
# my_id = 'id'
# my_pswd = 'password'
# my_course_id = 'course id'

print('Welcome. Press <Ctrl+C> or close the browser to quit.')
# chromedriver.exe must be added to PATH
driver = webdriver.Chrome()
driver.get("http://portal.ecnu.edu.cn")

driver.save_screenshot('0.png')
codeImage = driver.find_element_by_id('codeImage')
img = Image.open('0.png')
# Adjust location && size for img.crop()
left = codeImage.location['x'] * 1.51
top = codeImage.location['y'] * 1.5
right = left + codeImage.size['width'] * 1.3
bottom = top + codeImage.size['height'] * 1.5

img = img.crop((left, top, right, bottom))
img = img.convert('L')
img = ImageEnhance.Contrast(img).enhance(3)
# Single text line with only numbers
my_code = pytesseract.image_to_string(img,
config='--psm 7 -c tessedit_char_whitelist=0123456789')

driver.find_element_by_id('un').send_keys(my_id)
driver.find_element_by_id('pd').send_keys(my_pswd)
driver.find_element_by_name('code').send_keys(my_code)
driver.find_element_by_class_name('login_box_landing_btn').click()

def stop_func(attempts, delay):
    print('Loading... Attempts: %d, Delay: %d' % (attempts, delay))

@retry(wait_fixed=2000, stop_func=stop_func)
def click_edu():
    driver.find_element_by_link_text(' 本科教学').click()

def switch_2_new_tag():
    driver.switch_to.window(driver.window_handles[-1])

@retry(wait_fixed=2000, stop_func=stop_func)
def click_course():
    driver.find_element_by_css_selector('li.li_1 a.subMenu').click()

@retry(wait_fixed=2000, stop_func=stop_func)
def click_choose():
    driver.find_elements_by_link_text(' 点击进入')[2].click()

@retry(wait_fixed=2000, stop_func=stop_func)
def click_entry():
    driver.find_element_by_link_text(' 进入选课>>>>').click()

@retry(wait_fixed=2000, stop_func=stop_func)
def click_filter():
    driver.find_element_by_id('electableLessonList_filter_submit').click()

@retry(wait_fixed=2000, stop_func=stop_func)
def click_op():
    driver.find_element_by_class_name('lessonListOperator').click()

click_edu()
switch_2_new_tag()
click_course()
click_choose()
click_entry()
switch_2_new_tag()

while True:
    try:
        # An exception will occur if user closes the browser
        driver.find_element_by_name('electableLesson.no').send_keys(my_course_id)
    except:
        break

    click_filter()
    click_op()

    al = driver.switch_to.alert
    if al.text == '上限人数已满，请稍后再试':
        al.accept()
        print('Refreshing...')
        driver.refresh()
        continue
    else:
        al.accept()
        print('Success!')
        break
```

## 附录

- TODO: 存储用户输入的信息，使用户不用修改代码也能一劳永逸。这涉及到密码存储的问题——不能直接存储明文，所以需要加密机制。采用 `base64` 之类的编码等于没加密，采用单向散列函数则无法还原成密码明文，必须用双向的（也就是严格意义上的）加密机制，由于数据量不大，`DES, 3DES, AES, RSA` 都是值得考虑的选择。问题是我真的需要把这个简单的脚本复杂化吗？
- 虽然 `PIL` 被 `Pillow` 淘汰了，用的时候还是要 `from PIL import ...`。
- `webdriver ` 的选择器和 DOM 的 `document.queryselector` 很像，优势在于更灵活，甚至可以用 `xpath`，劣势嘛…… 没有 `jQuery` 了。
- 调整裁剪图片时用了 `location` 和 `size`，不知道为什么在网页上和在截图里数值上会有偏差，最后靠乱调参数才搞定。。也许是巧合，数值上正好差了 1.5 倍？
- 除了用 `ImageEnhance` 库增加验证码正确识别率以外，还可以用图像二值化的办法。理论上来说用 `pytesseract` 来识别 ECNU 公共数据库的验证码实在是杀鸡用牛刀了。
- 不明白 `pytesseract` 的 `config` 里的参数的含义，在网上粗略找了找没啥发现，命令行里敲 `--help` 就出现了。还是没有养成命令行看官方文档的习惯。
- 关闭浏览器时会在最后的 `while True` 循环第一行触发 `NoSuchWindowException`，毕竟浏览器都被关了嘛。所以额外加了个 `try...except`。
