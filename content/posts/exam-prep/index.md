---
title: 程序设计能力实训 资料准备
date: 2018-03-10 21:32:10
tags:
  - C/C++
  - 数学
  - 高精度
  - 快速幂
  - 字符串
  - 动态规划
  - 搜索
  - 最大区间和
  - 模版
categories:
  - 算法
---

其实差不多就是低难度 C++ 模板集合。

<!--more-->

## 排序

### 快速排序

```cpp
void quick_sort(int s[], int l, int r) //(s[], 0, n-1) ascending order
{
    int i, j, x;
    if (l < r)
    {
        i = l;
        j = r;
        x = s[i];
        while (i < j)
        {
            while(i < j && s[j] > x)
                j--;
            if(i < j)
                s[i++] = s[j];


            while(i < j && s[i] <x)
                i++;
            if(i < j)
                s[j--] = s[i];

        }
        s[i] = x;
        quick_sort(s, l, i-1);
        quick_sort(s, i+1, r);
    }
}
```

### 选择排序

```cpp
void sel_sort(int *num, int n) //ascending order
{
    int i, j, min, tmp;

    for (i = 0;i < n - 1; ++i){
        min = i;

        for (j = i + 1; j < n; ++j)
            if (num[min] > num[j]) min = j;


        if (min != i){
            tmp = num[min];
            num[min] = num[i];
            num[i] = tmp;
        }
    }
}
```

### 插入排序

```cpp
void ins_sort(int *num, int n) //ascending order
{
    int i, j;
    for (i = 1; i < n; ++i){
        for (j = 0; j < i; ++j)
            if (num[j] > num[i]){
                int tmp = num[i], k;
                for (k = i; k> j; --k) num[k] = num[k - 1];
                num[j] = tmp;
                break;
            }
    }
}
```

### 冒泡排序

```cpp
void bubble_sort(int *num, int n) // ascending order
{
    int i, j;
    for (i = n - 1; i> 0; --i){
        for (j = 0; j < i; ++j)
            if (num[j] > num[j + 1]){
                int tmp = num[j];
                num[j] = num[j + 1];
                num[j + 1] = tmp;
            }
    }
}
```

## 杨辉三角

```cpp
void tri(int m)
{
    int i,j,a[30][30]={{0}};

    for (i = 0; i < m; i++)
        a[i][0] = 1;

    for (i = 1; i < m; i++)
        for (j = 1; j <= i; j++)
            a[i][j] = a[i-1][j-1] + a[i-1][j];

    for (i = 0; i < m; i++){
        for (j = 0; j <= i; j++){
            if (j == i)
                printf("%d", a[i][j]);
            else
                printf("%d", a[i][j]);
        }
        printf("\n");
    }
}
```

## 十进制转 R 进制

```cpp
void TentoR(int a, int b) //a(base 10) to number(base b)
{
    int cnt,number[20];
    if (a == 0)
        return;
    TentoR(a / b, b);
    number[cnt++] = a % b;
}
```

## 二分查找

```cpp
int bin_search(int *a, int size, int p) //ascending order
{
    int l = 0, r = size - 1;
    while (l <= r){
        int mid = l + (r - l) / 2;
        if (p == a[mid]) return mid;
        else if (p> a[mid]) l = mid + 1;
        else r = mid - 1;
    }
    return -1;
}
```

## 字符串反转

```cpp
void rev_str(char s[])
{
    int c,i,j;
    for (i = 0, j = strlen(s) - 1; i <j; i++, j--){
        c = s [i];
        s[i] = s[j];
        s[j] = c;
    }
}
```

## 最大公约数

```cpp
long gcd(long a, long b) //lcm = a * b / gcd(a, b)
{
    return b == 0 ? a : gcd(b, a % b);
}
```

## 高精度

### 加法（非负）

```cpp
inline string add(string s1, string s2)
{
    string s;
    int len1 = s1.size(), len2 = s2.size();
    if (len1 < len2)
        for (int i = 1; i <= len2-len1; ++i)
            s1 = "0" + s1;
    else
        for (int i = 1; i <= len1-len2; ++i)
            s2 = "0" + s2;
    len1 = s1.size();
    int plus = 0, tmp;
    for (int i = len1-1; i>= 0; --i)
    {
        tmp = s1[i]-'0' + s2[i]-'0' + plus;
        plus = tmp / 10;
        tmp %= 10;
        s = char(tmp+'0') + s;
    }
    if (plus) s = char(plus+'0') + s;
    return s;
}
```

### 减法

```cpp
inline int cmp(const string& s1, const string& s2)
{
    if (s1.size() > s2.size()) return 1;
    else if (s1.size() <s2.size()) return -1;
    else return s1.compare(s2);
}

inline string subtract(string s1, string s2)
{
    string s;
    if (!cmp(s1, s2)) return "0";
    if (cmp(s1, s2) <0) {putchar('-'); swap(s1, s2);}
    int tmp = s1.size() - s2.size(), minus = 0;
    for (int i = s2.size()-1; i >= 0; --i)
    {
        if (s1[i+tmp] <s2[i]+minus)
        {
            s = char(s1[i+tmp] - s2[i] - minus + '0'+10) + s;
            minus = 1;
        } else
        {
            s = char(s1[i+tmp] - s2[i] - minus + '0') + s;
            minus = 0;
        }
    }
    for (int i = tmp-1; i>= 0; --i)
    {
        if (s1[i] - minus >= '0')
        {
            s = char(s1[i]-minus) + s;
            minus = 0;
        } else
        {
            s = char(s1[i] - minus + 10) + s;
            minus = 1;
        }
    }
    s.erase(0, s.find_first_not_of('0'));
    return s;
}
```

### 乘法（非负，需要前面的 add)

```cpp
inline string mul(string s1, string s2)
{
    string s, stmp;
    int len1 = s1.size(), len2 = s2.size();
    for (int i = len2-1; i>= 0; --i)
    {
        stmp = "";
        int tmp = s2[i]-'0', plus = 0, t = 0;
        if (tmp)
        {
            for (int j = 1; j <= len2-i-1; ++j)
                stmp += "0";
            for (int j = len1-1; j>= 0; --j)
            {
                t = (tmp*(s1[j]-'0') + plus) % 10;
                plus = (tmp*(s1[j]-'0') + plus) / 10;
                stmp = char(t+'0') + stmp;
            }
            if (plus) stmp = char(plus+'0') + stmp;
        }
        s = add(s, stmp);
    }
    s.erase(0, s.find_first_not_of('0'));
    if (s.empty()) s = "0";
    return s;
}
```

### 阶乘

```cpp
void fact(int n)
{
    int result[10005];
    memset(result, 0, sizeof(result));
    result[0] = 1;
    for (int i = 2; i <= n; ++i)
    {
        int left = 0;
        for (int j = 0; j < 10000; ++j)
        {
            result[j] = left + result[j] * i;
            left = result[j] / 10;
            result[j] %= 10;
        }
    }
    int k = 9999;
    while (!result[k])
        k--;
    for (int i = k; i>= 0; --i)
        printf("%d", result[i]);
    printf("\n");
}
```

### 除法（非负，需要前面的 `subtract` 和 `mul` 且除数不能为 0）

```cpp
inline void div(string s1, string s2, string& quot, string& rem)
{
    quot = rem = "";
    if (s1 =="0")
    {
        quot = rem = "0";
        return;
    }
    int comp = cmp(s1, s2);
    if (comp < 0)
    {
        quot = "0";
        rem = s1;
        return;
    }else if (!comp)
    {
        quot = "1";
        rem = "0";
        return;
    } else
    {
        int len1 = s1.size(), len2 = s2.size();
        string stmp;
        stmp.append(s1, 0, len2-1);
        for (int i = len2-1; i < len1; ++i)
        {
            stmp += s1[i];
            stmp.erase(0, stmp.find_first_not_of('0'));
            if (stmp.empty()) stmp = "0";
            for (char c ='9'; c>= '0'; --c)
            {
                string s, tmp;
                s += c;
                tmp = mul(s2, s);
                if (cmp(tmp, stmp) <= 0)
                {
                    quot += c;
                    stmp = subtract(stmp, tmp);
                    break;
                }
            }
        }
        rem = stmp;
    }
    quot.erase(0, quot.find_first_not_of('0'));
    if (quot.empty()) quot = "0";
}
```

## 大整数类

```cpp
struct BigInteger
{
    static const int BASE = 1e8;
    static const int WIDTH = 8;
    vector<int> s;
    BigInteger(long long num = 0) {*this = num;}
    BigInteger operator = (long long);
    BigInteger operator = (const string&);
    BigInteger operator + (const BigInteger&) const;
    BigInteger operator - (const BigInteger&) const;
    BigInteger operator * (const BigInteger&) const;
    BigInteger operator / (const BigInteger&) const;
    BigInteger operator += (const BigInteger&);
    BigInteger operator -= (const BigInteger&);
    BigInteger operator *= (const BigInteger&);
    BigInteger operator /= (const BigInteger&);
    bool operator <(const BigInteger&) const;
    bool operator > (const BigInteger&) const;
    bool operator <= (const BigInteger&) const;
    bool operator >= (const BigInteger&) const;
    bool operator != (const BigInteger&) const;
    bool operator == (const BigInteger&) const;
};

BigInteger BigInteger::operator = (long long num)       // 重载 = 运算符 (数字赋值)
{
    s.clear();
    do
    {
        s.push_back(num%BASE);
        num /= BASE;
    }while (num> 0);
    return *this;
}

BigInteger BigInteger::operator = (const string& str)       // 重载 = 运算符 (字符串赋值)
{
    s.clear();
    int x, len = (str.length() - 1) / WIDTH + 1;
    for (int i = 0; i < len; ++i)
    {
        int end = str.length() - i * WIDTH;
        int start = max(0, end-WIDTH);
        sscanf(str.substr(start, end-start).c_str(),"%d", &x);
        s.push_back(x);
    }
    return *this;
}

BigInteger BigInteger::operator + (const BigInteger& b) const       // 重载 + 运算符
{
    BigInteger c;
    c.s.clear();
    for (int i = 0, g = 0; ; ++i)
    {
        if (!g && i>= s.size() && i>= b.s.size())
            break;
        int x = g;
        if (i < s.size())
            x += s[i];
        if (i < b.s.size())
            x += b.s[i];
        c.s.push_back(x%BASE);
        g = x / BASE;
    }
    return c;
}

BigInteger BigInteger::operator += (const BigInteger& b)        // 重载 += 运算符
{
    *this = *this + b;
    return *this;
}

bool BigInteger::operator <(const BigInteger& b) const     // 重载 < 运算符
{
    if (s.size() != b.s.size())
        return s.size() < b.s.size();
    for (int i = s.size()-1; i >= 0; --i)
        if (s[i] != b.s[i])
            return s[i] <b.s[i];
    return false;
}

bool BigInteger::operator > (const BigInteger& b) const     // 重载 > 运算符
{
    return b < *this;
}

bool BigInteger::operator <= (const BigInteger& b) const     // 重载 <= 运算符
{
    return !(b < *this);
}

bool BigInteger::operator >= (const BigInteger& b) const     // 重载 >= 运算符
{
    return !(*this < b);
}

bool BigInteger::operator != (const BigInteger& b) const     // 重载!= 运算符
{
    return b < *this || *this < b;
}

bool BigInteger::operator == (const BigInteger& b) const     // 重载 == 运算符
{
    return !(b < *this) || !(*this < b);
}

ostream& operator <<(ostream& out, const BigInteger& x)        // 重载 << 运算符
{
    out <<x.s.back();
    for (int i = x.s.size()-2; i >= 0; --i)
    {
        char buf[20];
        sprintf(buf,"%08d", x.s[i]);
        for (int j = 0; j < strlen(buf); ++j)
            out <<buf[j];
    }
    return out;
}

istream& operator >> (istream& in, BigInteger& x)       // 重载 >> 运算符
{
    string s;
    if (!(in>> s))
        return in;
    x = s;
    return in;
}
```

## 快速幂取模

```cpp
typedef long long ll;

ll pow_mod(int a, int b, int p)
{
    ll ret = 1;
    while (b)
    {
        if (b&1) ret = (ret * a) % p;
        a = (a * a) % p;
        b >>= 1;
    }
    return ret;
}
```

## 扩展欧几里得

```cpp
int extgcd(int a, int b, int &x, int &y)
{
    if (!b)
    {
        x = 1; y = 0;
        return a;
    }
    int d = extgcd(b, a % b, x, y);
    int t = x;
    x = y;
    y = t - a / b * y;
    return d;
}
```

## 素数相关

### 欧拉筛

```cpp
// 欧拉筛
const int maxn = 1e7+5;
bool np[maxn]{true,true};
vector<int> prime;

int main()
{
    int n, m, x;
    cin >> n >> m;
    for (int i = 2; i <= n; ++i)
    {
        if (!np[i]) prime.push_back(i);
        for (int j = 0; j < prime.size() && i*prime[j] <= n; ++j)
        {
            np[i*prime[j]] = true;
            if (i % prime[j] == 0) break;
        }
    }
    for (int i = 1; i <= m; ++i)
    {
        scanf("%d", &x);
        printf("%s\n", np[x] ? "No" : "Yes");
    }
    return 0;
}
```

### 埃氏筛

```cpp
const int maxn = 1e6+5;
bool np[maxn]{true, true};

void init()
{
    for (int i = 2; i < maxn; i++)
        if (!np[i])
        {
            if (i> maxn/i) continue; // 或用 ll 省去这一步
            for (int j = i*i; j < maxn; j += i)
                np[j] = true;
        }
}
```

### 单独判断（sqrt(n)）

```cpp
typedef long long ll;
inline bool isprime(ll m)
{
    for (ll i = 2; i * i <= m; ++i)
        if (!(m % i)) return false;
    return true;
}
```

### 区间筛

```cpp
typedef long long ll;
const int maxn = 1e6+5;
ll a, b;
bool isp[maxn], ispsmall[maxn];

void seg_sieve()
{
    for (ll i = 2; i*i <= b; ++i) ispsmall[i] = true;
    for (ll i = 0; i <= b-a; ++i) isp[i] = true;
    for (ll i = 2; i*i <= b; ++i)
        if (ispsmall[i])
        {
            for (ll j = (i<<1); j*j <= b; j += i) ispsmall[j] = false;
            for (ll j = max(2LL, (a+i-1)/i) * i; j <= b; j += i) isp[j-a] = false;
        }
    if (a <= 1) isp[1-a] = false;
    bool flag = false;
    for (ll i = 0; i <= b-a; ++i)
        if (isp[i])
        {
            if (flag) printf(" %lld", i+a);
            else flag = true, printf("%lld", i+a);
        }
    flag ? puts("") : puts("no prime number.");
}
```

## 约瑟夫

```cpp
int n, m;
vector<int> v;

int main()
{
    cin >> n >> m;
    if (!n && !m) return 0;
    for (int i = 1; i <= n; ++i)
        v.push_back(i);
    int kill = 0;
    while (v.size() > 1)
    {
        kill = (kill+m-1) % v.size();
        printf("%d", v[kill]);
        v.erase(v.begin()+kill);
    }
    printf("%d\n", v[0]);
    return 0;
}
```

## 组合数计算

```cpp
typedef long long ll;
ll C[41][41];

void calc()
{
    C[1][0] = C[1][1] = 1;
    for(int i = 2; i <= 40; ++i)
    {
        C[i][0] = 1;
        for(int j = 1; j <= i; ++j)
            C[i][j] = C[i-1][j] + C[i-1][j-1];
    }
}
```

## LIS（nlogn）

```cpp
fill(f, f+n, INF);
for (int i = 0; i < n; ++i)
    *lower_bound(f, f+n, a[i]) = a[i];
printf("%d\n", lower_bound(f, f+n, INF) - f);
```

## 闰年判断

```cpp
bool is_leap(int n)
{
    return ((n % 4 == 0 && n % 100)|| n % 400 == 0) ? 1 : 0;
}
```

## 输出给定日期是星期几

```cpp
int main()
{
    int y, m, d;
    scanf("%d-%d-%d", &y, &m, &d);
    if (m == 1 || m == 2){
        --y;
        m += 12;
    }
    int c = y / 100;
    int yy = y - c * 100;
    int day = yy + yy / 4 + c / 4 - 2 * c + 13 * (m + 1) / 5 + d - 1;
    if (y <= 1582 && m <= 10 && d <= 4) day += 3;

    while (day < 0) day += 7;
    day %= 7;

    switch(day){
    case 1: printf("Monday\n");break;
    case 2: printf("Tuesday\n");break;
    case 3: printf("Wednesday\n");break;
    case 4: printf("Thursday\n");break;
    case 5: printf("Friday\n");break;
    case 6: printf("Saturday\n");break;
    default: printf("Sunday\n");
    }
    return 0;
}
```

## 巧算数学问题

### n! 首位数

```cpp
const double PI = 3.14159265358979;
const double E = 2.718281828;

int main()
{
    int n,fn;
    double log_n_fac;
    while (scanf("%d", &n) != EOF){
        log_n_fac = 0.5 * log10(2 * PI *(double)n) + (double)n * log10((double)n / E);
        log_n_fac -=(int)log_n_fac;
        fn = pow(10, log_n_fac);//Stirling's approximation
        switch(n){
            case 0:printf("1\n");break;
            case 1:printf("1\n");break;
            case 2:printf("2\n");break;
            case 3:printf("6\n");break;
            case 7:printf("5\n");break;
            case 8:printf("4\n");break;
            default:printf("%d\n", fn);
        }
    }
    return 0;
}
```

### n^n 首位数

```cpp
int main()
{
    int n;
    scanf("%d",&n);
    while(n != 0){
        printf("%d\n",(int)pow(10,n*log10(n)-(int)(n*log10(n))));
        scanf("%d",&n);
    }
    return 0;
}
```

### 整数质因子分解

```cpp
int n;
void solve()
{
    int i;
    int m = n;
    for (i = 2; i <= n; i++){
        int cnt = 0;
        if (m % i) continue;
        while (m % i == 0){
            m /= i;
            cnt++;
        }
        printf("(%d,%d)", i, cnt);
        if (m == 1) break;
    }
    printf("\n");
}
```

### n! 右端的 0 的个数

```cpp
int main()
{
    int t,i,n,m,z;
    scanf("%d", &t);
    for (i = 0; i < t; i++){
        scanf("%d", &n);
        m = 5;z = 0;
        while (n>= m){
            z += n / m;
            m *= 5;
        }
        printf("case #%d:\n%d\n", i, z);
    }
    return 0;
}
```

## 最长回文子串

```cpp
// 中心扩展法
string expand(string s, int c1, int c2) {
    int l = c1, r = c2;
    int n = s.size();
    while (l>= 0 && r <= n-1 && s[l] == s[r])
        l--, r++;
    return s.substr(l+1, r-l-1);
}

string lps(string s) {
    int n = s.size();
    if (!n) return "";
    string lungo = s.substr(0, 1);
    for (int i = 0; i < n-1; i++) {
        string p1 = expand(s, i, i);
        if (p1.size() > lungo.size())
            lungo = p1;
        string p2 = expand(s, i, i+1);
        if (p2.size() > lungo.size())
            lungo = p2;
    }
    return lungo;
}
```

## 最大区间和

```cpp
ans = a[0];
for (i = 0; i < n; ++i){
    if (tot> 0) tot += a[i];
    else tot = a[i];
    ans = (tot>ans)?tot:ans;
}
```

## 小型分数模板

```cpp
struct frac
{
    ll nume, deno;
    ll gcd(ll a, ll b)
    {
        a = abs(a); b = abs(b);
        return b ? gcd(b, a % b) : a;
    }
    void reduct()
    {
        if(!nume) {
            deno = 1;
            return;
        }
        ll g = gcd(nume, deno);
        nume /= g; deno /= g;
        return;
    }
    frac(ll a, ll b = 1)
    {
        nume = a; deno = b;
        (*this).reduct();
    }
    void print()
    {
        if(deno == 1) printf("%lld\n", nume);
        else printf("%lld/%lld\n", nume, deno);
    }
};

frac operator+(const frac& a, const frac& b)
{
    frac ret(a.nume*b.deno + b.nume*a.deno, a.deno*b.deno);
    ret.reduct();
    return ret;
}
```

## 简单 DP

### 01 背包

```cpp
for (i = 0; i < n; ++i)
    for (j = m; j>= w[i]; --j)
        dp[j] = max(dp[j], dp[j-w[i]] + c[i]);
```

### 最大上升子序列和（n^2）

```cpp
for (i = 0; i < n; ++i)
    dp[i] = a[i];
nowmax = a[0];
for (i = 0; i < n; ++i)
    for (int j = 0; j < i; ++j)
        if (a[j] <a[i])
        {
            dp[i] = max(dp[i], dp[j] + a[i]);
            nowmax = max(nowmax, dp[i]);
        }
```

### 整数拆分

```cpp
for (i = 1; i <= n; ++i)
    for (j = 2; j <= n; ++j)
    {
        dp[i][j] = dp[i][j - 1];
        if (i == j) ++dp[i][j];
        else if(i> j) dp[i][j] += dp[i - j][j];
    }
```

### 拆成 2 的幂和

```cpp
for (int i = 3; i <= 1000000; ++i)
{
    if (i & 1) dp[i] = dp[i-1] % mod;
    else dp[i] = (dp[i-2] + dp[i>>1]) % mod;
}
```

### 拆成不重复正整数

```cpp
dp[0] = 1;
for (int i = 1; i <= m; ++i)
    for (int j = n; j>= i; --j)
        dp[j] += dp[j-i];
```

### 数塔（最小和）

```cpp
for (i = 0; i < n; ++i)
    for (j = 0; j <= i; ++j) scanf("%d", &a[i][j]);
for (i = n - 1; i>= 0; --i)
    for (j = 0; j <= i; ++j)
        dp[j] = min(dp[j], dp[j + 1]) + a[i][j];
printf("%d\n", dp[0]);
```

### 数塔（最大和）

```cpp
for (i = 1; i <= n; ++i)
    for (j = 1; j <= i; ++j){
        scanf("%d", &a[i][j][0]);
        a[i][j][1] = a[i][j][0];
    }
for (j = 1; j <= n; ++j)
    maxn[n] = max(maxn[n], a[n][j][0]);

for (i = n-1; i>= 1; --i)
    for (j = 1; j <= i; ++j){
        a[i][j][0] += max(a[i+1][j][0], a[i+1][j+1][0]);
        maxn[i] = max(maxn[i], a[i][j][0]);
        a[i][j][1] += max(max(a[i+1][j][1], a[i+1][j+1][1]), maxn[i+1]);
    }
printf("%d\n", a[1][1][1]);
```

### 数塔（个位数最大和）

```cpp
for (i = 0; i < n; ++i)
    for (j = 0; j <= i; ++j) scanf("%d", &a[i][j]);
for (i = 0; i < n; ++i)
    dp[n - 1][i][a[n - 1][i] % 10] = 1;
for (i = n - 2; i>= 0; --i)
    for (j = 0; j <= i; ++j)
        for (k = 0; k < 10; ++k)
            if (dp[i + 1][j][k] || dp[i + 1][j + 1][k])
                dp[i][j][(k + a[i][j]) % 10] = 1;
for (i = 9; i>= 0; --i)
    if (dp[0][0][i]){printf("%d\n", i); break;}
```

### 装箱问题（DP）

```cpp
for (i = 0; i < n; ++i)
{
    scanf("%d", &w);
    for (j = m; j>= w; --j)
        dp[j] = max(dp[j], dp[j-w] + w);
}
```

### 装箱问题（搜索）

```cpp
void dfs(int cnt, int now)
{
    if (now> v) return;
    if (cnt == n + 1){
        if (now> max) max = now;
        return;
    }
    dfs(cnt + 1, now);
    dfs(cnt + 1, now + a[cnt]);
}
```

## 十六进制加法

```cpp
const int N = 233;
struct bigNum{
    int a[N];

    bigNum(){
        memset(a,sizeof(a),0);
        for (int i=0;i<N;i++)a[i] = 0;
    }

    void print(){
        for (int i = a[0]; i>0; i--){
            printf("%X",a[i]);
        }
        puts("");
    }

    bigNum operator + (const bigNum &b){
        bigNum c;
        c.a[0] = max(a[0], b.a[0]);
        int x = 0;
        for (int i=1;i<=c.a[0];i++){
            //printf("b[i] = %d", b.a[i]);
            x += a[i] + b.a[i];
            c.a[i] = x % 16;
            x /= 16;
        }
        if (x) c.a[++c.a[0]] = x;
        return c;
    }

}a, b;

int qd(char x){
    if ('0' <= x && x <='9')return x -'0';
    return x - 55;
}

bigNum jd(string st){
    bigNum ans;
    ans.a[0] = st.length();
    for (int i=1; i <= ans.a[0]; i++){
        ans.a[i] = qd(st[ans.a[0] - i]);
    }
    return ans;
}

int main(){
    int T;scanf("%d", &T);
    string st1, st2;
    for (int cas = 0;cas < T;cas++){
        printf("case #%d:\n", cas);
        cin >> st1 >> st2;
        a = jd(st1);
        b = jd(st2);
        bigNum c = a + b;
        c.print();
    }
    return 0;
}
```

## 其他

另外放一些 EOJ 上具有代表性的题，遇到类似的直接看提交记录就可以了：

* 区间筛法——49
* 埃氏筛因子——3469
* 谦虚数 / 丑数类似——1277
* 查单词——3018
* 多项式处理——2，2845
* KMP——3441
* 乱搞输出图形——2983
* 约瑟夫——1849，1982，3030
* 分数相关——3041，2980，2972
* 基础的大法师（雾）/ 剪枝 / 前缀和等等——3490
* 内存相关——2822
* floodfill——2848

## 部分库函数

```cpp
int isgraph(int ch)                         // 是否是可打印字符 (不含空格)
int isprint(int ch)                         // 是否是可打印字符 (含空格)
int ispunct(int ch)
double atan2(double y, double x)            // y/x 的反正切 (弧度)
int atoi(char *nptr)
double strtod(char *str)
int sscanf(char str, char *format)          // 通过 str 格式化赋值
char strcpy(char* dest, char* src)
char strcat(char* dest, char* src)
char strchr(const char *s1, int c)
int strcmp(const char* s1, const char* s2)  // 返回 s1-s2
int strncmp(const char* s1, const char* s2, size_t maxlen)
char strrev(char *s)
char strstr(const char* s1, const char* s2) // s2 中第一次出现 s1 的位置

string s(cstr[, chars_len]);
string s(num, c);

string s(“abcd”);
s.compare(“abcd”);                          // 0
s.compare(“dcba”);                          // < 0
s.compare(“ab”);                            // > 0
s.compare(0,2,s,2,2);                       // 比较 ab 和 cd < 0

s.assign(“nico”,5);                         // 'n','i','c','o','\0'
s.insert(1,str);                            // 插入到索引前
s.replace(1,2,”nternationalizatio”);        // 从 1 开始的 2 个
s.erase(13);                                // 从 13 开始往后全删除
s.erase(7,5);                               // 从 7 开始往后删 5 个

string::find 系列：
1. 搜索对象
2. [起点索引]
3. [搜索字符个数]
```
