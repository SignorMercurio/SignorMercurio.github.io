---
title: OJ 常用的模板们
date: 2018-02-05 12:20:23
tags:
  - 线段树
  - 最大区间和
  - 矩阵
  - 高精度
  - 图论
  - 字符串
  - 搜索
  - 数学
  - 模版
categories:
  - 算法
---

全是不太熟的模板。

<!--more-->

## 线段树 (EOJ 2525)
> 有 n 个灯，m 次操作，0 表示一段区间内灯的状态全部反转，1 表示询问一段区间内亮着的灯的数量。

```cpp
#include <bits/stdc++.h>
using namespace std;

const int maxn = 1e5+5;

int st[maxn<<2], add[maxn<<2], n, m, flag, s, e;

void pushdown(int rt, int l, int r)
{
    int mid = (l+r) >> 1;
    st[rt<<1] = mid-l+1 - st[rt<<1];
    st[rt<<1|1] = r-mid - st[rt<<1|1];
    add[rt<<1] ^= add[rt];
    add[rt<<1|1] ^= add[rt];
    add[rt] = 0;
}

void update(int rt, int s, int e, int l, int r)
{
    if (s <= l && r <= e)
    {
        st[rt] = r-l+1 - st[rt];
        add[rt] ^= 1;
        return;
    }
    int mid = (l+r) >> 1;
    if (add[rt]) pushdown(rt, l, r);
    if (s <= mid) update(rt<<1, s, e, l, mid);
    if (e> mid) update(rt<<1|1, s, e, mid+1, r);
    st[rt] = st[rt<<1] + st[rt<<1|1];
}

int query(int rt, int s, int e, int l, int r)
{
    if (s <= l && r <= e) return st[rt];
    int ans = 0, mid = (l+r) >> 1;
    if (add[rt]) pushdown(rt, l, r);
    if (s <= mid) ans += query(rt<<1, s, e, l, mid);
    if (e> mid) ans += query(rt<<1|1, s, e, mid+1, r);
    return ans;
}

int main()
{
    scanf("%d%d", &n, &m);
    for (int i = 0; i < m; ++i)
    {
        scanf("%d%d%d", &flag, &s, &e);
        if (flag) printf("%d\n", query(1, s, e, 1, n));
        else update(1, s, e, 1, n);
    }
    return 0;
}
```

## 最大连续子序列的和
由于要让和最大，可以直接屏蔽掉和为负数的情况 `(tot < 0)`，但是由于求的是连续子序列的和，不能一遇到负数的项就扔掉。如：`5 6 -1 5 4 -7`，最大连续子序列和为 `6+(-1)+5+4=14`。
然后用 `tot` 更新 `ans` 就行了。

```c
#include <stdio.h>

int main()
{
    int cas, i, n;
    scanf("%d", &cas);
    while (cas--){
        scanf("%d", &n);
        int a[100] = {0};
        for (i = 0; i < n; ++i)
            scanf("%d", &a[i]);
        int ans = a[0], tot = 0;
        for (i = 0; i < n; ++i){
            if (tot> 0) tot += a[i];
            else tot = a[i];
            if (tot> ans) ans = tot;
        }
        printf("%d\n", ans);
    }
    return 0;
}
```

## 高斯消元求行列式及逆矩阵
> 给定一个 n*n 的矩阵，输出它的行列式值和逆矩阵（保证存在）。

期末复习线性代数时，发现自己求逆矩阵总是求错，于是干脆写了个程序来实现。。
高斯消元法求解线性方程组只要稍微修改下代码就可以，判断无解 / 无穷多解也不难，至于求自由未知量然后输出任意一解…… 还没有想好。


```cpp
#include <bits/stdc++.h>
using namespace std;

const double eps = 1e-6;
const int N = 12;

void gauss(double a[][N], double b[], double x[], int n)
{
    int i;
    double s;
    for (int k = 1; k <= n; ++k) {
        for (i = k; i <= n && fabs(a[i][k]) <eps; ++i);
        if (i != k) {
            for (int j = k; j <= n; ++j)
                swap(a[i][j], a[k][j]);
            swap(b[i], b[k]);
        }
        for (i = k+1; i <= n; ++i) {
            s = a[i][k] / a[k][k];
            for (int j = k; j <= n; ++j)
                a[i][j] -= a[k][j] * s;
            b[i] -= b[k] * s;
        }
    }
    for (i = n; i>= 1; --i) {
        s = b[i];
        for (int j = i+1; j <= n; ++j)
            s -= x[j] *a[i][j];
        x[i] = s / a[i][i];
        if (fabs(x[i]) <eps) x[i] = 0;
    }
}

int main()
{
    double a[N][N], b[N], x[N], mt[N][N], mk[N][N];
    int n;
    cin >> n;
    for (int i = 1; i <= n; ++i) {
        for (int j = 1; j <= n; ++j) {
            cin >> mk[i][j];
            a[i][j] = mk[i][j];
        }
        b[i] = 0;
    }
    gauss(a, b, x, n);
    double det = 1;
    for (int i = 1; i <= n; ++i)
        det *= a[i][i];
    if (fabs(det) <eps) det = 0;
    printf("%0.2f\n", det);
    for (int k = 1; k <= n; ++k) {
        for (int i = 1; i <= n; ++i) {
            for (int j = 1; j <= n; ++j)
                a[i][j] = mk[i][j];
            b[i] = 0;
        }
        b[k] = 1;
        gauss(a, b, x, n);
        for (int i = 1; i <= n; ++i)
            mt[i][k] = x[i];
    }
    for (int i = 1; i <= n; ++i) {
        for (int j = 1; j < n; ++j)
            printf("%0.2f", mt[i][j]);
        printf("%0.2f\n", mt[i][n]);
    }
    return 0;
}
```


## 计算两个一元多项式的乘积
算是高精度乘法？
细节比较多。降幂输出非零系数。

```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define N 100

void readpoly(char *s, int* poly)
{
    while (*s){
        int sign = 1, a = 0, i = 0;
        if (*s =='+') ++s;
        else if (*s =='-') sign = -1, ++s;

        while (isdigit(*s)){
            a = a * 10 + *s -'0';
            ++s;
        }
        if (a == 0) a = 1;
        if (*s !='x') {poly[0] = a * sign; return;}
        else ++s;

        if (*s =='^') ++s;
        while (isdigit(*s)) {
            i = i * 10 + *s - '0';
            ++s;
        }
        if (i == 0) i = 1;

        poly[i] = a * sign;
    }
}

void multiply(char *s1,char *s2, int* poly)
{
    int poly1[N] = {0}, poly2[N] = {0}, i, j;
    readpoly(s1, poly1);
    readpoly(s2, poly2);
    for (i = 0; i < N / 2; ++i)
        for (j = 0; j < N / 2; ++j)
            poly[i + j] += poly1[i] * poly2[j];
}

int main()
{
    char s1[N+1], s2[N+1];

    while(scanf("%s%s", s1, s2) != EOF){
        int poly[N] = {0}, out[N], n = 0, i;
        multiply(s1, s2, poly);
        for (i = 0; i < N; ++i)
            if (poly[i]) out[n++] = poly[i];
        for (i = n - 1; i>= 0; --i){
            printf("%d", out[i]);
            i ? printf("") : printf("\n");
        }
    }
    return 0;
}
```


## Prim(EOJ 3199)

```cpp
#include <bits/stdc++.h>
using namespace std;

const int maxn = 105;
const int INF = 0x3f3f3f3f;
int mp[maxn][maxn], dis[maxn], vis[maxn], n, sum;

inline int prim()
{
    memset(vis, 0, sizeof vis);
    memset(dis, INF, sizeof dis);
    sum = dis[1] = 0;
    for (;;)
    {
        int u = -1, v, mincost = INF;
        for (int i = 1; i <= n; ++i)
            if (dis[i] <mincost && !vis[i])
            {
                mincost = dis[i];
                u = i;
            }
        if (u == -1) break;
        vis[u] = 1;
        sum += dis[u];
        for (v = 1; v <= n; ++v)
            if (dis[v] > mp[u][v]) dis[v] = mp[u][v];
    }
    return sum;
}

int main()
{
    while (cin>> n)
    {
        memset(mp, INF, sizeof mp);
        for (int i = 1; i <= n; ++i)
            for (int j = 1; j <= n; ++j)
                scanf("%d", &mp[i][j]);
        printf("%d\n", prim());
    }
    return 0;
}
```


## Kruskal(EOJ 3201)
> n 个点，m 条边的图，要使得图中没有圈，求要去掉的边的权值和的最小值。

求图的最大生成树，用总权值减生成树权值得到答案。似乎是只能用 Kruskal 做。边数组应该是要开到 10000 * 10000 / 2 的，没想到 EOJ 上提交 RTE，改成 10000 * 100 就好了……


```cpp
#include <bits/stdc++.h>
using namespace std;

#define maxn 11000

struct edge
{
    int u, v;
    double w;
}g[maxn*100];

struct node
{
    double x, y;
}point[maxn];

double sum;
int n, m, fa[maxn];

inline double dis(const node& a, const node& b)
{
    return sqrt((a.x-b.x)*(a.x-b.x)+(a.y-b.y)*(a.y-b.y));
}

bool cmp(const edge& a, const edge& b)
{
    return a.w > b.w;
}

inline int find(int x)
{
    return x == fa[x] ? x : fa[x] = find(fa[x]);
}

inline double kruskal()
{
    sort(g, g+m, cmp);
    double remain = 0.0;
    for (int i = 0; i < m; ++i)
    {
        int x = find(g[i].u), y = find(g[i].v);
        if (x != y)
        {
            fa[x] = y;
            remain += g[i].w;
        }else continue;
    }
    return sum - remain;
}

int main()
{
    int u, v;
    cin >> n >> m;
    for (int i = 1; i <= n; ++i)
        fa[i] = i;
    for (int i = 1; i <= n; ++i)
        scanf("%lf%lf", &point[i].x, &point[i].y);
    for (int i = 0; i < m; ++i)
    {
        scanf("%d%d", &u, &v);
        g[i].u = u;
        g[i].v = v;
        g[i].w = dis(point[u], point[v]);
        sum += g[i].w;
    }
    printf("%.6f\n", kruskal());
    return 0;
}
```

## KMP
> 对于一个给定的字符串 s，唐纳德给出 q 次询问，第 i 次询问包括三个参数 li,ri,zi，问在 `s[li…ri]` 的所有子串中共有多少个恰好为 zi。
1≤|s|≤100, q≤∑|zi|≤100

坑点在于可重复。。比赛时用 Python 的切片水过去了，后来发现 C++ 用 string 的 `substr` 和 `find` 方法也不难写，这里仅记录一下刚学的 KMP 解法。

说实话，KMP 初学起来是有些绕，不过找点例子，耐心画几个图很快就能理解了。这个算法比较有趣的是求 next 数组时也是用的 KMP，有种自洽的感觉。据说实际上，库函数 `strstr` 和 KMP 效率差不多（甚至更快？）。

```cpp
#include <bits/stdc++.h>
using namespace std;

const int maxn = 1005;
char s[maxn], t[maxn];
int nxt[maxn];
int q, l, r, len;

inline void getnext()
{
    nxt[0] = -1;
    for (int i = 1, j = -1; i < len; ++i)
    {
        while (j> -1 && t[j+1] != t[i])
            j = nxt[j];
        if (t[j+1] == t[i]) ++j;
        nxt[i] = j;
    }
}

inline int kmp()
{
    getnext();
    int ans = 0;
    for (int i = l, j = -1; i <= r; ++i)
    {
        while (j> -1 && t[j+1] != s[i])
            j = nxt[j];
        if (t[j+1] == s[i]) ++j;
        if (j == len-1) ++ans;
    }
    return ans;
}

int main()
{
    scanf("%s%d", s, &q);
    while (q--)
    {
        scanf("%d%d %s", &l, &r, t);
        len = strlen(t);
        printf("%d\n", kmp());
    }
    return 0;
}
```

## 带路径还原的 BFS
> 给定一个迷宫和起点终点，求最快要多少步到终点以及最快的路径，不能到达输出 -1。

显然 bfs，也因此需要开一个 `step` 数组记录步数，更新没有走过的点的 `step`。路径还原则又需要一个数组记录这一步的上一个点，还原时从后往前递归输出即可。


```cpp
#include <bits/stdc++.h>
using namespace std;

const int maxn = 205;
int n, m, sx, sy, ex, ey, ans;
char mp[maxn][maxn];
int step[maxn][maxn];
const int dx[] = {1,-1,0,0};
const int dy[] = {0,0,1,-1};

struct node
{
    int x, y;
}a[maxn][maxn];

inline bool in(int x, int y)
{
    return x>=0 && x<n && y>=0 && y<n;
}

inline void bfs()
{
    queue<node> q;
    node u, v;
    int now = 0;
    u.x = sx; u.y = sy;
    q.push(u);
    while (!q.empty())
    {
        u = q.front(); q.pop();
        now = step[u.x][u.y];
        for (int i = 0; i < 4; ++i)
        {
            v.x = u.x+dx[i]; v.y = u.y+dy[i];
            if (in(v.x, v.y) && mp[v.x][v.y]=='.' || mp[v.x][v.y] == 'E')
                if (!step[v.x][v.y])
                {
                    a[v.x][v.y].x = u.x;
                    a[v.x][v.y].y = u.y;
                    step[v.x][v.y] = now+1;
                    if (mp[v.x][v.y] == 'E')
                    {
                        ans = step[v.x][v.y];
                        return;
                    }
                    q.push(v);
                }
        }
    }
}

inline void dfs(int x, int y)
{
    if (x!=sx || y!=sy) dfs(a[x][y].x, a[x][y].y);
    printf("%d %d\n", x, y);
}

int main()
{
    cin >> n >> m; cin.get();
    for (int i = 0; i < n; ++i)
    {
        scanf("%s", mp[i]);
        for (int j = 0; j < m; ++j)
            if (mp[i][j] == 'S')
            {
                sx = i;
                sy = j;
            }else if(mp[i][j] == 'E')
            {
                ex = i;
                ey = j;
            }
    }
    memset(step, 0, sizeof step);
    bfs();
    if (ans)
    {
        printf("%d\n", ans);
        dfs(ex, ey);
    }else printf("-1\n");
    return 0;
}
```

## 判断两条线段是否相交
包括了一个或多个点重合的情况。
输入点的坐标顺序为 Ax,Ay,Bx,By,Cx,Cy,Dx,Dy，判断线段 AB 与线段 CD 是否相交。
由于问题比较简单，没有用到向量、叉积什么的，而是用了奇怪的作图法 + 不证明直接推广法（？）。
可以画个图验证一下。对于稍难的计算几何题，这些奇技淫巧就没有用了。

```c
#include <stdio.h>

int main()
{
    int x1, y1, x2, y2, x3, y3, x4, y4;
    while (~scanf("%d%d%d%d%d%d%d%d", &x1, &y1, &x2, &y2, &x3, &y3, &x4, &y4)){
        double k = 1.0 * (y1 - y2) / (x1 - x2);
        double n = y1 - k * x1;
        double ans1 = k * x3 + n, ans2 = k * x4 + n;
        if ((ans1 <= y3 && ans2>= y4) || (ans1>= y3 && ans2 <= y4)) printf("Yes\n");
        else printf("No\n");
    }
    return 0;
}
```

## 计算多边形面积
我们假定得到了按照逆时针顺序给出的 n 个顶点的坐标 `x1, y1, x2, y2 ... xn, yn` 且坐标均为整数。
那么最简洁的方法就是计算向量叉积（其实也是算行列式）来求，对凹多边形也适用。直观的理解是将多边形分为了若干个小三角形分别求面积。

```cpp
#include <iostream>
#include <cstdio>
#include <cmath>
using namespace std;


int main(void)
{
    int n, i, x[101], y[101];
    double sum;
    while(cin>> n && n){
        for (i = 0; i < n; ++i)
            cin >> x[i] >> y[i];
        sum = 0;
        for (i = 0; i < n - 1; ++i)
            sum += (x[i] * y[i + 1] - x[i + 1] * y[i]);
        sum = (fabs(sum + x[i] * y[0] - x[0] * y[i])) * 1.0 / 2;
        printf("%.1f\n", sum);
    }
}
```

## 判断线段是否与矩形相交
> 输入格式：
xstart ystart xend yend xleft ytop xright ybottom
Note: The terms top left and bottom right do not imply any ordering of coordinates.

计算几何题对我来说，光是写对就要花很久，而代码还要做到既简洁又易懂真是难上加难……
注意点在于：线段与矩形不相交，这意味着线段不仅可以在矩形外，还可以在矩形内。

```cpp
#include <bits/stdc++.h>
using namespace std;

int main()
{
	int t, x1, y1, x2, y2, xl, yt, xr, yb;
	int a, b, c, f1, f2, f3, f4;
	cin >> t;
	while (t--)
    {
		scanf("%d%d%d%d%d%d%d%d", &x1, &y1, &x2, &y2, &xl, &yt, &xr, &yb);
		if (xl> xr) swap(xl, xr);
        if (yt < yb) swap(yt, yb);
		a = y1 - y2;
		b = x2 - x1;
		c = x1 * y2 - y1 * x2;
		f1 = a * xl + b * yb + c;
		f2 = a * xl + b * yt + c;
		f3 = a * xr + b * yb + c;
		f4 = a * xr + b * yt + c;
		if ((f1>0 && f2>0 && f3>0 && f4>0) || (f1<0 && f2<0 && f3<0 && f4<0))
			printf("F\n");
		else if ((x1> xr && x2 > xr) || (x1 < xl && x2 < xl))
			printf("F\n");
		else if ((y1> yt && y2 > yt) || (y1 < yb && y2 < yb))
			printf("F\n");
		else
            printf("T\n");
	}
	return 0;
}
```

## Graham 求凸包 (EOJ 1189)
> 给定平面上的 n 个点及半径 r，求圆的周长与凸包周长之和。


```cpp
#include <bits/stdc++.h>
using namespace std;

const double PI = acos(-1.0);
const int maxn = 1005;

struct point {int x, y;}p[maxn];
int s[maxn], top;

inline int cross(point p0, point p1, point p2)
{
    return (p1.x-p0.x) * (p2.y-p0.y) - (p1.y-p0.y) * (p2.x-p0.x);
}

inline double dis(point p1, point p2)
{
    return sqrt((p2.x-p1.x)*(p2.x-p1.x) + (p2.y-p1.y)*(p2.y-p1.y));
}

inline bool cmp(point p1, point p2)
{
    int c = cross(p[0], p1, p2);
    if (c> 0) return 1;
    else if (!c && dis(p[0], p1) <dis(p[0], p2)) return 1;
    return 0;
}

inline void graham(int n)
{
    s[0] = 0;
    if (n == 1) top = 0;
    else
    {
        s[1] = top = 1;
        if (n == 2) return;
        for (int i = 2; i < n; ++i)
        {
            while (top && cross(p[s[top-1]], p[s[top]], p[i]) <= 0)
                --top;
            s[++top] = i;
        }
    }
}

int main()
{
    int n, r;
    double ans;
    while (cin>> n >> r)
    {
        scanf("%d%d", &p[0].x, &p[0].y);
        point p0;
        p0.x = p[0].x; p0.y = p[0].y;
        int k = 0;
        for (int i = 1; i < n; ++i)
        {
            scanf("%d%d", &p[i].x, &p[i].y);
            if ((p0.y>p[i].y) || ((p0.y==p[i].y)&&(p0.x>p[i].x)))
            {
                p0.x = p[i].x;
                p0.y = p[i].y;
                k = i;
            }
        }
        p[k] = p[0];
        p[0] = p0;
        sort(p+1, p+n, cmp);
        graham(n);
        ans = 2 * PI * r;
        for (int i = 0; i <= top; ++i)
            ans += dis(p[s[i]], p[s[(i+1) % (top+1)]]);
        printf("%d\n", (int)(ans+0.5));
    }
    return 0;
}
```
