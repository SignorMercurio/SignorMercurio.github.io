---
title: 最短路问题
date: 2018-02-04 11:32:55
tags:
  - 图论
  - 模版
categories:
  - 算法
---

Dijkstra, Bellman-Ford && SPFA.

<!--more-->

## EOJ 3196 Wormholes
其实就是判断图中是否有负环……SPFA 或者 Bellman-Ford 判负环。写的时候还不会 SPFA，所以这里用的 Bellman-Ford。

```cpp
#include <bits/stdc++.h>
using namespace std;

const int N = 505;
const int M = 2550;
const int INF = 1e6;

int n, m, k, cnt, dis[N];

struct node {int u, v, w;}e[M<<1];

void add_edge(int uu, int vv, int ww)
{
    e[cnt].u = uu;
    e[cnt].v = vv;
    e[cnt++].w = ww;
}

bool bellman_ford()
{
    int i;
    for (i = 1; i <= n; ++i) dis[i] = INF;
    for (i = 1; i < n; ++i) {
        bool flag = 0;
        for (int j = 1; j <= cnt; ++j)
            if (dis[e[j].v] > dis[e[j].u] + e[j].w) {
                dis[e[j].v] = dis[e[j].u] + e[j].w;
                flag = 1;
            }
        if (!flag) break;
    }
    for (i = 1; i <= cnt; ++i)
        if (dis[e[i].v] > dis[e[i].u] + e[i].w)
            return 1;
    return 0;
}

int main()
{
    int t, u, v, w;
    cin >> t;
    while (t--) {
        cin >> n >> m >> k;
        cnt = 1;
        while (m--) {
            cin >> u >> v >> w;
            add_edge(u, v, w);
            add_edge(v, u, w);
        }
        while (k--) {
            cin >> u >> v >> w;
            add_edge(u, v, -w);
        }
        cout <<(bellman_ford() ? "YES" : "NO") << endl;
    }
    return 0;
}
```


## EOJ 3202 Roadblocks
求次短路的模板题。用 `dist`, `dist2` 分别保存最短路和次短路，用 Dijkstra 更新这两个数组，最后 `dist2[n-1]` 就是答案。

```cpp
#include <bits/stdc++.h>
using namespace std;

const int N = 5010;
const int INF = 0x3f3f3f3f;

int n, m, dist[N], dist2[N];

struct edge {int to, cost;};
typedef pair<int, int> P;
vector<edge> g[N];

void dijkstra()
{
    priority_queue<P, vector<P>, greater<P> > q;
    fill(dist, dist + n, INF);
    fill(dist2, dist2 + n, INF);
    dist[0] = 0;
    q.push(P(0, 0));
    while (!q.empty()) {
        P p = q.top(); q.pop();
        int v = p.second, d = p.first;
        if (dist2[v] <d) continue;
        for (int i = 0; i < g[v].size(); ++i) {
            edge &e = g[v][i];
            int d2 = d + e.cost;
            if (dist[e.to] > d2) {
                swap(dist[e.to], d2);
                q.push(P(dist[e.to], e.to));
            }
            if (dist2[e.to] > d2 && dist[e.to] <d2) {
                dist2[e.to] = d2;
                q.push(P(dist2[e.to], e.to));
            }
        }
    }
}

int main()
{
    int u, v, w;
    while (cin>> n >> m) {
        for (int i = 0; i < n; ++i)
            g[i].clear();
        for (int i = 0; i < m; ++i) {
            cin >> u >> v >> w;
            g[u-1].push_back((edge){v-1, w});
            g[v-1].push_back((edge){u-1, w});
        }
        dijkstra();
        cout <<dist2[n-1] << endl;
    }
    return 0;
}
```

## EOJ 3197 Invitation Cards
> 有编号 1～P 的站点， 有 Q 条公交车路线，公交车路线只从一个起点站直接到达终点站，是单向的，每条路线有它自己的车费。
有 P 个人早上从 1 出发，他们要到达每一个公交站点， 然后到了晚上再返回点 1。 求所有人来回的最小费用之和。

去的时候比较容易，就是求单源最短路；回来时是求多点到单点的最短路，考虑反向建图，那么问题也化为求单源最短路。两次 SPFA 即可。

```cpp
#include <bits/stdc++.h>
using namespace std;

const int N = 1e6 + 10;
const int INF = 0x3f3f3f3f;
typedef long long ll;

int n, m, head1[N], head2[N], dis[N], t1, t2;
bool vis[N];
struct node {int u, v, w, next;} edge1[N<<1], edge2[N<<1];

ll spfa(node edge[], int head[])
{
    for (int i = 1; i <= n; ++i)
        dis[i] = INF, vis[i] = 0;
    queue<int> q;
    q.push(1);
    dis[1] = 0, vis[1] = 1;
    while (!q.empty()) {
        int u = q.front();
        q.pop();
        vis[u] = 0;
        for (int i = head[u]; ~i; i = edge[i].next) {
            int v = edge[i].v;
            if (dis[v] > edge[i].w + dis[u]) {
                dis[v] = edge[i].w + dis[u];
                if (!vis[v]) vis[v] = 1, q.push(v);
            }
        }
    }
    ll ans = 0;
    for (int i = 1; i <= n; ++i)
        ans += dis[i];
    return ans;
}

void add_edge(int u, int v, int w)
{
    edge1[t1].v = v;
    edge1[t1].w = w;
    edge1[t1].next = head1[u];
    head1[u] = t1++;

    edge2[t2].v = u;
    edge2[t2].w = w;
    edge2[t2].next = head2[v];
    head2[v] = t2++;
}

int main()
{
    int t, u, v, w;
    cin >> t;
    while (t--) {
        cin >> n >> m;
        t1 = t2 = 0;
        memset(head1, -1, sizeof(head1));
        memset(head2, -1, sizeof(head2));
        for (int i = 0; i < m; ++i) {
            cin >> u >> v >> w;
            add_edge(u, v, w);
        }
        cout <<spfa(edge1, head1) + spfa(edge2, head2) << endl;
    }
    return 0;
}
```

## 计算最短路径条数
> 求出有 n (1 < n ≤ 100) 个结点有向图中，结点 1 到结点 n 的最短路径，以及最短路径的条数。
第一行有 2 个整数 n, m (0 < m < 3000)，接下来 m 行每行有三个整数 u, v, w 结点 u 到 v 有一条权为 w 的边 (w < 1e5)。

Dijkstra 模板题 + 重边判定。`cnt` 数组记录最短路条数，`same` 数组记录原来边的条数（也就记录了重边条数）。

```cpp
#include <bits/stdc++.h>
using namespace std;

const int N = 105;
const int INF = 0x3f3f3f3f;

int v[N], d[N], mp[N][N], cnt[N], same[N][N];
int n, m;

void init()
{
    memset(same, 0, sizeof(same));
    for (int i = 0; i < N; ++i)
        for (int j = 0; j < N; ++j)
            mp[i][j] = INF;
    int u, v, w;
    while (m--) {
        scanf("%d%d%d", &u, &v, &w);
        mp[u-1][v-1] = w;
        ++same[u-1][v-1];
    }
    for (int i = 0; i < n; ++i) {
        d[i] = (i ? INF : 0);
        cnt[i] = (i ? 0 : 1);
    }
}

void dijkstra()
{
    for (int i = 0; i < n; ++i) {
        int x, now = INF;
        for (int y = 0; y < n; ++y)
            if (!v[y] && d[y] <= now)
                now = d[x=y];
        v[x] = 1;
        for (int y = 0; y < n; ++y)
            if (!v[y]) {
                if (d[x] + mp[x][y] == d[y])
                    cnt[y] += cnt[x] * same[x][y];
                else if (d[x] + mp[x][y] <d[y]) {
                        cnt[y] = cnt[x] * same[x][y];
                        d[y] = d[x] + mp[x][y];
                }
            }
    }
}

int main()
{
    cin >> n >> m;
    init();
    memset(v, 0, sizeof(v));
    dijkstra();
    if (d[n-1] == INF) d[n-1] = -1;
    cout <<d[n-1] <<" "<< cnt[n-1] << endl;
    return 0;
}
```