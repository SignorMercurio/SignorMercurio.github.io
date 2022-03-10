---
title: C++ 练习 | 贪吃蛇
date: 2017-12-16 17:33:58
tags:
  - 项目
  - C/C++
categories:
  - 编程语言
---

学一门语言不仅要会写 Hello World，还要会写贪吃蛇。

<!--more-->

## 代码

对这个不到 200 行的命令行游戏还算满意。代码如下：

```cpp
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <windows.h>
#include <conio.h>
#define N 28
#define UP 72
#define DOWN 80
#define LEFT 75
#define RIGHT 77
using namespace std;

typedef struct{int x, y;}point;

point snake[400], food, next_head;//next_head pos of head
char game_map[N][N];
int head, tail;
int lv, len, interval;
char dir;

void gotoxy(int x, int y)//prevent blinking
{
    HANDLE hConsoleOutput;
    COORD dwCursorPosition;
    dwCursorPosition.X = x;
    dwCursorPosition.Y = y;
    hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleCursorPosition(hConsoleOutput, dwCursorPosition);
}

inline void update(char game_map[][N], int lv, int len, int interval)
{
    gotoxy(0, 0);
    int i, j;
    printf("\n");
    for (i = 0; i < N; ++i){
        printf("\t\t");
        for (j = 0; j < N; ++j)
            printf("%c", game_map[i][j]);
        switch(i){
            case 0: printf("\tLevel: %d", lv); break;
            case 4: printf("\tLength: %d", len); break;
            case 8: printf("\tInterval: %3d ms", interval); break;
            case 18: printf("\tPress Space to Pause");
        }
        printf("\n");
    }
}

inline void rand_food()
{
    srand(int(time(0)));
    do{
        food.x = rand() % 20 + 1;
        food.y = rand() % 20 + 1;
    }while (game_map[food.x][food.y] != '');
    game_map[food.x][food.y] = '$';
}

inline void init()
{
    int i, j;
    for (i = 1; i <= N-2; ++i)
        for (j = 1; j <= N-2; ++j)
            game_map[i][j] = ' ';
    for (i = 0; i <= N-1; ++i)
        game_map[0][i] = game_map[N-1][i] = game_map[i][0] = game_map[i][N-1] = '#';
    game_map[1][1] = game_map[1][2] = game_map[1][3] = game_map[1][4] = '@';
    game_map[1][5] = 'Q';
    head = 4; tail = 0;
    snake[head].x = 1; snake[head].y = 5;
    snake[tail].x = 1; snake[tail].y = 1;
    snake[1].x = 1; snake[1].y = 2;
    snake[2].x = 1; snake[2].y = 3;
    snake[3].x = 1; snake[3].y = 4;
    rand_food();
    lv = 0; len = 5; interval = 400;
    dir = RIGHT;

    puts("\n\n\n\n\n\n\n\n\n\n\n\t\t\t\t\t\tPress Any Key");
    getch();
    update(game_map, lv, len, interval);
}

inline int mov()
{
    bool timeover = true;
    double start = (double)clock() / CLOCKS_PER_SEC;            //get total time
    char tmp;
here:
    //wait for 1s
    while ((timeover = ((double)clock() / CLOCKS_PER_SEC - start <= interval / 1000.0)) && !_kbhit());
    if (timeover){
        char c = getch();
        if (c ==' ') {
            printf("Game Paused");
            while (getch() != '');
            system("cls");
            update(game_map, lv, len, interval);
        }
        else if ((c != UP && c != DOWN && c != LEFT && c != RIGHT) ||
            (dir == UP && c == DOWN) || (dir == DOWN && c == UP) ||
            (dir == LEFT && c == RIGHT) || (dir == RIGHT && c == LEFT))
            goto here;
        else
            dir = c;
    }
    switch (dir){
        case UP:
            next_head.x = snake[head].x - 1; next_head.y = snake[head].y;
            break;
        case DOWN:
            next_head.x = snake[head].x + 1; next_head.y = snake[head].y;
            break;
        case LEFT:
            next_head.x = snake[head].x; next_head.y = snake[head].y - 1;
            break;
        case RIGHT:
            next_head.x = snake[head].x; next_head.y = snake[head].y + 1;
            break;
    }
    if ((!next_head.x || next_head.x == N-1 || !next_head.y || next_head.y == N-1) ||                       //hit the wall
        (game_map[next_head.x][next_head.y] != '' && !(next_head.x == food.x && next_head.y == food.y))){     //hit itself
        puts("Game Over!\nReplay? y/n");
        while (tolower(tmp = getchar()) != 'y' && tolower(tmp) != 'n');
        if (tmp =='y') return 2;
        else return 0;
    }
    if (len == 100){
        puts("Congratulations!\nReplay? y/n");
        while (tolower(tmp = getchar()) != 'y' && tolower(tmp) != 'n');
        if (tmp =='y') return 2;
        else return 0;
    }
    return 1;
}

inline void eating()
{
    ++len;
    int grade = len / 5 - 1;
    if (grade != lv){
        lv = grade;
        if (interval> 50)
            interval = 400 - lv * 50;
    }
    game_map[next_head.x][next_head.y] = 'Q';                        //change head pos
    game_map[snake[head].x][snake[head].y] = '@';        //head becomes body
    head = (head + 1) % 400;
    snake[head].x = next_head.x;
    snake[head].y = next_head.y;                             //change head pos
    rand_food();
    update(game_map, lv, len, interval);
}

inline void not_eating()
{
    game_map[snake[tail].x][snake[tail].y] = '';            //tail becomes' '
    tail = (tail + 1) % 400;
    game_map[next_head.x][next_head.y] = 'Q';
    game_map[snake[head].x][snake[head].y] = '@';
    head = (head + 1) % 400;
    snake[head].x = next_head.x;
    snake[head].y = next_head.y;
    update(game_map, lv, len, interval);
}

int main()
{
    SetConsoleTitle("Snake");
    system("color 3E");
there:
    init();
    while (1)
        switch(mov()){
        case 1:
            if (next_head.x == food.x && next_head.y == food.y) eating();
            else not_eating();
            break;
        case 2: system("cls"); goto there; break;
        default: return 0;
        }
    return 0;
}
```

