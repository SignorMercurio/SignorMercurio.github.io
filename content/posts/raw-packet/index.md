---
title: 算无遗策：socket 编程发送 RAW 数据包
date: 2020-11-16
tags:
  - C/C++
  - 网络
categories:
  - 安全工具
---

实习的时候写的一小段代码。

<!--more-->

要求是用 C/C++ 写发送 RAW 数据包的工具，需要支持 TCP 和 UDP。查了下资料发现比想象的要复杂，并且只发现了发送 ICMP RAW 数据包的样例，照着改了改。

## 大致需求

- 数据包以 RAW 方式发送
- 支持 TCP 和 UDP 协议
- 发送地址由使用者指定
- 源地址随机
- 发送消息内容随机

## 一些固定的部分

头文件 `raw.h` 中存在一个固定的结构体和固定的函数：

```cpp
extern int errno;

#pragma pack(1)
typedef struct PACKET_RAW_HEADER {
    uint32_t dwIP;
    uint16_t uPort;

    PACKET_RAW_HEADER() : dwIP(0), uPort(0) {}
} PacketRawHeader, * pPacketRawHeader;
#pragma pack()

int sendrawpacket(PacketRawHeader* pRawHeader, bool bTCP);
```

之后的修改都必须基于这二者进行。

因此可以根据这些固定的部分先把主函数写好：

```cpp
#include "raw.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s [ip] [port] [tcp|udp]\n", argv[0]);
        exit(-1);
    }
    PacketRawHeader *pPacketRawHeader = new PacketRawHeader();
    pPacketRawHeader->dwIP = inet_addr(argv[1]);
    pPacketRawHeader->uPort = htons(atoi(argv[2]));
    bool bTCP = true;
    if (!strcmp(argv[3], "udp")) {
        bTCP = false;
    }
    printf("%s\n", strerror(sendrawpacket(pPacketRawHeader, bTCP)));

    return 0;
}
```

随后在主要需要修改的 `sendrawpacket` 函数中处理中断，关闭 `socket`：

```cpp
int sockfd;

int sendrawpacket(PacketRawHeader* pRawHeader, bool bTCP)
{
    signal (SIGINT, interrupt_handler);
    signal (SIGTERM, interrupt_handler);
}

void interrupt_handler (int signum) {
    close(sockfd);
    free(clientaddr);
    exit(0);
}
```

## 主要逻辑

### 创建 socket

```cpp
int sendrawpacket(PacketRawHeader* pRawHeader, bool bTCP)
{
    //...
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) <0) {
        fprintf(stderr,"Error creating socket:%s\n", strerror(errno));
        return errno;
    }
    //...
}
```

根据要求，需要采用 `SOCK_RAW` + `IPPROTO_RAW` 的方式创建 `socket`。此时必须自己填充 IP 头部 以及 TCP/UDP 头部。

### 设置地址

设置目标地址，该地址由命令行参数指定：

```cpp
struct sockaddr_in* clientaddr = NULL;

int sendrawpacket(PacketRawHeader* pRawHeader, bool bTCP)
{
    //...
    clientaddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    if (clientaddr == NULL) {
        fprintf(stderr,"Error allocating memory:%s\n", strerror(errno));
        goto end;
    }

    clientaddr->sin_family = AF_INET;
    clientaddr->sin_port = pRawHeader->uPort;
    clientaddr->sin_addr.s_addr = pRawHeader->dwIP;
    //...
end:
    close(sockfd);
    return errno;
}
```

而源地址则由程序随机生成：

```cpp
int sendrawpacket(PacketRawHeader* pRawHeader, bool bTCP)
{
    char buffer[BUF_LEN] = {0};
    char src_ip[20] = {0};
    uint16_t src_port;
    char *string_data = NULL;
    size_t hdr_size = (bTCP ? (THDR_SZ) : (UHDR_SZ));
    //...
    srand(time(NULL));
    string_data = (char *) (buffer + IPHDR_SZ + hdr_size);
    for (int i = 0; i < MSG_LEN; ++i) {
        string_data[i] = '0' + rand()%72;
    }
    string_data[MSG_LEN] = 0;
    printf("Message: %s\n", string_data);

    sprintf(src_ip,"%d.%d.%d.%d", rand()%256, rand()%256, rand()%256, rand()%256);
    src_port = rand()%65535 + 1;
    printf("Source IP: %s\nSource Port: %d\n", src_ip, src_port);
    //...
}
```

其中定义的宏如下：

```cpp
#define BUF_LEN 1024
#define MSG_LEN 50
#define IPHDR_SZ sizeof(struct iphdr)
#define THDR_SZ sizeof(struct tcphdr)
#define UHDR_SZ sizeof(struct udphdr)
```

这里用 `buffer` 存放完整的报文，`string_data` 存放消息，报文结构实际上是：

```
 ------------------------------------------
| IP Header | TCP/UDP Header | string_data |
 ------------------------------------------
 \                                         /
  ---------------- buffer -----------------
```

### 填充 IP 头部

```cpp
int sendrawpacket(PacketRawHeader* pRawHeader, bool bTCP)
{
    // ...
    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    //...
    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = IPHDR_SZ + hdr_size + strlen(string_data);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = (bTCP ? IPPROTO_TCP : IPPROTO_UDP);
    ip_hdr->saddr = inet_addr(src_ip);
    ip_hdr->daddr = clientaddr->sin_addr.s_addr;
    ip_hdr->check = csum((unsigned short *)ip_hdr, ip_hdr->tot_len);
    //...
}
```

这里需要对 IP 头部计算校验和，计算方法和之后 TCP / UDP 头部校验和计算方法相同，每 16 bit 进行反码求和：

```cpp
unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes> 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum>>16) + (sum & 0xffff);
    sum = sum + (sum>>16);
    answer = (short)~sum;

    return (answer);
}
```

### 填充 TCP / UDP 头部

```cpp
int sendrawpacket(PacketRawHeader* pRawHeader, bool bTCP)
{
    // ...
    struct tcphdr *tcp_hdr = (struct tcphdr *)(buffer + IPHDR_SZ);
    struct udphdr *udp_hdr = (struct udphdr *)(buffer + IPHDR_SZ);
    //...
    if (bTCP) {
        tcp_hdr->source = htons(src_port);
        tcp_hdr->dest = clientaddr->sin_port;
        tcp_hdr->doff = 5;
        tcp_hdr->window = htons(200);
        tcp_hdr->syn = 1;
    } else {
        udp_hdr->source = htons(src_port);
        udp_hdr->dest = clientaddr->sin_port;
        udp_hdr->len = htons(8 + strlen(string_data));
    }
    //...
}
```

这里协议头部中使用了一些常用的参数值，使用 TCP 协议时发送 SYN 包。

### 填充 TCP / UDP 伪头部

先定义伪头部结构体：

```cpp
struct pseudo_iphdr {
    uint32_t source_ip_addr;
    uint32_t dest_ip_addr;
    uint8_t fixed;
    uint8_t protocol;
    uint16_t len;
};

#define PHDR_SZ sizeof(struct pseudo_iphdr)
```

随后填充伪头部：

```cpp
int sendrawpacket(PacketRawHeader* pRawHeader, bool bTCP)
{
    // ...
    struct pseudo_iphdr csum_hdr;
    //...
    csum_hdr.source_ip_addr = ip_hdr->saddr;
    csum_hdr.dest_ip_addr = clientaddr->sin_addr.s_addr;
    csum_hdr.fixed = 0;
    csum_hdr.protocol = (bTCP ? IPPROTO_TCP : IPPROTO_UDP);
    csum_hdr.len = htons(hdr_size + strlen(string_data));
    //...
}
```

### 计算 TCP / UDP 校验和

填充好伪头部后，便可以计算校验和了。首先将需要校验的部分放进 `csum_buffer` 中，也就是伪头部 + 头部 + 数据。随后用 `csum` 函数计算校验和并填入相应字段：

```cpp
int sendrawpacket(PacketRawHeader* pRawHeader, bool bTCP)
{
    // ...
    char *csum_buffer = NULL;
    size_t psize;
    //...
    psize = PHDR_SZ + hdr_size + strlen(string_data);
    csum_buffer = (char *)calloc(psize, sizeof(char));
    if (csum_buffer == NULL) {
        fprintf(stderr,"Error allocating memory:%s\n", strerror(errno));
        goto end1;
    }

    memcpy(csum_buffer, (char *)&csum_hdr, PHDR_SZ);
    memcpy(csum_buffer + PHDR_SZ, udp_hdr, hdr_size + strlen(string_data));

    if (bTCP) {
        tcp_hdr->check = csum((unsigned short *) csum_buffer, psize);
    } else {
        udp_hdr->check = csum((unsigned short *) csum_buffer, psize);
    }

    free (csum_buffer);
    csum_buffer = NULL;
    //...
end1:
    free(clientaddr);
    clientaddr = NULL;
end:
    close(sockfd);
    return errno;
}
```

此时报文大概是这样：

```
 ----------------------------------------------------
| ... | Pseudo Header | TCP/UDP Header | string_data |
 ----------------------------------------------------
 \                   /
  ---- IP Header ----
 \                                                   /
  ---------------------- buffer ---------------------
```

### 发送数据包

直接使用 `sendto` 指定地址为 `clientaddr` 即可。

```cpp
int sendrawpacket(PacketRawHeader* pRawHeader, bool bTCP)
{
    //...
    if (sendto(sockfd, buffer, ip_hdr->tot_len, 0, (struct sockaddr *)clientaddr, sizeof(struct sockaddr_in)) <0) {
        fprintf(stderr,"Error sending message:%s\n", strerror(errno));
        goto end1;
    }
end1:
    free(clientaddr);
    clientaddr = NULL;
end:
    close(sockfd);
    return errno;
}
```

最后，可以使用 wireshark 进行测试，并打开校验和验证功能。
