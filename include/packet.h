#ifndef PACKET_H
#define PACKET_H

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <time.h>

// 常量定义
#define MAX_PACKET_SIZE 65536
#define IP_FRAGMENT_TIMEOUT 30    // IP分片重组超时时间（秒）
#define TCP_STREAM_TIMEOUT 120    // TCP流重组超时时间（秒）
#define SNAPLEN 65535            // 抓包长度
#define PROMISC 1               // 混杂模式
#define PCAP_TIMEOUT 1000       // 抓包超时时间（毫秒）

// 数据包解析结构
struct parsed_packet {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    const u_char *payload;
    size_t payload_len;
    struct timeval timestamp;
};

// 函数声明
int init_capture(const char *interface, const char *filter_exp, pcap_t **handle);
void cleanup_capture(pcap_t *handle);
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void start_capture(pcap_t *handle, int packet_count);

#endif // PACKET_H
