#ifndef IP_REASSEMBLY_H
#define IP_REASSEMBLY_H

#include <stdint.h>
#include <time.h>

// IP分片结构
struct ip_fragment {
    uint16_t id;           // IP标识
    uint16_t offset;       // 分片偏移
    uint16_t length;       // 分片长度
    time_t timestamp;      // 时间戳
    uint8_t *data;         // 分片数据
    struct ip_fragment *next;  // 链表下一个节点
};

// IP分片重组上下文
struct ip_reassembly_ctx {
    struct ip_fragment *fragments;  // 分片链表
    uint16_t expected_len;         // 期望的总长度
    uint16_t received_len;         // 已接收的长度
    time_t last_update;           // 最后更新时间
};

// 函数声明
struct ip_fragment* create_fragment(uint16_t id, uint16_t offset, uint16_t length, 
                                  const uint8_t *data, time_t timestamp);
void free_fragments(struct ip_fragment *fragments);
int add_ip_fragment(struct ip_reassembly_ctx *ctx, const struct ip_fragment *fragment);
uint8_t* get_reassembled_packet(struct ip_reassembly_ctx *ctx, uint16_t *total_len);
void cleanup_expired_fragments(struct ip_reassembly_ctx *ctx, time_t timeout);

#endif // IP_REASSEMBLY_H
