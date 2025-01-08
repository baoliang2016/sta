#ifndef TCP_STREAM_H
#define TCP_STREAM_H

#include <stdint.h>
#include <time.h>

// TCP流结构定义
struct tcp_stream {
    uint32_t seq;               // 序列号
    uint32_t ack;               // 确认号
    uint8_t *data;              // 数据
    size_t data_len;            // 数据长度
    time_t timestamp;           // 时间戳
    struct tcp_stream *next;     // 链表下一个节点
};

// TCP重组上下文
struct tcp_reassembly_ctx {
    uint32_t init_seq;          // 初始序列号
    uint32_t next_seq;          // 期望的下一个序列号
    uint32_t ack;               // 当前确认号
    struct tcp_stream *streams;  // TCP流链表
    size_t data_len;            // 总数据长度
    time_t last_seen;           // 最后一次看到的时间
};

#endif // TCP_STREAM_H 