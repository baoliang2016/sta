#include "tcp_reassembly.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include "packet.h"

// 创建新的TCP段
struct tcp_stream* create_segment(uint32_t seq, uint32_t ack,
                                const uint8_t *data, size_t data_len,
                                time_t timestamp) {
    struct tcp_stream *segment = malloc(sizeof(struct tcp_stream));
    if (!segment) {
        return NULL;
    }

    segment->seq = seq;
    segment->ack = ack;
    segment->timestamp = timestamp;
    segment->next = NULL;
    
    // 分配并复制数据
    segment->data = malloc(data_len);
    if (!segment->data) {
        free(segment);
        return NULL;
    }
    
    memcpy(segment->data, data, data_len);
    segment->data_len = data_len;
    
    return segment;
}

// 释放TCP流链表
void free_streams(struct tcp_stream *streams) {
    while (streams) {
        struct tcp_stream *next = streams->next;
        free(streams->data);
        free(streams);
        streams = next;
    }
}

// 添加新的TCP段到重组上下文
int add_tcp_segment(struct tcp_reassembly_ctx *ctx, const struct tcp_stream *segment) {
    if (!ctx || !segment) {
        return -1;
    }

    // 创建新段的副本
    struct tcp_stream *new_seg = create_segment(segment->seq, segment->ack,
                                              segment->data, segment->data_len,
                                              segment->timestamp);
    if (!new_seg) {
        return -1;
    }

    // 更新上下文状态
    ctx->last_seen = time(NULL);

    // 按序列号排序插入
    struct tcp_stream **pp = &ctx->streams;
    while (*pp && (*pp)->seq < new_seg->seq) {
        pp = &(*pp)->next;
    }
    new_seg->next = *pp;
    *pp = new_seg;

    // 更新数据长度
    ctx->data_len += new_seg->data_len;

    // 检查是否可以更新next_seq
    if (ctx->next_seq == new_seg->seq) {
        ctx->next_seq = new_seg->seq + new_seg->data_len;
    }

    return 0;
}

// 获取重组后的数据
int get_reassembled_data(const struct tcp_reassembly_ctx *ctx,
                        uint8_t *buffer, size_t buffer_size) {
    if (!ctx || !buffer || !ctx->streams || buffer_size < ctx->data_len) {
        return -1;
    }

    size_t total_copied = 0;
    struct tcp_stream *stream = ctx->streams;
    uint32_t expected_seq = ctx->init_seq;

    while (stream && total_copied < buffer_size) {
        // 检查序列号是否连续
        if (stream->seq != expected_seq) {
            break;
        }

        // 复制数据
        size_t remaining = buffer_size - total_copied;
        size_t to_copy = (stream->data_len < remaining) ? stream->data_len : remaining;
        
        memcpy(buffer + total_copied, stream->data, to_copy);
        total_copied += to_copy;
        expected_seq = stream->seq + stream->data_len;
        
        stream = stream->next;
    }

    return total_copied;
}

// 初始化TCP重组上下文
void init_tcp_reassembly(struct tcp_reassembly_ctx *ctx) {
    if (!ctx) return;
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->streams = NULL;
    ctx->init_seq = 0;
    ctx->next_seq = 0;
    ctx->ack = 0;
    ctx->data_len = 0;
    ctx->last_seen = time(NULL);
}

// 检查TCP重组是否完成
bool is_tcp_reassembly_complete(const struct tcp_reassembly_ctx *ctx) {
    if (!ctx || !ctx->streams) {
        return false;
    }
    
    // 检查是否所有数据都是连续的
    struct tcp_stream *stream = ctx->streams;
    uint32_t expected_seq = ctx->init_seq;
    
    while (stream) {
        if (stream->seq != expected_seq) {
            return false;
        }
        expected_seq = stream->seq + stream->data_len;
        stream = stream->next;
    }
    
    return true;
}

// 清理TCP重组上下文
void cleanup_tcp_reassembly(struct tcp_reassembly_ctx *ctx) {
    if (!ctx) return;
    
    free_streams(ctx->streams);
    ctx->streams = NULL;
    ctx->data_len = 0;
    ctx->init_seq = 0;
    ctx->next_seq = 0;
    ctx->ack = 0;
    ctx->last_seen = 0;
}

// 处理超时的TCP流
void handle_timeout_streams(struct tcp_reassembly_ctx *ctx,
                          time_t current_time) {
    if (!ctx) return;
    
    if (current_time - ctx->last_seen > TCP_STREAM_TIMEOUT) {
        cleanup_tcp_reassembly(ctx);
    }
}
