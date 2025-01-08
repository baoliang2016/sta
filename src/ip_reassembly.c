#include "ip_reassembly.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#define IP_FRAGMENT_TIMEOUT 30  // 30秒超时

// 释放分片链表
void free_fragments(struct ip_fragment *fragments) {
    while (fragments) {
        struct ip_fragment *next = fragments->next;
        free(fragments->data);
        free(fragments);
        fragments = next;
    }
}

// 创建IP分片
struct ip_fragment* create_fragment(uint16_t id, uint16_t offset, uint16_t length, 
                                  const uint8_t *data, time_t timestamp) {
    struct ip_fragment *fragment = malloc(sizeof(struct ip_fragment));
    if (!fragment) {
        return NULL;
    }

    fragment->id = id;
    fragment->offset = offset;
    fragment->length = length;
    fragment->timestamp = timestamp;
    fragment->next = NULL;

    fragment->data = malloc(length);
    if (!fragment->data) {
        free(fragment);
        return NULL;
    }

    memcpy(fragment->data, data, length);
    return fragment;
}

// 添加IP分片
int add_ip_fragment(struct ip_reassembly_ctx *ctx, const struct ip_fragment *fragment) {
    if (!ctx || !fragment) {
        return -1;
    }

    // 创建新的分片节点
    struct ip_fragment *new_frag = create_fragment(fragment->id, fragment->offset,
                                                  fragment->length, fragment->data,
                                                  fragment->timestamp);
    if (!new_frag) {
        return -1;
    }

    // 插入到合适位置
    struct ip_fragment **pp = &ctx->fragments;
    while (*pp && (*pp)->offset < new_frag->offset) {
        pp = &(*pp)->next;
    }
    new_frag->next = *pp;
    *pp = new_frag;

    // 更新接收长度和时间戳
    ctx->received_len += new_frag->length;
    ctx->last_update = time(NULL);

    return 0;
}

// 获取重组后的数据包
uint8_t* get_reassembled_packet(struct ip_reassembly_ctx *ctx, uint16_t *total_len) {
    if (!ctx || !ctx->fragments || !total_len) {
        return NULL;
    }

    // 计算总长度
    size_t total_size = 0;
    struct ip_fragment *frag = ctx->fragments;
    while (frag) {
        total_size += frag->length;
        frag = frag->next;
    }

    // 分配内存
    uint8_t *buffer = malloc(total_size);
    if (!buffer) {
        return NULL;
    }

    // 复制数据
    size_t offset = 0;
    frag = ctx->fragments;
    while (frag) {
        memcpy(buffer + offset, frag->data, frag->length);
        offset += frag->length;
        frag = frag->next;
    }

    *total_len = (uint16_t)total_size;
    return buffer;
}

// 清理过期分片
void cleanup_expired_fragments(struct ip_reassembly_ctx *ctx, time_t timeout) {
    if (!ctx) {
        return;
    }

    time_t current_time = time(NULL);
    if (current_time - ctx->last_update > timeout) {
        free_fragments(ctx->fragments);
        ctx->fragments = NULL;
        ctx->received_len = 0;
        ctx->expected_len = 0;
        ctx->last_update = current_time;
    }
}
