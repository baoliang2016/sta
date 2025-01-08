#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H

#include "tcp_stream.h"

// TCP重组相关函数声明
struct tcp_stream* create_segment(uint32_t seq, uint32_t ack, 
                                const uint8_t *data, size_t data_len, 
                                time_t timestamp);
void free_streams(struct tcp_stream *streams);
int add_tcp_segment(struct tcp_reassembly_ctx *ctx, const struct tcp_stream *segment);
int get_reassembled_data(const struct tcp_reassembly_ctx *ctx,
                        uint8_t *buffer, size_t buffer_size);

#endif // TCP_REASSEMBLY_H
