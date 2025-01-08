#ifndef HTTP_CONTENT_H
#define HTTP_CONTENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// 解压缩结果结构
struct decompressed_data {
    char *data;
    size_t len;
};

// 解析chunked编码数据
int parse_chunked_data(const char *input, size_t input_len,
                      char **output, size_t *output_len);

// 解压gzip数据
struct decompressed_data* decompress_gzip(const char *input, size_t input_len);

// 解压deflate数据
struct decompressed_data* decompress_deflate(const char *input, size_t input_len);

// 解压br (Brotli)数据
struct decompressed_data* decompress_brotli(const char *input, size_t input_len);

// 释放解压缩数据
void free_decompressed_data(struct decompressed_data *data);

#endif // HTTP_CONTENT_H 