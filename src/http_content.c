#include <stdio.h>
#include "http_content.h"
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <brotli/decode.h>

// 解析chunked编码数据
int parse_chunked_data(const char *input, size_t input_len,
                      char **output, size_t *output_len) {
    if (!input || !output || !output_len) return -1;

    size_t total_size = 0;
    size_t pos = 0;
    char *buffer = malloc(input_len); // 最大可能大小
    if (!buffer) return -1;

    while (pos < input_len) {
        // 读取chunk大小
        char size_str[16] = {0};
        size_t i = 0;
        while (pos < input_len && i < 15 && input[pos] != '\r' && input[pos] != '\n') {
            size_str[i++] = input[pos++];
        }
        if (pos + 1 >= input_len) break;
        
        // 跳过CRLF
        pos += 2;

        // 转换chunk大小
        size_t chunk_size;
        sscanf(size_str, "%zx", &chunk_size);
        if (chunk_size == 0) break; // 最后的chunk

        // 复制chunk数据
        if (pos + chunk_size > input_len) {
            free(buffer);
            return -1;
        }
        memcpy(buffer + total_size, input + pos, chunk_size);
        total_size += chunk_size;
        pos += chunk_size + 2; // 跳过chunk数据和CRLF
    }

    *output = buffer;
    *output_len = total_size;
    return 0;
}

// 解压gzip数据
struct decompressed_data* decompress_gzip(const char *input, size_t input_len) {
    if (!input || input_len == 0) return NULL;

    z_stream strm = {0};
    strm.next_in = (Bytef*)input;
    strm.avail_in = input_len;

    if (inflateInit2(&strm, 16+MAX_WBITS) != Z_OK) {
        return NULL;
    }

    struct decompressed_data *result = malloc(sizeof(struct decompressed_data));
    if (!result) {
        inflateEnd(&strm);
        return NULL;
    }

    size_t buffer_size = input_len * 4; // 估计解压后大小
    result->data = malloc(buffer_size);
    if (!result->data) {
        free(result);
        inflateEnd(&strm);
        return NULL;
    }

    strm.next_out = (Bytef*)result->data;
    strm.avail_out = buffer_size;

    int ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        free(result->data);
        free(result);
        inflateEnd(&strm);
        return NULL;
    }

    result->len = strm.total_out;
    inflateEnd(&strm);
    return result;
}

// 解压deflate数据
struct decompressed_data* decompress_deflate(const char *input, size_t input_len) {
    if (!input || input_len == 0) return NULL;

    z_stream strm = {0};
    strm.next_in = (Bytef*)input;
    strm.avail_in = input_len;

    if (inflateInit(&strm) != Z_OK) {
        return NULL;
    }

    struct decompressed_data *result = malloc(sizeof(struct decompressed_data));
    if (!result) {
        inflateEnd(&strm);
        return NULL;
    }

    size_t buffer_size = input_len * 4;
    result->data = malloc(buffer_size);
    if (!result->data) {
        free(result);
        inflateEnd(&strm);
        return NULL;
    }

    strm.next_out = (Bytef*)result->data;
    strm.avail_out = buffer_size;

    int ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        free(result->data);
        free(result);
        inflateEnd(&strm);
        return NULL;
    }

    result->len = strm.total_out;
    inflateEnd(&strm);
    return result;
}

// 解压br (Brotli)数据
struct decompressed_data* decompress_brotli(const char *input, size_t input_len) {
    if (!input || input_len == 0) return NULL;

    struct decompressed_data *result = malloc(sizeof(struct decompressed_data));
    if (!result) return NULL;

    size_t buffer_size = input_len * 4;
    result->data = malloc(buffer_size);
    if (!result->data) {
        free(result);
        return NULL;
    }

    size_t decoded_size = buffer_size;
    BrotliDecoderResult bret = BrotliDecoderDecompress(
        input_len, (const uint8_t*)input,
        &decoded_size, (uint8_t*)result->data);

    if (bret != BROTLI_DECODER_RESULT_SUCCESS) {
        free(result->data);
        free(result);
        return NULL;
    }

    result->len = decoded_size;
    return result;
}

void free_decompressed_data(struct decompressed_data *data) {
    if (data) {
        free(data->data);
        free(data);
    }
} 