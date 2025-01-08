#include "file_extractor.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

static struct file_extractor_ctx *current_ctx = NULL;

// 修改ELF魔数的定义
static const uint8_t ELF_MAGIC[] = {0x7F, 'E', 'L', 'F'};

// 检测文件类型
static const char *detect_file_type(const uint8_t *data, size_t len) {
    if (len < 4) return NULL;

    // 使用数组比较而不是字符串
    if (memcmp(data, ELF_MAGIC, 4) == 0) return "elf";
    if (memcmp(data, "\x89PNG", 4) == 0) return "png";
    if (memcmp(data, "\xFF\xD8\xFF", 3) == 0) return "jpg";
    if (memcmp(data, "GIF8", 4) == 0) return "gif";
    if (memcmp(data, "%PDF", 4) == 0) return "pdf";
    if (memcmp(data, "PK\x03\x04", 4) == 0) return "zip";
    if (memcmp(data, "MZ", 2) == 0) return "exe";

    // 检测文本文件
    int is_text = 1;
    for (size_t i = 0; i < len && i < 256; i++) {
        if (!isprint(data[i]) && !isspace(data[i])) {
            is_text = 0;
            break;
        }
    }
    if (is_text) return "txt";

    return "unknown";
}

int init_file_extractor() {
    if (current_ctx) {
        free(current_ctx);
    }

    current_ctx = malloc(sizeof(struct file_extractor_ctx));
    if (!current_ctx) {
        return -1;
    }

    memset(current_ctx, 0, sizeof(*current_ctx));
    current_ctx->status = FILE_EXTRACT_INIT;
    current_ctx->start_time = time(NULL);
    current_ctx->last_update = current_ctx->start_time;

    return 0;
}

int process_file_data(const struct parsed_packet *packet) {
    if (!current_ctx || !packet || !packet->payload || packet->payload_len == 0) {
        return -1;
    }

    // 初始化上下文
    if (current_ctx->status == FILE_EXTRACT_INIT) {
        current_ctx->src_ip = packet->src_ip;
        current_ctx->dst_ip = packet->dst_ip;
        current_ctx->src_port = packet->src_port;
        current_ctx->dst_port = packet->dst_port;
        current_ctx->protocol = packet->protocol;

        // 检测文件类型
        const char *file_type = detect_file_type(packet->payload, packet->payload_len);
        char filename[256];
        time_t now = time(NULL);
        snprintf(filename, sizeof(filename), "file_%ld.%s", now, file_type);
        current_ctx->filename = strdup(filename);
    }

    // 分配内存
    size_t new_size = current_ctx->received_size + packet->payload_len;
    uint8_t *new_data = realloc(current_ctx->file_data, new_size);
    if (!new_data) {
        return -1;
    }

    // 追加数据
    memcpy(new_data + current_ctx->received_size, packet->payload, packet->payload_len);
    current_ctx->file_data = new_data;
    current_ctx->file_size = new_size;
    current_ctx->received_size = new_size;
    current_ctx->last_update = time(NULL);
    current_ctx->status = FILE_EXTRACT_IN_PROGRESS;

    return 0;
}

int save_extracted_file(const struct file_extractor_ctx *ctx) {
    if (!ctx || !ctx->filename || !ctx->file_data || ctx->file_size == 0) {
        return -1;
    }

    char path[512];
    snprintf(path, sizeof(path), "extracted_files/%s", ctx->filename);

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }

    fwrite(ctx->file_data, 1, ctx->file_size, fp);
    fclose(fp);

    return 0;
}

void cleanup_file_extractor() {
    if (current_ctx) {
        if (current_ctx->filename) {
            free(current_ctx->filename);
        }
        if (current_ctx->file_data) {
            free(current_ctx->file_data);
        }
        free(current_ctx);
        current_ctx = NULL;
    }
}

file_extract_status_t get_extract_status(const struct file_extractor_ctx *ctx) {
    if (!ctx) return FILE_EXTRACT_ERROR;
    return ctx->status;
}

const struct file_extractor_ctx *get_extracted_file_info() {
    return current_ctx;
}
