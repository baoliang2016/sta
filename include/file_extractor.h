#ifndef FILE_EXTRACTOR_H
#define FILE_EXTRACTOR_H

#include "packet.h"
#include <stdbool.h>

// 文件提取状态
typedef enum {
    FILE_EXTRACT_INIT,
    FILE_EXTRACT_IN_PROGRESS,
    FILE_EXTRACT_COMPLETE,
    FILE_EXTRACT_ERROR
} file_extract_status_t;

// 文件提取上下文
struct file_extractor_ctx {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    char *filename;
    uint8_t *file_data;
    size_t file_size;
    size_t received_size;
    file_extract_status_t status;
    time_t start_time;
    time_t last_update;
};

// 初始化文件提取器
int init_file_extractor();

// 处理数据包中的文件数据
int process_file_data(const struct parsed_packet *packet);

// 保存提取的文件
int save_extracted_file(const struct file_extractor_ctx *ctx);

// 清理文件提取器
void cleanup_file_extractor();

// 获取当前提取状态
file_extract_status_t get_extract_status(const struct file_extractor_ctx *ctx);

// 获取提取的文件信息
const struct file_extractor_ctx *get_extracted_file_info();

#endif // FILE_EXTRACTOR_H
