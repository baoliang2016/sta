#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <time.h>
#include "packet.h"
#include "protocol_parser.h"

// 日志级别
typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
} log_level_t;

// 日志记录结构
struct log_entry {
    time_t timestamp;
    log_level_t level;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    const char *message;
    size_t message_len;
};

// 初始化日志系统
int init_logger(const char *log_file);

// 记录日志
void log_message(log_level_t level, const struct parsed_packet *packet,
                const char *message);

// 添加格式化日志函数
void log_message_fmt(log_level_t level, const struct parsed_packet *packet,
                    const char *format, ...);

// 记录文件传输
void log_file_transfer(const struct parsed_packet *packet,
                      const char *filename, size_t file_size);

// 关闭日志系统
void close_logger();

// 设置日志级别
void set_log_level(log_level_t level);

// 获取当前日志级别
log_level_t get_log_level();

// 添加协议日志记录函数
void log_protocol_data(const struct parsed_packet *packet,
                      const struct protocol_data *proto_data);

#endif // LOGGER_H
