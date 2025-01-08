#include "logger.h"
#include "packet.h"
#include "protocol_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <ctype.h>

// 前向声明
static void log_dns_record(FILE *file, const struct dns_record *record);
static const char* get_dns_type_str(uint16_t type);
static void generate_connection_id(char *buf, size_t size, 
                                 const struct parsed_packet *packet,
                                 protocol_type_t type);

static FILE *log_file = NULL;
static log_level_t current_log_level = LOG_LEVEL_INFO;

// 获取日志级别的字符串表示
static const char* get_log_level_str(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_DEBUG:   return "DEBUG";
        case LOG_LEVEL_INFO:    return "INFO";
        case LOG_LEVEL_WARNING: return "WARN";
        case LOG_LEVEL_ERROR:   return "ERROR";
        case LOG_LEVEL_CRITICAL: return "CRITICAL";
        default:               return "UNKNOWN";
    }
}

int init_logger(const char *log_file_path) {
    if (!log_file_path) {
        fprintf(stderr, "Invalid log file path\n");
        return -1;
    }

    log_file = fopen(log_file_path, "a");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file: %s\n", log_file_path);
        return -1;
    }

    // 设置缓冲区为行缓冲
    setvbuf(log_file, NULL, _IOLBF, 0);
    return 0;
}

void log_message(log_level_t level, const struct parsed_packet *packet,
                const char *message) {
    if (!log_file || level < current_log_level || !message) {
        return;
    }

    time_t now;
    struct tm *timeinfo;
    char timestamp[64];

    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S]", timeinfo);

    // 安全检查
    if (!packet) {
        fprintf(log_file, "%s [%s] %s\n",
                timestamp, get_log_level_str(level), message);
        return;
    }

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // 转换IP地址
    if (!inet_ntop(AF_INET, &packet->src_ip, src_ip, sizeof(src_ip))) {
        strcpy(src_ip, "unknown");
    }
    if (!inet_ntop(AF_INET, &packet->dst_ip, dst_ip, sizeof(dst_ip))) {
        strcpy(dst_ip, "unknown");
    }

    fprintf(log_file, "%s [%s] %s:%u -> %s:%u [%s] %s\n",
            timestamp,
            get_log_level_str(level),
            src_ip,
            packet->src_port,
            dst_ip,
            packet->dst_port,
            packet->protocol == IPPROTO_TCP ? "TCP" :
            packet->protocol == IPPROTO_UDP ? "UDP" : "OTHER",
            message);

    fflush(log_file);
}

void log_file_transfer(const struct parsed_packet *packet,
                      const char *filename, size_t file_size) {
    if (!log_file || !packet || !filename) {
        return;
    }

    time_t now;
    struct tm *timeinfo;
    char timestamp[64];

    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S]", timeinfo);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // 转换IP地址
    if (!inet_ntop(AF_INET, &packet->src_ip, src_ip, sizeof(src_ip))) {
        strcpy(src_ip, "unknown");
    }
    if (!inet_ntop(AF_INET, &packet->dst_ip, dst_ip, sizeof(dst_ip))) {
        strcpy(dst_ip, "unknown");
    }

    fprintf(log_file, "%s [INFO] File transfer detected: %s -> %s, File: %s, Size: %zu bytes\n",
            timestamp, src_ip, dst_ip, filename, file_size);

    fflush(log_file);
}

void close_logger() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

void set_log_level(log_level_t level) {
    if (level >= LOG_LEVEL_DEBUG && level <= LOG_LEVEL_CRITICAL) {
        current_log_level = level;
    }
}

log_level_t get_log_level() {
    return current_log_level;
}

// 添加一个辅助函数来创建目录
static int ensure_directory_exists(const char *path) {
    char tmp[512];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                printf("DEBUG: Failed to create directory %s: %s\n", 
                       tmp, strerror(errno));
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        printf("DEBUG: Failed to create directory %s: %s\n", 
               tmp, strerror(errno));
        return -1;
    }
    return 0;
}

// 生成连接ID的辅助函数
static void generate_connection_id(char *buf, size_t size, 
                                 const struct parsed_packet *packet,
                                 protocol_type_t type) {
    snprintf(buf, size, "%s_%u_%u_%u_%u",
             get_protocol_name(type),
             packet->src_ip,
             packet->dst_ip,
             packet->src_port,
             packet->dst_port);
}

// 在log_protocol_data函数中添加DNS日志记录
static void log_dns_record(FILE *file, const struct dns_record *record) {
    if (!record) return;

    fprintf(file, "Name: %s\n", record->name);
    fprintf(file, "Type: %d", record->type);
    switch (record->type) {
        case DNS_TYPE_A:
            fprintf(file, " (A)\n");
            fprintf(file, "Address: %s\n", 
                    inet_ntoa(*(struct in_addr*)&record->rdata.a.address));
            break;
        case DNS_TYPE_NS:
            fprintf(file, " (NS)\n");
            fprintf(file, "Name Server: %s\n", record->rdata.ns.nsdname);
            break;
        case DNS_TYPE_CNAME:
            fprintf(file, " (CNAME)\n");
            fprintf(file, "Canonical Name: %s\n", record->rdata.cname.cname);
            break;
        case DNS_TYPE_SOA:
            fprintf(file, " (SOA)\n");
            fprintf(file, "Master Name: %s\n", record->rdata.soa.mname);
            fprintf(file, "Responsible: %s\n", record->rdata.soa.rname);
            fprintf(file, "Serial: %u\n", record->rdata.soa.serial);
            fprintf(file, "Refresh: %u\n", record->rdata.soa.refresh);
            fprintf(file, "Retry: %u\n", record->rdata.soa.retry);
            fprintf(file, "Expire: %u\n", record->rdata.soa.expire);
            fprintf(file, "Minimum TTL: %u\n", record->rdata.soa.minimum);
            break;
        case DNS_TYPE_PTR:
            fprintf(file, " (PTR)\n");
            fprintf(file, "Domain Name: %s\n", record->rdata.ptr.ptrdname);
            break;
        case DNS_TYPE_MX:
            fprintf(file, " (MX)\n");
            fprintf(file, "Preference: %u\n", record->rdata.mx.preference);
            fprintf(file, "Mail Exchange: %s\n", record->rdata.mx.exchange);
            break;
        case DNS_TYPE_TXT:
            fprintf(file, " (TXT)\n");
            fprintf(file, "Text: %s\n", record->rdata.txt.txt_data);
            break;
        case DNS_TYPE_AAAA:
            fprintf(file, " (AAAA)\n");
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &record->rdata.aaaa.address, 
                     addr_str, sizeof(addr_str));
            fprintf(file, "IPv6 Address: %s\n", addr_str);
            break;
        case DNS_TYPE_SRV:
            fprintf(file, " (SRV)\n");
            fprintf(file, "Priority: %u\n", record->rdata.srv.priority);
            fprintf(file, "Weight: %u\n", record->rdata.srv.weight);
            fprintf(file, "Port: %u\n", record->rdata.srv.port);
            fprintf(file, "Target: %s\n", record->rdata.srv.target);
            break;
        default:
            fprintf(file, " (Unknown)\n");
    }
    fprintf(file, "Class: %d\n", record->class);
    fprintf(file, "TTL: %u\n", record->ttl);
    fprintf(file, "\n");
}

void log_protocol_data(const struct parsed_packet *packet,
                      const struct protocol_data *proto_data) {
    printf("DEBUG: Starting protocol data logging\n");
    
    if (!log_file || !packet || !proto_data) {
        printf("DEBUG: Invalid parameters for protocol logging\n");
        return;
    }

    char connection_id[256];
    char filename[512];
    char dir_path[256];
    FILE *proto_file;
    char timestamp[32];

    // 获取时间戳
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    // 生成连接标识符
    generate_connection_id(connection_id, sizeof(connection_id), 
                         packet, proto_data->type);

    // 创建目录结构
    snprintf(dir_path, sizeof(dir_path), "logs/protocols/%s", 
             get_protocol_name(proto_data->type));
    
    printf("DEBUG: Creating directory structure: %s\n", dir_path);
    if (ensure_directory_exists(dir_path) != 0) {
        printf("DEBUG: Failed to create directory structure\n");
        return;
    }

    // 使用连接标识符创建文件名
    snprintf(filename, sizeof(filename), "%s/%s.log",
             dir_path, connection_id);

    printf("DEBUG: Opening protocol file: %s\n", filename);
    proto_file = fopen(filename, "a");
    if (!proto_file) {
        printf("DEBUG: Failed to open protocol file: %s\n", strerror(errno));
        return;
    }

    // 写入时间戳和分隔符
    fprintf(proto_file, "\n=== %s ===\n", timestamp);

    // 根据协议类型写入详细信息
    switch (proto_data->type) {
        case PROTO_HTTP:
            printf("DEBUG: Processing HTTP protocol data\n");
            if (proto_data->is_request) {
                printf("DEBUG: HTTP Request - Method: %s, URI: %s, Host: %s\n",
                       proto_data->http.method ? proto_data->http.method : "NULL",
                       proto_data->http.uri ? proto_data->http.uri : "NULL",
                       proto_data->http.host ? proto_data->http.host : "NULL");
                
                fprintf(proto_file, "--- HTTP Request ---\n");
                fprintf(proto_file, "From: %s:%u\n", 
                        inet_ntoa(*(struct in_addr*)&packet->src_ip), 
                        packet->src_port);
                if (proto_data->http.method)
                    fprintf(proto_file, "Method: %s\n", proto_data->http.method);
                if (proto_data->http.uri)
                    fprintf(proto_file, "URI: %s\n", proto_data->http.uri);
                if (proto_data->http.host)
                    fprintf(proto_file, "Host: %s\n", proto_data->http.host);
                if (proto_data->request)
                    fprintf(proto_file, "\nRequest Headers:\n%s\n", proto_data->request);
            } else {
                printf("DEBUG: HTTP Response - Status: %d, Content-Type: %s\n",
                       proto_data->http.http_status,
                       proto_data->http.content_type ? proto_data->http.content_type : "NULL");
                
                fprintf(proto_file, "--- HTTP Response ---\n");
                fprintf(proto_file, "From: %s:%u\n", 
                        inet_ntoa(*(struct in_addr*)&packet->src_ip), 
                        packet->src_port);
                fprintf(proto_file, "Status: %d\n", proto_data->http.http_status);
                if (proto_data->http.content_type)
                    fprintf(proto_file, "Content-Type: %s\n", proto_data->http.content_type);
                if (proto_data->http.content_encoding)
                    fprintf(proto_file, "Content-Encoding: %s\n", proto_data->http.content_encoding);
                if (proto_data->http.transfer_encoding)
                    fprintf(proto_file, "Transfer-Encoding: %s\n", proto_data->http.transfer_encoding);
                
                fprintf(proto_file, "\nResponse Headers:\n%s\n", proto_data->response);
                
                // 记录解码后的内容
                if (proto_data->http.decoded_content) {
                    fprintf(proto_file, "\nDecoded Content (%zu bytes):\n", 
                            proto_data->http.decoded_content_len);
                    // 对于文本内容，直接写入；对于二进制内容，可以使用base64编码
                    if (proto_data->http.content_type && 
                        strstr(proto_data->http.content_type, "text/")) {
                        fprintf(proto_file, "%.*s\n", 
                                (int)proto_data->http.decoded_content_len,
                                proto_data->http.decoded_content);
                    } else {
                        fprintf(proto_file, "[Binary content not shown]\n");
                    }
                } else if (proto_data->http.raw_content) {
                    fprintf(proto_file, "\nRaw Content (%zu bytes):\n", 
                            proto_data->http.raw_content_len);
                    if (proto_data->http.content_type && 
                        strstr(proto_data->http.content_type, "text/")) {
                        fprintf(proto_file, "%.*s\n", 
                                (int)proto_data->http.raw_content_len,
                                proto_data->http.raw_content);
                    } else {
                        fprintf(proto_file, "[Binary content not shown]\n");
                    }
                }
            }
            break;
        case PROTO_DNS:
            {
                fprintf(proto_file, "\n=== DNS %s ===\n", 
                        proto_data->dns.is_response ? "Response" : "Query");
                fprintf(proto_file, "Transaction ID: 0x%04x\n", proto_data->dns.query_id);
                fprintf(proto_file, "Flags: 0x%04x\n", proto_data->dns.flags);

                // 记录查询信息
                if (proto_data->dns.questions && proto_data->dns.qdcount > 0) {
                    fprintf(proto_file, "\n--- Queries (%d) ---\n", proto_data->dns.qdcount);
                    for (uint16_t i = 0; i < proto_data->dns.qdcount; i++) {
                        if (proto_data->dns.questions[i].qname) {
                            fprintf(proto_file, "Query #%d:\n", i + 1);
                            fprintf(proto_file, "  Domain: %s\n", proto_data->dns.questions[i].qname);
                            const char *type_str = get_dns_type_str(proto_data->dns.questions[i].qtype);
                            fprintf(proto_file, "  Type: %d (%s)\n", 
                                    proto_data->dns.questions[i].qtype,
                                    type_str);
                            fprintf(proto_file, "  Class: %d (%s)\n", 
                                    proto_data->dns.questions[i].qclass,
                                    proto_data->dns.questions[i].qclass == 1 ? "IN" : "Unknown");
                        }
                    }
                }

                // 如果是响应，记录回答部分
                if (proto_data->dns.is_response) {
                    if (proto_data->dns.answers) {
                        fprintf(proto_file, "\n=== Answers ===\n");
                        for (const struct dns_record *rec = proto_data->dns.answers; rec; rec = rec->next) {
                            log_dns_record(proto_file, rec);
                        }
                    }
                    
                    if (proto_data->dns.authorities) {
                        fprintf(proto_file, "\n=== Authority Records ===\n");
                        for (const struct dns_record *rec = proto_data->dns.authorities; rec; rec = rec->next) {
                            log_dns_record(proto_file, rec);
                        }
                    }
                    
                    if (proto_data->dns.additionals) {
                        fprintf(proto_file, "\n=== Additional Records ===\n");
                        for (const struct dns_record *rec = proto_data->dns.additionals; rec; rec = rec->next) {
                            log_dns_record(proto_file, rec);
                        }
                    }
                }
            }
            break;
        // TODO: 添加其他协议的日志记录格式
        default:
            printf("DEBUG: Processing unknown protocol type: %d\n", proto_data->type);
            if (proto_data->is_request) {
                fprintf(proto_file, "\n=== Request Data ===\n%s\n", proto_data->request);
            } else {
                fprintf(proto_file, "\n=== Response Data ===\n%s\n", proto_data->response);
            }
    }

    fprintf(proto_file, "\n");
    fflush(proto_file);
    fclose(proto_file);
}

void log_message_fmt(log_level_t level, const struct parsed_packet *packet,
                    const char *format, ...) {
    if (!log_file || level < current_log_level) {
        return;
    }

    char message[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    log_message(level, packet, message);
}

// DNS类型转字符串函数的实现
static const char* get_dns_type_str(uint16_t type) {
    switch (type) {
        case 1:  return "A";
        case 2:  return "NS";
        case 5:  return "CNAME";
        case 6:  return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 255: return "ANY";
        default: return "Unknown";
    }
}
