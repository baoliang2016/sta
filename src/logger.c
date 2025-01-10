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

// 在文件开头添加日志目录定义
#define LOG_DIR "logs"
#define PROTOCOL_LOG_DIR "logs/protocols"

// 在文件开头添加 FTP 会话跟踪结构
struct ftp_session {
    char connection_id[256];
    time_t timestamp;
    char *command;
    char *argument;
    int response_code;
    char *response_msg;
    char *filename;
    size_t filesize;
    bool is_upload;
    FILE *log_file;
};

// 添加 FTP 会话管理
static struct ftp_session *ftp_sessions = NULL;
static size_t ftp_session_count = 0;

// 在文件开头添加 HTTP 会话跟踪结构
struct http_session {
    char connection_id[256];
    time_t timestamp;
    // 请求信息
    char *method;
    char *uri;
    char *host;
    char *request_headers;
    uint8_t *request_body;
    size_t request_body_len;
    // 响应信息
    int status_code;
    char *response_headers;
    uint8_t *response_body;
    size_t response_body_len;
    char *content_type;
    FILE *log_file;
};

// 添加 HTTP 会话管理
static struct http_session *http_sessions = NULL;
static size_t http_session_count = 0;

// 前向声明
static void log_dns_record(FILE *file, const struct dns_record *record);
static const char* get_dns_type_str(uint16_t type);
static void generate_connection_id(char *buf, size_t size, 
                                 const struct parsed_packet *packet,
                                 protocol_type_t type);
static void cleanup_http_session(struct http_session *session);
static bool is_printable_content(const uint8_t *data, size_t len);

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
    // 清理 FTP 会话
    for (size_t i = 0; i < ftp_session_count; i++) {
        if (ftp_sessions[i].log_file) {
            fclose(ftp_sessions[i].log_file);
        }
        free(ftp_sessions[i].command);
        free(ftp_sessions[i].argument);
        free(ftp_sessions[i].filename);
    }
    free(ftp_sessions);
    ftp_sessions = NULL;
    ftp_session_count = 0;

    // 清理 HTTP 会话
    for (size_t i = 0; i < http_session_count; i++) {
        if (http_sessions[i].log_file) {
            fclose(http_sessions[i].log_file);
        }
        cleanup_http_session(&http_sessions[i]);
    }
    free(http_sessions);
    http_sessions = NULL;
    http_session_count = 0;

    // 关闭主日志文件
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
    if (!packet || !proto_data) {
        return;
    }

    // 创建日志目录结构
    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/%s/%s",
             LOG_DIR, "protocols", get_protocol_name(proto_data->type));
    
    if (ensure_directory_exists(dir_path) != 0) {
        fprintf(stderr, "Failed to create directory: %s\n", dir_path);
        return;
    }

    char connection_id[256];
    char filename[512];
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
            {
                char connection_id[256];
                generate_connection_id(connection_id, sizeof(connection_id), packet, proto_data->type);
                
                // 查找或创建会话
                struct http_session *session = NULL;
                for (size_t i = 0; i < http_session_count; i++) {
                    if (strcmp(http_sessions[i].connection_id, connection_id) == 0) {
                        session = &http_sessions[i];
                        break;
                    }
                }
                
                if (!session) {
                    // 创建新会话
                    http_sessions = realloc(http_sessions, (http_session_count + 1) * sizeof(struct http_session));
                    if (!http_sessions) {
                        fprintf(stderr, "Failed to allocate memory for HTTP session\n");
                        return;
                    }
                    session = &http_sessions[http_session_count++];
                    memset(session, 0, sizeof(struct http_session));
                    strncpy(session->connection_id, connection_id, sizeof(session->connection_id) - 1);
                    
                    // 创建会话日志文件
                    char log_path[512];
                    snprintf(log_path, sizeof(log_path), "%s/http_%s.log", dir_path, connection_id);
                    session->log_file = fopen(log_path, "a");
                    if (!session->log_file) {
                        fprintf(stderr, "Failed to open HTTP log file: %s\n", log_path);
                        return;
                    }
                }
                
                if (proto_data->is_request) {
                    // 保存请求信息
                    session->timestamp = time(NULL);
                    if (proto_data->http.method) {
                        free(session->method);
                        session->method = strdup(proto_data->http.method);
                    }
                    if (proto_data->http.uri) {
                        free(session->uri);
                        session->uri = strdup(proto_data->http.uri);
                    }
                    if (proto_data->http.host) {
                        free(session->host);
                        session->host = strdup(proto_data->http.host);
                    }
                    if (proto_data->request) {
                        free(session->request_headers);
                        session->request_headers = strdup(proto_data->request);
                    }
                    if (proto_data->http.raw_content) {
                        free(session->request_body);
                        session->request_body = malloc(proto_data->http.raw_content_len);
                        if (session->request_body) {
                            memcpy(session->request_body, proto_data->http.raw_content, 
                                   proto_data->http.raw_content_len);
                            session->request_body_len = proto_data->http.raw_content_len;
                        }
                    }
                    
                    // 记录请求部分
                    fprintf(session->log_file, "\n=== HTTP Transaction at %s", ctime(&session->timestamp));
                    fprintf(session->log_file, "Source IP: %s\n", inet_ntoa(*(struct in_addr*)&packet->src_ip));
                    fprintf(session->log_file, "Source Port: %u\n", packet->src_port);
                    fprintf(session->log_file, "Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&packet->dst_ip));
                    fprintf(session->log_file, "Destination Port: %u\n", packet->dst_port);
                    fprintf(session->log_file, "\n--- Request ---\n");
                    fprintf(session->log_file, "Method: %s\n", session->method ? session->method : "Unknown");
                    fprintf(session->log_file, "URI: %s\n", session->uri ? session->uri : "Unknown");
                    fprintf(session->log_file, "Host: %s\n", session->host ? session->host : "Unknown");
                    fprintf(session->log_file, "\nRequest Headers:\n%s\n", 
                            session->request_headers ? session->request_headers : "None");
                    
                    if (session->request_body && session->request_body_len > 0) {
                        fprintf(session->log_file, "\nRequest Body (%zu bytes):\n", session->request_body_len);
                        // 如果是文本内容，直接打印
                        if (is_printable_content(session->request_body, session->request_body_len)) {
                            fprintf(session->log_file, "%.*s\n", (int)session->request_body_len, 
                                    (char*)session->request_body);
                        } else {
                            fprintf(session->log_file, "[Binary content]\n");
                        }
                    }
                    
                    fflush(session->log_file);
                } else {
                    // 保存响应信息
                    session->status_code = proto_data->http.http_status;
                    if (proto_data->response) {
                        free(session->response_headers);
                        session->response_headers = strdup(proto_data->response);
                    }
                    if (proto_data->http.content_type) {
                        free(session->content_type);
                        session->content_type = strdup(proto_data->http.content_type);
                    }
                    if (proto_data->http.decoded_content) {
                        free(session->response_body);
                        session->response_body = malloc(proto_data->http.decoded_content_len);
                        if (session->response_body) {
                            memcpy(session->response_body, proto_data->http.decoded_content,
                                   proto_data->http.decoded_content_len);
                            session->response_body_len = proto_data->http.decoded_content_len;
                        }
                    }
                    
                    // 记录响应部分
                    fprintf(session->log_file, "\n--- Response ---\n");
                    fprintf(session->log_file, "Status Code: %d\n", session->status_code);
                    fprintf(session->log_file, "Content-Type: %s\n", 
                            session->content_type ? session->content_type : "Unknown");
                    fprintf(session->log_file, "\nResponse Headers:\n%s\n",
                            session->response_headers ? session->response_headers : "None");
                    
                    if (session->response_body && session->response_body_len > 0) {
                        fprintf(session->log_file, "\nResponse Body (%zu bytes):\n", 
                                session->response_body_len);
                        if (session->content_type && 
                            (strstr(session->content_type, "text/") || 
                             strstr(session->content_type, "application/json"))) {
                            fprintf(session->log_file, "%.*s\n", (int)session->response_body_len,
                                    (char*)session->response_body);
                        } else {
                            fprintf(session->log_file, "[Binary content]\n");
                        }
                    }
                    
                    fprintf(session->log_file, "\nConnection ID: %s\n", session->connection_id);
                    fprintf(session->log_file, "=== End of Transaction ===\n\n");
                    fflush(session->log_file);
                    
                    // 清理会话数据
                    cleanup_http_session(session);
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
        case PROTO_FTP:
            {
                char connection_id[256];
                generate_connection_id(connection_id, sizeof(connection_id), packet, proto_data->type);
                
                // 查找或创建会话
                struct ftp_session *session = NULL;
                for (size_t i = 0; i < ftp_session_count; i++) {
                    if (strcmp(ftp_sessions[i].connection_id, connection_id) == 0) {
                        session = &ftp_sessions[i];
                        break;
                    }
                }
                
                if (!session) {
                    // 创建新会话
                    ftp_sessions = realloc(ftp_sessions, (ftp_session_count + 1) * sizeof(struct ftp_session));
                    if (!ftp_sessions) {
                        fprintf(stderr, "Failed to allocate memory for FTP session\n");
                        return;
                    }
                    session = &ftp_sessions[ftp_session_count++];
                    memset(session, 0, sizeof(struct ftp_session));
                    strncpy(session->connection_id, connection_id, sizeof(session->connection_id) - 1);
                    
                    // 创建会话日志文件
                    char log_path[512];
                    snprintf(log_path, sizeof(log_path), "%s/ftp_%s.log", dir_path, connection_id);
                    session->log_file = fopen(log_path, "a");
                    if (!session->log_file) {
                        fprintf(stderr, "Failed to open FTP log file: %s\n", log_path);
                        return;
                    }
                }
                
                if (proto_data->is_request) {
                    // 保存请求信息
                    session->timestamp = time(NULL);  // 使用当前时间而不是proto_data中的时间
                    if (proto_data->ftp.command) {
                        free(session->command);  // 释放旧的命令（如果有）
                        session->command = strdup(proto_data->ftp.command);
                    }
                    if (proto_data->ftp.argument) {
                        free(session->argument);  // 释放旧的参数（如果有）
                        session->argument = strdup(proto_data->ftp.argument);
                    }
                    session->is_upload = proto_data->ftp.is_upload;
                    if (proto_data->ftp.filename) {
                        free(session->filename);  // 释放旧的文件名（如果有）
                        session->filename = strdup(proto_data->ftp.filename);
                    }
                    
                    // 增强的请求日志格式
                    fprintf(session->log_file, "\n=== FTP Request at %s", ctime(&session->timestamp));
                    fprintf(session->log_file, "Source IP: %s\n", inet_ntoa(*(struct in_addr*)&packet->src_ip));
                    fprintf(session->log_file, "Source Port: %u\n", packet->src_port);
                    fprintf(session->log_file, "Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&packet->dst_ip));
                    fprintf(session->log_file, "Destination Port: %u\n", packet->dst_port);
                    fprintf(session->log_file, "Command: %s\n", session->command ? session->command : "Unknown");
                    if (session->argument) {
                        fprintf(session->log_file, "Argument: %s\n", session->argument);
                    }
                    if (session->filename) {
                        fprintf(session->log_file, "File: %s\n", session->filename);
                        fprintf(session->log_file, "Operation: %s\n", session->is_upload ? "Upload" : "Download");
                    }
                    fprintf(session->log_file, "Connection ID: %s\n", session->connection_id);
                    fprintf(session->log_file, "\n");
                    fflush(session->log_file);
                } else {
                    // 记录响应信息
                    fprintf(session->log_file, "=== FTP Response at %s", ctime(&session->timestamp));
                    fprintf(session->log_file, "Source IP: %s\n", inet_ntoa(*(struct in_addr*)&packet->src_ip));
                    fprintf(session->log_file, "Source Port: %u\n", packet->src_port);
                    fprintf(session->log_file, "Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&packet->dst_ip));
                    fprintf(session->log_file, "Destination Port: %u\n", packet->dst_port);
                    fprintf(session->log_file, "Response Code: %d\n", proto_data->ftp.response_code);
                    if (proto_data->ftp.response_msg) {
                        fprintf(session->log_file, "Response Message: %s\n", proto_data->ftp.response_msg);
                    }
                    
                    if (session->filename) {
                        fprintf(session->log_file, "File: %s\n", session->filename);
                        fprintf(session->log_file, "Operation: %s\n", 
                                session->is_upload ? "Upload" : "Download");
                    }
                    
                    if (proto_data->ftp.filesize > 0) {
                        fprintf(session->log_file, "Size: %zu bytes\n", proto_data->ftp.filesize);
                    }
                    fprintf(session->log_file, "Connection ID: %s\n", session->connection_id);
                    fprintf(session->log_file, "\n");
                    fflush(session->log_file);
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

// 清理 HTTP 会话数据
void cleanup_http_session(struct http_session *session) {
    if (!session) return;
    
    free(session->method);
    free(session->uri);
    free(session->host);
    free(session->request_headers);
    free(session->request_body);
    free(session->response_headers);
    free(session->response_body);
    free(session->content_type);
    
    memset(session, 0, sizeof(struct http_session));
}

// 添加 is_printable_content 函数的实现
static bool is_printable_content(const uint8_t *data, size_t len) {
    if (!data || len == 0) return false;
    
    // 检查前1024字节或整个内容（取较小值）
    size_t check_len = (len > 1024) ? 1024 : len;
    size_t printable_count = 0;
    
    for (size_t i = 0; i < check_len; i++) {
        if (isprint(data[i]) || isspace(data[i])) {
            printable_count++;
        }
    }
    
    // 如果90%以上的字符是可打印的，认为是文本内容
    return (printable_count * 100 / check_len) >= 90;
}
