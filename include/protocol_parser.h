#ifndef PROTOCOL_PARSER_H
#define PROTOCOL_PARSER_H

#include "packet.h"
#include <stdint.h>
#include <stdbool.h>

// 协议类型枚举
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_HTTP,
    PROTO_FTP,
    PROTO_DNS,
    PROTO_SMTP,
    PROTO_POP3,
    PROTO_ICMP,
    PROTO_HTTPS,
    PROTO_SSH,
    PROTO_TELNET
} protocol_type_t;

// 在protocol_data结构之前添加DNS相关结构定义
struct dns_question {
    char *qname;            // 查询名称
    uint16_t qtype;         // 查询类型
    uint16_t qclass;        // 查询类
};

struct dns_header {
    uint16_t query_id;          // DNS查询ID
    uint16_t flags;             // 标志字段
    bool is_response;           // 是否是响应
    bool is_authoritative;      // 是否是权威应答
    bool is_truncated;          // 是否被截断
    bool recursion_desired;     // 期望递归
    bool recursion_available;   // 递归可用
    uint8_t rcode;             // 响应码
    uint16_t qdcount;          // 问题数
    uint16_t ancount;          // 回答数
    uint16_t nscount;          // 授权数
    uint16_t arcount;          // 附加数
    struct dns_question *questions;  // 问题部分
    struct dns_record *answers;      // 回答部分
    struct dns_record *authorities;  // 授权部分
    struct dns_record *additionals;  // 附加部分
};

// 协议数据结构
struct protocol_data {
    protocol_type_t type;
    bool is_request;
    union {
        struct {
            char *method;
            char *uri;
            char *host;
            int http_status;
            char *content_type;
            char *content_encoding;
            char *transfer_encoding;
            size_t content_length;
            uint8_t *raw_content;
            size_t raw_content_len;
            uint8_t *decoded_content;
            size_t decoded_content_len;
        } http;
        struct {
            uint16_t query_id;
            uint16_t flags;
            uint16_t qdcount;
            uint16_t ancount;
            uint16_t nscount;
            uint16_t arcount;
            bool is_response;
            bool is_authoritative;
            bool is_truncated;
            bool recursion_desired;
            bool recursion_available;
            uint8_t rcode;
            struct dns_question *questions;
            struct dns_record *answers;
            struct dns_record *authorities;
            struct dns_record *additionals;
        } dns;
    };
    char *request;
    char *response;
};

// DNS相关定义
#define DNS_TYPE_A      1   // IPv4地址
#define DNS_TYPE_NS     2   // 域名服务器
#define DNS_TYPE_CNAME  5   // 规范名称
#define DNS_TYPE_SOA    6   // 权威记录开始
#define DNS_TYPE_PTR    12  // 指针记录
#define DNS_TYPE_MX     15  // 邮件交换
#define DNS_TYPE_TXT    16  // 文本记录
#define DNS_TYPE_AAAA   28  // IPv6地址
#define DNS_TYPE_SRV    33  // 服务定位
#define DNS_TYPE_ANY    255 // 任意类型

// DNS记录结构
struct dns_record {
    char *name;              // 域名
    uint16_t type;          // 记录类型
    uint16_t class;         // 类别(通常是IN)
    uint32_t ttl;           // 生存时间
    uint16_t rdlength;      // 资源数据长度
    union {
        struct {
            uint32_t address;    // IPv4地址
        } a;
        struct {
            char *nsdname;       // 域名服务器名称
        } ns;
        struct {
            char *cname;         // 规范名称
        } cname;
        struct {
            char *mname;         // 主域名服务器
            char *rname;         // 管理员邮箱
            uint32_t serial;     // 序列号
            uint32_t refresh;    // 刷新间隔
            uint32_t retry;      // 重试间隔
            uint32_t expire;     // 过期时间
            uint32_t minimum;    // 最小TTL
        } soa;
        struct {
            char *ptrdname;      // 指针域名
        } ptr;
        struct {
            uint16_t preference; // 优先级
            char *exchange;      // 邮件服务器
        } mx;
        struct {
            char *txt_data;      // 文本数据
        } txt;
        struct {
            struct in6_addr address; // IPv6地址
        } aaaa;
        struct {
            uint16_t priority;   // 优先级
            uint16_t weight;     // 权重
            uint16_t port;       // 端口
            char *target;        // 目标主机
        } srv;
    } rdata;
    struct dns_record *next;     // 链表下一个节点
};

// 函数声明
protocol_type_t identify_protocol(const struct parsed_packet *packet, const uint8_t *payload, size_t payload_len);
struct protocol_data* parse_protocol_data(protocol_type_t proto_type, const uint8_t *payload, size_t payload_len, bool is_request);
void free_protocol_data(struct protocol_data *data);
const char* get_protocol_name(protocol_type_t type);

#endif // PROTOCOL_PARSER_H 