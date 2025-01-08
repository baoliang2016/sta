#include "protocol_parser.h"
#include "http_content.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <strings.h>

// 静态函数声明
static bool is_valid_dns_packet(const uint8_t *payload, size_t payload_len,
                              uint16_t src_port, uint16_t dst_port);
static char* dns_decompress_name(const uint8_t *data, size_t len, size_t *offset);
static struct dns_record* parse_dns_record(const uint8_t *data, size_t len, size_t *offset);
static void parse_dns_data(struct protocol_data *data, const uint8_t *payload, size_t payload_len);

// 常用端口定义
#define PORT_HTTP 80
#define PORT_HTTPS 443
#define PORT_FTP 21
#define PORT_DNS 53
#define PORT_SMTP 25
#define PORT_POP3 110
#define PORT_SSH 22
#define PORT_TELNET 23

// 在文件开头添加DNS相关的常量定义
#define DNS_QR_MASK    0x8000  // 查询/响应标志掩码
#define DNS_OPCODE_MASK 0x7800 // 操作码掩码
#define DNS_TC_MASK    0x0200  // 截断标志掩码
#define DNS_RD_MASK    0x0100  // 期望递归标志掩码
#define DNS_RA_MASK    0x0080  // 递归可用标志掩码
#define DNS_RCODE_MASK 0x000F  // 响应码掩码
#define DNS_HEADER_SIZE 12
#define DNS_MAX_LABEL_LEN 63
#define DNS_MAX_NAME_LEN 255
#define DNS_TYPE_SIZE 2
#define DNS_CLASS_SIZE 2

// 识别协议类型
protocol_type_t identify_protocol(const struct parsed_packet *packet, const uint8_t *payload, size_t payload_len) {
    if (!packet || !payload || payload_len == 0) {
        return PROTO_UNKNOWN;
    }

    printf("DEBUG: Protocol identification - SrcPort: %u, DstPort: %u, Payload length: %zu\n", 
           packet->src_port, packet->dst_port, payload_len);

    // DNS协议识别
    if (packet->src_port == PORT_DNS || packet->dst_port == PORT_DNS) {
        if (is_valid_dns_packet(payload, payload_len, packet->src_port, packet->dst_port)) {
            return PROTO_DNS;
        }
    }

    // HTTP协议识别
    if (payload_len > 4) {
        if (strncmp((char*)payload, "GET ", 4) == 0 ||
            strncmp((char*)payload, "POST ", 5) == 0 ||
            strncmp((char*)payload, "HEAD ", 5) == 0 ||
            strncmp((char*)payload, "HTTP/", 5) == 0) {
            return PROTO_HTTP;
        }
    }

    // FTP协议识别
    if (packet->dst_port == PORT_FTP || 
        (payload_len > 4 && (strncmp((char*)payload, "USER ", 5) == 0 ||
                            strncmp((char*)payload, "PASS ", 5) == 0 ||
                            strncmp((char*)payload, "LIST", 4) == 0))) {
        return PROTO_FTP;
    }

    // 其他协议识别
    switch (packet->dst_port) {
        case PORT_SMTP: return PROTO_SMTP;
        case PORT_POP3: return PROTO_POP3;
        case PORT_SSH: return PROTO_SSH;
        case PORT_TELNET: return PROTO_TELNET;
    }

    printf("DEBUG: Protocol not identified\n");
    return PROTO_UNKNOWN;
}

// DNS协议识别
static bool is_valid_dns_packet(const uint8_t *payload, size_t payload_len, 
                              uint16_t src_port, uint16_t dst_port) {
    (void)src_port;
    (void)dst_port;

    // 确保有足够的数据长度（UDP头部8字节 + DNS头部12字节）
    if (payload_len < 8 + DNS_HEADER_SIZE) {
        printf("DEBUG: Packet too short for DNS header\n");
        return false;
    }

    // 打印原始数据用于调试
    printf("DEBUG: DNS header raw bytes: ");
    for (int i = 0; i < DNS_HEADER_SIZE; i++) {
        printf("%02x ", payload[8 + i]);  // 从UDP负载后开始打印
    }
    printf("\n");

    // DNS头部字段解析（注意字节序）
    // 跳过UDP头部8字节
    const uint8_t *dns_header = payload + 8;
    uint16_t id = (dns_header[0] << 8) | dns_header[1];        // Transaction ID
    uint16_t flags = (dns_header[2] << 8) | dns_header[3];     // Flags
    uint16_t qdcount = (dns_header[4] << 8) | dns_header[5];   // Questions
    uint16_t ancount = (dns_header[6] << 8) | dns_header[7];   // Answer RRs
    uint16_t nscount = (dns_header[8] << 8) | dns_header[9];   // Authority RRs
    uint16_t arcount = (dns_header[10] << 8) | dns_header[11]; // Additional RRs

    bool is_response = (flags & DNS_QR_MASK) != 0;
    uint16_t opcode = (flags & DNS_OPCODE_MASK) >> 11;

    printf("DEBUG: DNS packet analysis:\n");
    printf("  Transaction ID: 0x%04x\n", id);
    printf("  Flags: 0x%04x\n", flags);
    printf("  QR: %d (%s)\n", is_response, is_response ? "Response" : "Query");
    printf("  Opcode: %d\n", opcode);
    printf("  Questions: %d\n", qdcount);
    printf("  Answer RRs: %d\n", ancount);
    printf("  Authority RRs: %d\n", nscount);
    printf("  Additional RRs: %d\n", arcount);

    // 验证DNS查询包的基本格式
    if (!is_response) {  // 如果是查询包
        if (qdcount != 1 || ancount != 0 || nscount != 0 || arcount != 0) {
            printf("DEBUG: Invalid DNS query format\n");
            return false;
        }
    }

    // 解析查询部分
    size_t pos = DNS_HEADER_SIZE;  // 从DNS头部后开始解析
    
    // 解析域名部分
    while (pos < payload_len) {
        uint8_t len = payload[pos];
        
        // 域名结束
        if (len == 0) {
            pos++;
            // 检查是否有足够空间存放类型和类
            if (pos + 4 > payload_len) {
                printf("DEBUG: Incomplete DNS query\n");
                return false;
            }
            
            uint16_t qtype = (payload[pos] << 8) | payload[pos + 1];
            uint16_t qclass = (payload[pos + 2] << 8) | payload[pos + 3];
            
            printf("DEBUG: Query type: %u, class: %u\n", qtype, qclass);
            return true;
        }

        // 检查压缩指针
        if ((len & 0xC0) == 0xC0) {
            pos += 2;  // 跳过压缩指针
            if (pos + 4 <= payload_len) {
                uint16_t qtype = (payload[pos] << 8) | payload[pos + 1];
                uint16_t qclass = (payload[pos + 2] << 8) | payload[pos + 3];
                printf("DEBUG: Compressed query - type: %u, class: %u\n", qtype, qclass);
                return true;
            }
            break;
        }

        // 检查标签长度
        if (len > DNS_MAX_LABEL_LEN) {
            printf("DEBUG: Invalid label length: %u\n", len);
            return false;
        }

        pos += len + 1;
        if (pos >= payload_len) {
            printf("DEBUG: Truncated domain name\n");
            return false;
        }
    }

    return false;
}

// DNS名称解压缩函数
static char* dns_decompress_name(const uint8_t *data, size_t len, size_t *offset) {
    if (!data || !offset || *offset >= len) {
        printf("DEBUG: Invalid parameters in dns_decompress_name\n");
        return NULL;
    }

    char name[DNS_MAX_NAME_LEN + 1] = {0};
    size_t name_len = 0;
    size_t pos = *offset;
    bool jumped = false;
    size_t jump_count = 0;
    const size_t max_jumps = 10;  // 防止无限循环

    printf("DEBUG: Starting domain name parsing at offset %zu\n", pos);

    while (pos < len) {
        uint8_t label_len = data[pos];
        printf("DEBUG: Label length at pos %zu: %u\n", pos, label_len);

        // 检查压缩指针
        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= len) {
                printf("DEBUG: Compression pointer truncated\n");
                return NULL;
            }
            if (jump_count++ >= max_jumps) {
                printf("DEBUG: Too many compression jumps\n");
                return NULL;
            }

            size_t new_offset = ((label_len & 0x3F) << 8) | data[pos + 1];
            printf("DEBUG: Found compression pointer to offset %zu\n", new_offset);
            
            if (new_offset >= len) {
                printf("DEBUG: Invalid compression pointer offset\n");
                return NULL;
            }

            if (!jumped) {
                *offset = pos + 2;
                jumped = true;
            }
            pos = new_offset;
            continue;
        }

        // 处理普通标签
        if (label_len == 0) {
            if (!jumped) {
                *offset = pos + 1;
            }
            break;
        }

        // 检查标签长度
        if (label_len > DNS_MAX_LABEL_LEN) {
            printf("DEBUG: Label too long: %u\n", label_len);
            return NULL;
        }
        if (pos + 1 + label_len > len) {
            printf("DEBUG: Label extends beyond packet end\n");
            return NULL;
        }
        if (name_len + label_len + 1 > DNS_MAX_NAME_LEN) {
            printf("DEBUG: Domain name too long\n");
            return NULL;
        }

        // 添加点分隔符
        if (name_len > 0) {
            name[name_len++] = '.';
        }

        // 复制标签内容并打印调试信息
        printf("DEBUG: Copying label: ");
        for (size_t i = 0; i < label_len; i++) {
            char c = data[pos + 1 + i];
            printf("%c", isprint(c) ? c : '.');
            name[name_len++] = c;
        }
        printf("\n");

        pos += label_len + 1;
    }

    name[name_len] = '\0';
    printf("DEBUG: Completed domain name: %s\n", name);
    return strdup(name);
}

// 解析DNS记录
static struct dns_record* parse_dns_record(const uint8_t *data, size_t len, size_t *offset) {
    struct dns_record *record = calloc(1, sizeof(struct dns_record));
    if (!record) return NULL;

    // 解析名称
    record->name = dns_decompress_name(data, len, offset);
    if (!record->name || *offset + 10 > len) {
        free(record);
        return NULL;
    }

    // 解析固定字段
    record->type = ntohs(*(uint16_t*)(data + *offset));
    *offset += 2;
    record->class = ntohs(*(uint16_t*)(data + *offset));
    *offset += 2;
    record->ttl = ntohl(*(uint32_t*)(data + *offset));
    *offset += 4;
    record->rdlength = ntohs(*(uint16_t*)(data + *offset));
    *offset += 2;

    if (*offset + record->rdlength > len) {
        free(record->name);
        free(record);
        return NULL;
    }

    // 解析资源数据
    switch (record->type) {
        case DNS_TYPE_A:
            if (record->rdlength == 4) {
                memcpy(&record->rdata.a.address, data + *offset, 4);
            }
            break;
            
        case DNS_TYPE_NS:
            record->rdata.ns.nsdname = dns_decompress_name(data, len, offset);
            break;
            
        case DNS_TYPE_CNAME:
            record->rdata.cname.cname = dns_decompress_name(data, len, offset);
            break;
            
        case DNS_TYPE_SOA:
            {
                size_t pos = *offset;
                record->rdata.soa.mname = dns_decompress_name(data, len, &pos);
                record->rdata.soa.rname = dns_decompress_name(data, len, &pos);
                if (pos + 20 <= len) {
                    record->rdata.soa.serial = ntohl(*(uint32_t*)(data + pos));
                    record->rdata.soa.refresh = ntohl(*(uint32_t*)(data + pos + 4));
                    record->rdata.soa.retry = ntohl(*(uint32_t*)(data + pos + 8));
                    record->rdata.soa.expire = ntohl(*(uint32_t*)(data + pos + 12));
                    record->rdata.soa.minimum = ntohl(*(uint32_t*)(data + pos + 16));
                }
            }
            break;
            
        case DNS_TYPE_PTR:
            record->rdata.ptr.ptrdname = dns_decompress_name(data, len, offset);
            break;
            
        case DNS_TYPE_MX:
            if (record->rdlength >= 2) {
                record->rdata.mx.preference = ntohs(*(uint16_t*)(data + *offset));
                *offset += 2;
                record->rdata.mx.exchange = dns_decompress_name(data, len, offset);
            }
            break;
            
        case DNS_TYPE_TXT:
            if (record->rdlength > 0) {
                uint8_t txt_len = data[*offset];
                if (txt_len < record->rdlength) {
                    record->rdata.txt.txt_data = malloc(txt_len + 1);
                    if (record->rdata.txt.txt_data) {
                        memcpy(record->rdata.txt.txt_data, data + *offset + 1, txt_len);
                        record->rdata.txt.txt_data[txt_len] = '\0';
                    }
                }
            }
            break;
            
        case DNS_TYPE_AAAA:
            if (record->rdlength == 16) {
                memcpy(&record->rdata.aaaa.address, data + *offset, 16);
            }
            break;
            
        case DNS_TYPE_SRV:
            if (record->rdlength >= 6) {
                record->rdata.srv.priority = ntohs(*(uint16_t*)(data + *offset));
                record->rdata.srv.weight = ntohs(*(uint16_t*)(data + *offset + 2));
                record->rdata.srv.port = ntohs(*(uint16_t*)(data + *offset + 4));
                *offset += 6;
                record->rdata.srv.target = dns_decompress_name(data, len, offset);
            }
            break;
    }

    *offset += record->rdlength;
    return record;
}

// 解析DNS数据
static void parse_dns_data(struct protocol_data *data, const uint8_t *payload, size_t payload_len) {
    if (!data || !payload || payload_len < 8 + DNS_HEADER_SIZE) {
        printf("DEBUG: Invalid DNS data\n");
        return;
    }

    // 从UDP负载后开始解析DNS头部（跳过8字节UDP头部）
    const uint8_t *dns_header = payload + 8;
    data->dns.query_id = (dns_header[0] << 8) | dns_header[1];
    data->dns.flags = (dns_header[2] << 8) | dns_header[3];
    data->dns.qdcount = (dns_header[4] << 8) | dns_header[5];
    data->dns.ancount = (dns_header[6] << 8) | dns_header[7];
    data->dns.nscount = (dns_header[8] << 8) | dns_header[9];
    data->dns.arcount = (dns_header[10] << 8) | dns_header[11];

    data->dns.is_response = (data->dns.flags & DNS_QR_MASK) != 0;
    data->dns.is_authoritative = (data->dns.flags & 0x0400) != 0;
    data->dns.is_truncated = (data->dns.flags & 0x0200) != 0;
    data->dns.recursion_desired = (data->dns.flags & 0x0100) != 0;
    data->dns.recursion_available = (data->dns.flags & 0x0080) != 0;
    data->dns.rcode = data->dns.flags & 0x000F;

    printf("DEBUG: Parsing DNS data - QCount: %d\n", data->dns.qdcount);

    // 初始化指针为NULL
    data->dns.questions = NULL;
    data->dns.answers = NULL;
    data->dns.authorities = NULL;
    data->dns.additionals = NULL;

    size_t offset = DNS_HEADER_SIZE;

    // 解析问题部分
    if (data->dns.qdcount > 0) {
        size_t offset = DNS_HEADER_SIZE;  // 从DNS头部之后开始
        
        data->dns.questions = calloc(data->dns.qdcount, sizeof(struct dns_question));
        if (!data->dns.questions) {
            printf("DEBUG: Failed to allocate memory for DNS questions\n");
            return;
        }

        printf("DEBUG: Starting to parse %d questions at offset %zu\n", data->dns.qdcount, offset);

        // 解析每个问题
        for (uint16_t i = 0; i < data->dns.qdcount && offset < payload_len - 8; i++) {
            // 解析域名（注意跳过UDP头部）
            char *name = dns_decompress_name(payload + 8, payload_len - 8, &offset);
            if (name) {
                data->dns.questions[i].qname = name;
                printf("DEBUG: Successfully parsed domain name: %s\n", name);

                // 确保有足够的空间读取类型和类
                if (offset + 4 <= payload_len - 8) {
                    data->dns.questions[i].qtype = (payload[offset + 8] << 8) | payload[offset + 9];
                    data->dns.questions[i].qclass = (payload[offset + 10] << 8) | payload[offset + 11];
                    offset += 4;

                    printf("DEBUG: Question %d - Name: %s, Type: %d, Class: %d\n", 
                           i + 1, name, data->dns.questions[i].qtype, data->dns.questions[i].qclass);
                } else {
                    printf("DEBUG: Not enough data for type and class\n");
                }
            } else {
                printf("DEBUG: Failed to parse domain name at offset %zu\n", offset);
                break;
            }
        }
    }

    // 解析回答部分
    struct dns_record **current = &data->dns.answers;
    for (uint16_t i = 0; i < data->dns.ancount && offset < payload_len; i++) {
        *current = parse_dns_record(payload, payload_len, &offset);
        if (*current) current = &(*current)->next;
    }

    // 解析授权部分
    current = &data->dns.authorities;
    for (uint16_t i = 0; i < data->dns.nscount && offset < payload_len; i++) {
        *current = parse_dns_record(payload, payload_len, &offset);
        if (*current) current = &(*current)->next;
    }

    // 解析附加部分
    current = &data->dns.additionals;
    for (uint16_t i = 0; i < data->dns.arcount && offset < payload_len; i++) {
        *current = parse_dns_record(payload, payload_len, &offset);
        if (*current) current = &(*current)->next;
    }
}

// HTTP数据解析函数
static void parse_http_data(struct protocol_data *data, const uint8_t *payload, size_t payload_len) {
    if (!data || !payload || payload_len == 0) {
        printf("DEBUG: Invalid HTTP data\n");
        return;
    }

    // 为HTTP头部分配内存并复制数据
    char *headers = malloc(payload_len + 1);
    if (!headers) {
        printf("DEBUG: Failed to allocate memory for HTTP headers\n");
        return;
    }

    memcpy(headers, payload, payload_len);
    headers[payload_len] = '\0';

    printf("DEBUG: Parsing HTTP data, length: %zu\n", payload_len);

    // 解析第一行（请求行或状态行）
    char *line = strtok(headers, "\r\n");
    if (!line) {
        printf("DEBUG: Failed to parse first line\n");
        free(headers);
        return;
    }

    if (data->is_request) {
        // 解析HTTP请求
        char *method = strtok(line, " ");
        char *uri = strtok(NULL, " ");
        char *version = strtok(NULL, " ");

        if (method) data->http.method = strdup(method);
        if (uri) data->http.uri = strdup(uri);

        printf("DEBUG: HTTP Request - Method: %s, URI: %s, Version: %s\n",
               method ? method : "NULL",
               uri ? uri : "NULL",
               version ? version : "NULL");
    } else {
        // 解析HTTP响应
        char *version = strtok(line, " ");
        char *status = strtok(NULL, " ");

        if (status) {
            data->http.http_status = atoi(status);
        }

        printf("DEBUG: HTTP Response - Version: %s, Status: %d\n",
               version ? version : "NULL",
               data->http.http_status);
    }

    // 解析头部字段
    while ((line = strtok(NULL, "\r\n")) != NULL) {
        if (strlen(line) == 0) break; // 头部结束

        char *key = line;
        char *value = strchr(line, ':');
        if (!value) continue;

        *value++ = '\0';
        while (*value == ' ') value++;

        if (strcasecmp(key, "Content-Type") == 0) {
            data->http.content_type = strdup(value);
        } else if (strcasecmp(key, "Content-Length") == 0) {
            data->http.content_length = atoi(value);
        } else if (strcasecmp(key, "Host") == 0) {
            data->http.host = strdup(value);
        } else if (strcasecmp(key, "Content-Encoding") == 0) {
            data->http.content_encoding = strdup(value);
        } else if (strcasecmp(key, "Transfer-Encoding") == 0) {
            data->http.transfer_encoding = strdup(value);
        }
    }

    // 查找消息体
    char *body = strstr(headers, "\r\n\r\n");
    if (body) {
        body += 4;
        size_t body_len = payload_len - (body - headers);
        if (body_len > 0) {
            // 保存原始内容
            data->http.raw_content = malloc(body_len);
            if (data->http.raw_content) {
                memcpy(data->http.raw_content, body, body_len);
                data->http.raw_content_len = body_len;
            }

            // 处理编码的内容
            if (data->http.content_encoding) {
                if (strcasecmp(data->http.content_encoding, "gzip") == 0) {
                    struct decompressed_data *dec = decompress_gzip(body, body_len);
                    if (dec) {
                        data->http.decoded_content = (uint8_t *)dec->data;
                        data->http.decoded_content_len = dec->len;
                        free(dec);
                    }
                } else if (strcasecmp(data->http.content_encoding, "deflate") == 0) {
                    struct decompressed_data *dec = decompress_deflate(body, body_len);
                    if (dec) {
                        data->http.decoded_content = (uint8_t *)dec->data;
                        data->http.decoded_content_len = dec->len;
                        free(dec);
                    }
                }
            }
        }
    }

    free(headers);
}

// 解析协议数据
struct protocol_data* parse_protocol_data(protocol_type_t proto_type, 
                                        const uint8_t *payload, 
                                        size_t payload_len,
                                        bool is_request) {
    printf("DEBUG: Starting protocol parsing - Type: %s, Length: %zu, Is Request: %d\n",
           get_protocol_name(proto_type), payload_len, is_request);

    if (!payload || payload_len == 0) {
        printf("DEBUG: Invalid payload data\n");
        return NULL;
    }

    struct protocol_data *data = calloc(1, sizeof(struct protocol_data));
    if (!data) {
        printf("DEBUG: Failed to allocate protocol data\n");
        return NULL;
    }

    data->type = proto_type;
    data->is_request = is_request;

    // 保存原始数据
    if (is_request) {
        data->request = malloc(payload_len + 1);
        if (data->request) {
            memcpy(data->request, payload, payload_len);
            data->request[payload_len] = '\0';
        }
    } else {
        data->response = malloc(payload_len + 1);
        if (data->response) {
            memcpy(data->response, payload, payload_len);
            data->response[payload_len] = '\0';
        }
    }

    // 根据协议类型解析数据
    switch (proto_type) {
        case PROTO_HTTP:
            parse_http_data(data, payload, payload_len);
            break;
        case PROTO_DNS:
            parse_dns_data(data, payload, payload_len);
            break;
        default:
            printf("DEBUG: Unknown protocol type: %d\n", proto_type);
            break;
    }

    return data;
}

// 释放协议数据
void free_protocol_data(struct protocol_data *data) {
    if (!data) return;

    free(data->request);
    free(data->response);
    
    // 释放HTTP特定数据
    if (data->type == PROTO_HTTP) {
        free(data->http.content_type);
        free(data->http.host);
        free(data->http.uri);
        free(data->http.method);
        free(data->http.content_encoding);
        free(data->http.transfer_encoding);
        free(data->http.raw_content);
        free(data->http.decoded_content);
    } else if (data->type == PROTO_DNS) {
        // 释放DNS问题部分
        if (data->dns.questions) {
            for (uint16_t i = 0; i < data->dns.qdcount; i++) {
                free(data->dns.questions[i].qname);
            }
            free(data->dns.questions);
        }

        // 释放DNS记录链表
        struct dns_record *rec, *next;
        
        // 释放回答记录
        rec = data->dns.answers;
        while (rec) {
            next = rec->next;
            free(rec->name);
            switch (rec->type) {
                case DNS_TYPE_NS:
                    free(rec->rdata.ns.nsdname);
                    break;
                case DNS_TYPE_CNAME:
                    free(rec->rdata.cname.cname);
                    break;
                case DNS_TYPE_SOA:
                    free(rec->rdata.soa.mname);
                    free(rec->rdata.soa.rname);
                    break;
                case DNS_TYPE_PTR:
                    free(rec->rdata.ptr.ptrdname);
                    break;
                case DNS_TYPE_MX:
                    free(rec->rdata.mx.exchange);
                    break;
                case DNS_TYPE_TXT:
                    free(rec->rdata.txt.txt_data);
                    break;
                case DNS_TYPE_SRV:
                    free(rec->rdata.srv.target);
                    break;
            }
            free(rec);
            rec = next;
        }

        // 释放授权记录
        rec = data->dns.authorities;
        while (rec) {
            next = rec->next;
            free(rec->name);
            // ... 同上的switch语句 ...
            free(rec);
            rec = next;
        }

        // 释放附加记录
        rec = data->dns.additionals;
        while (rec) {
            next = rec->next;
            free(rec->name);
            // ... 同上的switch语句 ...
            free(rec);
            rec = next;
        }
    }
    
    free(data);
}

// 获取协议名称
const char* get_protocol_name(protocol_type_t type) {
    switch (type) {
        case PROTO_HTTP:  return "HTTP";
        case PROTO_FTP:   return "FTP";
        case PROTO_DNS:   return "DNS";
        case PROTO_SMTP:  return "SMTP";
        case PROTO_POP3:  return "POP3";
        case PROTO_ICMP:  return "ICMP";
        case PROTO_HTTPS: return "HTTPS";
        case PROTO_SSH:   return "SSH";
        case PROTO_TELNET: return "TELNET";
        default:         return "UNKNOWN";
    }
} 