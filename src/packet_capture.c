#include "packet.h"
#include "ip_reassembly.h"
#include "tcp_stream.h"
#include "tcp_reassembly.h"
#include "logger.h"
#include "file_extractor.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

// 数据包处理回调
void packet_handler(u_char *user, const struct pcap_pkthdr *header, 
                   const u_char *packet) {
    (void)user; // 避免未使用参数的警告
    
    if (!header || !packet) {
        return;
    }
    
    struct parsed_packet parsed;
    memset(&parsed, 0, sizeof(struct parsed_packet));

    // 复制时间戳
    parsed.timestamp = header->ts;

    // 解析以太网头
    const struct ether_header *eth_header = (struct ether_header *)packet;
    if (!eth_header || ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return; // 只处理IP包
    }

    // 确保数据包长度足够
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
        return;
    }

    // 解析IP头
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    parsed.src_ip = ip_header->ip_src.s_addr;
    parsed.dst_ip = ip_header->ip_dst.s_addr;
    parsed.protocol = ip_header->ip_p;

    // 处理TCP/UDP
    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        size_t ip_header_len = ip_header->ip_hl * 4;
        if (header->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr)) {
            return;
        }

        const struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header_len);
        parsed.src_port = ntohs(tcp_header->th_sport);
        parsed.dst_port = ntohs(tcp_header->th_dport);
    }

    // 记录日志
    log_message(LOG_LEVEL_INFO, &parsed, "Packet captured");

    // 处理IP分片
    if (ip_header->ip_off & IP_MF) {
        // TODO: 实现IP分片处理
    }

    // 处理TCP流
    if (ip_header->ip_p == IPPROTO_TCP) {
        // TODO: 实现TCP流重组
    }

    // 处理文件提取
    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        // TODO: 实现文件提取
    }

    // 提取负载数据
    const u_char *payload = NULL;
    size_t payload_len = 0;
    
    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        size_t ip_header_len = ip_header->ip_hl * 4;
        const struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header_len);
        size_t tcp_header_len = tcp_header->th_off * 4;
        
        payload = (u_char *)tcp_header + tcp_header_len;
        payload_len = ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;
        
        log_message_fmt(LOG_LEVEL_DEBUG, &parsed, 
                       "Payload detected - Length: %zu bytes", payload_len);
        
        if (payload_len > 0) {
            // 打印前100个字节的负载内容（用于调试）
            char debug_payload[101] = {0};
            size_t debug_len = payload_len > 100 ? 100 : payload_len;
            memcpy(debug_payload, payload, debug_len);
            log_message_fmt(LOG_LEVEL_DEBUG, &parsed, 
                          "Payload preview: %s", debug_payload);

            // 识别协议
            protocol_type_t proto_type = identify_protocol(&parsed, payload, payload_len);
            log_message_fmt(LOG_LEVEL_DEBUG, &parsed,
                          "Protocol identified: %s", get_protocol_name(proto_type));

            if (proto_type != PROTO_UNKNOWN) {
                // 解析协议数据
                bool is_request = (parsed.src_port > parsed.dst_port);
                log_message_fmt(LOG_LEVEL_DEBUG, &parsed,
                              "Processing as %s", is_request ? "request" : "response");

                struct protocol_data *proto_data = parse_protocol_data(
                    proto_type, payload, payload_len, is_request);
                
                if (proto_data) {
                    log_message(LOG_LEVEL_DEBUG, &parsed,
                              "Protocol data parsed successfully");
                    // 记录协议数据
                    log_protocol_data(&parsed, proto_data);
                    free_protocol_data(proto_data);
                } else {
                    log_message(LOG_LEVEL_ERROR, &parsed,
                              "Failed to parse protocol data");
                }
            }
        }
    }
}

int init_capture(const char *device, const char *filter_exp, pcap_t **handle) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 打开网络接口
    *handle = pcap_open_live(device, SNAPLEN, PROMISC, PCAP_TIMEOUT, errbuf);
    if (*handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return -1;
    }

    // 设置非阻塞模式
    if (pcap_setnonblock(*handle, 1, errbuf) == -1) {
        fprintf(stderr, "Failed to set non-blocking mode: %s\n", errbuf);
        pcap_close(*handle);
        return -1;
    }

    // 编译和设置过滤器
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", device);
        net = 0;
        mask = 0;
    }

    if (pcap_compile(*handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(*handle));
        return -1;
    }

    if (pcap_setfilter(*handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(*handle));
        return -1;
    }

    pcap_freecode(&fp);
    return 0;
}

void start_capture(pcap_t *handle, int packet_count) {
    pcap_loop(handle, packet_count, packet_handler, NULL);
}

void cleanup_capture(pcap_t *handle) {
    if (handle) {
        pcap_close(handle);
    }
}
