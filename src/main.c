#include "packet.h"
#include "ip_reassembly.h"
#include "tcp_reassembly.h"
#include "logger.h"
#include "file_extractor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>

static volatile int running = 1;

// 信号处理
void handle_signal(int sig) {
    running = 0;
}

// 打印使用说明
void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -i <interface>   Network interface to capture (required)\n");
    printf("  -p <port>        Port to capture (default: any)\n");
    printf("  -l <logfile>     Log file path (default: traffic.log)\n");
    printf("  -c <count>       Number of packets to capture (default: 0, unlimited)\n");
    printf("  -v               Verbose output\n");
    printf("  -h               Show this help message\n");
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *logfile = "traffic.log";
    int packet_count = 0;
    int verbose = 0;
    int port = 0;  // 0表示抓取所有端口
    int opt;

    // 解析命令行参数
    while ((opt = getopt(argc, argv, "i:p:l:c:vh")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'l':
                logfile = optarg;
                break;
            case 'c':
                packet_count = atoi(optarg);
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    if (!interface) {
        fprintf(stderr, "Error: Network interface is required\n");
        print_usage(argv[0]);
        return 1;
    }

    // 初始化信号处理
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // 构建过滤器表达式
    char filter_exp[256] = "ip";  // 基本过滤器：只捕获IP包
    if (port > 0) {
        // 如果指定了端口，添加端口过滤条件
        snprintf(filter_exp, sizeof(filter_exp), 
                "ip and (port %d)", port);
    }

    // 初始化各模块
    pcap_t *handle;
    if (init_capture(interface, filter_exp, &handle) != 0) {
        return 1;
    }

    if (init_logger(logfile) != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        cleanup_capture(handle);
        return 1;
    }

    if (init_file_extractor() != 0) {
        fprintf(stderr, "Failed to initialize file extractor\n");
        close_logger();
        cleanup_capture(handle);
        return 1;
    }

    // 打印启动信息
    printf("Starting capture on interface %s\n", interface);
    if (port > 0) {
        printf("Capturing only port %d\n", port);
    } else {
        printf("Capturing all ports\n");
    }

    // 主循环
    start_capture(handle, packet_count);

    // 清理资源
    cleanup_capture(handle);
    close_logger();
    cleanup_file_extractor();

    printf("\nCapture stopped. Log saved to %s\n", logfile);
    return 0;
}
