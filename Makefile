# 编译器和标志
CC = gcc
CFLAGS = -Wall -Wextra -I./include -g \
         -D_GNU_SOURCE \
         -D_DEFAULT_SOURCE \
         -D_BSD_SOURCE \
         -D_POSIX_C_SOURCE=200809L \
         -Wno-format-truncation

# 链接标志
LDFLAGS = -lpcap -lpthread -lz -lbrotlidec

# 目录
SRC_DIR = src
OBJ_DIR = obj
INC_DIR = include

# 源文件和目标文件
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
DEPS = $(OBJS:.o=.d)

# 目标文件
TARGET = packet_analyzer

# 默认目标
all: directories $(TARGET)

# 显示编译信息
info:
	@echo "Source files: $(SRCS)"
	@echo "Object files: $(OBJS)"
	@echo "Dependencies: $(DEPS)"

# 创建必要的目录
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p logs/protocols

# 编译目标文件
$(TARGET): $(OBJS)
	@echo "Linking $@..."
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Build complete: $@"

# 编译源文件
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# 清理
clean:
	@echo "Cleaning..."
	@rm -rf $(OBJ_DIR) $(TARGET) logs/protocols/*
	@echo "Clean complete"

# 运行
run: $(TARGET)
	@echo "Running $(TARGET)..."
	./$(TARGET)

# 调试
debug: $(TARGET)
	@echo "Starting debugger..."
	gdb ./$(TARGET)

# 检查依赖库
check-deps:
	@echo "Checking dependencies..."
	@which pkg-config > /dev/null || (echo "pkg-config not found"; exit 1)
	@pkg-config --exists libpcap || (echo "libpcap not found"; exit 1)
	@pkg-config --exists zlib || (echo "zlib not found"; exit 1)
	@pkg-config --exists libbrotlidec || (echo "libbrotli not found"; exit 1)
	@echo "All dependencies found"

# 安装依赖（针对CentOS/RHEL系统）
install-deps-rhel:
	@echo "Installing dependencies for CentOS/RHEL..."
	sudo yum install -y libpcap-devel zlib-devel brotli-devel

# 安装依赖（针对Ubuntu/Debian系统）
install-deps-debian:
	@echo "Installing dependencies for Ubuntu/Debian..."
	sudo apt-get install -y libpcap-dev zlib1g-dev libbrotli-dev

# 包含依赖文件
-include $(DEPS)

# 伪目标
.PHONY: all clean run debug directories check-deps install-deps-rhel install-deps-debian info help

# 显示帮助信息
help:
	@echo "Available targets:"
	@echo "  all              - Build the project (default)"
	@echo "  clean            - Remove build files and logs"
	@echo "  run              - Build and run the program"
	@echo "  debug            - Build and start debugger"
	@echo "  check-deps       - Check required dependencies"
	@echo "  install-deps-rhel  - Install dependencies on CentOS/RHEL"
	@echo "  install-deps-debian - Install dependencies on Ubuntu/Debian"
	@echo "  info             - Display build information"
	@echo "  help             - Display this help message"
