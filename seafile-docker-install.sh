#!/bin/bash

# Seafile Docker 自动安装脚本
# 适用于 Debian/Ubuntu 系列发行版
# GitHub: https://github.com/wzwys9/my_abc
# 版本: 1.1
# 更新日期: 2025-07-11
echo -e "1.8"
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
SCRIPT_VERSION="1.11"
PROJECT_DIR=""
DOMAIN=""
EMAIL=""
MYSQL_ROOT_PASSWORD=""
MYSQL_SEAFILE_PASSWORD=""
SEAFILE_ADMIN_EMAIL=""
SEAFILE_ADMIN_PASSWORD=""
OS_ID=""
OS_VERSION_ID=""
OS_CODENAME=""
DOCKER_SUDO=""

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

log_success() {
    echo -e "${PURPLE}[SUCCESS]${NC} $1"
}

log_debug() {
    echo -e "${CYAN}[DEBUG]${NC} $1"
}

# 显示横幅
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "=================================================="
    echo "🐳 Seafile Docker 自动安装脚本 v${SCRIPT_VERSION}"
    echo "=================================================="
    echo -e "${NC}"
    echo "此脚本将自动为您安装："
    echo "  🐳 Docker & Docker Compose"
    echo "  🗃️  Seafile + MySQL + Memcached"
    echo "  🔒 Nginx反向代理 + SSL证书"
    echo "  ⚙️  自动化管理脚本"
    echo
    echo "支持系统: Debian 11+, Ubuntu 20.04+"
    echo "预计用时: 15-25分钟"
    echo "=================================================="
    echo
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "⚠️ 安全提示：请不要使用root用户运行此脚本！"
        log_info "建议操作："
        echo "  1. 创建普通用户: sudo adduser username"
        echo "  2. 添加sudo权限: sudo usermod -aG sudo username"
        echo "  3. 切换用户: su - username"
        echo "  4. 重新运行此脚本"
        exit 1
    fi
}

# 检测操作系统信息
detect_os() {
    # 安装lsb-release如果不存在
    if ! command -v lsb_release &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y lsb-release
        else
            log_error "无法安装lsb-release，请手动安装"
            exit 1
        fi
    fi

    # 读取系统信息
    OS_ID=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    OS_VERSION_ID=$(lsb_release -sr)
    OS_CODENAME=$(lsb_release -sc)
    
    # 输出调试信息
    log_debug "检测到的系统信息："
    log_debug "OS_ID: $OS_ID"
    log_debug "OS_VERSION_ID: $OS_VERSION_ID"  
    log_debug "OS_CODENAME: $OS_CODENAME"
}

# 检查系统版本
check_system() {
    log_step "🔍 检查系统环境..."
    
    detect_os
    
    # 检查是否为Debian系列
    case "$OS_ID" in
        "ubuntu")
            if [[ ! "$OS_VERSION_ID" =~ ^(18\.04|20\.04|22\.04|24\.04) ]]; then
                log_warn "⚠️ Ubuntu版本 $OS_VERSION_ID 未经测试，建议使用 20.04/22.04 LTS"
                read -p "是否继续安装? (y/N): " continue_install
                if [[ ! $continue_install =~ ^[Yy]$ ]]; then
                    exit 0
                fi
            fi
            ;;
        "debian")
            # 检查Debian版本
            case "$OS_VERSION_ID" in
                "11"|"12")
                    log_info "✅ 支持的Debian版本: $OS_VERSION_ID ($OS_CODENAME)"
                    ;;
                *)
                    log_warn "⚠️ Debian版本 $OS_VERSION_ID 未经测试，建议使用 11 (bullseye) 或 12 (bookworm)"
                    read -p "是否继续安装? (y/N): " continue_install
                    if [[ ! $continue_install =~ ^[Yy]$ ]]; then
                        exit 0
                    fi
                    ;;
            esac
            ;;
        "linuxmint"|"pop"|"elementary"|"zorin")
            log_info "✅ 检测到基于Ubuntu的发行版: $OS_ID"
            # 对于基于Ubuntu的发行版，使用Ubuntu的包管理方式
            OS_ID="ubuntu"
            ;;
        "kali"|"parrot")
            log_info "✅ 检测到基于Debian的发行版: $OS_ID"
            # 对于基于Debian的发行版，使用Debian的包管理方式
            OS_ID="debian"
            ;;
        *)
            log_error "❌ 不支持的操作系统: $OS_ID"
            log_error "此脚本仅支持 Debian/Ubuntu 系列发行版"
            exit 1
            ;;
    esac
    
    # 检查内存
    TOTAL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    if [[ $TOTAL_MEM -lt 1500 ]]; then
        log_warn "⚠️ 系统内存不足2GB ($TOTAL_MEM MB)，可能影响Seafile性能"
        read -p "是否继续安装? (y/N): " continue_install
        if [[ ! $continue_install =~ ^[Yy]$ ]]; then
            log_info "安装已取消"
            exit 0
        fi
    fi
    
    # 检查磁盘空间
    AVAILABLE_SPACE=$(df / | awk 'NR==2 {print $4}')
    if [[ $AVAILABLE_SPACE -lt 5242880 ]]; then  # 5GB in KB
        log_warn "⚠️ 磁盘可用空间不足5GB，建议清理磁盘空间"
    fi
    
    log_success "✅ 系统环境检查通过: $OS_ID $OS_VERSION_ID ($OS_CODENAME)"
    log_info "📊 系统信息: 内存 ${TOTAL_MEM}MB, 可用空间 $((AVAILABLE_SPACE/1024/1024))GB"
}

# 生成随机密码
generate_password() {
    local length=${1:-16}
    openssl rand -base64 $length | tr -d "=+/" | cut -c1-$length
}

# 验证域名格式
validate_domain() {
    local domain=$1
    if [[ $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    else
        return 1
    fi
}

# 验证邮箱格式
validate_email() {
    local email=$1
    if [[ $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# 获取服务器公网IP
get_server_ip() {
    local ip=""
    
    # 尝试多个IP检测服务
    local ip_services=(
        "http://ifconfig.me/ip"
        "http://ipinfo.io/ip"
        "http://ip.sb"
        "http://myip.ipip.net"
        "http://checkip.amazonaws.com"
    )
    
    for service in "${ip_services[@]}"; do
        ip=$(curl -s --connect-timeout 10 --max-time 15 "$service" 2>/dev/null | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
        if [[ -n "$ip" && "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    # 如果所有服务都失败，尝试从网络接口获取
    ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
    if [[ -n "$ip" && "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "$ip"
        return 0
    fi
    
    return 1
}

# 检查域名解析
check_domain_resolution() {
    local domain=$1
    log_step "🌐 检查域名解析..."
    
    # 获取服务器公网IP
    SERVER_IP=$(get_server_ip)
    
    if [[ -z "$SERVER_IP" ]]; then
        log_warn "⚠️ 无法获取服务器公网IP，跳过域名解析检查"
        log_info "请确保域名已正确解析到此服务器"
        return 0
    fi
    
    # 检查域名解析
    RESOLVED_IP=$(dig +short $domain 2>/dev/null | tail -n1)
    
    if [[ -z "$RESOLVED_IP" ]]; then
        # 尝试使用nslookup
        RESOLVED_IP=$(nslookup $domain 2>/dev/null | awk '/^Address: / { print $2 }' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -1)
    fi
    
    if [[ "$RESOLVED_IP" == "$SERVER_IP" ]]; then
        log_success "✅ 域名解析正确: $domain -> $SERVER_IP"
    else
        log_warn "⚠️ 域名解析检查:"
        echo "  域名: $domain"
        echo "  解析IP: $RESOLVED_IP"
        echo "  服务器IP: $SERVER_IP"
        echo
        echo "如果域名解析不正确，SSL证书获取可能失败"
        read -p "是否继续安装? (y/N): " continue_install
        if [[ ! $continue_install =~ ^[Yy]$ ]]; then
            log_info "安装已取消，请先配置正确的域名解析"
            exit 0
        fi
    fi
}

# 获取用户输入
get_user_input() {
    log_step "📝 收集配置信息..."
    echo
    
    # 域名配置
    while true; do
        read -p "🌐 请输入您的域名 (例如: cloud.example.com): " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            log_error "域名不能为空"
            continue
        fi
        if validate_domain "$DOMAIN"; then
            break
        else
            log_error "域名格式不正确，请重新输入"
        fi
    done
    
    # 检查域名解析
    check_domain_resolution "$DOMAIN"
    
    # SSL证书邮箱
    while true; do
        read -p "📧 请输入邮箱地址 (用于SSL证书申请): " EMAIL
        if [[ -z "$EMAIL" ]]; then
            log_error "邮箱不能为空"
            continue
        fi
        if validate_email "$EMAIL"; then
            break
        else
            log_error "邮箱格式不正确，请重新输入"
        fi
    done
    
    # 管理员邮箱
    SEAFILE_ADMIN_EMAIL="admin@${DOMAIN}"
    read -p "👤 Seafile管理员邮箱 (默认: $SEAFILE_ADMIN_EMAIL): " input_admin_email
    if [[ -n "$input_admin_email" ]]; then
        if validate_email "$input_admin_email"; then
            SEAFILE_ADMIN_EMAIL="$input_admin_email"
        else
            log_warn "邮箱格式不正确，使用默认邮箱: $SEAFILE_ADMIN_EMAIL"
        fi
    fi
    
    echo
    log_info "🔐 密码配置 (建议使用强密码)"
    
    # MySQL root密码
    while true; do
        read -s -p "🗃️  MySQL root密码 (最少8位): " MYSQL_ROOT_PASSWORD
        echo
        if [[ ${#MYSQL_ROOT_PASSWORD} -lt 8 ]]; then
            log_error "密码长度至少8位"
            continue
        fi
        read -s -p "🔄 确认MySQL root密码: " confirm_password
        echo
        if [[ "$MYSQL_ROOT_PASSWORD" == "$confirm_password" ]]; then
            break
        else
            log_error "两次输入的密码不一致"
        fi
    done
    
    # MySQL seafile用户密码
    while true; do
        read -s -p "🗃️  MySQL seafile用户密码 (最少8位): " MYSQL_SEAFILE_PASSWORD
        echo
        if [[ ${#MYSQL_SEAFILE_PASSWORD} -lt 8 ]]; then
            log_error "密码长度至少8位"
            continue
        fi
        read -s -p "🔄 确认MySQL seafile用户密码: " confirm_password
        echo
        if [[ "$MYSQL_SEAFILE_PASSWORD" == "$confirm_password" ]]; then
            break
        else
            log_error "两次输入的密码不一致"
        fi
    done
    
    # Seafile管理员密码
    while true; do
        read -s -p "👤 Seafile管理员密码 (最少8位): " SEAFILE_ADMIN_PASSWORD
        echo
        if [[ ${#SEAFILE_ADMIN_PASSWORD} -lt 8 ]]; then
            log_error "密码长度至少8位"
            continue
        fi
        read -s -p "🔄 确认Seafile管理员密码: " confirm_password
        echo
        if [[ "$SEAFILE_ADMIN_PASSWORD" == "$confirm_password" ]]; then
            break
        else
            log_error "两次输入的密码不一致"
        fi
    done
    
    echo
    log_info "📋 配置信息确认:"
    echo "  🌐 域名: $DOMAIN"
    echo "  📧 SSL邮箱: $EMAIL"
    echo "  👤 管理员邮箱: $SEAFILE_ADMIN_EMAIL"
    echo "  🗃️  数据库: MySQL 8.0"
    echo "  🐳 容器化: Docker Compose"
    echo "  🖥️  系统: $OS_ID $OS_VERSION_ID"
    echo
    
    read -p "✅ 确认以上信息正确吗? (y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        log_info "安装已取消"
        exit 0
    fi
    
    log_success "✅ 配置信息收集完成"
}

# 安装系统依赖
install_dependencies() {
    log_step "📦 安装系统依赖包..."
    
    # 更新软件包列表
    sudo apt-get update
    
    # 安装基础工具
    sudo apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        software-properties-common \
        wget \
        unzip \
        tar \
        openssl \
        dnsutils \
        net-tools
    
    log_success "✅ 系统依赖安装完成"
}

# 安装Docker
install_docker() {
    log_step "🐳 安装Docker和Docker Compose..."
    
    # 检查是否已安装Docker
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version | cut -d ' ' -f3 | cut -d ',' -f1)
        log_info "Docker已安装: $DOCKER_VERSION"
    else
        log_info "正在安装Docker..."
        
        # 删除旧版本
        sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        
        # 清理可能存在的错误Docker仓库配置
        log_info "清理旧的Docker仓库配置..."
        sudo rm -f /etc/apt/sources.list.d/docker.list
        sudo rm -f /usr/share/keyrings/docker-archive-keyring.gpg
        
        # 根据系统类型配置Docker仓库
        case "$OS_ID" in
            "ubuntu")
                log_info "配置Ubuntu Docker仓库..."
                # Ubuntu系统配置
                curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
                ;;
            "debian")
                log_info "配置Debian Docker仓库..."
                # Debian系统配置
                curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
                ;;
            *)
                log_error "不支持的操作系统: $OS_ID"
                exit 1
                ;;
        esac
        
        # 验证仓库配置
        log_info "验证Docker仓库配置..."
        if [[ "$OS_ID" == "debian" ]]; then
            if ! grep -q "download.docker.com/linux/debian" /etc/apt/sources.list.d/docker.list; then
                log_error "Docker仓库配置失败"
                exit 1
            fi
        else
            if ! grep -q "download.docker.com/linux/ubuntu" /etc/apt/sources.list.d/docker.list; then
                log_error "Docker仓库配置失败"
                exit 1
            fi
        fi
        
        # 更新软件包列表
        log_info "更新软件包列表..."
        sudo apt-get update
        
        # 安装Docker
        log_info "安装Docker软件包..."
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        
        # 启动Docker服务
        sudo systemctl start docker
        sudo systemctl enable docker
        
        # 将当前用户添加到docker组
        sudo usermod -aG docker $USER
        
        # 激活docker组权限（避免需要重新登录）
        log_info "激活Docker组权限..."
        newgrp docker
        
        DOCKER_VERSION=$(docker --version | cut -d ' ' -f3 | cut -d ',' -f1)
        log_success "✅ Docker安装完成: $DOCKER_VERSION"
    fi
    
    # 检查Docker Compose
    if command -v docker-compose &> /dev/null; then
        COMPOSE_VERSION=$(docker-compose --version | cut -d ' ' -f3 | cut -d ',' -f1)
        log_info "Docker Compose已安装: $COMPOSE_VERSION"
    else
        log_info "正在安装Docker Compose..."
        
        # 获取最新版本号
        COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d '"' -f 4)
        
        # 下载并安装
        sudo curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
        
        # 创建软链接
        sudo ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
        
        log_success "✅ Docker Compose安装完成: $COMPOSE_VERSION"
    fi
    
    # 测试Docker权限
    log_info "测试Docker权限..."
    if ! docker ps &>/dev/null; then
        log_warn "Docker权限需要sudo，将在脚本中使用sudo执行Docker命令"
        # 设置全局变量指示需要使用sudo
        DOCKER_SUDO="sudo"
    else
        DOCKER_SUDO=""
    fi
    
    # 检查Docker服务状态
    if ! sudo systemctl is-active --quiet docker; then
        log_error "Docker服务未运行"
        exit 1
    fi
    
    log_success "✅ Docker环境准备完成"
}

# 创建项目目录和文件
create_project() {
    log_step "📁 创建项目目录和配置文件..."
    
    # 设置项目目录
    PROJECT_DIR="$HOME/seafile-docker"
    
    # 如果目录已存在，询问是否覆盖
    if [[ -d "$PROJECT_DIR" ]]; then
        log_warn "⚠️ 项目目录已存在: $PROJECT_DIR"
        read -p "是否删除现有目录并重新创建? (y/N): " overwrite
        if [[ $overwrite =~ ^[Yy]$ ]]; then
            rm -rf "$PROJECT_DIR"
            log_info "已删除现有目录"
        else
            log_error "安装已取消"
            exit 1
        fi
    fi
    
    # 创建项目目录结构
    mkdir -p "$PROJECT_DIR"
    cd "$PROJECT_DIR"
    
    # 创建数据持久化目录
    mkdir -p data/seafile-data
    mkdir -p data/mysql-data
    mkdir -p ssl
    mkdir -p logs
    
    log_info "创建Docker Compose配置文件..."
    
    # 创建docker-compose.yml
    cat > docker-compose.yml << EOF
version: '3.8'

services:
  # MySQL数据库
  seafile-mysql:
    image: mysql:8.0
    container_name: seafile-mysql
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_LOG_CONSOLE: true
      MYSQL_DATABASE: seafile_db
      MYSQL_USER: seafile
      MYSQL_PASSWORD: ${MYSQL_SEAFILE_PASSWORD}
      TZ: Asia/Shanghai
    volumes:
      - ./data/mysql-data:/var/lib/mysql
      - ./logs/mysql:/var/log/mysql
    networks:
      - seafile-net
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      timeout: 20s
      retries: 10
    command: --default-authentication-plugin=mysql_native_password --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci

  # Memcached缓存
  seafile-memcached:
    image: memcached:1.6-alpine
    container_name: seafile-memcached
    command: memcached -m 256 -I 10m
    networks:
      - seafile-net
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "11211"]
      timeout: 10s
      retries: 3

  # Seafile服务
  seafile:
    image: seafileltd/seafile-mc:11.0-latest
    container_name: seafile
    ports:
      - "127.0.0.1:8080:80"
    volumes:
      - ./data/seafile-data:/shared
      - ./logs/seafile:/opt/seafile/logs
    environment:
      - DB_HOST=seafile-mysql
      - DB_ROOT_PASSWD=${MYSQL_ROOT_PASSWORD}
      - DB_USER=seafile
      - DB_PASSWD=${MYSQL_SEAFILE_PASSWORD}
      - SEAFILE_ADMIN_EMAIL=${SEAFILE_ADMIN_EMAIL}
      - SEAFILE_ADMIN_PASSWORD=${SEAFILE_ADMIN_PASSWORD}
      - SEAFILE_SERVER_LETSENCRYPT=false
      - SEAFILE_SERVER_HOSTNAME=${DOMAIN}
      - TIME_ZONE=Asia/Shanghai
    depends_on:
      seafile-mysql:
        condition: service_healthy
      seafile-memcached:
        condition: service_healthy
    networks:
      - seafile-net
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/api2/ping/"]
      timeout: 10s
      retries: 3
      start_period: 60s

  # Nginx反向代理
  nginx:
    image: nginx:alpine
    container_name: seafile-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./logs/nginx:/var/log/nginx
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - /var/www/certbot:/var/www/certbot:ro
    depends_on:
      seafile:
        condition: service_healthy
    networks:
      - seafile-net
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "nginx", "-t"]
      timeout: 10s
      retries: 3

networks:
  seafile-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
EOF

    log_info "创建Nginx配置文件..."
    
    # 创建nginx.conf
    cat > nginx.conf << 'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    # 日志格式
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'rt=$request_time uct="$upstream_connect_time" '
                    'uht="$upstream_header_time" urt="$upstream_response_time"';
    
    access_log /var/log/nginx/access.log main;
    
    # 基本设置
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # 文件上传大小限制
    client_max_body_size 1G;
    client_body_buffer_size 128k;
    client_header_buffer_size 3m;
    large_client_header_buffers 4 256k;
    
    # Gzip压缩
    gzip on;
    gzip_vary on;
    gzip_min_length 1000;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    # 速率限制
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=20r/s;

EOF

    # 添加域名相关的server配置
    cat >> nginx.conf << EOF
    # HTTP重定向到HTTPS
    server {
        listen 80;
        server_name ${DOMAIN};
        
        # Let's Encrypt验证路径
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
            try_files \$uri =404;
        }
        
        # 健康检查路径
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
        
        # 其他请求重定向到HTTPS
        location / {
            return 301 https://\$server_name\$request_uri;
        }
    }

    # HTTPS配置
    server {
        listen 443 ssl http2;
        server_name ${DOMAIN};

        # SSL证书配置
        ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
        
        # SSL安全配置
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1h;
        ssl_session_tickets off;
        ssl_stapling on;
        ssl_stapling_verify on;

        # 安全头
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options DENY;
        add_header X-XSS-Protection "1; mode=block";
        add_header Referrer-Policy "strict-origin-when-cross-origin";
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; media-src 'self'; object-src 'none'; child-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

        # 主要代理配置
        location / {
            proxy_pass http://seafile:80;
            proxy_set_header Host \$http_host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host \$server_name;
            proxy_read_timeout 1200s;
            proxy_connect_timeout 75s;
            proxy_send_timeout 1200s;
            proxy_buffering off;
            proxy_request_buffering off;
        }

        # 文件上传下载优化
        location /seafhttp {
            proxy_pass http://seafile:8082;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_request_buffering off;
            proxy_buffering off;
            proxy_read_timeout 1200s;
            proxy_send_timeout 1200s;
            client_max_body_size 0;
        }

        # WebDAV支持
        location /seafdav {
            proxy_pass http://seafile:8080;
            proxy_set_header Host \$http_host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_read_timeout 1200s;
            proxy_send_timeout 1200s;
            client_max_body_size 0;
            proxy_request_buffering off;
            
            # WebDAV需要的方法
            limit_except GET POST OPTIONS PROPFIND PROPPATCH MKCOL COPY MOVE DELETE PUT {
                deny all;
            }
        }

        # API速率限制
        location ~ ^/api2/ {
            limit_req zone=api burst=50 nodelay;
            proxy_pass http://seafile:80;
            proxy_set_header Host \$http_host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
        }

        # 登录速率限制
        location ~ ^/(accounts/login|api2/auth-token) {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://seafile:80;
            proxy_set_header Host \$http_host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
        }

        # 静态文件缓存
        location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            proxy_pass http://seafile:80;
            proxy_set_header Host \$http_host;
            expires 7d;
            add_header Cache-Control "public, no-transform";
        }

        # 健康检查
        location /nginx-health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
EOF

    # 创建环境变量文件
    cat > .env << EOF
# Seafile Docker 环境变量配置
# 生成时间: $(date)

# 系统信息
OS_ID=${OS_ID}
OS_VERSION=${OS_VERSION_ID}
OS_CODENAME=${OS_CODENAME}

# 域名配置
DOMAIN=${DOMAIN}
EMAIL=${EMAIL}

# 数据库配置
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}
MYSQL_SEAFILE_PASSWORD=${MYSQL_SEAFILE_PASSWORD}

# Seafile配置
SEAFILE_ADMIN_EMAIL=${SEAFILE_ADMIN_EMAIL}
SEAFILE_ADMIN_PASSWORD=${SEAFILE_ADMIN_PASSWORD}

# 项目目录
PROJECT_DIR=${PROJECT_DIR}
EOF

    # 设置正确的权限
    chmod 600 .env
    chmod 644 docker-compose.yml nginx.conf
    
    log_success "✅ 项目目录和配置文件创建完成"
    log_info "📂 项目位置: $PROJECT_DIR"
}

# 安装certbot并获取SSL证书
setup_ssl() {
    log_step "🔒 配置SSL证书..."
    
    # 安装certbot
    if ! command -v certbot &> /dev/null; then
        log_info "安装Certbot..."
        sudo apt-get update
        
        # 根据系统类型安装certbot
        case "$OS_ID" in
            "ubuntu")
                sudo apt-get install -y certbot
                ;;
            "debian")
                # Debian系统可能需要从backports安装更新的certbot
                if [[ "$OS_VERSION_ID" == "11" ]]; then
                    sudo apt-get install -y certbot
                else
                    sudo apt-get install -y certbot
                fi
                ;;
            *)
                sudo apt-get install -y certbot
                ;;
        esac
    fi
    
    # 创建证书目录
    sudo mkdir -p /var/www/certbot
    
    # 停止可能占用80端口的服务
    sudo systemctl stop nginx 2>/dev/null || true
    sudo systemctl stop apache2 2>/dev/null || true
    sudo pkill -f "nginx" 2>/dev/null || true
    
    # 检查80端口是否被占用
    if netstat -tlpn 2>/dev/null | grep ":80 " >/dev/null 2>&1; then
        log_error "端口80被占用，请先停止占用该端口的服务"
        netstat -tlpn | grep ":80 "
        exit 1
    fi
    
    log_info "启动临时web服务器获取SSL证书..."
    
    # 创建临时nginx配置
    cat > temp-nginx.conf << EOF
events {
    worker_connections 1024;
}

http {
    server {
        listen 80;
        server_name ${DOMAIN};
        
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
            try_files \$uri =404;
        }
        
        location / {
            return 200 'Temporary server for SSL certificate acquisition';
            add_header Content-Type text/plain;
        }
    }
}
EOF

    # 启动临时nginx容器
    ${DOCKER_SUDO} docker run --rm -d \
        --name temp-nginx \
        -p 80:80 \
        -v "$(pwd)/temp-nginx.conf:/etc/nginx/nginx.conf" \
        -v /var/www/certbot:/var/www/certbot \
        nginx:alpine

    # 等待nginx启动
    sleep 5
    
    # 测试nginx是否正常运行
    if ! curl -s http://localhost >/dev/null; then
        log_error "临时nginx服务器启动失败"
        ${DOCKER_SUDO} docker stop temp-nginx 2>/dev/null || true
        exit 1
    fi
    
    # 获取SSL证书
    log_info "正在申请SSL证书，请稍等..."
    
    if sudo certbot certonly \
        --webroot \
        --webroot-path=/var/www/certbot \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --force-renewal \
        --rsa-key-size 4096 \
        --must-staple \
        -d "$DOMAIN"; then
        log_success "✅ SSL证书获取成功"
    else
        log_error "❌ SSL证书获取失败"
        docker stop temp-nginx 2>/dev/null || true
        exit 1
    fi
    
    # 停止临时nginx
    ${DOCKER_SUDO} docker stop temp-nginx 2>/dev/null || true
    ${DOCKER_SUDO} docker rm temp-nginx 2>/dev/null || true
    
    # 清理临时文件
    rm -f temp-nginx.conf
    
    # 验证证书
    if sudo openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/cert.pem" -text -noout >/dev/null 2>&1; then
        CERT_EXPIRY=$(sudo openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/cert.pem" -noout -enddate | cut -d= -f2)
        log_success "✅ SSL证书验证成功，有效期至: $CERT_EXPIRY"
    else
        log_error "❌ SSL证书验证失败"
        exit 1
    fi
}

# 创建证书续期脚本
create_renewal_script() {
    log_step "⚙️ 配置SSL证书自动续期..."
    
    # 创建续期脚本
    cat > renew-cert.sh << 'EOF'
#!/bin/bash
# SSL证书自动续期脚本
# 由Seafile Docker安装脚本自动生成

set -e

LOG_FILE="/var/log/seafile-cert-renewal.log"
PROJECT_DIR="$HOME/seafile-docker"

# 检测是否需要sudo执行docker命令
if ! docker ps &>/dev/null; then
    DOCKER_SUDO="sudo"
else
    DOCKER_SUDO=""
fi

# 日志函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "开始SSL证书续期检查..."

# 进入项目目录
cd "$PROJECT_DIR" || {
    log "错误: 无法进入项目目录 $PROJECT_DIR"
    exit 1
}

# 停止nginx容器以释放80端口
log "停止nginx容器..."
if ! ${DOCKER_SUDO} docker-compose stop nginx; then
    log "警告: 停止nginx容器失败"
fi

# 续期证书
log "执行证书续期..."
if sudo certbot renew --quiet --deploy-hook "systemctl reload nginx 2>/dev/null || true"; then
    log "证书续期检查完成"
else
    log "错误: 证书续期失败"
    # 即使续期失败也要重启nginx
    ${DOCKER_SUDO} docker-compose start nginx
    exit 1
fi

# 重启nginx容器
log "重启nginx容器..."
if ${DOCKER_SUDO} docker-compose start nginx; then
    log "nginx容器重启成功"
else
    log "错误: nginx容器重启失败"
    exit 1
fi

# 验证服务状态
sleep 5
if ${DOCKER_SUDO} docker-compose ps | grep -q "seafile-nginx.*Up"; then
    log "SSL证书续期完成，服务运行正常"
else
    log "警告: 服务状态异常，请检查"
fi

# 清理Docker资源
${DOCKER_SUDO} docker system prune -f >/dev/null 2>&1 || true

log "SSL证书续期流程结束"
EOF

    chmod +x renew-cert.sh
    
    # 创建测试脚本
    cat > test-renewal.sh << 'EOF'
#!/bin/bash
# SSL证书续期测试脚本

echo "测试SSL证书续期功能..."
sudo certbot renew --dry-run
echo "如果上述命令没有错误，说明自动续期配置正确"
EOF

    chmod +x test-renewal.sh
    
    # 添加到crontab
    log_info "配置定时任务..."
    
    # 检查是否已存在相关的crontab条目
    if crontab -l 2>/dev/null | grep -q "$PROJECT_DIR/renew-cert.sh"; then
        log_info "定时任务已存在，跳过添加"
    else
        # 添加到crontab（每周一凌晨3点执行）
        (crontab -l 2>/dev/null; echo "0 3 * * 1 $PROJECT_DIR/renew-cert.sh") | crontab -
        log_success "✅ 定时任务添加成功"
    fi
    
    # 创建日志文件
    sudo touch /var/log/seafile-cert-renewal.log
    sudo chown $USER:$USER /var/log/seafile-cert-renewal.log
    
    log_success "✅ SSL证书自动续期配置完成"
    log_info "📅 续期时间: 每周一 03:00"
    log_info "📝 日志文件: /var/log/seafile-cert-renewal.log"
    log_info "🧪 测试命令: $PROJECT_DIR/test-renewal.sh"
}

# 启动服务
start_services() {
    log_step "🚀 启动Seafile服务..."
    
    cd "$PROJECT_DIR"
    
    # 检查Docker服务状态
    if ! sudo systemctl is-active --quiet docker; then
        log_info "启动Docker服务..."
        sudo systemctl start docker
    fi
    
    # 拉取最新镜像
    log_info "拉取Docker镜像..."
    ${DOCKER_SUDO} docker-compose pull
    
    # 启动所有服务
    log_info "启动容器服务..."
    ${DOCKER_SUDO} docker-compose up -d
    
    log_info "⏳ 等待服务启动完成..."
    
    # 等待MySQL启动
    log_info "等待MySQL数据库启动..."
    timeout=120
    counter=0
    while [ $counter -lt $timeout ]; do
        if ${DOCKER_SUDO} docker-compose logs seafile-mysql 2>/dev/null | grep -q "ready for connections"; then
            log_success "✅ MySQL数据库启动完成"
            break
        fi
        sleep 2
        counter=$((counter + 2))
        if [ $((counter % 20)) -eq 0 ]; then
            log_info "等待MySQL启动... ($counter/$timeout 秒)"
        fi
    done
    
    if [ $counter -ge $timeout ]; then
        log_error "❌ MySQL启动超时"
        ${DOCKER_SUDO} docker-compose logs seafile-mysql
        exit 1
    fi
    
    # 等待Seafile启动
    log_info "等待Seafile服务启动..."
    timeout=300
    counter=0
    while [ $counter -lt $timeout ]; do
        if ${DOCKER_SUDO} docker-compose logs seafile 2>/dev/null | grep -q "Seafile started"; then
            log_success "✅ Seafile服务启动完成"
            break
        fi
        if ${DOCKER_SUDO} docker-compose logs seafile 2>/dev/null | grep -q "Error\|Failed\|Exception"; then
            log_error "❌ Seafile启动出现错误"
            ${DOCKER_SUDO} docker-compose logs seafile
            exit 1
        fi
        sleep 5
        counter=$((counter + 5))
        if [ $((counter % 30)) -eq 0 ]; then
            log_info "等待Seafile启动... ($counter/$timeout 秒)"
        fi
    done
    
    if [ $counter -ge $timeout ]; then
        log_error "❌ Seafile启动超时"
        ${DOCKER_SUDO} docker-compose logs seafile
        exit 1
    fi
    
    # 等待Nginx启动
    log_info "等待Nginx代理启动..."
    sleep 10
    
    # 检查所有容器状态
    log_info "检查容器运行状态..."
    if ${DOCKER_SUDO} docker-compose ps | grep -q "Exit\|unhealthy"; then
        log_warn "⚠️ 发现异常容器状态:"
        ${DOCKER_SUDO} docker-compose ps
        echo
        log_info "容器日志:"
        ${DOCKER_SUDO} docker-compose logs --tail=20
    else
        log_success "✅ 所有容器运行正常"
        ${DOCKER_SUDO} docker-compose ps
    fi
}

# 验证安装
verify_installation() {
    log_step "🔍 验证安装结果..."
    
    # 等待服务完全就绪
    sleep 15
    
    # 检查SSL证书
    log_info "检查SSL证书状态..."
    if echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -issuer | grep -q "Let's Encrypt"; then
        log_success "✅ SSL证书正常"
    else
        log_warn "⚠️ SSL证书检查失败，可能需要等待DNS传播"
    fi
    
    # 检查网站访问
    log_info "检查网站访问..."
    
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN" || echo "000")
    if [[ "$HTTP_CODE" == "301" || "$HTTP_CODE" == "302" ]]; then
        log_success "✅ HTTP重定向正常 (状态码: $HTTP_CODE)"
    else
        log_warn "⚠️ HTTP访问异常 (状态码: $HTTP_CODE)"
    fi
    
    HTTPS_CODE=$(curl -s -k -o /dev/null -w "%{http_code}" "https://$DOMAIN" || echo "000")
    if [[ "$HTTPS_CODE" == "200" || "$HTTPS_CODE" == "302" ]]; then
        log_success "✅ HTTPS访问正常 (状态码: $HTTPS_CODE)"
    else
        log_warn "⚠️ HTTPS访问异常 (状态码: $HTTPS_CODE)"
        log_info "这可能是因为Seafile还在初始化中，请稍等几分钟"
    fi
    
    # 检查容器健康状态
    log_info "检查容器健康状态..."
    local unhealthy_containers=$(${DOCKER_SUDO} docker-compose ps --filter "health=unhealthy" -q)
    if [[ -z "$unhealthy_containers" ]]; then
        log_success "✅ 所有容器健康状态正常"
    else
        log_warn "⚠️ 发现不健康的容器，请检查日志"
    fi
    
    # 检查磁盘空间
    local available_space=$(df "$PROJECT_DIR" | awk 'NR==2 {print $4}')
    if [[ $available_space -gt 1048576 ]]; then  # 1GB
        log_success "✅ 磁盘空间充足 ($((available_space/1024/1024))GB可用)"
    else
        log_warn "⚠️ 磁盘空间不足，建议清理空间"
    fi
    
    log_success "✅ 安装验证完成"
}

# 创建管理脚本
create_management_scripts() {
    log_step "⚙️ 创建管理脚本..."
    
    # 创建状态检查脚本
    cat > status.sh << 'EOF'
#!/bin/bash
# Seafile状态检查脚本

set -e

PROJECT_DIR="$HOME/seafile-docker"
cd "$PROJECT_DIR"

# 检测是否需要sudo执行docker命令
if ! docker ps &>/dev/null; then
    DOCKER_SUDO="sudo"
else
    DOCKER_SUDO=""
fi

echo "=========================================="
echo "🐳 Seafile Docker 状态检查"
echo "=========================================="
echo

# Docker容器状态
echo "=== 📦 容器状态 ==="
${DOCKER_SUDO} docker-compose ps
echo

# 健康检查
echo "=== 🏥 健康检查 ==="
for service in seafile-mysql seafile-memcached seafile seafile-nginx; do
    health=$(${DOCKER_SUDO} docker inspect --format='{{.State.Health.Status}}' $service 2>/dev/null || echo "no-healthcheck")
    if [[ "$health" == "healthy" ]]; then
        echo "✅ $service: $health"
    elif [[ "$health" == "no-healthcheck" ]]; then
        status=$(${DOCKER_SUDO} docker inspect --format='{{.State.Status}}' $service 2>/dev/null || echo "not-found")
        if [[ "$status" == "running" ]]; then
            echo "🟢 $service: $status (no healthcheck)"
        else
            echo "🔴 $service: $status"
        fi
    else
        echo "🔴 $service: $health"
    fi
done
echo

# 系统资源
echo "=== 💻 系统资源 ==="
echo "CPU使用率:"
top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//' || echo "无法获取"

echo "内存使用:"
free -h | awk 'NR==2{printf "使用: %s/%s (%.1f%%)\n", $3,$2,$3*100/$2}'

echo "磁盘使用:"
df -h "$PROJECT_DIR" | awk 'NR==2{printf "使用: %s/%s (%s)\n", $3,$2,$5}'

echo

# 网络检查
echo "=== 🌐 网络检查 ==="
DOMAIN=$(grep "server_name" nginx.conf | head -1 | awk '{print $2}' | sed 's/;//')

echo "测试HTTP重定向:"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN" 2>/dev/null || echo "连接失败")
echo "HTTP状态码: $HTTP_CODE"

echo "测试HTTPS访问:"
HTTPS_CODE=$(curl -s -k -o /dev/null -w "%{http_code}" "https://$DOMAIN" 2>/dev/null || echo "连接失败")
echo "HTTPS状态码: $HTTPS_CODE"

echo

# SSL证书状态
echo "=== 🔒 SSL证书状态 ==="
if [[ -f "/etc/letsencrypt/live/$DOMAIN/cert.pem" ]]; then
    CERT_EXPIRY=$(sudo openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/cert.pem" -noout -enddate | cut -d= -f2)
    DAYS_LEFT=$(( ($(date -d "$CERT_EXPIRY" +%s) - $(date +%s)) / 86400 ))
    echo "证书有效期至: $CERT_EXPIRY"
    echo "剩余天数: $DAYS_LEFT 天"
    if [[ $DAYS_LEFT -lt 30 ]]; then
        echo "⚠️ 证书即将过期，建议手动续期"
    fi
else
    echo "❌ 未找到SSL证书"
fi

echo
echo "=========================================="
echo "📊 检查完成 - $(date)"
echo "=========================================="
EOF

    # 创建备份脚本
    cat > backup.sh << 'EOF'
#!/bin/bash
# Seafile数据备份脚本

set -e

PROJECT_DIR="$HOME/seafile-docker"
BACKUP_DIR="$HOME/seafile-backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="seafile-backup-$TIMESTAMP.tar.gz"

cd "$PROJECT_DIR"

# 检测是否需要sudo执行docker命令
if ! docker ps &>/dev/null; then
    DOCKER_SUDO="sudo"
else
    DOCKER_SUDO=""
fi

echo "=========================================="
echo "💾 Seafile 数据备份"
echo "=========================================="
echo "开始时间: $(date)"
echo "备份目录: $BACKUP_DIR"
echo "备份文件: $BACKUP_FILE"
echo

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 停止服务（可选，注释掉以实现热备份）
# echo "停止服务..."
# ${DOCKER_SUDO} docker-compose stop

echo "创建备份..."

# 备份数据和配置
tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
    --exclude=data/mysql-data/binlog* \
    --exclude=data/mysql-data/mysql \
    --exclude=data/mysql-data/performance_schema \
    --exclude=data/mysql-data/information_schema \
    --exclude=data/mysql-data/sys \
    --exclude=logs \
    data/ \
    docker-compose.yml \
    nginx.conf \
    .env 2>/dev/null || true

# 重启服务（如果之前停止了）
# echo "重启服务..."
# ${DOCKER_SUDO} docker-compose start

# 计算备份大小
BACKUP_SIZE=$(du -h "$BACKUP_DIR/$BACKUP_FILE" | cut -f1)

echo "备份完成!"
echo "文件大小: $BACKUP_SIZE"
echo "保存路径: $BACKUP_DIR/$BACKUP_FILE"

# 清理旧备份（保留最近10个）
echo
echo "清理旧备份..."
cd "$BACKUP_DIR"
ls -t seafile-backup-*.tar.gz 2>/dev/null | tail -n +11 | xargs rm -f
REMAINING_BACKUPS=$(ls -1 seafile-backup-*.tar.gz 2>/dev/null | wc -l)
echo "保留备份数: $REMAINING_BACKUPS"

echo
echo "=========================================="
echo "✅ 备份完成 - $(date)"
echo "=========================================="
EOF

    # 创建日志查看脚本
    cat > logs.sh << 'EOF'
#!/bin/bash
# Seafile日志查看脚本

PROJECT_DIR="$HOME/seafile-docker"
cd "$PROJECT_DIR"

# 检测是否需要sudo执行docker命令
if ! docker ps &>/dev/null; then
    DOCKER_SUDO="sudo"
else
    DOCKER_SUDO=""
fi

echo "=========================================="
echo "📋 Seafile 日志查看"
echo "=========================================="
echo

case "${1:-all}" in
    "mysql"|"db")
        echo "=== MySQL 日志 ==="
        ${DOCKER_SUDO} docker-compose logs -f seafile-mysql
        ;;
    "seafile"|"app")
        echo "=== Seafile 应用日志 ==="
        ${DOCKER_SUDO} docker-compose logs -f seafile
        ;;
    "nginx"|"web")
        echo "=== Nginx 日志 ==="
        ${DOCKER_SUDO} docker-compose logs -f nginx
        ;;
    "memcached"|"cache")
        echo "=== Memcached 日志 ==="
        ${DOCKER_SUDO} docker-compose logs -f seafile-memcached
        ;;
    "all"|*)
        echo "=== 所有服务日志 ==="
        echo "使用 Ctrl+C 停止查看"
        echo
        ${DOCKER_SUDO} docker-compose logs -f
        ;;
esac
EOF

    # 创建更新脚本
    cat > update.sh << 'EOF'
#!/bin/bash
# Seafile更新脚本

set -e

PROJECT_DIR="$HOME/seafile-docker"
cd "$PROJECT_DIR"

# 检测是否需要sudo执行docker命令
if ! docker ps &>/dev/null; then
    DOCKER_SUDO="sudo"
else
    DOCKER_SUDO=""
fi

echo "=========================================="
echo "🔄 Seafile 更新"
echo "=========================================="
echo

# 创建备份
echo "1. 创建更新前备份..."
./backup.sh

echo
echo "2. 拉取最新镜像..."
${DOCKER_SUDO} docker-compose pull

echo
echo "3. 停止服务..."
${DOCKER_SUDO} docker-compose down

echo
echo "4. 启动服务..."
${DOCKER_SUDO} docker-compose up -d

echo
echo "5. 等待服务启动..."
sleep 30

echo
echo "6. 检查服务状态..."
${DOCKER_SUDO} docker-compose ps

echo
echo "=========================================="
echo "✅ 更新完成 - $(date)"
echo "=========================================="
echo
echo "如果遇到问题，可以使用备份恢复:"
echo "  1. docker-compose down"
echo "  2. 恢复data目录"
echo "  3. docker-compose up -d"
EOF

    # 创建卸载脚本
    cat > uninstall.sh << 'EOF'
#!/bin/bash
# Seafile卸载脚本

PROJECT_DIR="$HOME/seafile-docker"

# 检测是否需要sudo执行docker命令
if ! docker ps &>/dev/null; then
    DOCKER_SUDO="sudo"
else
    DOCKER_SUDO=""
fi

echo "=========================================="
echo "🗑️  Seafile 卸载"
echo "=========================================="
echo "⚠️ 这将删除所有Seafile数据和配置!"
echo "建议在卸载前运行 ./backup.sh 创建备份"
echo

read -p "确认要卸载Seafile吗? (yes/NO): " confirm
if [[ "$confirm" != "yes" ]]; then
    echo "取消卸载"
    exit 0
fi

read -p "是否同时删除所有数据? (yes/NO): " delete_data
echo

cd "$PROJECT_DIR" 2>/dev/null || {
    echo "项目目录不存在，可能已经卸载"
    exit 0
}

echo "停止并删除容器..."
${DOCKER_SUDO} docker-compose down -v

echo "删除镜像..."
${DOCKER_SUDO} docker rmi seafileltd/seafile-mc:11.0-latest mysql:8.0 memcached:1.6-alpine nginx:alpine 2>/dev/null || true

if [[ "$delete_data" == "yes" ]]; then
    echo "删除项目目录..."
    cd "$HOME"
    rm -rf "$PROJECT_DIR"
    DOMAIN=$(grep server_name "$PROJECT_DIR/nginx.conf" 2>/dev/null | head -1 | awk '{print $2}' | sed 's/;//' || echo "")
    if [[ -n "$DOMAIN" ]]; then
        echo "删除SSL证书..."
        sudo rm -rf "/etc/letsencrypt/live/$DOMAIN" 2>/dev/null || true
    fi
fi

echo "删除定时任务..."
crontab -l 2>/dev/null | grep -v "$PROJECT_DIR/renew-cert.sh" | crontab - 2>/dev/null || true

echo
echo "=========================================="
echo "✅ 卸载完成"
echo "=========================================="
EOF

    # 设置执行权限
    chmod +x status.sh backup.sh logs.sh update.sh uninstall.sh

    # 创建README文件
    cat > README.md << EOF
# Seafile Docker 安装

这是一个自动生成的Seafile Docker项目，运行在 ${OS_ID} ${OS_VERSION_ID} 系统上。

## 🚀 快速开始

\`\`\`bash
# 查看状态
./status.sh

# 查看日志
./logs.sh

# 重启服务
docker-compose restart

# 停止服务
docker-compose down

# 启动服务  
docker-compose up -d
\`\`\`

## 📊 管理脚本

- \`status.sh\` - 检查系统状态
- \`backup.sh\` - 备份数据
- \`logs.sh [service]\` - 查看日志
- \`update.sh\` - 更新Seafile
- \`uninstall.sh\` - 卸载Seafile
- \`renew-cert.sh\` - 续期SSL证书
- \`test-renewal.sh\` - 测试证书续期

## 📁 目录结构

\`\`\`
seafile-docker/
├── docker-compose.yml  # Docker编排文件
├── nginx.conf          # Nginx配置
├── .env               # 环境变量
├── data/              # 数据目录
│   ├── seafile-data/  # Seafile数据
│   └── mysql-data/    # 数据库数据
├── logs/              # 日志目录
└── *.sh               # 管理脚本
\`\`\`

## 🔧 常用命令

\`\`\`bash
# 查看容器状态
docker-compose ps

# 进入容器
docker-compose exec seafile bash
docker-compose exec seafile-mysql mysql -u root -p

# 查看实时日志
docker-compose logs -f

# 重建容器
docker-compose up -d --force-recreate

# 清理无用资源
docker system prune -f
\`\`\`

## 🆘 故障排除

1. **容器启动失败**: 检查 \`docker-compose logs\`
2. **无法访问网站**: 检查域名解析和防火墙
3. **SSL证书问题**: 运行 \`sudo certbot certificates\`
4. **数据库连接错误**: 检查 \`.env\` 文件中的密码

## 📞 获取帮助

- 查看日志: \`./logs.sh\`
- 检查状态: \`./status.sh\`
- 官方文档: https://manual.seafile.com/

## 系统信息

- 操作系统: ${OS_ID} ${OS_VERSION_ID} (${OS_CODENAME})
- 安装时间: $(date)
- 脚本版本: ${SCRIPT_VERSION}
EOF

    log_success "✅ 管理脚本创建完成"
    echo
    log_info "📝 可用的管理脚本:"
    echo "  ./status.sh      - 系统状态检查"
    echo "  ./backup.sh      - 数据备份" 
    echo "  ./logs.sh        - 日志查看"
    echo "  ./update.sh      - 系统更新"
    echo "  ./uninstall.sh   - 系统卸载"
}

# 显示完成信息
show_completion_info() {
    clear
    echo -e "${GREEN}"
    echo "=========================================="
    echo "🎉 Seafile Docker 安装成功!"
    echo "=========================================="
    echo -e "${NC}"
    
    echo -e "${CYAN}📍 访问信息${NC}"
    echo "🌐 网站地址: https://$DOMAIN"
    echo "👤 管理员邮箱: $SEAFILE_ADMIN_EMAIL"
    echo "🔑 管理员密码: [您设置的密码]"
    echo
    
    echo -e "${CYAN}📂 安装信息${NC}"
    echo "📁 项目目录: $PROJECT_DIR"
    echo "🐳 容器数量: 4个 (MySQL + Memcached + Seafile + Nginx)"
    echo "💾 数据目录: $PROJECT_DIR/data"
    echo "📝 日志目录: $PROJECT_DIR/logs"
    echo "🖥️  运行系统: $OS_ID $OS_VERSION_ID ($OS_CODENAME)"
    echo
    
    echo -e "${CYAN}⚙️ 管理命令${NC}"
    echo "查看状态: cd $PROJECT_DIR && ./status.sh"
    echo "查看日志: cd $PROJECT_DIR && ./logs.sh"
    echo "重启服务: cd $PROJECT_DIR && docker-compose restart"
    echo "停止服务: cd $PROJECT_DIR && docker-compose down"
    echo "备份数据: cd $PROJECT_DIR && ./backup.sh"
    echo "更新系统: cd $PROJECT_DIR && ./update.sh"
    echo
    
    echo -e "${CYAN}🔐 SSL证书${NC}"
    echo "🔒 自动续期已配置 (每周一 03:00)"
    echo "📅 续期日志: /var/log/seafile-cert-renewal.log"
    echo "🧪 测试续期: cd $PROJECT_DIR && ./test-renewal.sh"
    echo
    
    echo -e "${CYAN}💡 使用提示${NC}"
    echo "1. 首次访问可能需要等待1-2分钟完成初始化"
    echo "2. 如果无法访问，请检查域名解析和防火墙设置"
    echo "3. 建议定期运行 ./backup.sh 备份重要数据"
    echo "4. 查看详细文档: $PROJECT_DIR/README.md"
    echo
    
    # 最终检查
    log_step "🔍 最终连接测试..."
    
    sleep 5
    
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN" 2>/dev/null || echo "000")
    HTTPS_STATUS=$(curl -s -k -o /dev/null -w "%{http_code}" "https://$DOMAIN" 2>/dev/null || echo "000")
    
    echo -e "${CYAN}🌐 连接测试结果${NC}"
    if [[ "$HTTP_STATUS" =~ ^(301|302)$ ]]; then
        echo "✅ HTTP重定向: $HTTP_STATUS (正常)"
    else
        echo "⚠️ HTTP状态: $HTTP_STATUS"
    fi
    
    if [[ "$HTTPS_STATUS" =~ ^(200|302|301)$ ]]; then
        echo "✅ HTTPS访问: $HTTPS_STATUS (正常)"
    else
        echo "⚠️ HTTPS状态: $HTTPS_STATUS (可能还在初始化中)"
    fi
    
    echo
    echo -e "${GREEN}=========================================="
    echo "🚀 开始享受您的私人云存储吧!"
    echo "==========================================${NC}"
    echo
    
    # 提示用户记录密码
    echo -e "${YELLOW}⚠️ 重要提醒:${NC}"
    echo "请务必记录以下信息并妥善保管:"
    echo "- 网站地址: https://$DOMAIN"  
    echo "- 管理员邮箱: $SEAFILE_ADMIN_EMAIL"
    echo "- 管理员密码: [您刚才设置的密码]"
    echo "- 项目目录: $PROJECT_DIR"
    echo
    
    # 显示下一步操作建议
    echo -e "${CYAN}📋 建议的下一步操作:${NC}"
    echo "1. 访问 https://$DOMAIN 并登录"
    echo "2. 创建资料库并上传测试文件"
    echo "3. 运行 ./backup.sh 创建初始备份"
    echo "4. 阅读 README.md 了解更多功能"
    echo
}

# 错误处理函数
handle_error() {
    local exit_code=$?
    log_error "❌ 脚本执行失败 (退出码: $exit_code)"
    log_error "错误发生在第 $1 行"
    
    echo
    echo "🔧 故障排除建议:"
    echo "1. 检查错误信息并根据提示解决"
    echo "2. 确保域名已正确解析到服务器"
    echo "3. 检查网络连接和防火墙设置"
    echo "4. 对于Debian系统，确保使用正确的软件源"
    echo "5. 查看详细日志: $PROJECT_DIR/logs.sh"
    echo "6. 如需帮助，请保存上述错误信息"
    
    exit $exit_code
}

# 主函数
main() {
    # 设置错误处理
    trap 'handle_error $LINENO' ERR
    
    # 显示横幅
    show_banner
    
    # 确认继续
    read -p "按回车键开始安装，或按 Ctrl+C 取消: "
    
    # 执行安装步骤
    log_step "🔧 开始安装流程..."
    
    check_root
    check_system
    get_user_input
    install_dependencies
    install_docker
    create_project
    setup_ssl
    create_renewal_script
    start_services
    verify_installation
    create_management_scripts
    show_completion_info
    
    # 保存安装信息
    cat > "$PROJECT_DIR/install-info.txt" << EOF
Seafile Docker 安装信息
========================
安装时间: $(date)
域名: $DOMAIN
管理员邮箱: $SEAFILE_ADMIN_EMAIL
项目目录: $PROJECT_DIR
脚本版本: $SCRIPT_VERSION
系统信息: $OS_ID $OS_VERSION_ID ($OS_CODENAME)
Docker版本: $(docker --version)
=========================================
EOF
    
    log_success "🎉 安装完成！感谢使用 Seafile Docker 安装脚本！"
}

# 运行主函数
main "$@"
