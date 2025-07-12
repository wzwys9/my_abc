#!/bin/bash

# Seafile Docker Root权限一键安装脚本
# 适用于 Debian/Ubuntu 系列发行版
# 必须以root权限运行
# GitHub: https://github.com/wzwys9/my_abc
# 版本: 2.0 (Root专用版本)
# 更新日期: 2025-07-11

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
SCRIPT_VERSION="2.0"
PROJECT_DIR="/opt/seafile-docker"
DOMAIN=""
EMAIL=""
MYSQL_ROOT_PASSWORD=""
MYSQL_SEAFILE_PASSWORD=""
SEAFILE_ADMIN_EMAIL=""
SEAFILE_ADMIN_PASSWORD=""
OS_ID=""
OS_VERSION_ID=""
OS_CODENAME=""

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

# 显示横幅
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "=================================================="
    echo "🐳 Seafile Docker Root一键安装脚本 v${SCRIPT_VERSION}"
    echo "=================================================="
    echo -e "${NC}"
    echo "此脚本将自动为您安装："
    echo "  🐳 Docker & Docker Compose"
    echo "  🗃️  Seafile + MySQL + Memcached"
    echo "  🔒 Nginx反向代理 + SSL证书"
    echo "  ⚙️  自动化管理脚本"
    echo
    echo "支持系统: Debian 11+, Ubuntu 20.04+"
    echo "安装位置: /opt/seafile-docker"
    echo "预计用时: 15-25分钟"
    echo "=================================================="
    echo
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "❌ 此脚本必须以root权限运行！"
        log_info "请使用以下方式运行："
        echo "  sudo bash $0"
        echo "  或者切换到root用户: su -"
        exit 1
    fi
    log_success "✅ Root权限检查通过"
}

# 检测操作系统信息
detect_os() {
    if ! command -v lsb_release &> /dev/null; then
        apt-get update
        apt-get install -y lsb-release
    fi

    OS_ID=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    OS_VERSION_ID=$(lsb_release -sr)
    OS_CODENAME=$(lsb_release -sc)
}

# 检查系统版本
check_system() {
    log_step "🔍 检查系统环境..."
    
    detect_os
    
    case "$OS_ID" in
        "ubuntu")
            if [[ ! "$OS_VERSION_ID" =~ ^(20\.04|22\.04|24\.04) ]]; then
                log_warn "⚠️ Ubuntu版本 $OS_VERSION_ID 未经测试"
            fi
            ;;
        "debian")
            case "$OS_VERSION_ID" in
                "11"|"12")
                    log_info "✅ 支持的Debian版本: $OS_VERSION_ID ($OS_CODENAME)"
                    ;;
                *)
                    log_warn "⚠️ Debian版本 $OS_VERSION_ID 未经测试"
                    ;;
            esac
            ;;
        *)
            log_error "❌ 不支持的操作系统: $OS_ID"
            exit 1
            ;;
    esac
    
    # 检查内存
    TOTAL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    if [[ $TOTAL_MEM -lt 1500 ]]; then
        log_warn "⚠️ 系统内存不足2GB ($TOTAL_MEM MB)"
    fi
    
    log_success "✅ 系统环境检查通过: $OS_ID $OS_VERSION_ID"
    log_info "📊 系统信息: 内存 ${TOTAL_MEM}MB"
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
        if [[ $DOMAIN =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            break
        else
            log_error "域名格式不正确"
        fi
    done
    
    # SSL证书邮箱
    while true; do
        read -p "📧 请输入邮箱地址 (用于SSL证书): " EMAIL
        if [[ -z "$EMAIL" ]]; then
            log_error "邮箱不能为空"
            continue
        fi
        if [[ $EMAIL =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            log_error "邮箱格式不正确"
        fi
    done
    
    # 管理员邮箱
    SEAFILE_ADMIN_EMAIL="admin@${DOMAIN}"
    read -p "👤 Seafile管理员邮箱 (默认: $SEAFILE_ADMIN_EMAIL): " input_admin_email
    if [[ -n "$input_admin_email" && $input_admin_email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        SEAFILE_ADMIN_EMAIL="$input_admin_email"
    fi
    
    # 生成随机密码选项
    echo
    log_info "🔐 密码配置"
    read -p "是否自动生成随机密码? (y/N): " auto_password
    
    if [[ $auto_password =~ ^[Yy]$ ]]; then
        MYSQL_ROOT_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
        MYSQL_SEAFILE_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
        SEAFILE_ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
        
        log_info "✅ 已生成随机密码"
    else
        # 手动输入密码
        while true; do
            read -s -p "🗃️  MySQL root密码 (最少8位): " MYSQL_ROOT_PASSWORD
            echo
            if [[ ${#MYSQL_ROOT_PASSWORD} -ge 8 ]]; then break; fi
            log_error "密码长度至少8位"
        done
        
        while true; do
            read -s -p "🗃️  MySQL seafile用户密码 (最少8位): " MYSQL_SEAFILE_PASSWORD
            echo
            if [[ ${#MYSQL_SEAFILE_PASSWORD} -ge 8 ]]; then break; fi
            log_error "密码长度至少8位"
        done
        
        while true; do
            read -s -p "👤 Seafile管理员密码 (最少8位): " SEAFILE_ADMIN_PASSWORD
            echo
            if [[ ${#SEAFILE_ADMIN_PASSWORD} -ge 8 ]]; then break; fi
            log_error "密码长度至少8位"
        done
    fi
    
    echo
    log_info "📋 配置信息确认:"
    echo "  🌐 域名: $DOMAIN"
    echo "  📧 SSL邮箱: $EMAIL"
    echo "  👤 管理员邮箱: $SEAFILE_ADMIN_EMAIL"
    echo "  📁 安装位置: $PROJECT_DIR"
    echo "  🖥️  系统: $OS_ID $OS_VERSION_ID"
    echo
    
    read -p "✅ 确认以上信息正确吗? (y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        log_info "安装已取消"
        exit 0
    fi
    
    log_success "✅ 配置信息收集完成"
}

# 全局清理
global_cleanup() {
    log_info "🧹 执行环境清理..."
    
    # 清理容器
    for cmd in "docker" "systemctl"; do
        case $cmd in
            docker)
                docker stop temp-nginx nginx-temp seafile-temp 2>/dev/null || true
                docker rm temp-nginx nginx-temp seafile-temp 2>/dev/null || true
                docker system prune -f 2>/dev/null || true
                ;;
            systemctl)
                systemctl stop nginx apache2 httpd lighttpd 2>/dev/null || true
                ;;
        esac
    done
    
    # 清理文件
    rm -f temp-nginx.conf nginx-temp.conf 2>/dev/null || true
    
    # 清理进程
    pkill -f "nginx.*temp" 2>/dev/null || true
    pkill -f "certbot.*standalone" 2>/dev/null || true
    pkill -f "acme.*daemon" 2>/dev/null || true
    
    # 清理端口
    for port in 80 443; do
        if netstat -tlpn 2>/dev/null | grep ":$port " >/dev/null 2>&1; then
            PORT_PIDS=$(netstat -tlpn | grep ":$port " | awk '{print $7}' | cut -d'/' -f1 | grep -v "^-$" | sort -u)
            for pid in $PORT_PIDS; do
                if [[ -n "$pid" && "$pid" != "-" ]]; then
                    kill -9 "$pid" 2>/dev/null || true
                fi
            done
        fi
    done
    
    log_success "✅ 环境清理完成"
}

# 安装系统依赖
install_dependencies() {
    log_step "📦 安装系统依赖..."
    
    apt-get update
    apt-get install -y \
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
    
    if command -v docker &> /dev/null; then
        log_info "Docker已安装，跳过安装"
    else
        # 删除旧版本
        apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        
        # 配置Docker仓库
        case "$OS_ID" in
            "ubuntu")
                curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
                ;;
            "debian")
                curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
                ;;
        esac
        
        # 安装Docker
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        
        # 启动Docker
        systemctl start docker
        systemctl enable docker
    fi
    
    # 安装Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d '"' -f 4)
        curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
    fi
    
    log_success "✅ Docker环境准备完成"
}

# 创建项目目录和配置
create_project() {
    log_step "📁 创建项目配置..."
    
    # 如果目录存在，清理
    if [[ -d "$PROJECT_DIR" ]]; then
        log_warn "⚠️ 项目目录已存在，将清理重建"
        rm -rf "$PROJECT_DIR"
    fi
    
    # 创建目录结构
    mkdir -p "$PROJECT_DIR"/{data/{seafile-data,mysql-data},logs,ssl}
    cd "$PROJECT_DIR"
    
    # 创建docker-compose.yml
    cat > docker-compose.yml << EOF
version: '3.8'

services:
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

  seafile-memcached:
    image: memcached:1.6-alpine
    container_name: seafile-memcached
    command: memcached -m 256 -I 10m
    networks:
      - seafile-net
    restart: unless-stopped

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
    networks:
      - seafile-net
    restart: unless-stopped

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
    depends_on:
      - seafile
    networks:
      - seafile-net
    restart: unless-stopped

networks:
  seafile-net:
    driver: bridge
EOF

    # 创建nginx.conf
    cat > nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    sendfile on;
    keepalive_timeout 65;
    client_max_body_size 1G;
    
    # HTTP重定向到HTTPS
    server {
        listen 80;
        server_name DOMAIN_PLACEHOLDER;
        return 301 https://$server_name$request_uri;
    }

    # HTTPS配置
    server {
        listen 443 ssl http2;
        server_name DOMAIN_PLACEHOLDER;

        ssl_certificate /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/privkey.pem;
        
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;

        # 安全头
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options DENY;

        location / {
            proxy_pass http://seafile:80;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_read_timeout 1200s;
        }

        location /seafhttp {
            proxy_pass http://seafile:8082;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_request_buffering off;
        }
    }
}
EOF

    # 替换域名占位符
    sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" nginx.conf
    
    # 创建环境变量文件
    cat > .env << EOF
# Seafile Docker Root安装配置
DOMAIN=$DOMAIN
EMAIL=$EMAIL
MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASSWORD
MYSQL_SEAFILE_PASSWORD=$MYSQL_SEAFILE_PASSWORD
SEAFILE_ADMIN_EMAIL=$SEAFILE_ADMIN_EMAIL
SEAFILE_ADMIN_PASSWORD=$SEAFILE_ADMIN_PASSWORD
PROJECT_DIR=$PROJECT_DIR
INSTALL_TIME=$(date)
EOF

    chmod 600 .env
    
    log_success "✅ 项目配置创建完成"
}

# SSL证书配置
setup_ssl() {
    log_step "🔒 配置SSL证书..."
    
    # 清理旧的SSL工具
    apt-get remove -y certbot python3-certbot* 2>/dev/null || true
    snap remove certbot 2>/dev/null || true
    
    echo
    log_info "📋 SSL证书获取方式："
    echo "1. 使用acme.sh自动获取（推荐）"
    echo "2. 创建自签名证书（测试用）"
    echo "3. 稍后手动配置"
    echo
    
    read -p "请选择 (1-3，默认为1): " ssl_choice
    ssl_choice=${ssl_choice:-1}
    
    case $ssl_choice in
        1)
            # 使用acme.sh
            log_info "安装acme.sh..."
            curl -s https://get.acme.sh | sh -s email="$EMAIL"
            
            # 设置环境
            export PATH="/root/.acme.sh:$PATH"
            source /root/.acme.sh/acme.sh.env 2>/dev/null || true
            
            mkdir -p "/etc/letsencrypt/live/$DOMAIN"
            
            log_info "获取SSL证书..."
            if /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --force; then
                # 安装证书
                /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
                    --cert-file "/etc/letsencrypt/live/$DOMAIN/cert.pem" \
                    --key-file "/etc/letsencrypt/live/$DOMAIN/privkey.pem" \
                    --fullchain-file "/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
                
                log_success "✅ SSL证书获取成功"
            else
                log_warn "⚠️ acme.sh失败，使用自签名证书"
                ssl_choice=2
            fi
            ;;
        2|*)
            # 创建自签名证书
            log_info "创建自签名证书..."
            mkdir -p "/etc/letsencrypt/live/$DOMAIN"
            
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "/etc/letsencrypt/live/$DOMAIN/privkey.pem" \
                -out "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" \
                -subj "/C=CN/ST=State/L=City/O=Seafile/CN=$DOMAIN"
            
            cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "/etc/letsencrypt/live/$DOMAIN/cert.pem"
            
            log_warn "⚠️ 使用自签名证书，浏览器会显示安全警告"
            ;;
    esac
    
    # 设置证书权限
    chown -R root:root "/etc/letsencrypt/live/$DOMAIN"
    chmod 644 "/etc/letsencrypt/live/$DOMAIN"/*.pem
    chmod 600 "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    
    log_success "✅ SSL配置完成"
}

# 启动服务
start_services() {
    log_step "🚀 启动Seafile服务..."
    
    cd "$PROJECT_DIR"
    
    # 拉取镜像
    log_info "拉取Docker镜像..."
    docker-compose pull
    
    # 启动服务
    log_info "启动服务..."
    docker-compose up -d
    
    # 等待服务启动
    log_info "等待服务启动完成..."
    sleep 60
    
    # 检查状态
    log_info "检查服务状态..."
    docker-compose ps
    
    log_success "✅ 服务启动完成"
}

# 创建管理脚本
create_management_scripts() {
    log_step "⚙️ 创建管理脚本..."
    
    cd "$PROJECT_DIR"
    
    # 状态检查脚本
    cat > status.sh << 'EOF'
#!/bin/bash
cd /opt/seafile-docker
echo "=== Seafile服务状态 ==="
docker-compose ps
echo
echo "=== 系统资源 ==="
free -h
df -h /opt/seafile-docker
EOF

    # 重启脚本
    cat > restart.sh << 'EOF'
#!/bin/bash
cd /opt/seafile-docker
echo "重启Seafile服务..."
docker-compose restart
echo "服务重启完成"
EOF

    # 备份脚本
    cat > backup.sh << 'EOF'
#!/bin/bash
cd /opt/seafile-docker
BACKUP_DIR="/opt/seafile-backups"
BACKUP_FILE="seafile-backup-$(date +%Y%m%d-%H%M%S).tar.gz"

mkdir -p "$BACKUP_DIR"
echo "创建备份: $BACKUP_FILE"

tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
    --exclude=data/mysql-data/mysql \
    --exclude=data/mysql-data/performance_schema \
    --exclude=data/mysql-data/information_schema \
    --exclude=logs \
    data/ docker-compose.yml nginx.conf .env

echo "备份完成: $BACKUP_DIR/$BACKUP_FILE"
EOF

    # 设置权限
    chmod +x status.sh restart.sh backup.sh
    
    # 创建systemd服务
    cat > /etc/systemd/system/seafile-docker.service << EOF
[Unit]
Description=Seafile Docker
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable seafile-docker
    
    log_success "✅ 管理脚本创建完成"
}

# 显示完成信息
show_completion_info() {
    clear
    echo -e "${GREEN}"
    echo "=========================================="
    echo "🎉 Seafile Docker安装成功！"
    echo "=========================================="
    echo -e "${NC}"
    
    echo -e "${CYAN}📍 访问信息${NC}"
    echo "🌐 网站地址: https://$DOMAIN"
    echo "👤 管理员邮箱: $SEAFILE_ADMIN_EMAIL"
    echo "🔑 管理员密码: $SEAFILE_ADMIN_PASSWORD"
    echo
    
    echo -e "${CYAN}📂 安装信息${NC}"
    echo "📁 项目目录: $PROJECT_DIR"
    echo "📊 数据目录: $PROJECT_DIR/data"
    echo "📝 日志目录: $PROJECT_DIR/logs"
    echo "📋 配置文件: $PROJECT_DIR/.env"
    echo
    
    echo -e "${CYAN}⚙️ 管理命令${NC}"
    echo "查看状态: cd $PROJECT_DIR && ./status.sh"
    echo "重启服务: cd $PROJECT_DIR && ./restart.sh"
    echo "备份数据: cd $PROJECT_DIR && ./backup.sh"
    echo "查看日志: cd $PROJECT_DIR && docker-compose logs -f"
    echo
    
    echo -e "${CYAN}🔧 系统管理${NC}"
    echo "启动服务: systemctl start seafile-docker"
    echo "停止服务: systemctl stop seafile-docker"
    echo "服务状态: systemctl status seafile-docker"
    echo
    
    # 保存密码信息
    cat > "$PROJECT_DIR/passwords.txt" << EOF
Seafile Docker 密码信息
=====================
生成时间: $(date)

域名: $DOMAIN
管理员邮箱: $SEAFILE_ADMIN_EMAIL
管理员密码: $SEAFILE_ADMIN_PASSWORD

MySQL Root密码: $MYSQL_ROOT_PASSWORD
MySQL Seafile密码: $MYSQL_SEAFILE_PASSWORD

SSL邮箱: $EMAIL
=====================
EOF
    
    chmod 600 "$PROJECT_DIR/passwords.txt"
    
    echo -e "${YELLOW}⚠️ 重要提醒:${NC}"
    echo "1. 密码信息已保存到: $PROJECT_DIR/passwords.txt"
    echo "2. 请妥善保管密码信息"
    echo "3. 建议定期运行备份脚本"
    echo "4. 首次访问可能需要等待1-2分钟"
    echo
    
    echo -e "${GREEN}🎉 安装完成！现在可以访问您的Seafile了！${NC}"
}

# 主函数
main() {
    # 显示横幅
    show_banner
    
    # 确认继续
    read -p "按回车键开始安装，或按 Ctrl+C 取消: "
    
    # 执行安装步骤
    check_root
    global_cleanup
    check_system
    get_user_input
    install_dependencies
    install_docker
    create_project
    setup_ssl
    start_services
    create_management_scripts
    show_completion_info
    
    log_success "🎉 Seafile Docker Root安装完成！"
}

# 错误处理
handle_error() {
    local exit_code=$?
    log_error "❌ 安装失败 (退出码: $exit_code)"
    log_error "错误发生在第 $1 行"
    
    echo
    echo "🔧 故障排除:"
    echo "1. 检查网络连接"
    echo "2. 确保域名解析正确"
    echo "3. 检查防火墙设置"
    echo "4. 查看详细日志"
    
    # 清理
    global_cleanup
    exit $exit_code
}

# 设置错误处理
trap 'handle_error $LINENO' ERR

# 运行主函数
main "$@"
