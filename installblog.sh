#!/bin/bash

# ============================================
# WordPress 博客一键部署脚本
# 完全交互式，无敏感信息硬编码
# ============================================
#
# 📖 使用方法：
#   1. 下载脚本：
#      wget https://raw.githubusercontent.com/你的用户名/仓库名/main/setup.sh
#   
#   2. 添加执行权限：
#      chmod +x setup.sh
#   
#   3. 以 root 权限运行：
#      sudo ./setup.sh
#   
#   4. 按提示输入域名、邮箱和密码
#
# ✨ 功能特性：
#   - 自动安装 Docker 和 Docker Compose
#   - 自动申请 Let's Encrypt SSL 证书
#   - SSL 证书每周自动检查续期
#   - 完整的 WordPress + MySQL + Nginx 环境
#   - 交互式配置，无需修改脚本
#
# 📋 前置条件：
#   - Ubuntu/Debian Linux 系统
#   - 域名已配置 DNS A 记录指向服务器
#   - 开放 80 和 443 端口
#   - root 权限
#
# 🔧 部署后管理：
#   查看状态：  docker-compose ps
#   查看日志：  docker-compose logs -f
#   重启服务：  docker-compose restart
#   停止服务：  docker-compose down
#   启动服务：  docker-compose up -d
#
# ============================================

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印标题
print_header() {
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""
}

# 打印成功信息
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# 打印错误信息
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# 打印警告信息
print_warning() {
    echo -e "${YELLOW}! $1${NC}"
}

# 打印信息
print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# 检查命令是否存在
command_exists() {
    command -v "$1" &> /dev/null
}

# 安装 Docker
install_docker() {
    print_header "安装 Docker"
    
    if command_exists docker; then
        print_success "Docker 已安装"
        docker --version
    else
        print_info "开始安装 Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        rm get-docker.sh
        
        # 将当前用户加入 docker 组
        if [ -n "$SUDO_USER" ]; then
            usermod -aG docker $SUDO_USER
        else
            usermod -aG docker $USER
        fi
        
        print_success "Docker 安装完成"
        print_warning "请注销并重新登录以使 docker 组权限生效"
    fi
    echo ""
}

# 安装 Docker Compose
install_docker_compose() {
    print_header "安装 Docker Compose"
    
    if command_exists docker-compose; then
        print_success "Docker Compose 已安装"
        docker-compose --version
    else
        print_info "开始安装 Docker Compose..."
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        print_success "Docker Compose 安装完成"
        docker-compose --version
    fi
    echo ""
}

# 收集用户输入
collect_user_input() {
    print_header "配置信息收集"
    
    # 域名
    read -p "请输入你的域名（例如: blog.example.com）: " DOMAIN
    while [ -z "$DOMAIN" ]; do
        print_error "域名不能为空！"
        read -p "请输入你的域名: " DOMAIN
    done
    print_success "域名: $DOMAIN"
    echo ""
    
    # 邮箱
    read -p "请输入你的邮箱（用于 SSL 证书通知）: " EMAIL
    while [ -z "$EMAIL" ]; do
        print_error "邮箱不能为空！"
        read -p "请输入你的邮箱: " EMAIL
    done
    print_success "邮箱: $EMAIL"
    echo ""
    
    # MySQL Root 密码
    while true; do
        read -sp "请设置 MySQL Root 密码（至少8位）: " MYSQL_ROOT_PASSWORD
        echo ""
        if [ ${#MYSQL_ROOT_PASSWORD} -lt 8 ]; then
            print_error "密码至少需要8位！"
            continue
        fi
        read -sp "请再次输入 MySQL Root 密码: " MYSQL_ROOT_PASSWORD_CONFIRM
        echo ""
        if [ "$MYSQL_ROOT_PASSWORD" = "$MYSQL_ROOT_PASSWORD_CONFIRM" ]; then
            print_success "MySQL Root 密码设置完成"
            break
        else
            print_error "两次密码不一致，请重新输入！"
        fi
    done
    echo ""
    
    # WordPress 数据库密码
    while true; do
        read -sp "请设置 WordPress 数据库密码（至少8位）: " MYSQL_PASSWORD
        echo ""
        if [ ${#MYSQL_PASSWORD} -lt 8 ]; then
            print_error "密码至少需要8位！"
            continue
        fi
        read -sp "请再次输入 WordPress 数据库密码: " MYSQL_PASSWORD_CONFIRM
        echo ""
        if [ "$MYSQL_PASSWORD" = "$MYSQL_PASSWORD_CONFIRM" ]; then
            print_success "WordPress 数据库密码设置完成"
            break
        else
            print_error "两次密码不一致，请重新输入！"
        fi
    done
    echo ""
    
    # 确认信息
    print_header "请确认以下信息"
    echo "域名: $DOMAIN"
    echo "邮箱: $EMAIL"
    echo "MySQL Root 密码: ********"
    echo "WordPress 数据库密码: ********"
    echo ""
    
    read -p "确认无误？(y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        print_error "已取消部署"
        exit 1
    fi
    echo ""
}

# 创建目录结构
create_directories() {
    print_header "创建目录结构"
    
    mkdir -p nginx/conf.d
    mkdir -p nginx/ssl
    
    print_success "目录创建完成"
    echo ""
}

# 创建 docker-compose.yml
create_docker_compose() {
    print_header "创建 Docker Compose 配置"
    
    cat > docker-compose.yml <<EOF
services:
  # MySQL 数据库
  db:
    image: mysql:8.0
    container_name: blog_mysql
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
      TZ: Asia/Shanghai
    volumes:
      - db_data:/var/lib/mysql
    networks:
      - blog_network

  # WordPress 应用
  wordpress:
    image: wordpress:latest
    container_name: blog_wordpress
    restart: always
    depends_on:
      - db
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: ${MYSQL_PASSWORD}
      WORDPRESS_DB_NAME: wordpress
      TZ: Asia/Shanghai
    volumes:
      - wordpress_data:/var/www/html
    networks:
      - blog_network

  # Nginx 反向代理
  nginx:
    image: nginx:alpine
    container_name: blog_nginx
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d
      - ./nginx/ssl:/etc/nginx/ssl
      - wordpress_data:/var/www/html:ro
      - /root/letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - wordpress
    networks:
      - blog_network

volumes:
  db_data:
  wordpress_data:

networks:
  blog_network:
    driver: bridge
EOF
    
    print_success "docker-compose.yml 创建完成"
    echo ""
}

# 创建 Nginx 初始配置
create_nginx_config() {
    print_header "创建 Nginx 配置"
    
    cat > nginx/conf.d/blog.conf <<EOF
# HTTP 配置 - 临时使用
server {
    listen 80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://wordpress:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
    print_success "Nginx 初始配置创建完成"
    echo ""
}

# 创建 Nginx HTTPS 配置模板
create_nginx_ssl_config() {
    cat > nginx/conf.d/blog.conf <<EOF
# HTTP 重定向到 HTTPS
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

# HTTPS 配置
server {
    listen 443 ssl;
    http2 on;
    server_name ${DOMAIN};

    # SSL 证书
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    
    # SSL 安全配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # 安全头
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # 上传限制
    client_max_body_size 100M;

    # 代理配置
    location / {
        proxy_pass http://wordpress:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        
        # WebSocket 支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
}

# 检查 DNS 解析
check_dns() {
    print_header "检查 DNS 解析"
    
    print_info "正在检查域名 $DOMAIN 的 DNS 解析..."
    
    if command_exists dig; then
        DNS_IP=$(dig +short $DOMAIN | tail -n1)
    elif command_exists nslookup; then
        DNS_IP=$(nslookup $DOMAIN | grep -A1 "Name:" | tail -n1 | awk '{print $2}')
    else
        print_warning "未找到 dig 或 nslookup 命令，跳过 DNS 检查"
        return
    fi
    
    if [ -n "$DNS_IP" ]; then
        print_success "域名解析到: $DNS_IP"
        
        # 获取本机公网 IP
        SERVER_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "未知")
        print_info "服务器公网 IP: $SERVER_IP"
        
        if [ "$DNS_IP" != "$SERVER_IP" ] && [ "$SERVER_IP" != "未知" ]; then
            print_warning "DNS 解析的 IP ($DNS_IP) 与服务器 IP ($SERVER_IP) 不一致"
            print_warning "SSL 证书申请可能会失败，请确认 DNS 配置正确"
            read -p "是否继续？(y/n): " CONTINUE
            if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
                print_error "已取消部署"
                exit 1
            fi
        fi
    else
        print_warning "无法解析域名 $DOMAIN"
        print_warning "请确保 DNS 已正确配置并生效"
        read -p "是否继续？(y/n): " CONTINUE
        if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
            print_error "已取消部署"
            exit 1
        fi
    fi
    echo ""
}

# 启动 Docker 服务
start_docker_services() {
    print_header "启动 Docker 服务"
    
    docker-compose up -d
    
    print_success "Docker 服务已启动"
    echo ""
    
    print_info "等待服务初始化（30秒）..."
    sleep 30
    print_success "服务初始化完成"
    echo ""
}

# 申请 SSL 证书（使用 standalone 模式）
request_ssl_certificate() {
    print_header "申请 SSL 证书"
    
    print_info "正在向 Let's Encrypt 申请证书..."
    print_warning "此过程可能需要 1-3 分钟，请耐心等待"
    echo ""
    
    # 停止 Nginx 以释放 80 端口
    docker-compose stop nginx
    
    # 使用 standalone 模式申请证书
    if docker run --rm -it \
        -p 80:80 \
        -p 443:443 \
        -v /root/letsencrypt:/etc/letsencrypt \
        -v /root/letsencrypt-lib:/var/lib/letsencrypt \
        certbot/certbot certonly \
        --standalone \
        --email $EMAIL \
        --agree-tos \
        --no-eff-email \
        -d $DOMAIN; then
        
        print_success "SSL 证书申请成功！"
        
        # 设置证书文件权限
        chmod -R 755 /root/letsencrypt/archive/ 2>/dev/null || true
        chmod -R 755 /root/letsencrypt/live/ 2>/dev/null || true
        
        return 0
    else
        print_error "SSL 证书申请失败"
        
        echo ""
        print_warning "常见失败原因："
        echo "1. DNS 解析未生效 - 使用 'nslookup $DOMAIN' 检查"
        echo "2. 80 端口未开放 - 使用 'ufw allow 80' 开放端口"
        echo "3. Let's Encrypt 限流 - 同一域名每小时最多 5 次失败尝试"
        echo ""
        
        return 1
    fi
}

# 切换到 HTTPS 配置
switch_to_https() {
    print_header "启用 HTTPS"
    
    # 创建 HTTPS 配置
    create_nginx_ssl_config
    
    # 启动 Nginx
    docker-compose start nginx
    
    print_success "HTTPS 配置已启用"
    echo ""
}

# 创建证书自动续期脚本
create_renewal_script() {
    print_header "配置证书自动续期"
    
    cat > /root/renew-cert.sh <<'EOF'
#!/bin/bash
# SSL 证书自动续期脚本

cd /root

# 停止 Nginx（释放 80 端口）
docker-compose stop nginx

# 续期证书
docker run --rm \
  -p 80:80 \
  -p 443:443 \
  -v /root/letsencrypt:/etc/letsencrypt \
  -v /root/letsencrypt-lib:/var/lib/letsencrypt \
  certbot/certbot renew --quiet

# 启动 Nginx
docker-compose start nginx

echo "$(date): 证书续期检查完成" >> /var/log/certbot-renew.log
EOF
    
    chmod +x /root/renew-cert.sh
    
    # 添加到 cron（每周一凌晨 3 点检查）
    (crontab -l 2>/dev/null | grep -v renew-cert.sh; echo "0 3 * * 1 /root/renew-cert.sh >> /var/log/certbot-renew.log 2>&1") | crontab -
    
    print_success "证书自动续期已配置（每周一凌晨 3 点检查）"
    echo ""
}

# 显示部署结果
show_result() {
    print_header "部署完成"
    
    echo -e "${GREEN}🎉 恭喜！博客部署成功！${NC}"
    echo ""
    echo -e "${BLUE}访问地址:${NC} https://$DOMAIN"
    echo -e "${BLUE}管理后台:${NC} https://$DOMAIN/wp-admin"
    echo ""
    echo -e "${YELLOW}下一步操作:${NC}"
    echo "1. 访问 https://$DOMAIN 完成 WordPress 初始化"
    echo "2. 设置网站标题和管理员账户"
    echo "3. 安装主题和插件"
    echo ""
    echo -e "${YELLOW}常用命令:${NC}"
    echo "查看服务状态: docker-compose ps"
    echo "查看日志: docker-compose logs -f"
    echo "重启服务: docker-compose restart"
    echo "停止服务: docker-compose down"
    echo "备份数据库: docker-compose exec db mysqldump -u wordpress -p wordpress > backup.sql"
    echo ""
    echo -e "${GREEN}SSL 证书会每周自动检查更新，无需手动操作${NC}"
    echo ""
}

# 显示失败信息
show_failure() {
    print_header "部署失败"
    
    echo -e "${RED}SSL 证书申请失败，但服务已启动${NC}"
    echo ""
    echo -e "${YELLOW}可能的原因:${NC}"
    echo "1. DNS 解析未生效（需要等待几分钟到几小时）"
    echo "2. 80 端口未开放或被防火墙拦截"
    echo "3. 域名配置错误"
    echo ""
    echo -e "${YELLOW}临时访问地址:${NC} http://$DOMAIN"
    echo ""
    echo -e "${YELLOW}修复后手动申请证书:${NC}"
    echo "docker-compose stop nginx"
    echo "docker run --rm -it \\"
    echo "  -p 80:80 -p 443:443 \\"
    echo "  -v /root/letsencrypt:/etc/letsencrypt \\"
    echo "  -v /root/letsencrypt-lib:/var/lib/letsencrypt \\"
    echo "  certbot/certbot certonly --standalone \\"
    echo "  --email $EMAIL --agree-tos --no-eff-email -d $DOMAIN"
    echo ""
    echo "chmod -R 755 /root/letsencrypt/archive/"
    echo "chmod -R 755 /root/letsencrypt/live/"
    echo ""
    echo "然后创建 HTTPS 配置并启动："
    echo "./renew-cert.sh  # 或手动执行上面的命令"
    echo ""
}

# 主流程
main() {
    clear
    print_header "WordPress 博客一键部署脚本"
    
    # 检查是否为 root 用户
    if [ "$EUID" -ne 0 ]; then
        print_error "请使用 root 权限运行此脚本"
        echo "使用: sudo $0"
        exit 1
    fi
    
    # 安装依赖
    install_docker
    install_docker_compose
    
    # 收集用户输入
    collect_user_input
    
    # 检查 DNS
    check_dns
    
    # 创建配置文件
    create_directories
    create_docker_compose
    create_nginx_config
    
    # 启动服务
    start_docker_services
    
    # 申请 SSL 证书
    if request_ssl_certificate; then
        switch_to_https
        create_renewal_script
        show_result
    else
        # 即使证书申请失败，也启动 Nginx（使用 HTTP）
        docker-compose start nginx
        show_failure
    fi
}

# 执行主流程
main
