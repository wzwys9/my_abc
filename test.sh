#!/bin/bash

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
  echo "请使用root权限运行此脚本"
  exit 1
fi

# 检查是否安装了nginx
if ! command -v nginx &>/dev/null; then
  echo "未检测到Nginx,是否安装? (y/n)"
  read install_nginx
  if [ "$install_nginx" == "y" ] || [ "$install_nginx" == "Y" ]; then
    # 检测系统类型
    if command -v apt &>/dev/null; then
      apt update
      apt install -y nginx socat
    elif command -v yum &>/dev/null; then
      yum install -y epel-release
      yum install -y nginx socat
    else
      echo "无法确定系统类型,请手动安装Nginx后再运行此脚本"
      exit 1
    fi
    echo "Nginx安装完成"
  else
    echo "未安装Nginx,退出脚本"
    exit 1
  fi
fi

# 检查并安装acme.sh
if [ ! -d "$HOME/.acme.sh" ]; then
  echo "正在安装acme.sh..."
  curl https://get.acme.sh | sh -s email=my@example.com
  source ~/.bashrc
  echo "acme.sh安装完成"
else
  echo "acme.sh已安装"
fi

# 获取用户输入
echo "请输入域名 (例如: example.com):"
read domain_name

echo "请输入后端服务端口 (例如: 19304):"
read backend_port

echo "请输入子路径 (例如: /abc123,如果没有请留空):"
read sub_path

# 如果子路径为空,设置为默认值
if [ -z "$sub_path" ]; then
  echo "未提供子路径,只配置根路径代理"
  has_sub_path=false
else
  # 确保子路径以/开头
  if [[ $sub_path != /* ]]; then
    sub_path="/$sub_path"
  fi
  has_sub_path=true
fi

# 创建证书目录
cert_dir="/root/cert/$domain_name"
if [ ! -d "$cert_dir" ]; then
  mkdir -p "$cert_dir"
  echo "证书目录已创建: $cert_dir"
fi

# 创建webroot目录用于acme验证
webroot_dir="/var/www/acme-challenge"
if [ ! -d "$webroot_dir" ]; then
  mkdir -p "$webroot_dir"
  echo "webroot目录已创建: $webroot_dir"
fi

# 生成临时Nginx配置用于初始证书签发
temp_config_file="/etc/nginx/conf.d/${domain_name}_temp.conf"
cat > "$temp_config_file" << EOF
server {
    listen 80;
    server_name $domain_name;
    
    # ACME验证路径
    location /.well-known/acme-challenge/ {
        root $webroot_dir;
    }
    
    location / {
        return 200 'Waiting for SSL setup...';
        add_header Content-Type text/plain;
    }
}
EOF

echo "临时配置已生成,准备签发证书..."
systemctl reload nginx

# 停止3xui可能占用的80端口进程(如果需要)
echo "检查端口占用情况..."
if lsof -Pi :80 -sTCP:LISTEN -t >/dev/null 2>&1; then
  echo "端口80已被占用,nginx将使用webroot模式"
fi

# 使用acme.sh签发证书 (webroot模式,不需要停止nginx)
echo "正在使用acme.sh签发证书..."
~/.acme.sh/acme.sh --issue -d "$domain_name" -w "$webroot_dir" --force

# 检查证书是否签发成功
if [ $? -eq 0 ]; then
  echo "证书签发成功,正在安装证书..."
  
  # 安装证书到指定目录
  ~/.acme.sh/acme.sh --installcert -d "$domain_name" \
    --key-file "$cert_dir/privkey.pem" \
    --fullchain-file "$cert_dir/fullchain.pem" \
    --reloadcmd "systemctl reload nginx"
  
  echo "证书已安装到: $cert_dir"
else
  echo "证书签发失败,请检查:"
  echo "1. 域名DNS是否正确解析到本服务器"
  echo "2. 防火墙是否开放80端口"
  echo "3. 是否有其他服务占用80端口"
  exit 1
fi

# 删除临时配置
rm -f "$temp_config_file"

# 生成正式的Nginx配置文件
config_file="/etc/nginx/conf.d/$domain_name.conf"
cat > "$config_file" << EOF
server {
    listen 80;
    server_name $domain_name;
    
    # ACME验证路径 - 用于证书续签
    location /.well-known/acme-challenge/ {
        root $webroot_dir;
    }
    
    # 其他请求重定向到HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $domain_name;
    
    ssl_certificate $cert_dir/fullchain.pem;
    ssl_certificate_key $cert_dir/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # 更智能的处理客户端IP
    set \$real_ip \$remote_addr;
    if (\$http_cf_connecting_ip) {
        set \$real_ip \$http_cf_connecting_ip;
    }
    
EOF

# 如果有子路径,添加子路径配置
if [ "$has_sub_path" = true ]; then
cat >> "$config_file" << EOF
    location $sub_path {
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$real_ip;
        proxy_redirect off;
        proxy_pass https://127.0.0.1:$backend_port$sub_path;
        proxy_ssl_verify off;
    }
    
EOF
fi

# 添加根路径配置
cat >> "$config_file" << EOF
    location / {
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$real_ip;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_redirect off;
        proxy_pass https://127.0.0.1:$backend_port;
        proxy_ssl_verify off;
        
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
    }
}
EOF

echo "正式配置文件已生成: $config_file"

# 检查nginx配置
echo "正在检查Nginx配置..."
nginx -t

if [ $? -eq 0 ]; then
  echo "配置检查通过,正在重新加载Nginx..."
  systemctl reload nginx
  echo "Nginx已重新加载"
  
  # 显示证书信息
  echo ""
  echo "========================================="
  echo "配置完成!"
  echo "========================================="
  echo "域名: $domain_name"
  echo "证书路径: $cert_dir"
  echo "证书将通过acme.sh自动续签"
  echo "续签方式: webroot (不需要停止nginx)"
  echo ""
  echo "可以使用以下命令查看证书信息:"
  echo "~/.acme.sh/acme.sh --info -d $domain_name"
  echo ""
  echo "手动强制续签命令:"
  echo "~/.acme.sh/acme.sh --renew -d $domain_name --force"
  echo "========================================="
else
  echo "Nginx配置检查失败,请修复错误后再重新加载"
  exit 1
fi

# 设置cron任务自动续签(acme.sh会自动添加,这里只是确认)
echo ""
echo "检查证书自动续签任务..."
if crontab -l | grep -q "acme.sh"; then
  echo "✓ 自动续签任务已配置"
else
  echo "! 警告: 未检测到自动续签任务,acme.sh应该已自动配置"
fi

echo ""
echo "脚本执行完毕!"
