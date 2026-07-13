#!/bin/bash

# ============================================================
# Xray 多端口管理脚本 - 重构版
# 版本: 3.0.2
# ============================================================

# 等待1秒, 避免curl下载脚本的打印与脚本本身的显示冲突
sleep 1

echo -e "                     _ ___                   \n ___ ___ __ __ ___ _| |  _|___ __ __   _ ___ \n|-_ |_  |  |  |-_ | _ |   |- _|  |  |_| |_  |\n|___|___|  _  |___|___|_|_|___|  _  |___|___|\n        |_____|               |_____|        "

# ============================================================
# 第一部分：全局配置和常量
# ============================================================

# 颜色定义
readonly RED='\e[91m'
readonly GREEN='\e[92m'
readonly YELLOW='\e[93m'
readonly MAGENTA='\e[95m'
readonly CYAN='\e[96m'
readonly NONE='\e[0m'

# 脚本版本
readonly VERSION="3.0.2"

# 配置文件路径
readonly CONFIG_FILE="/usr/local/etc/xray/config.json"
readonly CONFIG_DIR="/usr/local/etc/xray"
readonly PORT_INFO_FILE="$HOME/.xray_port_info.json"
readonly LOG_FILE="$HOME/.xray_management.log"
readonly HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"

# 全局变量
IPv4=""
IPv6=""
SELECTED_IP=""
SELECTED_NETSTACK=""

# ============================================================
# 第二部分：工具函数 - 日志、颜色、提示
# ============================================================

# 日志记录
log() {
    local level=$1 message=$2
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
}

log_info()  { log "INFO" "$1"; }
log_error() { log "ERROR" "$1"; }
log_warn()  { log "WARN" "$1"; }

# 用户提示
msg_error() {
    echo -e "\n${RED} 输入错误! ${NONE}\n"
    log_error "用户输入错误"
}

msg_warn() {
    echo -e "\n${YELLOW} $1 ${NONE}\n"
    log_warn "$1"
}

msg_success() {
    echo -e "\n${GREEN} $1 ${NONE}\n"
    log_info "$1"
}

msg_info() {
    echo -e "${YELLOW}$1${NONE}"
}

# 等待用户按键
pause() {
    read -rsp "$(echo -e "按 ${GREEN}Enter 回车键${NONE} 继续....或按 ${RED}Ctrl + C${NONE} 取消.")" -d $'\n'
    echo
}

# 打印分隔线
print_line() {
    echo "----------------------------------------------------------------"
}

# 打印标题
print_title() {
    echo
    echo -e "${YELLOW} $1 ${NONE}"
    print_line
}

# ============================================================
# 第三部分：验证函数
# ============================================================

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 必须以root权限运行此脚本${NONE}"
        exit 1
    fi
}

# 验证端口号
validate_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 ]] && [[ "$port" -le 65535 ]]
}

# 验证UUID格式
validate_uuid() {
    local uuid=$1
    [[ "$uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

# 验证ShortID格式
validate_shortid() {
    local shortid=$1
    [[ "$shortid" =~ ^([0-9a-fA-F]{2}){0,8}$ ]]
}

# 验证SNI域名，避免无效REALITY配置
validate_domain() {
    local domain=$1
    [[ ${#domain} -le 253 ]] &&
        [[ "$domain" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

# 验证SOCKS5主机名/IP，拒绝空白和HAProxy配置注入字符
validate_proxy_host() {
    local host=$1
    [[ -n "$host" && ${#host} -le 253 ]] || return 1
    [[ "$host" =~ ^[A-Za-z0-9._:-]+$ ]] || return 1
    [[ "$host" != .* && "$host" != *. && "$host" != *..* ]]
}

validate_positive_int() {
    local value=$1 max=${2:-2147483647}
    [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= max ))
}

# 读取y/n确认
read_yes_no() {
    local prompt=$1 default=${2:-n}
    local answer
    read -p "$(echo -e "($prompt y/n, 默认: ${CYAN}$default${NONE}): ")" answer
    [[ -z "$answer" ]] && answer=$default
    [[ "$answer" == "y" || "$answer" == "Y" ]]
}

# 读取端口输入
read_port_input() {
    local prompt=$1 default=$2 varname=$3
    local port

    while :; do
        read -p "$(echo -e "$prompt (默认: ${CYAN}${default}${NONE}): ")" port
        [[ -z "$port" ]] && port=$default

        if ! validate_port "$port"; then
            msg_error
            continue
        fi

        printf -v "$varname" '%s' "$port"
        return 0
    done
}

# ============================================================
# 第四部分：网络函数 - IP检测
# ============================================================

# 获取公共IP
get_public_ip() {
    local ip_type=$1 interface=$2 timeout=3
    local -a curl_args=(-"${ip_type}" -fsS -m "$timeout")
    [[ -n "$interface" ]] && curl_args+=(--interface "$interface")
    local ip_apis=(
        "https://www.cloudflare.com/cdn-cgi/trace"
        "https://api.ipify.org"
        "https://ip.sb"
        "https://api.ip.sb/ip"
        "https://ifconfig.me"
    )

    for api in "${ip_apis[@]}"; do
        local ip
        if [[ $api == "https://www.cloudflare.com/cdn-cgi/trace" ]]; then
            ip=$(curl "${curl_args[@]}" "$api" 2>/dev/null | sed -n 's/^ip=//p')
        else
            ip=$(curl "${curl_args[@]}" "$api" 2>/dev/null)
        fi
        ip=${ip//$'\r'/}
        ip=${ip//$'\n'/}

        if [[ -n "$ip" && $ip =~ ^[0-9a-fA-F:.]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

# 获取本机IP
get_local_ips() {
    local success=false
    IPv4="" IPv6=""

    # 获取网络接口列表
    local InFaces=()
    local iface iface_path
    for iface_path in /sys/class/net/*; do
        [[ -e "$iface_path" ]] || continue
        iface=${iface_path##*/}
        [[ "$iface" =~ ^(eth|ens|eno|esp|enp|venet|vif) ]] && InFaces+=("$iface")
    done

    for i in "${InFaces[@]}"; do
        msg_info "正在检测接口 $i ..."

        if [[ -z "$IPv4" ]]; then
            local Public_IPv4=$(get_public_ip 4 "$i")
            if [[ -n "$Public_IPv4" ]]; then
                IPv4="$Public_IPv4"
                echo -e "${GREEN}在接口 $i 上成功获取到IPv4: $IPv4${NONE}"
                log_info "获取到IPv4: $IPv4 (接口: $i)"
                success=true
            fi
        fi

        if [[ -z "$IPv6" ]]; then
            local Public_IPv6=$(get_public_ip 6 "$i")
            if [[ -n "$Public_IPv6" ]]; then
                IPv6="$Public_IPv6"
                echo -e "${GREEN}在接口 $i 上成功获取到IPv6: $IPv6${NONE}"
                log_info "获取到IPv6: $IPv6 (接口: $i)"
                success=true
            fi
        fi

        [[ -n "$IPv4" && -n "$IPv6" ]] && break
    done

    # 如果通过网络接口获取失败，尝试直接获取
    if [[ -z "$IPv4" ]]; then
        msg_info "尝试直接获取IPv4..."
        IPv4=$(get_public_ip 4)
        if [[ -n "$IPv4" ]]; then
            echo -e "${GREEN}成功获取到IPv4: $IPv4${NONE}"
            log_info "直接获取到IPv4: $IPv4"
            success=true
        fi
    fi

    if [[ -z "$IPv6" ]]; then
        msg_info "尝试直接获取IPv6..."
        IPv6=$(get_public_ip 6)
        if [[ -n "$IPv6" ]]; then
            echo -e "${GREEN}成功获取到IPv6: $IPv6${NONE}"
            log_info "直接获取到IPv6: $IPv6"
            success=true
        fi
    fi

    if ! $success; then
        echo -e "${RED}警告: 未能获取到任何公共IP地址${NONE}"
        log_error "未能获取到任何公共IP地址"
        return 1
    fi
    return 0
}

# 选择网络栈
select_network_stack() {
    SELECTED_IP="" SELECTED_NETSTACK=""

    if ! get_local_ips; then
        echo -e "${RED}获取IP地址失败!${NONE}"
        if ! read_yes_no "是否继续?" "n"; then
            return 1
        fi
    fi

    # 如果只有一种IP，自动选择
    if [[ -n "$IPv4" && -z "$IPv6" ]]; then
        SELECTED_IP=$IPv4 SELECTED_NETSTACK=4
        echo -e "${GREEN}自动选择IPv4: ${CYAN}$SELECTED_IP${NONE}"
        return 0
    elif [[ -z "$IPv4" && -n "$IPv6" ]]; then
        SELECTED_IP=$IPv6 SELECTED_NETSTACK=6
        echo -e "${GREEN}自动选择IPv6: ${CYAN}$SELECTED_IP${NONE}"
        return 0
    elif [[ -z "$IPv4" && -z "$IPv6" ]]; then
        echo -e "${RED}错误: 服务器既没有IPv4也没有IPv6公网地址${NONE}"
        return 1
    fi

    # 双栈情况，让用户选择
    echo
    echo -e "服务器是${MAGENTA}双栈(同时有IPv4和IPv6)${NONE}，请选择IP类型"
    echo "如果你不懂这段话是什么意思, 请直接回车"
    read -p "$(echo -e "输入 ${CYAN}4${NONE} 表示IPv4, ${CYAN}6${NONE} 表示IPv6: ") " netstack

    case "$netstack" in
        4) SELECTED_IP=$IPv4 SELECTED_NETSTACK=4 ;;
        6) SELECTED_IP=$IPv6 SELECTED_NETSTACK=6 ;;
        *) SELECTED_IP=$IPv4 SELECTED_NETSTACK=4 ;;  # 默认IPv4
    esac

    echo -e "${GREEN}已选择: $([ "$SELECTED_NETSTACK" = "4" ] && echo "IPv4" || echo "IPv6") - ${CYAN}$SELECTED_IP${NONE}"
    return 0
}

# ============================================================
# 第五部分：端口信息管理
# ============================================================

# 初始化目录和文件
init_directories() {
    [[ ! -d "$CONFIG_DIR" ]] && mkdir -p "$CONFIG_DIR"

    if [[ ! -f "$PORT_INFO_FILE" ]]; then
        echo '{"ports":[]}' > "$PORT_INFO_FILE"
        chmod 600 "$PORT_INFO_FILE"
    fi

    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
}

# 获取端口信息
get_port_info() {
    local port=$1
    jq -c ".ports[] | select(.port == $port)" "$PORT_INFO_FILE"
}

# 获取端口配置字段
get_port_field() {
    local port=$1 field=$2
    jq -r ".ports[] | select(.port == $port) | .$field" "$PORT_INFO_FILE"
}

# 检查端口是否已配置
check_port_exists() {
    local port=$1
    jq -e ".ports[] | select(.port == $port)" "$PORT_INFO_FILE" > /dev/null 2>&1
}

# 获取端口数量
get_port_count() {
    jq '.ports | length' "$PORT_INFO_FILE"
}

# 保存端口基本信息
save_port_info() {
    local port=$1 uuid=$2 private_key=$3 public_key=$4 shortid=$5 domain=$6

    if check_port_exists "$port"; then
        # 更新已存在的端口配置；所有字符串均通过--arg传递，避免引号破坏JSON
        jq --argjson port "$port" --arg uuid "$uuid" --arg private_key "$private_key" \
            --arg public_key "$public_key" --arg shortid "$shortid" --arg domain "$domain" \
            '(.ports[] | select(.port == $port)) |= {
                port: $port, uuid: $uuid, private_key: $private_key,
                public_key: $public_key, shortid: $shortid, domain: $domain,
                socks5: (.socks5 // null), haproxy: (.haproxy // null)
            }' "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
    else
        # 添加新端口
        jq --argjson port "$port" --arg uuid "$uuid" --arg private_key "$private_key" \
            --arg public_key "$public_key" --arg shortid "$shortid" --arg domain "$domain" \
            '.ports += [{port: $port, uuid: $uuid, private_key: $private_key,
                public_key: $public_key, shortid: $shortid, domain: $domain,
                socks5: null, haproxy: null}]' \
            "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
    fi

    jq -e . "${PORT_INFO_FILE}.tmp" >/dev/null || { rm -f "${PORT_INFO_FILE}.tmp"; return 1; }
    mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
    chmod 600 "$PORT_INFO_FILE"
    log_info "保存端口 $port 配置"
}

# 删除端口信息
delete_port_info() {
    local port=$1
    jq --argjson port "$port" 'del(.ports[] | select(.port == $port))' "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"
    mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
    chmod 600 "$PORT_INFO_FILE"
    log_info "删除端口 $port 配置"
}

# 设置SOCKS5配置
set_port_socks5_config() {
    local port=$1 enabled=$2 address=$3 socks_port=$4
    local auth_needed=$5 username=$6 password=$7 udp_over_tcp=$8

    local socks5_config
    if [[ "$enabled" == "y" ]]; then
        socks5_config=$(jq -n \
            --arg addr "$address" \
            --argjson port "$socks_port" \
            --argjson auth "$([ "$auth_needed" == "y" ] && echo true || echo false)" \
            --arg user "$username" \
            --arg pass "$password" \
            --argjson udp "$([ "$udp_over_tcp" == "y" ] && echo true || echo false)" \
            '{enabled: true, address: $addr, port: $port, auth_needed: $auth, username: $user, password: $pass, udp_over_tcp: $udp}')
    else
        socks5_config="null"
    fi

    if ! jq --argjson port "$port" --argjson config "$socks5_config" \
        '(.ports[] | select(.port == $port)).socks5 = $config' \
        "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"; then
        rm -f "${PORT_INFO_FILE}.tmp"
        return 1
    fi
    jq -e . "${PORT_INFO_FILE}.tmp" >/dev/null || { rm -f "${PORT_INFO_FILE}.tmp"; return 1; }
    mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
    chmod 600 "$PORT_INFO_FILE"
    log_info "设置端口 $port 的SOCKS5配置"
}

# 设置HAProxy配置
set_port_haproxy_config() {
    local port=$1 enabled=$2 haproxy_port=$3 threads=$4 maxconn=$5

    local haproxy_config
    if [[ "$enabled" == "y" ]]; then
        validate_port "$port" && validate_port "$haproxy_port" && \
            validate_positive_int "$threads" 256 && validate_positive_int "$maxconn" 1000000 || {
                echo -e "${RED}HAProxy端口、线程数或最大连接数无效${NONE}"
                return 1
            }
        haproxy_config=$(jq -n --argjson port "$haproxy_port" --argjson threads "$threads" \
            --argjson maxconn "$maxconn" \
            '{enabled: true, port: $port, threads: $threads, maxconn: $maxconn}') || return 1
    else
        haproxy_config="null"
    fi

    if ! jq --argjson port "$port" --argjson config "$haproxy_config" \
        '(.ports[] | select(.port == $port)).haproxy = $config' \
        "$PORT_INFO_FILE" > "${PORT_INFO_FILE}.tmp"; then
        rm -f "${PORT_INFO_FILE}.tmp"
        return 1
    fi
    jq -e . "${PORT_INFO_FILE}.tmp" >/dev/null || { rm -f "${PORT_INFO_FILE}.tmp"; return 1; }
    mv "${PORT_INFO_FILE}.tmp" "$PORT_INFO_FILE"
    chmod 600 "$PORT_INFO_FILE"
    log_info "设置端口 $port 的HAProxy配置"
}

# 保留端口的代理配置（用于修改UUID/域名/ShortID时）
preserve_port_proxy_config() {
    local port=$1
    local port_info=$(get_port_info "$port")

    # 保留SOCKS5配置
    local socks5_config=$(echo "$port_info" | jq -r '.socks5')
    if [[ "$socks5_config" != "null" ]]; then
        local enabled=$(echo "$socks5_config" | jq -r '.enabled // false')
        if [[ "$enabled" == "true" ]]; then
            local addr=$(echo "$socks5_config" | jq -r '.address')
            local sport=$(echo "$socks5_config" | jq -r '.port')
            local auth=$(echo "$socks5_config" | jq -r '.auth_needed')
            local user=$(echo "$socks5_config" | jq -r '.username')
            local pass=$(echo "$socks5_config" | jq -r '.password')
            local udp=$(echo "$socks5_config" | jq -r '.udp_over_tcp')

            set_port_socks5_config "$port" "y" "$addr" "$sport" \
                "$([ "$auth" == "true" ] && echo y || echo n)" "$user" "$pass" \
                "$([ "$udp" == "true" ] && echo y || echo n)"
        fi
    fi

    # 保留HAProxy配置
    local haproxy_config=$(echo "$port_info" | jq -r '.haproxy')
    if [[ "$haproxy_config" != "null" ]]; then
        local enabled=$(echo "$haproxy_config" | jq -r '.enabled // false')
        if [[ "$enabled" == "true" ]]; then
            local hport=$(echo "$haproxy_config" | jq -r '.port')
            local threads=$(echo "$haproxy_config" | jq -r '.threads')
            local maxconn=$(echo "$haproxy_config" | jq -r '.maxconn')
            set_port_haproxy_config "$port" "y" "$hport" "$threads" "$maxconn"
        fi
    fi
}

# ============================================================
# 第六部分：配置文件操作
# ============================================================

# 构建VLESS入站配置
build_inbound_config() {
    local port=$1 uuid=$2 private_key=$3 shortid=$4 domain=$5

    jq -n --argjson port "$port" --arg uuid "$uuid" --arg private_key "$private_key" \
        --arg shortid "$shortid" --arg domain "$domain" \
        '{
            listen: "0.0.0.0", port: $port, protocol: "vless",
            settings: {clients: [{id: $uuid, flow: "xtls-rprx-vision"}], decryption: "none"},
            streamSettings: {
                network: "tcp", security: "reality",
                realitySettings: {
                    show: false, dest: ($domain + ":443"), xver: 0,
                    serverNames: [$domain], privateKey: $private_key,
                    shortIds: ["", $shortid]
                }
            },
            sniffing: {enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true},
            tag: ("inbound-" + ($port | tostring))
        }'
}

# 构建SOCKS5出站配置
build_socks5_outbound() {
    local port=$1 address=$2 socks_port=$3 auth_needed=$4 user=$5 pass=$6 udp_over_tcp=$7
    local auth_json=false udp_json=false
    [[ "$auth_needed" == "true" && -n "$user" && -n "$pass" ]] && auth_json=true
    [[ "$udp_over_tcp" == "true" ]] && udp_json=true

    jq -n --argjson port "$port" --arg address "$address" --argjson socks_port "$socks_port" \
        --argjson auth "$auth_json" --arg user "$user" --arg pass "$pass" --argjson udp "$udp_json" \
        '{
            protocol: "socks",
            settings: {servers: [({address: $address, port: $socks_port} +
                (if $auth then {users: [{user: $user, pass: $pass}]} else {} end))]},
            streamSettings: {sockopt:
                (if $udp then
                    {udpFragmentSize: 1400, tcpFastOpen: true, tcpKeepAliveInterval: 15, mark: 255}
                 else
                    {tcpFastOpen: true, tcpKeepAliveInterval: 15, tcpMptcp: true, tcpNoDelay: true, mark: 255}
                 end)},
            tag: ("socks5-out-" + ($port | tostring))
        }'
}

# 更新Xray配置文件
update_config_file() {
    mkdir -p "$CONFIG_DIR"
    local temp_config
    temp_config=$(mktemp "${CONFIG_DIR}/.config.json.tmp.XXXXXX") || return 1

    # 始终先在临时文件中完整生成，验证成功后才替换线上配置
    cat > "$temp_config" << 'EOL'
{
  "log": {"loglevel": "warning", "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log"},
  "dns": {
    "servers": ["tcp://8.8.8.8", "tcp://1.1.1.1", "tcp://1.0.0.1", "tcp://8.8.4.4", "localhost"],
    "queryStrategy": "UseIPv4",
    "disableCache": true,
    "disableFallback": false,
    "tag": "dns-out"
  },
  "inbounds": [],
  "outbounds": [
    {"protocol": "freedom", "settings": {}, "tag": "direct"},
    {"protocol": "dns", "tag": "dns-out"},
    {"protocol": "blackhole", "settings": {}, "tag": "blocked"}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"}]
  }
}
EOL

    # 处理每个端口配置
    while read -r port_info; do
        [[ -z "$port_info" ]] && continue

        local port=$(echo "$port_info" | jq -r '.port')
        local uuid=$(echo "$port_info" | jq -r '.uuid')
        local private_key=$(echo "$port_info" | jq -r '.private_key')
        local shortid=$(echo "$port_info" | jq -r '.shortid')
        local domain=$(echo "$port_info" | jq -r '.domain')

        # 添加入站配置
        local inbound=$(build_inbound_config "$port" "$uuid" "$private_key" "$shortid" "$domain")
        jq --argjson inbound "$inbound" '.inbounds += [$inbound]' "$temp_config" > "${temp_config}.new"
        mv "${temp_config}.new" "$temp_config"

        # 处理SOCKS5配置
        local socks5_config=$(echo "$port_info" | jq -r '.socks5')
        if [[ "$socks5_config" != "null" && "$(echo "$socks5_config" | jq -r '.enabled')" == "true" ]]; then
            local haproxy_config=$(echo "$port_info" | jq -r '.haproxy')
            local socks5_address socks5_port

            if [[ "$haproxy_config" != "null" && "$(echo "$haproxy_config" | jq -r '.enabled')" == "true" ]]; then
                socks5_address="127.0.0.1"
                socks5_port=$(echo "$haproxy_config" | jq -r '.port')
            else
                socks5_address=$(echo "$socks5_config" | jq -r '.address')
                socks5_port=$(echo "$socks5_config" | jq -r '.port')
            fi

            local auth_needed=$(echo "$socks5_config" | jq -r '.auth_needed')
            local socks5_user=$(echo "$socks5_config" | jq -r '.username')
            local socks5_pass=$(echo "$socks5_config" | jq -r '.password')
            local udp_over_tcp=$(echo "$socks5_config" | jq -r '.udp_over_tcp')

            # 添加SOCKS5出站
            local socks5_outbound=$(build_socks5_outbound "$port" "$socks5_address" "$socks5_port" \
                "$auth_needed" "$socks5_user" "$socks5_pass" "$udp_over_tcp")
            jq --argjson outbound "$socks5_outbound" '.outbounds += [$outbound]' "$temp_config" > "${temp_config}.new"
            mv "${temp_config}.new" "$temp_config"

            # 添加路由规则
            jq --arg port "$port" '.routing.rules += [{
                type: "field",
                inboundTag: [("inbound-" + $port)],
                outboundTag: ("socks5-out-" + $port)
            }]' "$temp_config" > "${temp_config}.new"
            mv "${temp_config}.new" "$temp_config"
        fi
    done < <(jq -c '.ports[]' "$PORT_INFO_FILE")

    if ! jq -e . "$temp_config" >/dev/null; then
        echo -e "${RED}生成的Xray配置不是有效JSON，已保留原配置${NONE}"
        rm -f "$temp_config" "${temp_config}.new"
        return 1
    fi

    # 先验证配置，再原子替换，防止错误配置导致服务无法启动
    if command -v xray >/dev/null 2>&1 && ! xray run -test -config "$temp_config" >/dev/null 2>&1; then
        echo -e "${RED}Xray配置验证失败，已保留原配置${NONE}"
        xray run -test -config "$temp_config" 2>&1
        rm -f "$temp_config" "${temp_config}.new"
        return 1
    fi

    [[ -f "$CONFIG_FILE" ]] && cp "$CONFIG_FILE" "${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    chmod 644 "$temp_config"
    mv -f "$temp_config" "$CONFIG_FILE"
    rm -f "${temp_config}.new"
    log_info "配置文件已更新"
}

# 更新HAProxy配置文件
update_haproxy_config() {
    local haproxy_dir
    haproxy_dir=$(dirname "$HAPROXY_CONFIG")
    mkdir -p "$haproxy_dir"
    local temp_haproxy
    temp_haproxy=$(mktemp "${haproxy_dir}/.haproxy.cfg.tmp.XXXXXX") || return 1

    # 获取最大线程数
    local max_threads=12
    while read -r port_info; do
        local threads
        threads=$(echo "$port_info" | jq -r '.haproxy.threads // 12')
        validate_positive_int "$threads" 256 || { rm -f "$temp_haproxy"; return 1; }
        [[ $threads -gt $max_threads ]] && max_threads=$threads
    done < <(jq -c '.ports[] | select(.haproxy != null and .haproxy.enabled == true)' "$PORT_INFO_FILE")

    # 创建基本配置
    cat > "$temp_haproxy" << EOL
global
    maxconn 5000
    nbthread $max_threads
    tune.bufsize 32768
    tune.maxrewrite 1024

defaults
    mode tcp
    timeout connect 15s
    timeout client 30s
    timeout server 30s
    option tcp-smart-accept
    option tcp-smart-connect
    option tcplog

EOL

    # 添加每个端口的配置
    while read -r port_info; do
        local port=$(echo "$port_info" | jq -r '.port')
        local haproxy_port=$(echo "$port_info" | jq -r '.haproxy.port')
        local haproxy_maxconn=$(echo "$port_info" | jq -r '.haproxy.maxconn')
        local socks5_address=$(echo "$port_info" | jq -r '.socks5.address')
        local socks5_port=$(echo "$port_info" | jq -r '.socks5.port')

        validate_port "$port" && validate_port "$haproxy_port" && validate_port "$socks5_port" &&
            validate_positive_int "$haproxy_maxconn" 1000000 && validate_proxy_host "$socks5_address" || {
                echo -e "${RED}HAProxy参数无效，取消更新${NONE}"
                rm -f "$temp_haproxy"
                return 1
            }

        cat >> "$temp_haproxy" << EOL
frontend socks_front_$port
    bind *:$haproxy_port
    default_backend socks_servers_$port

backend socks_servers_$port
    server socks1 $socks5_address:$socks5_port maxconn $haproxy_maxconn check inter 5000 rise 2 fall 3

EOL
    done < <(jq -c '.ports[] | select(.haproxy != null and .haproxy.enabled == true)' "$PORT_INFO_FILE")

    # 临时配置验证成功后才替换线上文件
    if ! haproxy -c -f "$temp_haproxy"; then
        echo -e "${RED}HAProxy配置验证失败，原配置未修改${NONE}"
        rm -f "$temp_haproxy"
        return 1
    fi

    [[ -f "$HAPROXY_CONFIG" ]] && cp "$HAPROXY_CONFIG" "${HAPROXY_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
    chmod 644 "$temp_haproxy"
    mv -f "$temp_haproxy" "$HAPROXY_CONFIG"
    restart_haproxy
}

# ============================================================
# 第七部分：服务管理
# ============================================================

# 检查依赖
check_dependencies() {
    # HAProxy仅在配置SOCKS5转发时安装，避免脚本一启动就安装并启用服务
    local dependencies=("curl" "jq" "qrencode" "lsof" "wget" "systemctl")
    local missing=()

    for dep in "${dependencies[@]}"; do
        command -v "$dep" &> /dev/null || missing+=("$dep")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        msg_info "正在安装缺少的依赖: ${missing[*]}"
        apt update -y && apt install -y "${missing[@]}"

        for dep in "${missing[@]}"; do
            if ! command -v "$dep" &> /dev/null; then
                echo -e "${RED}安装 $dep 失败，请手动安装${NONE}"
                return 1
            fi
        done
    fi
    return 0
}

# 重启Xray服务
restart_xray() {
    msg_info "重启 Xray 服务..."
    if systemctl restart xray; then
        echo -e "${GREEN}Xray 服务重启成功!${NONE}"
        log_info "Xray 服务重启成功"
        return 0
    else
        echo -e "${RED}Xray 服务重启失败，请手动检查!${NONE}"
        log_error "Xray 服务重启失败"
        return 1
    fi
}

# 重启HAProxy服务
restart_haproxy() {
    if systemctl is-active --quiet haproxy; then
        systemctl restart haproxy
    else
        systemctl start haproxy
    fi

    sleep 2
    if systemctl is-active --quiet haproxy; then
        echo -e "${GREEN}HAProxy重启成功${NONE}"
        log_info "HAProxy服务重启成功"
    else
        echo -e "${RED}HAProxy服务启动失败，请检查配置${NONE}"
        log_error "HAProxy服务启动失败"
    fi
}

# 检查Xray服务状态
check_xray_service() {
    if ! systemctl is-active --quiet xray; then
        echo -e "${RED}Xray 服务未运行，尝试启动...${NONE}"
        systemctl start xray
        sleep 2

        if ! systemctl is-active --quiet xray; then
            echo -e "${RED}Xray 服务启动失败${NONE}"
            log_error "Xray服务启动失败"
            return 1
        fi
    fi

    echo -e "${GREEN}Xray 服务运行中${NONE}"
    return 0
}

# ============================================================
# 第八部分：端口配置操作
# ============================================================

# 生成默认UUID
generate_default_uuid() {
    if command -v xray >/dev/null 2>&1; then
        xray uuid 2>/dev/null && return 0
    fi
    if [[ -r /proc/sys/kernel/random/uuid ]]; then
        tr 'A-F' 'a-f' < /proc/sys/kernel/random/uuid
        return 0
    fi
    command -v uuidgen >/dev/null 2>&1 && uuidgen | tr 'A-F' 'a-f'
}

# 生成密钥对
generate_keys() {
    xray x25519 2>/dev/null
}

# 查找可用端口
find_available_port() {
    local start_port=$1
    local port=$start_port
    while lsof -i:"$port" >/dev/null 2>&1 || check_port_exists "$port"; do
        port=$((port + 1))
    done
    validate_port "$port" || return 1
    echo "$port"
}

# 配置SOCKS5代理
configure_socks5() {
    local port=$1
    local socks5_address socks5_port auth_needed socks5_user socks5_pass udp_over_tcp

    # 获取SOCKS5地址
    while :; do
        read -p "请输入 SOCKS5 服务器地址: " socks5_address
        if ! validate_proxy_host "$socks5_address"; then
            echo -e "${RED}错误: 请输入合法的IP地址或主机名${NONE}"
            continue
        fi
        if [[ "$socks5_address" == "127.0.0.1" || "$socks5_address" == "localhost" || "$socks5_address" == "::1" ]]; then
            echo -e "${RED}错误: 不能使用本地地址${NONE}"
            continue
        fi
        break
    done

    # 获取SOCKS5端口
    while :; do
        read -p "请输入 SOCKS5 端口: " socks5_port
        if ! validate_port "$socks5_port"; then
            msg_error; continue
        fi
        break
    done

    # 认证设置
    read_yes_no "是否需要用户名密码认证?" "n" && auth_needed="y" || auth_needed="n"
    if [[ "$auth_needed" == "y" ]]; then
        read -r -p "请输入用户名: " socks5_user
        read -r -p "请输入密码: " socks5_pass
    fi

    # UDP设置
    read_yes_no "是否启用 UDP over TCP?" "n" && udp_over_tcp="y" || udp_over_tcp="n"

    # 保存SOCKS5配置
    set_port_socks5_config "$port" "y" "$socks5_address" "$socks5_port" "$auth_needed" "$socks5_user" "$socks5_pass" "$udp_over_tcp"

    # 自动配置HAProxy
    if ! command -v haproxy >/dev/null 2>&1; then
        msg_info "正在安装HAProxy..."
        apt-get update && apt-get install -y haproxy || {
            echo -e "${RED}HAProxy安装失败${NONE}"
            return 1
        }
        systemctl enable haproxy >/dev/null 2>&1 || true
    fi
    local haproxy_port
    haproxy_port=$(find_available_port $((port + 10))) || {
        echo -e "${RED}未找到可用的HAProxy端口${NONE}"
        return 1
    }
    set_port_haproxy_config "$port" "y" "$haproxy_port" 12 400
    update_haproxy_config

    echo -e "${GREEN}SOCKS5和HAProxy配置完成，HAProxy端口: $haproxy_port${NONE}"
    log_info "为端口 $port 配置SOCKS5代理"
}

# 添加新端口配置
add_port_configuration() {
    print_title "添加新端口配置"

    # 检查Xray是否安装
    if ! command -v xray &> /dev/null; then
        echo -e "${RED}未检测到Xray安装${NONE}"
        if read_yes_no "是否现在安装Xray?" "n"; then
            install_xray
        else
            return
        fi
    fi

    # 选择网络栈
    if ! select_network_stack; then
        return 1
    fi

    # 端口选择
    local port
    while :; do
        read -p "$(echo -e "请输入端口 [${MAGENTA}1-65535${NONE}] (默认: ${CYAN}7999${NONE}): ")" port
        [[ -z "$port" ]] && port=7999

        if ! validate_port "$port"; then
            msg_error; continue
        fi
        if check_port_exists "$port"; then
            echo -e "${RED}端口 $port 已被配置${NONE}"; continue
        fi
        if lsof -i:"$port" >/dev/null 2>&1; then
            echo -e "${RED}端口 $port 已被占用${NONE}"; continue
        fi
        break
    done
    echo -e "${YELLOW}端口 = ${CYAN}${port}${NONE}"
    print_line

    # UUID
    local default_uuid=$(generate_default_uuid "$SELECTED_IP" "$port")
    local uuid
    while :; do
        read -p "$(echo -e "请输入UUID (默认: ${CYAN}${default_uuid}${NONE}): ")" uuid
        [[ -z "$uuid" ]] && uuid=$default_uuid
        if ! validate_uuid "$uuid"; then
            msg_error; continue
        fi
        break
    done
    echo -e "${YELLOW}UUID = ${CYAN}${uuid}${NONE}"
    print_line

    # 生成密钥
    local tmp_key private_key public_key
    tmp_key=$(generate_keys "$uuid")
    private_key=$(echo "$tmp_key" | awk -F': ' '/^PrivateKey:/{print $2; exit}')
    public_key=$(echo "$tmp_key" | awk -F': ' '/^(Password \(PublicKey\)|PublicKey):/{print $2; exit}')
    [[ -n "$private_key" && -n "$public_key" ]] || {
        echo -e "${RED}X25519密钥生成或解析失败${NONE}"
        return 1
    }
    echo -e "${YELLOW}私钥 = ${CYAN}${private_key}${NONE}"
    echo -e "${YELLOW}公钥 = ${CYAN}${public_key}${NONE}"
    print_line

    # ShortID
    local default_shortid=$(echo -n "${uuid}" | sha1sum | head -c 16)
    local shortid
    while :; do
        read -p "$(echo -e "请输入ShortID (默认: ${CYAN}${default_shortid}${NONE}): ")" shortid
        [[ -z "$shortid" ]] && shortid=$default_shortid
        if ! validate_shortid "$shortid"; then
            msg_error; continue
        fi
        break
    done
    echo -e "${YELLOW}ShortID = ${CYAN}${shortid}${NONE}"
    print_line

    # 域名
    while :; do
        read -r -p "$(echo -e "请输入SNI域名 (默认: ${CYAN}learn.microsoft.com${NONE}): ")" domain
        [[ -z "$domain" ]] && domain="learn.microsoft.com"
        validate_domain "$domain" && break
        echo -e "${RED}域名格式无效，请输入类似 learn.microsoft.com 的域名${NONE}"
    done
    echo -e "${YELLOW}SNI = ${CYAN}${domain}${NONE}"
    print_line

    # 保存配置
    save_port_info "$port" "$uuid" "$private_key" "$public_key" "$shortid" "$domain"

    # SOCKS5配置
    if read_yes_no "是否配置SOCKS5转发代理?" "n"; then
        configure_socks5 "$port"
    fi

    # 更新配置并重启
    if ! update_config_file; then
        echo -e "${RED}配置生成或验证失败，未重启Xray${NONE}"
        return 1
    fi
    restart_xray

    # 生成连接信息
    generate_connection_info "$port" "$uuid" "$public_key" "$shortid" "$domain" "$SELECTED_IP" "$SELECTED_NETSTACK"

    msg_success "端口配置成功添加!"
    pause
}

# 修改端口配置
modify_port_configuration() {
    print_title "修改端口配置"

    local port_count=$(get_port_count)
    if [[ $port_count -eq 0 ]]; then
        echo -e "${RED}目前没有配置任何端口${NONE}"
        return
    fi

    list_port_configurations

    # 选择端口
    local port_index
    while :; do
        read -p "$(echo -e "请选择要修改的配置序号 [${GREEN}1-$port_count${NONE}]: ")" port_index
        if [[ -z "$port_index" ]] || ! [[ "$port_index" =~ ^[0-9]+$ ]] || \
           [[ "$port_index" -lt 1 ]] || [[ "$port_index" -gt "$port_count" ]]; then
            msg_error; continue
        fi
        break
    done

    local port=$(jq -r ".ports[$((port_index-1))].port" "$PORT_INFO_FILE")
    local original_md5=$(jq -c '.ports' "$PORT_INFO_FILE" | md5sum | cut -d ' ' -f1)

    # 获取当前IP
    get_local_ips
    local current_ip=$IPv4 current_netstack=4
    [[ -z "$current_ip" && -n "$IPv6" ]] && current_ip=$IPv6 && current_netstack=6

    echo -e "${YELLOW}正在修改端口 ${CYAN}$port${NONE} 的配置${NONE}"
    print_line
    echo -e "  ${GREEN}1.${NONE} 修改UUID"
    echo -e "  ${GREEN}2.${NONE} 修改域名(SNI)"
    echo -e "  ${GREEN}3.${NONE} 修改ShortID"
    echo -e "  ${GREEN}4.${NONE} 修改SOCKS5代理设置"
    echo -e "  ${GREEN}5.${NONE} 管理HAProxy设置"
    echo -e "  ${GREEN}0.${NONE} 返回"
    print_line

    read -p "$(echo -e "请选择 [${GREEN}0-5${NONE}]: ")" choice

    case $choice in
        1) modify_port_uuid "$port" ;;
        2) modify_port_domain "$port" ;;
        3) modify_port_shortid "$port" ;;
        4) modify_port_socks5 "$port" ;;
        5) modify_port_haproxy "$port" ;;
        0) return ;;
        *) msg_error; return ;;
    esac

    # 检查是否有变更
    local new_md5=$(jq -c '.ports' "$PORT_INFO_FILE" | md5sum | cut -d ' ' -f1)
    if [[ "$original_md5" != "$new_md5" ]]; then
        msg_info "配置已更改，更新Xray配置..."
        update_config_file
        restart_xray

        local port_info=$(get_port_info "$port")
        generate_connection_info "$port" \
            "$(echo "$port_info" | jq -r '.uuid')" \
            "$(echo "$port_info" | jq -r '.public_key')" \
            "$(echo "$port_info" | jq -r '.shortid')" \
            "$(echo "$port_info" | jq -r '.domain')" \
            "$current_ip" "$current_netstack"
    fi

    pause
}

# 修改UUID
modify_port_uuid() {
    local port=$1
    local port_info=$(get_port_info "$port")
    local old_uuid=$(echo "$port_info" | jq -r '.uuid')

    echo -e "当前UUID: ${CYAN}$old_uuid${NONE}"

    local default_uuid=$(generate_default_uuid "$IPv4" "$port")
    local new_uuid
    while :; do
        read -p "$(echo -e "请输入新UUID (默认: ${CYAN}${default_uuid}${NONE}): ")" new_uuid
        [[ -z "$new_uuid" ]] && new_uuid=$default_uuid
        if ! validate_uuid "$new_uuid"; then
            msg_error; continue
        fi
        break
    done

    local tmp_key new_private_key new_public_key
    tmp_key=$(generate_keys "$new_uuid")
    new_private_key=$(echo "$tmp_key" | awk -F': ' '/^PrivateKey:/{print $2; exit}')
    new_public_key=$(echo "$tmp_key" | awk -F': ' '/^(Password \(PublicKey\)|PublicKey):/{print $2; exit}')
    [[ -n "$new_private_key" && -n "$new_public_key" ]] || {
        echo -e "${RED}X25519密钥生成或解析失败${NONE}"
        return 1
    }
    local new_shortid=$(echo -n "${new_uuid}" | sha1sum | head -c 16)
    local domain=$(echo "$port_info" | jq -r '.domain')

    save_port_info "$port" "$new_uuid" "$new_private_key" "$new_public_key" "$new_shortid" "$domain"
    preserve_port_proxy_config "$port"

    msg_success "UUID修改成功!"
    log_info "修改端口 $port 的UUID: $old_uuid -> $new_uuid"
}

# 修改域名
modify_port_domain() {
    local port=$1
    local port_info=$(get_port_info "$port")
    local old_domain=$(echo "$port_info" | jq -r '.domain')

    echo -e "当前域名: ${CYAN}$old_domain${NONE}"

    while :; do
        read -r -p "$(echo -e "请输入新域名 (默认: ${CYAN}learn.microsoft.com${NONE}): ")" new_domain
        [[ -z "$new_domain" ]] && new_domain="learn.microsoft.com"
        validate_domain "$new_domain" && break
        echo -e "${RED}域名格式无效${NONE}"
    done

    save_port_info "$port" \
        "$(echo "$port_info" | jq -r '.uuid')" \
        "$(echo "$port_info" | jq -r '.private_key')" \
        "$(echo "$port_info" | jq -r '.public_key')" \
        "$(echo "$port_info" | jq -r '.shortid')" \
        "$new_domain"
    preserve_port_proxy_config "$port"

    msg_success "域名修改成功!"
    log_info "修改端口 $port 的域名: $old_domain -> $new_domain"
}

# 修改ShortID
modify_port_shortid() {
    local port=$1
    local port_info=$(get_port_info "$port")
    local old_shortid=$(echo "$port_info" | jq -r '.shortid')
    local uuid=$(echo "$port_info" | jq -r '.uuid')

    echo -e "当前ShortID: ${CYAN}$old_shortid${NONE}"

    local default_shortid=$(echo -n "${uuid}" | sha1sum | head -c 16)
    local new_shortid
    while :; do
        read -p "$(echo -e "请输入新ShortID (默认: ${CYAN}${default_shortid}${NONE}): ")" new_shortid
        [[ -z "$new_shortid" ]] && new_shortid=$default_shortid
        if ! validate_shortid "$new_shortid"; then
            msg_error; continue
        fi
        break
    done

    save_port_info "$port" "$uuid" \
        "$(echo "$port_info" | jq -r '.private_key')" \
        "$(echo "$port_info" | jq -r '.public_key')" \
        "$new_shortid" \
        "$(echo "$port_info" | jq -r '.domain')"
    preserve_port_proxy_config "$port"

    msg_success "ShortID修改成功!"
    log_info "修改端口 $port 的ShortID: $old_shortid -> $new_shortid"
}

# 修改SOCKS5设置
modify_port_socks5() {
    local port=$1
    local port_info=$(get_port_info "$port")
    local socks5_config=$(echo "$port_info" | jq -r '.socks5')

    if [[ "$socks5_config" != "null" && "$(echo "$socks5_config" | jq -r '.enabled')" == "true" ]]; then
        echo -e "当前状态: ${GREEN}已启用${NONE}"
        local addr=$(echo "$socks5_config" | jq -r '.address')
        local sport=$(echo "$socks5_config" | jq -r '.port')
        echo -e "SOCKS5服务器: ${CYAN}$addr:$sport${NONE}"

        if read_yes_no "是否禁用SOCKS5代理?" "n"; then
            set_port_socks5_config "$port" "n" "" "" "" "" "" ""
            set_port_haproxy_config "$port" "n" 1 1 1
            update_haproxy_config
            msg_success "SOCKS5代理已禁用!"
        else
            configure_socks5 "$port"
        fi
    else
        echo -e "当前状态: ${RED}未启用${NONE}"
        if read_yes_no "是否启用SOCKS5代理?" "n"; then
            configure_socks5 "$port"
        fi
    fi

    update_config_file
}

# 修改HAProxy设置
modify_port_haproxy() {
    local port=$1
    local port_info=$(get_port_info "$port")
    local socks5_config=$(echo "$port_info" | jq -r '.socks5')

    if [[ "$socks5_config" == "null" || "$(echo "$socks5_config" | jq -r '.enabled')" != "true" ]]; then
        echo -e "${RED}请先配置SOCKS5代理${NONE}"
        pause
        return
    fi

    local haproxy_config=$(echo "$port_info" | jq -r '.haproxy')
    if [[ "$haproxy_config" != "null" && "$(echo "$haproxy_config" | jq -r '.enabled')" == "true" ]]; then
        local hport=$(echo "$haproxy_config" | jq -r '.port')
        local threads=$(echo "$haproxy_config" | jq -r '.threads')
        local maxconn=$(echo "$haproxy_config" | jq -r '.maxconn')

        echo -e "当前状态: ${GREEN}已启用${NONE}"
        echo -e "端口: ${CYAN}$hport${NONE}, 线程: ${CYAN}$threads${NONE}, 最大连接: ${CYAN}$maxconn${NONE}"

        echo -e "\n  ${GREEN}1.${NONE} 修改配置"
        echo -e "  ${GREEN}0.${NONE} 返回"
        read -p "请选择 [0-1]: " action

        if [[ "$action" == "1" ]]; then
            read -p "$(echo -e "新HAProxy端口 (当前: ${CYAN}$hport${NONE}): ")" new_port
            [[ -z "$new_port" ]] && new_port=$hport
            read -p "$(echo -e "新线程数 (当前: ${CYAN}$threads${NONE}): ")" new_threads
            [[ -z "$new_threads" ]] && new_threads=$threads
            read -p "$(echo -e "新最大连接数 (当前: ${CYAN}$maxconn${NONE}): ")" new_maxconn
            [[ -z "$new_maxconn" ]] && new_maxconn=$maxconn

            set_port_haproxy_config "$port" "y" "$new_port" "$new_threads" "$new_maxconn"
            update_haproxy_config
            msg_success "HAProxy配置已更新!"
        fi
    else
        echo -e "当前状态: ${RED}未启用${NONE}"
        if read_yes_no "是否启用HAProxy?" "n"; then
            local haproxy_port=$(find_available_port $((port + 1)))
            read -p "$(echo -e "HAProxy端口 (默认: ${CYAN}$haproxy_port${NONE}): ")" hport
            [[ -z "$hport" ]] && hport=$haproxy_port
            read -p "$(echo -e "线程数 (默认: ${CYAN}12${NONE}): ")" threads
            [[ -z "$threads" ]] && threads=12
            read -p "$(echo -e "最大连接数 (默认: ${CYAN}400${NONE}): ")" maxconn
            [[ -z "$maxconn" ]] && maxconn=400

            set_port_haproxy_config "$port" "y" "$hport" "$threads" "$maxconn"
            update_haproxy_config
            msg_success "HAProxy已启用!"
        fi
    fi
}

# 删除端口配置
delete_port_configuration() {
    print_title "删除端口配置"

    local port_count=$(get_port_count)
    if [[ $port_count -eq 0 ]]; then
        echo -e "${RED}目前没有配置任何端口${NONE}"
        return
    fi

    list_port_configurations

    local port_index
    while :; do
        read -p "$(echo -e "请选择要删除的配置序号 [${GREEN}1-$port_count${NONE}], 输入 0 取消: ")" port_index

        [[ "$port_index" == "0" ]] && { echo -e "${YELLOW}操作已取消${NONE}"; return; }

        if [[ -z "$port_index" ]] || ! [[ "$port_index" =~ ^[0-9]+$ ]] || \
           [[ "$port_index" -lt 1 ]] || [[ "$port_index" -gt "$port_count" ]]; then
            msg_error; continue
        fi
        break
    done

    local port=$(jq -r ".ports[$((port_index-1))].port" "$PORT_INFO_FILE")

    if read_yes_no "确认删除端口 $port 的配置?" "n"; then
        delete_port_info "$port"
        rm -f "$HOME/vless_reality_${port}.txt"

        if [[ $(get_port_count) -eq 0 ]]; then
            msg_info "已删除所有端口配置，停止服务"
            systemctl stop haproxy xray 2>/dev/null
            [[ -f "$CONFIG_FILE" ]] && mv "$CONFIG_FILE" "${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
            [[ -f "$HAPROXY_CONFIG" ]] && mv "$HAPROXY_CONFIG" "${HAPROXY_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
        else
            update_config_file
            update_haproxy_config
            restart_xray
        fi

        msg_success "端口 $port 配置已删除!"
    fi

    pause
}

# ============================================================
# 第九部分：显示和信息生成
# ============================================================

# 显示端口列表
list_port_configurations() {
    echo
    print_title "当前所有端口配置"

    local port_count=$(get_port_count)
    if [[ $port_count -eq 0 ]]; then
        echo -e "${RED}目前没有配置任何端口${NONE}"
        return
    fi

    echo -e "${CYAN}序号   端口    UUID    域名    代理状态    HAProxy状态${NONE}"
    print_line

    local index=1
    while read -r port_info; do
        local port=$(echo "$port_info" | jq -r '.port')
        local uuid=$(echo "$port_info" | jq -r '.uuid')
        local uuid_short="${uuid:0:8}...${uuid:24}"
        local domain=$(echo "$port_info" | jq -r '.domain')

        local socks5_status="${RED}禁用${NONE}"
        if [[ "$(echo "$port_info" | jq -r '.socks5.enabled')" == "true" ]]; then
            local addr=$(echo "$port_info" | jq -r '.socks5.address')
            local sport=$(echo "$port_info" | jq -r '.socks5.port')
            socks5_status="${GREEN}启用 (${addr}:${sport})${NONE}"
        fi

        local haproxy_status="${RED}禁用${NONE}"
        if [[ "$(echo "$port_info" | jq -r '.haproxy.enabled')" == "true" ]]; then
            local hport=$(echo "$port_info" | jq -r '.haproxy.port')
            haproxy_status="${GREEN}启用 (端口:${hport})${NONE}"
        fi

        echo -e "${GREEN}$index${NONE}    ${CYAN}$port${NONE}    ${YELLOW}$uuid_short${NONE}    ${MAGENTA}$domain${NONE}    ${socks5_status}    ${haproxy_status}"
        index=$((index+1))
    done < <(jq -c '.ports[]' "$PORT_INFO_FILE")

    print_line

    if systemctl is-active --quiet haproxy; then
        echo -e "${GREEN}HAProxy服务状态: 运行中${NONE}"
    else
        echo -e "${RED}HAProxy服务状态: 未运行${NONE}"
    fi
}

# 生成连接信息
generate_connection_info() {
    local port=$1 uuid=$2 public_key=$3 shortid=$4 domain=$5 ip=$6 netstack=$7

    echo
    echo "---------- 端口 $port 的 Xray 配置信息 -------------"
    echo -e "${GREEN}---VLESS Reality 服务器配置---${NONE}"
    echo -e "${YELLOW}地址 = ${CYAN}${ip}${NONE}"
    echo -e "${YELLOW}端口 = ${CYAN}${port}${NONE}"
    echo -e "${YELLOW}UUID = ${CYAN}${uuid}${NONE}"
    echo -e "${YELLOW}流控 = ${CYAN}xtls-rprx-vision${NONE}"
    echo -e "${YELLOW}传输协议 = ${CYAN}tcp${NONE}"
    echo -e "${YELLOW}安全 = ${CYAN}reality${NONE}"
    echo -e "${YELLOW}SNI = ${CYAN}${domain}${NONE}"
    echo -e "${YELLOW}公钥 = ${CYAN}${public_key}${NONE}"
    echo -e "${YELLOW}ShortId = ${CYAN}${shortid}${NONE}"

    # 检查SOCKS5/HAProxy配置
    local port_info=$(get_port_info "$port")
    if [[ -n "$port_info" ]]; then
        if [[ "$(echo "$port_info" | jq -r '.socks5.enabled')" == "true" ]]; then
            local socks5_addr=$(echo "$port_info" | jq -r '.socks5.address')
            local socks5_port=$(echo "$port_info" | jq -r '.socks5.port')
            echo -e "${YELLOW}SOCKS5代理 = ${CYAN}${socks5_addr}:${socks5_port}${NONE}"

            if [[ "$(echo "$port_info" | jq -r '.haproxy.enabled')" == "true" ]]; then
                local haproxy_port=$(echo "$port_info" | jq -r '.haproxy.port')
                echo -e "${YELLOW}HAProxy端口 = ${CYAN}${haproxy_port}${NONE}"
            fi
        fi
    fi

    # 生成链接
    local display_ip=$ip
    [[ "$netstack" == "6" ]] && display_ip="[$ip]"

    local vless_url="vless://${uuid}@${display_ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=random&pbk=${public_key}&sid=${shortid}&#VLESS_R_${port}"

    echo
    echo "---------- VLESS Reality URL ----------"
    echo -e "${CYAN}${vless_url}${NONE}"
    echo
    echo "二维码:"
    qrencode -t UTF8 "$vless_url" 2>/dev/null

    # 保存到文件
    local output_file="$HOME/vless_reality_${port}.txt"
    cat > "$output_file" << EOL
---------- 端口 $port 的 Xray 配置信息 -------------
地址 = ${ip}
端口 = ${port}
UUID = ${uuid}
流控 = xtls-rprx-vision
传输协议 = tcp
安全 = reality
SNI = ${domain}
公钥 = ${public_key}
ShortId = ${shortid}

---------- VLESS Reality URL ----------
${vless_url}
EOL

    echo
    echo "链接信息已保存到 $output_file"
    log_info "生成端口 $port 的连接信息"
}

# 显示所有连接
show_all_connections() {
    print_title "端口连接信息"

    local port_count=$(get_port_count)
    if [[ $port_count -eq 0 ]]; then
        echo -e "${RED}目前没有配置任何端口${NONE}"
        return
    fi

    if ! get_local_ips; then
        echo -e "${RED}获取IP地址失败!${NONE}"
        return
    fi

    local ip=$IPv4 netstack=4
    [[ -z "$ip" && -n "$IPv6" ]] && ip=$IPv6 && netstack=6

    while read -r port_info; do
        generate_connection_info \
            "$(echo "$port_info" | jq -r '.port')" \
            "$(echo "$port_info" | jq -r '.uuid')" \
            "$(echo "$port_info" | jq -r '.public_key')" \
            "$(echo "$port_info" | jq -r '.shortid')" \
            "$(echo "$port_info" | jq -r '.domain')" \
            "$ip" "$netstack"
    done < <(jq -c '.ports[]' "$PORT_INFO_FILE")

    pause
}

# ============================================================
# 第十部分：备份恢复、安装卸载
# ============================================================

# 备份配置
backup_configuration() {
    print_title "备份当前配置"

    local backup_dir="$HOME/xray_backup_$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"

    [[ -f "$PORT_INFO_FILE" ]] && cp "$PORT_INFO_FILE" "$backup_dir/"
    [[ -f "$CONFIG_FILE" ]] && cp "$CONFIG_FILE" "$backup_dir/"
    [[ -f "$HAPROXY_CONFIG" ]] && cp "$HAPROXY_CONFIG" "$backup_dir/"
    cp -r "$CONFIG_DIR"/* "$backup_dir/" 2>/dev/null

    tar -czf "${backup_dir}.tar.gz" -C "$(dirname "$backup_dir")" "$(basename "$backup_dir")"
    rm -rf "$backup_dir"

    echo -e "${GREEN}备份文件: ${backup_dir}.tar.gz${NONE}"
    log_info "备份配置到 ${backup_dir}.tar.gz"
    pause
}

# 恢复配置
restore_configuration() {
    print_title "恢复配置"

    read -p "请输入备份文件路径: " backup_file

    if [[ ! -f "$backup_file" ]]; then
        echo -e "${RED}备份文件不存在${NONE}"
        return
    fi

    if ! read_yes_no "恢复将覆盖当前配置，是否继续?" "n"; then
        return
    fi

    local temp_dir=$(mktemp -d)
    if ! tar -xzf "$backup_file" -C "$temp_dir"; then
        echo -e "${RED}解压备份文件失败${NONE}"
        rm -rf "$temp_dir"
        return
    fi

    local port_info_file=$(find "$temp_dir" -name ".xray_port_info.json" | head -n 1)
    local xray_config=$(find "$temp_dir" -name "config.json" | head -n 1)
    local haproxy_cfg=$(find "$temp_dir" -name "haproxy.cfg" | head -n 1)

    [[ -n "$port_info_file" ]] && cp "$port_info_file" "$PORT_INFO_FILE" && chmod 600 "$PORT_INFO_FILE"
    [[ -n "$xray_config" ]] && mkdir -p "$CONFIG_DIR" && cp "$xray_config" "$CONFIG_FILE"
    [[ -n "$haproxy_cfg" ]] && mkdir -p /etc/haproxy && cp "$haproxy_cfg" "$HAPROXY_CONFIG"

    rm -rf "$temp_dir"

    [[ -n "$haproxy_cfg" ]] && restart_haproxy
    [[ -n "$xray_config" ]] && restart_xray

    msg_success "配置恢复完成!"
    pause
}

# 更新GeoData
update_geodata() {
    print_title "更新 GeoIP 和 GeoSite 数据"

    if bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata; then
        msg_success "数据库更新成功!"
        restart_xray
    else
        msg_warn "官方脚本更新失败，尝试手动更新..."
        if wget -O /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat && \
           wget -O /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat; then
            msg_success "数据库手动更新成功!"
            restart_xray
        else
            echo -e "${RED}数据库更新失败!${NONE}"
        fi
    fi

    echo -e "${YELLOW}当前 Xray 版本:${NONE}"
    xray --version
    pause
}

# 安装Xray
install_xray() {
    echo
    echo -e "${YELLOW}此脚本仅兼容 Debian 10+ 系统${NONE}"
    echo -e "脚本版本: ${CYAN}$VERSION${NONE}"
    print_line

    msg_info "安装依赖..."
    if ! apt-get update || ! apt-get install -y curl sudo jq qrencode net-tools lsof wget; then
        echo -e "${RED}依赖安装失败${NONE}"
        return 1
    fi

    if command -v xray &> /dev/null; then
        if ! read_yes_no "检测到已安装Xray，是否重新安装?" "n"; then
            return
        fi
    fi

    msg_info "安装Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

    if ! command -v xray &> /dev/null; then
        echo -e "${RED}Xray 安装失败${NONE}"
        return 1
    fi

    update_geodata

    # 启用BBR
    msg_info "启用BBR..."
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1

    init_directories

    msg_success "Xray 安装完成!"
    msg_info "接下来请添加端口配置"
    pause

    add_port_configuration
}

# 卸载Xray
uninstall_xray() {
    print_title "卸载 Xray"

    echo -e "${RED}警告: 此操作将完全卸载 Xray 和 HAProxy 并删除所有配置!${NONE}"

    read -p "$(echo -e "确认卸载? 输入 ${RED}uninstall${NONE} 确认: ")" confirm
    [[ "$confirm" != "uninstall" ]] && { echo -e "${YELLOW}操作已取消${NONE}"; return; }

    # 停止HAProxy
    if systemctl is-active --quiet haproxy; then
        systemctl stop haproxy
        systemctl disable haproxy
    fi
    [[ -f "$HAPROXY_CONFIG" ]] && rm -f "$HAPROXY_CONFIG"

    # 卸载Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge

    # 清理文件
    [[ -f "$PORT_INFO_FILE" ]] && rm -f "$PORT_INFO_FILE"
    rm -f "$HOME/vless_reality_"*.txt 2>/dev/null
    [[ -f "$LOG_FILE" ]] && rm -f "$LOG_FILE"

    if read_yes_no "是否卸载HAProxy软件包?" "n"; then
        apt -y remove haproxy && apt -y autoremove
    fi

    msg_success "Xray 和 HAProxy 已完全卸载!"
    pause
}

# 查看日志
view_xray_logs() {
    print_title "查看 Xray 日志"

    echo -e "  ${GREEN}1.${NONE} 访问日志"
    echo -e "  ${GREEN}2.${NONE} 错误日志"
    echo -e "  ${GREEN}0.${NONE} 返回"

    read -p "请选择 [0-2]: " choice

    case $choice in
        1) [[ -f "/var/log/xray/access.log" ]] && tail -n 100 /var/log/xray/access.log || echo -e "${RED}日志不存在${NONE}" ;;
        2) [[ -f "/var/log/xray/error.log" ]] && tail -n 100 /var/log/xray/error.log || echo -e "${RED}日志不存在${NONE}" ;;
    esac

    pause
}

# 显示帮助
show_help() {
    print_title "帮助信息"
    echo -e "  ${GREEN}1.${NONE} 安装/重装 Xray - 安装或重新安装Xray"
    echo -e "  ${GREEN}2.${NONE} 添加新端口配置 - 添加VLESS Reality端口"
    echo -e "  ${GREEN}3.${NONE} 查看所有端口配置 - 显示已配置的端口列表"
    echo -e "  ${GREEN}4.${NONE} 修改端口配置 - 修改UUID/域名/ShortID/代理设置"
    echo -e "  ${GREEN}5.${NONE} 删除端口配置 - 删除指定端口"
    echo -e "  ${GREEN}6.${NONE} 显示连接信息 - 生成连接链接和二维码"
    echo -e "  ${GREEN}7.${NONE} 更新GeoData - 更新GeoIP/GeoSite数据库"
    echo -e "  ${GREEN}8.${NONE} 备份与恢复 - 备份或恢复配置"
    echo -e "  ${GREEN}9.${NONE} 查看日志 - 查看Xray运行日志"
    echo -e "  ${GREEN}10.${NONE} 帮助信息 - 显示此帮助"
    echo -e "  ${GREEN}11.${NONE} 卸载Xray - 完全卸载Xray和HAProxy"
    echo -e "  ${GREEN}12.${NONE} 同步配置 - 从Xray配置恢复端口信息"
    print_line
    echo -e "版本: ${CYAN}$VERSION${NONE}"
    pause
}

# ============================================================
# 第十一部分：配置同步（从Xray配置恢复端口信息）
# ============================================================

# 从Xray配置同步端口信息
sync_config_from_xray() {
    print_title "从Xray配置同步端口信息"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}Xray配置文件不存在${NONE}"
        return 1
    fi

    echo -e "${YELLOW}此功能将从现有Xray配置中提取端口信息${NONE}"
    echo -e "${YELLOW}适用于 .xray_port_info.json 丢失或损坏的情况${NONE}"
    echo

    if ! read_yes_no "是否继续?" "n"; then
        return
    fi

    # 解析现有HAProxy配置
    declare -A haproxy_map  # vless_port -> "haproxy_port:socks5_addr:socks5_port"
    if [[ -f "$HAPROXY_CONFIG" ]]; then
        msg_info "解析现有HAProxy配置..."
        local current_vless_port="" current_haproxy_port=""

        while IFS= read -r line; do
            if [[ "$line" =~ ^frontend\ socks_front_([0-9]+)$ ]]; then
                current_vless_port="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ bind\ \*:([0-9]+) && -n "$current_vless_port" ]]; then
                current_haproxy_port="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ server\ socks1\ ([^:]+):([0-9]+) && -n "$current_vless_port" ]]; then
                local socks5_addr="${BASH_REMATCH[1]}"
                local socks5_port="${BASH_REMATCH[2]}"
                haproxy_map[$current_vless_port]="${current_haproxy_port}:${socks5_addr}:${socks5_port}"
                echo -e "${GREEN}发现HAProxy配置: VLESS端口=$current_vless_port -> HAProxy端口=$current_haproxy_port, SOCKS5=$socks5_addr:$socks5_port${NONE}"
                current_vless_port=""
            fi
        done < "$HAPROXY_CONFIG"
    fi

    # 重置端口信息文件
    echo '{"ports":[]}' > "$PORT_INFO_FILE"
    chmod 600 "$PORT_INFO_FILE"

    # 解析Xray配置中的inbound
    msg_info "解析Xray配置..."
    local inbound_count=0

    while read -r inbound; do
        [[ -z "$inbound" ]] && continue

        local protocol=$(echo "$inbound" | jq -r '.protocol')
        local security=$(echo "$inbound" | jq -r '.streamSettings.security // ""')

        # 只处理VLESS+Reality
        if [[ "$protocol" != "vless" || "$security" != "reality" ]]; then
            continue
        fi

        local port=$(echo "$inbound" | jq -r '.port')
        local uuid=$(echo "$inbound" | jq -r '.settings.clients[0].id')
        local private_key=$(echo "$inbound" | jq -r '.streamSettings.realitySettings.privateKey')
        local shortid=$(echo "$inbound" | jq -r '.streamSettings.realitySettings.shortIds[1] // .streamSettings.realitySettings.shortIds[0] // ""')
        local domain=$(echo "$inbound" | jq -r '.streamSettings.realitySettings.serverNames[0]')
        local tag=$(echo "$inbound" | jq -r '.tag')

        # 生成公钥
        local public_key=""
        local tmp_key
        tmp_key=$(xray x25519 -i "${private_key}" 2>/dev/null)
        if [[ -n "$tmp_key" ]]; then
            public_key=$(echo "$tmp_key" | awk -F': ' '/^(Password \(PublicKey\)|PublicKey):/{print $2; exit}')
        fi

        echo -e "${CYAN}发现端口 $port: UUID=${uuid:0:8}..., 域名=$domain${NONE}"

        # 保存基本信息
        save_port_info "$port" "$uuid" "$private_key" "$public_key" "$shortid" "$domain"

        # 查找关联的SOCKS5出站
        local socks5_tag=""
        while read -r rule; do
            local inbound_tags=$(echo "$rule" | jq -r '.inboundTag[]? // empty' 2>/dev/null)
            if [[ "$inbound_tags" == *"$tag"* ]]; then
                local outbound_tag=$(echo "$rule" | jq -r '.outboundTag')
                if [[ "$outbound_tag" == *"socks5"* ]]; then
                    socks5_tag="$outbound_tag"
                    break
                fi
            fi
        done < <(jq -c '.routing.rules[]' "$CONFIG_FILE" 2>/dev/null)

        # 如果有SOCKS5出站，提取配置
        if [[ -n "$socks5_tag" ]]; then
            local socks5_outbound=$(jq -c --arg tag "$socks5_tag" '.outbounds[] | select(.tag == $tag)' "$CONFIG_FILE")

            if [[ -n "$socks5_outbound" ]]; then
                local socks5_addr=$(echo "$socks5_outbound" | jq -r '.settings.servers[0].address')
                local socks5_port=$(echo "$socks5_outbound" | jq -r '.settings.servers[0].port')

                # 检查认证
                local auth_needed="n"
                local socks5_user="" socks5_pass=""
                if echo "$socks5_outbound" | jq -e '.settings.servers[0].users' > /dev/null 2>&1; then
                    auth_needed="y"
                    socks5_user=$(echo "$socks5_outbound" | jq -r '.settings.servers[0].users[0].user // ""')
                    socks5_pass=$(echo "$socks5_outbound" | jq -r '.settings.servers[0].users[0].pass // ""')

                    # 如果用户名密码不完整，提示输入
                    if [[ -z "$socks5_user" || "$socks5_user" == "1" || -z "$socks5_pass" || "$socks5_pass" == "1" ]]; then
                        echo -e "${YELLOW}端口 $port 的SOCKS5认证信息不完整${NONE}"
                        read -p "请输入SOCKS5用户名: " socks5_user
                        read -p "请输入SOCKS5密码: " socks5_pass
                    fi
                fi

                # 检查UDP over TCP
                local udp_over_tcp="n"
                if echo "$socks5_outbound" | jq -e '.streamSettings.sockopt.udpFragmentSize' > /dev/null 2>&1; then
                    udp_over_tcp="y"
                fi

                # 如果SOCKS5地址是本地地址，尝试从HAProxy配置获取真实地址
                if [[ "$socks5_addr" == "127.0.0.1" || "$socks5_addr" == "localhost" ]]; then
                    if [[ -n "${haproxy_map[$port]}" ]]; then
                        IFS=':' read -r hp_port hp_addr hp_sport <<< "${haproxy_map[$port]}"
                        echo -e "${YELLOW}端口 $port 使用HAProxy转发，真实SOCKS5地址: $hp_addr:$hp_sport${NONE}"
                        socks5_addr="$hp_addr"
                        socks5_port="$hp_sport"

                        # 设置SOCKS5和HAProxy配置
                        set_port_socks5_config "$port" "y" "$socks5_addr" "$socks5_port" "$auth_needed" "$socks5_user" "$socks5_pass" "$udp_over_tcp"
                        set_port_haproxy_config "$port" "y" "$hp_port" 12 400
                    else
                        echo -e "${RED}警告: 端口 $port 的SOCKS5使用本地地址但未找到HAProxy配置${NONE}"
                        set_port_socks5_config "$port" "y" "$socks5_addr" "$socks5_port" "$auth_needed" "$socks5_user" "$socks5_pass" "$udp_over_tcp"
                    fi
                else
                    # 非本地地址，检查是否有HAProxy配置
                    set_port_socks5_config "$port" "y" "$socks5_addr" "$socks5_port" "$auth_needed" "$socks5_user" "$socks5_pass" "$udp_over_tcp"

                    if [[ -n "${haproxy_map[$port]}" ]]; then
                        IFS=':' read -r hp_port _ _ <<< "${haproxy_map[$port]}"
                        set_port_haproxy_config "$port" "y" "$hp_port" 12 400
                    fi
                fi

                echo -e "${GREEN}端口 $port: SOCKS5代理已配置 ($socks5_addr:$socks5_port)${NONE}"
            fi
        fi

        inbound_count=$((inbound_count + 1))
    done < <(jq -c '.inbounds[]' "$CONFIG_FILE")

    if [[ $inbound_count -eq 0 ]]; then
        echo -e "${RED}未在Xray配置中找到VLESS+Reality端口${NONE}"
        return 1
    fi

    echo
    echo -e "${GREEN}成功同步 $inbound_count 个端口配置${NONE}"

    # 重新生成配置文件确保一致性
    msg_info "重新生成配置文件..."
    update_config_file

    # 更新HAProxy配置
    local haproxy_count=$(jq '[.ports[] | select(.haproxy != null and .haproxy.enabled == true)] | length' "$PORT_INFO_FILE")
    if [[ $haproxy_count -gt 0 ]]; then
        msg_info "更新HAProxy配置..."
        update_haproxy_config
    fi

    # 重启服务
    restart_xray

    msg_success "配置同步完成!"
    list_port_configurations
    pause
}

# ============================================================
# 第十二部分：主菜单和入口
# ============================================================

show_menu() {
    while true; do
        echo
        echo "---------- Xray 多端口管理脚本 V${VERSION} -------------"
        echo -e "  ${GREEN}1.${NONE} 安装/重装 Xray"
        echo -e "  ${GREEN}2.${NONE} 添加新端口配置"
        echo -e "  ${GREEN}3.${NONE} 查看所有端口配置"
        echo -e "  ${GREEN}4.${NONE} 修改端口配置"
        echo -e "  ${GREEN}5.${NONE} 删除端口配置"
        echo -e "  ${GREEN}6.${NONE} 显示所有端口连接信息"
        echo -e "  ${GREEN}7.${NONE} 更新 GeoIP/GeoSite 数据"
        echo -e "  ${GREEN}8.${NONE} 备份与恢复"
        echo -e "  ${GREEN}9.${NONE} 查看 Xray 日志"
        echo -e "  ${GREEN}10.${NONE} 帮助信息"
        echo -e "  ${GREEN}11.${NONE} 卸载 Xray"
        echo -e "  ${GREEN}12.${NONE} 从Xray配置同步端口信息"
        echo -e "  ${GREEN}0.${NONE} 退出"
        echo "------------------------------------"
        read -p "请选择 [0-12]: " choice

        case $choice in
            1) install_xray ;;
            2) add_port_configuration ;;
            3) list_port_configurations; pause ;;
            4) modify_port_configuration ;;
            5) delete_port_configuration ;;
            6) show_all_connections ;;
            7) update_geodata ;;
            8)
                echo -e "\n  ${GREEN}1.${NONE} 备份配置"
                echo -e "  ${GREEN}2.${NONE} 恢复配置"
                echo -e "  ${GREEN}0.${NONE} 返回"
                read -p "请选择 [0-2]: " sub
                case $sub in
                    1) backup_configuration ;;
                    2) restore_configuration ;;
                esac
                ;;
            9) view_xray_logs ;;
            10) show_help ;;
            11) uninstall_xray ;;
            12) sync_config_from_xray ;;
            0) echo -e "${GREEN}感谢使用 Xray 多端口管理脚本${NONE}"; exit 0 ;;
            *) msg_error ;;
        esac
    done
}

main() {
    check_root
    init_directories
    check_dependencies || exit 1
    log_info "脚本启动，版本 $VERSION"

    if [[ $# -eq 0 ]]; then
        show_menu
    else
        install_xray "$@"
    fi
}

# 被测试脚本source时不自动执行
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
