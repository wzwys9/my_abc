#!/bin/bash

# Xray配置修复脚本
# 修复现有配置文件中的错误

set -e

CONFIG_FILE="/usr/local/etc/xray/config.json"
BACKUP_FILE="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

echo "==================================================="
echo "Xray配置文件修复脚本"
echo "==================================================="
echo

# 检查配置文件是否存在
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "错误: 配置文件不存在: $CONFIG_FILE"
    exit 1
fi

# 备份当前配置
echo "备份当前配置到: $BACKUP_FILE"
cp "$CONFIG_FILE" "$BACKUP_FILE"

echo "分析配置文件..."
echo

# 检查是否有错误的privateKey
if grep -q '"privateKey": "Password:"' "$CONFIG_FILE"; then
    echo "检测到错误的privateKey配置!"
    echo "以下端口需要修复:"

    # 找出所有有问题的端口
    jq -r '.inbounds[] | select(.streamSettings.realitySettings.privateKey == "Password:") | .port' "$CONFIG_FILE" | while read port; do
        echo "  - 端口 $port"
    done
    echo
fi

# 生成临时修复文件
TEMP_FILE=$(mktemp)
cp "$CONFIG_FILE" "$TEMP_FILE"

# 处理每个inbound
echo "开始修复配置..."
echo

# 获取所有inbound的索引
inbound_count=$(jq '.inbounds | length' "$TEMP_FILE")

for ((i=0; i<$inbound_count; i++)); do
    port=$(jq -r ".inbounds[$i].port" "$TEMP_FILE")
    echo "处理端口 $port ..."

    # 检查privateKey是否为"Password:"
    privateKey=$(jq -r ".inbounds[$i].streamSettings.realitySettings.privateKey" "$TEMP_FILE")

    if [[ "$privateKey" == "Password:" ]]; then
        echo "  ⚠️  检测到错误的privateKey，生成新密钥..."

        # 获取对应的UUID用于生成密钥
        uuid=$(jq -r ".inbounds[$i].settings.clients[0].id" "$TEMP_FILE")

        # 生成新的私钥
        new_private_key=$(echo -n ${uuid} | md5sum | head -c 32 | base64 -w 0 | tr '+/' '-_' | tr -d '=')

        # 获取公钥
        key_output=$(echo -n ${new_private_key} | xray x25519 -i 2>/dev/null || echo "")

        if [[ -n "$key_output" ]]; then
            actual_private_key=$(echo "$key_output" | awk '{print $3}')
            public_key=$(echo "$key_output" | awk '{print $6}')

            echo "  ✓ 新私钥: $actual_private_key"
            echo "  ✓ 新公钥: $public_key"

            # 更新privateKey
            TEMP_FILE2=$(mktemp)
            jq ".inbounds[$i].streamSettings.realitySettings.privateKey = \"$actual_private_key\"" "$TEMP_FILE" > "$TEMP_FILE2"
            mv "$TEMP_FILE2" "$TEMP_FILE"

            echo "  ⚠️  请记录端口 $port 的新公钥: $public_key"
            echo "     客户端配置需要使用这个新公钥！"
            echo
        else
            echo "  ✗ 生成密钥失败！请手动修复"
        fi
    fi

    # 更新sniffing配置
    current_sniffing=$(jq -r ".inbounds[$i].sniffing.enabled" "$TEMP_FILE")
    has_routeOnly=$(jq -r ".inbounds[$i].sniffing.routeOnly" "$TEMP_FILE")

    if [[ "$current_sniffing" == "false" ]] || [[ "$has_routeOnly" == "null" ]]; then
        echo "  ⚙️  更新sniffing配置..."

        TEMP_FILE2=$(mktemp)
        jq ".inbounds[$i].sniffing.enabled = true | .inbounds[$i].sniffing.routeOnly = true" "$TEMP_FILE" > "$TEMP_FILE2"
        mv "$TEMP_FILE2" "$TEMP_FILE"

        echo "  ✓ sniffing已更新为: enabled=true, routeOnly=true"
    fi

    # 更新shortIds配置
    shortIds=$(jq -r ".inbounds[$i].streamSettings.realitySettings.shortIds" "$TEMP_FILE")

    if [[ "$shortIds" != *'""'* ]]; then
        echo "  ⚙️  优化shortIds配置..."

        # 获取当前的shortId
        current_shortId=$(jq -r ".inbounds[$i].streamSettings.realitySettings.shortIds[0]" "$TEMP_FILE")

        TEMP_FILE2=$(mktemp)
        jq ".inbounds[$i].streamSettings.realitySettings.shortIds = [\"\", \"$current_shortId\"]" "$TEMP_FILE" > "$TEMP_FILE2"
        mv "$TEMP_FILE2" "$TEMP_FILE"

        echo "  ✓ shortIds已更新为: [\"\", \"$current_shortId\"]"
    fi

    echo "  ✓ 端口 $port 处理完成"
    echo
done

# 验证JSON格式
echo "验证修复后的配置文件..."
if jq empty "$TEMP_FILE" 2>/dev/null; then
    echo "✓ JSON格式验证通过"

    # 应用修复
    mv "$TEMP_FILE" "$CONFIG_FILE"

    echo
    echo "==================================================="
    echo "配置文件修复完成！"
    echo "==================================================="
    echo "原始配置已备份到: $BACKUP_FILE"
    echo "新配置已保存到: $CONFIG_FILE"
    echo
    echo "请执行以下命令重启Xray服务:"
    echo "  systemctl restart xray"
    echo "  systemctl status xray"
    echo
    echo "⚠️  重要提醒："
    echo "如果有端口的密钥被重新生成，请更新客户端配置中的公钥！"
    echo
else
    echo "✗ JSON格式验证失败！"
    echo "原配置未被修改，请手动检查"
    rm -f "$TEMP_FILE"
    exit 1
fi
