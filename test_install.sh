#!/usr/bin/env bash
# shellcheck disable=SC2218  # 测试中会临时替换后文定义的函数以注入失败
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/etc/xray"

# 生成路径隔离的测试副本，避免触碰宿主机配置
sed \
    -e "s|readonly CONFIG_FILE=.*|readonly CONFIG_FILE=\"$TMP/etc/xray/config.json\"|" \
    -e "s|readonly CONFIG_DIR=.*|readonly CONFIG_DIR=\"$TMP/etc/xray\"|" \
    -e "s|readonly PORT_INFO_FILE=.*|readonly PORT_INFO_FILE=\"$TMP/port-info.json\"|" \
    -e "s|readonly LOG_FILE=.*|readonly LOG_FILE=\"$TMP/management.log\"|" \
    -e "s|readonly HAPROXY_CONFIG=.*|readonly HAPROXY_CONFIG=\"$TMP/haproxy.cfg\"|" \
    -e "s|readonly LOCK_FILE=.*|readonly LOCK_FILE=\"$TMP/manager.lock\"|" \
    "$SCRIPT_DIR/install.sh" > "$TMP/install-testable.sh"
# shellcheck source=/dev/null
source "$TMP/install-testable.sh"

echo '{"ports":[]}' > "$PORT_INFO_FILE"
: > "$LOG_FILE"

assert_ok() { "$@" || { echo "FAIL: $*" >&2; exit 1; }; }
assert_fail() { if "$@"; then echo "FAIL (expected failure): $*" >&2; exit 1; fi; }

assert_ok validate_port 443
assert_fail validate_port 0
assert_fail validate_port 65536
assert_ok validate_uuid 550E8400-E29B-41D4-A716-446655440000
assert_ok validate_shortid a1B2c3D4
assert_ok validate_shortid ''
assert_fail validate_shortid xyz
assert_fail validate_shortid abc
assert_ok validate_domain learn.microsoft.com
assert_fail validate_domain 'bad"domain.com'
assert_ok validate_proxy_host proxy.example.com
assert_ok validate_proxy_host 2001:db8::1
assert_fail validate_proxy_host $'proxy.example.com\nserver evil 1.2.3.4:80'
assert_fail validate_proxy_host 'proxy example.com'

# 兼容新版Xray的 "Password (PublicKey):" 输出格式
key_output=$'PrivateKey: private-test-key\nPassword (PublicKey): public-test-key\nHash32: ignored'
parsed_private=$(echo "$key_output" | awk -F': ' '/^PrivateKey:/{print $2; exit}')
parsed_public=$(echo "$key_output" | awk -F': ' '/^(Password \(PublicKey\)|PublicKey):/{print $2; exit}')
[[ "$parsed_private" == private-test-key && "$parsed_public" == public-test-key ]]

uuid=550e8400-e29b-41d4-a716-446655440000
save_port_info 7999 "$uuid" private public a1b2c3d4 'learn.microsoft.com'
set_port_socks5_config 7999 y 'proxy.example.com' 1080 y 'user"name' 'p@ss"word' n
set_port_haproxy_config 7999 y 8009 2 400
update_config_file
[[ "$CONFIG_FILE" == *.json ]]
jq -e '.ports[0].socks5.username == "user\"name"' "$PORT_INFO_FILE" >/dev/null
jq -e '.inbounds[0].port == 7999' "$CONFIG_FILE" >/dev/null
jq -e '.outbounds[] | select(.tag == "socks5-out-7999") | .settings.servers[0].users[0].pass == "p@ss\"word"' "$CONFIG_FILE" >/dev/null
jq -e '.routing.rules[] | select(.outboundTag == "socks5-out-7999")' "$CONFIG_FILE" >/dev/null

# HAProxy端口不得与其他VLESS/HAProxy端口冲突
save_port_info 9000 "$uuid" private2 public2 b1c2d3e4 'learn.microsoft.com'
state_before=$(sha256sum "$PORT_INFO_FILE" | cut -d' ' -f1)
assert_fail set_port_haproxy_config 9000 y 8009 2 400
assert_fail set_port_haproxy_config 9000 y 7999 2 400
state_after=$(sha256sum "$PORT_INFO_FILE" | cut -d' ' -f1)
[[ "$state_before" == "$state_after" ]]
delete_port_info 9000

# 非法HAProxy参数不得破坏状态文件
state_before=$(sha256sum "$PORT_INFO_FILE" | cut -d' ' -f1)
assert_fail set_port_haproxy_config 7999 y invalid 2 400
state_after=$(sha256sum "$PORT_INFO_FILE" | cut -d' ' -f1)
[[ "$state_before" == "$state_after" ]]

# 修改已有SOCKS配置时，所有提示直接回车必须保留该端口自己的旧值
state_before=$(jq -c '.ports[0]' "$PORT_INFO_FILE")
command() {
    if [[ "$1" == "-v" && "$2" == "haproxy" ]]; then return 0; fi
    builtin command "$@"
}
original_update_haproxy=$(declare -f update_haproxy_config)
update_haproxy_config() { return 0; }
configure_socks5 7999 <<< $'\n\n\n\n\n'
unset -f command update_haproxy_config
eval "$original_update_haproxy"
state_after=$(jq -c '.ports[0]' "$PORT_INFO_FILE")
[[ "$state_before" == "$state_after" ]]

# Xray验证失败必须保留原配置
cp "$CONFIG_FILE" "$TMP/config.before"
mkdir -p "$TMP/bin"
cat > "$TMP/bin/xray" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$TMP/bin/xray"
PATH="$TMP/bin:$PATH"
assert_fail update_config_file
cmp -s "$TMP/config.before" "$CONFIG_FILE"
PATH=${PATH#"$TMP/bin:"}

# HAProxy配置需先验证再替换
cp "$HAPROXY_CONFIG" "$TMP/haproxy.before" 2>/dev/null || echo 'original-valid-config' > "$HAPROXY_CONFIG"
cp "$HAPROXY_CONFIG" "$TMP/haproxy.before"
cat > "$TMP/bin/haproxy" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$TMP/bin/haproxy"
PATH="$TMP/bin:$PATH"
restart_haproxy() { :; }
assert_fail update_haproxy_config
cmp -s "$TMP/haproxy.before" "$HAPROXY_CONFIG"

# 事务快照任一复制失败时必须失败，且不得删除或改变原状态
cp "$PORT_INFO_FILE" "$TMP/state.snapshot.before"
original_cp=$(declare -f cp 2>/dev/null || true)
cp() { return 1; }
assert_fail begin_config_transaction
unset -f cp
[[ -z "$original_cp" ]] || eval "$original_cp"
cmp -s "$TMP/state.snapshot.before" "$PORT_INFO_FILE"
[[ -z "$CONFIG_TXN_DIR" ]]

# 修改事务失败时必须同时回滚状态文件、Xray配置和HAProxy配置
cp "$PORT_INFO_FILE" "$TMP/state.transaction.before"
echo 'old-xray-config' > "$CONFIG_FILE"
echo 'old-haproxy-config' > "$HAPROXY_CONFIG"
begin_config_transaction
set_port_socks5_config 7999 y 'changed.example.com' 2080 n '' '' n
update_haproxy_config() { echo 'new-haproxy-config' > "$HAPROXY_CONFIG"; return 0; }
update_config_file() { echo 'new-xray-config' > "$CONFIG_FILE"; return 1; }
restart_xray() { echo restart >> "$TMP/restarts"; return 0; }
restart_haproxy() { echo haproxy-restart >> "$TMP/restarts"; return 0; }
assert_fail apply_configuration_changes y
cmp -s "$TMP/state.transaction.before" "$PORT_INFO_FILE"
grep -qx 'old-xray-config' "$CONFIG_FILE"
grep -qx 'old-haproxy-config' "$HAPROXY_CONFIG"

# 成功应用时Xray和HAProxy各只重启一次
echo '{"ports":[]}' > "$PORT_INFO_FILE"
save_port_info 7999 "$uuid" private public a1b2c3d4 'learn.microsoft.com'
set_port_socks5_config 7999 y '127.0.0.2' 1080 n '' '' n
set_port_haproxy_config 7999 y 8009 2 400
begin_config_transaction
: > "$TMP/restarts.success"
update_haproxy_config() { echo '{}' > "$HAPROXY_CONFIG"; return 0; }
update_config_file() { echo '{}' > "$CONFIG_FILE"; return 0; }
restart_haproxy() { echo haproxy >> "$TMP/restarts.success"; return 0; }
restart_xray() { echo xray >> "$TMP/restarts.success"; return 0; }
assert_ok apply_configuration_changes y
[[ $(grep -c '^haproxy$' "$TMP/restarts.success") -eq 1 ]]
[[ $(grep -c '^xray$' "$TMP/restarts.success") -eq 1 ]]

# 禁用最后一个HAProxy监听时应停止服务，而不是验证无法启动的空配置
set_port_haproxy_config 7999 n 1 1 1
begin_config_transaction
: > "$TMP/last-listener.calls"
update_haproxy_config() { echo should-not-generate-empty >> "$TMP/last-listener.calls"; return 1; }
update_config_file() { echo '{}' > "$CONFIG_FILE"; return 0; }
stop_haproxy() { echo stop-haproxy >> "$TMP/last-listener.calls"; return 0; }
restart_haproxy() { echo restart-haproxy >> "$TMP/last-listener.calls"; return 0; }
restart_xray() { echo restart-xray >> "$TMP/last-listener.calls"; return 0; }
assert_ok apply_configuration_changes y
! grep -q '^should-not-generate-empty$' "$TMP/last-listener.calls"
[[ $(grep -c '^stop-haproxy$' "$TMP/last-listener.calls") -eq 1 ]]
[[ $(grep -c '^restart-xray$' "$TMP/last-listener.calls") -eq 1 ]]
[[ ! -e "$HAPROXY_CONFIG" ]]

# 同步未发现有效入站时必须恢复原状态并清理事务
echo '{"ports":[{"port":7443}]}' > "$PORT_INFO_FILE"
echo '{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}' > "$CONFIG_FILE"
rm -f "$HAPROXY_CONFIG"
cp "$PORT_INFO_FILE" "$TMP/sync-state.before"
read_yes_no() { return 0; }
pause() { :; }
assert_fail sync_config_from_xray
cmp -s "$TMP/sync-state.before" "$PORT_INFO_FILE"
[[ -z "$CONFIG_TXN_DIR" ]]

# 源JSON中途损坏时必须在开启事务前拒绝，不能提交已解析出的部分结果
cat > "$CONFIG_FILE" <<'EOF'
{"inbounds":[],"outbounds":[],"routing":{"rules":[]}}
BROKEN
EOF
cp "$PORT_INFO_FILE" "$TMP/sync-corrupt.before"
assert_fail sync_config_from_xray
cmp -s "$TMP/sync-corrupt.before" "$PORT_INFO_FILE"
[[ -z "$CONFIG_TXN_DIR" ]]

# 只含状态文件的备份必须从状态重建配置，不能形成“新状态旧配置”
mkdir -p "$TMP/restore-src"
cat > "$TMP/restore-src/.xray_port_info.json" <<EOF
{"ports":[{"port":7999,"uuid":"$uuid","private_key":"private","public_key":"public","shortid":"a1b2c3d4","domain":"learn.microsoft.com","socks5":null,"haproxy":null}]}
EOF
tar -czf "$TMP/restore-state-only.tar.gz" -C "$TMP/restore-src" .
echo 'pre-restore-xray' > "$CONFIG_FILE"
echo 'pre-restore-haproxy' > "$HAPROXY_CONFIG"
update_haproxy_config() { echo 'unexpected-haproxy-generation' > "$HAPROXY_CONFIG"; return 1; }
update_config_file() { echo 'rebuilt-xray' > "$CONFIG_FILE"; return 0; }
stop_haproxy() { echo stopped > "$TMP/restore-haproxy-action"; return 0; }
restart_haproxy() { return 0; }
restart_xray() { return 0; }
assert_ok restore_configuration <<< "$TMP/restore-state-only.tar.gz"
grep -qx 'rebuilt-xray' "$CONFIG_FILE"
grep -qx 'stopped' "$TMP/restore-haproxy-action"
jq -e '.ports[0].port == 7999' "$PORT_INFO_FILE" >/dev/null
[[ ! -e "$HAPROXY_CONFIG" ]]

# 入口必须实际持有非阻塞锁；已有实例持锁时第二个实例应失败。
assert_fail flock "$LOCK_FILE" -c "bash '$TMP/install-testable.sh' </dev/null >/dev/null 2>&1"
# flock缺失时必须安装其真实软件包util-linux，而不是不存在的flock包。
grep -q 'apt install -y util-linux' "$SCRIPT_DIR/install.sh"
! grep -q 'apt install -y flock' "$SCRIPT_DIR/install.sh"

# 删除最后一个端口时，任一配置归档失败都必须可回滚，不能提交分裂状态
# 故障注入到第二份配置的备份复制，确保原活动文件尚未被删除。
echo '{"ports":[{"port":7999}]}' > "$PORT_INFO_FILE"
echo 'delete-all-old-xray' > "$CONFIG_FILE"
echo 'delete-all-old-haproxy' > "$HAPROXY_CONFIG"
cp "$PORT_INFO_FILE" "$TMP/delete-all-state.before"
begin_config_transaction
echo '{"ports":[]}' > "$PORT_INFO_FILE"
cp() {
    local destination=${!#}
    case "$destination" in
        "$HAPROXY_CONFIG".bak.*) return 1 ;;
        *) command cp "$@" ;;
    esac
}
assert_fail archive_inactive_config_files
unset -f cp
assert_ok rollback_or_report
cmp -s "$TMP/delete-all-state.before" "$PORT_INFO_FILE"
grep -qx 'delete-all-old-xray' "$CONFIG_FILE"
grep -qx 'delete-all-old-haproxy' "$HAPROXY_CONFIG"
[[ -z "$CONFIG_TXN_DIR" ]]

echo "ALL TESTS PASSED"
