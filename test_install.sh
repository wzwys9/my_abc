#!/usr/bin/env bash
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
jq -e '.ports[0].socks5.username == "user\"name"' "$PORT_INFO_FILE" >/dev/null
jq -e '.inbounds[0].port == 7999' "$CONFIG_FILE" >/dev/null
jq -e '.outbounds[] | select(.tag == "socks5-out-7999") | .settings.servers[0].users[0].pass == "p@ss\"word"' "$CONFIG_FILE" >/dev/null
jq -e '.routing.rules[] | select(.outboundTag == "socks5-out-7999")' "$CONFIG_FILE" >/dev/null

# 非法HAProxy参数不得破坏状态文件
state_before=$(sha256sum "$PORT_INFO_FILE" | cut -d' ' -f1)
assert_fail set_port_haproxy_config 7999 y invalid 2 400
state_after=$(sha256sum "$PORT_INFO_FILE" | cut -d' ' -f1)
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

echo "ALL TESTS PASSED"
