#!/bin/bash

echo "=========================================="
echo "Xray密钥生成诊断脚本"
echo "=========================================="
echo

# 使用PORT_INFO_FILE中的UUID
uuid="262173df-aa59-315d-a961-cad800edb216"

echo "步骤1: 生成seed"
seed=$(echo -n ${uuid} | md5sum | head -c 32 | base64 -w 0 | tr '+/' '-_' | tr -d '=')
echo "UUID: $uuid"
echo "生成的seed: $seed"
echo

echo "=========================================="
echo "步骤2: 运行xray x25519命令"
echo "=========================================="
echo "命令: xray x25519 -i \"${seed}\""
echo
echo "完整输出:"
xray x25519 -i "${seed}"
echo

echo "=========================================="
echo "步骤3: 捕获输出到变量并分析"
echo "=========================================="
tmp_key=$(xray x25519 -i "${seed}")
echo "tmp_key变量的完整内容:"
echo "$tmp_key"
echo

echo "=========================================="
echo "步骤4: 使用awk提取字段"
echo "=========================================="
echo "tmp_key的字段分解:"
echo "$tmp_key" | awk '{for(i=1;i<=NF;i++) print "字段$" i ": " $i}'
echo

echo "awk '{print \$3}' 提取结果: $(echo ${tmp_key} | awk '{print $3}')"
echo "awk '{print \$6}' 提取结果: $(echo ${tmp_key} | awk '{print $6}')"
echo

echo "=========================================="
echo "步骤5: 对比PORT_INFO_FILE中保存的值"
echo "=========================================="
echo "PORT_INFO_FILE中的private_key: Password:"
echo "PORT_INFO_FILE中的public_key: xr0zPPudUXhC6jMKW-ase0ERGG1M2LCUciEQ64h3daM"
echo

echo "=========================================="
echo "诊断完成"
echo "=========================================="
