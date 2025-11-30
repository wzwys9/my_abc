#!/bin/bash

# ============================================
# 终端工具一键安装脚本1.2
# 包含: zoxide, fzf, bat, eza, fd, ripgrep, btop, ncdu, tmux
# ============================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检测 shell 类型
detect_shell() {
    if [ -n "$ZSH_VERSION" ]; then
        echo "zsh"
    elif [ -n "$BASH_VERSION" ]; then
        echo "bash"
    else
        echo "bash"
    fi
}

CURRENT_SHELL=$(detect_shell)
SHELL_RC="$HOME/.bashrc"
if [ "$CURRENT_SHELL" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
fi

echo ""
echo "============================================"
echo "   终端工具一键安装脚本"
echo "============================================"
echo ""
print_status "检测到 Shell: $CURRENT_SHELL"
print_status "配置文件: $SHELL_RC"
echo ""

# ============================================
# 1. 更新包管理器
# ============================================
print_status "更新包管理器..."
sudo apt update

# ============================================
# 2. 安装所有工具
# ============================================
print_status "安装终端工具..."

# 基础工具列表
TOOLS="zoxide fzf bat eza fd-find ripgrep btop ncdu tmux"

for tool in $TOOLS; do
    print_status "安装 $tool..."
    if sudo apt install -y "$tool" 2>/dev/null; then
        print_success "$tool 安装成功"
    else
        print_warning "$tool 安装失败，可能需要手动安装"
    fi
done

# ============================================
# 3. 创建全局配置脚本（所有用户生效）
# ============================================
print_status "创建全局配置脚本..."

GLOBAL_SCRIPT="/etc/profile.d/terminal-tools.sh"

sudo tee "$GLOBAL_SCRIPT" > /dev/null << 'EOF'
#!/bin/bash

# ============================================
# 终端工具全局别名配置
# 适用于所有用户
# ============================================

# ----- bat (语法高亮的 cat) -----
if command -v batcat &> /dev/null; then
    alias cat='batcat'
    alias bat='batcat'
fi

# ----- eza (更好的 ls) -----
if command -v eza &> /dev/null; then
    alias ls='eza --icons'
    alias ll='eza -l --icons --git'
    alias la='eza -la --icons --git'
    alias lt='eza --tree --level=2 --icons'
fi

# ----- fd (更好的 find) -----
if command -v fdfind &> /dev/null; then
    alias fd='fdfind'
fi

# ----- ripgrep (更好的 grep) -----
# rg 命令本身就是 ripgrep，无需别名

# ----- zoxide (智能目录跳转) -----
if command -v zoxide &> /dev/null; then
    # 根据当前 shell 类型初始化
    if [ -n "$ZSH_VERSION" ]; then
        eval "$(zoxide init zsh)"
    elif [ -n "$BASH_VERSION" ]; then
        eval "$(zoxide init bash)"
    fi
fi

# ----- fzf (模糊搜索) -----
if command -v fzf &> /dev/null; then
    # 启用 fzf 快捷键绑定（bash）
    if [ -n "$BASH_VERSION" ]; then
        if [ -f /usr/share/doc/fzf/examples/key-bindings.bash ]; then
            source /usr/share/doc/fzf/examples/key-bindings.bash
        fi
        if [ -f /usr/share/doc/fzf/examples/completion.bash ]; then
            source /usr/share/doc/fzf/examples/completion.bash
        fi
    fi
    
    # 启用 fzf 快捷键绑定（zsh）
    if [ -n "$ZSH_VERSION" ]; then
        if [ -f /usr/share/doc/fzf/examples/key-bindings.zsh ]; then
            source /usr/share/doc/fzf/examples/key-bindings.zsh
        fi
        if [ -f /usr/share/doc/fzf/examples/completion.zsh ]; then
            source /usr/share/doc/fzf/examples/completion.zsh
        fi
    fi
    
    # fzf 默认选项
    export FZF_DEFAULT_OPTS='--height 40% --layout=reverse --border'
    
    # 如果有 fd，用 fd 作为 fzf 的默认搜索命令
    if command -v fdfind &> /dev/null; then
        export FZF_DEFAULT_COMMAND='fdfind --type f --hidden --follow --exclude .git'
        export FZF_CTRL_T_COMMAND="$FZF_DEFAULT_COMMAND"
        export FZF_ALT_C_COMMAND='fdfind --type d --hidden --follow --exclude .git'
    fi
fi
EOF

# 添加可执行权限
sudo chmod +x "$GLOBAL_SCRIPT"
print_success "全局配置脚本已创建: $GLOBAL_SCRIPT"

# ============================================
# 3.5. 配置全局 bashrc（非登录 shell 也生效）
# ============================================
print_status "配置全局 bashrc（确保非登录 shell 也能加载）..."

GLOBAL_BASHRC="/etc/bash.bashrc"

# 检查是否已添加
if ! grep -q "source /etc/profile.d/terminal-tools.sh" "$GLOBAL_BASHRC" 2>/dev/null; then
    sudo tee -a "$GLOBAL_BASHRC" > /dev/null << 'EOF'

# === Load Terminal Tools Config ===
if [ -f /etc/profile.d/terminal-tools.sh ]; then
    source /etc/profile.d/terminal-tools.sh
fi
EOF
    print_success "已在 $GLOBAL_BASHRC 中添加配置加载"
else
    print_warning "$GLOBAL_BASHRC 配置已存在，跳过"
fi

# ============================================
# 4. 配置当前用户的 shell 配置文件（保留，作为备份）
# ============================================
print_status "配置当前用户的 shell 配置文件..."

# 备份原配置文件
if [ -f "$SHELL_RC" ]; then
    cp "$SHELL_RC" "${SHELL_RC}.backup.$(date +%Y%m%d_%H%M%S)"
    print_status "已备份 $SHELL_RC"
fi

# 添加配置（检查是否已存在）
MARKER="# === Terminal Tools Config (Auto Generated) ==="

if grep -q "$MARKER" "$SHELL_RC" 2>/dev/null; then
    print_warning "配置已存在，跳过添加别名"
else
    cat >> "$SHELL_RC" << 'EOF'

# === Terminal Tools Config (Auto Generated) ===

# ----- bat (语法高亮的 cat) -----
if command -v batcat &> /dev/null; then
    alias cat='batcat'
    alias bat='batcat'
fi

# ----- eza (更好的 ls) -----
if command -v eza &> /dev/null; then
    alias ls='eza --icons'
    alias ll='eza -l --icons --git'
    alias la='eza -la --icons --git'
    alias lt='eza --tree --level=2 --icons'
fi

# ----- fd (更好的 find) -----
if command -v fdfind &> /dev/null; then
    alias fd='fdfind'
fi

# ----- ripgrep (更好的 grep) -----
# rg 命令本身就是 ripgrep，无需别名

# ----- zoxide (智能目录跳转) -----
if command -v zoxide &> /dev/null; then
    eval "$(zoxide init bash)"
    # 如果是 zsh，改成: eval "$(zoxide init zsh)"
fi

# ----- fzf (模糊搜索) -----
if command -v fzf &> /dev/null; then
    # 启用 fzf 快捷键绑定
    if [ -f /usr/share/doc/fzf/examples/key-bindings.bash ]; then
        source /usr/share/doc/fzf/examples/key-bindings.bash
    fi
    if [ -f /usr/share/doc/fzf/examples/completion.bash ]; then
        source /usr/share/doc/fzf/examples/completion.bash
    fi
    
    # fzf 默认选项
    export FZF_DEFAULT_OPTS='--height 40% --layout=reverse --border'
    
    # 如果有 fd，用 fd 作为 fzf 的默认搜索命令
    if command -v fdfind &> /dev/null; then
        export FZF_DEFAULT_COMMAND='fdfind --type f --hidden --follow --exclude .git'
        export FZF_CTRL_T_COMMAND="$FZF_DEFAULT_COMMAND"
        export FZF_ALT_C_COMMAND='fdfind --type d --hidden --follow --exclude .git'
    fi
fi

# === End Terminal Tools Config ===
EOF
    print_success "别名配置已添加到 $SHELL_RC"
fi

# ============================================
# 5. 配置 tmux（全局配置）
# ============================================
print_status "配置 tmux（全局配置）..."

TMUX_CONF="/etc/tmux.conf"

if [ -f "$TMUX_CONF" ]; then
    sudo cp "$TMUX_CONF" "${TMUX_CONF}.backup.$(date +%Y%m%d_%H%M%S)"
    print_status "已备份 $TMUX_CONF"
fi

sudo tee "$TMUX_CONF" > /dev/null << 'EOF'
# ============================================
# tmux 全局配置文件
# ============================================

# ----- 基础设置 -----
# 启用鼠标支持（点击切换面板、拖拽调整大小、滚动）
set -g mouse on

# 窗口和面板编号从 1 开始（默认从 0）
set -g base-index 1
setw -g pane-base-index 1

# 自动重新编号窗口
set -g renumber-windows on

# 历史记录行数
set -g history-limit 10000

# 减少 ESC 延迟（对 vim 用户重要）
set -sg escape-time 10

# 启用 256 色
set -g default-terminal "screen-256color"

# ----- 快捷键设置 -----
# 更直观的分屏快捷键
bind | split-window -h -c "#{pane_current_path}"   # Ctrl+B | 左右分屏
bind - split-window -v -c "#{pane_current_path}"   # Ctrl+B - 上下分屏
bind _ split-window -v -c "#{pane_current_path}"   # Ctrl+B _ 上下分屏（备用）

# 新窗口保持当前路径
bind c new-window -c "#{pane_current_path}"

# Alt + 方向键切换面板（无需先按 Ctrl+B）
bind -n M-Left select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up select-pane -U
bind -n M-Down select-pane -D

# Ctrl + 方向键调整面板大小
bind -n C-Left resize-pane -L 2
bind -n C-Right resize-pane -R 2
bind -n C-Up resize-pane -U 2
bind -n C-Down resize-pane -D 2

# r 重新加载配置
bind r source-file /etc/tmux.conf \; display-message "Config reloaded!"

# ----- 状态栏设置 -----
# 状态栏位置
set -g status-position bottom

# 状态栏颜色
set -g status-style 'bg=#333333 fg=#ffffff'

# 左侧显示会话名
set -g status-left '#[fg=#ffffff,bg=#007acc] #S #[default] '
set -g status-left-length 30

# 右侧显示时间
set -g status-right '#[fg=#ffffff,bg=#555555] %Y-%m-%d %H:%M '
set -g status-right-length 50

# 当前窗口样式
setw -g window-status-current-style 'fg=#ffffff bg=#007acc bold'
setw -g window-status-current-format ' #I:#W '

# 其他窗口样式
setw -g window-status-style 'fg=#bbbbbb bg=#444444'
setw -g window-status-format ' #I:#W '

# 面板边框颜色
set -g pane-border-style 'fg=#444444'
set -g pane-active-border-style 'fg=#007acc'

# ----- 复制模式 (vi 风格) -----
setw -g mode-keys vi
bind -T copy-mode-vi v send-keys -X begin-selection
bind -T copy-mode-vi y send-keys -X copy-selection-and-cancel

# ============================================
# 常用操作速记：
# --------------------------------------------
# tmux              新建会话
# tmux new -s name  新建命名会话
# tmux a            重连会话
# tmux ls           列出会话
# 
# Ctrl+B d          断开（会话保持运行）
# Ctrl+B |          左右分屏
# Ctrl+B -          上下分屏
# Alt+方向键         切换面板
# Ctrl+B c          新窗口
# Ctrl+B n/p        下/上一个窗口
# Ctrl+B x          关闭当前面板
# Ctrl+B r          重载配置
# ============================================
EOF

print_success "tmux 全局配置已写入 $TMUX_CONF"

# ============================================
# 6. 完成
# ============================================
echo ""
echo "============================================"
print_success "安装完成！"
echo "============================================"
echo ""
echo "已安装的工具："
echo "  ✓ zoxide   - 智能目录跳转 (用 z 关键词 跳转)"
echo "  ✓ fzf      - 模糊搜索 (Ctrl+R 搜历史命令)"
echo "  ✓ bat      - 语法高亮的 cat"
echo "  ✓ eza      - 更好的 ls"
echo "  ✓ fd       - 更好的 find"
echo "  ✓ ripgrep  - 更好的 grep (用 rg 命令)"
echo "  ✓ btop     - 系统监控"
echo "  ✓ ncdu     - 磁盘分析"
echo "  ✓ tmux     - 终端复用"
echo ""
echo "配置文件："
echo "  ✓ 全局别名配置: $GLOBAL_SCRIPT (登录 shell 加载)"
echo "  ✓ 全局bash配置: $GLOBAL_BASHRC (所有 bash 加载)"
echo "  ✓ 全局tmux配置: $TMUX_CONF (所有用户生效)"
echo "  ✓ 当前用户配置: $SHELL_RC"
echo ""
echo "配置的别名："
echo "  cat  → batcat (语法高亮)"
echo "  ls   → eza --icons"
echo "  ll   → eza -l --icons --git"
echo "  la   → eza -la --icons --git"
echo "  lt   → eza --tree (树形显示)"
echo "  fd   → fdfind"
echo ""
print_warning "请执行以下命令使配置立即生效："
echo ""
echo "  source /etc/profile.d/terminal-tools.sh"
echo ""
echo "或者重新登录系统。"
echo ""
echo "tmux 快速开始："
echo "  tmux              # 启动"
echo "  Ctrl+B |          # 左右分屏"
echo "  Ctrl+B -          # 上下分屏"
echo "  Alt+方向键         # 切换面板"
echo "  Ctrl+B d          # 断开（不关闭）"
echo "  tmux a            # 重新连接"
echo ""
