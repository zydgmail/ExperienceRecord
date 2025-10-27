# mitmproxy HTTPS 抓包完整教程

本教程详细介绍如何使用 mitmproxy 对 Android 设备进行 HTTPS 抓包，特别适用于 Android 7.0+ 及 Android 14+ 系统。

---

## 目录
1. [环境准备](#1-环境准备)
2. [mitmproxy 安装与启动](#2-mitmproxy-安装与启动)
3. [证书获取与转换](#3-证书获取与转换)
4. [Android 设备代理配置](#4-android-设备代理配置)
5. [系统证书注入（Android 7.0+）](#5-系统证书注入android-70)
6. [验证与测试](#6-验证与测试)
7. [常见问题与解决方案](#7-常见问题与解决方案)

---

## 1. 环境准备

### 1.1 所需工具
- **PC 端**：
  - mitmproxy（或 mitmweb）
  - ADB（Android Debug Bridge）
  - OpenSSL（用于证书格式转换）
  
- **Android 设备**：
  - Root 权限（必须，用于注入系统证书）
  - 已启用 USB 调试
  - 与 PC 处于同一局域网

### 1.2 安装 mitmproxy

**Windows（使用 pip）：**
```powershell
pip install mitmproxy
```

**macOS（使用 Homebrew）：**
```bash
brew install mitmproxy
```

**Linux（使用 pip）：**
```bash
pip3 install mitmproxy
```

### 1.3 安装 ADB

**Windows：**
- 下载 [Android SDK Platform-Tools](https://developer.android.com/studio/releases/platform-tools)
- 解压并添加到系统 PATH 环境变量

**macOS：**
```bash
brew install android-platform-tools
```

**Linux：**
```bash
sudo apt install adb  # Ubuntu/Debian
```

### 1.4 验证安装

```bash
# 验证 mitmproxy
mitmproxy --version

# 验证 ADB
adb version

# 验证 OpenSSL
openssl version
```

---

## 2. mitmproxy 安装与启动

### 2.1 首次启动 mitmproxy

首次运行 mitmproxy 会自动生成 CA 证书：

```bash
# 命令行模式
mitmproxy

# Web 界面模式（推荐）
mitmweb

# 代理模式（无界面）
mitmdump
```

启动后，mitmproxy 默认监听 `8080` 端口。

### 2.2 证书生成位置

证书会自动生成在以下目录：

- **Windows**: `C:\Users\<用户名>\.mitmproxy\`
- **macOS/Linux**: `~/.mitmproxy/`

主要文件包括：
- `mitmproxy-ca-cert.pem` - PEM 格式证书
- `mitmproxy-ca-cert.cer` - DER 格式证书
- `mitmproxy-ca.pem` - CA 根证书（包含私钥）

### 2.3 获取 PC 的局域网 IP

**Windows：**
```powershell
ipconfig
# 查找 "无线局域网适配器 WLAN" 或 "以太网适配器" 的 IPv4 地址
```

**macOS/Linux：**
```bash
ifconfig
# 或
ip addr show
```

记下 IP 地址，例如 `192.168.1.100`。

---

## 3. 证书获取与转换

### 3.1 方法一：手机浏览器下载（推荐）

1. 确保手机已连接 PC 的代理（见第 4 节）
2. 在手机浏览器访问：`http://mitm.it`
3. 选择 Android 图标下载证书（`.cer` 格式）
4. 将证书传输到 PC

### 3.2 方法二：直接从 PC 获取

证书位于 `~/.mitmproxy/mitmproxy-ca-cert.cer`（或 Windows 下的 `%USERPROFILE%\.mitmproxy\`）

### 3.3 证书格式转换

Android 系统证书需要特定命名格式（哈希值.0）。

**步骤：**

```bash
# 1. 进入证书目录
cd ~/.mitmproxy/   # Linux/macOS
cd %USERPROFILE%\.mitmproxy\   # Windows PowerShell

# 2. 如果证书是 .cer 格式，确保是 PEM 编码（可选转换）
openssl x509 -inform DER -in mitmproxy-ca-cert.cer -out mitmproxy-ca-cert.pem

# 3. 计算证书哈希值并重命名
# Linux/macOS:
hashed_name=$(openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.pem | head -1)
cp mitmproxy-ca-cert.pem ${hashed_name}.0

# Windows PowerShell:
$hash = (openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.pem | Select-Object -First 1)
Copy-Item mitmproxy-ca-cert.pem "$hash.0"

# 4. 查看生成的文件（例如：c8750f0d.0）
ls *.0
```

**说明：**
- `subject_hash_old` 是 OpenSSL 的一个参数选项，用于计算证书的旧版哈希值（MD5 算法）
- 该参数确保证书兼容 Android 4.0 到 Android 13 的所有版本
- Android 10+ 使用新哈希算法（`-subject_hash`），但仍兼容旧算法
- 生成的文件名类似 `c8750f0d.0`，其中 `c8750f0d` 是哈希值，`.0` 是固定后缀
- 这是 Android 识别系统证书的命名规则，文件名必须与证书内容的哈希值匹配

---

## 4. Android 设备代理配置

### 4.1 设置 Wi-Fi 代理

1. 打开手机 **设置** → **WLAN**
2. 长按已连接的 Wi-Fi 网络 → **修改网络**
3. 展开 **高级选项**
4. **代理** 选择 **手动**
5. 填写：
   - **代理服务器主机名**：PC 的局域网 IP（如 `192.168.1.100`）
   - **代理服务器端口**：`8080`（mitmproxy 默认端口）
6. 保存设置

### 4.2 验证代理连接

在手机浏览器访问 `http://mitm.it`，如果能看到 mitmproxy 的证书下载页面，说明代理配置成功。

---

## 5. 系统证书注入（Android 7.0+）

### 5.1 为什么需要系统证书？

从 **Android 7.0 (API 24)** 开始，应用默认只信任系统证书存储区的 CA 证书，不再信任用户手动安装的证书。因此，需要将 mitmproxy 证书注入到系统证书目录。

### 5.2 检查设备 Root 权限

```bash
# 连接设备
adb devices

# 尝试获取 root 权限
adb root

# 如果上述命令失败，尝试 shell 内 su
adb shell
su   # 输入后设备应弹出授权请求
```

### 5.3 证书注入方法

#### 方法一：自动化脚本注入（推荐，适用于 Android 14+）

使用本教程提供的 `htk-inject-system-cert.sh` 脚本（见附录）。

**使用方法：**

```bash
# 赋予执行权限
chmod +x htk-inject-system-cert.sh

# 执行注入（替换为你的证书路径和代理地址）
./htk-inject-system-cert.sh ./c8750f0d.0 192.168.1.100:8080

# 不设置代理（仅注入证书）
./htk-inject-system-cert.sh ./c8750f0d.0 ""

# 清除代理
./htk-inject-system-cert.sh ./c8750f0d.0 :0
```

**脚本工作原理（Android 14+ 特有）：**

Android 14 将系统证书移至 `/apex/com.android.conscrypt/cacerts`，且该路径为只读 APEX 模块。脚本通过以下技术绕过限制：

1. **tmpfs 挂载**：在 `/system/etc/security/cacerts` 挂载临时文件系统
2. **命名空间注入**：通过 `nsenter` 进入 Zygote 进程的 mount namespace
3. **bind mount**：将证书目录绑定挂载到 APEX 路径，对所有应用生效

#### 方法二：手动注入（适用于 Android 7.0 - 13）

```bash
# 1. 推送证书到设备临时目录
adb push c8750f0d.0 /data/local/tmp/

# 2. 获取 root 权限
adb root
adb remount

# 3. 复制证书到系统目录
adb shell su -c "cp /data/local/tmp/c8750f0d.0 /system/etc/security/cacerts/"

# 4. 设置权限
adb shell su -c "chmod 644 /system/etc/security/cacerts/c8750f0d.0"

# 5. 设置 SELinux 上下文（可选，部分设备需要）
adb shell su -c "chcon u:object_r:system_file:s0 /system/etc/security/cacerts/c8750f0d.0"

# 6. 重启设备
adb reboot
```

#### 方法三：使用 Magisk 模块（适用于已安装 Magisk 的设备）

如果设备使用 Magisk 进行 Root 管理：

1. **通过 mitmweb 下载模块**：
   - 启动 mitmweb 并配置代理
   - 手机浏览器访问 `http://mitm.it/cert/magisk`
   - 下载 `mitmproxy-magisk-module.zip`

2. **安装模块**：
   - 打开 Magisk 应用 → **模块** → **从本地安装**
   - 选择下载的 zip 文件
   - 重启设备

### 5.4 验证证书安装

重启后，进入设备：

**设置** → **安全** → **加密与凭据** → **信任的凭据** → **系统** 标签

在列表中找到 **mitmproxy** 证书，说明安装成功。

---

## 6. 验证与测试

### 6.1 测试 HTTPS 抓包

1. 确保 mitmproxy 正在运行
2. 手机打开任意使用 HTTPS 的应用（如浏览器、微信等）
3. 在 mitmweb 界面（`http://127.0.0.1:8081`）查看是否捕获到 HTTPS 流量

### 6.2 检查证书信任

如果无法抓取 HTTPS：

```bash
# 检查系统证书目录
adb shell su -c "ls -l /system/etc/security/cacerts/ | grep mitmproxy"

# 或检查 Android 14+ 的 APEX 路径
adb shell su -c "ls -l /apex/com.android.conscrypt/cacerts/ | grep c8750f0d"

# 验证权限（应为 -rw-r--r-- 即 644）
```

### 6.3 测试特定应用

某些应用使用 **证书绑定 (Certificate Pinning)**，即使安装了系统证书也无法抓包。解决方法：

- 使用 **Frida** + **Objection** 绕过证书绑定
- 使用 **Xposed** + **JustTrustMe** 模块
- 反编译应用并修改网络安全配置

---

## 7. 常见问题与解决方案

### 7.1 无法看到 HTTPS 流量

**原因与解决：**

1. **证书未正确安装**
   - 检查证书是否在系统存储区（非用户区）
   - 验证文件权限为 `644`

2. **应用使用证书绑定**
   - 使用 Frida 脚本禁用 SSL Pinning
   - 示例：`frida -U -f com.example.app -l ssl-unpinning.js`

3. **代理设置错误**
   - 确认 PC 防火墙未阻止 8080 端口
   - 检查手机和 PC 在同一网络

### 7.2 Android 14 证书注入失败

**问题**：`mount: tmpfs: Permission denied`

**解决**：

- 确保设备已完全 Root（可执行 `adb root`）
- 检查 SELinux 状态：
  ```bash
  adb shell getenforce
  # 如果是 Enforcing，临时设为 Permissive：
  adb shell su -c "setenforce 0"
  ```

### 7.3 设备无法写入 `/data/data` 目录

**原因**：即使有 Root 权限，部分目录受 SELinux 或应用沙箱保护。

**解决**：
- 使用脚本注入到系统证书目录（`/system/etc/security/cacerts`）
- 避免直接修改 `/data/data` 下的应用私有数据

### 7.4 重启后证书消失

**原因**：
- 使用 tmpfs 挂载的证书在重启后会丢失（Android 14 脚本方法）
- 非持久化修改

**解决**：
- 使用 Magisk 模块实现持久化
- 每次重启后重新运行注入脚本

### 7.5 某些应用仍无法抓包

**可能原因**：
1. **双向 TLS 认证**：应用需要客户端证书
2. **自定义证书存储**：应用不使用系统证书
3. **检测代理环境**：应用拒绝在代理下运行

**解决思路**：
- 使用透明代理模式（需配置 iptables 规则）
- 虚拟化/沙箱环境（如 VirtualXposed）

---

## 附录

### 附录 A：htk-inject-system-cert.sh 完整脚本

以下是完整的证书注入脚本，支持 Android 7.0 到 Android 14+。

**脚本功能：**

1. 推送证书到设备临时目录
2. 尝试 `adb root`，失败则使用 `su -c`
3. 在设备上执行注入逻辑：
   - 备份现有系统证书
   - 挂载 tmpfs 到 `/system/etc/security/cacerts`
   - 复制注入证书并设置权限
   - 设置 SELinux context
4. 可选设置全局 HTTP 代理

**完整脚本代码：**

```bash
#!/usr/bin/env bash

# htk-inject-system-cert.sh

# 用法:
#   ./htk-inject-system-cert.sh /path/to/local/cert.crt [PROXY]

# 示例:
#   ./htk-inject-system-cert.sh ./c8750f0d.0 192.168.1.100:8888
#   ./htk-inject-system-cert.sh ./c8750f0d.0 ""    # 不设置代理（不变更）
#   ./htk-inject-system-cert.sh ./c8750f0d.0 :0   # 清除代理

set -euo pipefail

#######################################
# 配置 - 可按需修改默认值
#######################################
LOCAL_CERT_PATH="${1:-}"
PROXY_ARG="${2:-}"   # 例: 192.168.1.100:8888 或 :0 表示清除代理，空字符串表示不改proxy

TMP_REMOTE_DIR="/data/local/tmp/htk-ca-copy"
REMOTE_TMP_CERT_DIR="/data/local/tmp"
REMOTE_CERT_BASENAME=""
ADB_BIN="${ADB_BIN:-adb}"

function die() {
  echo "ERROR: $*" >&2
  exit 1
}

if [[ -z "$LOCAL_CERT_PATH" ]]; then
  die "必须指定本地证书路径。用法: $0 /path/to/cert [PROXY]"
fi

if [[ ! -f "$LOCAL_CERT_PATH" ]]; then
  die "本地证书不存在: $LOCAL_CERT_PATH"
fi

if ! command -v "$ADB_BIN" >/dev/null 2>&1; then
  die "找不到 adb，可通过环境变量 ADB_BIN 指定路径。"
fi

REMOTE_CERT_BASENAME="$(basename "$LOCAL_CERT_PATH")"

echo "准备将证书 '$LOCAL_CERT_PATH' (作为 $REMOTE_CERT_BASENAME) 注入到设备 /system/etc/security/cacerts"
echo "代理设置参数: '${PROXY_ARG}'"
echo

# 推送证书到设备临时目录
echo "1) 推送证书到设备: $REMOTE_TMP_CERT_DIR/$REMOTE_CERT_BASENAME"
"$ADB_BIN" push "$LOCAL_CERT_PATH" "$REMOTE_TMP_CERT_DIR/" >/dev/null || die "adb push 失败"

# 尝试切换到 adb root（如果设备支持）
echo "2) 尝试 adb root"
if "$ADB_BIN" root >/dev/null 2>&1; then
  echo "adb root 成功或设备已 root"
else
  echo "adb root 失败，后续将尝试通过 su -c 在设备上以 root 执行命令（需要设备已 root 并安装 su）"
fi

# 在设备上执行注入脚本（通过 su -c 'sh -s' 以 root 权限运行 stdin 中的脚本）
echo "3) 在设备上执行注入逻辑（需要 root 权限）..."

# 构造远程执行的脚本
REMOTE_PAYLOAD=$(cat <<'EOS'
set -e
REMOTE_TMP_CERT_DIR="/data/local/tmp"
REMOTE_CERT_BASENAME="__CERT_BASENAME__"
TMPDIR="/data/local/tmp/htk-ca-copy"
SYSTEM_CA_DIR="/system/etc/security/cacerts"

echo "device: 使用证书文件: $REMOTE_CERT_BASENAME"
rm -rf "$TMPDIR" || true
mkdir -m 700 "$TMPDIR"

if [ -d "$SYSTEM_CA_DIR" ]; then
  cp -a "$SYSTEM_CA_DIR"/* "$TMPDIR"/ 2>/dev/null || true
fi

# 尝试挂载 tmpfs
if ! mount -t tmpfs tmpfs "$SYSTEM_CA_DIR" 2>/dev/null; then
  echo "device: tmpfs mount 失败，尝试 remount /system 为 rw"
  if mount | grep -q " on /system "; then
    if mount -o remount,rw /system 2>/dev/null || mount -o rw,remount /system 2>/dev/null; then
      mount -t tmpfs tmpfs "$SYSTEM_CA_DIR" || { echo "device: tmpfs 挂载仍然失败"; exit 1; }
    else
      echo "device: 无法 remount /system"; exit 1
    fi
  else
    echo "device: 无法找到 /system 挂载点"; exit 1
  fi
fi

if [ -d "$TMPDIR" ] && [ "$(ls -A "$TMPDIR" 2>/dev/null || true)" != "" ]; then
  if mv "$TMPDIR"/* "$SYSTEM_CA_DIR"/ 2>/dev/null; then
    true
  else
    cp -a "$TMPDIR"/* "$SYSTEM_CA_DIR"/ 2>/dev/null || true
  fi
fi

if [ -f "$REMOTE_TMP_CERT_DIR/$REMOTE_CERT_BASENAME" ]; then
  cp "$REMOTE_TMP_CERT_DIR/$REMOTE_CERT_BASENAME" "$SYSTEM_CA_DIR"/ || { echo "device: 复制注入证书失败"; exit 1; }
else
  echo "device: 找不到临时证书 $REMOTE_TMP_CERT_DIR/$REMOTE_CERT_BASENAME"; exit 1
fi

chown root:root "$SYSTEM_CA_DIR"/* || true
chmod 644 "$SYSTEM_CA_DIR"/* || true
if command -v chcon >/dev/null 2>&1; then chcon u:object_r:system_file:s0 "$SYSTEM_CA_DIR"/* 2>/dev/null || true; fi
rm -rf "$TMPDIR" || true
echo "device: 证书注入成功"
EOS
)

# 把真实的文件名替换进去并发送给设备执行
REMOTE_PAYLOAD_REPLACED="${REMOTE_PAYLOAD//__CERT_BASENAME__/$REMOTE_CERT_BASENAME}"

# 通过 adb shell su -c 'sh -s' 执行替换后的脚本
printf '%s\n' "$REMOTE_PAYLOAD_REPLACED" | "$ADB_BIN" shell su -c 'sh -s' || die "远程注入脚本执行失败"

echo
echo "4) （可选）设置全局 http_proxy"
if [[ -n "$PROXY_ARG" ]]; then
  if [[ "$PROXY_ARG" == ":0" ]]; then
    echo "  清除设备全局 http_proxy"
    "$ADB_BIN" shell settings put global http_proxy :0 || echo "警告: 无法设置 proxy（可能设备不支持该 settings）"
  else
    echo "  设置设备全局 http_proxy 为: $PROXY_ARG"
    "$ADB_BIN" shell settings put global http_proxy "$PROXY_ARG" || echo "警告: 无法设置 proxy（可能设备不支持该 settings）"
  fi
else
  echo "  未指定 proxy，跳过 proxy 修改"
fi

echo
echo "5) 清理本地临时文件（可选）"
# 如果你不希望保留本地证书拷贝，可以在这里删除（脚本默认不删除）
# rm -f "$LOCAL_CERT_PATH"

echo
echo "完成：系统证书已注入（如果设备支持并且已 root）。如未生效请确认："
echo "  - 设备已 root 或 su 可用并授予权限"
echo "  - /system 可写（部分非 root 设备无法修改系统 CA）"
echo "  - 目标系统路径为 /system/etc/security/cacerts（厂商可能不同）"
echo
echo "如果要回滚：重启设备或重新挂载原来的 /system 目录（有些系统重启会恢复）"
```

**使用说明：**

1. **保存脚本**：将上述代码保存为 `htk-inject-system-cert.sh`

2. **赋予执行权限**（Linux/macOS）：
   ```bash
   chmod +x htk-inject-system-cert.sh
   ```

3. **执行脚本**：
   ```bash
   # 基本用法
   ./htk-inject-system-cert.sh ./c8750f0d.0 192.168.1.100:8080
   
   # 仅注入证书，不设置代理
   ./htk-inject-system-cert.sh ./c8750f0d.0 ""
   
   # 清除现有代理设置
   ./htk-inject-system-cert.sh ./c8750f0d.0 :0
   ```

4. **Windows 用户**：需要在 Git Bash 或 WSL 环境中运行此脚本

### 附录 B：证书转换命令速查

```bash
# DER 转 PEM
openssl x509 -inform DER -in cert.cer -out cert.pem

# 计算哈希值（旧版）
openssl x509 -inform PEM -subject_hash_old -in cert.pem | head -1

# 计算哈希值（新版）
openssl x509 -inform PEM -subject_hash -in cert.pem | head -1

# 查看证书信息
openssl x509 -in cert.pem -text -noout
```

### 附录 C：推荐工具链

| 工具 | 用途 | 链接 |
|------|------|------|
| mitmproxy | HTTPS 抓包代理 | https://mitmproxy.org |
| Frida | 动态插桩框架 | https://frida.re |
| Objection | Frida 辅助工具 | https://github.com/sensepost/objection |
| Magisk | Android Root 管理 | https://github.com/topjohnwu/Magisk |
| HTTP Toolkit | 一体化抓包方案 | https://httptoolkit.com |

### 附录 D：mitmproxy 常用命令

```bash
# 启动 Web 界面，监听 8080 端口
mitmweb

# 指定端口
mitmweb --listen-port 9090

# 保存流量到文件
mitmdump -w traffic.flow

# 从文件读取流量
mitmweb -r traffic.flow

# 过滤特定域名
mitmproxy --set intercept='~d example.com'

# 开启上游代理
mitmproxy --mode upstream:http://proxy.example.com:8080
```

---

## 总结

完整的 mitmproxy HTTPS 抓包流程：

1. ✅ **安装 mitmproxy** 并首次启动生成证书
2. ✅ **转换证书格式** 为 Android 系统证书命名规则（哈希值.0）
3. ✅ **配置手机代理** 指向 PC 的 mitmproxy
4. ✅ **注入系统证书** 使用脚本或手动方法（需 Root）
5. ✅ **验证抓包** 打开应用测试流量捕获
6. ✅ **处理特殊情况** 如证书绑定、双向认证等

**关键要点**：
- Android 7.0+ 必须使用系统证书
- Android 14+ 需使用特殊挂载技术（脚本自动处理）
- Root 权限是必需的
- 证书文件名必须为哈希值.0 格式
- 证书权限必须为 644

祝抓包顺利！🎉
