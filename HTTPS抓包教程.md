### 目标
- **PC浏览器抓包**：使用 Wireshark，依赖浏览器导出 TLS 会话密钥（`SSLKEYLOGFILE`）。
- **手机 App 抓包**：通过代理方式使用 Fiddler。Android 7.0+ 需按系统 CA 安装流程处理证书。

---

### 一、Wireshark 抓包（适合 PC 浏览器）
适用场景：Chrome/Firefox/Edge 等浏览器访问 HTTPS，希望在 Wireshark 中解密 TLS 流量。

1) 配置环境变量 `SSLKEYLOGFILE`
- 作用：让浏览器把 TLS 会话密钥写入指定文件，Wireshark 用该文件解密。
- 路径建议：选择一个可写路径，例如：
  - Windows: `C:\Users\<用户名>\ssl_keys\sslkeylog.txt`
  - macOS/Linux: `~/ssl_keys/sslkeylog.txt`

2) 设置系统环境变量
- Windows（PowerShell）
```powershell
[Environment]::SetEnvironmentVariable("SSLKEYLOGFILE", "C:\\Users\\<用户名>\\ssl_keys\\sslkeylog.txt", "User")
```
  - 关闭并重新打开浏览器（必须）。
- macOS（zsh/bash）
```bash
echo 'export SSLKEYLOGFILE="$HOME/ssl_keys/sslkeylog.txt"' >> ~/.zshrc
source ~/.zshrc
```
- Linux（bash）
```bash
echo 'export SSLKEYLOGFILE="$HOME/ssl_keys/sslkeylog.txt"' >> ~/.bashrc
source ~/.bashrc
```

3) 验证密钥是否写入
- 重新启动浏览器后访问任意 HTTPS 网站，检查 `sslkeylog.txt` 是否增长。

4) Wireshark 中加载密钥
- 打开 Wireshark → Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename → 选择 `sslkeylog.txt`。
- 常用过滤：
  - 仅看 TLS 握手：`tls.handshake`
  - 仅看某域名（需 SNI/HTTP）：`tls.handshake.extensions_server_name contains "example.com"` 或 `http.host == "example.com"`
  - 仅看某端口：`tcp.port == 443`

5) 常见问题
- 必须在“设置好环境变量并重启浏览器”之后再开始访问，才能记录密钥。
- 某些应用（非浏览器）不会遵守 `SSLKEYLOGFILE`，此法不适用。

---

### 二、Fiddler 抓包（适合手机 App，需代理）
适用场景：抓取 iOS/Android App 的 HTTP/HTTPS 流量，通过 PC 上的 Fiddler 作为代理。

1) PC 端准备
- 安装 Fiddler Classic 或 Fiddler Everywhere。
- 启用 HTTPS 解密：
  - Fiddler Classic：Tools → Options → HTTPS → 勾选 “Decrypt HTTPS traffic”。
  - Fiddler Everywhere：Settings → HTTPS → Enable “Capture HTTPS traffic”。
- 记下 PC 的局域网 IP（例如 `192.168.1.100`）与 Fiddler 监听端口（默认 8888）。

2) 手机与 PC 同网 & 设置代理
- 手机与 PC 连接同一 Wi‑Fi。
- 在手机 Wi‑Fi 代理设置里：
  - 代理主机名：PC 的局域网 IP（如 `192.168.1.100`）
  - 代理端口：Fiddler 监听端口（默认 `8888`）

3) 安装并信任 Fiddler 根证书
- 在手机浏览器访问 `http://<PC-IP>:8888`（如 `http://192.168.1.100:8888`），按提示下载并安装根证书。

4) Android 7.0+ 特性（默认不信任“用户”证书）
- Android 7.0 及以上，App 默认只信任“系统”证书，不信任手动安装的“用户”证书。
- 若 App 未额外信任用户证书，需将 Fiddler 根证书作为“系统 CA”安装（通常需要 Root/可写 system 分区）。

将 Fiddler 根证书安装为系统 CA（Root 设备）：
```bash
# 1) 在 PC 上将 Fiddler 导出的证书从 DER 转为 PEM
openssl x509 -inform DER -in FiddlerRoot.cer -out FiddlerRoot.pem

# 2) 复制（或覆盖）为 PEM 名称（Linux/mac）
cp FiddlerRoot.cer FiddlerRoot.pem   # Linux/mac

# 3) 计算旧版主题哈希并重命名为 HASH.0
HASH=$(openssl x509 -in FiddlerRoot.pem -subject_hash_old -noout | head -n1)
mv FiddlerRoot.pem ${HASH}.0

# 4) 推送到系统 CA 目录（需要 root）
adb root
adb remount
adb push ${HASH}.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0
adb reboot
```
- 说明与要点：
  - 目录路径：`/system/etc/security/cacerts/`
  - 权限必须为 `-rw-r--r-- (0644)`，否则不被加载。
  - 重启后生效。
  - 没有 Root 权限无法写入系统 CA 目录。此时可尝试：
    - 若 App 支持网络安全配置（Network Security Config）允许用户 CA，直接安装用户证书即可；
    - 若 App 使用证书绑定（certificate pinning），需调试手段（如 Frida/Objection/Xposed）绕过，超出本文范围。

5) iOS 设备要点
- 在 `http://<PC-IP>:8888` 安装描述文件后，前往：设置 → 通用 → 关于本机 → 证书信任设置 → 启用对该根证书的完全信任。
- 某些 App 使用证书绑定，同样可能需要额外绕过手段。

6) 验证与故障排查
- 在 Fiddler 中应能看到手机发起的请求；若无：
  - 检查手机代理是否正确填写 IP/端口，PC 与手机是否同网。
  - Windows 防火墙/杀毒是否拦截 Fiddler 端口。
  - HTTPS 报错：确认证书已安装并（Android 7+）已作为系统 CA 生效。
  - App 若使用证书绑定，普通代理解密将失败。

---

### 小结
- 浏览器抓包优先用 Wireshark + `SSLKEYLOGFILE`，简单可靠。
- 手机 App 抓包用 Fiddler 代理；Android 7.0+ 需系统 CA 才能被大多数 App 信任。

