# SocketProxy

跨平台、兼容标准 Shadowsocks AEAD 的代理工具（Go 实现）。

已实现：
- 配置、加密协议、服务端、本地 SOCKS5 客户端、TCP 转发
- UDP 中继与 DNS（SOCKS5 UDP ASSOCIATE）
- 多节点、测速、故障转移、SIP002 订阅
- SOCKS5 用户名/密码认证（RFC 1929）
- SIP003 插件（如 `v2ray-plugin`，客户端 + 服务端）

## 构建

```powershell
# 使用 Makefile（需安装 GNU make）
make            # 生成 bin\sp-client.exe 与 bin\sp-server.exe
make clean
make test

# 或使用批处理（无需 make）
.\scripts\build.bat

# 或手动
go build -o bin\sp-client.exe ./cmd/sp-client
go build -o bin\sp-server.exe ./cmd/sp-server
```

注意：`go build ./...` 只做编译检查，不会产出可执行文件（多包时二进制会被丢弃）。

## 运行

客户端（默认读取 `configs/client.json`）：

```bash
go run ./cmd/sp-client
go run ./cmd/sp-client -node hk-plugin
```

服务端（默认读取 `configs/server.json`）：

```bash
go run ./cmd/sp-server
```

验证：

```powershell
curl.exe --socks5 127.0.0.1:1080 http://example.com
# 启用认证时
curl.exe --socks5 user:pass@127.0.0.1:1080 http://example.com
```

## 浏览器使用（Windows 自动系统代理）

`sp-client` 监听成功后会自动：
- 在本地随机端口启动一个 HTTP 代理（支持 HTTPS 的 CONNECT，带域名即远程 DNS）
- 把 Windows 系统代理设置为该 HTTP 代理
- 进程正常退出（Ctrl+C）时恢复原系统代理

因此 Chrome / Edge 无需手动设置即可直接访问；本地 SOCKS5（`127.0.0.1:1080`）仍可用于其它支持 SOCKS5 的程序。

- Firefox：设置 → 常规 → 网络设置 → 选择「使用系统代理设置」即可；或手动 SOCKS5 `127.0.0.1:1080` 并勾选「使用 SOCKS v5 时代理 DNS 查询」
- 关闭自动设置：配置 `"disableSystemProxy": true`
- 若进程被强制结束，下次启动会先恢复上次备份再重新设置
- 备份文件：`%LOCALAPPDATA%\socketproxy\sysproxy-backup.json`

`mode: auto` 下，某个目标直连失败后会在 10 分钟内直接走代理，避免重复等待。

## 配置文件

每个端只保留一个示例，内部用注释说明全部用法：
- 客户端：`configs/client.json`
- 服务端：`configs/server.json`

配置文件支持 `//` 行注释与 `/* */` 块注释。

客户端常用字段：
- `mode`（连接模式）：
  - `auto`：先尝试正常直连目标，失败再走代理（默认）
  - `proxy`：所有连接都走代理
  - `direct`：仅直连（UDP 关闭）
- `directTimeout`：直连超时（秒，默认 5），仅 `auto` / `direct` 使用
- `strategy`：
  - `manual`：优先使用指定节点，节点不可用时自动切换到其他节点
  - `latency`：按测速结果选择延迟最低的节点
  - `failover`：当前节点失败后切换，并记住新的可用节点
- `node`：首选节点名，可用 `-node` 覆盖（名称不存在会报错）
- `auth.username` / `auth.password`：启用 SOCKS5 用户名/密码认证（可选）
- `healthCheck.interval` / `healthCheck.timeout`：测速间隔与超时（秒）
- `subscription.url` / `subscription.updateInterval`：SIP002 订阅地址与刷新间隔（秒）
- 节点字段：`server`、`port`、`password`、`method`、`udp`、`timeout`、`plugin`、`pluginOpts`、`pluginArgs`
- 插件模式下 `udp` 通常为 `false`

服务端常用字段：
- `listen`：TCP 监听地址；插件模式下为插件公网监听地址
- `udpListen`：UDP 监听地址（仅直连模式；默认与 `listen` 相同）
- `disableUDP`：设为 `true` 关闭 UDP
- `plugin` / `pluginOpts` / `pluginArgs`：SIP003 插件配置
- 插件模式下内部 SS 服务自动改绑 `127.0.0.1:<随机端口>`，UDP 自动关闭

## 插件（SIP003）

安装 `v2ray-plugin`（二选一）：
1. 从 https://github.com/shadowsocks/v2ray-plugin/releases 下载对应平台压缩包，解压后将 `v2ray-plugin(.exe)` 所在目录加入 `PATH`
2. 或用 Go 安装：`go install github.com/shadowsocks/v2ray-plugin@latest`

- `plugin`：插件可执行文件（名称或完整路径）
- `pluginOpts`：传给插件的 `SS_PLUGIN_OPTIONS`（如 `tls;host=example.com`）
- `pluginArgs`：启动插件时的额外参数（可选）
- 服务端以 `pluginOpts: "server"` 运行服务端模式
- TLS 需提供服务端证书/私钥：`pluginOpts` 中加 `tls;cert=...;key=...`
- 直连 SS（不用插件）时，删除配置中的 `plugin` / `pluginOpts` / `pluginArgs` 三行

## 支持

- 加密方法：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`
- SOCKS5：`CONNECT`、`UDP ASSOCIATE`（不支持分片）、用户名/密码认证（RFC 1929）
- HTTP 代理：`CONNECT` 与普通 HTTP（用于系统代理 / 浏览器）
- 订阅格式：SIP002 `ss://` URI（明文或整体 base64）
- 插件：SIP003（客户端 + 服务端）

## 测试

```bash
go test ./...
```
