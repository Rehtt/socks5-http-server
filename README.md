# SOCKS5代理服务器

这是一个用Go语言实现的功能强大的SOCKS5代理服务器，具备HTTP流量分析和规则匹配功能。

## 主要特性

### 🔧 核心功能
- **完整的SOCKS5协议支持** - 支持标准SOCKS5代理协议
- **HTTP流量分析** - 深度分析HTTP请求和响应
- **规则匹配系统** - 基于正则表达式的URL匹配
- **响应修改** - 自定义HTTP响应内容和状态码
- **实时统计** - 详细的连接和请求统计信息

### 📊 数据分析
- **连接监控** - 实时监控所有代理连接
- **HTTP请求分析** - 详细分析HTTP请求头、参数等
- **安全检测** - 检测SQL注入、XSS、路径遍历等攻击
- **流量统计** - 数据传输量、访问频率等统计

### ⚙️ 配置管理
- **JSON配置文件** - 灵活的配置文件系统
- **动态规则管理** - 支持启用/禁用规则
- **自定义响应** - 可配置的响应内容和HTTP头

## 快速开始

### 1. 编译和运行

```bash
# 进入项目目录
cd test/test3

# 编译
go build -o socks5-server

# 运行
./socks5-server
```

### 2. 配置文件

首次运行时，程序会自动创建默认配置文件 `config.json`：

```json
{
  "server": {
    "port": 1080,
    "enable_https": false,
    "log_level": "info",
    "report_interval": 30
  },
  "rules": [
    {
      "name": "Google拦截",
      "pattern": ".*google\\.com.*",
      "response_body": "...",
      "status_code": 200,
      "headers": {
        "X-Proxy-Modified": "true",
        "X-Proxy-Rule": "Google拦截"
      },
      "enabled": true
    }
  ]
}
```

### 3. 客户端配置

配置你的浏览器或应用程序使用SOCKS5代理：
- **代理服务器**: `127.0.0.1`
- **端口**: `1080` (或配置文件中设置的端口)
- **协议**: `SOCKS5`

## 配置说明

### 服务器配置 (server)

| 字段 | 类型 | 描述 | 默认值 |
|------|------|------|--------|
| `port` | int | 监听端口 | 1080 |
| `enable_https` | bool | 是否启用HTTPS | false |
| `log_level` | string | 日志级别 | "info" |
| `report_interval` | int | 统计报告间隔(秒) | 30 |

### 规则配置 (rules)

| 字段 | 类型 | 描述 |
|------|------|------|
| `name` | string | 规则名称 |
| `pattern` | string | 正则表达式匹配模式 |
| `response_body` | string | 自定义响应内容 |
| `status_code` | int | HTTP状态码 |
| `headers` | object | 自定义HTTP头 |
| `enabled` | bool | 是否启用规则 |

## 使用示例

### 1. 基本代理使用

```bash
# 使用curl通过代理访问
curl --socks5 127.0.0.1:1080 http://example.com
```

### 2. 浏览器配置

以Chrome为例：
```bash
# 启动Chrome并设置SOCKS5代理
google-chrome --proxy-server="socks5://127.0.0.1:1080"
```

### 3. 自定义规则

编辑 `config.json` 文件添加新规则：

```json
{
  "name": "自定义拦截",
  "pattern": ".*example\\.com.*",
  "response_body": "<html><body><h1>访问被拦截</h1></body></html>",
  "status_code": 403,
  "headers": {
    "X-Blocked-By": "SOCKS5-Proxy"
  },
  "enabled": true
}
```

## 功能详解

### HTTP流量分析

服务器会详细分析每个HTTP请求：

```
=== HTTP请求详细分析 ===
请求ID: a1b2c3d4
时间戳: 2024-01-01 12:00:00
方法: GET
URL: http://example.com/path
Host: example.com
User-Agent: Mozilla/5.0...
Content-Type: text/html
是否被修改: false

URL分析:
  协议: http
  主机: example.com
  路径: /path

安全性分析:
  ⚠️  可能的SQL注入尝试
  ⚠️  可疑的User-Agent
========================
```

### 统计报告

每30秒（可配置）输出详细统计：

```
=== 基本统计信息 ===
总连接数: 15
HTTP请求数: 42
修改响应数: 3
==================

=== 详细流量分析报告 ===
总连接数: 15
HTTP连接数: 12
HTTPS连接数: 3
总数据传输: 1048576 bytes (1.00 MB)

访问的主机 (前10个):
  google.com: 8
  baidu.com: 5
  example.com: 2

User-Agent统计 (前5个):
  Mozilla/5.0 (Chrome): 10
  curl/7.68.0: 2

HTTP方法统计:
  GET: 35
  POST: 7

响应代码统计:
  200: 30
  403: 5
  404: 2
========================
```

### 安全检测

服务器会自动检测常见的安全威胁：

- **SQL注入检测** - 检测URL中的SQL注入模式
- **XSS检测** - 检测跨站脚本攻击尝试
- **路径遍历检测** - 检测目录遍历攻击
- **可疑User-Agent** - 检测扫描器和攻击工具
- **敏感参数检测** - 检测密码、令牌等敏感信息

## 日志示例

```
2024/01/01 12:00:00 SOCKS5服务器启动在 :1080
2024/01/01 12:00:00 成功加载 3 个规则
2024/01/01 12:00:05 记录连接: 127.0.0.1:54321 -> google.com:80 (HTTP: true)
2024/01/01 12:00:05 成功建立连接到 google.com:80 (HTTP: true, ConnID: a1b2c3d4)
2024/01/01 12:00:05 HTTP请求: GET http://google.com/
2024/01/01 12:00:05 匹配规则，修改响应: http://google.com/
2024/01/01 12:00:05 连接关闭: a1b2c3d4, 持续时间: 2.5s, 发送: 1024 bytes, 接收: 2048 bytes
```

## 高级功能

### 1. 响应模板

支持在响应内容中使用模板变量：

```html
<html>
<body>
    <h1>访问被拦截</h1>
    <p>时间: {{.Time}}</p>
    <p>规则: {{.Rule}}</p>
</body>
</html>
```

### 2. 自定义HTTP头

可以为每个规则设置自定义HTTP头：

```json
{
  "headers": {
    "X-Proxy-Modified": "true",
    "X-Proxy-Rule": "规则名称",
    "X-Block-Reason": "违反访问策略"
  }
}
```

### 3. 状态码控制

支持返回各种HTTP状态码：

- `200` - 正常响应（自定义内容）
- `403` - 禁止访问
- `404` - 页面不存在
- `204` - 无内容（常用于广告拦截）

## 故障排除

### 1. 连接失败

- 检查防火墙设置
- 确认端口未被占用
- 验证客户端代理配置

### 2. 规则不生效

- 检查正则表达式语法
- 确认规则已启用 (`enabled: true`)
- 查看日志中的错误信息

### 3. 性能问题

- 调整 `report_interval` 减少统计频率
- 优化正则表达式模式
- 监控内存使用情况

## 开发和扩展

### 项目结构

```
test/test3/
├── main.go          # 主程序和SOCKS5服务器
├── analyzer.go      # 流量分析器
├── config.go        # 配置管理器
├── go.mod           # Go模块文件
├── config.json      # 配置文件（运行时生成）
└── README.md        # 说明文档
```

### 添加新功能

1. **自定义分析器** - 在 `analyzer.go` 中添加新的分析方法
2. **扩展规则系统** - 在 `config.go` 中添加新的规则类型
3. **协议支持** - 在 `main.go` 中添加对其他协议的支持

## 许可证

本项目采用MIT许可证。

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 联系方式

如有问题或建议，请通过Issue与我们联系。 