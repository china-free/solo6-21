# Logalyzer - 多源日志聚合分析工具

一个功能强大的命令行日志分析工具，支持从多个日志源（本地文件、远程SSH、云存储）采集日志，按时间线聚合，支持关键词过滤、正则匹配，以及自定义规则告警。

## 功能特性

- **多源采集**: 支持本地文件、SSH远程服务器、S3兼容云存储
- **时间线聚合**: 自动按时间戳合并多个源的日志
- **灵活过滤**: 关键词搜索、正则表达式匹配、日志级别过滤、时间范围筛选
- **智能告警**: 自定义规则，支持阈值告警和滑动窗口检测
- **会话管理**: 保存分析状态，支持随时中断和继续
- **格式自动识别**: 支持多种日志格式，可自定义解析规则
- **彩色输出**: 终端彩色显示，不同日志级别区分显示

## 安装

### 方式一：使用 pip

```bash
pip install -r requirements.txt
```

### 方式二：使用 poetry

```bash
poetry install
```

## 快速开始

### 1. 查看帮助

```bash
python -m logalyzer.cli.main --help
```

### 2. 查看配置的日志源

```bash
python -m logalyzer.cli.main collect sources
```

### 3. 采集日志

```bash
# 采集所有源的日志
python -m logalyzer.cli.main collect run

# 只采集最近24小时的日志
python -m logalyzer.cli.main collect run --start-time 24h

# 实时跟踪日志
python -m logalyzer.cli.main collect run --follow

# 保存到会话
python -m logalyzer.cli.main collect run --save-session my-analysis
```

### 4. 过滤日志

```bash
# 从会话中过滤包含"ERROR"的日志
python -m logalyzer.cli.main filter run --session <session-id> --keyword ERROR

# 使用正则表达式过滤
python -m logalyzer.cli.main filter run --session <session-id> --regex ".*Database.*"

# 只看ERROR和FATAL级别的日志
python -m logalyzer.cli.main filter run --session <session-id> --level ERROR --level FATAL

# 时间范围过滤
python -m logalyzer.cli.main filter run --session <session-id> --start-time "2026-06-17 10:00:00" --end-time "2026-06-17 10:30:00"
```

### 5. 告警管理

```bash
# 查看配置的告警规则
python -m logalyzer.cli.main alert list

# 测试告警规则
python -m logalyzer.cli.main alert test --session <session-id>
```

### 6. 会话管理

```bash
# 列出所有会话
python -m logalyzer.cli.main session list

# 查看会话详情
python -m logalyzer.cli.main session show <session-id>

# 导出会话
python -m logalyzer.cli.main session export <session-id> --output result.json --format json

# 删除会话
python -m logalyzer.cli.main session delete <session-id>
```

## 配置文件

默认配置文件为 `logalyzer.yaml`，示例配置：

```yaml
session_dir: .logalyzer_sessions
log_level: INFO

sources:
  # 本地文件源
  - name: local-app
    type: local
    enabled: true
    config:
      path: ./logs/app.log
      encoding: utf-8
      log_format:
        timestamp:
          regex: '(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})'
          format: '%Y-%m-%d %H:%M:%S,%f'
        level:
          regex: '\[(DEBUG|INFO|WARN|ERROR|FATAL)\]'

  # SSH远程源
  - name: ssh-server1
    type: ssh
    enabled: false
    config:
      host: server1.example.com
      port: 22
      username: admin
      key_file: ~/.ssh/id_rsa
      log_path: /var/log/app/app.log

  # 云存储源（S3兼容）
  - name: cloud-s3-logs
    type: cloud
    enabled: false
    config:
      provider: s3
      bucket: my-app-logs
      prefix: production/
      region: us-east-1
      access_key: YOUR_ACCESS_KEY
      secret_key: YOUR_SECRET_KEY

alert_rules:
  # 高错误率告警：60秒内出现5次以上ERROR
  - name: high-error-rate
    pattern: ERROR
    is_regex: false
    severity: error
    threshold: 5
    window_seconds: 60
    action: console

  # 数据库连接失败告警
  - name: database-connection-failed
    pattern: '.*Database connection.*failed.*'
    is_regex: true
    severity: critical
    threshold: 1
    window_seconds: 60
    action: console
```

## 项目结构

```
logalyzer/
├── __init__.py
├── config.py              # 配置管理
├── sources/               # 日志源采集
│   ├── __init__.py
│   ├── base.py            # 抽象基类
│   ├── local.py           # 本地文件源
│   ├── ssh.py             # SSH远程源
│   └── cloud.py           # 云存储源
├── parsers/               # 日志解析
│   ├── __init__.py
│   └── parser.py          # 日志格式解析
├── aggregator/            # 日志聚合
│   ├── __init__.py
│   └── aggregator.py      # 时间线聚合
├── filters/               # 过滤引擎
│   ├── __init__.py
│   └── filter.py          # 关键词、正则过滤
├── alerts/                # 告警引擎
│   ├── __init__.py
│   └── engine.py          # 自定义规则告警
├── session/               # 会话管理
│   ├── __init__.py
│   └── manager.py         # 保存/加载会话
└── cli/                   # 命令行接口
    ├── __init__.py
    └── main.py            # CLI入口
```

## 日志格式配置

### 支持的时间格式

工具内置支持多种常见时间格式：
- `2026-06-17 10:00:01,123` (Java Log4j)
- `2026-06-17T10:00:01Z` (ISO 8601)
- `2026/06/17 10:00:01`
- `17/Jun/2026:10:00:01 +0800` (Nginx)
- `Jun 17 10:00:01` (Syslog)

### 自定义格式

在配置文件中指定日志格式：

```yaml
log_format:
  timestamp:
    regex: '(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    format: '%Y-%m-%d %H:%M:%S'
  level:
    regex: '\[(DEBUG|INFO|WARN|ERROR)\]'
    mapping:
      WARNING: WARN
  fields:
    thread:
      regex: '\[([^\]]+)\]'
```

## 告警规则

### 规则参数

| 参数 | 说明 | 示例 |
|------|------|------|
| name | 规则名称 | high-error-rate |
| pattern | 匹配模式 | ERROR |
| is_regex | 是否为正则 | true/false |
| severity | 告警级别 | info/warning/error/critical |
| threshold | 阈值 | 5 |
| window_seconds | 时间窗口(秒) | 60 |
| action | 触发动作 | console |

### 示例

```yaml
# 1分钟内出现5次ERROR触发告警
- name: high-error-rate
  pattern: ERROR
  severity: error
  threshold: 5
  window_seconds: 60

# 出现OutOfMemoryError立即告警
- name: out-of-memory
  pattern: OutOfMemoryError
  severity: critical
  threshold: 1
  window_seconds: 60
```

## 时间格式

支持多种时间指定方式：

- 绝对时间：`2026-06-17 10:00:00`、`2026-06-17`
- 相对时间：`24h`（24小时前）、`7d`（7天前）、`30m`（30分钟前）

## 命令速查

| 命令 | 说明 |
|------|------|
| `collect run` | 采集日志 |
| `collect sources` | 列出数据源 |
| `filter run` | 过滤日志 |
| `alert list` | 列出告警规则 |
| `alert test` | 测试告警规则 |
| `session list` | 列出会话 |
| `session show` | 显示会话详情 |
| `session export` | 导出会话 |
| `session delete` | 删除会话 |

## License

MIT
