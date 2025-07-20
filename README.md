<!-- @format -->

# SSH 同步工具（ssh-sync-tool）

## 项目简介

**ssh-sync-tool** 是一个基于 Go 语言开发的 SSH 远程到本地单向同步工具，支持多种同步与监听模式，适用于需要将远程服务器目录高效同步到本地的场景。工具支持断点续传、目录变动监听、hash 校验、日志记录、带宽限制、备份与锁机制等功能，适合开发、运维等多种需求。

## 主要特性

- **多种同步模式**：支持普通同步、静默/详细同步、本地监听自动同步、远程监听自动同步、远程 hash 监听同步等。
- **高效安全**：基于 SSH 协议，支持密钥认证，安全可靠。
- **断点续传与锁机制**：防止多实例冲突，支持断点续传。
- **hash 校验**：通过目录快照 hash 校验，确保同步一致性。
- **日志与备份**：支持日志等级、日志文件输出，自动备份与备份保留策略。
- **带宽限制**：可配置同步带宽，避免占用过多网络资源。
- **易用配置**：通过 YAML 配置文件灵活定制同步参数。

## 目录结构

```
ssh-sync-tool/
├── backup/           # 备份目录
├── config.yaml       # 主配置文件
├── data/             # 数据目录
├── internal/         # 核心代码
│   ├── cmd/          # 命令行与主逻辑
│   ├── config/       # 配置加载
│   ├── logger/       # 日志模块
│   ├── ssh/          # SSH 客户端
│   └── sync/         # 同步核心逻辑
├── lock/             # 锁文件目录
├── log/              # 日志文件目录
├── main.go           # 程序入口
├── go.mod            # Go 依赖管理
└── .last_sync_hash   # 上次同步 hash
```

## 快速开始

### 1. 下载与配置

1. [前往 Releases 页面](https://github.com/gzdzh-cn/ssh-sync-tool/releases) 下载适合你系统的二进制文件。
2. 下载根目录的 `config.yaml`，与二进制文件放在同一目录。
3. 修改 `config.yaml` 配置项。

目录示例：

```
/
├── config.yaml       # 主配置文件
├── ssh-sync-tool     # 二进制文件
```

### 2. 编译（可选）

如需自行编译：

```bash
go build -o ssh-sync-tool main.go
```

## 命令行用法（新版）

### 基本格式

```bash
./ssh-sync-tool [命令] [参数]
```

### 常用命令与别名

| 命令/别名              | 说明                   |
| ---------------------- | ---------------------- |
| sync, s                | 执行同步（默认）       |
| test, t                | 测试 SSH 连接          |
| conf, config           | 显示当前配置           |
| ver, version           | 显示版本信息           |
| w, watch               | 本地目录监听自动同步   |
| wr, watch-remote       | 远程目录轮询自动同步   |
| wrh, watch-remote-hash | 远程 hash 监听自动同步 |
| help, h                | 显示帮助信息           |

### 常用参数

| 参数                | 说明                             |
| ------------------- | -------------------------------- |
| -c, --config <文件> | 指定配置文件（默认 config.yaml） |
| --config=xxx.yaml   | 同上                             |
| -q, --quiet         | 静默模式                         |
| -v, --verbose       | 详细模式                         |

### 示例

```bash
# 执行同步（默认）
./ssh-sync-tool
./ssh-sync-tool sync
./ssh-sync-tool s

# 测试 SSH 连接
./ssh-sync-tool test
./ssh-sync-tool t

# 本地监听自动同步
./ssh-sync-tool w
./ssh-sync-tool watch

# 远程监听自动同步
./ssh-sync-tool wr
./ssh-sync-tool watch-remote

# 远程 hash 监听自动同步
./ssh-sync-tool wrh --config=prod.yaml

# 显示当前配置
./ssh-sync-tool conf

# 指定配置文件
./ssh-sync-tool sync -c my.yaml

# 静默同步
./ssh-sync-tool -q

# 详细同步
./ssh-sync-tool -v

# 显示帮助
./ssh-sync-tool help
```

## 日志与备份

- 日志文件默认输出到 `log/` 目录，可通过配置调整。
- 同步前自动备份本地变更，备份目录和保留天数可配置。

## 交叉编译（生成 Linux 和 Windows 可执行文件）

Go 支持一行命令生成不同平台和架构的可执行文件。常见命令如下：

#### 1. 生成可执行文件

```bash
#先安装 gf
go install github.com/gogf/gf/cmd/gf/v2@latest

# 批量生成多平台执行文件
gf build main.go -n ssh-sync-tool amd64,arm64 -s linux,darwin -p ./bin
```

#### 4. 注意事项

- 交叉编译不需要在目标系统上操作，只需在本地执行上述命令即可。
- 生成的文件可直接在对应系统运行，无需安装 Go 环境。
- 某些情况下，涉及 cgo 的代码需要在目标平台下编译，普通 Go 代码无需担心。

## 同步原理简述

- 工具通过 SSH 连接远程主机，获取远程目录快照（ls/stat），计算 hash。
- 本地也计算目录 hash，若 hash 不一致则触发同步。
- 支持本地/远程目录变动监听，自动触发同步。
- 同步完成后自动更新本地 hash 文件，确保下次同步只处理变更部分。
- 支持同步锁，防止多实例并发冲突。

## 适用场景

- 远程开发环境代码同步
- 运维自动化部署
- 远程备份与容灾
- 需要高效、可靠的单向目录同步场景

## 贡献与反馈

欢迎提交 issue 和 PR 进行改进。如有问题请联系项目维护者。

---

如需更详细的配置说明或功能扩展，请查阅源码或联系作者。
