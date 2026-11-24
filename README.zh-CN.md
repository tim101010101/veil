# Veil

[English](README.md) | 简体中文

> 本文是 [英文 README](README.md) 的翻译，两者不一致时以英文版为准。其他文档目前只有英文。

一个可自托管的密钥保险库，服务于命令行工具、CI 工作负载和 AI 智能体。
密钥在你的设备上加密，项目里只保存引用，只在命令真正需要时才交付明文。
服务器只保存密文，不持有解密密钥。

[快速开始](#快速开始) · [安装](#安装) · [文档](#文档) · [安全策略](SECURITY.md) · [参与贡献](CONTRIBUTING.md)

登录后，导入项目的 `.env`，然后带着密钥运行命令：

```sh
veil init --vault my-app
veil run -- npm start
```

`veil init` 把项目的 `.env` 导入一个 vault，并把引用写入 `veil.toml`。
`veil run` 为子进程解析这些引用，并在其输出中遮蔽匹配的值。原来的 `.env` 仍保留在磁盘上。

## 功能

- 在客户端加密密钥的值和名称。`veild` 只需一个 SQLite 数据库，并且没有任何解密 vault 的途径。
- 通过环境变量或命名管道交付密钥。提交到仓库的是引用，而不是值。
- 为受限设备和 OIDC 工作负载授予指定 vault 的访问权限。可要求本机在场确认，或在另一台设备上批准后才交付，
  并用 `veil audit` 查看交付记录。
- 通过限定范围的 MCP 工具接入智能体。除非你显式开启，否则不允许智能体查看明文。
- 用受支持的 Bitwarden 客户端读写同一份存储。

Veil 是早期的 1.0 之前版本。存放真实密钥前，请先阅读 [安全边界](#安全边界)。
Veil 独立于 Bitwarden，不是 Bitwarden 官方产品。兼容性仅覆盖
[固定版本并经过测试的客户端](tests/bitwarden/README.md)，不保证所有 Bitwarden 版本或功能。

## 安装

从 [GitHub Releases](https://github.com/tim101010101/veil/releases) 下载对应版本的 CLI 压缩包：

| 平台 | Target |
| --- | --- |
| macOS，Apple Silicon | `aarch64-apple-darwin` |
| macOS，Intel | `x86_64-apple-darwin` |
| Linux，x86_64 | `x86_64-unknown-linux-musl` |
| Linux，ARM64 | `aarch64-unknown-linux-musl` |

每个压缩包包含 CLI、许可证、依赖声明和构建信息，对应的 SHA256 文件需要单独下载。
请按照 [安装指南](docs/installation.md) 校验并安装。macOS 二进制没有 Developer ID 签名，也没有经过公证。
托管式自动更新尚未启用。

发布包只包含 CLI，使用时不需要 Rust。如果要自己编译，请参考
[从源码构建](docs/installation.md#build-from-source)。

## 快速开始

先按 [安装指南](docs/installation.md) 安装 CLI，然后选择服务器：

- **已有服务器和账号：** 使用它的 HTTPS 地址，直接继续下面的步骤。
- **第一次自建实例：** 按照 [启动你自己的服务器](docs/deployment.md#start-your-own-server)
  构建容器、检查就绪状态并创建账号，宿主机不需要 Rust 工具链。完成后从下面第 2 步继续。

### 1. 在个人电脑上登录

把地址和邮箱换成你自己的账号信息：

```sh
veil login --server https://vault.example.com --email you@example.com
```

按提示输入主密码。这会注册一台个人设备，可以访问所有现有和以后新建的 vault。
如果是共享主机或无界面主机，请改用 [受限设备注册](docs/usage.md#add-a-restricted-host)。

### 2. 导入并使用一个密钥

用一个假的值创建临时项目。如果 `demo` 这个 vault 里已经有你的数据，请换一个没用过的名字：

```sh
project_dir="$(mktemp -d)"
cd "$project_dir" || exit 1
printf 'DEMO_TOKEN=example-value-only\n' > .env
veil init --dry-run --vault demo
veil init --vault demo
veil run -- sh -c 'test "$DEMO_TOKEN" = example-value-only && echo delivered'
veil audit
```

命令会输出 `delivered`，审计记录里会出现一次交付。`veil.toml` 里保存的是
`veil://demo/DEMO_TOKEN/password` 这个引用，而不是值。`veil init` 会把 `.env` 加入 `.gitignore`，
但不会删除它；如果它已经被 Git 跟踪，也不会取消跟踪。

用于真实项目时，在项目目录里用它自己的 vault 名称执行同样的导入命令，写入前先检查 dry run 的结果。
提交 `veil.toml`，不要提交 `.env` 或客户端状态。更新、密钥存储、添加设备、恢复和排错，
请看 [日常使用](docs/usage.md)。自建服务器的备份请看 [备份与恢复](docs/deployment.md#backup-and-restore)。

## 安全边界

- 客户端加密无法保护已经被攻破的客户端或操作系统。
- 拿到密钥的进程可以复制或发送它。输出遮蔽不是沙箱，不覆盖编码后的值、文件或网络流量。
- 个人设备可以读取所有现有和以后新建的 vault。如果只想开放部分 vault，请使用受限设备或工作负载。
- 在场确认需要 macOS。其他平台会拒绝从要求在场确认的 vault 交付密钥。
- 管理 API 应保持私有。使用 Bitwarden 客户端不需要暴露整个 API。

使用真实密钥前，请阅读 [部署指南](docs/deployment.md)。报告漏洞请按 [安全策略](SECURITY.md) 进行，
不要使用公开的 issue。

## 文档

文档都在本仓库中，目前只有英文：

- [安装](docs/installation.md)：下载、校验和安装 CLI，或从源码构建。
- [日常使用](docs/usage.md)：项目引用、更新、密钥存储、设备、恢复、交付场景和排错。
- [自托管](docs/deployment.md)：启动服务器、限制访问、备份、恢复和升级。
- [术语表](GLOSSARY.md)：vault、item、设备和授权。

## 参与贡献

可复现的 bug 和功能建议请提交到 [GitHub Issues](https://github.com/tim101010101/veil/issues)。
示例中请使用一次性账号和假的密钥。请附上版本号和源码 commit，分享日志前先删除个人信息。

PR 流程见 [参与贡献](CONTRIBUTING.md)，开发环境和测试见 [开发指南](docs/development.md)。

## 许可证

Veil 采用 [AGPL-3.0-only](LICENSE) 许可证。发布的 CLI 压缩包在 `THIRD-PARTY-NOTICES.txt` 中
附带依赖的许可证和对应源码链接。
