# dsh-rgate

[![CI](https://github.com/raomaiping-hash/dsh-rgate/actions/workflows/ci.yml/badge.svg)](https://github.com/raomaiping-hash/dsh-rgate/actions/workflows/ci.yml)
[![version](https://img.shields.io/github/v/tag/raomaiping-hash/dsh-rgate)](https://github.com/raomaiping-hash/dsh-rgate/tags)
[![license](https://img.shields.io/github/license/raomaiping-hash/dsh-rgate)](LICENSE)

[English](README.md) | 中文

[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) Web UI 的远程访问登录门禁。给整个浏览器界面加上密码墙：公网（非回环）匿名访问只能看到登录页，登录前所有 `/api` RPC 一律拒绝。

## 为什么需要它

Harness 自带的浏览器信任围栏（`trustedHosts`）是防 DNS 重绑定的**可达性策略，不是认证**——只要 Host 头通过围栏，任何人都能使用 Web UI。本插件为自托管部署补上缺失的认证层：IP 扫描器撞到的是登录页，而不是你的 agent。

## 功能

- **全页登录墙**——通过 `webServer.tapIndex` 向每个 `index.html` 注入门禁脚本；未登录的非回环访问被重定向到 `/rgate-login`（自包含登录页）。
- **全量 `/api` 门禁**——用精确路由遮蔽内置 `/api` 前缀：全部 52 个 unary RPC + `/api/respond` + `/api/session.export`。回环直通；其余请求必须携带会话 cookie，否则在解析 body 之前就 `401`。
- **Cookie 会话**——`rgate_session`，HttpOnly + SameSite=Strict，7 天内存会话；登出与改密会吊销全部会话。
- **登录限速**——每客户端 5 次失败后指数退避（30 秒起翻倍，上限 16 分钟）。在 Cloudflare Tunnel 之后，客户端键取 `Cf-Connecting-Ip`（回退 `X-Forwarded-For`、再回退 socket 地址），攻击者无法把所有人一起锁死。
- **审计日志**——登录成功/失败/锁定、改密事件写入 harness 日志（journald），不含密码。
- **哈希密码存储**——`~/.dsh/remote-auth.json`（0600）内以 scrypt（N=16384, r=8, p=1）+ 随机盐 + 常数时间比较存储；旧版明文文件自动迁移。忘记密码：删除该文件并重启服务，新密码会在服务日志中打印一次。
- **Remote Access 设置分区**——`settings.section` 条目：门禁状态、登录/登出、改密。密码不再明文展示（哈希存储设计使然）。
- **Origin 校验**——登录/登出/改密端点拒绝跨站表单提交。

## 安装

从 GitHub 安装（纯 ESM，**无构建步骤、无安装脚本**——安装时不会执行任何代码）：

```sh
dsh plugin --profile web add github:raomaiping-hash/dsh-rgate
```

如需可复现安装，可锁定 commit sha：`dsh plugin --profile web add github:raomaiping-hash/dsh-rgate#<commit-sha>`——后续推送无法悄悄改变你机器上运行的内容。

从 npm 或 tarball 安装：

```sh
dsh plugin --profile web add dsh-rgate              # npm
dsh plugin --profile web add ./dsh-rgate-0.1.0.tgz  # tarball
```

随后重启 web profile。插件激活时打印 `[rgate] 门禁已启用 …`，首次启动会在 `~/.dsh/remote-auth.json` 生成随机密码：

```sh
journalctl -u deepseek-harness | grep rgate
```

## 配置

门禁本身没有配置文件，两个行为约定需要了解：

- **回环永远可信。**`127.0.0.1` / `localhost` / `::1` 不设墙——这是管理员通道。
- **其他所有 Host 一律要求登录**（局域网、Tailscale、公网域名一视同仁）。想要免登录入口，请在上游保护它（见下）。

密码文件位于 `$DSH_HOME/remote-auth.json`（默认 `~/.dsh/remote-auth.json`——遵循 harness 约定，与 `settings.yaml` 同层）：

| 字段 | 含义 |
| --- | --- |
| `version: 2` | scrypt 哈希存储 |
| `salt`、`N`、`r`、`p`、`hash` | scrypt 参数与派生密钥 |
| `createdAt`、`updatedAt` | 时间戳 |

## 新增的 HTTP 端点

| 端点 | 方法 | 用途 |
| --- | --- | --- |
| `/rgate-login` | GET | 自包含登录页（已放行时 302 到 `/`） |
| `/api/remote-auth.login` | POST `{password}` | 校验密码、下发会话 cookie |
| `/api/remote-auth.logout` | POST | 吊销会话并清除 cookie |
| `/api/remote-auth.status` | GET | `{configured, authenticated, loopback}` |
| `/api/remote-auth.secret` | GET | 仅回环：`{mode, path, createdAt, updatedAt}`——永不返回密码 |
| `/api/remote-auth.password` | POST `{current?, next}` | 改密（已认证会话，或回环 + 当前密码） |

## 已知边界

- **WebSocket 事件流不受门禁。**`/api/events.mux` 与 `/api/events.host` 的升级由内置 `dsh-client-connection` 持有：重复注册同名 upgrade 会抛错、抢先注册会打断启动。通过围栏的客户端仍可连接并收到实时会话事件帧。稳妥的修法在**上游**：给公网域名启用 Cloudflare Access（Zero Trust），或在前面放一个带认证的反向代理（如 nginx `auth_request`）——在流量到达 Harness 之前就把 UI、API、WebSocket 全部封闭。
- **RPC 面按快照固定。**门禁遮蔽的是测试所用 Harness 版本的 unary 方法表；Harness 升级新增 RPC 时，需要把新路径补进 `UNARY` 表。
- **会话在内存中。**Harness 重启会登出所有人（否则 7 天有效）。
- 静态资源对未登录访问者仍可见（它们是公开代码）；所有数据都在 API 门禁之后。

## 威胁模型

门禁是单密码、个人/小团队部署的**认证层**。前提是 Harness 进程与主机文件系统可信——能读到 `remote-auth.json` 或进程内存的人已经拥有主机。它不能替代系统/网络卫生、HTTPS 终结，或公网入口处的上游访问控制。

## 测试

`tests/smoke.mjs` 在隔离的 `HOME` 里用桩 context 驱动插件的真实路由处理器（不碰真实凭据）：

```sh
node tests/smoke.mjs
```

## 许可证

MIT
