# login

BORUIX 的**登录认证程序**：读取用户名与口令，校验通过后降权到目标用户，再切换到该用户的 shell。

[English](README.en.md)

## 它做什么

```
读用户名与口令 → 校验 → 降权到目标用户 → 切换到该用户的 shell
```

它是一个独立的程序，由系统初始化进程在提供终端时拉起。

## 校验失败的处理

| 规则 | 说明 |
| --- | --- |
| 最多 **3 次** | 输错 3 次后退出 |
| 失败信息**统一** | 不区分"用户不存在"与"口令错误"，避免被用来试探哪些用户名存在 |
| 耗尽后退出 | **绝不在失败时放行** |

## 已知限制

| 项目 | 状态 |
| --- | --- |
| 口令回显 | **已关闭**——输入口令时任何字符都不上屏 |
| 历史记录与补全 | **无**——只用于登录，不提供行编辑 |
| 失败次数锁定 | **无**——输错 3 次退出后即可重试 |
| 输入超时 | **无**——不设时限 |

## 构建

```bash
cargo build --release
```

## 文件结构

```
login/
├── Cargo.toml    # 包定义
├── build.rs      # 注入链接脚本
├── linker.ld     # 用户态段布局
└── src/
    └── main.rs   # 身份读取、口令校验与降权
```

## 相关项目

- [`libline`](https://github.com/BRX-Boruix/libline) —— 提供口令输入的回显抑制
- [`userd`](https://github.com/BRX-Boruix/userd) —— 账户守护进程，建家目录
- [`init`](https://github.com/BRX-Boruix/init) —— 拉起本程序
- [`shell`](https://github.com/BRX-Boruix/shell) —— 认证通过后切换到的 shell

## 许可

MIT License，版权归 Yang Borui 所有。详见 [LICENSE](LICENSE)。
