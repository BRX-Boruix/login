# login

BORUIX 的登录认证程序：读取用户名与口令，校验通过后降权到目标用户，再切换到该用户的 shell。

[English](README.en.md)

它是一个独立的程序，由系统初始化进程在提供终端时拉起。

## 使用

开机后终端上出现提示，依次输入用户名和口令。口令输入时不会显示任何字符。

```
login: alice
password:
```

校验通过后进入该用户的 shell；失败三次则退出，可以重新登录。

## 已知限制

口令错误与用户名不存在返回同一条提示，这是有意的——否则可以靠错误信息的差异试探出哪些用户名
存在。

登录时不提供历史记录与 Tab 补全，这两个能力只属于 shell。

失败三次退出后即可重试，没有失败锁定，输入也不设时限。

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
