# login

**简体中文** | [English](#english)

BORUIX 的**登录认证程序**——向用户索要用户名与口令，验证通过后**降低权限**并交出一个 shell。

```
提示用户名与口令 → 校验 → 降权 → 启动 shell
```

---

## 为什么它是独立程序

`login` 本可以是系统初始化进程里的一段代码，但它被做成了独立程序。原因是**职责分离**：

系统初始化进程是 PID 1，负责监督所有其他进程。如果把终端读写、口令读取、权限降低这些事塞进
PID 1，它就同时承担"进程监督"与"认证"两项职责——**任一出错都会影响整个系统存活**。

认证逻辑放在独立进程里，它崩溃了只影响一次登录尝试，系统本身不受影响。

## 认证流程

1. 提示输入用户名
2. 提示输入口令（**输入内容不上屏**）
3. 校验
4. 成功后**降低权限**至目标用户
5. 启动 shell

### 失败处理

| 行为 | 说明 |
| --- | --- |
| 最多尝试 **3 次** | 具名常量，不是散落的魔法数 |
| 失败信息**统一** | 不区分"用户不存在"与"口令错误" |
| 耗尽后如实退出 | **不**在失败时降权 |

**为什么失败信息要统一**：如果"用户不存在"和"口令错误"给出不同提示，攻击者就能借此**枚举系统中
存在哪些用户名**。统一提示消除了这个信息泄露。

**为什么失败时绝不降权**：那等于把一个 shell 交给未经认证的人。

## 口令不回显

输入口令时，**任何字符都不显示在屏幕上**——这是终端程序的基本要求，也是容易做错的地方。

它不只是"把字符吞掉"那么简单：用户仍需要能按退格修正输错的口令，而这类编辑操作与"不回显"之间
的交互必须处理正确。这项能力由用户态的行编辑库提供，**内核一行未改**，也没有引入终端的规范模式。

实现上有一个明确的边界：口令读取路径被裁剪到**最小编辑能力**——历史记录与 Tab 补全在这条路径上
**无法到达**（不是口头约定，而是在类型层面就不可用）。登录时按上方向键翻出别人上次输的密码，
显然不是我们想要的。

验证方式：在真实虚拟机中经键盘输入口令后，日志中**不出现口令明文**，而用户名逐字回显。

## 权限：一份实测得出的能力集

`login` 运行时的能力集是经过**实测确定**的，而不是凭直觉推断的：

| 能力 | 是否具备 | 原因 |
| --- | --- | --- |
| 读口令表 | 需要 | 进程以系统管理员身份运行，是口令文件的属主，以属主身份读取即可 |
| **不得**绕过文件策略 | **必须不含** | 持有它会**完全绕过**权限策略求值，口令文件形同虚设 |
| 降低权限 | **必须含** | 没有它就无法把权限降下去，认证闭环无法完成 |
| 拒绝信号 | 需要 | 使普通用户发来的信号被拒绝 |

第二行尤其重要：如果 `login` 持有"绕过文件策略"的能力，那么系统里所有文件权限检查都形同虚设。
这是实测确认的（而不是推测），也是它**必须不含**该项能力的原因。

第三行则是一个**设计上的必然**：降低权限这个动作本身需要足够的权限才能执行。

### 一个被修正过的结论

早期设计中曾规定"`login` 不得持有系统级能力"。实测发现**这条规定与降权规则直接冲突**——两者
不可能同时满足。该禁令已被修正，结论与实测数据都记录在案。

**降权与撤权在同一次操作内完成**，因此不存在"权限已降低、但系统级能力仍然在手"的中间状态。

## 身份信息的权威来源

用户名对应的用户 ID 与组 ID，**一律取自只有管理员可读的口令文件**，绝不读取另一个可被用户态
修改的账户文件。

原因直接明了：读一个可写文件，等于允许"改表即冒充身份"。

## 能读什么、不能读什么

| 边界 | 说明 |
| --- | --- |
| **不背历史与补全** | 见上文，这在类型层面就不可达 |
| **无失败锁定** | 不实现"多次失败后锁定账户"这类机制 |
| **无输入超时** | 输入不设时限 |

这些是**如实说明的已知边界**，不是遗漏。

## 多终端实例

`login` 接受一个实例号参数，用于支持多个终端各自独立登录。不带参数时使用实例 0。

认证之前，程序会把自己的输入绑定到对应实例的终端，并**独占键盘输入**——避免与其它实例的登录
程序争抢同一份输入。

## 测试

认证链路的验证在真实虚拟机上完成：输入用户名与口令，确认认证通过、权限正确降低、shell 正常
交出，且口令不出现在日志中。

## 构建

```bash
cargo build --release
```

编译产物部署为 BORUIX 系统中的用户态程序，由系统初始化进程拉起。

## 文件结构

```
login/
├── Cargo.toml    # 包定义
├── build.rs      # 注入链接脚本
├── linker.ld     # 用户态段布局
└── src/
    └── main.rs   # 程序本体
```

## 相关项目

- [`libline`](https://github.com/BRX-Boruix/libline) —— 行编辑库，提供口令不回显
- [`libc`](https://github.com/BRX-Boruix/libc) —— C 标准库（口令哈希与校验）
- [`init`](https://github.com/BRX-Boruix/init) —— 拉起本程序
- [`libsys`](https://github.com/BRX-Boruix/libsys) —— 用户态系统调用封装

## 许可

MIT License，版权归 Yang Borui 所有。详见 [LICENSE](LICENSE)。

---

# English

[简体中文](#login) | **English**

BORUIX's **login authentication program** — it prompts for a username and password, and on success
**drops privilege** and hands over a shell.

```
prompt for username and password → verify → drop privilege → start the shell
```

---

## Why it is a separate program

`login` could have been a section of code inside the system init process, but it is a separate
program for the sake of **separation of duties**:

The init process is PID 1 and supervises every other process. Packing terminal I/O, password
reading, and privilege dropping into PID 1 would make it carry both "process supervision" and
"authentication" — and **a failure in either would affect the survival of the whole system**.

With authentication in its own process, a crash costs one login attempt and leaves the system itself
unaffected.

## The authentication flow

1. Prompt for a username
2. Prompt for a password (**nothing appears on screen**)
3. Verify
4. On success, **drop privilege** to the target user
5. Start the shell

### Handling failure

| Behaviour | Explanation |
| --- | --- |
| At most **3 attempts** | A named constant, not magic numbers scattered about |
| Failure messages are **uniform** | No distinction between "no such user" and "wrong password" |
| Exits honestly when exhausted | It does **not** drop privilege on failure |

**Why failure messages are uniform**: if "no such user" and "wrong password" produced different
messages, an attacker could use the difference to **enumerate which usernames exist**. A uniform
message removes that leak.

**Why privilege is never dropped on failure**: doing so would hand a shell to someone unauthenticated.

## The password is not echoed

When a password is entered, **no character is displayed** — a basic requirement for a terminal
program, and an easy one to get wrong.

It is not merely a matter of swallowing characters: the user must still be able to backspace and
correct a mistyped password, and the interaction between such editing operations and "do not echo"
has to be handled correctly. This capability comes from the user-space line editing library, with
**not one line of the kernel changed** and no terminal canonical mode introduced.

There is one explicit boundary in the implementation: the password reading path is trimmed to the
**minimum editing capability** — history and Tab completion are **unreachable** on that path (not by
convention, but unusable at the type level). Pressing the up arrow at a login prompt to reveal the
previous person's password is plainly not wanted.

Verification: after typing a password from a real keyboard in a real VM, the log contains **no
password plaintext**, while the username echoes character by character.

## Privileges: a capability set established by measurement

`login`'s runtime capability set was determined **by measurement**, not by intuition:

| Capability | Required? | Reason |
| --- | --- | --- |
| Read the password table | Yes | The process runs as the administrator and owns the password file; reading it as the owner suffices |
| **Must not** bypass file policy | **Must be absent** | Holding it **entirely bypasses** policy evaluation, making the password file meaningless |
| Drop privilege | **Must be present** | Without it privilege cannot be lowered and the authentication loop cannot close |
| Refuse signals | Yes | Causes signals from ordinary users to be refused |

The second row matters especially: were `login` to hold the "bypass file policy" capability, every
file permission check in the system would be meaningless. This was confirmed by measurement rather
than assumed, and it is why that capability **must be absent**.

The third row is a **design necessity**: the act of dropping privilege itself requires sufficient
privilege to perform.

### A conclusion that was corrected

An early design stated that "`login` must not hold a system-level capability". Measurement found
that **this rule directly conflicts with the privilege-dropping rule** — the two cannot both hold.
The prohibition has been corrected, with both the conclusion and the measurement data recorded.

**Dropping and revoking privilege happen in a single operation**, so there is no intermediate state
of "privilege lowered but the system capability still in hand".

## The authoritative source of identity

A username's user ID and group ID are taken **exclusively from the password file readable only by the
administrator**, never from another account file that user space can modify.

The reason is direct: reading a writable file amounts to allowing "edit the table and you are someone
else".

## What it does and does not do

| Boundary | Explanation |
| --- | --- |
| **No history or completion** | As above; unreachable at the type level |
| **No failure lockout** | No "lock the account after repeated failures" mechanism |
| **No input timeout** | Input has no time limit |

These are **honestly stated known boundaries**, not omissions.

## Multiple terminal instances

`login` accepts an instance number argument, supporting independent logins on multiple terminals.
Without an argument it uses instance 0.

Before authenticating, the program binds its input to that instance's terminal and **takes exclusive
hold of the keyboard** — avoiding a contest with the login programs of other instances over the same
input.

## Testing

The authentication path is verified on a real VM: entering a username and password, confirming that
authentication succeeds, privilege is dropped correctly, and the shell is handed over properly, with
the password absent from the log.

## Building

```bash
cargo build --release
```

The artifact is deployed as a user-space program in a BORUIX system, started by the system init
process.

## Layout

```
login/
├── Cargo.toml    # package definition
├── build.rs      # injects the linker script
├── linker.ld     # user-space section layout
└── src/
    └── main.rs   # the program itself
```

## Related projects

- [`libline`](https://github.com/BRX-Boruix/libline) — the line editing library providing the no-echo capability
- [`libc`](https://github.com/BRX-Boruix/libc) — the C standard library (password hashing and verification)
- [`init`](https://github.com/BRX-Boruix/init) — starts this program
- [`libsys`](https://github.com/BRX-Boruix/libsys) — the user-space syscall wrapper

## License

MIT License, copyright Yang Borui. See [LICENSE](LICENSE).
