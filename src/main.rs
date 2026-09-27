//! `login` —— A2-7 认证与登录闭环（ADR-041 §1.3/§1.4）。
//!
//! ## 职责
//!
//! 独立用户态程序：读用户名与口令 → 校验 → **降权** → 切换到目标 shell。
//! 不是 init 的内联逻辑——init 是 PID 1（supervisor），把终端 I/O、口令读取、降权
//! 塞进 PID 1 会使它同时承担"进程监督"与"认证"，任一出错都影响系统存活。
//!
//! ## 能力集（**实测定案**，非推断）
//!
//! `{uid: 0, gid: 0, caps: CAP_KILL | CAP_SYSTEM}`。
//!
//! `CAP_OWNER` **必须不含**；`CAP_SYSTEM` **必须含**。两处都是实测结论：
//!
//! - **C1 要能读**：uid 0 即 shadow 文件属主，以**属主命中**读表，**不需要**任何 DAC 覆盖能力
//!   （`test_login_capability_set`：`{uid0,EMPTY}` 与 `{uid0,KILL}` 均读得成功）；
//! - **C2 必须不含 `CAP_OWNER`**：实测它会**完全绕过**策略求值
//!   （`test_shadow_file_separation` 第 ③ 组），持它则口令文件形同虚设；
//! - **C3 必须含 `CAP_SYSTEM`**：`test_login_downgrade_path` 实测事实 (1)——`{uid0,KILL}`
//!   调用 `identity_set(1000,1000,0)` 返回 **EACCES**、uid 仍为 0。A2-1 的规则是
//!   "无 `CAP_SYSTEM` 则 uid 不得改变"（`syscall.rs:2999`），故**没有 CAP_SYSTEM 就无法降权**。
//!   `syscall.rs:2996` 亦明文本程序是"认证通过后降权至目标用户"的唯一通道。
//! - **C4 要能防**：持 `CAP_KILL` 使普通用户的信号被 A2-0 单点判定拒绝（ADR-040 §3.5.4 #15）。
//!
//! ### 关于 `CAP_SYSTEM` 的风险（**如实承认，并说明为何此处不构成新增风险**）
//!
//! 实测事实 (3)：uid 1000 + `CAP_SYSTEM` 确可 `identity_set(0,0,0)` 变为 uid 0 **再**读得
//! shadow——"CAP_SYSTEM 是间接读表通道"这个担忧**是真的**。但对 login **不构成新增风险**：
//! login **本来就是 uid 0**，**无需** `CAP_SYSTEM` 就能读表；且 `CAP_SYSTEM` 只影响
//! `identity_set`，**不影响文件策略**（实测事实 (2)：`{uid0,SYSTEM|KILL}` 与 `{uid0,KILL}`
//! 读表结果相同）。故对 login 而言，`CAP_SYSTEM` 的**唯一**作用是"允许把 uid 降下去"。
//! 且降权与撤权在**同一次** `identity_set(uid, gid, 0)` 内完成，无"已降权但仍持 CAP_SYSTEM"
//! 的中间态。
//!
//! > 此结论**修正**了 ADR-041 §1.2.3 初稿"login 不得持 CAP_SYSTEM"的过度禁令——该禁令与
//! > A2-1 的降权规则直接冲突（两者不可能同时满足）。修正过程与实测数据记于该节
//!
//! > **关键纪律**：**不得**用 `ProcessIdentity::system(uid)` 构造本程序的身份——
//! > 该构造器的 caps 是 `SYSTEM|DEVICE|MEMORY|KILL|OWNER`（`process.rs:300`），**含 OWNER**。
//! > 本程序由 init 以显式 caps 启动（见 `init`），此处只做**收尾降权**。
//!
//! ## 身份权威来源（ADR-041 §1.2.6）
//!
//! uid/gid **一律取自 root-only 的 `/config/shadow.json`**，**绝不**读 `users.json`。
//! 因后者用户态可写，读它就等于允许"改表即冒充身份"（§1.2.5 风险 R-1）。
//!
//! ## 失败处理（ADR-041 §1.5）
//!
//! - 上限 **3 次**（具名常量，非魔法数）；
//! - 失败信息**统一**（不区分"用户不存在"与"口令错误"），避免用户名枚举；
//! - 耗尽后如实退出非零，**不**在失败时降权（否则等于把 shell 交给未认证者）。
//!
//! ## 诚实边界（S39）
//!
//! - **口令回显**：**已关闭**（2026-10-04，L-3 落地）。读口令走
//!   [`libline::read_line_plain`] 并传 `suppress_echo: true`，任何输入都不上屏。
//!   该能力由用户态库 `libline` 提供——**内核一行未改**，也不引入 termios。
//!   > **本条曾长期登记为未关闭**（ADR-041 §4.2 / `docs/TODO/multi-user.md`）。
//!   > [ADR-042 输入侧不背历史债](../../docs/adr/042-input-side-no-legacy-canonical-mode.md)
//!   > 明确拒绝 canonical 模式与 termios，行规程（含行编辑与回显抑制）归用户态库；
//!   > [ADR-046 决策 3](../../docs/adr/046-line-editing-user-space-library.md)
//!   > 指定 `login` 是回显抑制的落点。两者现已兑现。
//!   > **验证方式**：真实 QEMU 中经 PS/2 键盘键入口令，串口日志中
//!   > **不出现**口令明文，而用户名逐字回显（见 `sdk/l3_interactive.py`）。
//! - **只取回显抑制子集**：`login` **不**背历史与 Tab 补全（ADR-046 §4 条 3）。
//!   这不是口头约定：`read_line_plain` 把 `EditorCaps` 裁到 `plain()`，
//!   历史/补全在该路径上**编译期可见地不可达**，且 `completions` 永不被调用。
//! - **无失败锁定/审计**：不实现 PAM 式 `pam_faillock`（ADR-041 §1.2.2 已列明为差异项）。
//! - **无超时**：输入不设时限。

#![no_std]
#![no_main]
extern crate alloc;

use libsys::{open, read, write, Error, OpenFlags, Permissions};

/// 把无符号数以十进制追加到 String（login 不依赖 core::fmt 的格式化机器）。
fn push_dec(body: &mut alloc::string::String, mut v: u64) {
    if v == 0 {
        body.push('0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    while v > 0 && i > 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    body.push_str(core::str::from_utf8(&tmp[i..]).unwrap_or(""));
}

/// 【R13 后续：投影自愈】认证成功后（**降权前**的 uid0+CAP_SYSTEM 窗口内），把
/// shadow.json **全表**重投影为 /config/users.json。
///
/// 设计定位（ADR-041 §1.2.6 延伸）：
/// - shadow.json 是**唯一权威**（uid/gid/name + 口令）；users.json 此前是内核
///   种子播种的**第二份静态副本**——两处种子各自维护导致投影失步（实测：root
///   在 shadow 有条目、users.json 没有，登录后 shell 提示符只显示 "uid0"）。
/// - 自愈后 users.json 变为"shadow 的展示投影"，由认证路径维护：任何可认证
///   账户**第一次登录**后就必然出现在投影里，不存在"忘记同步"。
/// - **为何全表重投影**（而非只补当前用户）：投影 = 权威的完整镜像，逐条 upsert
///   会留下"改过 shadow 但该账户从未登录"的半失步态；全表写入让两个文件在
///   任何一次登录后**完全一致**（删除的账户也随之从投影消失）。
/// - **为何在降权前**：此刻仍是 uid0（shadow 属主）+ CAP_SYSTEM，既读得到
///   权威表、也写得了投影文件（0600→0644 属主写）；降权后两者都不可写。
/// - **绝不投影 salt/hash**：只写 name/uid/gid 三字段——users.json 保持 0644
///   全员可读，哈希永不出 shadow（ADR-041 §1.2.0 的分离前提原样保持）。
/// - **失败语义**：投影失败（写不进/序列化不可能失败）只**告警不阻断**——登录
///   的职责是认证，投影是尽力而为的衍生品；但告警如实打印，不静默。
fn regenerate_users_projection(shadow: &[libc::shadow::ShadowEntry]) {
    // 渲染：schema 与原种子/userd 解析器完全一致（S13：同一格式一处定语义）。
    // 账户名是解析器从 JSON 里读出来的字符串（不含引号/控制字符的普通名字），
    // 此处如原样回填 JSON 字符串字面量；数字用小助手转十进制（login 无 fmt 依赖）。
    let mut body = alloc::string::String::from("{\"users\":[");
    for (i, e) in shadow.iter().enumerate() {
        if i > 0 {
            body.push(',');
        }
        body.push_str("{\"name\":\"");
        body.push_str(&e.name);
        body.push_str("\",\"uid\":");
        push_dec(&mut body, e.uid as u64);
        body.push_str(",\"gid\":");
        push_dec(&mut body, e.gid as u64);
        body.push_str("}");
    }
    body.push_str("]}\n");

    // 写投影：CREATE_OR_TRUNCATE 保证整文件替换（不留旧条目尾巴）。
    // 权限传 all() 只影响**新建**时的初始模式；文件已存在（常态）则模式不变。
    match open("/config/users.json", OpenFlags::CREATE_OR_TRUNCATE, Permissions::all()) {
        Ok(fd) => {
            let bytes = body.as_bytes();
            let mut off = 0usize;
            let mut ok = true;
            while off < bytes.len() {
                match write(fd, &bytes[off..]) {
                    Ok(0) => { ok = false; break; }
                    Ok(n) => off += n,
                    Err(_) => { ok = false; break; }
                }
            }
            let _ = libsys::close(fd);
            if ok {
                puts(b"login: users.json projection updated (");
                let mut cnt = alloc::string::String::new();
                push_dec(&mut cnt, shadow.len() as u64);
                puts(cnt.as_bytes());
                puts(b" accounts)\n");
            } else {
                puts(b"login: WARNING users.json projection write failed\n");
            }
        }
        Err(_) => {
            puts(b"login: WARNING users.json projection open failed\n");
        }
    }
}

/// 标准输入 fd。
const STDIN: u64 = 0;
/// 标准输出 fd。
const STDOUT: u64 = 1;

/// 允许的失败次数上限（ADR-041 §1.5）。具名常量，避免魔法数散布。
const MAX_ATTEMPTS: usize = 3;

/// 输入行缓冲上限（用户名与口令共用）。
const LINE_MAX: usize = 128;

/// 登录后启动的 shell 路径。
const SHELL_PATH: &str = "/programs/shell.elf";

/// 打印一段字节（忽略错误——诊断输出失败不该改变认证结论）。
fn puts(s: &[u8]) {
    let _ = write(STDOUT, s);
}

/// 打印换行。
fn nl() {
    puts(b"\n");
}

/// `login` 的 `EditorHost`：只需「把字节写到 stdout」与「重绘当前行」。
///
/// **为何没有真正的补全实现**：`login` 走 [`libline::read_line_plain`]，该路径把
/// `EditorCaps` 裁到 `plain()`（历史/补全均不可达），故 `completions`
/// **永远不会被调用**。这里如实返回空，不伪造候选。
///
/// **重绘为何不打提示符**：`username: ` / `password: ` 由调用方在读之前打印一次。
/// 若在重绘里重复打印，口令输入时会把提示符刷屏；且口令本就不该重绘。
struct LoginHost;

impl libline::EditorHost for LoginHost {
    fn write(&mut self, bytes: &[u8]) {
        puts(bytes);
    }

    /// 回到行首 → 清行 → 重打缓冲区 → 光标左移回原位。
    ///
    /// 字节序列与 `shell` 的重绘保持一致（`\r` + `\x1b[K` + 内容 + `\x1b[<n>D`），
    /// 这样两个程序的终端行为相同，用户不会觉得登录界面与 shell 不一样。
    fn redraw(&mut self, buffer: &[u8], cursor: usize) {
        puts(b"\r\x1b[K");
        puts(buffer);
        let back = buffer.len().saturating_sub(cursor);
        if back > 0 {
            let mut b = [0u8; 24];
            puts(b"\x1b[");
            puts(dec_bytes(back as u64, &mut b));
            puts(b"D");
        }
    }

    /// 不给候选：`login` 走的路径不会调用本方法（见类型文档）。
    fn completions(&mut self, _word: &[u8], _is_command: bool) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        alloc::vec::Vec::new()
    }
}

/// 从 fd 0 取字节的输入源。
///
/// **为何要这一层**：`libline::ByteSource` 只解码**已被推入**的字节；「字节从哪来」
/// 是调用方的事（键盘 vs 事件总线，ADR-046 §4 条 5）。本类型就是 login 的答案：
/// 从 fd 0 读。`libline` 侧因此不需要知道终端的存在。
#[derive(Default)]
struct StdinSource {
    inner: libline::ByteSource,
}

impl libline::InputSource for StdinSource {
    fn next_item(&mut self) -> libline::InputItem {
        self.inner.next_item()
    }

    /// 从 fd 0 取一个字节，**在没有数据时原地重试**（不返回 `false` 去让出 CPU）。
    ///
    /// # 为何必须重试而不是让出（L-3 实测踩到的真实缺陷）
    ///
    /// 本内核的键盘阻塞是**单等待者**语义：`read` 空读时经 `block_for_kbd` 以 CAS
    /// 登记 `KBD_WAITER` 并挂起自己；键盘中断经 `wake_kbd` 把**登记过的那个 pid**
    /// 放回就绪队列（`kernel/crates/task/src/scheduler.rs:1712`、`:1836`）。
    ///
    /// 而 `libsys::yield_now()` 走的是 `SYS_TASK_WAIT(0,0)`——**纯让出，不登记
    /// `KBD_WAITER`**。于是若本方法在无键可读时返回 `false`，`libline` 就会
    /// `yield_now()` 空转：此时**没人登记等待**，`wake_kbd` 无处可唤醒，
    /// 击键只能躺在键盘队列里，直到下一次 `read` 恰好被调用才可能被取走。
    ///
    /// **实测症状**（真实 QEMU + PS/2 真实按键）：读用户名正常（每次回显都伴随
    /// write 系统调用，节奏被带起来了），但读口令时——**回显被抑制、几乎不发
    /// 系统调用**——键入了 8 个口令字符后，**回车永远不到**，登录永久挂住。
    /// 逐单元探针证据：`[IT] C=a..w` 全部到达，`[IT] SUBMIT` 永不出现；
    /// 改成原地重试后同一探针立刻拿到 `[IT] SUBMIT` 并登录成功。
    ///
    /// **与原实现的等价性**：修改前的 `login` 朴素 `read_line` 正是原地
    /// `continue`（见 git 历史），所以本写法不是新发明，而是**保住既有正确
    /// 行为**——这也解释了为何此前从未暴露：老实现压根不走 yield 路径。
    ///
    /// **为何不让 `libline` 各调用方自己决定是否 yield**：那是接口层面的设计
    /// 问题（poll 语义 vs park 语义），已如实登记，不在 L-3 内擅自扩大改动。
    fn refill(&mut self) -> bool {
        let mut one = [0u8; 1];
        loop {
            match read(STDIN, &mut one) {
                Ok(1) => {
                    self.inner.push_bytes(&one);
                    return true;
                }
                // 键盘空闲：**继续重试**（保持在内核里登记为键盘等待者）。
                Err(Error::WouldBlock) => continue,
                // 真错误 / 诚实 EOF：如实报「没有新增字节」。
                _ => return false,
            }
        }
    }
}

/// 把无符号数以十进制写进 `buf`，返回有效切片（供重绘的光标左移使用）。
fn dec_bytes(mut v: u64, buf: &mut [u8]) -> &[u8] {
    if v == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = buf.len();
    while v > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let n = buf.len() - i;
    buf.copy_within(i.., 0);
    &buf[..n]
}

/// 从 stdin 读一行（去首尾空白），返回长度。
///
/// `suppress_echo` 为 `true` 时（读口令），任何输入都不上屏。
///
/// **2026-10-04（L-3）**：原本本文件自带一份朴素的「逐字节读 + 退格」循环
/// （S28 登记的双份实现之一）。现改走 [`libline::read_line_plain`]——该工具函数把
/// `EditorCaps` 裁到 `plain()`，历史与补全在本路径上**不可达**，
/// 故 `login` 不会背上它不该有的能力（ADR-046 §4 条 3）。
///
/// 返回：去掉首尾空白后的字节数。0 表示空行。
/// **不 panic**——超过 `buf.len()` 即截断（缓冲区由 `Editor` 动态承载，
/// 再按需拷入调用方的固定缓冲）。
fn read_trimmed(buf: &mut [u8], suppress_echo: bool) -> usize {
    let mut editor = libline::Editor::new();
    let mut src = StdinSource::default();
    let mut host = LoginHost;

    // `read_line` 只在 提交/中断/EOF 时返回，**不会**返回 `Continue`；
    // 故这里不需要外层循环。回车由下方 `nl()` 统一补一个换行。
    let line = match libline::read_line_plain(
        &mut editor,
        &mut src,
        &mut host,
        |_h| {},
        libline::PlainLineOptions { suppress_echo },
    ) {
        libline::EditAction::Submitted(l) => {
            nl();
            l
        }
        // EOF：如实把已收集内容交回，不假装读到了完整行。
        libline::EditAction::Eof(l) => {
            nl();
            l
        }
        // 中断：本行作废。
        libline::EditAction::Interrupted => {
            nl();
            alloc::vec::Vec::new()
        }
        libline::EditAction::Continue => alloc::vec::Vec::new(),
    };

    // 固定缓冲区截断：保持原有契约（满即截断，不 panic）。
    let n = core::cmp::min(line.len(), buf.len());
    buf[..n].copy_from_slice(&line[..n]);

    let mut s = 0usize;
    let mut e = n;
    while s < e && (buf[s] == b' ' || buf[s] == b'\t') {
        s += 1;
    }
    while e > s && (buf[e - 1] == b' ' || buf[e - 1] == b'\t') {
        e -= 1;
    }
    if s > 0 {
        buf.copy_within(s..e, 0);
    }
    e - s
}

/// 主流程。**任何失败路径都以非零码退出，绝不降权后返回**。
fn login_main(instance: usize) -> i32 {
    puts(b"BORUIX login\n");

    // 载入口令表。读不到就是配置/权限错误——如实报错，**不**退化为"无口令放行"。
    let shadow = match libc::shadow::load_shadow() {
        Ok(list) => list,
        Err(e) => {
            puts(b"login: cannot read password database (");
            print_errno(e);
            puts(b")\n");
            return 2;
        }
    };

    let mut name_buf = [0u8; LINE_MAX];
    let mut pw_buf = [0u8; LINE_MAX];

    let mut attempt = 0usize;
    while attempt < MAX_ATTEMPTS {
        puts(b"username: ");
        let nlen = read_trimmed(&mut name_buf, false);
        if nlen == 0 {
            // 空用户名：计入一次尝试（避免空回车无限刷屏）。
            attempt += 1;
            puts(b"login: authentication failed\n");
            continue;
        }
        let name = match core::str::from_utf8(&name_buf[..nlen]) {
            Ok(s) => s,
            Err(_) => {
                attempt += 1;
                puts(b"login: authentication failed\n");
                continue;
            }
        };

        puts(b"password: ");
        let plen = read_trimmed(&mut pw_buf, true);

        // 校验：用户不存在与口令错误**给出同一条消息**（避免用户名枚举，§1.5）。
        let ok = match shadow.iter().find(|e| e.name == name) {
            Some(entry) => matches!(
                libc::shadow::verify(entry, &pw_buf[..plen]),
                Ok(true)
            ),
            None => false,
        };
        // 无论成败都擦除口令缓冲（减少明文在内存中的驻留）。
        for b in pw_buf.iter_mut() {
            *b = 0;
        }

        if !ok {
            attempt += 1;
            puts(b"login: authentication failed\n");
            continue;
        }

        // ---- 认证通过：取**权威** uid/gid（来自 shadow，非 users.json）----
        let entry = match shadow.iter().find(|e| e.name == name) {
            Some(e) => e,
            None => return 2, // 不可达：上面刚找到；防御性返回。
        };
        let (uid, gid) = (entry.uid, entry.gid);

        // ---- 投影自愈：shadow 全表 → users.json（仍持 uid0+CAP_SYSTEM）----
        // 必须在 groups_set/identity_set **之前**：降权后既读不到 shadow 也写不了投影。
        regenerate_users_projection(&shadow);

        // ---- 焦点认领（ADR-048 T3，owner 裁决 α：SYS_STREAM_FOCUS_SET）----
        // 认证成功后、**降权前**——此刻仍持 CAP_SYSTEM，是本会话唯一合法的
        // 焦点授予窗口（tcsetpgrp 同构：策略在用户态认证点，机制在内核门禁）。
        // 实例 0（单终端既有形态）也走同一调用：焦点真值本就指向 0，重复
        // 设置幂等，但**保留调用**让「login 认领焦点」成为单径语义（S15：
        // 不存在「实例 0 靠默认值、实例 1+ 靠 syscall」的双径）。
        // 失败 = 焦点没切过去 = 会话收不到键盘（假活会话）——如实退出，
        // 由 init 重生 getty（S20：绝不静默继续）。
        if let Err(e) = libsys::event::focus_set(instance) {
            puts(b"login: cannot claim console focus (instance ");
            // instance 十进制（usize→u64 同宽，u8 缓冲必够）。
            let mut ib = [0u8; 8];
            puts(dec_bytes(instance as u64, &mut ib));
            puts(b"): ");
            print_errno(e);
            puts(b"\n");
            return 5;
        }

        // ---- 降权：先设补充组，再设身份，顺序不可颠倒 ----
        // 先设组是因为身份切换后可能已失去 CAP_SYSTEM，届时 groups_set 会被拒绝。
        // 主组跟随目标 gid；清空补充组（本版本无 /config/groups.json 权威组表，
        // **不编造**组成员关系——如实置空，见 ADR-041 §1.2.6 的诚实边界）。
        if let Err(e) = libsys::groups_set(&[gid]) {
            puts(b"login: cannot set groups (");
            print_errno(e);
            puts(b")\n");
            return 3;
        }
        // **caps 传 0**：降权后不保留任何能力。
        //
        // 【为何本调用必须持 CAP_SYSTEM（**实测**，非推断）】
        // kernel `test_login_downgrade_path` 实测四种组合：
        //   (1) `{uid0, KILL}` + identity_set(1000,1000,0) → **EACCES**，uid 仍为 0；
        //   (4) `{uid1000, 无能力}` + identity_set(0,0,0) → EACCES（**无提权**，正确）。
        // 即：**无 CAP_SYSTEM 时 uid 不可改变**——这是 A2-1 的越权防线（`syscall.rs:2999`）。
        // 因此"读 shadow 需要 uid 0"与"降权需要 CAP_SYSTEM"是**同一条规则的两面**，
        // login 必须持 CAP_SYSTEM 才能完成降权；`syscall.rs:2996` 亦明文本程序为唯一通道。
        //
        // 【那 CAP_SYSTEM 会不会让 login 变成"间接读表"的绕过面？】
        // 实测事实 (3)：uid 1000 + CAP_SYSTEM 确可 `identity_set(0,0,0)` 变为 uid 0 再读得
        // shadow（`0x3`）——这个风险**是真的**。但它对 login **不构成新增风险**：
        // login **本来就是 uid 0**（以 shadow 属主身份启动），它**无需** CAP_SYSTEM 就能读表；
        // 而 CAP_SYSTEM 只影响 `identity_set`，不影响文件策略（实测事实 (2)：`{uid0,SYSTEM|KILL}`
        // 读表结果与 `{uid0,KILL}` 相同）。故对 login 而言 CAP_SYSTEM 的**唯一**作用是
        // "允许它把 uid 降下去"——即本行。
        //
        // 【因此本行的 caps=0 是**关键收口**】降权与撤权在**同一次** syscall 内完成，
        // 不存在"已降权但仍有 CAP_SYSTEM"的中间态。若此处失败而继续执行，等于把
        // uid 0 + CAP_SYSTEM 交给已登录用户（提权）——故失败一律终止，绝不继续。
        if let Err(e) = libsys::identity_set(uid, gid, 0) {
            puts(b"login: cannot drop privileges (");
            print_errno(e);
            puts(b")\n");
            return 4;
        }

        puts(b"login: welcome, ");
        puts(name.as_bytes());
        puts(b"\n");

        // ---- 切换到 shell ----
        // exec 失败时**不回落**到特权上下文：身份已降，此处失败只是"登不进去"。
        // 【R13 会话保活】exec_path = SYS_TASK_SPAWN：shell 是 login 的**子进程**。
        // login 必须等 shell 退出后**再**退出——若 login 先退（exit 0），init 的
        // supervisor 判"会话结束"立刻重生 login，而 shell 仍持有键盘等待者，
        // 两个 stdin 读者并发瓜分击键（实测 boot16：`cat /config/shadow.json`
        // 被 pid 7/8 交错读取，字符各得一半），并伴随虚假 NUL 回显。
        let shell_pid = match libsys::exec_path(SHELL_PATH, &[]) {
            Ok(pid) => pid,
            Err(e) => {
                puts(b"login: cannot start shell (");
                print_errno(e);
                puts(b")\n");
                return 5;
            }
        };
        loop {
            match libsys::waitpid_any() {
                Ok(wr) if wr.pid == shell_pid => {
                    // shell 已退出：会话随之结束，init 重生 login（下一位用户）。
                    break;
                }
                Ok(_) => continue, // 收到别的子进程（当前无），继续等 shell
                Err(libsys::Error::WouldBlock) => {
                    // shell 仍在运行：让出 CPU 等待（与 init 等待循环同款纪律）。
                    let _ = libsys::sleep(100_000_000);
                }
                Err(_) => {
                    // waitpid 不可用（理论不可达）：如实结束会话。
                    break;
                }
            }
        }
        return 0;
    }

    puts(b"login: too many failed attempts\n");
    // 失败耗尽：**保持特权身份退出**（不降权），由 init 决定后续（重启登录或停机）。
    1
}

/// 打印 errno 的数值形式。**不编造**可读字符串（本仓无 strerror 表）；
/// 数值足以与内核错误码对照，且避免引入一张可能与内核不同步的映射表。
fn print_errno(e: Error) {
    let code = errno_of(e);
    let mut digits = [0u8; 12];
    let mut i = digits.len();
    let mut v = code as i64;
    if v == 0 {
        i -= 1;
        digits[i] = b'0';
    }
    while v > 0 && i > 0 {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    puts(b"errno ");
    puts(&digits[i..]);
}

/// 取错误的 errno 数值（与内核 `Error::to_errno` 对齐，ADR-010）。
fn errno_of(e: Error) -> i32 {
    e.to_errno()
}

/// 入口：内核 ELF 加载器的用户态约定（与 pwde2e/shell 同制）。
///
/// 返回退出码；**不**自行调用 `exit`——由用户态运行时按返回值收尾，
/// 避免与运行时重复退出（既有程序一致的做法）。
/// 解析 argv[0] 为实例 id（十进制；无 argv = 0——init 既有 spawn 形态兼容）。
/// 非法如实退出（错误的实例号 = 会话接错终端，比死更糟，S09/S17）。
fn parse_instance(argc: isize, argv: *const *const u8) -> Option<usize> {
    if argc <= 0 || argv.is_null() {
        return Some(0);
    }
    // SAFETY: argc>=1 且 argv 由内核 exec 路径按 C 数组构造（NUL 结尾，
    // loader argv 雏形 argc=1，init/src/main.rs 同款访问形态）。
    let p = unsafe { *argv };
    if p.is_null() {
        return Some(0);
    }
    let mut n: usize = 0;
    let mut i = 0isize;
    let mut any = false;
    unsafe {
        while *p.offset(i) != 0 {
            let c = *p.offset(i);
            if c < b'0' || c > b'9' {
                return None;
            }
            n = n.checked_mul(10)?.checked_add((c - b'0') as usize)?;
            any = true;
            i += 1;
        }
    }
    if !any {
        return None;
    }
    Some(n)
}

#[unsafe(no_mangle)]
pub extern "C" fn user_main(argc: isize, argv: *const *const u8) -> i32 {
    match parse_instance(argc, argv) {
        Some(instance) => login_main(instance),
        None => {
            puts(b"login: FATAL: bad instance id in argv\n");
            1
        }
    }
}
