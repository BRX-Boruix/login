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
//! - **口令回显**：不做关闭回显——本内核终端层无 termios，且**不假装**做了。
//!   已实现的是**退格可erase**（见 `read_line`），这只影响可用性，不影响认证正确性。
//!   此限制已在 ADR-041 与本注释中显式声明，不得据"看起来像图形登录"推断回显已关。
//! - **无失败锁定/审计**：不实现 PAM 式 `pam_faillock`（ADR-041 §1.2.2 已列明为差异项）。
//! - **无超时**：输入不设时限。

#![no_std]
#![no_main]
extern crate alloc;

use libsys::{read, write, Error};

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

/// 读取一行（以 \n 或 \r 结束），支持退格。
///
/// **为何自己实现**：本内核 shell 侧**没有** cooked-mode / 行编辑器helper——
/// 终端读取是逐字节裸循环。任何登录程序都必须自带"读一行 + 处理退格"逻辑。
///
/// 返回：去掉行尾符后的字节数（0 表示空行）。**不 panic**——缓冲区满即截断返回。
fn read_line(buf: &mut [u8]) -> usize {
    let mut n = 0usize;
    loop {
        let mut one = [0u8; 1];
        match read(STDIN, &mut one) {
            Ok(0) | Err(_) => {
                // 读到 EOF / 出错：返回已收集内容，不假装读到了完整行。
                return n;
            }
            Ok(_) => {}
        }
        match one[0] {
            b'\n' | b'\r' => {
                nl();
                return n;
            }
            // 退格（BS 0x08 与 DEL 0x7f 都接受）：仅在非空时回退并erase屏幕。
            0x08 | 0x7f => {
                if n > 0 {
                    n -= 1;
                    // "\x08 \x08" 是终端 erase 惯用法：退格、空格覆盖、再退格。
                    puts(b"\x08 \x08");
                }
            }
            c => {
                if n < buf.len() {
                    buf[n] = c;
                    n += 1;
                    // 回显读入字符（见模块文档"诚实边界"：未关闭回显）。
                    let _ = write(STDOUT, &[c]);
                }
                // 缓冲满：静默忽略后续字符（不 panic、不丢已读内容）。
            }
        }
    }
}

/// 从 stdin 读一行并去除首尾空白，返回长度。
fn read_trimmed(buf: &mut [u8]) -> usize {
    let n = read_line(buf);
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
fn login_main() -> i32 {
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
        let nlen = read_trimmed(&mut name_buf);
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
        let plen = read_trimmed(&mut pw_buf);

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
        match libsys::exec_path(SHELL_PATH, &[]) {
            Ok(_pid) => {}
            Err(e) => {
                puts(b"login: cannot start shell (");
                print_errno(e);
                puts(b")\n");
                return 5;
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
#[unsafe(no_mangle)]
pub extern "C" fn user_main(_argc: isize, _argv: *const *const u8) -> i32 {
    login_main()
}
