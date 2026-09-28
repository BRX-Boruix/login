# login

BORUIX's **login authentication program**: it reads a username and password, verifies them, **drops privileges** to the target user, and switches to that user's shell.

[简体中文](README.md)

## What it does

```
read username and password → verify → drop privileges to the target user → switch to that user's shell
```

It is a **standalone user-space program**, not inlined logic of the system init process. Cramming terminal I/O, password reading, and privilege dropping into PID 1 would make it carry both "process supervision" and "authentication", and a failure in either would affect the system's survival.

## Identity comes from a read-only authoritative file

A user's identity (user ID, group ID) **always comes from the system configuration file** and **never** from the user-writable account table.

The reason is direct: the account table is writable from user space. If identity were taken from it, then **editing that one file would amount to impersonating someone else**.

## Handling failed verification

| Rule | Details |
| --- | --- |
| At most **3 attempts** | A named constant rather than a magic number |
| Failure messages are **uniform** | Not distinguishing "no such user" from "wrong password", avoiding username enumeration |
| Exits non-zero once exhausted | **Never drops privileges on failure** — that would be handing a shell to someone who has not authenticated |

## Privileges

The privileges this program runs with were **determined by measurement**, not inferred:

| Requirement | Why |
| --- | --- |
| Read the password file | Its identity is the file's owner, so it **matches as owner** — no privilege-override capability needed |
| **Must be able to drop privileges** | Dropping is itself a restricted operation; without the corresponding privilege the identity cannot be lowered |
| **Must not hold the "owner override" capability** | Measured: that capability **entirely bypasses** the permission policy evaluation — holding it makes the password file meaningless |

### A risk acknowledged honestly

The worry that "some privilege can serve as an indirect channel to read the password file" **is real**. But for this program it **adds no new risk**: it **already is** the password file's owner and needs no extra privilege to read it, and the privilege it does hold affects only **privilege dropping**, **not file access policy**. So for this program that privilege's **sole** effect is "allowing the identity to be lowered".

Dropping the identity and revoking capabilities happen in **one and the same** operation, so there is no intermediate state of "privileges dropped but still holding the capability".

> This **corrects** an earlier design prohibition that "the login program must not hold that privilege" — that prohibition **directly contradicted** the rule that "without it, privileges cannot be dropped"; the two can never both be satisfied.

## Honest boundaries

### Password echo: off

When a password is typed, **no character is displayed**. The capability comes from the user-space library [`libline`](https://github.com/BRX-Boruix/libline) — **no kernel line was changed**, and no terminal control interface was introduced.

**How it is verified**: typing a password on the real keyboard in a real virtual machine leaves **no plaintext password** in the serial log, while the username echoes character by character.

### Only the "echo suppression" subset

This program does **not** carry history or Tab completion. That is not a verbal agreement: the line editing component's feature set is trimmed to a minimal set there, so **history and completion are visibly unreachable at compile time on this path**.

### What is not implemented

| Item | Status |
| --- | --- |
| Failure lockout | **None** — no PAM-style failure lockout |
| Timeout | **None** — input has no time limit |

## Building

```bash
cargo build --release
```

Started by the system init process when it provides a terminal.

## Layout

```
login/
├── Cargo.toml    # package definition
├── build.rs      # injects the linker script
├── linker.ld     # user-space section layout
└── src/
    └── main.rs   # identity lookup, password verification, and privilege dropping
```

## Related projects

- [`libline`](https://github.com/BRX-Boruix/libline) — provides echo suppression for password input
- [`userd`](https://github.com/BRX-Boruix/userd) — the account daemon that creates home directories
- [`init`](https://github.com/BRX-Boruix/init) — starts this program
- [`shell`](https://github.com/BRX-Boruix/shell) — the shell switched to after authentication

## License

MIT License, copyright Yang Borui. See [LICENSE](LICENSE).
