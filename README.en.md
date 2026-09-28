# login

BORUIX's **login program**: it reads a username and password, verifies them, drops privileges to the target user, and switches to that user's shell.

[简体中文](README.md)

## What it does

```
read username and password → verify → drop privileges to the target user → switch to that user's shell
```

It is a standalone program, started by the system init process when it provides a terminal.

## Handling failed verification

| Rule | Details |
| --- | --- |
| At most **3 attempts** | Exits after three failures |
| Failure messages are **uniform** | Not distinguishing "no such user" from "wrong password", so they cannot be used to probe which usernames exist |
| Exits once exhausted | **Never lets anyone through on failure** |

## Known limitations

| Item | Status |
| --- | --- |
| Password echo | **Off** — no character is displayed while typing a password |
| History and completion | **None** — login only; no line editing |
| Failure lockout | **None** — after three failures it exits and can be retried |
| Input timeout | **None** — no time limit |

## Building

```bash
cargo build --release
```

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
