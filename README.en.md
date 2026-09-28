# login

BORUIX's login program: it reads a username and password, verifies them, drops privileges to the target user, and switches to that user's shell.

[简体中文](README.md)

It is a standalone program, started by the system init process when it provides a terminal.

## Usage

After boot a prompt appears on the terminal; enter the username and then the password. Nothing is displayed while typing the password.

```
login: alice
password:
```

Once verified you enter that user's shell; three failures exit and you can log in again.

## Known limitations

A wrong password and a nonexistent username return the same message. That is deliberate — otherwise the difference in error messages could be used to probe which usernames exist.

Login offers no history and no Tab completion; those belong to the shell alone.

After three failures it exits and can be retried. There is no failure lockout, and input has no time limit.

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
