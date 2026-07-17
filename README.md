# Pacinspect

Pacinspect is an AI-assisted security review gate for Arch User Repository (AUR) builds. It sends the PKGBUILD, related packaging files, local heuristic signals, and the previous Git revision's diff to an OpenAI-compatible chat-completions API. It explains each finding and blocks risky builds before `makepkg` reads the PKGBUILD.

Pacinspect is a review aid, not a sandbox or a guarantee that a package is safe. A model can miss malicious behavior. Read high-impact PKGBUILDs yourself and build untrusted packages in an isolated environment.

## Why the yay integration wraps makepkg

A shell alias cannot reliably identify every AUR dependency that yay resolves. Pacinspect instead launches yay with a temporary `--makepkg` override:

1. yay resolves dependencies and downloads each AUR package repository normally.
2. Before yay's first `makepkg` call for a package base—including source verification—Pacinspect inspects that package directory.
3. A safe or explicitly approved review is cached by content hash for that single yay run.
4. Pacinspect delegates the original arguments to the real makepkg executable.
5. A blocked or failed closed review returns before makepkg can source the PKGBUILD.

The override is process-local and is never saved to yay's configuration. Repository packages, which yay gives directly to pacman, are not scanned. Pacinspect rejects `pacinspect yay --save` so its temporary override cannot accidentally become permanent.

## Install

A Rust 1.85+ toolchain is required because the project uses Rust 2024 edition.

```sh
cargo install --path .
```

Ensure `$HOME/.cargo/bin` is in `PATH`, then configure the API:

```sh
pacinspect config init
```

The default file is `$XDG_CONFIG_HOME/pacinspect/config.toml` (normally `~/.config/pacinspect/config.toml`) and is written with mode `0600` on Unix.

Non-interactive configuration is also available:

```sh
pacinspect config set api-url https://api.openai.com/v1
pacinspect config set model gpt-4.1-mini
pacinspect config set api-key       # hidden prompt; avoids shell history
pacinspect config show              # API key is redacted
pacinspect config path
```

Environment variables override saved values:

| Variable | Fallback | Purpose |
| --- | --- | --- |
| `PACINSPECT_API_URL` | `OPENAI_BASE_URL` | API base URL or full `/chat/completions` URL |
| `PACINSPECT_API_KEY` | `OPENAI_API_KEY` | Bearer token |
| `PACINSPECT_MODEL` | none | Model name |
| `PACINSPECT_CONFIG` | platform default | Configuration file path |

An API key may be omitted for a local unauthenticated endpoint. The endpoint must accept OpenAI-style `POST /chat/completions` requests and return text in `choices[0].message.content`. Pacinspect asks the model for a strict JSON report but does not depend on provider-specific structured-output options.

## Use

Inspect an already downloaded package recipe:

```sh
pacinspect scan ~/.cache/yay/example
```

When a report reaches the configured threshold, the interactive choices are:

- abort the build (default),
- open the most relevant file in `$VISUAL` or `$EDITOR` and rescan,
- continue once and accept the reported risk.

Machine-readable and non-interactive modes:

```sh
pacinspect scan --json ~/.cache/yay/example
pacinspect scan --non-interactive ~/.cache/yay/example
pacinspect scan --accept-risk ~/.cache/yay/example
```

Run yay through the security gate:

```sh
pacinspect yay -- -S example
pacinspect yay -- -Syu
pacinspect yay example
```

All arguments after `yay` are forwarded. If the arguments contain `--makepkg`, that command becomes the real delegate while Pacinspect remains the temporary interceptor. Pacinspect also reads yay's current `makepkgbin` setting, falling back to the configured `makepkg_binary`.

`--noconfirm` does not approve a risky report. Without an interactive terminal, Pacinspect blocks automatically at `block_threshold`.

## What is reviewed

For each package base, Pacinspect collects:

- `PKGBUILD` and `.SRCINFO`;
- root-level text files and common packaging support files such as install scripts, patches, systemd units, hooks, tmpfiles, and sysusers files;
- a line-numbered diff from `HEAD^` to `HEAD`, when package history is available;
- local signals for download-and-execute pipelines, privilege commands, account or scheduler changes, obfuscated execution, sensitive host paths, setuid/capability changes, skipped integrity checks, and unencrypted source URLs.

The model is instructed to account for Arch packaging semantics: writes under `$srcdir` and `$pkgdir` are normal, while host modification or unrelated networking is not. It must explain evidence, context, severity, source provenance, and a concrete action.

Pacinspect does **not** download remote source contents itself. It can identify changed URLs, checksums, mutable VCS references, disabled integrity checks, and suspicious recipe changes, but it cannot claim to have reviewed remote content that is only referenced by a URL.

## Policy and exit behavior

Important defaults:

```toml
block_threshold = "medium"
fail_open = false
timeout_seconds = 90
max_input_bytes = 300000
```

`block_threshold` accepts `info`, `low`, `medium`, `high`, or `critical`. A model verdict of `dangerous` always blocks, even if its individual finding severities are lower. `fail_open = false` means API errors, invalid model output, and timeouts stop a wrapped build. Enabling fail-open is possible but weakens the gate and prints a prominent warning.

Exit codes:

- `0`: report approved, or the delegated command succeeded;
- `1`: configuration, API, input, or launch error;
- `2`: `scan` completed but policy blocked it;
- `125`: the makepkg shim blocked a yay build before delegation.

## Privacy and limitations

Package files and the recipe diff are sent to the configured API provider. Do not use a remote provider for private packaging repositories unless its data policy is acceptable.

The model receives untrusted package text and is explicitly told to ignore instructions embedded in it. This reduces prompt-injection risk but does not eliminate model error. Local heuristics are supplied as review leads rather than treated as proof, because many shell commands are legitimate inside packaging functions. Keep yay's normal diff menu enabled, verify upstream source signatures and checksums, and prefer isolated build users or containers for packages you do not trust.
