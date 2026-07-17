# Pacinspect

Pacinspect is an AI-assisted security review gate for Arch User Repository (AUR) builds. It sends the PKGBUILD, related packaging files, local heuristic signals, and the previous Git revision's diff to an OpenAI-compatible chat-completions API. It explains each finding and blocks risky builds before `makepkg` reads the PKGBUILD.

Pacinspect is a review aid, not a sandbox or a guarantee that a package is safe. A model can miss malicious behavior. Read high-impact PKGBUILDs yourself and build untrusted packages in an isolated environment.

## How the yay integration works

A shell alias cannot reliably identify every AUR dependency that yay resolves. Pacinspect uses two temporary, process-local yay overrides:

1. yay resolves dependencies and clones or updates every AUR package repository in the transaction.
2. Immediately before source verification, yay's pre-download editor hook passes Pacinspect the exact transaction's PKGBUILD paths. Pacinspect analyzes those package directories concurrently.
3. Each package gets an independent API request and model context. Reports and interactive decisions are presented sequentially so terminal output and prompts cannot overlap.
4. Safe or explicitly approved content hashes are cached for that yay run.
5. A temporary `makepkg` shim remains as a fail-closed fallback for recipes that changed after preflight or were not included in it, then delegates unchanged arguments to the real makepkg.

Yay finishes cloning all transaction PKGBUILD repositories before invoking the pre-download hook, so the analyses can overlap even when yay's own source downloads are sequential. A blocked preflight exits its editor hook unsuccessfully, which makes yay abort before source verification or PKGBUILD execution.

The overrides are never saved to yay's configuration. Pacinspect reserves yay's `editor`, `editorflags`, `editmenu`, and `answeredit` options during the wrapped process; conflicting arguments are stripped. Yay displays its normal “Proceed with install?” confirmation after the successful preflight hook. Repository packages passed directly to pacman are not scanned. Pacinspect rejects `pacinspect yay --save` so temporary overrides cannot become permanent.

## Install

A Rust 1.85+ toolchain is required because the project uses Rust 2024 edition.

```sh
cargo install --path .
```

### Arch Linux package

An AUR-ready `PKGBUILD` and `.SRCINFO` live in `packaging/aur`. Build and install them locally with:

```sh
cd packaging/aur
makepkg -si
```

The package installs `pacinspect` as the canonical executable and creates the requested alias chain:

```text
/usr/bin/pac -> pacinstall
/usr/bin/pacinstall -> pacinspect
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

`PACINSPECT_*` environment variables explicitly override saved settings. Generic OpenAI variables are compatibility fallbacks: a saved `api_key` takes precedence over `OPENAI_API_KEY`, and a saved configuration file's URL takes precedence over `OPENAI_BASE_URL`. This prevents credentials or endpoints exported for another tool from silently replacing Pacinspect's configured provider.

| Setting | Explicit override | Compatibility fallback |
| --- | --- | --- |
| API URL | `PACINSPECT_API_URL` | `OPENAI_BASE_URL` when no config file exists |
| API key | `PACINSPECT_API_KEY` | `OPENAI_API_KEY` when no key is saved |
| Model | `PACINSPECT_MODEL` | none |
| Configuration file | `PACINSPECT_CONFIG` | platform default |

An API key may be omitted for a local unauthenticated endpoint. The endpoint must accept OpenAI-style `POST /chat/completions` requests and return text in `choices[0].message.content`. Pacinspect asks the model for a strict JSON report but does not depend on provider-specific structured-output options.

## Use

With no path, scan every cached package directory containing a `PKGBUILD` under yay's currently configured `buildDir`:

```sh
pacinspect scan
```

Pass a path to inspect only one downloaded package recipe:

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

Without a path, `--json` emits one JSON array whose entries include `package_directory`; an explicit path retains the single-report JSON object. Pacinspect reads the active build directory from `yay -P -g`, so custom yay cache locations work without additional Pacinspect configuration.

Cached package analyses also run concurrently. The default limit is eight active API requests; use `pacinspect config set max-parallel-reviews N` to tune it for provider rate limits. Result order remains deterministic, and each request contains only one package's inspection bundle.

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
max_parallel_reviews = 8
```

`block_threshold` accepts `info`, `low`, `medium`, `high`, or `critical`. A model verdict of `dangerous` always blocks, even if its individual finding severities are lower. `fail_open = false` means API errors, invalid model output, and timeouts stop a wrapped build. Enabling fail-open is possible but weakens the gate and prints a prominent warning.

`max_parallel_reviews` controls both cached scans and yay transaction preflights. Lower it if the API returns rate-limit errors; increase it when the provider supports more simultaneous requests.

Exit codes:

- `0`: report approved, or the delegated command succeeded;
- `1`: configuration, API, input, or launch error;
- `2`: `scan` completed but policy blocked it;
- `125`: the makepkg shim blocked a yay build before delegation.

## Privacy and limitations

Package files and the recipe diff are sent to the configured API provider. Do not use a remote provider for private packaging repositories unless its data policy is acceptable.

The model receives untrusted package text and is explicitly told to ignore instructions embedded in it. This reduces prompt-injection risk but does not eliminate model error. Local heuristics are supplied as review leads rather than treated as proof, because many shell commands are legitimate inside packaging functions. Keep yay's normal diff menu enabled, verify upstream source signatures and checksums, and prefer isolated build users or containers for packages you do not trust.
