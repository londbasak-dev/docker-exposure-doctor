# Docker Exposure Doctor

A read-only, offline CLI that checks a supplied Docker Compose YAML file for common exposure declarations. It does not invoke Docker, launch containers, inspect a daemon, resolve images, read `.env` files, expand environment variables, or make network calls. Bundled examples contain only newly invented synthetic values.

## Install and try

Python 3.10 or newer is required. PyYAML is the only runtime dependency.

```sh
python -m venv .venv
# Activate the environment for your shell, then:
python -m pip install -e .
docker-exposure-doctor samples/exposed.compose.yaml
docker-exposure-doctor samples/exposed.compose.yaml --format json
docker-exposure-doctor samples/safer.compose.yaml --fail-on high
```

Exit status: `0` inspected without meeting a configured failure threshold; `1` findings meet `--fail-on high|medium|low`; `2` invalid arguments/input. The default `--fail-on never` returns `0` even when findings exist. A zero exit status is **not** a security certification. Reports go to stdout; no report file is created automatically.

## Rules and evidence

| Rule | Severity | Trigger |
| --- | --- | --- |
| `privileged` | high | Boolean privileged mode enabled |
| `host-network` / `host-pid` | high | Host network/process namespace |
| `powerful-capability` | high | `ALL` or `SYS_ADMIN` added |
| `docker-socket` | high | Host mount source mentions Docker socket/control pipe, even read-only |
| `broad-host-mount` | high | Syntactically normalized absolute host root or selected broad system directories; Windows drive root |
| `published-port` | medium | Host publication without an explicit numeric loopback address |
| `loopback-port` | info | Explicit numeric loopback host publication |
| `root-user` | medium | Explicit `root` or numeric zero UID, including leading zeros and `+0` |
| `image-user-unknown` | low | User absent or empty; image default remains unknown |
| `inline-secret` | high | Secret-like environment name has an inline nonempty value |

Evidence contains only a bounded conventional service name and a fixed field name, never environment values, mount paths, ports, parser excerpts, file paths, or arbitrary YAML text. Nonconventional service names use an ordinal label. Service names can themselves reveal business context: review them before sharing. Reports contain rule IDs, severities, and fixed advice. Pure `$NAME` and `${NAME}` references are not flagged as inline values; references with defaults are flagged conservatively. Environment variable names are not printed.

The parser uses PyYAML's safe object model with duplicate/string-key validation, a 2 MiB cap, depth 64 and 100,000 token limits. **YAML aliases and merge keys are refused**, including common Compose extension/anchor patterns. Supply a deliberately flattened file. Unsupported data shapes fail with a generic diagnostic without echoing input. Files are read only when explicitly selected, and never modified.

## Limits

This is a focused declaration linter, not a full Compose validator or runtime audit. It does not merge multiple Compose files, apply profiles, evaluate interpolation, inspect Dockerfiles/image defaults, follow `extends`/`include`, or inspect `env_file`, `secrets`, build arguments, labels, commands, or secret contents. Inline-secret detection currently covers `environment` only. Broad-mount checks cover selected exact directory roots rather than every potentially sensitive path. A missing finding does not establish safety.

Port checks describe the supplied declaration; firewall rules, daemon defaults, platform behavior and deployed bindings require separate verification. Numeric loopback bindings, including IPv4-mapped IPv6 loopback, receive an information finding, not an exposure warning. Bare ports under `ports` request a host publication and are flagged; `expose` alone is not host publication. Rootless Docker and user namespace remapping are not inferred. Absolute POSIX bind sources normalize `.` and `..` without filesystem access; symlinks are not resolved. Relative/variable mount paths cannot establish real host paths. Bare short-syntax source names are treated as named volumes, so a volume named `docker.sock` is not confused with a host socket. Read-only socket access is still flagged because it can expose Docker control capabilities.

## Development

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
```

Tests use synthetic in-memory or temporary Compose inputs. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). MIT licensed; see [LICENSE](LICENSE).
