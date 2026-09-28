# Sentinel — Ubuntu AI SysAdmin Agent

A self-hosted FastAPI service and responsive dark dashboard. The LLM proposes
commands, the backend checks them, and the operator approves each mutation.
No Node.js build. Python 3.14+ on Linux is required for production execution.

## Start on Ubuntu

Install Python 3.14+ and its venv package from a trusted source appropriate for
your Ubuntu release. The installer does not replace Ubuntu's system Python.

```bash
bash setup.sh "$HOME/server-agent"
cd "$HOME/server-agent"
nano .env  # enter your provider key, base URL and model
.venv/bin/python main.py
```

Open http://127.0.0.1:8000 and paste `AGENT_WEB_TOKEN` from `.env` into the header.
The installer generates this secret and requires an empty destination, so reruns
cannot silently overwrite credentials. It provisions all application files,
documentation and tests, creates a venv, installs wheels only, and checks dependencies.
To use a different Python executable, set `PYTHON=/path/to/python3.14`.

For a manual checkout, copy `.env.example` to `.env`, create a venv, install
`requirements.txt`, and replace both `CHANGE_ME` values in `.env`. Generate a token with:

```bash
python3.14 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Defaults: `SERVER_HOST=127.0.0.1`, `SERVER_PORT=8000`. For remote access, keep
loopback binding and use an SSH tunnel:

```bash
ssh -L 8000:127.0.0.1:8000 your-user@your-server
```

For a TLS reverse proxy, configure WebSocket upgrade forwarding, restrict network
access, and set `ALLOWED_ORIGINS=https://agent.example.com`. Use HTTPS/WSS outside
loopback/SSH. The app disables implicit trust of forwarded headers. Origin checks
are a browser defense; the secret token is still required on every connection.

## LLM provider

- OpenAI: `LLM_BASE_URL=https://api.openai.com/v1`; use an enabled tool-capable model.
- DeepSeek: set its OpenAI-compatible base URL and a tool-capable model in `.env`.
- Ollama: `LLM_BASE_URL=http://127.0.0.1:11434/v1`, `LLM_API_KEY=ollama`, and an
  installed model that supports tool calling.
- Other compatible endpoints must support Chat Completions, `tools`, `tool_choice`
  and `max_tokens`. Provider compatibility depends on the selected model.

Provider keys remain on the backend. Tokens stay in page memory, are cleared from
the input after connection, and are never put in URLs or localStorage. Chat history
is session-local and disappears on disconnect. Raw recent command output is sent
to the configured LLM: self-hosted execution does not imply local inference.
Do not ask the agent to read credentials or other sensitive files.

## Command policy and limitations

Every command is checked before execution and checked again after waits. A strict
literal-command grammar rejects shell operators, substitutions, globs, scripts,
wrappers, sudo, interpreters, editors and unsupported executables. Commands such as
`ls`, `cat`, `grep`, `systemctl status`, `free -m`, `uptime`, `ip a` and `ss -tulpn`
run automatically. File mutations, socket termination, package changes, service
changes, reboot/shutdown, signals and firewall operations require an exact-command
approval. Unflagged package changes are blocked; use `-y` or `--dry-run`.

Hard blocks include root/protected-system-path deletion and privilege changes,
filesystem formatting, raw disk tools and fork bombs. Shell composition like
`ls | grep log` is intentionally unsupported: ask for separate tool calls.
Unknown operations are blocked, never implicitly treated as read-only.

This policy is **defense in depth, not a sandbox or a guarantee for arbitrary
Bash**. Approved package/service operations may run trusted system hooks; symlink
races, existing server configuration, utility behavior and OS permissions still
matter. Do not run as root or grant blanket sudo. Built-in file-read protection
is limited and is not a general secret scanner. Audit commands may contain paths
or arguments; keep service journals access-controlled.

The systemd unit runs as `server-agent`, drops capabilities, prevents privilege
escalation, makes the filesystem read-only except its state/private temporary
directories, hides home directories, and limits memory/tasks/CPU. Consequently,
privileged changes normally fail even after UI approval. Approval is permission
to attempt a command, not a grant of OS privileges. Read access to some logs also
requires separately reviewed permissions. If privileged operations are needed,
have an administrator design a narrow privileged broker and adjust the service
restrictions for those exact operations; this project does not install one.
PrivateTmp means `/tmp` inside the service is not the host's normal `/tmp` view.

## Install the boot-time service

Run these commands as an administrator after configuring and testing the app.
The following assumes a fresh `/opt/server-agent` deployment; do not overwrite
an existing installation without a backup. Code and the venv must remain owned
by root so the service cannot modify its own security policy.

```bash
sudo useradd --system --home-dir /var/lib/server-agent --shell /usr/sbin/nologin server-agent
sudo install -d -m 0755 /opt/server-agent /opt/server-agent/static
sudo install -m 0644 main.py requirements.txt /opt/server-agent/
sudo install -m 0644 static/index.html /opt/server-agent/static/index.html
sudo python3.14 -m venv /opt/server-agent/.venv
sudo /opt/server-agent/.venv/bin/python -m pip install --only-binary=:all: -r /opt/server-agent/requirements.txt
sudo install -m 0600 .env /etc/server-agent.env
sudo install -m 0644 server-agent.service /etc/systemd/system/server-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now server-agent
sudo systemctl status server-agent --no-pager
sudo journalctl -u server-agent -n 100 --no-pager
```

Systemd reads the root-only environment file and passes values to the service.
Subprocesses receive a small explicit environment with no API or web token. The
default production command work directory is `/var/lib/server-agent`. The service
unit supports graceful cleanup and automatic restart. It is intentionally a single
worker: session state and the global command execution lock are in memory.

## WebSocket protocol

Connect to `/ws` with a matching browser Origin. Within 10 seconds send:

```json
{"action":"authenticate","token":"your-secret-token"}
```

The server replies with `authenticated` including `session_id` and `model`.
Then send the requested protocol messages:

```json
{"action":"chat","text":"Check memory usage"}
{"action":"approval_decision","id":"approval-id","approved":true}
```

Server events: `thinking {status}`, `command_executing {command}`,
`command_output {command, exit_code, stdout, stderr}`, `ask_approval {id, command}`,
`command_blocked {command, reason}`, and `agent_response {content}`.

Additional events: `command_output_chunk {command, stream, data}` for streaming,
`approval_resolved {id, approved}`, `error {message}`, and `turn_complete`.
Approval cards include `reason` and `expires_in`; final outputs include
`timed_out` and `truncated`. Responses may contain Markdown; the dashboard renders
all provider and command content as literal text for XSS safety.

One request runs per socket, at most eight sockets are admitted, and execution
is globally serialized. Approvals expire after 180 seconds, cannot be reused or
resolved from another session, and are cancelled on disconnect. Rejections stop
the turn rather than letting the model find a different way to perform the action.
Each request has a ten-command/ten-round budget. Provider calls have a 60-second
request timeout with one retry. Frames and per-session message rate are bounded.
For Internet-facing deployments add proxy connection/authentication rate limits.

Commands use null stdin and `DEBIAN_FRONTEND=noninteractive`, run for at most
120 seconds, and stream up to 64 KiB per output stream while continuing to drain
excess output. Timeouts/disconnects kill the process group and reap its leader.
Trusted binaries are resolved from system directories. The generated, quoted argv
is executed by a noninteractive Bash without loading profiles or `BASH_ENV`.

## Verification and maintenance

```bash
.venv/bin/python -m pip install --only-binary=:all: -r requirements-dev.txt
.venv/bin/python -m unittest discover -v
.venv/bin/python -m pip check
bash -n setup.sh
```

Tests cover policy bypass attempts, authentication/origin validation, approval
isolation/replay/rejection/expiry, provider failure, streamed stdout/stderr, output
floods, EOF stdin, environment isolation, timeouts and cancellation. They use a
fake LLM; no paid API calls or mutating server commands are used.

After editing canonical files, regenerate the self-contained installer with
`python tools/build_installer.py`. Dependencies use flexible minimum versions;
Pydantic's 3.14 support starts at 2.12, and modern FastAPI/Uvicorn/websockets builds
are required. Standard Uvicorn uses asyncio/h11, with no `uvloop`/`httptools` extras.
Wheels may not exist for every CPU/OS combination; a wheel-only install fails
clearly rather than silently compiling C/Rust dependencies. Future Python versions
must be tested as dependency support becomes available.

Compatibility references:
- https://pydantic.dev/articles/pydantic-v2-12-release
- https://fastapi.tiangolo.com/release-notes/#01183
- https://www.uvicorn.org/release-notes/
- https://websockets.readthedocs.io/en/stable/project/changelog.html
- https://developers.openai.com/api/docs/guides/function-calling

Tailwind is loaded via CDN as requested. The dashboard also includes its core CSS
so its layout remains usable offline. For a stricter deployment, vendor your CSS
and JavaScript and tighten the CSP instead of relying on an external CDN script.
