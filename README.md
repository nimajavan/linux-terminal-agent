# Sentinel â€” Ubuntu AI SysAdmin Agent

A self-hosted FastAPI service and responsive dark dashboard. The LLM proposes
commands, and the backend executes them directly as root without filtering or approval prompts.
No Node.js build. Python 3.14+ on Linux is required for production execution.

## Start on Ubuntu

Install Python 3.14+ and its venv package from a trusted source appropriate for
your Ubuntu release. The installer does not replace Ubuntu's system Python.

```bash
bash setup.sh "$HOME/server-agent"
cd "$HOME/server-agent"
nano .env  # enter your provider key, base URL and model
sudo .venv/bin/python main.py
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

For Windows Ollama with Ubuntu WSL, see the [Persian setup and troubleshooting
guide](docs/OLLAMA.fa.md). A safe configuration template is included in
`.env.ollama.example`; it contains no real credentials or private host addresses.

- OpenAI: `LLM_BASE_URL=https://api.openai.com/v1`; use an enabled tool-capable model.
- DeepSeek: set its OpenAI-compatible base URL and a tool-capable model in `.env`.
- Ollama: `LLM_BASE_URL=http://127.0.0.1:11434/v1`, `LLM_API_KEY=ollama`, and an
  installed model that supports tool calling.
- Other compatible endpoints must support Chat Completions, `tools`, `tool_choice`
  and `max_tokens`. Provider compatibility depends on the selected model.

For example, if `qwen3-coder:30b` is already installed, change only these entries
in your active environment file and preserve your generated dashboard token:

```dotenv
LLM_API_KEY=ollama
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_MODEL=qwen3-coder:30b
```

The `/v1` suffix is required for Ollama's OpenAI-compatible API. `127.0.0.1`
refers to the machine/network environment running the backend, not the browser.
Windows Ollama is reachable through that address from WSL in mirrored networking
mode; it is not normally reachable through WSL's loopback in NAT mode. Verify
the endpoint from Ubuntu with `curl --max-time 10 http://127.0.0.1:11434/v1/models`.
Choose a locally installed model with tool support that fits your hardware.

If startup reports an invalid `AGENT_WEB_TOKEN`, fix the `.env` beside the
`main.py` you are actually running. A separate checkout or installer output has
its own environment file. The systemd deployment instead uses
`/etc/server-agent.env`. Ollama's dummy API key does not replace the dashboard
token; both settings are required. See the Persian guide for a token repair
command that preserves a valid existing token.

Provider keys remain on the backend. Tokens stay in page memory, are cleared from
the input after connection, and are never put in URLs or localStorage. Chat history
is session-local and disappears on disconnect. Raw recent command output is sent
to the configured LLM: self-hosted execution does not imply local inference.
Do not ask the agent to read credentials or other sensitive files.

## Full root command execution

Authenticated sessions execute arbitrary Bash as root, without a command
allowlist, protected-path filters, hard blocks, or approval prompts. Pipelines,
redirections, substitutions, scripts and installed programs are supported.
The dashboard token therefore grants full root command execution on this host.
The server must be started as root; it never silently falls back to an ordinary
user. The supplied systemd unit uses `User=root` and `Group=root` and no longer
applies filesystem, capability, device, network-family or resource restrictions.

Authentication, browser origin validation, connection handling, streaming,
the 120-second command timeout, output bounds and per-turn budgets are unchanged.
Commands are noninteractive: stdin is closed and there is no PTY. Interactive
editors cannot be operated through this chat UI. Each call starts a fresh Bash
process; use a single command containing `cd ... && ...` when needed. Detached
descendants are cleaned up after execution; use systemd for persistent services.
Normal OS constraints still apply (for example, missing programs or WSL features
not supported by the underlying kernel).

Qwen3-Coder sometimes returns its tool protocol in plain text when it omits the
opening `<tool_call>` tag. The backend normalizes a complete, trailing
`run_bash_command` block into a structured tool call before execution. Existing
structured calls take precedence; fenced examples and other models are not
interpreted. Malformed blocks report an error instead of inventing a command.

## Install the boot-time service

Run these commands as an administrator after configuring and testing the app.
The following assumes a fresh `/opt/server-agent` deployment; do not overwrite
an existing installation without a backup. Code and the venv are installed with root ownership.

```bash
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
```

Server events: `thinking {status}`, `command_executing {command}`,
`command_output {command, exit_code, stdout, stderr}`, and `agent_response {content}`.

Additional events: `command_output_chunk {command, stream, data}` for streaming,
`error {message}`, and `turn_complete`. Approval requests are no longer emitted;
legacy `approval_decision` messages return an error. Final outputs include
`timed_out` and `truncated`. Responses may contain Markdown; the dashboard renders
all provider and command content as literal text for XSS safety.

One request runs per socket, at most eight sockets are admitted, and execution
is globally serialized. Active execution is cancelled on disconnect.
Each request has a ten-command/ten-round budget. Provider calls have a 60-second
request timeout with one retry. Frames and per-session message rate are bounded.
For Internet-facing deployments add proxy connection/authentication rate limits.

Commands use null stdin and `DEBIAN_FRONTEND=noninteractive`, run for at most
120 seconds, and stream up to 64 KiB per output stream while continuing to drain
excess output. Timeouts/disconnects kill the process group and reap its leader.
The exact tool command is executed by noninteractive Bash without loading profiles
or `BASH_ENV`. There is no command rewriting or executable-path allowlist.

## Verification and maintenance

```bash
.venv/bin/python -m pip install --only-binary=:all: -r requirements-dev.txt
sudo .venv/bin/python -m unittest discover -v
.venv/bin/python -m pip check
bash -n setup.sh
```

Tests cover authentication/origin validation, direct execution without approvals,
Qwen tool-call normalization, provider failure, streamed stdout/stderr, output
floods, EOF stdin, environment isolation, timeouts and cancellation. Root runner
tests inspect identity and operate only on disposable temporary files; destructive
command examples use mocks. Run the suite as root to include Linux runner tests.
No paid API calls or actual destructive server commands are used.

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
