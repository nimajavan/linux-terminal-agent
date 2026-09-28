"""Regenerate the standalone setup.sh from the canonical project files."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ["requirements.txt", "requirements-dev.txt", ".env.example", ".env.ollama.example", "main.py", "static/index.html", "server-agent.service", "README.md", "docs/OLLAMA.fa.md", "tests/test_agent.py", "tests/__init__.py"]
HEADER = r'''#!/usr/bin/env bash
# Standalone installer: no repository checkout or Node tooling required.
set -euo pipefail
umask 077
TARGET="${1:-$PWD/server-agent}"
PYTHON="${PYTHON:-python3.14}"
if [[ "$(uname -s)" != Linux ]]; then
  echo "This installer requires Linux." >&2; exit 1
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Install Python 3.14+ with venv support, then set PYTHON=/path/to/python3.14." >&2; exit 1
fi
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 14), "Python 3.14+ required"'
mkdir -p -- "$TARGET"
TARGET="$(cd -- "$TARGET" && pwd -P)"
# Never overwrite an existing project or secrets; choose a fresh directory.
if [[ -n "$(find "$TARGET" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "Target must be empty: $TARGET" >&2; exit 1
fi
mkdir -p -- "$TARGET/static" "$TARGET/tests" "$TARGET/docs"
'''
FOOTER = r'''
"$PYTHON" - "$TARGET/.env" <<'PY_TOKEN'
from pathlib import Path
import secrets
import sys
path = Path(sys.argv[1])
value = path.read_text()
value = value.replace("CHANGE_ME_TO_A_RANDOM_TOKEN_OF_AT_LEAST_32_CHARACTERS", secrets.token_urlsafe(48))
path.write_text(value)
path.chmod(0o600)
PY_TOKEN
"$PYTHON" -m venv "$TARGET/.venv"
"$TARGET/.venv/bin/python" -m pip install --upgrade pip
# Wheel-only install avoids unexpected C/Rust builds on new Python versions.
"$TARGET/.venv/bin/python" -m pip install --only-binary=:all: -r "$TARGET/requirements.txt"
"$TARGET/.venv/bin/python" -m pip check
echo
printf 'Project created at: %s\n' "$TARGET"
printf '1. Edit %s/.env and set LLM_API_KEY, LLM_BASE_URL, and LLM_MODEL.\n' "$TARGET"
printf '2. Copy AGENT_WEB_TOKEN from that file into the dashboard.\n'
printf '3. Start: cd %q && .venv/bin/python main.py\n' "$TARGET"
printf '4. Open http://127.0.0.1:8000 (or use the SSH tunnel in README.md).\n'
printf '5. Optional tests: install requirements-dev.txt, then run .venv/bin/python -m unittest discover -v\n'
printf 'For boot-time installation see %s/README.md. No service was enabled automatically.\n' "$TARGET"
'''


def build():
    chunks = [HEADER]
    for i, name in enumerate(FILES):
        delimiter = f"SENTINEL_FILE_{i}_END"
        value = (ROOT / name).read_text(encoding="utf-8")
        assert delimiter not in value
        target_name = ".env" if name == ".env.example" else name
        chunks.append(f'cat > "$TARGET/{target_name}" <<\'{delimiter}\'\n{value.rstrip()}\n{delimiter}\n')
    chunks.append(FOOTER)
    (ROOT / "setup.sh").write_text("".join(chunks), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    build()
