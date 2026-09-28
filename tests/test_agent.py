import asyncio
from pathlib import Path
import json
import os
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from openai.types.chat import ChatCompletionMessage
from starlette.websockets import WebSocketDisconnect

import main


class PolicyTests(unittest.TestCase):
    def test_read_only_examples(self):
        for command in ["ls -la /tmp", "cat /etc/os-release", "grep error /var/log/example.log", "systemctl status nginx --no-pager", "free -m", "uptime", "ip a", "ip route show", "ss -tulpn", "journalctl -u nginx -n 100 --no-pager"]:
            with self.subTest(command=command):
                self.assertEqual(main.triage(command).level, "safe")

    def test_mutations_require_approval(self):
        for command in ["rm /tmp/example", "reboot", "shutdown -h now", "kill 1234", "systemctl stop nginx", "systemctl restart nginx", "apt remove -y nginx", "apt-get purge --yes nginx", "ufw --force enable", "iptables -F", "ss -K", "ss --kill"]:
            with self.subTest(command=command):
                self.assertEqual(main.triage(command).level, "approval")

    def test_catastrophic_and_bypasses_blocked(self):
        commands = ["rm -rf /", "rm -fr '/etc'", "/bin/rm -rf /tmp/..", "r'm' -rf /", "rm --no-preserve-root /", "rm --target-directory=/ tmp", "chmod -R 777 /", "chmod 777 /etc/passwd", "dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sdb", ":(){ :|:& };:", "bash -c 'rm -rf /'", "sudo rm -rf /", "env rm -rf /", "python3 -c pass", "ls; reboot", "cat $(whoami)", "ls | cat", "ls > /tmp/out", "ls\nreboot", "ls &", "cat `id`", "rm /tmp/*", "ls \\x", "nano /tmp/x", "apt remove nginx", "apt-get -o APT::Update::Pre-Invoke=x update", "apt install -y ./evil.deb", "systemctl edit nginx", "journalctl --vacuum-time=1s", "ip link set lo down", "ip -batch /tmp/script", "ss --ki", "ss -D /tmp/out", "ss --diag=/tmp/out", "iptables -M /tmp/script -L", "cat /proc/self/environ"]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(main.triage(command).level, "blocked")

    @unittest.skipUnless(sys.platform == "linux", "Linux path semantics")
    def test_symlink_to_root_is_blocked(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "root-link"
            path.symlink_to("/", target_is_directory=True)
            self.assertEqual(main.triage(f"rm -rf {path}").level, "blocked")

    def test_secret_file_is_blocked(self):
        self.assertEqual(main.triage(f"cat '{main.ROOT / '.env'}'").level, "blocked")


def settings():
    return main.Settings("x" * 48, "dummy", "http://127.0.0.1:11434/v1", "test-model")


class FakeProvider:
    def __init__(self, messages):
        self.messages = list(messages)
        self.requests = []
        self.chat = SimpleNamespace(completions=self)

    async def create(self, **kwargs):
        self.requests.append(kwargs)
        value = self.messages.pop(0)
        if isinstance(value, Exception):
            raise value
        return SimpleNamespace(choices=[SimpleNamespace(message=ChatCompletionMessage.model_validate(value))])


def tool(command):
    return {"role": "assistant", "content": None, "tool_calls": [{"id": "call_test", "type": "function", "function": {"name": "run_bash_command", "arguments": json.dumps({"command": command})}}]}


class WebSocketTests(unittest.TestCase):
    def connect(self, client):
        return client.websocket_connect("/ws", headers={"origin": "http://testserver"})

    def authenticate(self, ws):
        ws.send_json({"action": "authenticate", "token": "x" * 48})
        self.assertEqual(ws.receive_json()["type"], "authenticated")

    def test_auth_origin_and_http(self):
        with TestClient(main.create_app(settings(), FakeProvider([]))) as client:
            page = client.get("/")
            self.assertEqual(page.status_code, 200)
            self.assertEqual(page.headers["x-frame-options"], "DENY")
            self.assertEqual(client.get("/.env").status_code, 404)
            self.assertEqual(client.get("/healthz").json(), {"status": "ok"})
            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect("/ws", headers={"origin": "https://evil.example"}):
                    pass
            for auth in [{"action": "authenticate", "token": "bad"}, [], {"action": "authenticate", "token": "é"}]:
                with self.subTest(auth=auth), self.connect(client) as ws:
                    ws.send_json(auth)
                    with self.assertRaises(WebSocketDisconnect):
                        ws.receive_json()

    def test_plain_reply_and_validation(self):
        provider = FakeProvider([{"role": "assistant", "content": "Ready."}])
        with TestClient(main.create_app(settings(), provider)) as client, self.connect(client) as ws:
            self.authenticate(ws)
            for data in [[], {"action": "chat", "text": " "}, {"action": "approval_decision", "id": "x", "approved": "true"}]:
                ws.send_json(data)
                self.assertEqual(ws.receive_json()["type"], "error")
            ws.send_json({"action": "chat", "text": "Hello"})
            self.assertEqual(ws.receive_json()["type"], "thinking")
            self.assertEqual(ws.receive_json()["content"], "Ready.")
            self.assertEqual(ws.receive_json()["type"], "turn_complete")

    def test_reject_stops_without_execution(self):
        with patch.object(main, "execute", new_callable=AsyncMock) as execute:
            with TestClient(main.create_app(settings(), FakeProvider([tool("reboot")]))) as client, self.connect(client) as ws:
                self.authenticate(ws)
                ws.send_json({"action": "chat", "text": "Reboot"})
                self.assertEqual(ws.receive_json()["type"], "thinking")
                approval = ws.receive_json()
                self.assertEqual(approval["type"], "ask_approval")
                ws.send_json({"action": "approval_decision", "id": approval["id"], "approved": False})
                self.assertFalse(ws.receive_json()["approved"])
                self.assertEqual(ws.receive_json()["type"], "command_blocked")
                self.assertEqual(ws.receive_json()["type"], "agent_response")
                self.assertEqual(ws.receive_json()["type"], "turn_complete")
            execute.assert_not_called()

    def test_approve_runs_exact_command_once(self):
        async def fake_execute(argv, command, cwd, emit):
            result = {"type": "command_output", "command": command, "exit_code": 0, "stdout": "done", "stderr": ""}
            await emit(result)
            return result
        provider = FakeProvider([tool("systemctl restart nginx"), {"role": "assistant", "content": "Restart completed."}])
        with patch.object(main, "execute", side_effect=fake_execute) as execute:
            with TestClient(main.create_app(settings(), provider)) as client, self.connect(client) as ws:
                self.authenticate(ws)
                ws.send_json({"action": "chat", "text": "Restart nginx"})
                ws.receive_json()
                approval = ws.receive_json()
                ws.send_json({"action": "approval_decision", "id": approval["id"], "approved": True})
                types = []
                while True:
                    event = ws.receive_json()
                    types.append(event["type"])
                    if event["type"] == "turn_complete":
                        break
                self.assertIn("command_output", types)
                ws.send_json({"action": "approval_decision", "id": approval["id"], "approved": True})
                self.assertEqual(ws.receive_json()["type"], "error")
            self.assertEqual(execute.await_count, 1)
            self.assertEqual(execute.call_args.args[0], ("systemctl", "restart", "nginx"))

    def test_approval_is_session_scoped_and_disconnect_cancels(self):
        with patch.object(main, "execute", new_callable=AsyncMock) as execute:
            with TestClient(main.create_app(settings(), FakeProvider([tool("reboot")]))) as client:
                with self.connect(client) as first, self.connect(client) as second:
                    self.authenticate(first)
                    self.authenticate(second)
                    first.send_json({"action": "chat", "text": "reboot"})
                    first.receive_json()
                    approval = first.receive_json()
                    second.send_json({"action": "approval_decision", "id": approval["id"], "approved": True})
                    self.assertEqual(second.receive_json()["type"], "error")
                execute.assert_not_called()

    def test_hard_block_never_requests_approval(self):
        with patch.object(main, "execute", new_callable=AsyncMock) as execute:
            with TestClient(main.create_app(settings(), FakeProvider([tool("rm -rf /")]))) as client, self.connect(client) as ws:
                self.authenticate(ws)
                ws.send_json({"action": "chat", "text": "test"})
                self.assertEqual(ws.receive_json()["type"], "thinking")
                self.assertEqual(ws.receive_json()["type"], "command_blocked")
                self.assertEqual(ws.receive_json()["type"], "agent_response")
                self.assertEqual(ws.receive_json()["type"], "turn_complete")
            execute.assert_not_called()


class SessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_sdk_against_local_compatible_api(self):
        requests = []

        async def handler(reader, writer):
            try:
                header = await reader.readuntil(b"\r\n\r\n")
                size = next(int(line.split(b":", 1)[1]) for line in header.split(b"\r\n") if line.lower().startswith(b"content-length:"))
                request = json.loads(await reader.readexactly(size))
                requests.append(request)
                body = json.dumps({"id": "test_completion", "object": "chat.completion", "created": 1, "model": "test-model", "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "Local SDK request verified."}}]}).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        ws = AsyncMock()
        async with server, main.AsyncOpenAI(api_key="local-test-only", base_url=f"http://127.0.0.1:{port}/v1", timeout=5, max_retries=0) as client:
            session = main.Session(ws, settings(), client, asyncio.Lock())
            await session.chat("hello")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["tools"][0]["function"]["name"], "run_bash_command")
        self.assertEqual(session.history[-1]["content"], "Local SDK request verified.")

    async def test_approval_expires(self):
        session = main.Session(AsyncMock(), settings(), None, asyncio.Lock())
        with patch.object(main, "APPROVAL_TIMEOUT", 0.01):
            self.assertFalse(await session.approve("reboot", "sensitive"))
        self.assertFalse(session.pending)

    async def test_provider_error_does_not_expose_secret_or_corrupt_history(self):
        provider = FakeProvider([RuntimeError("secret-value")])
        ws = AsyncMock()
        session = main.Session(ws, settings(), provider, asyncio.Lock())
        await session.chat("test")
        self.assertEqual(len(session.history), 1)
        self.assertNotIn("secret-value", str(ws.send_json.call_args_list))
        self.assertEqual(ws.send_json.call_args.args[0]["type"], "turn_complete")


@unittest.skipUnless(sys.platform == "linux", "Linux execution tests")
class RunnerTests(unittest.IsolatedAsyncioTestCase):
    async def run_python(self, code, **kwargs):
        events = []
        async def emit(event):
            events.append(event)
        # Test the runner directly, bypassing policy; Python remains forbidden to the agent.
        result = await main.execute(("python3", "-c", code), "test fixture", Path(tempfile.gettempdir()), emit, **kwargs)
        return result, events

    async def test_streams_stderr_exit_and_eof(self):
        result, events = await self.run_python("import sys; print('out'); print('err', file=sys.stderr); assert sys.stdin.read() == ''; sys.exit(7)")
        self.assertEqual(result["exit_code"], 7)
        self.assertIn("out", result["stdout"])
        self.assertIn("err", result["stderr"])
        self.assertTrue(any(e["type"] == "command_output_chunk" for e in events))

    async def test_output_flood_is_bounded(self):
        result, _ = await self.run_python("import sys; sys.stdout.write('a'*200000); sys.stderr.write('b'*200000)")
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["stdout"]), main.OUTPUT_LIMIT)
        self.assertEqual(len(result["stderr"]), main.OUTPUT_LIMIT)

    async def test_timeout_includes_descendants_holding_pipe(self):
        result, _ = await self.run_python("import subprocess; subprocess.Popen(['sleep','30'])", timeout=0.1)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["exit_code"], 124)

    async def test_credentials_not_in_subprocess_environment(self):
        with patch.dict(os.environ, {"AGENT_WEB_TOKEN": "secret-value", "LLM_API_KEY": "secret-key", "BASH_ENV": "/tmp/evil"}):
            result, _ = await self.run_python("import os; print(dict(os.environ))")
        self.assertNotIn("secret-value", result["stdout"])
        self.assertNotIn("secret-key", result["stdout"])
        self.assertNotIn("BASH_ENV", result["stdout"])
        self.assertIn("noninteractive", result["stdout"])

    async def test_cancel_kills_running_process(self):
        started = asyncio.Event()
        pid = None
        async def emit(event):
            nonlocal pid
            if event["type"] == "command_output_chunk":
                pid = int(event["data"].strip())
                started.set()
        task = asyncio.create_task(main.execute(("python3", "-c", "import os,time; print(os.getpid(),flush=True); time.sleep(30)"), "fixture", Path("/tmp"), emit))
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


if __name__ == "__main__":
    unittest.main()
