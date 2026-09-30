import asyncio
from pathlib import Path
import json
import os
import shlex
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from openai.types.chat import ChatCompletionMessage
from starlette.websockets import WebSocketDisconnect

import main


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

    def test_commands_execute_without_approval_or_filtering(self):
        # Destructive command strings are only passed to an AsyncMock.
        for command in ["systemctl restart nginx", "rm -rf /", "python3 -c 'print(1)'", "printf hello | cat > /tmp/demo"]:
            with self.subTest(command=command):
                async def fake_execute(text, cwd, emit):
                    result = {"type": "command_output", "command": text, "exit_code": 0, "stdout": "simulated", "stderr": ""}
                    await emit(result)
                    return result
                provider = FakeProvider([tool(command), {"role": "assistant", "content": "Done."}])
                with patch.object(main, "execute", side_effect=fake_execute) as execute:
                    with TestClient(main.create_app(settings(), provider)) as client, self.connect(client) as ws:
                        self.authenticate(ws)
                        ws.send_json({"action": "chat", "text": "test request"})
                        events = []
                        while True:
                            event = ws.receive_json()
                            events.append(event["type"])
                            if event["type"] == "turn_complete":
                                break
                        self.assertIn("command_output", events)
                        self.assertNotIn("ask_approval", events)
                        self.assertNotIn("command_blocked", events)
                    execute.assert_awaited_once()
                    self.assertEqual(execute.call_args.args[0], command)


class SessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_qwen_text_call_is_executed_and_result_returned_to_model(self):
        provider = FakeProvider([
            {"role": "assistant", "content": "I'll check.\n<function=run_bash_command>\n<parameter=command>\nss -tuln\n</parameter>\n</function>\n</tool_call>"},
            {"role": "assistant", "content": "Observed listening ports."},
        ])
        config = main.Settings("x" * 48, "dummy", "http://localhost:11434/v1", "qwen3-coder:30b")
        ws = AsyncMock()
        session = main.Session(ws, config, provider, asyncio.Lock())
        with patch.object(main.Session, "run_command", new_callable=AsyncMock, return_value={"exit_code": 0, "stdout": "LISTEN 127.0.0.1:8000", "stderr": ""}) as execute:
            await session.chat("Which ports are listening?")
            execute.assert_awaited_once_with("ss -tuln")
        messages = provider.requests[-1]["messages"]
        self.assertEqual(messages[-1]["role"], "tool")
        self.assertEqual(messages[-1]["tool_call_id"], messages[-2]["tool_calls"][0]["id"])
        self.assertIn("LISTEN", messages[-1]["content"])
        self.assertEqual(session.history[-1]["content"], "Observed listening ports.")

    async def test_disconnect_cancels_active_execution(self):
        started = asyncio.Event()
        cancelled = asyncio.Event()
        async def slow_execute(command, cwd, emit):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
        session = main.Session(AsyncMock(), settings(), FakeProvider([tool("sleep 30")]), asyncio.Lock())
        with patch.object(main, "execute", side_effect=slow_execute):
            session.task = asyncio.create_task(session.chat("test"))
            await asyncio.wait_for(started.wait(), 2)
            await session.close()
        self.assertTrue(cancelled.is_set())

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

    async def test_provider_error_does_not_expose_secret_or_corrupt_history(self):
        provider = FakeProvider([RuntimeError("secret-value")])
        ws = AsyncMock()
        session = main.Session(ws, settings(), provider, asyncio.Lock())
        await session.chat("test")
        self.assertEqual(len(session.history), 1)
        self.assertNotIn("secret-value", str(ws.send_json.call_args_list))
        self.assertEqual(ws.send_json.call_args.args[0]["type"], "turn_complete")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Linux root execution tests")
class RunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_root_shell_supports_pipes_redirects_and_expansions(self):
        events = []
        async def emit(event):
            events.append(event)
        with tempfile.TemporaryDirectory() as folder:
            result = await main.execute("printf '%s\\n' \"$(id -u)\" | cat > result.txt; cat result.txt", Path(folder), emit)
            self.assertEqual(result["stdout"].strip(), "0")
            self.assertEqual((Path(folder) / "result.txt").read_text().strip(), "0")
            self.assertEqual(result["exit_code"], 0)

    async def test_non_root_does_not_silently_claim_full_access(self):
        with patch.object(os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "root"):
                await main.execute("id -u", Path("/tmp"), AsyncMock())

    async def run_python(self, code, **kwargs):
        events = []
        async def emit(event):
            events.append(event)
        result = await main.execute(shlex.join(["python3", "-c", code]), Path(tempfile.gettempdir()), emit, **kwargs)
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
        task = asyncio.create_task(main.execute(shlex.join(["python3", "-c", "import os,time; print(os.getpid(),flush=True); time.sleep(30)"]), Path("/tmp"), emit))
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)


class ToolNormalizationTests(unittest.TestCase):
    def test_structured_calls_take_precedence(self):
        message = ChatCompletionMessage.model_validate(tool("uptime"))
        self.assertIs(main.normalize_tool_message(message, "qwen3-coder:30b"), message)

    def test_fenced_examples_and_other_models_remain_text(self):
        for model, content in [
            ("other-model", "<function=run_bash_command>"),
            ("qwen3-coder:30b", "```xml\n<function=run_bash_command>\n```"),
        ]:
            message = ChatCompletionMessage(role="assistant", content=content)
            self.assertIs(main.normalize_tool_message(message, model), message)

    def test_malformed_or_multiple_calls_do_not_become_commands(self):
        for content in [
            "<function=run_bash_command><parameter=command>uptime",
            "<function=other><parameter=command>uptime</parameter></function>",
            "<function=run_bash_command><parameter=command></parameter></function>",
            "<function=run_bash_command><parameter=command>uptime</parameter></function><function=run_bash_command><parameter=command>id</parameter></function>",
        ]:
            with self.subTest(content=content), self.assertRaises(ValueError):
                main.normalize_tool_message(ChatCompletionMessage(role="assistant", content=content), "qwen3-coder:30b")


if __name__ == "__main__":
    unittest.main()
