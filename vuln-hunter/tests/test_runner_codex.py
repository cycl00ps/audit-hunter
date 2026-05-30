"""Codex runner adapter tests without live API calls."""

from __future__ import annotations

from pathlib import Path

import pytest

from audit import runner
from audit.runner import (
    _build_codex_command,
    _codex_sandbox_for,
    _run_codex_agent_once,
)


def test_codex_command_shape(tmp_path: Path) -> None:
    cwd = tmp_path / "work"
    repo = tmp_path / "repo"
    schema = tmp_path / "schema.json"
    last = tmp_path / "last.txt"

    cmd = _build_codex_command(
        codex_path="/bin/codex",
        model="gpt-test",
        reasoning_effort=None,
        cwd=cwd,
        add_dirs=[repo],
        output_last_message=last,
        sandbox="read-only",
    )

    assert cmd == [
        "/bin/codex",
        "exec",
        "--model",
        "gpt-test",
        "--json",
        "--output-last-message",
        str(last),
        "-C",
        str(cwd),
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--add-dir",
        str(repo),
        "-",
    ]


def test_codex_command_includes_reasoning_effort(tmp_path: Path) -> None:
    cmd = _build_codex_command(
        codex_path="/bin/codex",
        model="gpt-test",
        reasoning_effort="xhigh",
        cwd=tmp_path,
        add_dirs=None,
        output_last_message=tmp_path / "last.txt",
        sandbox="read-only",
    )

    assert cmd[0:6] == [
        "/bin/codex",
        "exec",
        "--model",
        "gpt-test",
        "-c",
        'model_reasoning_effort="xhigh"',
    ]


def test_codex_sandbox_mapping() -> None:
    assert _codex_sandbox_for(stage="hunt", allowed_tools=["Read", "Bash"]) == "workspace-write"
    assert _codex_sandbox_for(stage="trace", allowed_tools=["Read", "Bash"]) == "read-only"
    assert _codex_sandbox_for(stage="validate", allowed_tools=["Read"]) == "read-only"


@pytest.mark.asyncio
async def test_codex_agent_parses_last_message_and_writes_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    prompt = tmp_path / "prompt.md"
    schema = tmp_path / "schema.json"
    cwd = tmp_path / "repo"
    artifacts = tmp_path / "artifacts"
    prompt.write_text("# Role\nEmit JSON.")
    schema.write_text(
        '{"type":"object","required":["ok"],"properties":{"ok":{"type":"boolean"}},'
        '"additionalProperties":false}'
    )

    calls: list[dict] = []

    class FakeStdin:
        def __init__(self, cmd):
            self.cmd = cmd
            self.buf = bytearray()

        def write(self, data: bytes):
            self.buf.extend(data)

        async def drain(self):
            calls.append({"cmd": self.cmd, "stdin": self.buf.decode("utf-8")})

        def close(self):
            pass

        async def wait_closed(self):
            pass

    class FakeStream:
        def __init__(self, lines: list[bytes]):
            self.lines = lines

        async def readline(self):
            if self.lines:
                return self.lines.pop(0)
            return b""

    class FakeLoginProc:
        returncode = 0

        async def communicate(self, input: bytes):
            calls.append({"login_stdin_len": len(input)})
            return b"Successfully logged in\n", b""

    class FakeExecProc:
        returncode = 0

        def __init__(self, cmd):
            self.cmd = cmd
            self.stdin = FakeStdin(cmd)
            self.stdout = FakeStream([
                b'{"type":"complete","session_id":"s1",'
                b'"usage":{"input_tokens":3,"output_tokens":4}}\n',
            ])
            self.stderr = FakeStream([])
            last_path = Path(self.cmd[self.cmd.index("--output-last-message") + 1])
            last_path.write_text('{"ok": true}')

        async def wait(self):
            return self.returncode

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        if cmd[1:3] == ("login", "--with-api-key"):
            calls.append({"login_env_home": kwargs["env"]["CODEX_HOME"]})
            return FakeLoginProc()
        calls.append({
            "cmd": list(cmd),
            "cwd": kwargs["cwd"],
            "stdin_pipe": kwargs["stdin"],
            "env": kwargs["env"],
        })
        return FakeExecProc(list(cmd))

    monkeypatch.setattr(runner.shutil, "which", lambda name: "/bin/codex")
    monkeypatch.setattr(runner.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    result = await _run_codex_agent_once(
        stage="validate",
        prompt_file=prompt,
        user_input={"repo_path": str(cwd)},
        schema_file=schema,
        allowed_tools=["Read"],
        model="gpt-test",
        reasoning_effort="xhigh",
        cwd=cwd,
        add_dirs=[cwd],
        max_turns=3,
        permission_mode="acceptEdits",
        artifact_dir=artifacts,
        artifact_name="one",
        repair_attempts=0,
    )

    assert result.payload == {"ok": True}
    assert result.input_tokens == 3
    assert result.output_tokens == 4
    assert result.raw_result_message["provider"] == "codex"
    assert result.artifact_path.exists()
    assert calls[2]["cmd"][-1] == "-"
    assert 'model_reasoning_effort="xhigh"' in calls[2]["cmd"]
    assert "--output-schema" not in calls[2]["cmd"]
    assert "--ignore-user-config" in calls[2]["cmd"]
    assert calls[2]["env"]["CODEX_HOME"] == calls[0]["login_env_home"]
    assert "# User input" in calls[3]["stdin"]
    assert '"reasoning_effort": "xhigh"' in result.artifact_path.read_text()
