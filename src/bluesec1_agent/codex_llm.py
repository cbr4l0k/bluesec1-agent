import asyncio
import json
import shutil
import tempfile
import time
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from loguru import logger

from bluesec1_agent.llm import (
    REPAIR_INSTRUCTION,
    STRUCTURED_OUTPUT_INSTRUCTION,
    NextStepRequestError,
    parse_next_step_payload,
    render_json,
)
from bluesec1_agent.models import NextStep

CODEX_INSTRUCTION = """
You are the reasoning step of an external investigation loop, not a coding agent.
Do not run commands, read files, or browse. Answer only from the conversation below.
""".strip()


class CodexStructuredStepClient:
    """Structured step generator backed by `codex exec` and the user's ChatGPT login."""

    def __init__(
        self,
        *,
        model: str | None,
        reasoning_effort: str | None,
        timeout_seconds: float,
        max_retries: int,
        ignore_user_config: bool = True,
        executable: str = "codex",
    ) -> None:
        """Prepare an isolated, empty working directory and the output schema.

        Args:
            model: Codex model override; `None` keeps the Codex config default.
            reasoning_effort: Codex `model_reasoning_effort` override.
            timeout_seconds: Timeout for one `codex exec` invocation.
            max_retries: Maximum schema-generation attempts per step.
            ignore_user_config: Skip `~/.codex/config.toml` (MCP servers, plugins, profiles)
                so each call starts fast; the ChatGPT login is still used.
            executable: Codex CLI executable name or path.
        """
        self.model = model
        self.reasoning_effort = reasoning_effort
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.ignore_user_config = ignore_user_config
        self.executable = executable
        self._workdir = Path(tempfile.mkdtemp(prefix="bluesec1-codex-"))
        self._schema_path = self._workdir / "next_step.schema.json"

    async def __aenter__(self) -> Self:
        """Enter the async client context."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Remove the temporary working directory."""
        await self.aclose()

    async def aclose(self) -> None:
        """Remove the temporary working directory."""
        shutil.rmtree(self._workdir, ignore_errors=True)

    async def next_step(
        self, messages: list[dict[str, Any]], response_format: dict[str, Any]
    ) -> NextStep:
        """Return one valid `NextStep`, repairing malformed replies when possible.

        Args:
            messages: Current investigation conversation.
            response_format: Strict `NextStep` schema built from the task's tool catalog.

        Returns:
            A locally validated structured investigation step.

        Raises:
            NextStepRequestError: If Codex fails or every reply violates the schema.
        """
        self._schema_path.write_text(
            json.dumps(response_format["json_schema"]["schema"]), encoding="utf-8"
        )
        prompt = self._render_prompt(messages)
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            started_at = time.perf_counter()
            raw_content = await self._exec(prompt)
            latency_ms = int((time.perf_counter() - started_at) * 1000)
            try:
                step = parse_next_step_payload(raw_content)
            except ValueError as exc:
                last_error = exc
                logger.warning(
                    "Invalid Codex response on attempt {}/{}: {}",
                    attempt,
                    self.max_retries,
                    raw_content[:2000] or str(exc),
                )
                prompt = (
                    f"{prompt}\n\nYour previous reply was:\n{raw_content or '<empty>'}\n\n"
                    f"{REPAIR_INSTRUCTION}"
                )
                continue

            tools = ", ".join(call.tool for call in step.functions)
            logger.info("Codex selected {} in {} ms.", tools, latency_ms)
            return step

        message = str(last_error or ValueError("Unable to parse Codex response."))
        raise NextStepRequestError(message) from last_error

    @staticmethod
    def _render_prompt(messages: list[dict[str, Any]]) -> str:
        """Flatten the chat history into one stateless Codex prompt."""
        system = "\n\n".join(
            str(message.get("content", "")) for message in messages if message["role"] == "system"
        )
        transcript = [message for message in messages if message["role"] != "system"]
        return (
            f"{CODEX_INSTRUCTION}\n\n{system}\n\n{STRUCTURED_OUTPUT_INSTRUCTION}\n\n"
            f"Conversation so far, oldest first:\n{render_json(transcript)}\n\n"
            "Return the next NextStep JSON object."
        )

    async def _exec(self, prompt: str) -> str:
        """Run one ephemeral, read-only `codex exec` and return its final message."""
        output_path = self._workdir / "last_message.txt"
        output_path.unlink(missing_ok=True)
        command = [
            self.executable,
            "exec",
            "--skip-git-repo-check",
            "--ephemeral",
            "--ignore-rules",
            "--sandbox",
            "read-only",
            "--cd",
            str(self._workdir),
            "--output-schema",
            str(self._schema_path),
            "--output-last-message",
            str(output_path),
        ]
        if self.ignore_user_config:
            command.append("--ignore-user-config")
        if self.model:
            command += ["--model", self.model]
        if self.reasoning_effort:
            command += ["--config", f'model_reasoning_effort="{self.reasoning_effort}"']
        command.append("-")

        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(
                process.communicate(prompt.encode("utf-8")), timeout=self.timeout_seconds
            )
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise NextStepRequestError(
                f"codex exec timed out after {self.timeout_seconds:.0f}s"
            ) from exc
        if process.returncode != 0:
            tail = stderr.decode("utf-8", errors="replace")[-2000:]
            raise NextStepRequestError(f"codex exec exited with {process.returncode}: {tail}")
        if not output_path.exists():
            return ""
        return output_path.read_text(encoding="utf-8")
