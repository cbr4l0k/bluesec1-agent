import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from openai import AsyncOpenAI

from bluesec1_agent.llm import (
    OpenAIStructuredStepClient,
    parse_next_step_payload,
)
from bluesec1_agent.models import NextStep, ToolCall, build_step_response_format

CATALOG = json.loads((Path(__file__).parent / "fixtures" / "available_tools.json").read_text())
RESPONSE_FORMAT = build_step_response_format(CATALOG)


class FakeCompletions:
    """Queue-backed fake for the OpenAI chat completion endpoint."""

    def __init__(self, contents: list[str]) -> None:
        """Store response content and request audit state."""
        self.contents = list(contents)
        self.requests: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        """Return the next queued assistant message."""
        self.requests.append(kwargs)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=self.contents.pop(0),
                        refusal=None,
                    )
                )
            ],
            usage=SimpleNamespace(total_tokens=17),
        )


class FakeOpenAI:
    """Minimal object graph required by `OpenAIStructuredStepClient`."""

    def __init__(self, contents: list[str]) -> None:
        """Expose fake chat completions."""
        self.completions = FakeCompletions(contents)
        self.chat = SimpleNamespace(completions=self.completions)


def valid_process_step() -> NextStep:
    """Build one valid non-terminal graph navigation step."""
    return NextStep(
        current_state="The trigger entity needs its relations.",
        plan_remaining_steps_brief=["Read the trigger entity."],
        task_completed=False,
        functions=[ToolCall(tool="get_entity", entity_id="entity-1", reasoning="Read it.")],
    )


def test_structured_client_repairs_malformed_response() -> None:
    """Malformed provider output should be retried outside the main history."""
    fake_openai = FakeOpenAI(["not-json", valid_process_step().model_dump_json()])
    client = OpenAIStructuredStepClient(
        base_url="https://llm.example/v1",
        api_key="secret",
        model="test-model",
        timeout_seconds=10.0,
        max_completion_tokens=1000,
        max_retries=3,
        client=cast(AsyncOpenAI, fake_openai),
    )
    original_messages = [{"role": "system", "content": "Investigate."}]

    step = asyncio.run(client.next_step(original_messages, RESPONSE_FORMAT))

    assert step.functions[0].tool == "get_entity"
    assert len(fake_openai.completions.requests) == 2
    first_messages = fake_openai.completions.requests[0]["messages"]
    assert "Never use top-level `action`" in first_messages[0]["content"]
    assert "advertised_tool" in first_messages[0]["content"]
    repaired_messages = fake_openai.completions.requests[1]["messages"]
    assert repaired_messages[-1]["role"] == "user"
    assert original_messages == [{"role": "system", "content": "Investigate."}]


def test_parser_rejects_inconsistent_completion_flag() -> None:
    """A non-terminal function cannot claim that the investigation is complete."""
    payload = valid_process_step().model_copy(update={"task_completed": True}).model_dump_json()

    with pytest.raises(ValueError, match="task_completed"):
        parse_next_step_payload(payload)


def _walk(node: Any) -> list[dict[str, Any]]:
    """Return every object node in a JSON Schema."""
    if isinstance(node, list):
        return [found for child in node for found in _walk(child)]
    if not isinstance(node, dict):
        return []
    return [node, *(found for child in node.values() for found in _walk(child))]


def test_response_schema_from_live_catalog_is_strict() -> None:
    """The real runtime catalog should become a strict schema with nullable optionals."""
    schema = RESPONSE_FORMAT["json_schema"]["schema"]
    variants = schema["properties"]["functions"]["items"]["anyOf"]

    assert {variant["properties"]["tool"]["enum"][0] for variant in variants} == {
        tool["name"] for tool in CATALOG
    }
    for node in _walk(schema):
        if isinstance(node.get("properties"), dict):
            assert set(node["required"]) == set(node["properties"])
            assert node["additionalProperties"] is False
        if "$ref" in node:
            assert list(node) == ["$ref"]
    for keyword in ("default", "discriminator", "oneOf", "const"):
        assert f'"{keyword}"' not in json.dumps(schema)
    search = next(v for v in variants if v["properties"]["tool"]["enum"] == ["search"])
    assert {"type": "null"} in search["properties"]["page_id"]["anyOf"]
    assert "reasoning" in search["required"]


def test_tool_call_arguments_drop_null_placeholders() -> None:
    """Nullable placeholders for omitted optional fields must not reach the runtime."""
    call = ToolCall(tool="search", query="svchost", reasoning="r", page_id=None, scope=None)

    assert call.arguments == {"query": "svchost", "reasoning": "r"}


def test_parser_rejects_finish_batched_with_other_calls() -> None:
    """finish_investigation must be the only call in its step."""
    step = valid_process_step()
    payload = step.model_copy(
        update={
            "task_completed": True,
            "functions": [*step.functions, ToolCall(tool="finish_investigation", submission={})],
        }
    ).model_dump_json()

    with pytest.raises(ValueError, match="only call"):
        parse_next_step_payload(payload)
