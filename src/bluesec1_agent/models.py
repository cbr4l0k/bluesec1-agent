import copy
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

IRArtifactKind = Literal[
    "host_to_isolate",
    "identity_to_rotate",
    "persistence_to_remove",
    "cleanup_to_verify",
    "file_to_delete",
    "network_block",
    "mailbox_action",
    "other",
    "process_observed",
    "registry_observed",
    "file_observed",
    "mount_observed",
    "lnk_observed",
    "ticket_observed",
    "identity_observed",
    "artifact_observed",
]

FINISH_TOOL = "finish_investigation"
ASSESS_TOOL = "assess_situation"

ASSESS_SITUATION_SPEC: dict[str, Any] = {
    "name": ASSESS_TOOL,
    "description": (
        "Local decision support, answered without a runtime tool call: run the Jev decision "
        "tree over the evidence gathered so far."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "hypothesis": {
                "type": "string",
                "minLength": 1,
                "description": "Your current working hypothesis about the alert.",
            }
        },
        "required": ["hypothesis"],
    },
}


class StrictModel(BaseModel):
    """Base model that rejects fields outside the public structured contract."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ToolCall(BaseModel):
    """One tool call: the tool name plus that tool's arguments as sibling fields.

    Arguments are validated by the runtime against its own catalog, so they are kept
    as extra fields here.
    """

    model_config = ConfigDict(extra="allow")

    tool: str = Field(min_length=1)

    @property
    def arguments(self) -> dict[str, Any]:
        """Return the tool arguments with null placeholders removed."""
        return _drop_nulls(self.model_extra or {})


MAX_CALLS_PER_STEP = 4


class NextStep(StrictModel):
    """One validated reasoning-and-action turn produced by the LLM."""

    current_state: str
    plan_remaining_steps_brief: list[str] = Field(min_length=1, max_length=5)
    task_completed: bool
    functions: list[ToolCall] = Field(
        min_length=1,
        max_length=MAX_CALLS_PER_STEP,
        description="Independent tool calls executed in order.",
    )


def build_step_response_format(tool_specs: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a strict `NextStep` response format from the runtime tool catalog.

    Args:
        tool_specs: Tool specifications advertised by the task, plus any local tools.

    Returns:
        OpenAI-style `json_schema` response format.
    """
    defs: dict[str, Any] = {}
    variants: list[dict[str, Any]] = []
    for spec in tool_specs:
        parameters = copy.deepcopy(spec.get("parameters") or {"type": "object"})
        for name, definition in parameters.pop("$defs", {}).items():
            if name in defs and defs[name] != definition:
                raise ValueError(f"Conflicting $defs entry {name!r} in the tool catalog.")
            defs[name] = definition
        properties = parameters.get("properties", {})
        variants.append(
            {
                "type": "object",
                "description": spec.get("description", ""),
                "properties": {"tool": {"type": "string", "enum": [spec["name"]]}, **properties},
                "required": ["tool", *parameters.get("required", [])],
                "additionalProperties": False,
            }
        )

    schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "current_state": {"type": "string"},
            "plan_remaining_steps_brief": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
                "maxItems": 5,
            },
            "task_completed": {"type": "boolean"},
            "functions": {
                "type": "array",
                "items": {"anyOf": variants},
                "minItems": 1,
                "maxItems": MAX_CALLS_PER_STEP,
            },
        },
        "required": ["current_state", "plan_remaining_steps_brief", "task_completed", "functions"],
        "additionalProperties": False,
    }
    if defs:
        schema["$defs"] = defs
    _normalize_strict_schema(schema)
    return {
        "type": "json_schema",
        "json_schema": {"name": "bluesec1_next_step", "strict": True, "schema": schema},
    }


def _normalize_strict_schema(node: Any) -> None:
    """Rewrite catalog JSON Schema into the subset strict structured outputs accept.

    Every property becomes required; optional ones become nullable instead. `oneOf`
    becomes `anyOf`, `const` becomes a one-value `enum`, `$ref` loses sibling keywords,
    and defaults and discriminators are dropped.

    Args:
        node: Mutable JSON Schema node or collection.
    """
    if isinstance(node, list):
        for record in node:
            _normalize_strict_schema(record)
        return
    if not isinstance(node, dict):
        return

    if "$ref" in node:
        for keyword in [key for key in node if key != "$ref"]:
            del node[keyword]
        return
    node.pop("default", None)
    node.pop("discriminator", None)
    if "oneOf" in node:
        node["anyOf"] = node.pop("oneOf")
    if "const" in node:
        node["enum"] = [node.pop("const")]
    properties = node.get("properties")
    if isinstance(properties, dict):
        required = set(node.get("required", []))
        for name, child in properties.items():
            if name not in required and not _allows_null(child):
                properties[name] = {"anyOf": [child, {"type": "null"}]}
        node["additionalProperties"] = False
        node["required"] = list(properties)
    for value in node.values():
        _normalize_strict_schema(value)


def _allows_null(schema: Any) -> bool:
    """Return whether a schema node already accepts `null`."""
    if not isinstance(schema, dict):
        return False
    if schema.get("type") == "null":
        return True
    variants = schema.get("anyOf") or schema.get("oneOf") or []
    return any(_allows_null(variant) for variant in variants)


def _drop_nulls(value: Any) -> Any:
    """Remove `None` object members recursively; strict schemas use them for omitted fields."""
    if isinstance(value, dict):
        return {key: _drop_nulls(child) for key, child in value.items() if child is not None}
    if isinstance(value, list):
        return [_drop_nulls(child) for child in value]
    return value
