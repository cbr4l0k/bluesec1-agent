import json
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, ConfigDict, Field
from typesafe_sdk import TypeSafeError

from bluesec1_agent.llm import StructuredStepClient, render_json
from bluesec1_agent.models import (
    ASSESS_SITUATION_SPEC,
    ASSESS_TOOL,
    FINISH_TOOL,
    build_step_response_format,
)
from bluesec1_agent.triage import EvidenceLedger, TriageDecisionTree
from bluesec1_client import (
    RemoteBenchmarkClient,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)

SYSTEM_PROMPT = """
You are a pragmatic senior SOC analyst investigating one security alert.

Return exactly one JSON object matching the supplied NextStep schema on every turn.
Do not emit prose, markdown, XML tags, or extra keys outside that object.

The task observation contains `available_tools`, the authoritative catalog of
enabled tool calls and their argument schemas. Follow that catalog exactly.

Investigation rules:
- Treat the alert as an initial hypothesis, not proof that the activity is malicious.
- Use only tools advertised in the current task observation.
- Each step may batch up to 4 independent read calls (for example several get_entity or
  get_relation calls on ids you already hold). Batch only calls you would make anyway:
  every runtime call counts against the score. finish_investigation and assess_situation
  must be the only call in their step.
- Start from the entity ids named in the alert, then expand through their relations.
- Prefer following relations over searching again: an entity you already hold tells
  you where to go next.
- Search when you have a concrete string worth looking for and no edge leading to it.
- Do not repeat an identical unhelpful or failed call.
- Use only entity_id values actually returned by the alert or by a tool.
- Every runtime tool requires a short `reasoning` argument explaining the call.
- finish_investigation takes one `submission` object. For `malicious`, list the entities
  needing response or forensic reporting in `ir_artifacts`. For `benign`, cite
  `legitimacy_evidence`: entities or relations plus the exact property names that show
  the activity is legitimate.
- Submit only artifacts and evidence supported by tool results. Do not invent ids.
- Keep current_state evidence-focused and the remaining plan short.
- Set task_completed=true exactly when selecting finish_investigation.
- Finish before the investigation step budget is exhausted.
""".strip()

TRIAGE_PROMPT = """
Decision support:
- `assess_situation` runs a local decision tree over everything gathered so far. It does
  not cost a runtime tool call, but it is limited per task.
- Pass your current hypothesis. It returns signal probabilities, the branch taken
  (investigate, respond, prove_benign, decide_now), the most informative ids to expand
  next, and proposed ir_artifacts (malicious) or legitimacy_evidence (benign).
- Call it after the first few expansions and again before finish_investigation.
- Treat its output as evidence-weighted advice: verify proposed artifact ids exist in
  the evidence and override it when the evidence clearly says otherwise.
""".strip()


TRACE_DIR = Path("logs")
MAX_RESULT_CHARS = 6_000


def _trace(task_id: str, event: dict[str, Any]) -> None:
    """Append one event to the task's JSONL trace under `logs/`."""
    TRACE_DIR.mkdir(exist_ok=True)
    with (TRACE_DIR / f"trace-{task_id}.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")


class AgentRunResult(BaseModel):
    """Aggregate results returned by one remote benchmark run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    successful_tasks: int
    failed_tasks: int
    task_results: list[TaskResult] = Field(default_factory=list)


class SimpleSGRAgent:
    """Run a typed one-action-per-turn LLM investigation loop."""

    def __init__(
        self,
        llm: StructuredStepClient,
        *,
        max_steps: int = 100,
        triage: TriageDecisionTree | None = None,
        max_assessments: int = 4,
    ) -> None:
        """Store the LLM dependency and per-task step limit.

        Args:
            llm: Structured step generator used for every investigation turn.
            max_steps: Maximum total runtime tool calls allowed for one task.
            triage: Optional Jev decision tree served as the local `assess_situation` tool.
            max_assessments: Maximum `assess_situation` calls per task.

        Raises:
            ValueError: If the configured limit is not positive.
        """
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.llm = llm
        self.max_steps = max_steps
        self.triage = triage
        self.max_assessments = max_assessments if triage is not None else 0

    async def run(self, client: RemoteBenchmarkClient) -> AgentRunResult:
        """Consume the remote queue and aggregate authoritative task results.

        Args:
            client: Open remote benchmark client that owns the current run.

        Returns:
            Aggregate result for the newly created remote run.

        Raises:
            RuntimeError: If the client is not open.
        """
        remote_run = client.run
        if remote_run is None:
            raise RuntimeError("RemoteBenchmarkClient must be open before running the agent.")

        task_results: list[TaskResult] = []
        while (session := await client.start_task()) is not None:
            logger.info("Starting structured investigation for task {}.", session.task_id)
            try:
                task_result = await self._investigate(session)
            except Exception as exc:
                logger.error("Task {} failed in the agent: {}", session.task_id, exc)
                error_message = f"{type(exc).__name__}: {exc}"[:2_000]
                aborted_result = await session.abort_task(error_message=error_message)
                task_result = TaskResult.model_validate(aborted_result)
            task_results.append(task_result)

        successful_tasks = sum(
            result.completion_reason in {"terminated", "truncated"} for result in task_results
        )
        return AgentRunResult(
            run_id=remote_run.run_id,
            successful_tasks=successful_tasks,
            failed_tasks=len(task_results) - successful_tasks,
            task_results=task_results,
        )

    async def _investigate(self, session: RemoteBenchmarkSession) -> TaskResult:
        """Drive one leased task until its terminal investigation tool succeeds.

        Args:
            session: Active remote task session.

        Returns:
            Authoritative terminal task result returned by the server.

        Raises:
            ValueError: If the task observation has an invalid tool catalog.
            RuntimeError: If the agent exhausts its step budget.
        """
        observation = session.task.observation
        tool_specs = self._tool_specs(observation)
        _trace(session.task_id, {"event": "task", "observation": observation})
        available_tools = {
            specification["name"]
            for specification in tool_specs
            if isinstance(specification.get("name"), str)
        }
        if FINISH_TOOL not in available_tools:
            raise ValueError("The runtime did not advertise finish_investigation.")

        llm_tool_specs = [
            {
                "name": specification["name"],
                "description": specification.get("description", ""),
                "parameters": specification.get("parameters", {}),
            }
            for specification in tool_specs
        ]
        if self.triage is not None:
            llm_tool_specs.append(ASSESS_SITUATION_SPEC)
        response_format = build_step_response_format(llm_tool_specs)
        alert = {
            key: _decode_json_string(value)
            for key, value in observation.items()
            if key not in {"available_tools", "last_tool_result"}
        }
        ledger = EvidenceLedger(alert=alert)
        assessments_left = self.max_assessments
        runtime_calls = 0
        system_prompt = f"{SYSTEM_PROMPT}\n\n{TRIAGE_PROMPT}" if self.triage else SYSTEM_PROMPT

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": render_json(
                    {
                        "instruction": "Investigate this alert and submit the correct response.",
                        "alert": alert,
                        "available_tools": [
                            {"name": spec["name"], "description": spec["description"]}
                            for spec in llm_tool_specs
                        ],
                        "note": "Each tool's argument schema is enforced by the response format.",
                    }
                ),
            },
        ]

        for turn in range(1, self.max_steps + self.max_assessments + 1):
            if runtime_calls >= self.max_steps:
                break
            step = await self.llm.next_step(messages, response_format)
            calls = [
                (f"turn_{turn}_{index}", call.tool, call.arguments)
                for index, call in enumerate(step.functions, 1)
            ]
            messages.append(
                {
                    "role": "assistant",
                    "content": step.plan_remaining_steps_brief[0],
                    "tool_calls": [
                        {
                            "type": "function",
                            "id": call_id,
                            "function": {"name": tool_name, "arguments": render_json(arguments)},
                        }
                        for call_id, tool_name, arguments in calls
                    ],
                }
            )

            for call_id, tool_name, arguments in calls:
                if tool_name == ASSESS_TOOL:
                    feedback = await self._assess(
                        ledger,
                        hypothesis=str(arguments.get("hypothesis", "")),
                        steps_left=self.max_steps - runtime_calls,
                        assessments_left=assessments_left,
                    )
                    assessments_left -= 1
                elif tool_name not in available_tools:
                    feedback = {
                        "status": "error",
                        "message": (
                            f"Tool {tool_name!r} is not advertised for this task. "
                            f"Available tools: {sorted(available_tools)}"
                        ),
                    }
                    logger.warning("Rejected unavailable tool {} locally.", tool_name)
                elif runtime_calls >= self.max_steps:
                    feedback = {"status": "error", "message": "Tool-call budget exhausted."}
                else:
                    response = await session.call_tool(tool_name, arguments)
                    runtime_calls += 1
                    feedback = self._tool_feedback(response)
                    ledger.record(tool_name, arguments, feedback["result"])
                    logger.info(
                        "Tool {} returned status {}.",
                        tool_name,
                        feedback.get("status", "unknown"),
                    )
                    if feedback["status"] != "ok":
                        logger.warning(
                            "Tool {} result: {}", tool_name, render_json(feedback["result"])
                        )
                    _trace(
                        session.task_id,
                        {
                            "event": "call",
                            "tool": tool_name,
                            "arguments": arguments,
                            "info": response.info,
                            "observation": response.observation,
                        },
                    )
                    if response.task_result is not None:
                        return TaskResult.model_validate(response.task_result)

                messages.append(
                    {
                        "role": "tool",
                        "content": _truncate(render_json(feedback), MAX_RESULT_CHARS),
                        "tool_call_id": call_id,
                    }
                )

        raise RuntimeError(
            f"Agent hit the {self.max_steps}-step limit without finish_investigation."
        )

    async def _assess(
        self,
        ledger: EvidenceLedger,
        *,
        hypothesis: str,
        steps_left: int,
        assessments_left: int,
    ) -> dict[str, Any]:
        """Answer `assess_situation` locally with the Jev decision tree.

        Args:
            ledger: Evidence gathered for the current task.
            hypothesis: The LLM's current working hypothesis.
            steps_left: Runtime tool calls still available.
            assessments_left: Assessments still available before this one.

        Returns:
            Tool feedback in the same shape as runtime tool results.
        """
        if self.triage is None or assessments_left <= 0:
            return {
                "tool_name": "assess_situation",
                "status": "error",
                "error": "assess_situation is unavailable or its per-task limit is spent.",
            }
        try:
            assessment = await self.triage.assess(
                ledger, hypothesis=hypothesis, steps_left=steps_left
            )
        except TypeSafeError as exc:
            logger.warning("Triage decision tree failed: {}", exc)
            return {"tool_name": "assess_situation", "status": "error", "error": str(exc)}
        return {
            "tool_name": "assess_situation",
            "status": "ok",
            "result": assessment.model_dump(mode="json"),
            "assessments_left": assessments_left - 1,
            "runtime_steps_left": steps_left,
        }

    @staticmethod
    def _tool_specs(observation: dict[str, Any]) -> list[dict[str, Any]]:
        """Decode the runtime tool catalog from the current observation.

        Args:
            observation: Current public task observation.

        Returns:
            Advertised tool specifications.

        Raises:
            ValueError: If `available_tools` is absent or malformed.
        """
        raw_tool_specs = observation.get("available_tools")
        if not isinstance(raw_tool_specs, str):
            raise ValueError("Observation has no JSON-encoded available_tools field.")
        try:
            tool_specs = json.loads(raw_tool_specs)
        except json.JSONDecodeError as exc:
            raise ValueError("available_tools is not valid JSON.") from exc
        if not isinstance(tool_specs, list) or not all(
            isinstance(specification, dict) for specification in tool_specs
        ):
            raise ValueError("available_tools must encode a list of tool specifications.")
        return [dict(specification) for specification in tool_specs]

    @staticmethod
    def _tool_feedback(response: ToolCallResult) -> dict[str, Any]:
        """Reduce a remote tool response to evidence needed by the LLM.

        Args:
            response: Server tool-call response.

        Returns:
            Compact evidence and lifecycle flags.
        """
        result = response.info.get("tool_result", response.observation.get("last_tool_result"))
        return {
            "tool_name": response.tool_name,
            "status": response.info.get("tool_status", "unknown"),
            "result": _decode_json_string(result),
            "reward": response.reward,
            "terminated": response.terminated,
            "truncated": response.truncated,
        }


def _decode_json_string(value: Any) -> Any:
    """Decode runtime values that arrive as JSON-encoded strings, leaving others as is."""
    if isinstance(value, str) and value.lstrip()[:1] in {"{", "["}:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _truncate(text: str, limit: int) -> str:
    """Cap one tool result shown to the LLM; the evidence ledger keeps the full result."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [truncated {len(text) - limit} chars; narrow the query or page]"
