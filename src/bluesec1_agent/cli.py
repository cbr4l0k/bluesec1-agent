import argparse
import asyncio
import contextlib
import json
import sys

import truststore
from pydantic import ValidationError
from typesafe_sdk import AsyncTypeSafeClient

from bluesec1_agent.agent import SimpleSGRAgent
from bluesec1_agent.codex_llm import CodexStructuredStepClient
from bluesec1_agent.llm import OpenAIStructuredStepClient
from bluesec1_agent.settings import Settings
from bluesec1_agent.triage import TriageDecisionTree
from bluesec1_client import (
    CompetitionClosedError,
    RemoteAuthenticationError,
    RemoteBenchmarkClient,
    RemoteRateLimitError,
    RemoteUnavailableError,
    RunCapacityExceededError,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the remote-runtime command-line interface.

    Returns:
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Run the structured-generation agent against scenario-runtime."
    )
    parser.add_argument("--endpoint", help="Override SCENARIO_RUNTIME_ENDPOINT.")
    parser.add_argument("--token", help="Override SCENARIO_RUNTIME_TOKEN.")
    parser.add_argument("--run-label", help="Override REMOTE_RUN_LABEL.")
    parser.add_argument("--agent-name", help="Override AGENT_NAME.")
    parser.add_argument("--arena", help="Override SCENARIO_RUNTIME_ARENA.")
    parser.add_argument(
        "--verify-tls",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Override SCENARIO_RUNTIME_VERIFY_TLS.",
    )
    return parser


async def run(args: argparse.Namespace) -> None:
    """Execute one new remote run and print its task results.

    Args:
        args: Parsed command-line arguments.
    """
    truststore.inject_into_ssl()
    settings = _load_settings()
    llm = _build_llm(settings)
    model_name = (
        f"codex:{settings.llm_default_model or 'default'}"
        if settings.llm_backend == "codex"
        else settings.llm_default_model
    )
    typesafe = (
        AsyncTypeSafeClient(api_key=settings.typesafe_api_key.get_secret_value())
        if settings.typesafe_api_key is not None
        else None
    )
    triage = (
        TriageDecisionTree(typesafe, model=settings.typesafe_model)
        if typesafe is not None
        else None
    )
    agent_name = args.agent_name or settings.agent_name
    verify_tls = (
        settings.scenario_runtime_verify_tls if args.verify_tls is None else args.verify_tls
    )
    async with (
        llm,
        typesafe or contextlib.nullcontext(),
        RemoteBenchmarkClient(
            endpoint=args.endpoint or settings.scenario_runtime_endpoint,
            token=args.token or settings.scenario_runtime_token.get_secret_value(),
            verify_tls=verify_tls,
            run_label=args.run_label or settings.remote_run_label,
            agent_name=agent_name,
            model_name=model_name,
            arena=args.arena or settings.scenario_runtime_arena,
            metadata={
                "agent": agent_name,
                "implementation": "structured-generation-scenario-runtime-grpc",
                "model": model_name,
            },
        ) as client,
    ):
        result = await SimpleSGRAgent(
            llm,
            max_steps=settings.agent_max_steps,
            triage=triage,
            max_assessments=settings.agent_max_assessments,
        ).run(client)

    print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))


def main() -> None:
    """Parse arguments and execute the async remote agent."""
    try:
        asyncio.run(run(build_parser().parse_args()))
    except RunCapacityExceededError as error:
        print(_run_capacity_message(error), file=sys.stderr)
        raise SystemExit(1) from error
    except CompetitionClosedError as error:
        print(
            "The selected competition arena is closed. Check SCENARIO_RUNTIME_ARENA or retry "
            "when the arena opens.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteRateLimitError as error:
        print(
            "Run starts are temporarily rate-limited. Wait before starting another run.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteAuthenticationError as error:
        print(
            "The runtime rejected your key. Check SCENARIO_RUNTIME_TOKEN in .env.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteUnavailableError as error:
        print(
            "Cannot reach the runtime. Check SCENARIO_RUNTIME_ENDPOINT and "
            "SCENARIO_RUNTIME_VERIFY_TLS in .env.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


def _build_llm(settings: Settings) -> OpenAIStructuredStepClient | CodexStructuredStepClient:
    """Create the step generator selected by `LLM_BACKEND`.

    Args:
        settings: Validated settings.

    Returns:
        Structured step client for the agent loop.
    """
    if settings.llm_backend == "codex":
        return CodexStructuredStepClient(
            model=settings.llm_default_model,
            reasoning_effort=settings.codex_reasoning_effort,
            timeout_seconds=settings.llm_timeout_seconds,
            max_retries=settings.llm_max_step_retries,
        )
    assert settings.llm_base_url and settings.llm_api_key and settings.llm_default_model
    return OpenAIStructuredStepClient(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key.get_secret_value(),
        model=settings.llm_default_model,
        timeout_seconds=settings.llm_timeout_seconds,
        max_completion_tokens=settings.llm_max_completion_tokens,
        max_retries=settings.llm_max_step_retries,
    )


def _load_settings() -> Settings:
    """Load settings and explain what is missing instead of raising a raw error.

    Returns:
        Validated settings.
    """
    try:
        return Settings()
    except ValidationError as error:
        missing = [str(item["loc"][0]) for item in error.errors() if item["type"] == "missing"]
        invalid = [item["msg"] for item in error.errors() if item["type"] == "value_error"]
        if not missing and not invalid:
            raise
        if missing:
            print("Missing configuration: " + ", ".join(missing), file=sys.stderr)
        for message in invalid:
            reason = message.removeprefix("Value error, ")
            print(f"Invalid configuration: {reason}", file=sys.stderr)
        print(
            "Copy .env.example to .env and fill it in. "
            "Runtime address and key: https://bluesec.team/",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


def _run_capacity_message(error: RunCapacityExceededError) -> str:
    """Explain which run limit was hit and what to do about it.

    Args:
        error: Capacity failure reported by the runtime.

    Returns:
        Message for the participant.
    """
    if getattr(error, "reason", None) == "PROCESS_ACTIVE_RUN_LIMIT_REACHED":
        lines = ["The runtime is at its overall capacity right now. This is not your limit."]
    else:
        lines = [
            "You have reached your limit of concurrent runs.",
            "Wait for a running one to finish. If an agent was killed mid-run, its run stays "
            "open until it is released.",
        ]
    return "\n".join(lines)
