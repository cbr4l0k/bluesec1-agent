import asyncio
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from typesafe_sdk import (
    AsyncTypeSafeClient,
    Choice,
    ChoiceAnswer,
    NoulAnswer,
    Question,
    Score,
    ScoreAnswer,
    SystemOneResponse,
    Usage,
)

from bluesec1_agent.triage import MALICIOUS_SIGNALS, EvidenceLedger, TriageDecisionTree


class FakeJev:
    """Answer every question with fixed probabilities chosen by the test."""

    def __init__(
        self,
        noul: float,
        top_choice: dict[str, str],
        score_level: int,
        nouls: dict[str, float] | None = None,
    ) -> None:
        """Store canned answers.

        Args:
            noul: Probability returned for every Noul not named in `nouls`.
            top_choice: Preferred label per Choice question id prefix.
            score_level: Level that receives most Score probability.
            nouls: Per-question Noul overrides.
        """
        self.noul = noul
        self.nouls = nouls or {}
        self.top_choice = top_choice
        self.score_level = score_level
        self.requests: list[Mapping[str, Question]] = []

    async def system_one(
        self, *, state: Any, questions: Mapping[str, Question], model: str | None
    ) -> SystemOneResponse:
        """Return deterministic answers in the SDK response shape."""
        self.requests.append(questions)
        answers: dict[str, Any] = {}
        for name, question in questions.items():
            if isinstance(question, Choice):
                labels = list(question.criteria)
                preferred = self.top_choice.get(name, self.top_choice.get(name[0], labels[0]))
                rest = (1 - 0.9) / max(len(labels) - 1, 1)
                probabilities = {label: 0.9 if label == preferred else rest for label in labels}
                answers[name] = ChoiceAnswer(
                    type="choice", choice=preferred, confidence=0.9, probabilities=probabilities
                )
            elif isinstance(question, Score):
                levels = range(len(question.criteria))
                probabilities = {i: 1.0 if i == self.score_level else 0.0 for i in levels}
                answers[name] = ScoreAnswer(
                    type="score",
                    score=float(self.score_level),
                    confidence=1.0,
                    legend={i: str(question.criteria[i]) for i in levels},
                    probabilities=probabilities,
                )
            else:
                answers[name] = NoulAnswer(type="noul", noul=self.nouls.get(name, self.noul))
        return SystemOneResponse(model="fake", usage=Usage(), answers=answers)


ALERT = json.loads((Path(__file__).parent / "fixtures" / "alert.json").read_text())
HOST = "412945fa-8255-509d-a789-5c08f8f9fec5"
PROCESS = "b043f4a9-ebc5-59db-b050-647e406a8d5e"
TRIGGER_RELATION = "ff023ed6-8e00-59a7-ad73-a021bd21ce0a"


def _ledger() -> EvidenceLedger:
    ledger = EvidenceLedger(alert={"alert_text": ALERT})
    ledger.record(
        "get_entity",
        {"entity_id": PROCESS, "reasoning": "r"},
        {"id": PROCESS, "type": "windows_process", "incoming_relation_ids": ["rel-parent"]},
    )
    return ledger


def test_ledger_harvests_real_alert_shapes() -> None:
    ledger = _ledger()

    assert ("get_entity", HOST) in ledger.frontier()
    assert ("get_relation", TRIGGER_RELATION) in ledger.frontier()
    assert ("get_relation", "rel-parent") in ledger.frontier()
    assert all(identifier != PROCESS for _, identifier in ledger.frontier())
    assert ledger.properties(PROCESS)["signer"] == "Microsoft Windows"


def test_insufficient_evidence_branches_to_investigate() -> None:
    jev = FakeJev(
        noul=0.1,
        top_choice={"activity_class": "insufficient_evidence", "open_question": "process_lineage"},
        score_level=0,
    )
    tree = TriageDecisionTree(cast(AsyncTypeSafeClient, jev))

    result = asyncio.run(tree.assess(_ledger(), hypothesis="unclear", steps_left=20))

    assert result.branch == "investigate"
    assert result.next_targets
    assert len(jev.requests) == 2


def test_confident_attack_branches_to_respond_with_artifacts() -> None:
    jev = FakeJev(
        noul=0.8,
        top_choice={
            "activity_class": "commodity_malware",
            "open_question": "nothing_blocking",
            "e": "host_to_isolate",
        },
        score_level=3,
        nouls={"benign_explanation": 0.05, "unresolved_contradiction": 0.05},
    )
    tree = TriageDecisionTree(cast(AsyncTypeSafeClient, jev))

    result = asyncio.run(tree.assess(_ledger(), hypothesis="dropper", steps_left=20))

    assert result.branch == "respond"
    assert result.verdict_lean == "malicious"
    assert {artifact.kind for artifact in result.proposed_artifacts} == {"host_to_isolate"}


def test_low_budget_forces_decision() -> None:
    jev = FakeJev(noul=0.1, top_choice={"e": "not_relevant"}, score_level=0)
    tree = TriageDecisionTree(cast(AsyncTypeSafeClient, jev))

    result = asyncio.run(tree.assess(_ledger(), hypothesis="unclear", steps_left=1))

    assert result.branch == "decide_now"
    assert result.proposed_artifacts == []


def test_benign_branch_cites_real_property_fields() -> None:
    jev = FakeJev(
        noul=0.9,
        top_choice={"activity_class": "admin_or_it_activity", "open_question": "nothing_blocking"},
        score_level=3,
        nouls={name: 0.02 for name in MALICIOUS_SIGNALS} | {"unresolved_contradiction": 0.02},
    )
    tree = TriageDecisionTree(cast(AsyncTypeSafeClient, jev))

    result = asyncio.run(tree.assess(_ledger(), hypothesis="service host", steps_left=20))

    assert result.branch == "prove_benign"
    process = next(e for e in result.proposed_legitimacy_evidence if e.id == PROCESS)
    assert process.anchor == "entity"
    assert "signer" in process.property_fields
    assert set(process.property_fields) <= set(_ledger().properties(PROCESS))
