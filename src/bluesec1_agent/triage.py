"""Jev-backed decision tree that advises the investigation loop.

The tree is owned by code. Jev only supplies typed judgments at each node:

    root: signals  (one parallel request over the whole evidence ledger)
      ├─ budget nearly spent ───────────────► DECIDE with the current lean
      ├─ evidence insufficient / ambiguous ─► INVESTIGATE: rank frontier ids
      ├─ malicious lean, confident ─────────► RESPOND: pick IR action per entity
      └─ benign lean, confident ────────────► PROVE_BENIGN: pick supporting evidence

Calling `assess` costs no runtime tool call, so the agent can consult it freely
between investigation steps.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Literal, get_args

from loguru import logger
from pydantic import BaseModel, ConfigDict
from typesafe_sdk import AsyncTypeSafeClient, Choice, Noul, Score, SystemOneResponse

from bluesec1_agent.models import IRArtifactKind

Branch = Literal["investigate", "respond", "prove_benign", "decide_now"]

ALL_KINDS: tuple[str, ...] = get_args(IRArtifactKind)
NOT_RELEVANT = "not_relevant"

MALICIOUS_SIGNALS: dict[str, str] = {
    "suspicious_lineage": (
        "A process in `evidence` has an unusual parent/child chain for its role, such as an "
        "office app, browser or service host spawning a shell, script host or unsigned binary."
    ),
    "lolbin_or_script_abuse": (
        "A built-in system binary or script interpreter in `evidence` is used for download, "
        "decoding, execution proxying or obfuscated commands rather than its normal purpose."
    ),
    "external_c2_or_exfil": (
        "`evidence` shows network activity to an external destination consistent with command "
        "and control, payload download or data exfiltration."
    ),
    "persistence_created": (
        "`evidence` shows a new autorun mechanism: run keys, services, scheduled tasks, startup "
        "folder items, WMI subscriptions or similar."
    ),
    "credential_or_identity_abuse": (
        "`evidence` shows credential dumping, LSASS access, ticket abuse, or an identity used "
        "from an unexpected host or context."
    ),
    "payload_drop_and_execute": (
        "`evidence` shows a file written to a user-writable or temp location and then executed "
        "or loaded."
    ),
}

ACTIVITY_CLASSES: dict[str, str] = {
    "commodity_malware": "Automated malware: dropper, loader, miner, infostealer or ransomware.",
    "hands_on_intrusion": "An operator is discovering, moving laterally or staging data.",
    "phishing_initial_access": "A user opened a malicious document, link or attachment.",
    "admin_or_it_activity": "Legitimate administration, deployment or IT automation.",
    "software_install_or_update": "A legitimate installer, updater or package manager.",
    "security_tool_activity": "EDR, AV, scanner or other security tooling behaving normally.",
    "developer_activity": "Builds, scripts or tooling run by a developer on their own machine.",
    "insufficient_evidence": "The evidence so far does not support any activity class.",
}
MALICIOUS_CLASSES = {"commodity_malware", "hands_on_intrusion", "phishing_initial_access"}

OPEN_QUESTIONS: dict[str, str] = {
    "process_lineage": "Who launched the alerted process and what it launched is unknown.",
    "network_destination": "Where it connected and whether that is legitimate is unknown.",
    "files_written": "Which files were dropped, modified or executed is unknown.",
    "registry_or_persistence": "Whether autoruns or registry changes were made is unknown.",
    "user_or_identity": "Which account acted and whether that is expected is unknown.",
    "nothing_blocking": "No open question blocks a verdict anymore.",
}

SUFFICIENCY_LEVELS = [
    "Only the alert itself is known; no corroborating evidence has been gathered.",
    "Some related entities are known, but the key open question is unresolved.",
    "Most of the relevant chain is known; one gap could still flip the verdict.",
    "The chain is understood end to end; more investigation would not change the verdict.",
]

INFORMATIVENESS_LEVELS = [
    "Expanding this id is unlikely to change anything about the verdict.",
    "Expanding this id adds context but probably not decisive evidence.",
    "Expanding this id likely answers the open question.",
    "Expanding this id is very likely to settle the verdict on its own.",
]


class FrontierTarget(BaseModel):
    """One unexpanded id worth following next."""

    model_config = ConfigDict(frozen=True)

    tool: Literal["get_entity", "get_relation"]
    id: str
    informativeness: float


class ProposedArtifact(BaseModel):
    """One entity Jev suggests reporting, with the probability of the chosen kind."""

    model_config = ConfigDict(frozen=True)

    entity_id: str
    kind: str
    probability: float


class ProposedEvidence(BaseModel):
    """One graph object Jev suggests citing as `legitimacy_evidence` for a benign verdict."""

    model_config = ConfigDict(frozen=True)

    anchor: Literal["entity", "relation"]
    id: str
    property_fields: list[str]
    probability: float


class TriageAssessment(BaseModel):
    """Typed advice returned to the investigating LLM."""

    model_config = ConfigDict(frozen=True)

    branch: Branch
    verdict_lean: Literal["malicious", "benign", "undetermined"]
    malicious_probability: float
    benign_explanation_probability: float
    contradiction_probability: float
    activity_class: str
    activity_confidence: float
    evidence_sufficiency: float
    open_question: str
    signals: dict[str, float]
    next_targets: list[FrontierTarget] = []
    proposed_artifacts: list[ProposedArtifact] = []
    proposed_legitimacy_evidence: list[ProposedEvidence] = []
    decision_path: list[str]
    advice: str


@dataclass
class EvidenceLedger:
    """Code-owned memory of everything the runtime returned for one task."""

    alert: dict[str, Any]
    results: list[dict[str, Any]] = field(default_factory=list)
    entity_ids: dict[str, None] = field(default_factory=dict)
    relation_ids: dict[str, None] = field(default_factory=dict)
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    expanded: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        """Harvest ids already named in the alert."""
        self._harvest(self.alert)

    def record(self, tool: str, arguments: dict[str, Any], result: Any) -> None:
        """Store one tool result and harvest the ids it mentions."""
        self.results.append({"tool": tool, "arguments": arguments, "result": result})
        for key in ("entity_id", "relation_id"):
            if isinstance(arguments.get(key), str):
                self.expanded.add(arguments[key])
        self._harvest(result)

    def frontier(self) -> list[tuple[Literal["get_entity", "get_relation"], str]]:
        """Return ids that were seen but never expanded, entities first."""
        frontier: list[tuple[Literal["get_entity", "get_relation"], str]] = [
            ("get_entity", i) for i in self.entity_ids if i not in self.expanded
        ]
        frontier += [("get_relation", i) for i in self.relation_ids if i not in self.expanded]
        return frontier

    def snapshot(self, max_chars: int) -> list[dict[str, Any]]:
        """Return the newest results that fit in `max_chars`, oldest first."""
        kept: list[dict[str, Any]] = []
        used = 0
        for item in reversed(self.results):
            size = len(json.dumps(item, default=str))
            if used + size > max_chars:
                break
            kept.append(item)
            used += size
        return kept[::-1]

    def properties(self, identifier: str) -> dict[str, Any]:
        """Return the non-null properties last seen for an entity or relation."""
        properties = self.objects.get(identifier, {}).get("properties") or {}
        return {name: value for name, value in properties.items() if value not in (None, [], "")}

    def _harvest(self, value: Any, key: str = "") -> None:
        """Collect graph objects and the entity and relation ids they reference."""
        if isinstance(value, dict):
            identifier = value.get("id")
            if isinstance(identifier, str) and ("source_id" in value or "target_id" in value):
                self.relation_ids.setdefault(identifier)
                self._remember(identifier, value)
            elif isinstance(identifier, str) and "type" in value:
                self.entity_ids.setdefault(identifier)
                self._remember(identifier, value)
            for child_key, child in value.items():
                if child_key != "id":
                    self._harvest(child, child_key.lower())
        elif isinstance(value, list):
            for child in value:
                self._harvest(child, key)
        elif isinstance(value, str) and value:
            if "relation" in key and key.endswith(("_id", "_ids")):
                self.relation_ids.setdefault(value)
            elif key in {"source_id", "target_id", "host_id"} or key.endswith(
                ("entity_id", "entity_ids")
            ):
                self.entity_ids.setdefault(value)

    def _remember(self, identifier: str, graph_object: dict[str, Any]) -> None:
        """Keep the most detailed copy of a graph object."""
        known = self.objects.get(identifier)
        if known is None or (graph_object.get("properties") and not known.get("properties")):
            self.objects[identifier] = graph_object


def _noisy_or(probabilities: list[float]) -> float:
    """Probability that at least one independent signal holds."""
    product = 1.0
    for probability in probabilities:
        product *= 1.0 - probability
    return 1.0 - product


class TriageDecisionTree:
    """Walk the triage tree, asking Jev one batched request per level."""

    def __init__(
        self,
        client: AsyncTypeSafeClient,
        *,
        model: str | None = None,
        max_evidence_chars: int = 24_000,
        max_candidates: int = 16,
        decide_margin: float = 0.25,
        sufficient_at: float = 1.8,
        artifact_threshold: float = 0.5,
    ) -> None:
        """Store the Jev client and the policy thresholds the tree branches on."""
        self.client = client
        self.model = model
        self.max_evidence_chars = max_evidence_chars
        self.max_candidates = max_candidates
        self.decide_margin = decide_margin
        self.sufficient_at = sufficient_at
        self.artifact_threshold = artifact_threshold

    async def assess(
        self, ledger: EvidenceLedger, *, hypothesis: str, steps_left: int
    ) -> TriageAssessment:
        """Run the full tree for the current ledger and return typed advice."""
        state = {
            "alert": ledger.alert,
            "analyst_hypothesis": hypothesis,
            "evidence": ledger.snapshot(self.max_evidence_chars),
        }
        root = await self._ask(state, self._root_questions())
        signals = {name: root.nouls[name].noul for name in MALICIOUS_SIGNALS}
        benign = root.nouls["benign_explanation"].noul
        contradiction = root.nouls["unresolved_contradiction"].noul
        activity = root.choices["activity_class"]
        sufficiency = root.scores["evidence_sufficiency"].score
        open_question = root.choices["open_question"].choice

        malicious = _noisy_or(list(signals.values()))
        class_malicious = sum(activity.probabilities.get(c, 0.0) for c in MALICIOUS_CLASSES)
        malicious = (malicious + class_malicious) / 2
        margin = malicious - benign
        lean: Literal["malicious", "benign", "undetermined"] = (
            "malicious"
            if margin >= self.decide_margin
            else "benign"
            if margin <= -self.decide_margin
            else "undetermined"
        )

        path = [
            f"root: malicious={malicious:.2f} benign={benign:.2f} "
            f"class={activity.choice}({activity.confidence:.2f}) sufficiency={sufficiency:.2f} "
            f"contradiction={contradiction:.2f}"
        ]
        branch: Branch
        if steps_left <= 2:
            branch = "decide_now"
            path.append(f"budget: {steps_left} steps left -> decide with current lean")
        elif (
            lean == "undetermined"
            or sufficiency < self.sufficient_at
            or activity.choice == "insufficient_evidence"
            or contradiction >= 0.5
        ) and ledger.frontier():
            branch = "investigate"
            path.append(f"gap: lean={lean}, open_question={open_question} -> investigate")
        else:
            branch = "prove_benign" if lean == "benign" or margin < 0 else "respond"
            path.append(f"confident {lean} -> {branch}")

        targets: list[FrontierTarget] = []
        artifacts: list[ProposedArtifact] = []
        evidence: list[ProposedEvidence] = []
        if branch == "investigate":
            targets = await self._rank_frontier(state, ledger, open_question)
            ranked = ", ".join(f"{t.id}={t.informativeness:.2f}" for t in targets)
            path.append(f"frontier: {ranked}")
        elif branch == "respond" or (branch == "decide_now" and margin > 0):
            artifacts = await self._pick_artifacts(state, ledger)
            path.append(f"artifacts: {len(artifacts)} selected")
        else:
            evidence = await self._pick_legitimacy_evidence(state, ledger)
            path.append(f"legitimacy evidence: {len(evidence)} selected")

        assessment = TriageAssessment(
            branch=branch,
            verdict_lean=lean,
            malicious_probability=round(malicious, 3),
            benign_explanation_probability=round(benign, 3),
            contradiction_probability=round(contradiction, 3),
            activity_class=activity.choice,
            activity_confidence=round(activity.confidence, 3),
            evidence_sufficiency=round(sufficiency, 2),
            open_question=open_question,
            signals={name: round(p, 3) for name, p in signals.items()},
            next_targets=targets,
            proposed_artifacts=artifacts,
            proposed_legitimacy_evidence=evidence,
            decision_path=path,
            advice=_advice(branch, lean, open_question, targets),
        )
        logger.info("Triage tree: {}", " | ".join(path))
        return assessment

    def _root_questions(self) -> dict[str, Noul | Choice | Score]:
        """Independent root judgments, asked together in one parallel request."""
        questions: dict[str, Noul | Choice | Score] = {
            name: Noul(instructions=text) for name, text in MALICIOUS_SIGNALS.items()
        }
        questions["benign_explanation"] = Noul(
            instructions=(
                "`evidence` contains a concrete legitimate explanation for the activity in "
                "`alert`: a signed vendor binary in its normal path, an expected parent, a known "
                "admin or update workflow, or an internal destination."
            )
        )
        questions["unresolved_contradiction"] = Noul(
            instructions=(
                "`evidence` contains facts that point in opposite directions, such as a signed "
                "binary with malicious behaviour or an attack-like chain with an admin context, "
                "and nothing gathered so far reconciles them."
            )
        )
        questions["activity_class"] = Choice(
            instructions="Which activity best explains `alert` given `evidence`?",
            criteria=ACTIVITY_CLASSES,
        )
        questions["evidence_sufficiency"] = Score(
            instructions="How completely does `evidence` explain the activity behind `alert`?",
            criteria=SUFFICIENCY_LEVELS,
        )
        questions["open_question"] = Choice(
            instructions=(
                "Which unresolved question most blocks a confident attack-or-false-positive "
                "verdict for `alert`, given `evidence` and `analyst_hypothesis`?"
            ),
            criteria=OPEN_QUESTIONS,
        )
        return questions

    async def _rank_frontier(
        self, state: dict[str, Any], ledger: EvidenceLedger, open_question: str
    ) -> list[FrontierTarget]:
        """Score each unexpanded id for how well it answers the open question."""
        frontier = ledger.frontier()[: self.max_candidates]
        questions: dict[str, Noul | Choice | Score] = {
            f"c{index}": Score(
                instructions=(
                    f"The analyst could next expand id `{identifier}` with `{tool}`. The open "
                    f"question is: {OPEN_QUESTIONS.get(open_question, open_question)} Judging "
                    "from where this id appears in `evidence` and `alert`, how useful would "
                    "expanding it be?"
                ),
                criteria=INFORMATIVENESS_LEVELS,
            )
            for index, (tool, identifier) in enumerate(frontier)
        }
        response = await self._ask(state, questions)
        ranked = sorted(
            (
                FrontierTarget(
                    tool=tool, id=identifier, informativeness=response.scores[f"c{i}"].score
                )
                for i, (tool, identifier) in enumerate(frontier)
            ),
            key=lambda target: target.informativeness,
            reverse=True,
        )
        return ranked[:3]

    async def _pick_artifacts(
        self, state: dict[str, Any], ledger: EvidenceLedger
    ) -> list[ProposedArtifact]:
        """Choose an IR action or forensic kind, or none, for each known entity."""
        entities = list(ledger.entity_ids)[: self.max_candidates]
        if not entities:
            return []
        criteria: dict[str, str | None] = {kind: None for kind in ALL_KINDS}
        criteria[NOT_RELEVANT] = "The entity is not part of the attack chain."
        questions: dict[str, Noul | Choice | Score] = {
            f"e{index}": Choice(
                instructions=(
                    f"Entity `{identifier}` (type {ledger.objects.get(identifier, {}).get('type')})"
                    " was observed. Which incident-response action or forensic artifact kind "
                    "does it need, given `evidence`?"
                ),
                criteria=criteria,
            )
            for index, identifier in enumerate(entities)
        }
        response = await self._ask(state, questions)
        picked: list[ProposedArtifact] = []
        for index, identifier in enumerate(entities):
            answer = response.choices[f"e{index}"]
            probability = answer.probabilities.get(answer.choice, 0.0)
            if answer.choice != NOT_RELEVANT and probability >= self.artifact_threshold:
                picked.append(
                    ProposedArtifact(
                        entity_id=identifier, kind=answer.choice, probability=round(probability, 3)
                    )
                )
        return picked

    async def _pick_legitimacy_evidence(
        self, state: dict[str, Any], ledger: EvidenceLedger
    ) -> list[ProposedEvidence]:
        """Select graph objects, then the exact properties, that show the activity is legitimate.

        Two requests: one Noul per known object, then one Noul per property of the
        objects that passed. Property names are copied from the ledger, never generated.
        """
        candidates = list(ledger.objects)[: self.max_candidates]
        if not candidates:
            return []
        objects = await self._ask(
            state,
            {
                f"o{index}": Noul(
                    instructions=(
                        f"Graph object `{identifier}` in `evidence` or `alert` helps show that "
                        "the activity in `alert` is legitimate rather than an attack."
                    )
                )
                for index, identifier in enumerate(candidates)
            },
        )
        supporting = sorted(
            (
                (objects.nouls[f"o{index}"].noul, identifier)
                for index, identifier in enumerate(candidates)
                if objects.nouls[f"o{index}"].noul >= self.artifact_threshold
            ),
            reverse=True,
        )[:4]
        if not supporting:
            return []

        fields: list[tuple[str, str]] = [
            (identifier, name)
            for _, identifier in supporting
            for name in list(ledger.properties(identifier))[:15]
        ]
        properties = (
            await self._ask(
                state,
                {
                    f"p{index}": Noul(
                        instructions=(
                            f"Property `{name}` = {json.dumps(ledger.properties(identifier)[name])}"
                            f" of graph object `{identifier}` is itself evidence that the activity "
                            "in `alert` is legitimate."
                        )
                    )
                    for index, (identifier, name) in enumerate(fields)
                },
            )
            if fields
            else None
        )

        picked: list[ProposedEvidence] = []
        for probability, identifier in supporting:
            names = [
                name
                for index, (owner, name) in enumerate(fields)
                if owner == identifier
                and properties is not None
                and properties.nouls[f"p{index}"].noul >= self.artifact_threshold
            ]
            anchor: Literal["entity", "relation"] = (
                "relation" if identifier in ledger.relation_ids else "entity"
            )
            if anchor == "entity" and not names:
                continue
            picked.append(
                ProposedEvidence(
                    anchor=anchor,
                    id=identifier,
                    property_fields=names,
                    probability=round(probability, 3),
                )
            )
        return picked

    async def _ask(
        self, state: dict[str, Any], questions: dict[str, Noul | Choice | Score]
    ) -> SystemOneResponse:
        """Send one batched System One request."""
        return await self.client.system_one(state=state, questions=questions, model=self.model)


def _advice(
    branch: Branch,
    lean: str,
    open_question: str,
    targets: list[FrontierTarget],
) -> str:
    """Translate the tree leaf into one instruction for the investigating LLM."""
    if branch == "investigate":
        follow = targets[0] if targets else None
        step = f" Next: {follow.tool}({follow.id})." if follow else ""
        return f"Not ready to decide. Resolve: {OPEN_QUESTIONS[open_question]}{step}"
    if branch == "decide_now":
        return f"Budget nearly spent. Finish now with the current lean ({lean})."
    if branch == "respond":
        return "Evidence supports an attack. Finish as malicious with the proposed artifacts."
    return "Evidence supports a false positive. Finish as benign citing the proposed evidence."
