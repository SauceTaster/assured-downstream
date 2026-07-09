from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from assured_downstream.catalog import repo_key


@dataclass(frozen=True)
class CandidatePolicyEntry:
    full_name: str
    reason: str
    source: str | None = None

    @property
    def key(self) -> str:
        owner, name = split_full_name(self.full_name)
        return repo_key(owner, name)


@dataclass(frozen=True)
class CandidateSelectionPolicy:
    allowlist: dict[str, CandidatePolicyEntry]
    suppressions: dict[str, CandidatePolicyEntry]

    @classmethod
    def empty(cls) -> "CandidateSelectionPolicy":
        return cls(allowlist={}, suppressions={})

    @classmethod
    def from_entries(
        cls,
        *,
        allowlist: list[str | dict[str, Any] | CandidatePolicyEntry] | None = None,
        suppressions: list[str | dict[str, Any] | CandidatePolicyEntry] | None = None,
    ) -> "CandidateSelectionPolicy":
        return cls(
            allowlist=index_entries(allowlist or [], default_reason="allowlisted"),
            suppressions=index_entries(suppressions or [], default_reason="suppressed"),
        )

    def allow_entry(self, full_name: str) -> CandidatePolicyEntry | None:
        return self.allowlist.get(normalize_full_name(full_name))

    def suppression_entry(self, full_name: str) -> CandidatePolicyEntry | None:
        return self.suppressions.get(normalize_full_name(full_name))

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "allowlist": [asdict(entry) for entry in self.allowlist.values()],
            "suppressions": [asdict(entry) for entry in self.suppressions.values()],
        }


def load_candidate_policy(
    *,
    allowlist_path: Path | None = None,
    suppression_path: Path | None = None,
) -> CandidateSelectionPolicy:
    allowlist = load_policy_entries(allowlist_path, "allowlisted") if allowlist_path else []
    suppressions = load_policy_entries(suppression_path, "suppressed") if suppression_path else []
    return CandidateSelectionPolicy.from_entries(
        allowlist=allowlist,
        suppressions=suppressions,
    )


def load_policy_entries(path: Path, default_reason: str) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    entries = extract_entries(payload)
    result = []
    for entry in entries:
        if isinstance(entry, str):
            result.append(
                {
                    "full_name": entry,
                    "reason": default_reason,
                    "source": str(path),
                }
            )
        elif isinstance(entry, dict):
            candidate = dict(entry)
            candidate.setdefault("reason", default_reason)
            candidate.setdefault("source", str(path))
            result.append(candidate)
        else:
            raise ValueError(f"Unsupported policy entry in {path}: {entry!r}")
    return result


def extract_entries(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("repositories", "repos", "allowlist", "suppressions", "suppressed"):
            entries = payload.get(key)
            if entries is not None:
                if not isinstance(entries, list):
                    raise ValueError(f"Policy field {key!r} must be a list")
                return entries
        if payload.get("full_name") or payload.get("repository") or (
            payload.get("owner") and payload.get("name")
        ):
            return [payload]
    raise ValueError("Policy file must contain a list or repository entry object")


def index_entries(
    entries: list[str | dict[str, Any] | CandidatePolicyEntry],
    *,
    default_reason: str,
) -> dict[str, CandidatePolicyEntry]:
    indexed: dict[str, CandidatePolicyEntry] = {}
    for entry in entries:
        policy_entry = coerce_policy_entry(entry, default_reason=default_reason)
        indexed[policy_entry.key] = policy_entry
    return indexed


def coerce_policy_entry(
    entry: str | dict[str, Any] | CandidatePolicyEntry,
    *,
    default_reason: str,
) -> CandidatePolicyEntry:
    if isinstance(entry, CandidatePolicyEntry):
        return entry
    if isinstance(entry, str):
        return CandidatePolicyEntry(full_name=canonical_full_name(entry), reason=default_reason)
    if isinstance(entry, dict):
        full_name = entry.get("full_name") or entry.get("repository")
        if not full_name and entry.get("owner") and entry.get("name"):
            full_name = f"{entry['owner']}/{entry['name']}"
        if not full_name:
            raise ValueError(f"Policy entry is missing a repository name: {entry!r}")
        return CandidatePolicyEntry(
            full_name=canonical_full_name(str(full_name)),
            reason=str(entry.get("reason") or default_reason),
            source=str(entry["source"]) if entry.get("source") else None,
        )
    raise ValueError(f"Unsupported policy entry: {entry!r}")


def selection_reason_for_repo(
    repo: dict[str, Any],
    *,
    selected: bool,
    decision: str,
    min_score: int | None,
    policy: CandidateSelectionPolicy,
    limited_out: bool = False,
) -> dict[str, Any]:
    full_name = repo_full_name(repo)
    score = repo.get("score", 0)
    allow_entry = policy.allow_entry(full_name)
    suppression_entry = policy.suppression_entry(full_name)

    reasons = []
    if suppression_entry is not None:
        reasons.append(
            policy_reason(
                "suppressed",
                suppression_entry.reason,
                source=suppression_entry.source,
            )
        )
        if allow_entry is not None:
            reasons.append(policy_reason("suppression_precedence", "suppression overrides allowlist"))
    elif allow_entry is not None:
        reasons.append(
            policy_reason(
                "allowlisted",
                allow_entry.reason,
                source=allow_entry.source,
            )
        )
        if min_score is not None and score < min_score:
            reasons.append(
                policy_reason(
                    "allowlist_score_override",
                    f"score {score} is below min_score {min_score}",
                )
            )
    elif min_score is not None and score < min_score:
        reasons.append(policy_reason("below_min_score", f"score {score} is below min_score {min_score}"))
    elif min_score is not None:
        reasons.append(policy_reason("score_eligible", f"score {score} meets min_score {min_score}"))
    else:
        reasons.append(policy_reason("score_ranked", f"score {score} ranked for dry-run selection"))

    if limited_out:
        reasons.append(policy_reason("limit_excluded", "candidate ranked outside the requested limit"))

    return {
        "source_full_name": full_name,
        "score": score,
        "recommended_mode": repo.get("recommended_mode", "DownstreamAssured"),
        "selected": selected,
        "decision": decision,
        "reasons": reasons,
    }


def policy_reason(code: str, message: str, *, source: str | None = None) -> dict[str, Any]:
    reason = {
        "code": code,
        "message": message,
    }
    if source:
        reason["source"] = source
    return reason


def repo_full_name(repo: dict[str, Any]) -> str:
    return f"{repo['owner']}/{repo['name']}"


def normalize_full_name(full_name: str) -> str:
    owner, name = split_full_name(full_name)
    return repo_key(owner, name)


def canonical_full_name(full_name: str) -> str:
    owner, name = split_full_name(full_name)
    return f"{owner}/{name}"


def split_full_name(full_name: str) -> tuple[str, str]:
    parts = full_name.strip().split("/", maxsplit=1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Repository name must be owner/name: {full_name!r}")
    return parts[0], parts[1]
