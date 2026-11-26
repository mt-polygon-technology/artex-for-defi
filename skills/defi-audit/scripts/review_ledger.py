#!/usr/bin/env python3
"""Persist per-card review evidence and semantic coverage for a catalog selection.

The ledger records analysis activity. It never treats an empty finding list, a
successful tool exit, or a high code-coverage percentage as proof of security.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import catalog

try:
    import fcntl
except ImportError:  # Windows local runs
    fcntl = None
    import msvcrt


EVIDENCE_STATUSES = (
    "untested", "hypothesis", "statically_supported", "reproduced",
    "confirmed", "refuted", "blocked", "not_applicable",
)
SELECTION_STATUSES = ("selected", "deselected", "blocked")


class LedgerError(ValueError):
    """Invalid ledger or update."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LedgerError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise LedgerError(f"{path} must contain a JSON object")
    return data


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=".review-ledger-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def _write_lock(path: Path):
    """Serialize read/modify/replace operations from concurrent workers."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with lock_path.open("a+b") as lock:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        else:
            lock.seek(0)
            if lock.read(1) == b"":
                lock.seek(0)
                lock.write(b"\0")
                lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            else:
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def _empty_coverage() -> dict[str, Any]:
    return {
        "actor_entrypoint": {},
        "successful_transitions": {},
        "reverts": {},
        "boundary_states": {},
    }


def validate_selection(selection: dict[str, Any], catalog_data: tuple) -> None:
    cards, sources, rules, _ = catalog_data
    if selection.get("catalog_schema_version") != cards["schema_version"]:
        raise LedgerError("selection catalog version differs from installed catalog")
    settings = selection.get("selection")
    rows = selection.get("ledger")
    if not isinstance(settings, dict) or not isinstance(rows, list):
        raise LedgerError("selection lacks settings or full ledger")
    expected_ids = [card["id"] for card in cards["cards"]]
    if [row.get("id") for row in rows if isinstance(row, dict)] != expected_ids:
        raise LedgerError("selection must contain each catalog ID once in catalog order")
    for row in rows:
        if row.get("status") not in SELECTION_STATUSES or not isinstance(row.get("reason"), str) or not row["reason"]:
            raise LedgerError(f"invalid selection status/reason for {row.get('id')}")
    blocks = {row["id"]: row["reason"] for row in rows if row["status"] == "blocked"}
    try:
        recomputed = catalog.select_cards(cards, sources, rules,
            track=settings["track"], protocol=settings["protocol"],
            features=set(settings["features"]), max_cards=settings["max_cards"], blocks=blocks)
    except (KeyError, TypeError, catalog.CatalogError) as exc:
        raise LedgerError(f"invalid selection settings: {exc}") from exc
    if rows != recomputed["ledger"] or selection.get("counts") != recomputed["counts"]:
        raise LedgerError("selection ledger does not match installed catalog rules")
    selected_ids = [card.get("id") for card in selection.get("selected_cards", [])]
    if selected_ids != [card["id"] for card in recomputed["selected_cards"]]:
        raise LedgerError("selected card list does not match full ledger")


def initialize(selection: dict[str, Any], catalog_data: tuple) -> dict[str, Any]:
    validate_selection(selection, catalog_data)
    cards, _, _, version = catalog_data
    cards_by_id = {card["id"]: card for card in cards["cards"]}
    now = _now()
    review_cards = []
    for row in selection["ledger"]:
        source = cards_by_id[row["id"]]
        is_blocked = row["status"] == "blocked"
        review_cards.append({
            "id": row["id"], "title": source["title"], "track": source["track"],
            "selection_status": row["status"], "selection_reason": row["reason"],
            "evidence_status": "blocked" if is_blocked else "untested",
            "reason": row["reason"] if is_blocked else "",
            "evidence_artifacts": [],
            "verified_artifacts": [],
            "evidence_record_ref": None,
            "evidence_record_root": None,
            "semantic_coverage": _empty_coverage(),
            "coverage_observations": [],
            "updated_at": now,
        })
    return {
        "schema_version": "1.0", "catalog_schema_version": cards["schema_version"],
        "catalog_sha256": version["files"]["detector_catalog.json"],
        "selection": selection["selection"],
        "created_at": now, "updated_at": now,
        "notice": "No project safety conclusion follows from zero findings or incomplete review coverage.",
        "cards": review_cards,
    }


def _validate_counts(counts: dict[str, Any], label: str) -> None:
    if not isinstance(counts, dict):
        raise LedgerError(f"{label} must be an object")
    for key, value in counts.items():
        if not isinstance(key, str) or not key or type(value) is not int or value < 0:
            raise LedgerError(f"invalid counter in {label}")


def _aggregate_observations(observations: list[dict[str, Any]], cid: str) -> dict[str, Any]:
    coverage = _empty_coverage()
    for observation in observations:
        if not isinstance(observation, dict):
            raise LedgerError(f"invalid coverage observation for {cid}")
        actor, entrypoint = observation.get("actor"), observation.get("entrypoint")
        outcome, count = observation.get("outcome"), observation.get("count")
        artifact, boundaries = observation.get("artifact"), observation.get("boundaries")
        if (not isinstance(actor, str) or not actor or not isinstance(entrypoint, str) or not entrypoint
                or outcome not in ("success", "revert") or type(count) is not int or count <= 0
                or not isinstance(artifact, str) or not artifact.strip()
                or not isinstance(boundaries, list) or any(not isinstance(b, str) or not b.strip() for b in boundaries)):
            raise LedgerError(f"invalid coverage observation for {cid}")
        pair = coverage["actor_entrypoint"].setdefault(actor, {}).setdefault(entrypoint, {"success": 0, "revert": 0})
        pair[outcome] += count
        if outcome == "success":
            transition = observation.get("transition") or entrypoint
            if not isinstance(transition, str):
                raise LedgerError(f"invalid transition label for {cid}")
            coverage["successful_transitions"][transition] = coverage["successful_transitions"].get(transition, 0) + count
        else:
            revert_reason = observation.get("revert_reason") or entrypoint
            if not isinstance(revert_reason, str):
                raise LedgerError(f"invalid revert label for {cid}")
            coverage["reverts"][revert_reason] = coverage["reverts"].get(revert_reason, 0) + count
        for boundary in dict.fromkeys(boundaries):
            coverage["boundary_states"][boundary] = coverage["boundary_states"].get(boundary, 0) + count
    return coverage


def _verify_record_ref(ref: str, artifact_root: Path, status: str, cid: str) -> None:
    try:
        import evidence

        artifact = evidence.artifact_ref(ref, artifact_root)
        record = evidence.read_json(artifact.path)
        errors, _ = evidence.validate_record(record, artifact_root)
    except (OSError, ValueError) as exc:
        raise LedgerError(f"structured evidence record is invalid for {cid}: {exc}") from exc
    if errors:
        raise LedgerError(f"structured evidence record is invalid for {cid}: {'; '.join(errors[:4])}")
    if record.get("status") != status:
        raise LedgerError(f"structured evidence status {record.get('status')!r} does not match {status!r}")
    if cid not in record.get("detector_ids", []):
        raise LedgerError(f"structured evidence record does not name detector {cid}")


def _verified_artifact(ref: str, artifact_root: Path) -> tuple[str, str]:
    try:
        import evidence

        root = artifact_root.resolve(strict=True)
        evidence.artifact_ref(ref, root)
    except (OSError, ValueError) as exc:
        raise LedgerError(f"artifact must be a verified path#sha256 beneath root: {exc}") from exc
    return ref, str(root)


def _add_verified_artifact(row: dict[str, Any], ref: str, root: str) -> None:
    pair = {"ref": ref, "root": root}
    if pair not in row["verified_artifacts"]:
        row["verified_artifacts"].append(pair)
    if ref not in row["evidence_artifacts"]:
        row["evidence_artifacts"].append(ref)


def _record_ref(record: Path, artifact_root: Path, status: str, cid: str) -> tuple[str, str]:
    try:
        # Resolve both sides before comparing: on macOS a temporary directory
        # below /var is commonly reported as /private/var, so an unresolved
        # record path can look unrelated to its already-resolved artifact root.
        root = artifact_root.resolve(strict=True)
        candidate = (record if record.is_absolute() else root / record).resolve(strict=True)
        relative = candidate.relative_to(root)
        blob = candidate.read_bytes()
    except (OSError, ValueError) as exc:
        raise LedgerError(f"record must be a file beneath artifact root: {exc}") from exc
    ref = relative.as_posix() + "#sha256=" + hashlib.sha256(blob).hexdigest()
    _verify_record_ref(ref, root, status, cid)
    return ref, str(root)


def validate_ledger(ledger: dict[str, Any], catalog_data: tuple) -> None:
    cards, sources, rules, version = catalog_data
    if ledger.get("schema_version") != "1.0" or ledger.get("catalog_sha256") != version["files"]["detector_catalog.json"]:
        raise LedgerError("ledger version/catalog hash differs from installed catalog")
    rows = ledger.get("cards")
    if not isinstance(rows, list) or [row.get("id") for row in rows if isinstance(row, dict)] != [card["id"] for card in cards["cards"]]:
        raise LedgerError("review ledger must contain each catalog ID once in order")
    settings = ledger.get("selection")
    if not isinstance(settings, dict):
        raise LedgerError("review ledger lacks selection settings")
    blocks = {row["id"]: row["selection_reason"] for row in rows if row.get("selection_status") == "blocked"}
    try:
        expected = catalog.select_cards(cards, sources, rules, track=settings["track"],
            protocol=settings["protocol"], features=set(settings["features"]),
            max_cards=settings["max_cards"], blocks=blocks)
    except (KeyError, TypeError, catalog.CatalogError) as exc:
        raise LedgerError(f"invalid persisted selection: {exc}") from exc
    for row, expected_row in zip(rows, expected["ledger"]):
        if row["selection_status"] != expected_row["status"] or row["selection_reason"] != expected_row["reason"]:
            raise LedgerError(f"selection status/reason changed for {row['id']}")
    for row in rows:
        cid = row["id"]
        if row.get("selection_status") not in SELECTION_STATUSES or not isinstance(row.get("selection_reason"), str) or not row["selection_reason"]:
            raise LedgerError(f"invalid selection state for {cid}")
        state = row.get("evidence_status")
        if state not in EVIDENCE_STATUSES:
            raise LedgerError(f"invalid evidence state for {cid}")
        if state in ("blocked", "not_applicable") and not row.get("reason"):
            raise LedgerError(f"{state} requires a reason for {cid}")
        artifacts = row.get("evidence_artifacts")
        if not isinstance(artifacts, list) or any(not isinstance(a, str) or not a.strip() for a in artifacts):
            raise LedgerError(f"invalid artifact list for {cid}")
        if state in ("statically_supported", "reproduced", "confirmed") and not artifacts:
            raise LedgerError(f"{state} requires an evidence artifact for {cid}")
        record_ref, record_root = row.get("evidence_record_ref"), row.get("evidence_record_root")
        if state in ("reproduced", "confirmed"):
            if not isinstance(record_ref, str) or not isinstance(record_root, str) or record_ref not in artifacts:
                raise LedgerError(f"{state} requires a hashed structured record for {cid}")
            _verify_record_ref(record_ref, Path(record_root), state, cid)
        elif record_ref is not None or record_root is not None:
            raise LedgerError(f"unpromoted status has an active structured record for {cid}")
        coverage = row.get("semantic_coverage")
        if not isinstance(coverage, dict) or set(coverage) != set(_empty_coverage()):
            raise LedgerError(f"invalid semantic coverage shape for {cid}")
        actor_entrypoint = coverage["actor_entrypoint"]
        if not isinstance(actor_entrypoint, dict):
            raise LedgerError(f"invalid actor-entrypoint counters for {cid}")
        for actor, entrypoints in actor_entrypoint.items():
            if not isinstance(actor, str) or not actor or not isinstance(entrypoints, dict):
                raise LedgerError(f"invalid actor-entrypoint counters for {cid}")
            for entrypoint, counts in entrypoints.items():
                if not isinstance(entrypoint, str) or not entrypoint or not isinstance(counts, dict) or set(counts) != {"success", "revert"}:
                    raise LedgerError(f"invalid actor-entrypoint counters for {cid}")
                _validate_counts(counts, f"{cid} actor-entrypoint")
        for name in ("successful_transitions", "reverts", "boundary_states"):
            _validate_counts(coverage[name], f"{cid} {name}")
        observations = row.get("coverage_observations")
        if not isinstance(observations, list):
            raise LedgerError(f"invalid coverage observations for {cid}")
        if coverage != _aggregate_observations(observations, cid):
            raise LedgerError(f"semantic coverage counters do not match observations for {cid}")
        if any(observation["artifact"] not in artifacts for observation in observations):
            raise LedgerError(f"coverage observation artifact missing from evidence list for {cid}")


def _card(ledger: dict[str, Any], cid: str) -> dict[str, Any]:
    for row in ledger["cards"]:
        if row["id"] == cid:
            return row
    raise LedgerError(f"unknown detector ID: {cid}")


def set_status(ledger: dict[str, Any], cid: str, status: str, reason: str = "",
               artifacts: list[str] | None = None, record: Path | None = None,
               artifact_root: Path | None = None) -> None:
    row = _card(ledger, cid)
    if status not in EVIDENCE_STATUSES:
        raise LedgerError(f"unsupported evidence status: {status}")
    if row["selection_status"] != "selected" and status not in ("untested", "blocked", "not_applicable"):
        raise LedgerError(f"{cid} was not selected; reselect before promoting evidence")
    reason = reason.strip()
    if status in ("blocked", "not_applicable", "refuted") and not reason:
        raise LedgerError(f"{status} requires an explicit reason")
    record_info = None
    if status in ("reproduced", "confirmed"):
        if record is None or artifact_root is None:
            raise LedgerError(f"{status} requires --record and --artifact-root, not an arbitrary artifact string")
        record_info = _record_ref(record, artifact_root, status, cid)
    elif record is not None or artifact_root is not None:
        raise LedgerError("--record and --artifact-root apply only to reproduced/confirmed")
    if status == "untested":
        row["reason"] = ""
    else:
        new_artifacts = [artifact.strip() for artifact in (artifacts or [])]
        if any(not artifact for artifact in new_artifacts):
            raise LedgerError("artifact references must be nonempty")
        if record_info is not None:
            new_artifacts.append(record_info[0])
        row["evidence_artifacts"] = list(dict.fromkeys(row["evidence_artifacts"] + new_artifacts))
        row["reason"] = reason or row["reason"]
    if status in ("statically_supported", "reproduced", "confirmed") and not row["evidence_artifacts"]:
        raise LedgerError(f"{status} requires at least one evidence artifact")
    row["evidence_record_ref"] = record_info[0] if record_info else None
    row["evidence_record_root"] = record_info[1] if record_info else None
    row["evidence_status"] = status
    row["updated_at"] = ledger["updated_at"] = _now()


def record_coverage(
    ledger: dict[str, Any], cid: str, *, actor: str, entrypoint: str,
    outcome: str, transition: str = "", revert_reason: str = "",
    boundaries: list[str] | None = None, count: int = 1, artifact: str,
) -> None:
    row = _card(ledger, cid)
    if row["selection_status"] != "selected":
        raise LedgerError(f"{cid} was not selected for this review")
    if outcome not in ("success", "revert") or type(count) is not int or count <= 0:
        raise LedgerError("outcome must be success/revert and count must be positive")
    actor, entrypoint, transition, revert_reason = (v.strip() for v in (actor, entrypoint, transition, revert_reason))
    artifact = artifact.strip()
    if not actor or not entrypoint or not artifact or any(not item.strip() for item in (boundaries or [])):
        raise LedgerError("actor, entrypoint, boundary labels and observation artifact must be nonempty")
    row["coverage_observations"].append({
        "actor": actor, "entrypoint": entrypoint, "outcome": outcome,
        "transition": transition, "revert_reason": revert_reason,
        "boundaries": list(dict.fromkeys(boundaries or [])), "count": count,
        "artifact": artifact, "recorded_at": _now(),
    })
    row["semantic_coverage"] = _aggregate_observations(row["coverage_observations"], cid)
    if artifact not in row["evidence_artifacts"]:
        row["evidence_artifacts"].append(artifact)
    row["updated_at"] = ledger["updated_at"] = _now()


def summarize(ledger: dict[str, Any]) -> dict[str, Any]:
    states = Counter(row["evidence_status"] for row in ledger["cards"])
    selection = Counter(row["selection_status"] for row in ledger["cards"])
    selected = [row for row in ledger["cards"] if row["selection_status"] == "selected"]
    untested = [row["id"] for row in selected if row["evidence_status"] == "untested"]
    no_success = [row["id"] for row in selected if sum(row["semantic_coverage"]["successful_transitions"].values()) == 0]
    return {
        "total_cards": len(ledger["cards"]), "selection_counts": dict(selection),
        "evidence_status_counts": {status: states[status] for status in EVIDENCE_STATUSES},
        "selected_untested_ids": untested,
        "selected_without_successful_transition_ids": no_success,
        "confirmed_count": states["confirmed"],
        "security_conclusion": "not_established",
        "notice": ledger["notice"],
    }


def render_text(ledger: dict[str, Any]) -> str:
    summary = summarize(ledger)
    out = [f"DeFi review ledger: {summary['total_cards']} cards",
           "Evidence states: " + ", ".join(f"{key}={value}" for key, value in summary["evidence_status_counts"].items()),
           "Selected untested: " + (", ".join(summary["selected_untested_ids"]) or "none"),
           "Selected with zero successful transitions: " + (", ".join(summary["selected_without_successful_transition_ids"]) or "none"),
           "Security conclusion: not established. Zero findings never means pass."]
    for row in ledger["cards"]:
        out.append(f"{row['id']} | {row['selection_status']} ({row['selection_reason']}) | {row['evidence_status']}"
                   + (f" | {row['reason']}" if row["reason"] else ""))
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("init", help="initialize a full review ledger from catalog select --format json")
    create.add_argument("--selection", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    status = sub.add_parser("status", help="record a review evidence state")
    status.add_argument("--ledger", type=Path, required=True)
    status.add_argument("--id", required=True)
    status.add_argument("--status", choices=EVIDENCE_STATUSES, required=True)
    status.add_argument("--reason", default="")
    status.add_argument("--artifact", action="append", default=[])
    status.add_argument("--record", type=Path, help="structured finding JSON for reproduced/confirmed")
    status.add_argument("--artifact-root", type=Path, help="root containing record and its hashed evidence artifacts")
    cover = sub.add_parser("cover", help="record observed semantic coverage")
    cover.add_argument("--ledger", type=Path, required=True)
    cover.add_argument("--id", required=True)
    cover.add_argument("--actor", required=True)
    cover.add_argument("--entrypoint", required=True)
    cover.add_argument("--outcome", choices=("success", "revert"), required=True)
    cover.add_argument("--transition", default="")
    cover.add_argument("--revert-reason", default="")
    cover.add_argument("--boundary", action="append", default=[])
    cover.add_argument("--count", type=int, default=1)
    cover.add_argument("--artifact", required=True, help="trace or test-output artifact supporting these observed counts")
    show = sub.add_parser("show", help="show all card states and coverage gaps")
    show.add_argument("--ledger", type=Path, required=True)
    show.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        catalog_data = catalog.load_data()
        if args.command == "init":
            with _write_lock(args.output):
                if args.output.exists():
                    raise LedgerError(f"ledger already exists: {args.output}")
                ledger = initialize(_read(args.selection), catalog_data)
                _atomic_write(args.output, ledger)
            print(f"initialized {len(ledger['cards'])}-card review ledger: {args.output}")
            return 0
        if args.command == "status":
            with _write_lock(args.ledger):
                ledger = _read(args.ledger)
                validate_ledger(ledger, catalog_data)
                set_status(ledger, args.id, args.status, args.reason, args.artifact,
                           args.record, args.artifact_root)
                validate_ledger(ledger, catalog_data)
                _atomic_write(args.ledger, ledger)
            print(f"{args.id}: {args.status}")
        elif args.command == "cover":
            with _write_lock(args.ledger):
                ledger = _read(args.ledger)
                validate_ledger(ledger, catalog_data)
                record_coverage(ledger, args.id, actor=args.actor, entrypoint=args.entrypoint,
                                outcome=args.outcome, transition=args.transition,
                                revert_reason=args.revert_reason, boundaries=args.boundary, count=args.count,
                                artifact=args.artifact)
                validate_ledger(ledger, catalog_data)
                _atomic_write(args.ledger, ledger)
            print(f"{args.id}: {args.actor} × {args.entrypoint} {args.outcome} +{args.count}")
        else:
            ledger = _read(args.ledger)
            validate_ledger(ledger, catalog_data)
            summary = summarize(ledger)
            sys.stdout.write(json.dumps({"summary": summary, "ledger": ledger}, indent=2, ensure_ascii=False) + "\n"
                             if args.format == "json" else render_text(ledger))
        return 0
    except (catalog.CatalogError, LedgerError) as exc:
        print(f"review ledger error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
