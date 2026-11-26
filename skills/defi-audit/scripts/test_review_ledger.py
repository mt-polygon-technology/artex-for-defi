"""Review-ledger tests for evidence gates and non-vacuous semantic coverage."""

from __future__ import annotations

import json
import copy
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import catalog
import review_ledger
import test_evidence


class ReviewLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = catalog.load_data()

    def fresh(self, *, blocked: bool = False):
        cards, sources, rules, _ = self.data
        selection = catalog.select_cards(
            cards, sources, rules, track="evm", protocol="lending",
            features={"oracle"}, max_cards=15,
            blocks={"EVM-01": "compiler missing"} if blocked else {},
        )
        return review_ledger.initialize(selection, self.data)

    def test_all_cards_retained_and_zero_findings_is_not_pass(self) -> None:
        ledger = self.fresh()
        self.assertEqual(len(ledger["cards"]), 43)
        self.assertTrue(all(row["evidence_status"] == "untested" for row in ledger["cards"]))
        summary = review_ledger.summarize(ledger)
        self.assertEqual(summary["confirmed_count"], 0)
        self.assertEqual(summary["security_conclusion"], "not_established")
        self.assertEqual(len(summary["selected_untested_ids"]), 15)
        self.assertEqual(len(summary["selected_without_successful_transition_ids"]), 15)

    def test_blocked_selection_carries_reason_into_review(self) -> None:
        ledger = self.fresh(blocked=True)
        row = next(row for row in ledger["cards"] if row["id"] == "EVM-01")
        self.assertEqual(row["selection_status"], "blocked")
        self.assertEqual(row["evidence_status"], "blocked")
        self.assertEqual(row["reason"], "compiler missing")
        review_ledger.validate_ledger(ledger, self.data)

    def test_status_promotion_requires_artifact_and_non_applicability_reason(self) -> None:
        ledger = self.fresh()
        with self.assertRaisesRegex(review_ledger.LedgerError, "artifact"):
            review_ledger.set_status(ledger, "ECO-04", "statically_supported")
        with self.assertRaisesRegex(review_ledger.LedgerError, "--record"):
            review_ledger.set_status(ledger, "ECO-04", "reproduced")
        with self.assertRaisesRegex(review_ledger.LedgerError, "--record"):
            review_ledger.set_status(ledger, "ECO-04", "confirmed", artifacts=["fake.txt"])
        with self.assertRaisesRegex(review_ledger.LedgerError, "reason"):
            review_ledger.set_status(ledger, "ECO-04", "not_applicable")

    def test_reproduced_and_confirmed_require_valid_matching_structured_record(self) -> None:
        fixture = test_evidence.EvidenceTests("test_reproduced_and_confirmed_gates")
        fixture.setUp()
        try:
            ledger = self.fresh()
            record = copy.deepcopy(fixture.record)
            record["detector_ids"] = ["ECO-04"]
            path = fixture.root / "finding.json"
            path.write_text(json.dumps(record))
            review_ledger.set_status(ledger, "ECO-04", "reproduced", record=path,
                                     artifact_root=fixture.root, reason="local counterexample")
            review_ledger.validate_ledger(ledger, self.data)
            row = next(row for row in ledger["cards"] if row["id"] == "ECO-04")
            self.assertRegex(row["evidence_record_ref"], r"finding\.json#sha256=[0-9a-f]{64}")
            self.assertIn(row["evidence_record_ref"], row["evidence_artifacts"])
            self.assertEqual(row["reason"], "local counterexample")
            with self.assertRaisesRegex(review_ledger.LedgerError, "does not match"):
                review_ledger.set_status(ledger, "ECO-04", "confirmed", record=path, artifact_root=fixture.root)
            other = copy.deepcopy(record)
            other["detector_ids"] = ["EVM-01"]
            other_path = fixture.root / "other.json"
            other_path.write_text(json.dumps(other))
            with self.assertRaisesRegex(review_ledger.LedgerError, "does not name detector"):
                review_ledger.set_status(ledger, "ECO-04", "reproduced", record=other_path, artifact_root=fixture.root)
            confirmed = copy.deepcopy(record)
            confirmed["status"] = "confirmed"
            independent_log = test_evidence.put(fixture.root, "logs/independent.log", b"[PASS] test_Repro independent\nSuite result: ok. 1 passed; 0 failed\n")
            independent_receipt = test_evidence.put(fixture.root, "independent.json", {
                "kind": "independent_replay", "command": fixture.command, "test_id": "test_Repro",
                "manifest_sha256": confirmed["environment"]["environment_manifest_sha256"],
                "exit_code": 0, "result": "pass", "log_ref": independent_log,
                "verifier": "separate-reviewer", "method": "independent_replay",
            })
            confirmed["evidence"]["independent_verification"] = {
                "performed": True, "method": "independent_replay", "verifier": "separate-reviewer",
                "artifacts": [independent_log, independent_receipt],
            }
            confirmed_path = fixture.root / "confirmed.json"
            confirmed_path.write_text(json.dumps(confirmed))
            review_ledger.set_status(ledger, "ECO-04", "confirmed", record=confirmed_path,
                                     artifact_root=fixture.root, reason="independently replayed")
            review_ledger.validate_ledger(ledger, self.data)
            self.assertEqual(row["evidence_status"], "confirmed")
        finally:
            fixture.doCleanups()

    def test_record_path_accepts_resolved_and_unresolved_root_aliases(self) -> None:
        fixture = test_evidence.EvidenceTests("test_reproduced_and_confirmed_gates")
        fixture.setUp()
        try:
            record = copy.deepcopy(fixture.record)
            record["detector_ids"] = ["ECO-04"]
            path = fixture.root / "finding.json"
            path.write_text(json.dumps(record))
            # A caller may pass an unresolved path (for example, /var on macOS)
            # while the artifact root has already been resolved by the ledger.
            unresolved_root = Path(str(fixture.root))
            ref, root = review_ledger._record_ref(path, unresolved_root, "reproduced", "ECO-04")
            self.assertRegex(ref, r"finding\.json#sha256=[0-9a-f]{64}")
            self.assertEqual(root, str(fixture.root.resolve(strict=True)))
        finally:
            fixture.doCleanups()

    def test_selected_only_and_observed_counters(self) -> None:
        ledger = self.fresh()
        with self.assertRaisesRegex(review_ledger.LedgerError, "not selected"):
            review_ledger.record_coverage(ledger, "X06", actor="attacker", entrypoint="borrow", outcome="success", artifact="traces/borrow.json")
        review_ledger.record_coverage(ledger, "ECO-04", actor="attacker", entrypoint="donateToReserves",
                                      outcome="success", transition="reserve_donation",
                                      boundaries=["near_liquidation", "dust_debt"], count=2, artifact="traces/donation.json")
        review_ledger.record_coverage(ledger, "ECO-04", actor="attacker", entrypoint="borrow",
                                      outcome="revert", revert_reason="health_check", count=1, artifact="traces/borrow.json")
        row = next(row for row in ledger["cards"] if row["id"] == "ECO-04")
        coverage = row["semantic_coverage"]
        self.assertEqual(coverage["actor_entrypoint"]["attacker"]["donateToReserves"], {"success": 2, "revert": 0})
        self.assertEqual(coverage["successful_transitions"], {"reserve_donation": 2})
        self.assertEqual(coverage["reverts"], {"health_check": 1})
        self.assertEqual(coverage["boundary_states"], {"near_liquidation": 2, "dust_debt": 2})
        self.assertNotIn("ECO-04", review_ledger.summarize(ledger)["selected_without_successful_transition_ids"])
        review_ledger.validate_ledger(ledger, self.data)
        coverage["successful_transitions"]["reserve_donation"] += 1
        with self.assertRaisesRegex(review_ledger.LedgerError, "do not match observations"):
            review_ledger.validate_ledger(ledger, self.data)

    def test_selection_tampering_and_missing_card_fail_closed(self) -> None:
        cards, sources, rules, _ = self.data
        selection = catalog.select_cards(cards, sources, rules, track="evm", protocol="lending", features=set())
        selection["ledger"][0]["status"] = "deselected"
        with self.assertRaisesRegex(review_ledger.LedgerError, "does not match"):
            review_ledger.initialize(selection, self.data)
        ledger = self.fresh()
        ledger["cards"].pop()
        with self.assertRaisesRegex(review_ledger.LedgerError, "each catalog ID"):
            review_ledger.validate_ledger(ledger, self.data)
        ledger = self.fresh()
        ledger["cards"][0]["selection_status"] = "deselected"
        with self.assertRaisesRegex(review_ledger.LedgerError, "selection status/reason changed"):
            review_ledger.validate_ledger(ledger, self.data)

    def test_cli_persists_updates_and_rejects_overwrite(self) -> None:
        cards, sources, rules, _ = self.data
        selection = catalog.select_cards(cards, sources, rules, track="evm", protocol="vault", features=set())
        with tempfile.TemporaryDirectory() as tmp:
            selection_path = Path(tmp) / "selection.json"
            ledger_path = Path(tmp) / "review.json"
            selection_path.write_text(json.dumps(selection))
            self.assertEqual(review_ledger.main(["init", "--selection", str(selection_path), "--output", str(ledger_path)]), 0)
            self.assertEqual(review_ledger.main(["init", "--selection", str(selection_path), "--output", str(ledger_path)]), 2)
            self.assertEqual(review_ledger.main(["cover", "--ledger", str(ledger_path), "--id", "EVM-01",
                                                 "--actor", "user", "--entrypoint", "withdraw", "--outcome", "success",
                                                 "--boundary", "zero_shares", "--artifact", "traces/withdraw.json"]), 0)
            self.assertEqual(review_ledger.main(["status", "--ledger", str(ledger_path), "--id", "EVM-01",
                                                 "--status", "hypothesis", "--reason", "suspect path"]), 0)
            persisted = json.loads(ledger_path.read_text())
            review_ledger.validate_ledger(persisted, self.data)
            row = persisted["cards"][0]
            self.assertEqual(row["semantic_coverage"]["boundary_states"]["zero_shares"], 1)
            self.assertEqual(row["evidence_status"], "hypothesis")

    def test_concurrent_worker_updates_do_not_lose_coverage(self) -> None:
        cards, sources, rules, _ = self.data
        selection = catalog.select_cards(cards, sources, rules, track="evm", protocol="vault", features=set())
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path = Path(tmp) / "review.json"
            review_ledger._atomic_write(ledger_path, review_ledger.initialize(selection, self.data))
            command = [sys.executable, str(Path(review_ledger.__file__)), "cover", "--ledger", str(ledger_path),
                       "--id", "EVM-01", "--actor", "attacker", "--entrypoint", "withdraw",
                       "--outcome", "success", "--artifact", "traces/withdraw.json"]
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda _: subprocess.run(command, capture_output=True, text=True), range(12)))
            self.assertTrue(all(result.returncode == 0 for result in results), [result.stderr for result in results])
            persisted = json.loads(ledger_path.read_text())
            review_ledger.validate_ledger(persisted, self.data)
            row = persisted["cards"][0]
            self.assertEqual(row["semantic_coverage"]["actor_entrypoint"]["attacker"]["withdraw"]["success"], 12)
            self.assertEqual(len(row["coverage_observations"]), 12)


if __name__ == "__main__":
    unittest.main()
