"""Evidence pack provenance (item 4): signed checkpoint, and that the pack ships together."""

import json

from govagent.evidence import verify_evidence_pack, write_evidence
from govagent.identity import KeyRing


def test_pack_is_checkpointed_and_verifies(make_env, tmp_path):
    env = make_env()
    env.audit.record("tool_requested", run_id="r1", tool="get_positions")
    env.audit.record("tool_executed", run_id="r1", tool="get_positions", outcome="executed")
    keys = KeyRing()
    out = write_evidence(env, tmp_path / "pack", "scripted", "scripted", keys=keys)
    summary = json.loads((out / "summary.json").read_text())
    prov = summary["provenance"]
    assert prov["checkpointed"] is True and prov["audit_head"] and prov["checkpoint_signature"]
    assert prov["seq_range"] == [1, 2] and prov["policy_sha256"] and prov["abom_sha256"]

    ok, detail = verify_evidence_pack(out, keys.public_keys())
    assert ok and "verified" in detail


def test_pack_without_checkpoint_says_so_plainly(make_env, tmp_path):
    env = make_env()
    env.audit.record("tool_requested", run_id="r1", tool="get_positions")
    out = write_evidence(env, tmp_path / "pack", "scripted", "scripted")  # no keys
    summary = json.loads((out / "summary.json").read_text())
    assert summary["provenance"]["checkpointed"] is False
    ok, detail = verify_evidence_pack(out)
    assert ok and "no checkpoint" in detail


def test_tampering_with_traces_breaks_verification(make_env, tmp_path):
    env = make_env()
    for i in range(3):
        env.audit.record("tool_requested", run_id="r1", tool="get_positions", n=i)
    keys = KeyRing()
    out = write_evidence(env, tmp_path / "pack", "scripted", "scripted", keys=keys)

    lines = (out / "traces.jsonl").read_text().splitlines()
    entry = json.loads(lines[1])
    entry["tool"] = "TAMPERED"
    lines[1] = json.dumps(entry, default=str)
    (out / "traces.jsonl").write_text("\n".join(lines) + "\n")

    ok, detail = verify_evidence_pack(out, keys.public_keys())
    assert not ok and "broken at seq 2" in detail


def test_a_pack_checked_against_a_different_runs_audit_file_is_rejected(make_env, tmp_path):
    """summary.json from one run, traces.jsonl from another: the provenance mismatch is caught even
    though each file is internally perfectly valid on its own."""
    env_a, env_b = make_env(), make_env()
    env_a.audit.record("tool_requested", run_id="run-a", tool="get_positions")
    env_b.audit.record("tool_requested", run_id="run-b", tool="get_client_profile")
    keys = KeyRing()
    out_a = write_evidence(env_a, tmp_path / "pack_a", "scripted", "scripted", keys=keys)
    out_b = write_evidence(env_b, tmp_path / "pack_b", "scripted", "scripted", keys=keys)

    mixed = tmp_path / "mixed"
    mixed.mkdir()
    (mixed / "summary.json").write_text((out_a / "summary.json").read_text())
    (mixed / "traces.jsonl").write_text((out_b / "traces.jsonl").read_text())

    ok, detail = verify_evidence_pack(mixed, keys.public_keys())
    assert not ok and "not shipped together" in detail
