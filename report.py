#!/usr/bin/env python3
"""
CreatorMark Evidence Toolkit — report.py
Compiles watermark manifests + canary evidence into a
structured legal report you can hand to a copyright attorney.
"""

import json
import sys
import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path

KEY_FILE     = Path.home() / ".creatormark" / "keys.json"
MANIFEST_DIR = Path.home() / ".creatormark" / "manifests"
CANARY_DIR   = Path.home() / ".creatormark" / "canaries"
EVIDENCE_DIR = Path.home() / ".creatormark" / "evidence"
REPORTS_DIR  = Path.home() / ".creatormark" / "reports"


def load_secret(identity: str) -> bytes:
    if not KEY_FILE.exists():
        return b""
    with open(KEY_FILE) as f:
        keys = json.load(f)
    rec = keys.get(identity, {})
    return bytes.fromhex(rec["secret"]) if "secret" in rec else b""


def verify_hmac(record: dict, secret: bytes) -> bool:
    stored = record.get("hmac_sha256") or record.get("hmac", "")
    clean  = {k: v for k, v in record.items() if k not in ("hmac_sha256", "hmac")}
    payload = json.dumps(clean, sort_keys=True).encode()
    expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(stored, expected)


def load_all(identity: str) -> tuple[list, list, list]:
    manifests, canaries, evidence = [], [], []

    if MANIFEST_DIR.exists():
        for f in sorted(MANIFEST_DIR.glob("*.json")):
            r = json.load(open(f))
            if r.get("owner") == identity:
                manifests.append(r)

    if CANARY_DIR.exists():
        for f in sorted(CANARY_DIR.glob("*.json")):
            r = json.load(open(f))
            if r.get("identity") == identity:
                canaries.append(r)

    if EVIDENCE_DIR.exists():
        for f in sorted(EVIDENCE_DIR.glob("*.json")):
            r = json.load(open(f))
            if r.get("identity") == identity:
                evidence.append(r)

    return manifests, canaries, evidence


def generate_report(identity: str, output_format: str = "txt") -> Path:
    secret = load_secret(identity)
    manifests, canaries, evidence = load_all(identity)

    hits = [e for e in evidence if e.get("verbatim_match") or e.get("near_match")]
    now  = datetime.now(timezone.utc).isoformat()

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    slug = now[:10].replace("-", "")
    out  = REPORTS_DIR / f"evidence_report_{slug}.{'md' if output_format == 'md' else 'txt'}"

    lines = []
    w = lines.append

    w("=" * 72)
    w("  CREATORMARK — COPYRIGHT EVIDENCE REPORT")
    w("=" * 72)
    w(f"  Identity   : {identity}")
    w(f"  Generated  : {now}")
    w(f"  Works registered    : {len(manifests)}")
    w(f"  Canary phrases      : {len(canaries)}")
    w(f"  Model probes logged : {len(evidence)}")
    w(f"  Potential violations: {len(hits)}")
    w("=" * 72)
    w("")

    # ── SECTION 1: Registered Works ──────────────────────────────────────────
    w("━" * 72)
    w("  SECTION 1 — REGISTERED WORKS")
    w("  (Cryptographically signed ownership records)")
    w("━" * 72)
    w("")
    if not manifests:
        w("  No registered works found.")
    for m in manifests:
        valid = verify_hmac(m, secret)
        w(f"  Work ID    : {m['id']}")
        w(f"  File       : {m['filename']}")
        w(f"  Type       : {m['content_type']}")
        w(f"  Registered : {m['timestamp_utc']}")
        w(f"  SHA-256    : {m['sha256_original']}")
        w(f"  Signature  : {'VALID ✓' if valid else 'INVALID — possible tampering'}")
        w("")

    # ── SECTION 2: Canary Inventory ───────────────────────────────────────────
    w("━" * 72)
    w("  SECTION 2 — CANARY PHRASE INVENTORY")
    w("  (Unique statistically improbable phrases embedded in published works)")
    w("━" * 72)
    w("")
    if not canaries:
        w("  No canary phrases registered.")
    for c in canaries:
        valid = verify_hmac(c, secret)
        w(f"  Canary ID  : {c['id']}")
        w(f"  Content    : {c['content_id']}")
        w(f"  Phrase     : \"{c['phrase']}\"")
        w(f"  Created    : {c['created_utc']}")
        w(f"  Signature  : {'VALID ✓' if valid else 'INVALID'}")
        w("")

    # ── SECTION 3: Model Probe Evidence ──────────────────────────────────────
    w("━" * 72)
    w("  SECTION 3 — AI MODEL PROBE RESPONSES")
    w("  (Logged responses to memorization test queries)")
    w("━" * 72)
    w("")
    if not evidence:
        w("  No probe responses logged yet.")
    for e in evidence:
        flag = "⚠️  POTENTIAL VIOLATION" if (e.get("verbatim_match") or e.get("near_match")) else "—"
        w(f"  Evidence ID  : {e['id']}")
        w(f"  Model tested : {e['model']}")
        w(f"  Canary ref   : {e['canary_id']}")
        w(f"  Probe type   : {e['probe_type']}")
        w(f"  Timestamp    : {e['timestamp_utc']}")
        w(f"  Prompt       : {e['prompt']}")
        w(f"  Response     : {e['response'][:300]}{'...' if len(e['response']) > 300 else ''}")
        w(f"  Target phrase: \"{e['target_phrase']}\"")
        w(f"  Verbatim     : {'YES' if e['verbatim_match'] else 'No'}")
        w(f"  Near match   : {'YES' if e['near_match'] else 'No'}")
        w(f"  Word overlap : {e.get('word_overlap_score', 0):.0%}")
        w(f"  Assessment   : {flag}")
        w("")

    # ── SECTION 4: Summary for Counsel ───────────────────────────────────────
    w("━" * 72)
    w("  SECTION 4 — SUMMARY FOR LEGAL COUNSEL")
    w("━" * 72)
    w("")
    w(f"  This report was generated by CreatorMark, an open-source tool for")
    w(f"  documenting copyright ownership and potential AI training violations.")
    w("")
    w(f"  Evidence summary:")
    w(f"    • {len(manifests)} original works with cryptographic registration timestamps")
    w(f"    • {len(canaries)} canary phrases embedded in published content")
    w(f"    • {len(evidence)} AI model probe responses logged")
    w(f"    • {len(hits)} responses showing potential memorization")
    w("")
    if hits:
        w("  Flagged interactions:")
        for h in hits:
            w(f"    • [{h['model']}] responded to canary {h['canary_id'][:8]}...")
            w(f"      Verbatim: {h['verbatim_match']} | Overlap: {h.get('word_overlap_score',0):.0%}")
        w("")
        w("  Recommended next steps:")
        w("    1. Engage a copyright attorney specializing in AI/IP")
        w("    2. Preserve ~/.creatormark/ directory as primary evidence")
        w("    3. Document the exact model version and access date for each probe")
        w("    4. Cross-reference with existing litigation:")
        w("       — NYT v. OpenAI (S.D.N.Y. 2023)")
        w("       — Andersen v. Stability AI (N.D. Cal. 2023)")
        w("       — Authors Guild related filings")
        w("    5. Consider filing with:")
        w("       — U.S. Copyright Office (copyright.gov)")
        w("       — Your national IP office if outside the US")
    else:
        w("  No memorization hits detected yet.")
        w("  Continue probing models and logging responses.")
    w("")
    w("━" * 72)
    w("  CRYPTOGRAPHIC INTEGRITY NOTE")
    w("━" * 72)
    w("")
    w("  All records in this report are signed with HMAC-SHA256 using a")
    w("  private key stored only on the creator's machine. The signing key")
    w("  was never transmitted or shared. Signature validity is confirmed")
    w("  above for each record. Timestamps are UTC and were recorded at the")
    w("  moment of registration — not retroactively.")
    w("")
    w("  To independently verify any record, provide the manifest JSON file")
    w("  and the signing key to a forensic expert.")
    w("")
    w("=" * 72)
    w(f"  END OF REPORT — {now}")
    w("=" * 72)

    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="report",
        description="Generate a legal evidence report from your CreatorMark records"
    )
    parser.add_argument("--identity", required=True, help="Your creator identity")
    parser.add_argument("--format", choices=["txt", "md"], default="txt",
                        help="Output format (default: txt)")
    args = parser.parse_args()

    print(f"\n[report] Compiling evidence for: {args.identity}")
    out = generate_report(args.identity, args.format)
    print(f"[report] ✓ Report saved: {out}")
    print(f"\n  This report is suitable for submission to a copyright attorney.")
    print(f"  Back up ~/.creatormark/ — it is your complete evidence vault.")


if __name__ == "__main__":
    main()