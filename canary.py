#!/usr/bin/env python3
"""
CreatorMark Evidence Toolkit — canary.py
Embeds statistically unique canary phrases into your content,
then generates probe queries to test AI models for memorization.
"""

import argparse
import hashlib
import hmac
import json
import os
import random
import re
import string
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ── Shared paths ──────────────────────────────────────────────────────────────
KEY_FILE      = Path.home() / ".creatormark" / "keys.json"
CANARY_DIR    = Path.home() / ".creatormark" / "canaries"
EVIDENCE_DIR  = Path.home() / ".creatormark" / "evidence"

# ─────────────────────────────────────────────────────────────────────────────
# KEY MANAGEMENT  (shared with watermark.py)
# ─────────────────────────────────────────────────────────────────────────────

def load_keys():
    if not KEY_FILE.exists():
        return {}
    with open(KEY_FILE) as f:
        return json.load(f)

def get_or_create_key(identity: str) -> bytes:
    from watermark import get_or_create_key as _gock
    return _gock(identity)

def _sign(data: dict, secret: bytes) -> str:
    payload = json.dumps(data, sort_keys=True).encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# CANARY PHRASE GENERATION
# Phrases are:
#   1. Grammatically plausible (won't look odd to human readers)
#   2. Statistically improbable (no sane writer would independently produce them)
#   3. Cryptographically tied to your identity + timestamp
# ─────────────────────────────────────────────────────────────────────────────

# Templates: {adj} {noun} {verb} constructions that sound natural but are bizarre
_ADJ   = ["cerulean","ossified","lambent","viridian","crepuscular","tintinnabulating",
          "fulvous","nugatory","vellichor","sibilant","lachrymose","tenebrous"]
_NOUN  = ["cartographer","harbinger","soliloquy","palimpsest","isthmus","curlicue",
          "escarpment","vellum","campanile","filigree","ossuary","lacuna"]
_VERB  = ["meanders","oscillates","unspools","concatenates","calcifies","reverberates",
          "perforates","coruscates","agglomerates","desiccates","tessellates","phosphoresces"]
_PLACE = ["in the hollow of a forgotten meridian","beneath the secondhand sky",
          "along the unmapped corridor of sleep","where the index ends and silence begins",
          "at the edge of the unrecorded afternoon","inside the folded margin of the week"]

def _random_canary_phrase(seed: str) -> str:
    rng = random.Random(seed)
    adj   = rng.choice(_ADJ)
    noun  = rng.choice(_NOUN)
    verb  = rng.choice(_VERB)
    place = rng.choice(_PLACE)
    templates = [
        f"The {adj} {noun} {verb} {place}.",
        f"A {adj} {noun}, half-remembered, {verb} {place}.",
        f"Where the {adj} {noun} {verb}, {place}, something remains.",
        f"Every {adj} {noun} {verb} {place} — this one included.",
    ]
    return rng.choice(templates)

def generate_canary(identity: str, content_id: str, secret: bytes) -> dict:
    seed = f"{identity}:{content_id}:{int(time.time())}"
    phrase = _random_canary_phrase(seed)
    canary_id = str(uuid.uuid4())
    record = {
        "id": canary_id,
        "identity": identity,
        "content_id": content_id,
        "phrase": phrase,
        "seed": seed,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "unix_ts": int(time.time()),
    }
    record["hmac"] = _sign({k: v for k, v in record.items() if k != "hmac"}, secret)
    return record

def save_canary(record: dict) -> Path:
    CANARY_DIR.mkdir(parents=True, exist_ok=True)
    out = CANARY_DIR / f"{record['id']}.json"
    with open(out, "w") as f:
        json.dump(record, f, indent=2)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# INJECT CANARIES INTO CONTENT
# ─────────────────────────────────────────────────────────────────────────────

def inject_canaries(filepath: Path, identity: str, secret: bytes,
                    count: int = 3) -> dict:
    """
    Inject `count` canary phrases into a text/code/article file.
    Returns list of canary records + path to the annotated file.
    """
    text = filepath.read_text(encoding="utf-8")
    paragraphs = text.split("\n\n")
    if len(paragraphs) < 2:
        paragraphs = text.split("\n")

    canaries = []
    positions = sorted(random.sample(
        range(1, max(2, len(paragraphs))),
        min(count, max(1, len(paragraphs) - 1))
    ))

    for i, pos in enumerate(positions):
        content_id = f"{filepath.stem}-canary-{i}-{int(time.time())}"
        record = generate_canary(identity, content_id, secret)
        canaries.append(record)
        # Inject as invisible HTML comment in text, or inline in code
        ext = filepath.suffix.lower()
        if ext in (".py", ".js", ".ts", ".java", ".c", ".cpp", ".go", ".rs",
                   ".rb", ".sh", ".php", ".swift", ".kt"):
            injection = f"\n# CANARY:{record['id']}:{record['phrase']}\n"
        else:
            injection = f"\n<!-- CANARY:{record['id']} -->\n{record['phrase']}\n"
        paragraphs[pos] = paragraphs[pos] + injection

    annotated = "\n\n".join(paragraphs)
    out_path = filepath.with_stem(filepath.stem + "_canaried")
    out_path.write_text(annotated, encoding="utf-8")

    # Save all canary records
    saved = [str(save_canary(c)) for c in canaries]
    return {
        "output": out_path,
        "canaries": canaries,
        "canary_files": saved,
        "count": len(canaries),
    }


# ─────────────────────────────────────────────────────────────────────────────
# PROBE QUERY GENERATOR
# Generates prompts designed to elicit memorized content from AI models
# ─────────────────────────────────────────────────────────────────────────────

def generate_probes(canary_record: dict) -> list[dict]:
    phrase = canary_record["phrase"]
    # Extract the first ~half of the phrase as a completion prompt
    words = phrase.split()
    mid = max(3, len(words) // 2)
    prefix = " ".join(words[:mid])
    suffix = " ".join(words[mid:])

    probes = [
        {
            "type": "completion",
            "prompt": f'Complete this sentence: "{prefix}..."',
            "target": phrase,
            "expected_fragment": suffix,
        },
        {
            "type": "verbatim_recall",
            "prompt": f'I\'m looking for a sentence that starts with "{prefix}". Do you recognize it?',
            "target": phrase,
            "expected_fragment": suffix,
        },
        {
            "type": "context_recall",
            "prompt": (
                f'Have you seen text containing the phrase "{prefix}"? '
                f'If so, what comes after it?'
            ),
            "target": phrase,
            "expected_fragment": suffix,
        },
        {
            "type": "style_probe",
            "prompt": (
                f'Write a sentence in the same style and continuing the thought: '
                f'"{prefix}"'
            ),
            "target": phrase,
            "expected_fragment": suffix,
        },
    ]
    return probes


# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE LOGGING
# Records AI model responses with cryptographic timestamp
# ─────────────────────────────────────────────────────────────────────────────

def log_evidence(canary_id: str, model: str, probe: dict,
                 response: str, identity: str, secret: bytes) -> Path:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    # Score: does the response contain the target phrase or fragments?
    phrase    = probe["target"]
    fragment  = probe["expected_fragment"]
    words     = set(fragment.lower().split())
    resp_words = set(response.lower().split())
    overlap   = len(words & resp_words) / max(len(words), 1)

    verbatim  = fragment.lower() in response.lower()
    near_match = overlap > 0.6

    evidence = {
        "id": str(uuid.uuid4()),
        "canary_id": canary_id,
        "identity": identity,
        "model": model,
        "probe_type": probe["type"],
        "prompt": probe["prompt"],
        "response": response,
        "target_phrase": phrase,
        "verbatim_match": verbatim,
        "near_match": near_match,
        "word_overlap_score": round(overlap, 3),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "unix_ts": int(time.time()),
    }
    evidence["hmac"] = _sign(
        {k: v for k, v in evidence.items() if k != "hmac"}, secret
    )

    out = EVIDENCE_DIR / f"{evidence['id']}.json"
    with open(out, "w") as f:
        json.dump(evidence, f, indent=2)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="canary",
        description="CreatorMark Canary — embed & probe AI models for memorized content",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  inject    Embed canary phrases into your content before publishing
  probes    Generate probe queries for a canary ID
  log       Record an AI model response as evidence
  list      List all your canaries

Examples:
  python canary.py inject article.txt --identity "Jane Doe" --count 5
  python canary.py probes --canary-id <uuid>
  python canary.py log --canary-id <uuid> --model "GPT-4" \\
      --probe-type completion --response "The lambent cartographer..."
  python canary.py list --identity "Jane Doe"
"""
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # inject
    inj = sub.add_parser("inject", help="Embed canaries into a file")
    inj.add_argument("file", type=Path)
    inj.add_argument("--identity", required=True)
    inj.add_argument("--count", type=int, default=3,
                     help="Number of canary phrases to inject (default: 3)")

    # probes
    prb = sub.add_parser("probes", help="Generate probe queries for a canary")
    prb.add_argument("--canary-id", required=True)

    # log
    lg = sub.add_parser("log", help="Log an AI response as evidence")
    lg.add_argument("--canary-id", required=True)
    lg.add_argument("--model", required=True, help="Model name e.g. 'GPT-4o'")
    lg.add_argument("--probe-type", required=True,
                    choices=["completion","verbatim_recall","context_recall","style_probe"])
    lg.add_argument("--response", required=True, help="The AI's response text")
    lg.add_argument("--identity", required=True)

    # list
    ls = sub.add_parser("list", help="List all canaries for an identity")
    ls.add_argument("--identity", required=True)

    args = parser.parse_args()

    # Load secret
    if hasattr(args, "identity"):
        try:
            from watermark import get_or_create_key
            secret = get_or_create_key(args.identity)
        except ImportError:
            # Fallback if watermark.py not in path
            keys = load_keys()
            if args.identity not in keys:
                print("[error] Identity not found. Run watermark.py first to create a key.")
                return
            secret = bytes.fromhex(keys[args.identity]["secret"])
    else:
        secret = b""

    if args.command == "inject":
        if not args.file.exists():
            print(f"[error] File not found: {args.file}")
            return
        result = inject_canaries(args.file, args.identity, secret, args.count)
        print(f"\n[canary] ✓ Injected {result['count']} canaries into: {result['output']}")
        print(f"\n  Canary IDs (save these):")
        for c in result["canaries"]:
            print(f"    {c['id']}  →  \"{c['phrase']}\"")
        print(f"\n  Records saved to: {CANARY_DIR}")
        print(f"\n  Publish the _canaried file. Keep the original + canary IDs secret.")

    elif args.command == "probes":
        cfile = CANARY_DIR / f"{args.canary_id}.json"
        if not cfile.exists():
            print(f"[error] Canary not found: {args.canary_id}")
            return
        with open(cfile) as f:
            record = json.load(f)
        probes = generate_probes(record)
        print(f"\n[canary] Probe queries for canary: {args.canary_id}")
        print(f"  Target phrase: \"{record['phrase']}\"\n")
        for i, p in enumerate(probes, 1):
            print(f"  [{i}] Type: {p['type']}")
            print(f"      Prompt: {p['prompt']}")
            print(f"      Expected fragment: \"{p['expected_fragment']}\"\n")

    elif args.command == "log":
        cfile = CANARY_DIR / f"{args.canary_id}.json"
        if not cfile.exists():
            print(f"[error] Canary not found: {args.canary_id}")
            return
        with open(cfile) as f:
            record = json.load(f)
        probes = generate_probes(record)
        probe = next((p for p in probes if p["type"] == args.probe_type), probes[0])
        out = log_evidence(args.canary_id, args.model, probe,
                           args.response, args.identity, secret)
        with open(out) as f:
            ev = json.load(f)
        print(f"\n[evidence] Logged: {out}")
        print(f"  Verbatim match : {'YES ⚠️' if ev['verbatim_match'] else 'No'}")
        print(f"  Near match     : {'YES ⚠️' if ev['near_match'] else 'No'}")
        print(f"  Word overlap   : {ev['word_overlap_score']:.0%}")
        if ev["verbatim_match"] or ev["near_match"]:
            print(f"\n  ⚠️  Potential memorization detected. This evidence file can")
            print(f"     be submitted to a copyright attorney.")

    elif args.command == "list":
        if not CANARY_DIR.exists():
            print("No canaries found.")
            return
        records = []
        for cf in sorted(CANARY_DIR.glob("*.json")):
            with open(cf) as f:
                r = json.load(f)
            if r.get("identity") == args.identity:
                records.append(r)
        if not records:
            print(f"No canaries for '{args.identity}'.")
            return
        print(f"\n{'ID':<38} {'Created':<32} Phrase")
        print("─" * 100)
        for r in records:
            print(f"{r['id']:<38} {r['created_utc']:<32} {r['phrase'][:40]}...")


if __name__ == "__main__":
    main()