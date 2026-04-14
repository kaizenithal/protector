#!/usr/bin/env python3
"""
Protector Evidence Toolkit — canary.py
Embeds statistically unique canary phrases into your content,
then generates probe queries to test AI models for memorization.
"""

import argparse
import hashlib
import hmac as _hmac
import json
import os
import random
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ── Shared paths ──────────────────────────────────────────────────────────────
KEY_FILE     = Path.home() / ".Protector" / "keys.json"
CANARY_DIR   = Path.home() / ".Protector" / "canaries"
EVIDENCE_DIR = Path.home() / ".Protector" / "evidence"

# Stopwords excluded from overlap scoring to prevent false positives
_STOPWORDS = {
    "a","an","the","and","or","but","in","on","at","to","of","for","is","are",
    "was","were","be","been","being","have","has","had","do","does","did","will",
    "would","could","should","may","might","shall","this","that","these","those",
    "it","its","i","my","me","we","our","you","your","he","she","they","their",
    "with","from","by","as","if","so","not","no","nor","yet","both","either",
    "where","when","what","which","who","how","something","remains","included",
    "half","remembered","every","one","still","even","here","there","then","now",
}


# ─────────────────────────────────────────────────────────────────────────────
# KEY MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

def load_keys() -> dict:
    if not KEY_FILE.exists():
        return {}
    with open(KEY_FILE) as f:
        return json.load(f)

def _get_secret(identity: str) -> bytes:
    """Load signing key, delegating to watermark.py if available."""
    try:
        from watermark import get_or_create_key
        return get_or_create_key(identity)
    except ImportError:
        pass
    keys = load_keys()
    if identity not in keys:
        print(f"[error] Identity '{identity}' not found.")
        print("        Run: python watermark.py watermark <file> --identity \"...\"")
        raise SystemExit(1)
    return bytes.fromhex(keys[identity]["secret"])

def _sign(data: dict, secret: bytes) -> str:
    payload = json.dumps(data, sort_keys=True).encode()
    return _hmac.new(secret, payload, hashlib.sha256).hexdigest()

def _verify_sign(record: dict, secret: bytes, sig_key: str = "hmac") -> bool:
    stored   = record.get(sig_key, "")
    clean    = {k: v for k, v in record.items() if k != sig_key}
    expected = _sign(clean, secret)
    return _hmac.compare_digest(stored, expected)


# ─────────────────────────────────────────────────────────────────────────────
# STEGANOGRAPHY  (via stego.py)
# Canary IDs are hidden using both zero-width Unicode (Channel A) and
# homoglyph substitution (Channel B). Either channel alone is sufficient
# for scan_file to recover the ID.
# ─────────────────────────────────────────────────────────────────────────────

try:
    from stego import (
        _zw_encode        as _encode_zw,
        _zw_decode        as _decode_zw,
        _ZW_SEP           as ZW_SEP,
        _homoglyph_encode,
        _homoglyph_decode,
        _homoglyph_capacity,
    )
    _STEGO_AVAILABLE = True
except ImportError:
    _STEGO_AVAILABLE = False
    ZW_ZERO = "\u200b"
    ZW_ONE  = "\u200c"
    ZW_SEP  = "\u200d"

    def _encode_zw(data: str) -> str:
        bits = "".join(f"{b:08b}" for b in data.encode())
        zw   = "".join("\u200c" if b == "1" else "\u200b" for b in bits)
        return "\u200d" + zw + "\u200d"

    def _decode_zw(text: str) -> str | None:
        parts = text.split("\u200d")
        if len(parts) < 3:
            return None
        zw   = parts[1]
        bits = "".join("1" if c == "\u200c" else "0"
                       for c in zw if c in ("\u200b", "\u200c"))
        if len(bits) % 8 != 0:
            return None
        try:
            return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode()
        except Exception:
            return None

    def _homoglyph_encode(text, data):  return text
    def _homoglyph_decode(text):        return None
    def _homoglyph_capacity(text):      return 0


# ─────────────────────────────────────────────────────────────────────────────
# CANARY PHRASE VOCABULARY
#
# Design goals:
#   1. Grammatically plausible  — won't look odd to human readers
#   2. Statistically improbable — no writer would independently produce them
#   3. Deterministic from seed  — reproducible for verification
#   4. Large pool               — ~50M+ unique combinations, minimises collisions
# ─────────────────────────────────────────────────────────────────────────────

_ADJ = [
    "cerulean","ossified","lambent","viridian","crepuscular","tintinnabulating",
    "fulvous","nugatory","sibilant","lachrymose","tenebrous","vermicular",
    "atavistic","canescent","diaphanous","effluvial","fugacious","gossamer",
    "hebdomadal","iridescent","lugubrious","mnemonic","noctilucent","oneiric",
    "palimpsestic","quiescent","refulgent","stygian","tenebrific","umbral",
    "vestigial","widdershins","xanthic","amaranthine","bathypelagic","chimerical",
    "diurnal","etiolated","fenestrated","galvanic","hyaline","icteric","katabatic",
    "liminal","moribund","nacreous","oleaginous","piscine","quotidian","rimose",
    "sclerotic","thalassic","vellichor","lacunal","apocryphal","phosphenic",
    "coruscant","sepulchral","fungible","axiomatic","penumbral","lacustrine",
]

_NOUN = [
    "cartographer","harbinger","soliloquy","palimpsest","isthmus","curlicue",
    "escarpment","vellum","campanile","filigree","ossuary","lacuna",
    "archipelago","bibliomancer","cartouche","diorama","ephemeris","fascia",
    "gazetteer","horology","iconoclast","lithograph","nomenclature","oubliette",
    "penumbra","quincunx","rhizome","scriptorium","taxidermy","umbra",
    "wunderkammer","xenolith","zoetrope","alchemist","cenotaph","dirigible",
    "escutcheon","falconer","glyph","heliograph","incunabula","kaleidoscope",
    "luminaire","marginalia","nocturne","orrery","panorama","quatrefoil",
    "reliquary","triptych","underpainting","vellichor","dendrogram","folio",
    "lemniscate","meridian","nadir","recto","sigil","verso",
]

_VERB = [
    "meanders","oscillates","unspools","concatenates","calcifies","reverberates",
    "perforates","coruscates","agglomerates","desiccates","tessellates","phosphoresces",
    "attenuates","bifurcates","coalesces","effloresces","fibrillates","granulates",
    "intercalates","juxtaposes","laminates","nucleates","obfuscates","percolates",
    "reticulates","scintillates","transmogrifies","undulates","vesiculates",
    "absconds","crenulates","evanesces","festers","gutters","inosculates",
    "keratinizes","liquefies","mortifies","nidificates","putrefies","quickens",
    "ramifies","stratifies","turgescences","vitrifies","withers","sediments",
    "precipitates","sublimes","calculates","annotates","indexes",
    "catalogs","deciphers","encodes","extrapolates","interpolates","redacts",
]

_PLACE = [
    "in the hollow of a forgotten meridian",
    "beneath the secondhand sky",
    "along the unmapped corridor of sleep",
    "where the index ends and silence begins",
    "at the edge of the unrecorded afternoon",
    "inside the folded margin of the week",
    "across the threshold of an unnamed cartography",
    "within the parenthesis of a borrowed century",
    "below the watermark of the previous tide",
    "at the coordinates no surveyor recorded",
    "through the aperture of an absent season",
    "beside the residue of a collapsed longitude",
    "under the annotation of a missing page",
    "past the declension of the final hour",
    "amid the sediment of a half-dreamed archive",
    "along the littoral of a cancelled expedition",
    "inside the lacuna between two unreliable atlases",
    "at the terminus of an uncharted recursion",
    "beneath the palimpsest of a withdrawn inference",
    "within the recto of an illegible folio",
    "at the margin where the catalogue runs out",
    "inside the draft that was never archived",
    "across the verso of an unwitnessed document",
    "where the footnote outlasts the text",
    "in the register of events no one filed",
]

_TEMPLATES = [
    "The {adj} {noun} {verb} {place}.",
    "A {adj} {noun}, half-remembered, {verb} {place}.",
    "Where the {adj} {noun} {verb}, {place}, something remains.",
    "Every {adj} {noun} {verb} {place} — this one included.",
    "Here, a {adj} {noun} {verb} {place}, unobserved.",
    "The {adj} {noun} still {verb} {place}, even now.",
    "Somewhere, a {adj} {noun} {verb} {place} without witness.",
    "It was the {adj} {noun} that {verb} {place}, not the other.",
    "No one recorded how the {adj} {noun} {verb} {place}.",
    "The {adj} {noun} {verb} {place}, as it always has.",
]

def _random_canary_phrase(seed: str) -> str:
    rng = random.Random(seed)
    return rng.choice(_TEMPLATES).format(
        adj   = rng.choice(_ADJ),
        noun  = rng.choice(_NOUN),
        verb  = rng.choice(_VERB),
        place = rng.choice(_PLACE),
    )

def _vocab_size() -> int:
    return len(_ADJ) * len(_NOUN) * len(_VERB) * len(_PLACE) * len(_TEMPLATES)


# ─────────────────────────────────────────────────────────────────────────────
# CANARY RECORD
# ─────────────────────────────────────────────────────────────────────────────

def generate_canary(identity: str, content_id: str, secret: bytes) -> dict:
    # uuid4 entropy in seed prevents collisions even on rapid calls
    entropy = str(uuid.uuid4())
    seed    = f"{identity}:{content_id}:{entropy}"
    phrase  = _random_canary_phrase(seed)
    record  = {
        "id"          : str(uuid.uuid4()),
        "identity"    : identity,
        "content_id"  : content_id,
        "phrase"      : phrase,
        "seed"        : seed,
        "created_utc" : datetime.now(timezone.utc).isoformat(),
        "unix_ts"     : int(time.time()),
    }
    record["hmac"] = _sign({k: v for k, v in record.items() if k != "hmac"}, secret)
    return record

def save_canary(record: dict) -> Path:
    CANARY_DIR.mkdir(parents=True, exist_ok=True)
    out = CANARY_DIR / f"{record['id']}.json"
    with open(out, "w") as f:
        json.dump(record, f, indent=2)
    return out

def load_canary(canary_id: str) -> dict:
    cfile = CANARY_DIR / f"{canary_id}.json"
    if not cfile.exists():
        print(f"[error] Canary not found: {canary_id}")
        raise SystemExit(1)
    with open(cfile) as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# INJECT CANARIES INTO CONTENT
# ─────────────────────────────────────────────────────────────────────────────

# Import CODE_EXTS from watermark.py so both files stay in sync.
# If a new language is added to watermark.py it is automatically
# supported here without a separate change.
try:
    from watermark import CODE_EXTS as _CODE_EXTS
except ImportError:
    # Fallback if watermark.py is not in path
    _CODE_EXTS = {".py",".js",".ts",".jsx",".tsx",".java",".c",".cpp",
                  ".go",".rs",".rb",".sh",".php",".swift",".kt"}

def inject_canaries(filepath: Path, identity: str, secret: bytes,
                    count: int = 3) -> dict:
    """
    Inject canary phrases into a file, distributed evenly across its length.

    Each canary phrase is embedded with two independent identification channels:
      Channel A — The canary UUID is encoded as invisible zero-width Unicode
                  characters immediately before the visible phrase. Fast to
                  strip, but catches unsophisticated scrapers.
      Channel B — The canary UUID is homoglyph-encoded into the phrase itself.
                  Requires sufficient carrier characters in the phrase (a UUID
                  needs 37 bytes; typical phrases have 3-6 bytes capacity).
                  Currently falls back to Channel A only in most cases — see
                  TODO for the planned short-fingerprint alternative.

    Plain text / markdown / HTML:
        Phrase injected as natural prose. ID hidden via both channels.

    Code files:
        Injected as a comment line. ID hidden via both channels.
    """
    text    = filepath.read_text(encoding="utf-8")
    ext     = filepath.suffix.lower()
    is_code = ext in _CODE_EXTS

    paragraphs = text.split("\n\n")
    if len(paragraphs) < 2:
        paragraphs = text.split("\n")

    n_segs   = len(paragraphs)
    n_inject = min(count, max(1, n_segs - 1))

    # Evenly spaced positions — avoids random clustering in short documents
    step      = max(1, (n_segs - 1) // n_inject)
    positions = [min(1 + i * step, n_segs - 1) for i in range(n_inject)]

    canaries = []
    for i, pos in enumerate(positions):
        content_id = f"{filepath.stem}-c{i}-{str(uuid.uuid4())[:8]}"
        record     = generate_canary(identity, content_id, secret)
        canaries.append(record)

        canary_id = record["id"]
        phrase    = record["phrase"]

        # Channel A: zero-width UUID (invisible, fast to strip)
        hidden_id = _encode_zw(canary_id)

        # Channel B: homoglyph UUID encoded into the phrase itself.
        # Capacity is in bytes; compare against the encoded byte length of
        # the actual payload (canary_id + null terminator), not its character
        # count, so multi-byte identities are handled correctly.
        hg_payload      = canary_id + "\x00"
        hg_payload_size = len(hg_payload.encode("utf-8"))
        if _STEGO_AVAILABLE and _homoglyph_capacity(phrase) >= hg_payload_size:
            try:
                phrase_stego = _homoglyph_encode(phrase, hg_payload)
            except ValueError:
                phrase_stego = phrase
        else:
            phrase_stego = phrase

        if is_code:
            cmt = "#" if ext in {".py", ".rb", ".sh"} else "//"
            injection = f"\n{hidden_id}{cmt} {phrase_stego}\n"
        else:
            injection = f"\n\n{hidden_id}{phrase_stego}\n"

        paragraphs[pos] += injection

    sep       = "\n" if is_code else "\n\n"
    annotated = sep.join(paragraphs)
    out_path  = filepath.with_stem(filepath.stem + "_canaried")
    out_path.write_text(annotated, encoding="utf-8")

    saved = [str(save_canary(c)) for c in canaries]
    return {"output": out_path, "canaries": canaries,
            "canary_files": saved, "count": len(canaries)}


# ─────────────────────────────────────────────────────────────────────────────
# SCAN — extract canary IDs from any file
# ─────────────────────────────────────────────────────────────────────────────

def scan_file(filepath: Path) -> list[str]:
    """
    Extract embedded canary IDs from a file.
    Tries Channel A (zero-width) first, then Channel B (homoglyphs).
    Returns deduplicated list of valid UUID strings found.
    """
    text  = filepath.read_text(encoding="utf-8", errors="ignore")
    found = set()

    # Channel A: zero-width segments
    parts = text.split(ZW_SEP)
    for i in range(1, len(parts) - 1, 2):
        decoded = _decode_zw(ZW_SEP + parts[i] + ZW_SEP)
        if decoded:
            try:
                uuid.UUID(decoded)
                found.add(decoded)
            except ValueError:
                pass

    # Channel B: homoglyph-encoded UUID in each sentence/line.
    # Pre-check for any homoglyphs first (O(n)) before the O(n*m) segment
    # scan — if no homoglyphs are present at all, skip entirely.
    if _STEGO_AVAILABLE:
        from stego import _HOMOGLYPH_REVERSE
        has_homoglyphs = any(c in _HOMOGLYPH_REVERSE for c in text)
        if has_homoglyphs:
            for segment in re.split(r"(?<=[.!?\n])\s*", text):
                if len(segment) < 10:
                    continue
                raw = _homoglyph_decode(segment)
                if raw:
                    raw = raw.rstrip("\x00")
                    try:
                        uuid.UUID(raw)
                        found.add(raw)
                    except ValueError:
                        pass

    return list(found)

# ─────────────────────────────────────────────────────────────────────────────
# PROBE QUERY GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

_MIN_PREFIX_WORDS = 5

def generate_probes(canary_record: dict) -> list[dict]:
    phrase = canary_record["phrase"]
    words  = phrase.rstrip(".").split()

    # 60% prefix, minimum 5 words, always leave ≥2 words as expected suffix
    mid    = max(_MIN_PREFIX_WORDS, int(len(words) * 0.6))
    mid    = min(mid, len(words) - 2)
    prefix = " ".join(words[:mid])
    suffix = " ".join(words[mid:])

    return [
        {
            "type"             : "completion",
            "prompt"           : f'Complete this sentence exactly as written: "{prefix}..."',
            "target"           : phrase,
            "expected_fragment": suffix,
        },
        {
            "type"             : "verbatim_recall",
            "prompt"           : (
                f'I\'m trying to find a specific sentence I read. '
                f'It begins: "{prefix}". Do you recognise it or know how it continues?'
            ),
            "target"           : phrase,
            "expected_fragment": suffix,
        },
        {
            "type"             : "context_recall",
            "prompt"           : (
                f'Have you encountered text containing the phrase "{prefix}"? '
                f'If so, quote what follows it.'
            ),
            "target"           : phrase,
            "expected_fragment": suffix,
        },
        {
            "type"             : "style_probe",
            "prompt"           : (
                f'Continue this sentence in the exact same voice and style, '
                f'keeping any unusual vocabulary: "{prefix}"'
            ),
            "target"           : phrase,
            "expected_fragment": suffix,
        },
        {
            "type"             : "indirect_probe",
            "prompt"           : (
                f'What text, if any, do you associate with the phrase '
                f'"{" ".join(words[:3])}"? Quote it if you can.'
            ),
            "target"           : phrase,
            "expected_fragment": phrase,
        },
    ]


# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE SCORING & LOGGING
# ─────────────────────────────────────────────────────────────────────────────

def _content_words(text: str) -> set[str]:
    """Lowercase words with stopwords and punctuation removed."""
    return {
        w.strip(".,;:!?\"'()[]—") for w in text.lower().split()
        if w.strip(".,;:!?\"'()[]—") not in _STOPWORDS
        and len(w.strip(".,;:!?\"'()[]—")) > 2
    }

def _score_response(response: str, probe: dict) -> dict:
    phrase   = probe["target"]
    fragment = probe["expected_fragment"]

    verbatim    = fragment.lower() in response.lower()
    full_phrase = phrase.lower()   in response.lower()

    # Content-word overlap (stopwords excluded)
    frag_words = _content_words(fragment)
    resp_words = _content_words(response)
    overlap    = len(frag_words & resp_words) / max(len(frag_words), 1) if frag_words else 0.0

    # Order-sensitive word sequence score
    fw  = [w for w in fragment.lower().split() if w not in _STOPWORDS]
    rw  = [w for w in response.lower().split() if w not in _STOPWORDS]
    lcs = 0
    rw_copy = list(rw)
    for word in fw:
        if word in rw_copy:
            lcs += 1
            rw_copy = rw_copy[rw_copy.index(word) + 1:]
    order_score = lcs / max(len(fw), 1) if fw else 0.0

    combined   = (overlap * 0.5) + (order_score * 0.5)
    near_match = combined > 0.55 and not (verbatim or full_phrase)

    return {
        "verbatim_match"    : verbatim or full_phrase,
        "near_match"        : near_match,
        "word_overlap_score": round(overlap, 3),
        "order_score"       : round(order_score, 3),
        "combined_score"    : round(combined, 3),
    }

def log_evidence(canary_id: str, model: str, probe: dict,
                 response: str, identity: str, secret: bytes) -> Path:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    scores   = _score_response(response, probe)
    evidence = {
        "id"           : str(uuid.uuid4()),
        "canary_id"    : canary_id,
        "identity"     : identity,
        "model"        : model,
        "probe_type"   : probe["type"],
        "prompt"       : probe["prompt"],
        "response"     : response,
        "target_phrase": probe["target"],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "unix_ts"      : int(time.time()),
        **scores,
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
        description="Protector Canary — embed & probe AI models for memorized content",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  inject    Embed canary phrases into your content before publishing
  probes    Generate probe queries for a canary ID
  log       Record an AI model response as evidence
  scan      Detect embedded canary IDs in any file
  list      List all your canaries

Examples:
  python canary.py inject article.txt --identity "Jane Doe" --count 5
  python canary.py probes --canary-id <uuid> --identity "Jane Doe"
  python canary.py log --canary-id <uuid> --model "GPT-4o" \\
      --probe-type completion --response-file response.txt --identity "Jane Doe"
  python canary.py log --canary-id <uuid> --model "GPT-4o" \\
      --probe-type completion --response "The lambent..." --identity "Jane Doe"
  python canary.py scan suspicious_file.txt
  python canary.py list --identity "Jane Doe"
"""
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inj = sub.add_parser("inject", help="Embed canaries into a file")
    inj.add_argument("file", type=Path)
    inj.add_argument("--identity", required=True)
    inj.add_argument("--count", type=int, default=3,
                     help="Number of canary phrases to inject (default: 3)")

    prb = sub.add_parser("probes", help="Generate probe queries for a canary")
    prb.add_argument("--canary-id", required=True)
    prb.add_argument("--identity", required=True)

    lg = sub.add_parser("log", help="Log an AI response as evidence")
    lg.add_argument("--canary-id", required=True)
    lg.add_argument("--model", required=True, help="e.g. 'GPT-4o', 'Gemini 1.5'")
    lg.add_argument("--probe-type", required=True,
                    choices=["completion","verbatim_recall","context_recall",
                             "style_probe","indirect_probe"])
    lg.add_argument("--identity", required=True)
    resp = lg.add_mutually_exclusive_group(required=True)
    resp.add_argument("--response",      help="AI response text (inline)")
    resp.add_argument("--response-file", type=Path,
                      help="Path to a file containing the AI response")

    sc = sub.add_parser("scan", help="Detect canary IDs embedded in a file")
    sc.add_argument("file", type=Path)

    ls = sub.add_parser("list", help="List all canaries for an identity")
    ls.add_argument("--identity", required=True)

    args = parser.parse_args()

    # scan needs no signing key
    if args.command == "scan":
        if not args.file.exists():
            print(f"[error] File not found: {args.file}")
            raise SystemExit(1)
        ids = scan_file(args.file)
        if not ids:
            print(f"[scan] No Protector canary IDs found in: {args.file}")
        else:
            print(f"\n[scan] Found {len(ids)} canary ID(s) in: {args.file}")
            for cid in ids:
                cfile = CANARY_DIR / f"{cid}.json"
                if cfile.exists():
                    with open(cfile) as f:
                        rec = json.load(f)
                    print(f"  ✓  {cid}")
                    print(f"     Owner  : {rec['identity']}")
                    print(f"     Phrase : {rec['phrase']}")
                    print(f"     Created: {rec['created_utc']}")
                else:
                    print(f"  ?  {cid}  (not in local vault — may belong to another creator)")
        return

    secret = _get_secret(args.identity)

    if args.command == "inject":
        if not args.file.exists():
            print(f"[error] File not found: {args.file}")
            raise SystemExit(1)
        result = inject_canaries(args.file, args.identity, secret, args.count)
        print(f"\n[canary] ✓ Injected {result['count']} canaries into: {result['output']}")
        print(f"  Vocabulary pool : ~{_vocab_size():,} unique phrases\n")
        for c in result["canaries"]:
            print(f"  {c['id']}")
            print(f"  → \"{c['phrase']}\"\n")
        if result['count'] < args.count:
            print(f"  [note] Requested {args.count} canaries but only "
                  f"{result['count']} were injected — document too short "
                  f"to accommodate all of them.")
        print(f"  Records saved to: {CANARY_DIR}")
        print(f"  Publish the _canaried file. Keep originals + canary IDs private.")

    elif args.command == "probes":
        record = load_canary(args.canary_id)
        if not _verify_sign(record, secret):
            print("[warn] HMAC verification failed — record may be tampered.")
        probes = generate_probes(record)
        print(f"\n[canary] Probe queries for: {args.canary_id}")
        print(f"  Target: \"{record['phrase']}\"\n")
        for i, p in enumerate(probes, 1):
            print(f"  [{i}] {p['type'].upper()}")
            print(f"       Prompt           : {p['prompt']}")
            print(f"       Expected fragment: \"{p['expected_fragment']}\"\n")

    elif args.command == "log":
        if args.response_file:
            if not args.response_file.exists():
                print(f"[error] Response file not found: {args.response_file}")
                raise SystemExit(1)
            response = args.response_file.read_text(encoding="utf-8")
        else:
            response = args.response

        record = load_canary(args.canary_id)
        probes = generate_probes(record)
        probe  = next((p for p in probes if p["type"] == args.probe_type), probes[0])
        out    = log_evidence(args.canary_id, args.model, probe,
                              response, args.identity, secret)
        with open(out) as f:
            ev = json.load(f)

        print(f"\n[evidence] Logged: {out}")
        print(f"  Model          : {ev['model']}")
        print(f"  Verbatim match : {'YES ⚠️' if ev['verbatim_match'] else 'No'}")
        print(f"  Near match     : {'YES ⚠️' if ev['near_match'] else 'No'}")
        print(f"  Word overlap   : {ev['word_overlap_score']:.0%}")
        print(f"  Order score    : {ev['order_score']:.0%}")
        print(f"  Combined score : {ev['combined_score']:.0%}")
        if ev["verbatim_match"] or ev["near_match"]:
            print(f"\n  ⚠️  Potential memorization detected.")
            print(f"     Run: python report.py --identity \"{args.identity}\"")

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
        print(f"\n  {'ID':<38} {'Created':<32} Phrase")
        print("  " + "─" * 108)
        for r in records:
            valid = _verify_sign(r, secret)
            flag  = "✓" if valid else "⚠"
            print(f"  {flag} {r['id']:<38} {r['created_utc']:<32} {r['phrase'][:45]}...")


if __name__ == "__main__":
    main()