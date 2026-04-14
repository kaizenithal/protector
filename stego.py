#!/usr/bin/env python3
"""
Protector — stego.py
Multi-channel text steganography for Layer 1 payload hardening.

Two independent encoding channels, each survivable independently:

  Channel A — Zero-width Unicode
    Fast and invisible. Stripped by NFKC normalization or a simple regex,
    but catches unsophisticated scrapers and is a useful baseline layer.

  Channel B — Homoglyph substitution
    Replaces ASCII carrier letters with visually identical Unicode
    counterparts (primarily Cyrillic). Survives Unicode normalization
    stripping because aggressive normalization also breaks legitimate
    non-ASCII content. Hard to remove without damaging multilingual text,
    proper nouns, and technical identifiers.

Any single surviving channel is sufficient to recover the full payload.

Channel C (syntactic steganography) is reserved for a future release.
It requires careful design to be reliable across real-world text pipelines
and will be implemented properly when that design work is done.
"""

import hashlib
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# CHANNEL A — ZERO-WIDTH UNICODE
# ─────────────────────────────────────────────────────────────────────────────

_ZW_ZERO = "\u200b"   # zero-width space        → bit 0
_ZW_ONE  = "\u200c"   # zero-width non-joiner   → bit 1
_ZW_SEP  = "\u200d"   # zero-width joiner       → frame delimiter

def _zw_encode(data: str) -> str:
    """
    Encode `data` as a block of invisible zero-width Unicode characters.

    Example:
        hidden = _zw_encode("hello")
        # Returns a string of zero-width chars that decodes back to "hello"
    """
    bits = "".join(f"{b:08b}" for b in data.encode("utf-8"))
    zw   = "".join(_ZW_ONE if b == "1" else _ZW_ZERO for b in bits)
    return _ZW_SEP + zw + _ZW_SEP

def _zw_decode(text: str) -> Optional[str]:
    """
    Scan `text` for zero-width encoded payloads and return the first
    successfully decoded one, or None if none found.

    Scans all ZW_SEP-delimited blocks so that a document with multiple
    injected copies (e.g. at p25 and p75) recovers whichever survives.
    """
    parts = text.split(_ZW_SEP)
    # parts alternates: [normal_text, zw_block, normal_text, zw_block, ...]
    # zw blocks are at odd indices: 1, 3, 5, ...
    for i in range(1, len(parts) - 1, 2):
        zw   = parts[i]
        bits = "".join("1" if c == _ZW_ONE else "0"
                       for c in zw if c in (_ZW_ZERO, _ZW_ONE))
        if not bits or len(bits) % 8 != 0:
            continue
        try:
            decoded = bytes(
                int(bits[j:j+8], 2) for j in range(0, len(bits), 8)
            ).decode("utf-8")
            return decoded
        except Exception:
            continue
    return None


# ─────────────────────────────────────────────────────────────────────────────
# CHANNEL B — HOMOGLYPH SUBSTITUTION
#
# Each ASCII carrier letter has a Unicode homoglyph that is visually
# identical in common Latin/sans-serif fonts. We encode a bit stream by
# choosing between the ASCII original (bit 0) and its homoglyph (bit 1)
# for each carrier character encountered in the text.
#
# Why this survives stripping:
#   — A stripper needs a complete, correct homoglyph mapping for every pair.
#   — Aggressive normalization converts non-ASCII letters, which also breaks
#     legitimate non-English content, proper nouns, and technical identifiers.
#   — Targeted stripping (only known pairs) requires knowing the exact mapping
#     used, which varies per implementation.
#   — Stripping leaves no visible trace — so there is no way to prove removal
#     occurred without the original file for comparison.
#
# Channel B encodes on the post-Channel-A text. Channel A injects zero-width
# characters but does not add carrier characters, so Channel B capacity is
# effectively the same as on the original text.
# ─────────────────────────────────────────────────────────────────────────────

# Maps ASCII carrier → Unicode homoglyph (bit 1 representation).
# All pairs verified visually identical in common Latin/sans-serif fonts.
_HOMOGLYPHS: dict[str, str] = {
    "a": "\u0430",   # Cyrillic small a
    "c": "\u0441",   # Cyrillic small es
    "e": "\u0435",   # Cyrillic small ie
    "o": "\u043e",   # Cyrillic small o
    "p": "\u0440",   # Cyrillic small er
    "x": "\u0445",   # Cyrillic small ha
    "y": "\u0443",   # Cyrillic small u
    "i": "\u0456",   # Cyrillic/Ukrainian i
    "s": "\u0455",   # Cyrillic dze
    "A": "\u0410",   # Cyrillic capital A
    "C": "\u0421",   # Cyrillic capital ES
    "E": "\u0415",   # Cyrillic capital IE
    "O": "\u041e",   # Cyrillic capital O
    "P": "\u0420",   # Cyrillic capital ER
    "X": "\u0425",   # Cyrillic capital HA
    "Y": "\u0423",   # Cyrillic capital U
    "H": "\u041d",   # Cyrillic capital EN
    "K": "\u041a",   # Cyrillic capital KA
    "M": "\u041c",   # Cyrillic capital EM
    "T": "\u0422",   # Cyrillic capital TE
    "B": "\u0412",   # Cyrillic capital VE
}

# Reverse map: homoglyph → ASCII original (for decoding)
_HOMOGLYPH_REVERSE: dict[str, str] = {v: k for k, v in _HOMOGLYPHS.items()}

_CARRIER_SET = set(_HOMOGLYPHS.keys())

def _homoglyph_encode(text: str, data: str) -> str:
    """
    Encode `data` into `text` via homoglyph substitution.
    Raises ValueError if the text has insufficient carrier characters.

    Example:
        stego = _homoglyph_encode("The cartographer oscillates.", "hi")
        # Visually identical to original; encodes "hi" in carrier chars
    """
    bits      = "".join(f"{b:08b}" for b in data.encode("utf-8"))
    positions = [i for i, ch in enumerate(text) if ch in _CARRIER_SET]

    if len(positions) < len(bits):
        raise ValueError(
            f"Insufficient carriers: need {len(bits)} bits across carrier "
            f"characters, found {len(positions)}. Use a longer text."
        )

    chars = list(text)
    for bit, pos in zip(bits, positions):
        if bit == "1":
            chars[pos] = _HOMOGLYPHS[chars[pos]]
        # bit == "0": leave as ASCII original (already correct)

    return "".join(chars)

def _homoglyph_decode(text: str) -> Optional[str]:
    """
    Extract a null-terminated payload from homoglyph substitutions in `text`.
    Returns the decoded string, or None if no payload found.

    Example:
        payload = _homoglyph_decode(stego_text)
    """
    bits = []
    for ch in text:
        if ch in _CARRIER_SET:
            bits.append("0")
        elif ch in _HOMOGLYPH_REVERSE:
            bits.append("1")

    if len(bits) < 8:
        return None

    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = int("".join(bits[i:i+8]), 2)
        if byte == 0:
            break
        result.append(byte)

    if not result:
        return None
    try:
        return result.decode("utf-8")
    except Exception:
        return None

def _homoglyph_capacity(text: str) -> int:
    """
    Return the number of bytes encodable in `text` via homoglyph substitution.

    Note: comparison against payload size should use len(payload.encode("utf-8"))
    to correctly handle multi-byte characters.
    """
    carriers = sum(1 for ch in text if ch in _CARRIER_SET)
    return carriers // 8


# ─────────────────────────────────────────────────────────────────────────────
# MULTI-CHANNEL ENCODER / DECODER
# ─────────────────────────────────────────────────────────────────────────────

# Prefix embedded in every channel payload for identification and version control.
# If the encoding scheme changes incompatibly, bump this to "CM2:".
_CHANNEL_HEADER = "CM1:"

def encode_all_channels(text: str, payload: str) -> tuple[str, dict]:
    """
    Encode `payload` into `text` across both available channels.

    Channel A (zero-width) is injected at ~25% and ~75% paragraph positions
    for resilience — if one copy is stripped, the other may survive.

    Channel B (homoglyphs) is applied to the post-Channel-A text. Channel A
    does not add carrier characters, so Channel B capacity is unchanged.

    Returns:
        (stego_text, channel_report)
        channel_report maps channel name → status string explaining what
        happened (embedded, skipped with reason, etc).

    Example:
        stego, report = encode_all_channels(article_text, json_payload)
        print(report)
        # {'channel_a_zw': 'embedded (2 copies)',
        #  'channel_b_homoglyph': 'embedded (42 carriers available)'}
    """
    report  = {}
    current = text

    # ── Channel A: Zero-width ─────────────────────────────────────────────────
    zw_data  = _CHANNEL_HEADER + payload + "\x00"
    zw_block = _zw_encode(zw_data)

    paragraphs = current.split("\n\n")
    n = len(paragraphs)
    if n >= 4:
        p25 = max(1, n // 4)
        p75 = max(p25 + 1, (3 * n) // 4)
        paragraphs[p25] += zw_block
        paragraphs[p75] += zw_block
        report["channel_a_zw"] = "embedded (2 copies)"
    elif n >= 2:
        paragraphs[1] += zw_block
        report["channel_a_zw"] = "embedded (1 copy)"
    else:
        current += zw_block
        report["channel_a_zw"] = "embedded (1 copy, end of text)"
        paragraphs = None

    if paragraphs is not None:
        current = "\n\n".join(paragraphs)

    # ── Channel B: Homoglyphs ─────────────────────────────────────────────────
    # Channel B runs on the post-Channel-A text. This is intentional and safe:
    # Channel A injects zero-width characters (U+200B/C/D) which are not in
    # _CARRIER_SET and are not ASCII letters, so they contribute zero carrier
    # characters. Channel B capacity is therefore identical to what it would
    # be on the original text.
    hg_data       = _CHANNEL_HEADER + payload + "\x00"
    hg_data_bytes = len(hg_data.encode("utf-8"))
    capacity      = _homoglyph_capacity(current)

    if capacity >= hg_data_bytes:
        try:
            current = _homoglyph_encode(current, hg_data)
            report["channel_b_homoglyph"] = (
                f"embedded ({capacity} bytes capacity, "
                f"{hg_data_bytes} bytes used)"
            )
        except ValueError as e:
            report["channel_b_homoglyph"] = f"skipped: {e}"
    else:
        shortfall = hg_data_bytes - capacity
        report["channel_b_homoglyph"] = (
            f"skipped: need {hg_data_bytes} bytes of carrier capacity, "
            f"have {capacity} (shortfall: {shortfall} bytes). "
            f"Use a longer text."
        )

    return current, report


def decode_all_channels(text: str) -> dict:
    """
    Attempt payload extraction from both channels.

    Returns a dict with keys:
        'channel_a_zw'        → decoded payload string, or None
        'channel_b_homoglyph' → decoded payload string, or None

    Example:
        results = decode_all_channels(stego_text)
        payload = results['channel_b_homoglyph'] or results['channel_a_zw']
    """
    results = {}

    # ── Channel A ────────────────────────────────────────────────────────────
    raw_a = _zw_decode(text)
    if raw_a and raw_a.startswith(_CHANNEL_HEADER):
        results["channel_a_zw"] = raw_a[len(_CHANNEL_HEADER):].rstrip("\x00")
    else:
        results["channel_a_zw"] = None

    # ── Channel B ────────────────────────────────────────────────────────────
    raw_b = _homoglyph_decode(text)
    if raw_b and raw_b.startswith(_CHANNEL_HEADER):
        results["channel_b_homoglyph"] = raw_b[len(_CHANNEL_HEADER):].rstrip("\x00")
    else:
        results["channel_b_homoglyph"] = None

    return results


def best_payload(text: str) -> Optional[str]:
    """
    Return the best available decoded payload across all channels.
    Prefers Channel B (most resilient to stripping) over Channel A.
    Returns None if no payload is recoverable.

    Example:
        payload = best_payload(stego_text)
        if payload:
            data = json.loads(payload)
    """
    decoded = decode_all_channels(text)
    return decoded.get("channel_b_homoglyph") or decoded.get("channel_a_zw")


# ─────────────────────────────────────────────────────────────────────────────
# DIAGNOSTIC TOOL
# ─────────────────────────────────────────────────────────────────────────────

def channel_report(text: str) -> None:
    """
    Print a human-readable diagnostic report of channel status in `text`.
    Shows which channels are present, their payloads, and overall resilience.
    """
    print("\n[stego] Channel analysis:")
    results = decode_all_channels(text)

    a = results["channel_a_zw"]
    print(f"  Channel A (zero-width)  : "
          f"{'✓ payload recovered' if a else '✗ not found / stripped'}")
    if a:
        print(f"    → {a[:80]}{'...' if len(a) > 80 else ''}")

    b = results["channel_b_homoglyph"]
    hg_count = sum(1 for ch in text if ch in _HOMOGLYPH_REVERSE)
    print(f"  Channel B (homoglyphs)  : "
          f"{'✓ payload recovered' if b else f'✗ not found ({hg_count} homoglyphs present)'}")
    if b:
        print(f"    → {b[:80]}{'...' if len(b) > 80 else ''}")

    surviving = sum(1 for v in [a, b] if v)
    print(f"\n  Channels surviving      : {surviving}/2")
    if surviving == 0:
        print("  ⚠️  All channels stripped — watermark not recoverable from this text.")
    elif surviving == 2:
        print("  ✓  Full redundancy intact.")
    else:
        print("  ⚠️  Partial — watermark recoverable but one channel has been stripped.")


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE DIAGNOSTIC CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="stego",
        description="Protector stego — multi-channel steganography diagnostics"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    an = sub.add_parser("analyze", help="Analyze which channels are present in a file")
    an.add_argument("file", type=Path)

    cap = sub.add_parser("capacity", help="Report encoding capacity of a file")
    cap.add_argument("file", type=Path)

    args = parser.parse_args()

    if args.command == "analyze":
        text = args.file.read_text(encoding="utf-8", errors="ignore")
        channel_report(text)

    elif args.command == "capacity":
        text = args.file.read_text(encoding="utf-8", errors="ignore")
        hg   = _homoglyph_capacity(text)
        print(f"\n[stego] Capacity for: {args.file}")
        print(f"  Channel A (zero-width)  : unlimited (payload injected, not substituted)")
        print(f"  Channel B (homoglyphs)  : {hg} bytes  ({hg * 8} bits)")
        print(f"\n  Channel B is the binding constraint.")
        print(f"  Maximum payload size    : {hg} bytes")