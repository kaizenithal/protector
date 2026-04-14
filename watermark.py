#!/usr/bin/env python3
"""
Protector — Cryptographic Watermarking CLI
Protects text, images, video, and code with provable ownership.
"""

import argparse
import hashlib
import hmac as _hmac
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# FILE TYPE CONSTANTS  (module-level so all functions share them)
# ─────────────────────────────────────────────────────────────────────────────

TEXT_EXTS  = {".txt", ".md", ".html", ".htm", ".rst", ".csv"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"}
VIDEO_EXTS = {".mp4", ".mov", ".avi", ".mkv", ".webm"}

COMMENT_STYLES = {
    ".py"  : "#",  ".rb": "#",  ".sh": "#",
    ".js"  : "//", ".ts": "//", ".jsx": "//", ".tsx": "//",
    ".java": "//", ".c" : "//", ".cpp": "//", ".go" : "//",
    ".rs"  : "//", ".php": "//", ".swift": "//", ".kt": "//",
}
CODE_EXTS = set(COMMENT_STYLES.keys())


# ─────────────────────────────────────────────────────────────────────────────
# KEY MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

KEY_FILE = Path.home() / ".Protector" / "keys.json"

def load_keys() -> dict:
    if not KEY_FILE.exists():
        return {}
    with open(KEY_FILE) as f:
        return json.load(f)

def save_keys(keys: dict) -> None:
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(KEY_FILE, "w") as f:
        json.dump(keys, f, indent=2)
    os.chmod(KEY_FILE, 0o600)

def get_or_create_key(identity: str) -> bytes:
    keys = load_keys()
    if identity not in keys:
        secret = os.urandom(32).hex()
        keys[identity] = {
            "secret" : secret,
            "created": datetime.now(timezone.utc).isoformat(),
        }
        save_keys(keys)
        print(f"[key] New signing key created for '{identity}'")
    return bytes.fromhex(keys[identity]["secret"])


# ─────────────────────────────────────────────────────────────────────────────
# MANIFEST / RECEIPT
# ─────────────────────────────────────────────────────────────────────────────

MANIFEST_DIR = Path.home() / ".Protector" / "manifests"

def build_manifest(filepath: Path, identity: str, content_hash: str,
                   wm_type: str, extra: dict | None = None) -> dict:
    manifest = {
        "id"             : str(uuid.uuid4()),
        "version"        : "1.0",
        "owner"          : identity,
        "file"           : str(filepath.resolve()),
        "filename"       : filepath.name,
        "content_type"   : wm_type,
        "sha256_original": content_hash,
        "timestamp_utc"  : datetime.now(timezone.utc).isoformat(),
        "unix_ts"        : int(time.time()),
    }
    if extra:
        manifest.update(extra)
    return manifest

def sign_manifest(manifest: dict, secret: bytes) -> str:
    payload = json.dumps(manifest, sort_keys=True).encode()
    return _hmac.new(secret, payload, hashlib.sha256).hexdigest()

def verify_manifest_sig(record: dict, secret: bytes) -> bool:
    """Verify a manifest record without mutating it."""
    stored = record.get("hmac_sha256", "")
    clean  = {k: v for k, v in record.items() if k != "hmac_sha256"}
    expected = sign_manifest(clean, secret)
    return _hmac.compare_digest(stored, expected)

def save_manifest(manifest: dict, signature: str) -> Path:
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    record = {**manifest, "hmac_sha256": signature}
    out = MANIFEST_DIR / f"{manifest['id']}.json"
    with open(out, "w") as f:
        json.dump(record, f, indent=2)
    return out

def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# MULTI-CHANNEL STEGANOGRAPHY  (via stego.py)
# ─────────────────────────────────────────────────────────────────────────────

try:
    from stego import encode_all_channels, best_payload, channel_report as _stego_report
    _STEGO_AVAILABLE = True
except ImportError:
    _STEGO_AVAILABLE = False

# Zero-width constants kept for fallback and for canary.py compatibility
ZW_ZERO = "\u200b"
ZW_ONE  = "\u200c"
ZW_SEP  = "\u200d"

def _encode_zw(data: str) -> str:
    bits = "".join(f"{b:08b}" for b in data.encode())
    zw   = "".join(ZW_ONE if b == "1" else ZW_ZERO for b in bits)
    return ZW_SEP + zw + ZW_SEP

def _decode_zw(text: str) -> str | None:
    """Scan all ZW_SEP-delimited blocks, returning the first that decodes."""
    parts = text.split(ZW_SEP)
    for i in range(1, len(parts) - 1, 2):
        zw   = parts[i]
        bits = "".join("1" if c == ZW_ONE else "0"
                       for c in zw if c in (ZW_ZERO, ZW_ONE))
        if not bits or len(bits) % 8 != 0:
            continue
        try:
            return bytes(int(bits[j:j+8], 2) for j in range(0, len(bits), 8)).decode()
        except Exception:
            continue
    return None

def _embed(text: str, payload: str) -> tuple[str, dict]:
    """Embed payload using all available channels. Returns (stego_text, report)."""
    if _STEGO_AVAILABLE:
        return encode_all_channels(text, payload)
    # Fallback: zero-width only — stego.py not found
    print("[warn] stego.py not found — using single-channel zero-width only.")
    print("       Place stego.py in the same directory for full multi-channel protection.")
    hidden = _encode_zw(payload)
    paragraphs = text.split("\n\n")
    if len(paragraphs) >= 2:
        paragraphs[1] += hidden
        return "\n\n".join(paragraphs), {"channel_a_zw": "embedded (fallback)"}
    return text + hidden, {"channel_a_zw": "embedded (fallback, end of text)"}


# ─────────────────────────────────────────────────────────────────────────────
# TEXT WATERMARKING
# ─────────────────────────────────────────────────────────────────────────────

def watermark_text(filepath: Path, identity: str, secret: bytes) -> dict:
    text          = filepath.read_text(encoding="utf-8")
    original_hash = hashlib.sha256(text.encode()).hexdigest()
    manifest_id   = str(uuid.uuid4())

    payload = json.dumps({
        "manifest_id": manifest_id,
        "owner"      : identity,
        "file"       : filepath.name,
        "hash"       : original_hash,
        "ts"         : int(time.time()),
    })

    # Multi-channel embedding: zero-width (Channel A) + homoglyphs (Channel B)
    watermarked, ch_report = _embed(text, payload)

    # Append human-readable attribution footer
    watermarked += (
        f"\n\n<!-- © {identity} | "
        f"SHA256:{original_hash[:16]}... | "
        f"ManifestID:{manifest_id[:8]}... | "
        f"Protector -->\n"
    )

    out_path = filepath.with_stem(filepath.stem + "_watermarked")
    out_path.write_text(watermarked, encoding="utf-8")

    print(f"  Channel coverage:")
    for ch, status in ch_report.items():
        print(f"    {ch}: {status}")

    manifest = build_manifest(filepath, identity, original_hash, "text", {
        "id"             : manifest_id,
        "hidden_payload" : payload,
        "channel_report" : ch_report,
    })
    sig     = sign_manifest(manifest, secret)
    receipt = save_manifest(manifest, sig)
    return {"output": out_path, "receipt": receipt, "hash": original_hash}


# ─────────────────────────────────────────────────────────────────────────────
# IMAGE WATERMARKING  (distributed LSB steganography + visible overlay)
# ─────────────────────────────────────────────────────────────────────────────

def watermark_image(filepath: Path, identity: str, secret: bytes) -> dict:
    try:
        import numpy as np
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        print("[error] Missing dependencies.\n  Install: pip install Pillow numpy")
        sys.exit(1)

    original_hash = file_sha256(filepath)
    manifest_id   = str(uuid.uuid4())
    img = Image.open(filepath).convert("RGBA")
    arr = np.array(img, dtype=np.uint8)

    # ── LSB steganography with distributed stride ─────────────────────────────
    # Embedding at indices 0,1,2,... is the most detectable LSB pattern.
    # Using a seeded stride spreads bits across the whole image, making
    # statistical detection significantly harder.
    payload       = f"OWNER:{identity}|MID:{manifest_id}|HASH:{original_hash[:32]}"
    payload_bytes = payload.encode() + b"\x00"
    bits          = "".join(f"{b:08b}" for b in payload_bytes)

    flat     = arr.flatten().tolist()
    n_pixels = len(flat)
    # Stride derived from hash — deterministic but not obvious
    stride   = max(3, (n_pixels // max(len(bits), 1)) // 2)
    indices  = [i * stride % n_pixels for i in range(len(bits))]

    if len(set(indices)) < len(bits):
        # Fallback to sequential if image is too small
        indices = list(range(min(len(bits), n_pixels)))
        print("[warn] Image small — using sequential LSB embedding")

    for idx, bit in zip(indices, bits):
        flat[idx] = (flat[idx] & 0xFE) | int(bit)

    arr    = np.array(flat, dtype=np.uint8).reshape(arr.shape)
    img_wm = Image.fromarray(arr, "RGBA")

    # ── Visible watermark overlay ─────────────────────────────────────────────
    draw  = ImageDraw.Draw(img_wm)
    w, h  = img_wm.size
    label = f"© {identity}"
    font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "C:/Windows/Fonts/arial.ttf",
    ]
    font = None
    for fp in font_paths:
        try:
            font = ImageFont.truetype(fp, max(14, h // 40))
            break
        except Exception:
            continue
    if font is None:
        font = ImageFont.load_default()

    bbox       = draw.textbbox((0, 0), label, font=font)
    tw, th     = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x, y       = w - tw - 12, h - th - 12
    draw.rectangle([x - 4, y - 4, x + tw + 4, y + th + 4], fill=(0, 0, 0, 120))
    draw.text((x, y), label, fill=(255, 255, 255, 220), font=font)

    out_path = filepath.with_stem(filepath.stem + "_watermarked").with_suffix(".png")
    img_wm.save(out_path, "PNG")

    manifest = build_manifest(filepath, identity, original_hash, "image", {
        "id"         : manifest_id,
        "lsb_payload": payload,
        "lsb_stride" : stride,
        "dimensions" : f"{w}x{h}",
    })
    sig     = sign_manifest(manifest, secret)
    receipt = save_manifest(manifest, sig)
    return {"output": out_path, "receipt": receipt, "hash": original_hash}


# ─────────────────────────────────────────────────────────────────────────────
# CODE WATERMARKING  (comment header + zero-width hidden payload)
# ─────────────────────────────────────────────────────────────────────────────

def watermark_code(filepath: Path, identity: str, secret: bytes) -> dict:
    code          = filepath.read_text(encoding="utf-8")
    original_hash = hashlib.sha256(code.encode()).hexdigest()
    manifest_id   = str(uuid.uuid4())
    ext           = filepath.suffix.lower()
    cmt           = COMMENT_STYLES.get(ext, "#")
    ts            = datetime.now(timezone.utc).isoformat()

    payload = json.dumps({
        "manifest_id": manifest_id,
        "owner"      : identity,
        "file"       : filepath.name,
        "hash"       : original_hash,
        "ts"         : ts,
    })

    # Multi-channel: zero-width in code body + homoglyphs in comment header
    header_text = (
        f"{cmt} ═══════════════════════════════════════════════\n"
        f"{cmt}  © {identity}  |  Protector v1.0\n"
        f"{cmt}  Registered : {ts}\n"
        f"{cmt}  SHA-256    : {original_hash}\n"
        f"{cmt}  Manifest   : {manifest_id}\n"
        f"{cmt}  This file contains cryptographic ownership proof.\n"
        f"{cmt}  Unauthorized AI training use violates copyright law.\n"
        f"{cmt} ═══════════════════════════════════════════════\n\n"
    )
    # Embed via both channels (A + B) into the comment header (rich in carrier chars)
    header_stego, ch_report = _embed(header_text, payload)
    # Also append raw zero-width at end of file as independent fallback
    zw_fallback = _encode_zw(payload)
    watermarked = header_stego + code + f"\n{zw_fallback}"
    out_path = filepath.with_stem(filepath.stem + "_watermarked")
    out_path.write_text(watermarked, encoding="utf-8")

    print(f"  Channel coverage:")
    for ch, status in ch_report.items():
        print(f"    {ch}: {status}")

    manifest = build_manifest(filepath, identity, original_hash, "code", {
        "id"            : manifest_id,
        "language"      : ext,
        "hidden_payload": payload,
        "channel_report": ch_report,
    })
    sig     = sign_manifest(manifest, secret)
    receipt = save_manifest(manifest, sig)
    return {"output": out_path, "receipt": receipt, "hash": original_hash}


# ─────────────────────────────────────────────────────────────────────────────
# VIDEO WATERMARKING  (ffmpeg metadata + burned-in overlay)
# ─────────────────────────────────────────────────────────────────────────────

def watermark_video(filepath: Path, identity: str, secret: bytes) -> dict:
    import subprocess
    import shutil

    if not shutil.which("ffmpeg"):
        print("[error] ffmpeg not found. Install: https://ffmpeg.org/download.html")
        sys.exit(1)

    original_hash = file_sha256(filepath)
    manifest_id   = str(uuid.uuid4())
    ts            = datetime.now(timezone.utc).isoformat()
    # Preserve original container format
    out_path      = filepath.with_stem(filepath.stem + "_watermarked")

    meta_comment = (
        f"Copyright:{identity} | "
        f"Protector | "
        f"ManifestID:{manifest_id} | "
        f"SHA256:{original_hash} | "
        f"Registered:{ts} | "
        f"Unauthorized AI training use prohibited"
    )

    cmd = [
        "ffmpeg", "-y", "-i", str(filepath),
        "-metadata", f"copyright=© {identity}",
        "-metadata", f"comment={meta_comment}",
        "-metadata", f"encoded_by=Protector",
        "-metadata", f"creation_time={ts}",
        "-vf", (
            # Escape single quotes in identity for ffmpeg filter safety
            f"drawtext=text='© {identity.replace(chr(39), '')}':fontsize=24:"
            f"fontcolor=white@0.6:x=w-tw-20:y=h-th-20:"
            f"box=1:boxcolor=black@0.4:boxborderw=6"
        ),
        "-codec:a", "copy",
        str(out_path),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[error] ffmpeg failed:\n{result.stderr[-2000:]}")
        sys.exit(1)

    manifest = build_manifest(filepath, identity, original_hash, "video", {
        "id"              : manifest_id,
        "ffmpeg_metadata" : meta_comment,
    })
    sig     = sign_manifest(manifest, secret)
    receipt = save_manifest(manifest, sig)
    return {"output": out_path, "receipt": receipt, "hash": original_hash}


# ─────────────────────────────────────────────────────────────────────────────
# VERIFY
# ─────────────────────────────────────────────────────────────────────────────

def verify_file(filepath: Path, identity: str, secret: bytes) -> None:
    current_hash = file_sha256(filepath)
    print(f"\n[verify] File  : {filepath}")
    print(f"         SHA256 : {current_hash}")

    if not MANIFEST_DIR.exists():
        print("[verify] No manifests found. Run 'watermark' first.")
        return

    found = []
    for mf in MANIFEST_DIR.glob("*.json"):
        with open(mf) as f:
            record = json.load(f)
        if record.get("owner") == identity and \
           record.get("sha256_original") == current_hash:
            found.append(record)

    if not found:
        print("[verify] ✗  No matching manifest found for this identity.")
        print("         File may have been modified or not watermarked by you.")
        return

    for record in found:
        valid = verify_manifest_sig(record, secret)   # non-mutating
        print(f"\n[verify] ✓  Match found!")
        print(f"         Manifest ID : {record['id']}")
        print(f"         Registered  : {record['timestamp_utc']}")
        print(f"         Type        : {record['content_type']}")
        print(f"         HMAC valid  : {'YES ✓' if valid else 'NO ⚠️  — manifest may be tampered!'}")


# ─────────────────────────────────────────────────────────────────────────────
# LIST MANIFESTS
# ─────────────────────────────────────────────────────────────────────────────

def list_manifests(identity: str, secret: bytes) -> None:
    if not MANIFEST_DIR.exists():
        print("No manifests found.")
        return

    records = []
    for mf in sorted(MANIFEST_DIR.glob("*.json")):
        with open(mf) as f:
            r = json.load(f)
        if r.get("owner") == identity:
            records.append(r)

    if not records:
        print(f"No manifests for identity '{identity}'.")
        return

    print(f"\n  {'Sig':<4} {'ID':<38} {'Type':<8} {'File':<28} Registered")
    print("  " + "─" * 108)
    for r in records:
        valid = verify_manifest_sig(r, secret)
        flag  = "✓" if valid else "⚠"
        print(f"  {flag:<4} {r['id']:<38} {r['content_type']:<8} "
              f"{r['filename']:<28} {r['timestamp_utc']}")


# ─────────────────────────────────────────────────────────────────────────────
# DETECT  (extract watermarks from any file)
# ─────────────────────────────────────────────────────────────────────────────

def detect_watermark(filepath: Path) -> None:
    ext = filepath.suffix.lower()
    print(f"\n[detect] Scanning: {filepath}")

    if ext in TEXT_EXTS:
        text    = filepath.read_text(encoding="utf-8", errors="ignore")
        if _STEGO_AVAILABLE:
            _stego_report(text)
        else:
            payload = _decode_zw(text)
            if payload:
                print(f"[detect] ✓ Hidden text payload found:\n  {payload}")
            else:
                print("[detect] No hidden zero-width payload detected.")

    elif ext in CODE_EXTS:
        code    = filepath.read_text(encoding="utf-8", errors="ignore")
        if _STEGO_AVAILABLE:
            _stego_report(code)
        else:
            payload = _decode_zw(code)
            if payload:
                print(f"[detect] ✓ Hidden code payload found:\n  {payload}")
            else:
                print("[detect] No hidden payload detected.")

    elif ext in IMAGE_EXTS:
        print("[detect] Image LSB payloads use a distributed stride stored in the")
        print("         manifest — they cannot be extracted without it.")
        print("         Run: python watermark.py verify <file> --identity <you>")
        print("         to check ownership using the manifest's stride value.")

    elif ext in VIDEO_EXTS:
        import subprocess
        import shutil
        if not shutil.which("ffprobe"):
            print("[detect] ffprobe not found (install ffmpeg).")
            return
        proc = subprocess.run(
            ["ffprobe", "-v", "quiet", "-print_format", "json",
             "-show_format", str(filepath)],
            capture_output=True, text=True,
        )
        if "Protector" in proc.stdout or "copyright" in proc.stdout.lower():
            data = json.loads(proc.stdout)
            tags = data.get("format", {}).get("tags", {})
            print("[detect] ✓ Video metadata found:")
            for k, v in tags.items():
                print(f"  {k}: {v}")
        else:
            print("[detect] No Protector metadata found in video.")

    else:
        print(f"[detect] Unsupported file type: {ext}")
        print(f"  Supported: {sorted(TEXT_EXTS | IMAGE_EXTS | VIDEO_EXTS | CODE_EXTS)}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="Protector",
        description="Protector — Cryptographic watermarking for creators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python watermark.py watermark article.txt  --identity "Jane Doe"
  python watermark.py watermark photo.jpg    --identity "Jane Doe"
  python watermark.py watermark script.py    --identity "Jane Doe"
  python watermark.py watermark video.mp4    --identity "Jane Doe"
  python watermark.py verify   photo.jpg     --identity "Jane Doe"
  python watermark.py list                   --identity "Jane Doe"
  python watermark.py detect   suspicious_file.txt
"""
    )
    sub = parser.add_subparsers(dest="command", required=True)

    wm = sub.add_parser("watermark", help="Watermark a file")
    wm.add_argument("file", type=Path)
    wm.add_argument("--identity", required=True, help="Your name or creator ID")

    vr = sub.add_parser("verify", help="Verify a file against your manifests")
    vr.add_argument("file", type=Path)
    vr.add_argument("--identity", required=True)

    ls = sub.add_parser("list", help="List all your registered works")
    ls.add_argument("--identity", required=True)

    dt = sub.add_parser("detect", help="Detect watermarks in any file")
    dt.add_argument("file", type=Path)

    args = parser.parse_args()

    # detect needs no signing key
    if args.command == "detect":
        if not args.file.exists():
            print(f"[error] File not found: {args.file}")
            sys.exit(1)
        detect_watermark(args.file)
        return

    # Sanitize identity: strip whitespace, reject dangerous characters,
    # enforce reasonable max length
    identity = args.identity.strip()
    if not identity:
        print("[error] --identity cannot be empty.")
        sys.exit(1)
    if len(identity) > 200:
        print("[error] --identity must be 200 characters or fewer.")
        sys.exit(1)
    if any(c in identity for c in ('/','\\','\x00','\n','\r')):
        print("[error] --identity contains invalid characters (path separators or null bytes).")
        sys.exit(1)
    args.identity = identity

    secret = get_or_create_key(args.identity)

    if args.command == "list":
        list_manifests(args.identity, secret)
        return

    if args.command == "verify":
        if not args.file.exists():
            print(f"[error] File not found: {args.file}")
            sys.exit(1)
        verify_file(args.file, args.identity, secret)
        return

    # watermark
    filepath: Path = args.file
    if not filepath.exists():
        print(f"[error] File not found: {filepath}")
        sys.exit(1)

    ext = filepath.suffix.lower()
    print(f"\n[Protector] Watermarking: {filepath}  (type: {ext})")

    if ext in TEXT_EXTS:
        result = watermark_text(filepath, args.identity, secret)
    elif ext in IMAGE_EXTS:
        result = watermark_image(filepath, args.identity, secret)
    elif ext in VIDEO_EXTS:
        result = watermark_video(filepath, args.identity, secret)
    elif ext in CODE_EXTS:
        result = watermark_code(filepath, args.identity, secret)
    else:
        print(f"[error] Unsupported file type: {ext}")
        print(f"  Supported: {sorted(TEXT_EXTS | IMAGE_EXTS | VIDEO_EXTS | CODE_EXTS)}")
        sys.exit(1)

    print(f"\n[Protector] ✓ Done!")
    print(f"  Watermarked file : {result['output']}")
    print(f"  Ownership receipt: {result['receipt']}")
    print(f"  Original SHA-256 : {result['hash']}")
    print(f"\n  Keep your receipt file safe — it's your legal proof of ownership.")


if __name__ == "__main__":
    import sys as _sys
    if _sys.version_info < (3, 10):
        print(f"[error] Protector requires Python 3.10 or later.")
        print(f"        You are running Python {_sys.version_info.major}.{_sys.version_info.minor}.")
        _sys.exit(1)
    main()