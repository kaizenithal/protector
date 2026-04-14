#!/usr/bin/env python3
"""
CreatorMark - Cryptographic Watermarking CLI
Protects text, images, video, and code with provable ownership.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ── Optional heavy deps (imported lazily) ────────────────────────────────────
def _require(pkg, install_hint):
    try:
        return __import__(pkg)
    except ImportError:
        print(f"[error] Missing dependency: {pkg}\n  Install: {install_hint}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# KEY MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

KEY_FILE = Path.home() / ".creatormark" / "keys.json"

def load_keys():
    if not KEY_FILE.exists():
        return {}
    with open(KEY_FILE) as f:
        return json.load(f)

def save_keys(keys):
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(KEY_FILE, "w") as f:
        json.dump(keys, f, indent=2)
    os.chmod(KEY_FILE, 0o600)

def get_or_create_key(identity: str) -> bytes:
    keys = load_keys()
    if identity not in keys:
        secret = os.urandom(32).hex()
        keys[identity] = {"secret": secret, "created": datetime.now(timezone.utc).isoformat()}
        save_keys(keys)
        print(f"[key] New signing key created for '{identity}'")
    return bytes.fromhex(keys[identity]["secret"])


# ─────────────────────────────────────────────────────────────────────────────
# MANIFEST / RECEIPT
# ─────────────────────────────────────────────────────────────────────────────

MANIFEST_DIR = Path.home() / ".creatormark" / "manifests"

def build_manifest(filepath: Path, identity: str, content_hash: str,
                   wm_type: str, extra: dict = None) -> dict:
    manifest = {
        "id": str(uuid.uuid4()),
        "version": "1.0",
        "owner": identity,
        "file": str(filepath.resolve()),
        "filename": filepath.name,
        "content_type": wm_type,
        "sha256_original": content_hash,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "unix_ts": int(time.time()),
    }
    if extra:
        manifest.update(extra)
    return manifest

def sign_manifest(manifest: dict, secret: bytes) -> str:
    payload = json.dumps(manifest, sort_keys=True).encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

def save_manifest(manifest: dict, signature: str):
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
# TEXT WATERMARKING  (Unicode zero-width steganography + metadata block)
# ─────────────────────────────────────────────────────────────────────────────

# Zero-width chars used to encode binary payload invisibly in text
ZW_ZERO = "\u200b"   # zero-width space  → bit 0
ZW_ONE  = "\u200c"   # zero-width non-joiner → bit 1
ZW_SEP  = "\u200d"   # zero-width joiner → byte separator

def _encode_zw(data: str) -> str:
    """Encode a string as invisible zero-width characters."""
    bits = "".join(f"{byte:08b}" for byte in data.encode())
    zw = "".join(ZW_ONE if b == "1" else ZW_ZERO for b in bits)
    return ZW_SEP + zw + ZW_SEP

def _decode_zw(text: str) -> str | None:
    """Extract hidden payload from zero-width chars, or None if absent."""
    parts = text.split(ZW_SEP)
    if len(parts) < 3:
        return None
    zw = parts[1]
    bits = "".join("1" if c == ZW_ONE else "0" for c in zw if c in (ZW_ZERO, ZW_ONE))
    if len(bits) % 8 != 0:
        return None
    try:
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode()
    except Exception:
        return None

def watermark_text(filepath: Path, identity: str, secret: bytes) -> dict:
    text = filepath.read_text(encoding="utf-8")
    original_hash = hashlib.sha256(text.encode()).hexdigest()

    payload = json.dumps({
        "owner": identity,
        "file": filepath.name,
        "ts": int(time.time()),
    })
    hidden = _encode_zw(payload)

    # Inject hidden payload after first paragraph break (or at end)
    if "\n\n" in text:
        idx = text.index("\n\n") + 2
        watermarked = text[:idx] + hidden + text[idx:]
    else:
        watermarked = text + hidden

    # Append human-readable attribution block
    sig_line = f"\n\n<!-- © {identity} | SHA256:{original_hash[:16]}... | CreatorMark -->\n"
    watermarked += sig_line

    out_path = filepath.with_stem(filepath.stem + "_watermarked")
    out_path.write_text(watermarked, encoding="utf-8")

    manifest = build_manifest(filepath, identity, original_hash, "text",
                               {"hidden_payload": payload})
    sig = sign_manifest(manifest, secret)
    receipt = save_manifest(manifest, sig)
    return {"output": out_path, "receipt": receipt, "hash": original_hash}


# ─────────────────────────────────────────────────────────────────────────────
# IMAGE WATERMARKING  (LSB steganography + visible overlay)
# ─────────────────────────────────────────────────────────────────────────────

def watermark_image(filepath: Path, identity: str, secret: bytes) -> dict:
    Image = _require("PIL.Image", "pip install Pillow").Image
    ImageDraw = _require("PIL.ImageDraw", "pip install Pillow").ImageDraw
    ImageFont = _require("PIL.ImageFont", "pip install Pillow").ImageFont
    import PIL.Image as PILImage
    import PIL.ImageDraw as PILDraw
    import PIL.ImageFont as PILFont
    import struct, numpy

    original_hash = file_sha256(filepath)
    img = PILImage.open(filepath).convert("RGBA")
    arr = numpy.array(img, dtype=numpy.uint8)

    # --- LSB steganography (invisible layer) ---
    payload = f"OWNER:{identity}|TS:{int(time.time())}|HASH:{original_hash[:32]}"
    payload_bytes = payload.encode() + b"\x00"  # null terminated
    bits = "".join(f"{b:08b}" for b in payload_bytes)

    flat = arr.flatten()
    if len(bits) > len(flat):
        print("[warn] Image too small for full LSB payload — truncating")
        bits = bits[:len(flat)]

    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | int(bit)

    arr = flat.reshape(arr.shape)
    img_wm = PILImage.fromarray(arr, "RGBA")

    # --- Visible watermark overlay ---
    draw = PILDraw.Draw(img_wm)
    w, h = img_wm.size
    label = f"© {identity}"
    try:
        font = PILFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", max(14, h // 40))
    except Exception:
        font = PILFont.load_default()

    bbox = draw.textbbox((0, 0), label, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x, y = w - tw - 12, h - th - 12
    draw.rectangle([x - 4, y - 4, x + tw + 4, y + th + 4], fill=(0, 0, 0, 120))
    draw.text((x, y), label, fill=(255, 255, 255, 220), font=font)

    out_path = filepath.with_stem(filepath.stem + "_watermarked").with_suffix(".png")
    img_wm.save(out_path, "PNG")

    manifest = build_manifest(filepath, identity, original_hash, "image",
                               {"lsb_payload": payload, "dimensions": f"{w}x{h}"})
    sig = sign_manifest(manifest, secret)
    receipt = save_manifest(manifest, sig)
    return {"output": out_path, "receipt": receipt, "hash": original_hash}


# ─────────────────────────────────────────────────────────────────────────────
# CODE WATERMARKING  (comment block + invisible Unicode in identifiers)
# ─────────────────────────────────────────────────────────────────────────────

COMMENT_STYLES = {
    ".py": ("#", "#"),
    ".js": ("//", "//"),
    ".ts": ("//", "//"),
    ".jsx": ("//", "//"),
    ".tsx": ("//", "//"),
    ".java": ("//", "//"),
    ".c": ("//", "//"),
    ".cpp": ("//", "//"),
    ".go": ("//", "//"),
    ".rs": ("//", "//"),
    ".rb": ("#", "#"),
    ".sh": ("#", "#"),
    ".php": ("//", "//"),
    ".swift": ("//", "//"),
    ".kt": ("//", "//"),
}

def watermark_code(filepath: Path, identity: str, secret: bytes) -> dict:
    code = filepath.read_text(encoding="utf-8")
    original_hash = hashlib.sha256(code.encode()).hexdigest()
    ext = filepath.suffix.lower()
    cmt = COMMENT_STYLES.get(ext, ("#", "#"))[0]

    ts = datetime.now(timezone.utc).isoformat()
    payload = json.dumps({"owner": identity, "file": filepath.name,
                          "hash": original_hash, "ts": ts})
    hidden_payload = _encode_zw(payload)

    header = (
        f"{cmt} ═══════════════════════════════════════════════\n"
        f"{cmt}  © {identity}  |  CreatorMark v1.0\n"
        f"{cmt}  Registered: {ts}\n"
        f"{cmt}  SHA-256: {original_hash}\n"
        f"{cmt}  This file contains cryptographic ownership proof.\n"
        f"{cmt}  Unauthorized training use violates copyright law.\n"
        f"{cmt} ═══════════════════════════════════════════════\n\n"
    )

    watermarked = header + code + f"\n{hidden_payload}"
    out_path = filepath.with_stem(filepath.stem + "_watermarked")
    out_path.write_text(watermarked, encoding="utf-8")

    manifest = build_manifest(filepath, identity, original_hash, "code",
                               {"language": ext, "hidden_payload": payload})
    sig = sign_manifest(manifest, secret)
    receipt = save_manifest(manifest, sig)
    return {"output": out_path, "receipt": receipt, "hash": original_hash}


# ─────────────────────────────────────────────────────────────────────────────
# VIDEO WATERMARKING  (metadata injection via ffmpeg)
# ─────────────────────────────────────────────────────────────────────────────

def watermark_video(filepath: Path, identity: str, secret: bytes) -> dict:
    import subprocess, shutil

    if not shutil.which("ffmpeg"):
        print("[error] ffmpeg not found. Install: https://ffmpeg.org/download.html")
        sys.exit(1)

    original_hash = file_sha256(filepath)
    ts = datetime.now(timezone.utc).isoformat()
    out_path = filepath.with_stem(filepath.stem + "_watermarked")

    meta_comment = (
        f"Copyright: {identity} | "
        f"CreatorMark SHA256:{original_hash} | "
        f"Registered:{ts} | "
        f"Unauthorized AI training use prohibited"
    )

    cmd = [
        "ffmpeg", "-y", "-i", str(filepath),
        "-metadata", f"copyright=© {identity}",
        "-metadata", f"comment={meta_comment}",
        "-metadata", f"encoded_by=CreatorMark",
        "-metadata", f"creation_time={ts}",
        # Burn visible watermark using drawtext filter
        "-vf", (
            f"drawtext=text='© {identity}':fontsize=24:fontcolor=white@0.6:"
            f"x=w-tw-20:y=h-th-20:box=1:boxcolor=black@0.4:boxborderw=6"
        ),
        "-codec:a", "copy",
        str(out_path)
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[error] ffmpeg failed:\n{result.stderr}")
        sys.exit(1)

    manifest = build_manifest(filepath, identity, original_hash, "video",
                               {"ffmpeg_metadata": meta_comment})
    sig = sign_manifest(manifest, secret)
    receipt = save_manifest(manifest, sig)
    return {"output": out_path, "receipt": receipt, "hash": original_hash}


# ─────────────────────────────────────────────────────────────────────────────
# VERIFY
# ─────────────────────────────────────────────────────────────────────────────

def verify_file(filepath: Path, identity: str, secret: bytes):
    """Check if a file matches any stored manifest for this identity."""
    current_hash = file_sha256(filepath)
    print(f"\n[verify] File : {filepath}")
    print(f"         SHA256: {current_hash}")

    if not MANIFEST_DIR.exists():
        print("[verify] No manifests found. Run 'watermark' first.")
        return

    found = []
    for mf in MANIFEST_DIR.glob("*.json"):
        with open(mf) as f:
            record = json.load(f)
        if record.get("owner") != identity:
            continue
        if record.get("sha256_original") == current_hash:
            found.append(record)

    if not found:
        print("[verify] ✗  No matching manifest found for this identity.")
        print("         File may have been modified or was not watermarked by you.")
        return

    for record in found:
        sig_stored = record.pop("hmac_sha256", None)
        sig_check = sign_manifest(record, secret)
        valid = hmac.compare_digest(sig_stored or "", sig_check)
        print(f"\n[verify] ✓  Match found!")
        print(f"         Manifest ID : {record['id']}")
        print(f"         Registered  : {record['timestamp_utc']}")
        print(f"         Type        : {record['content_type']}")
        print(f"         HMAC valid  : {'YES ✓' if valid else 'NO — manifest may be tampered!'}")


# ─────────────────────────────────────────────────────────────────────────────
# LIST MANIFESTS
# ─────────────────────────────────────────────────────────────────────────────

def list_manifests(identity: str):
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

    print(f"\n{'ID':<38} {'Type':<8} {'File':<30} {'Registered'}")
    print("─" * 100)
    for r in records:
        print(f"{r['id']:<38} {r['content_type']:<8} {r['filename']:<30} {r['timestamp_utc']}")


# ─────────────────────────────────────────────────────────────────────────────
# DETECT (check for watermarks in a file you don't own)
# ─────────────────────────────────────────────────────────────────────────────

def detect_watermark(filepath: Path):
    """Attempt to extract any CreatorMark watermark from a file."""
    ext = filepath.suffix.lower()
    print(f"\n[detect] Scanning: {filepath}")

    if ext in (".txt", ".md", ".html", ".htm", ".rst"):
        text = filepath.read_text(encoding="utf-8", errors="ignore")
        payload = _decode_zw(text)
        if payload:
            print(f"[detect] ✓ Hidden text payload found:\n  {payload}")
        else:
            print("[detect] No hidden zero-width payload detected.")

    elif ext in COMMENT_STYLES:
        code = filepath.read_text(encoding="utf-8", errors="ignore")
        payload = _decode_zw(code)
        if payload:
            print(f"[detect] ✓ Hidden code payload found:\n  {payload}")
        else:
            print("[detect] No hidden payload detected.")

    elif ext in (".jpg", ".jpeg", ".png", ".bmp", ".tiff"):
        try:
            import numpy
            from PIL import Image
            img = Image.open(filepath).convert("RGBA")
            arr = numpy.array(img).flatten()
            bits = "".join(str(b & 1) for b in arr)
            result = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte = int(bits[i:i+8], 2)
                if byte == 0:
                    break
                result.append(byte)
            decoded = result.decode("utf-8", errors="ignore")
            if "OWNER:" in decoded or "CreatorMark" in decoded:
                print(f"[detect] ✓ LSB steganography payload found:\n  {decoded}")
            else:
                print("[detect] No recognizable LSB payload found.")
        except ImportError:
            print("[detect] Install Pillow + numpy to scan images.")

    elif ext in (".mp4", ".mov", ".avi", ".mkv", ".webm"):
        import subprocess, shutil
        if not shutil.which("ffprobe"):
            print("[detect] ffprobe not found (install ffmpeg).")
            return
        result = subprocess.run(
            ["ffprobe", "-v", "quiet", "-print_format", "json",
             "-show_format", str(filepath)],
            capture_output=True, text=True
        )
        if "CreatorMark" in result.stdout or "copyright" in result.stdout.lower():
            import json as _json
            data = _json.loads(result.stdout)
            tags = data.get("format", {}).get("tags", {})
            print(f"[detect] ✓ Video metadata found:")
            for k, v in tags.items():
                print(f"  {k}: {v}")
        else:
            print("[detect] No CreatorMark metadata found in video.")
    else:
        print(f"[detect] Unsupported file type: {ext}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="creatormark",
        description="CreatorMark — Cryptographic watermarking for creators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  creatormark watermark article.txt  --identity "Jane Doe"
  creatormark watermark photo.jpg    --identity "Jane Doe"
  creatormark watermark script.py    --identity "Jane Doe"
  creatormark watermark video.mp4    --identity "Jane Doe"
  creatormark verify   photo.jpg     --identity "Jane Doe"
  creatormark list                   --identity "Jane Doe"
  creatormark detect   suspicious_file.txt
"""
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # watermark
    wm = sub.add_parser("watermark", help="Watermark a file")
    wm.add_argument("file", type=Path)
    wm.add_argument("--identity", required=True, help="Your name or creator ID")

    # verify
    vr = sub.add_parser("verify", help="Verify a file against your manifests")
    vr.add_argument("file", type=Path)
    vr.add_argument("--identity", required=True)

    # list
    ls = sub.add_parser("list", help="List all your registered works")
    ls.add_argument("--identity", required=True)

    # detect
    dt = sub.add_parser("detect", help="Detect watermarks in any file")
    dt.add_argument("file", type=Path)

    args = parser.parse_args()

    if args.command == "detect":
        detect_watermark(args.file)
        return

    secret = get_or_create_key(args.identity)

    if args.command == "list":
        list_manifests(args.identity)
        return

    if args.command == "verify":
        verify_file(args.file, args.identity, secret)
        return

    # watermark
    filepath: Path = args.file
    if not filepath.exists():
        print(f"[error] File not found: {filepath}")
        sys.exit(1)

    ext = filepath.suffix.lower()
    print(f"\n[creatormark] Watermarking: {filepath}  (type: {ext})")

    text_exts  = {".txt", ".md", ".html", ".htm", ".rst", ".csv"}
    image_exts = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"}
    video_exts = {".mp4", ".mov", ".avi", ".mkv", ".webm"}
    code_exts  = set(COMMENT_STYLES.keys())

    if ext in text_exts:
        result = watermark_text(filepath, args.identity, secret)
    elif ext in image_exts:
        result = watermark_image(filepath, args.identity, secret)
    elif ext in video_exts:
        result = watermark_video(filepath, args.identity, secret)
    elif ext in code_exts:
        result = watermark_code(filepath, args.identity, secret)
    else:
        print(f"[error] Unsupported file type: {ext}")
        print(f"  Supported: {sorted(text_exts | image_exts | video_exts | code_exts)}")
        sys.exit(1)

    print(f"\n[creatormark] ✓ Done!")
    print(f"  Watermarked file : {result['output']}")
    print(f"  Ownership receipt: {result['receipt']}")
    print(f"  Original SHA-256 : {result['hash']}")
    print(f"\n  Keep your receipt file safe — it's your legal proof of ownership.")


if __name__ == "__main__":
    main()