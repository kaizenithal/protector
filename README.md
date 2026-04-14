# Protector 🔏
# Protector 🔏

>Engine to support setting up a pipeline to cover legal protection of your digital assets.

### Cryptographic Evidence Toolkit for Creators

Protector helps you prove you created your work before anyone stole it.
It watermarks your files, embeds invisible traceable phrases, probes AI
models for memorization of your content, and compiles everything into a
legal evidence report you can hand to a copyright attorney.

This is free, open-source software licensed under GPL-3.0. It runs entirely
on your machine. Nothing is sent anywhere.

---

## Requirements

- **Python 3.10 or later** (required — uses modern union type syntax)
- **pip install pillow numpy** (required for image watermarking)
- **ffmpeg** (required for video watermarking only)
  - macOS: `brew install ffmpeg`
  - Ubuntu: `sudo apt install ffmpeg`
  - Windows: https://ffmpeg.org/download.html

## File Structure

All four files must be in the same directory:

```
watermark.py   — register and watermark your files
canary.py      — embed traceable phrases and probe AI models
report.py      — compile everything into a legal evidence report
stego.py       — multi-channel steganography engine (dependency)
```

**stego.py is required.** Without it, watermark.py falls back to
single-channel zero-width encoding only (Channel A). You will see a
warning if it is missing.

---

## ⚠️  BACK UP YOUR SIGNING KEY

Your signing key lives at `~/.Protector/keys.json`. This key is the
cryptographic root of all your ownership proofs. **If you lose it, every
manifest becomes unverifiable.**

Back it up now:
- Copy it to an encrypted cloud location (iCloud Keychain, Bitwarden, etc.)
- Or print it and store it somewhere safe

```bash
cat ~/.Protector/keys.json   # view your key to back it up
```

---

## Full Workflow

### Step 1 — Register and watermark your work
```bash
python watermark.py watermark article.txt  --identity "Your Name"
python watermark.py watermark photo.jpg    --identity "Your Name"
python watermark.py watermark script.py    --identity "Your Name"
python watermark.py watermark video.mp4    --identity "Your Name"
```

This creates a watermarked copy and a signed manifest receipt in
`~/.Protector/manifests/`.

### Step 2 — Embed canary phrases before publishing
```bash
python canary.py inject article.txt --identity "Your Name" --count 5
```

This produces `article_canaried.txt`. **Publish this file, not the
original.** The canary phrases are statistically unique sentences no
one else would independently write. Their IDs are hidden invisibly
inside the text.

### Step 3 — Generate probe queries
```bash
python canary.py probes --canary-id <uuid> --identity "Your Name"
```

Copy the prompts and paste them into any AI chatbot (ChatGPT, Gemini,
Claude, etc.). If the model completes your canary phrase, it was in its
training data — which means your content was scraped.

### Step 4 — Log AI responses as evidence
```bash
python canary.py log \
  --canary-id <uuid> \
  --model "GPT-4o" \
  --probe-type completion \
  --response-file response.txt \
  --identity "Your Name"
```

### Step 5 — Generate a legal evidence report
```bash
python report.py --identity "Your Name"
```

The report is saved to `~/.Protector/reports/` and is suitable for
submission to a copyright attorney.

---

## Your Evidence Vault

Everything lives in `~/.Protector/` — **back up this entire directory.**

```
~/.Protector/
  keys.json        ← Your signing key (chmod 600, never share)
  manifests/       ← One JSON per registered work
  canaries/        ← One JSON per canary phrase
  evidence/        ← One JSON per logged AI response
  reports/         ← Generated legal reports
```

Every record is signed with HMAC-SHA256. This proves each record existed
at a specific time and has not been tampered with.

---

## Verify and Detect

```bash
# Verify a file is yours
python watermark.py verify photo.jpg --identity "Your Name"

# List all your registered works
python watermark.py list --identity "Your Name"

# Detect watermarks in any file
python watermark.py detect suspicious_file.txt

# Analyze steganography channels in a text file
python stego.py analyze article_watermarked.txt

# Check encoding capacity of a file
python stego.py capacity article.txt
```

---

## How the Watermarking Works

| Content | Invisible Layer | Visible Layer |
|---------|----------------|---------------|
| Text / Articles | Zero-width Unicode (A) + Homoglyphs (B) | HTML comment footer |
| Images | Distributed-stride LSB steganography | Corner copyright badge |
| Video | ffmpeg container metadata | Burned-in text overlay |
| Code | Zero-width + Homoglyphs in header | Comment block with hash |

Every watermarked file generates a signed HMAC-SHA256 ownership manifest.
This is your legal proof of prior creation.

---

## Legal Resources

- U.S. Copyright Office: copyright.gov/registration
- Authors Guild: authorsguild.org
- National Writers Union: nwu.org
- Volunteer Lawyers for the Arts: vlany.org
- EU: euipo.europa.eu
- UK: gov.uk/intellectual-property-an-overview
- Active litigation to follow:
  - NYT v. OpenAI (S.D.N.Y.)
  - Andersen v. Stability AI (N.D. Cal.)
  - Getty Images v. Stability AI

---

## Windows Users

`os.chmod()` — used to restrict your key file to owner-only access — has
no effect on Windows NTFS. Your key file at `~/.Protector/keys.json` will
not be automatically permission-restricted on Windows.

To manually restrict it:
```cmd
icacls %USERPROFILE%\.Protector\keys.json /inheritance:r /grant:r "%USERNAME%:R"
```
