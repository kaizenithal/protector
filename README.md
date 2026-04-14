# Protector 🔏

> This was originally AI Generated. Please validate before taking legal action. Feel free to contribute.


### Cryptographic Evidence Toolkit for Creators

Three tools that work together to register your work, detect AI memorization,
and compile court-ready evidence — all stored locally, all cryptographically signed.

---

## The Three Tools

| Tool | Purpose |
|------|---------|
| `watermark.py` | Register & watermark your files with cryptographic proof of ownership |
| `canary.py` | Embed unique traceable phrases + probe AI models for memorization |
| `report.py` | Compile everything into a legal evidence report |

---

## Installation

```bash
pip install pillow numpy

# For video watermarking only:
# macOS:   brew install ffmpeg
# Ubuntu:  sudo apt install ffmpeg
# Windows: https://ffmpeg.org/download.html
```

---

## Full Workflow

### Step 1 — Register & watermark your work
```bash
python watermark.py watermark article.txt --identity "Your Name"
python watermark.py watermark photo.jpg   --identity "Your Name"
python watermark.py watermark script.py   --identity "Your Name"
```

### Step 2 — Embed canary phrases before publishing
```bash
python canary.py inject article.txt --identity "Your Name" --count 5
# → Produces article_canaried.txt  (publish THIS version)
# → Saves canary IDs to ~/.creatormark/canaries/
```

### Step 3 — Generate probe queries
```bash
python canary.py probes --canary-id <uuid-from-step-2>
# → Prints prompts to paste into any AI chatbot
```

### Step 4 — Log AI responses as evidence
```bash
python canary.py log \
  --canary-id <uuid> \
  --model "GPT-4o" \
  --probe-type completion \
  --response "The lambent cartographer oscillates..." \
  --identity "Your Name"
```

### Step 5 — Generate legal report
```bash
python report.py --identity "Your Name"
# → Saves a structured report to ~/.creatormark/reports/
```

---

## Your evidence vault

Everything lives in ~/.creatormark/ — back this up.

  keys.json       ← Signing key (chmod 600, never share)
  manifests/      ← One JSON per registered work
  canaries/       ← One JSON per canary phrase
  evidence/       ← One JSON per logged AI response
  reports/        ← Generated legal reports

Every record is signed with HMAC-SHA256. This proves each record
existed at a specific time and hasn't been tampered with.

---

## Legal resources

- U.S. Copyright Office: copyright.gov/registration
- Authors Guild: authorsguild.org
- National Writers Union: nwu.org
- Active litigation: NYT v. OpenAI | Andersen v. Stability AI | Getty v. Stability AI
