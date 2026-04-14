# Protector — TODO
### Verified against actual codebase state — April 2026

Every item below was confirmed present in the code by direct inspection
and automated checks before being listed. Nothing here is speculative.

Severity legend:
  [BLOCKER]  Must fix before release — correctness or security issue
  [HIGH]     Should fix before release — affects usability or trust
  [MEDIUM]   Fix soon after release — noticeable gaps
  [LOW]      Future improvement — parked by design

---

## report.py

[BLOCKER] `import hmac` is unaliased — hmac module name can be shadowed
  File   : report.py line 11
  Detail : `import hmac` with no alias, then `hmac.new(...)` and
           `hmac.compare_digest(...)` called directly. All other files
           use `import hmac as _hmac` for safety. Inconsistent and at
           risk if any local variable named `hmac` is ever introduced.
  Fix    : Change to `import hmac as _hmac` and update all call sites.

[BLOCKER] File handles leaked in load_all()
  File   : report.py lines 44, 50, 56
  Detail : `json.load(open(f))` used in all three loops — manifests,
           canaries, evidence. File handles are never closed. On a large
           vault this will eventually exhaust OS file descriptor limits.
  Fix    : Replace with `with open(f) as fh: r = json.load(fh)` in each.

[BLOCKER] load_secret() silently returns b"" if identity not found
  File   : report.py lines 22-28
  Detail : If identity is misspelled or not in keys.json, load_secret()
           returns empty bytes without any warning. Every HMAC verification
           in the report then silently fails, marking all records INVALID
           with no explanation why. A creator hands this to a lawyer and
           every signature shows invalid — devastating to their case.
  Fix    : Check if identity is missing and print a clear warning before
           returning, noting that all HMAC results will be unreliable.

[HIGH] verify_hmac() duplicates verify_manifest_sig() from watermark.py
  File   : report.py lines 31-36
  Detail : Two independent implementations of the same HMAC verification
           logic. If one is updated the other silently diverges. Already
           happened once — report.py handles both "hmac_sha256" and "hmac"
           keys while watermark.py only handles "hmac_sha256".
  Fix    : Import verify_manifest_sig from watermark.py, or move shared
           HMAC logic to a utils.py module both files import from.

[HIGH] Report filename slug uses date only — same-day runs overwrite
  File   : report.py line 71
  Detail : `slug = now[:10].replace("-", "")` produces e.g. "20260413".
           Running the report twice in one day silently overwrites the
           first. For a legal evidence document, silent overwrite is
           unacceptable — each run should be independently preserved.
  Fix    : Include time component or a short UUID in the slug, e.g.:
           `now[:19].replace(":", "").replace("-", "").replace("T", "_")`

[HIGH] AI response truncated to 300 chars in the legal evidence document
  File   : report.py line 140
  Detail : `e['response'][:300]` truncates the logged AI response in the
           report output. For a terminal printout this is fine. In a
           document submitted to a copyright attorney or court, truncated
           evidence is weaker than full evidence and could be challenged.
  Fix    : Write the full response to the report. Add a `--truncate`
           flag if readability is a concern for human review.

[MEDIUM] argparse imported inside main() instead of top-level
  File   : report.py line 205
  Detail : Minor style inconsistency — all other files import argparse
           at the top. Makes the file look unfinished to contributors.
  Fix    : Move `import argparse` to the top of the file.

---

## watermark.py

[BLOCKER] _require() is defined but never called — dead code
  File   : watermark.py lines 40-45
  Detail : After the image watermarking rewrite, all PIL imports were
           moved into a try/except block inside watermark_image(). The
           _require() helper now has exactly zero callers. Dead code in
           a security tool creates confusion about what the codebase
           actually does.
  Fix    : Remove _require() entirely.

[BLOCKER] Fallback _decode_zw() in watermark.py is single-shot (parts[1])
  File   : watermark.py lines 150-162
  Detail : The fallback zero-width decoder (used when stego.py is absent)
           still reads only parts[1] — the first block. stego.py's
           _zw_decode() was correctly updated to scan all blocks, but
           watermark.py's inline fallback was not. If stego.py is missing
           and the first ZW block was stripped, the second copy is never
           checked.
  Fix    : Update the fallback _decode_zw() to loop over odd-indexed
           parts the same way stego.py does, or simplify by always
           delegating to stego.py and removing the fallback entirely
           (making stego.py a hard dependency rather than optional).

[HIGH] stego.py import warning fires at module import time
  File   : watermark.py line 138
  Detail : `print("[warn] stego.py not found...")` is inside the except
           block of the top-level try/import. This fires whenever
           watermark.py is imported by any other module (e.g. report.py
           importing verify_manifest_sig), even when watermarking is
           not being performed. Noisy and misleading in those contexts.
  Fix    : Move the warning into _embed() so it only fires when
           watermarking is actually attempted.

[HIGH] _extract() is defined but never called
  File   : watermark.py lines 176-180
  Detail : `_extract()` was defined as the extraction counterpart to
           `_embed()` but is never called anywhere in the codebase.
           Dead code. verify_file() uses file_sha256() comparison rather
           than payload extraction — which is correct — but _extract()
           was never wired up to detect_watermark() either.
  Fix    : Either wire _extract() into detect_watermark() for text/code
           files, or remove it. Leaving dead code in a security tool
           misleads contributors about how extraction works.

[HIGH] detect_watermark() image branch scans sequentially but watermark
  was written with distributed stride — will find nothing
  File   : watermark.py lines 519-534
  Detail : watermark_image() writes LSB bits at stride-spaced indices
           (stride stored in manifest). detect_watermark() reads bits
           at indices 0,1,2,3... sequentially. The sequential scan will
           not recover the payload for any image watermarked with the
           current code. The existing warning comment acknowledges this
           but still attempts the scan, producing misleading output.
  Fix    : Remove the sequential scan attempt entirely. Replace with a
           clear message directing the user to run `verify` instead,
           which uses the manifest's stride value.

[HIGH] watermark_text() has stale comment referencing syntactic markers
  File   : watermark.py line 200
  Detail : Comment reads "Multi-channel embedding: homoglyphs + zero-width
           + syntactic markers". Channel C was removed. Two active channels
           remain: A (zero-width) and B (homoglyphs).
  Fix    : Update comment to "Multi-channel embedding: zero-width (A)
           + homoglyphs (B)".

[HIGH] watermark_code() has stale comment referencing syntactic markers
  File   : watermark.py line 340
  Detail : Comment reads "Embed homoglyphs + syntactic into the comment
           header". Channel C was removed.
  Fix    : Update to "Embed via both channels (A + B) into comment header".

[MEDIUM] build_manifest() type hint uses `extra: dict = None`
  File   : watermark.py line 86
  Detail : Should be `extra: dict | None = None` for correctness under
           Python 3.10+ type checking. Current form works at runtime but
           is imprecise and will produce type-checker warnings.
  Fix    : Change to `extra: dict | None = None`.

[MEDIUM] ffmpeg drawtext filter not safe for identities with special chars
  File   : watermark.py line 397
  Detail : Identity is interpolated directly into the ffmpeg drawtext
           filter string. An identity containing single quotes, colons,
           or backslashes will break the filter string silently or cause
           ffmpeg to fail.
  Fix    : Escape or sanitize the identity for ffmpeg filter context
           before interpolation. At minimum, replace single quotes.

[MEDIUM] os.chmod(KEY_FILE, 0o600) is a no-op on Windows
  File   : watermark.py line 64
  Detail : chmod has no effect on Windows NTFS. The key file will not
           be permission-restricted on Windows without additional work.
  Fix    : Add a note in the README. Optionally detect platform and use
           `icacls` via subprocess on Windows for equivalent protection.

---

## canary.py

[HIGH] scan_file() Channel B loop is O(n×m) — slow on long documents
  File   : canary.py lines 360-373
  Detail : Channel B scanning calls _homoglyph_decode() on every
           sentence/line segment in the file. For a long article with
           500+ segments this is 500 decode attempts per scan. Since
           Channel B in canary injection currently never fires (see MEDIUM
           item below), this loop always runs to completion and always
           finds nothing — paying the full cost every time.
  Fix    : Gate the Channel B scan on whether any homoglyphs are
           actually detected in the text first. A quick pre-scan for
           any character in _HOMOGLYPH_REVERSE costs O(n) and avoids
           the O(n×m) loop when no homoglyphs are present.

[HIGH] inject_canaries() docstring describes old single-channel behaviour
  File   : canary.py lines 270-281
  Detail : Docstring says "The canary ID is hidden in zero-width Unicode
           immediately before it" with no mention of Channel B. The
           dual-channel injection was added but the docstring was not
           updated.
  Fix    : Update docstring to describe both channels and the fallback
           behaviour when Channel B capacity is insufficient.

[MEDIUM] Channel B in canary injection never fires in practice
  File   : canary.py line 310
  Detail : A UUID payload (37 bytes) requires 296 carrier bits. Typical
           canary phrases have 3-6 bytes of homoglyph capacity (24-48
           bits). The capacity check correctly rejects Channel B every
           time — but the branch and the check exist as active code,
           which is misleading. Channel A alone is used for canary IDs.
  Fix options (pick one before release):
    (a) Encode a short fingerprint of the UUID instead of the full UUID
        — e.g. first 4 bytes of SHA256(canary_id) — which fits in the
        phrase capacity and provides partial identification.
    (b) Document this as a known limitation in a comment and leave the
        branch as future scaffolding.
    (c) Remove the Channel B branch from inject_canaries() until (a)
        is properly designed.

[MEDIUM] _NOUN vocabulary contains duplicate: 'palimpsest'
  File   : canary.py lines 123-134
  Detail : 'palimpsest' appears twice in _NOUN. Reduces effective
           vocabulary size and skews phrase distribution toward that word.
  Fix    : Remove one occurrence.

[MEDIUM] _VERB vocabulary contains duplicate: 'desiccates'
  File   : canary.py lines 136-147
  Detail : 'desiccates' appears twice in _VERB. Same issue as above.
  Fix    : Remove one occurrence.

[MEDIUM] _CODE_EXTS duplicates CODE_EXTS from watermark.py
  File   : canary.py lines 263-266
  Detail : canary.py defines its own `_CODE_EXTS` set independently.
           watermark.py defines `CODE_EXTS` from `COMMENT_STYLES.keys()`.
           If a new language extension is added to one, the other silently
           misses it.
  Fix    : Import CODE_EXTS from watermark.py, or move to a shared
           constants.py both files import.

[LOW] --count shortfall not reported to user
  File   : canary.py inject command
  Detail : If the document is too short to fit the requested canary count,
           fewer canaries are injected silently. The user may not notice.
  Fix    : After injection, if result['count'] < requested count, print
           a note explaining the document was too short.

---

## stego.py

  No blockers or high-priority issues. All previously identified items
  were resolved during the Channel C removal rewrite:
    ✓ Unused imports (json, unicodedata) removed
    ✓ _zw_decode() scans all ZW blocks (not just parts[1])
    ✓ Channel B capacity comparison uses byte length consistently
    ✓ Channel B post-Channel-A comment added
    ✓ Channel C fully removed with future-release note

---

## Project / Repository

[BLOCKER] No LICENSE file
  Detail : Without a license, the project is legally "all rights reserved"
           by default — the opposite of the intended open-source mission.
  Fix    : Add LICENSE file before any public release.
           Recommendation: GPL-3.0 (prevents companies taking it
           proprietary) or MIT (maximum adoption). Given the mission,
           GPL-3.0 is worth strong consideration.

[BLOCKER] No SECURITY.md
  Detail : Any security tool needs a documented process for reporting
           vulnerabilities privately before public disclosure.
  Fix    : Add SECURITY.md with a contact method (dedicated email or
           GitHub private security advisory).

[HIGH] README.md needs to be renamed PROTECTOR.md
  Detail : Agreed during session — rename before public release.

[HIGH] PROTECTOR.md does not mention stego.py
  Detail : stego.py is a core dependency that must be in the same
           directory. The README makes no mention of it, its role,
           or the fallback behaviour when it is absent.
  Fix    : Add a section describing the file structure and dependencies.

[HIGH] No mention of key backup in documentation
  Detail : The signing key at ~/.Protector/keys.json is the root of
           all provenance. If lost, all manifests become unverifiable.
           This is the single most critical operational risk for users.
  Fix    : Add a prominent "BACK UP YOUR KEY" section with specific
           instructions (encrypted backup, etc).

[HIGH] No CONTRIBUTING.md
  Detail : No guidance for contributors on code style, how to propose
           new vocabulary words, or how new steganography channels
           should be reviewed before merging.

[HIGH] No Python version requirement stated or enforced
  Detail : The codebase uses `str | None` union syntax (PEP 604) which
           requires Python 3.10+. Running on 3.9 produces a SyntaxError
           with no helpful message.
  Fix    : Add a version check at startup in watermark.py and document
           the requirement (Python >= 3.10) in PROTECTOR.md.

[HIGH] No input sanitization on --identity
  Detail : Identity is embedded into file paths, ffmpeg metadata, JSON
           payloads, and watermark text. A malformed identity (path
           separators, null bytes, shell metacharacters, very long strings)
           could cause unexpected behaviour across all watermark types.
  Fix    : Validate identity at the CLI entry point in watermark.py:
           strip whitespace, reject path separators and null bytes,
           enforce a max length (e.g. 200 chars).

[MEDIUM] No shared constants.py or utils.py
  Detail : KEY_FILE, MANIFEST_DIR, CANARY_DIR, EVIDENCE_DIR, REPORTS_DIR
           are defined independently in both watermark.py and report.py.
           CODE_EXTS is defined independently in watermark.py and canary.py.
           HMAC verification logic is duplicated between watermark.py and
           report.py. Single source of truth needed.
  Fix    : Create constants.py and utils.py before release.

[MEDIUM] No pyproject.toml or setup.py
  Detail : No package definition. Users must manually place all files in
           the same directory. Cannot be installed via pip.
  Fix    : Add a minimal pyproject.toml.

[MEDIUM] PROTECTOR.md legal resources section is US-centric
  Detail : International creators need pointers to their own IP offices
           and relevant legislation (EU AI Act, UK Copyright Act, etc).

[MEDIUM] No CHANGELOG.md
  Detail : Standard practice for open-source projects.

[LOW] No __version__ string anywhere in the codebase
  Detail : watermark.py header says "Protector v1.0" in comment blocks
           but there is no canonical __version__ = "0.1.0" string.
  Fix    : Add to constants.py (when created) and wire to --version flag.

[LOW] No automated tests
  Detail : No test suite for a security tool that creators will depend on
           for legal evidence.
  Fix    : Add tests/ with at minimum:
           • Round-trip encode/decode for Channels A and B
           • Manifest sign/verify round-trip
           • Canary inject/scan round-trip
           • Fallback behaviour when stego.py is absent

---

## Summary

  BLOCKER : 8   (must fix before any public release)
  HIGH    : 16  (should fix before public release)
  MEDIUM  : 12  (fix in first patch release)
  LOW     : 3   (future work)
  TOTAL   : 39