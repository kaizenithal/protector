# Security Policy

## Reporting a Vulnerability

Protector is a security tool that creators depend on for legal evidence.
Vulnerabilities — especially anything that could silently weaken watermark
protection, corrupt evidence records, or compromise signing keys — are taken
seriously.

**Please do not open a public GitHub issue for security vulnerabilities.**

### How to report

Email: monsieur@legitimate.earth

Or use GitHub's private security advisory feature:
Repository → Security → Advisories → New draft security advisory

### What to include

- A clear description of the vulnerability
- The affected file(s) and line numbers if known
- Steps to reproduce
- Potential impact on creators using the tool
- Any suggested fix, if you have one

### What to expect

- Acknowledgement within 48 hours
- A fix or workaround within 14 days for critical issues
- Credit in the changelog if you wish

### Scope

In scope:
- HMAC signing or verification weaknesses
- Steganography channel bypasses
- Key storage or key derivation issues
- Any issue that causes false "VALID" verification results
- Any issue that silently degrades watermark coverage

Out of scope:
- Issues in third-party dependencies (Pillow, numpy, ffmpeg)
- Social engineering
- Physical access scenarios