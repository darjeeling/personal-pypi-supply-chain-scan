# Malicious Supply Chain Review Prompt v2

This prompt asks GPT-5.5 to review extracted PyPI package artifacts for malicious supply-chain compromise indicators only.

Primary focus:

- automatic execution such as `.pth`, `sitecustomize.py`, `usercustomize.py`, `setup.py`, PEP 517 hooks, import-time side effects
- credential theft from environment variables, `.env`, SSH keys, cloud credentials, AI provider keys, Kubernetes config, CI/CD secrets, registry tokens
- exfiltration and staging through archive creation, webhook/drop services, raw public IPs, suspicious domains, attacker-controlled repositories
- persistence through systemd, launch agents, cron, shell profile edits, startup folders, background polling
- lateral movement through Kubernetes, Docker socket, cloud metadata, GitHub Actions, registry publish tokens
- obfuscation and staged loaders using base64, zlib, gzip, marshal, pickle, eval, exec, compile, XOR, steganography, downloader stubs
- distribution integrity anomalies such as unexpected files, hidden payloads, native binaries, wheel/sdist mismatch, typosquatting, dependency confusion

Non-goals:

- ordinary application security review
- benign CLI behavior
- normal SDK/API calls
- normal documented environment variable usage
- expected user-triggered network/file access

Output languages:

- Korean report
- English report

