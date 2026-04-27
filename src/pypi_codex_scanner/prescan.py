from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ast
import base64
import binascii
import ipaddress
import json
import math
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse


TEXT_SUFFIXES = {
    ".cfg",
    ".cmd",
    ".ini",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".pyw",
    ".pth",
    ".rst",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
BINARY_SUFFIXES = {".dll", ".dylib", ".exe", ".node", ".pyd", ".so"}
HIGH_VALUE_NAMES = {
    ".env",
    "entry_points.txt",
    "metadata",
    "pyproject.toml",
    "requires.txt",
    "setup.cfg",
    "setup.py",
    "sitecustomize.py",
    "usercustomize.py",
}
BASE64_BLOB_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{80,}={0,2})(?![A-Za-z0-9+/=])"
)
URL_RE = re.compile(r"https?://[^\s'\"<>)\]}]+")
HOST_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])")
KNOWN_BENIGN_DOMAINS = {
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "pypi.org",
    "python.org",
    "pythonhosted.org",
    "files.pythonhosted.org",
    "readthedocs.io",
    "docs.python.org",
    "localhost",
}
IGNORED_INVENTORY_DOMAINS = {"example.com", "example.org", "example.net"}
COMMON_CODE_SUFFIXES = {
    "add",
    "append",
    "classlist",
    "click",
    "decode",
    "decrypt",
    "disabled",
    "encode",
    "encrypt",
    "get",
    "href",
    "id",
    "innerhtml",
    "innertext",
    "json",
    "match",
    "name",
    "now",
    "post",
    "route",
    "run",
    "startswith",
    "text",
    "tree",
    "type",
    "util",
}
SUSPICIOUS_DOMAIN_SUFFIXES = {
    "webhook.site",
    "ngrok.io",
    "ngrok-free.app",
    "pastebin.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "transfer.sh",
    "workers.dev",
    "pages.dev",
}
AST_GREP_RULES = """
id: py-dynamic-code-exec
language: python
rule:
  any:
    - pattern: eval($ARG)
    - pattern: exec($ARG)
    - pattern: compile($$$ARGS)
---
id: py-obfuscation-loader
language: python
rule:
  any:
    - pattern: base64.b64decode($ARG)
    - pattern: zlib.decompress($ARG)
    - pattern: gzip.decompress($ARG)
    - pattern: marshal.loads($ARG)
    - pattern: pickle.loads($ARG)
---
id: py-process-execution
language: python
rule:
  any:
    - pattern: subprocess.run($$$ARGS)
    - pattern: subprocess.Popen($$$ARGS)
    - pattern: os.system($ARG)
    - pattern: os.popen($ARG)
---
id: py-network-upload
language: python
rule:
  any:
    - pattern: requests.post($$$ARGS)
    - pattern: httpx.post($$$ARGS)
    - pattern: urllib.request.urlopen($$$ARGS)
"""


@dataclass(frozen=True)
class PreScanFinding:
    rule_id: str
    category: str
    severity: str
    path: str
    line: int | None
    detail: str
    evidence: str | None = None


def scan_extracted_package(
    extract_dir: Path,
    manifest: dict,
    *,
    max_files: int,
    max_chars: int,
) -> dict:
    findings: list[PreScanFinding] = []
    indicators = NetworkIndicators()
    files = manifest.get("files", [])
    by_path = {item["path"]: item for item in files}
    ast_grep_findings = _scan_with_ast_grep(extract_dir)
    findings.extend(ast_grep_findings)

    for item in files:
        rel = item["path"]
        path = extract_dir / rel
        findings.extend(_scan_path(rel, item.get("size", 0)))
        findings.extend(_scan_binary(path, rel))
        text = _read_text(path)
        if text is None:
            continue
        indicators.add_text(rel, text)
        findings.extend(_scan_text(rel, text))
        if rel.endswith((".py", ".pyw", ".pth")):
            findings.extend(_scan_python(rel, text))

    ordered = _dedupe_findings(findings)
    selected_paths = _select_paths(ordered, by_path, max_files)
    corpus = _build_focused_corpus(extract_dir, selected_paths, max_chars)
    return {
        "findings": [finding.__dict__ for finding in ordered],
        "finding_count": len(ordered),
        "ast_grep_enabled": shutil.which("ast-grep") is not None,
        "network_indicators": indicators.to_dict(),
        "selected_paths": selected_paths,
        "focused_corpus": corpus,
    }


def _scan_path(rel: str, size: int) -> list[PreScanFinding]:
    path = Path(rel)
    lower = rel.lower()
    name = path.name.lower()
    suffix = path.suffix.lower()
    findings: list[PreScanFinding] = []

    if suffix == ".pth":
        findings.append(
            PreScanFinding("python-pth-startup", "automatic_execution", "high", rel, None, ".pth file executes on Python startup")
        )
    if name in {"sitecustomize.py", "usercustomize.py"}:
        findings.append(
            PreScanFinding("python-startup-hook", "automatic_execution", "high", rel, None, "Python startup customization hook")
        )
    if name == "setup.py":
        findings.append(
            PreScanFinding("setup-py-present", "automatic_execution", "info", rel, None, "setup.py present; inspect for install-time code")
        )
    if suffix in BINARY_SUFFIXES:
        findings.append(
            PreScanFinding("native-binary", "distribution_integrity", "medium", rel, None, f"native/binary artifact present ({suffix}, {size} bytes)")
        )
    if any(part.startswith(".") and part not in {".dist-info", ".egg-info"} for part in path.parts):
        findings.append(
            PreScanFinding("hidden-path", "distribution_integrity", "low", rel, None, "hidden path inside distribution artifact")
        )
    if lower.endswith((".dist-info/record", ".egg-info/sources.txt", ".dist-info/wheel")):
        findings.append(
            PreScanFinding("metadata-index", "distribution_integrity", "info", rel, None, "distribution metadata useful for artifact review")
        )
    return findings


def _scan_text(rel: str, text: str) -> list[PreScanFinding]:
    findings: list[PreScanFinding] = []
    rules: list[tuple[str, str, str, re.Pattern[str], str]] = [
        ("credential-file-path", "credential_theft", "high", re.compile(r"(\.aws/credentials|\.kube/config|id_rsa|id_ed25519|known_hosts|\.npmrc|\.pypirc|\.docker/config\.json)"), "sensitive credential/config path reference"),
        ("secret-token-name", "credential_theft", "medium", re.compile(r"(GITHUB_TOKEN|ACTIONS_ID_TOKEN|NPM_TOKEN|PYPI_TOKEN|TWINE_PASSWORD|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS)"), "secret-like environment variable name"),
        ("k8s-lateral", "lateral_movement", "high", re.compile(r"(serviceaccount/token|kube-system|hostPath|privileged\s*[:=]\s*true|/var/run/secrets/kubernetes\.io)"), "Kubernetes lateral-movement related indicator"),
        ("persistence-path", "persistence", "high", re.compile(r"(systemd/user|/etc/systemd|\.config/systemd|LaunchAgents|crontab|\.bashrc|\.zshrc|Startup)"), "persistence-related path or mechanism"),
        ("archive-staging", "exfiltration", "medium", re.compile(r"(tarfile|zipfile|gzip|shutil\.make_archive|\.tar\.gz|\.zip)"), "archive/staging related code"),
        ("c2-or-drop", "exfiltration", "medium", re.compile(r"(webhook\.site|pastebin|ngrok|raw\.githubusercontent\.com|github\.com/[^\\s'\"]+/(?:Shai-Hulud|tpcp|payload))"), "suspicious drop/C2 endpoint pattern"),
        ("obfuscation-loader", "obfuscation", "medium", re.compile(r"(base64\.b64decode|zlib\.decompress|marshal\.loads|pickle\.loads|exec\s*\(|eval\s*\(|compile\s*\(|fromhex\s*\(|\bxor\b)", re.IGNORECASE), "obfuscation or dynamic loader primitive"),
        ("process-exec", "execution", "medium", re.compile(r"(subprocess\.|os\.system|popen\s*\(|pty\.spawn|curl\s+|wget\s+)"), "process execution or downloader primitive"),
    ]
    for rule_id, category, severity, pattern, detail in rules:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            evidence = _line_at(text, line)
            findings.append(PreScanFinding(rule_id, category, severity, rel, line, detail, evidence))
    for match in re.finditer(r"https?://((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:[/:'\"\\s]|$)", text):
        if _is_private_or_local_ip(match.group(1)):
            continue
        line = text.count("\n", 0, match.start()) + 1
        findings.append(
            PreScanFinding(
                "raw-public-ip-endpoint",
                "exfiltration",
                "medium",
                rel,
                line,
                "raw public IP HTTP endpoint",
                _line_at(text, line),
            )
        )
    for url in _extract_urls(text):
        host = _normalize_host(urlparse(url).hostname)
        if host and _is_suspicious_domain(host):
            line = _line_for_substring(text, url)
            findings.append(
                PreScanFinding(
                    "suspicious-domain-endpoint",
                    "exfiltration",
                    "medium",
                    rel,
                    line,
                    f"suspicious network endpoint domain: {host}",
                    _line_at(text, line) if line else url[:240],
                )
            )
    for host in _extract_bare_hosts(text):
        if _is_suspicious_domain(host):
            line = _line_for_substring(text, host)
            findings.append(
                PreScanFinding(
                    "suspicious-domain-reference",
                    "exfiltration",
                    "medium",
                    rel,
                    line,
                    f"suspicious domain reference: {host}",
                    _line_at(text, line) if line else host,
                )
            )
    for match in BASE64_BLOB_RE.finditer(text):
        blob = match.group(0)
        decoded_size = _decoded_base64_size(blob)
        if decoded_size is None or decoded_size < 48:
            continue
        line = text.count("\n", 0, match.start()) + 1
        findings.append(
            PreScanFinding(
                "embedded-base64-blob",
                "obfuscation",
                "medium",
                rel,
                line,
                f"long base64-like blob ({len(blob)} chars, decoded size about {decoded_size} bytes)",
                _line_at(text, line),
            )
        )
    return findings


class NetworkIndicators:
    def __init__(self) -> None:
        self.urls: dict[str, set[str]] = {}
        self.domains: dict[str, set[str]] = {}
        self.raw_public_ips: dict[str, set[str]] = {}
        self.suspicious_endpoints: dict[str, set[str]] = {}

    def add_text(self, rel: str, text: str) -> None:
        for url in _extract_urls(text):
            host = _normalize_host(urlparse(url).hostname)
            if host and _is_private_or_local_host(host):
                continue
            self._add(self.urls, url, rel)
            if host:
                self._add_host(rel, host)
                if _is_suspicious_domain(host):
                    self._add(self.suspicious_endpoints, url, rel)
                if _is_public_ip_literal(host):
                    self._add(self.raw_public_ips, host, rel)
        for host in _extract_bare_hosts(text):
            self._add_host(rel, host)
            if _is_suspicious_domain(host):
                self._add(self.suspicious_endpoints, host, rel)
            if _is_public_ip_literal(host):
                self._add(self.raw_public_ips, host, rel)

    def to_dict(self) -> dict:
        return {
            "urls": _serialize_indicator_map(self.urls, limit=80),
            "domains": _serialize_indicator_map(self.domains, limit=120),
            "raw_public_ips": _serialize_indicator_map(self.raw_public_ips, limit=40),
            "suspicious_endpoints": _serialize_indicator_map(self.suspicious_endpoints, limit=80),
        }

    def _add_host(self, rel: str, host: str) -> None:
        if _should_ignore_host(host):
            return
        self._add(self.domains, host, rel)

    @staticmethod
    def _add(mapping: dict[str, set[str]], value: str, rel: str) -> None:
        mapping.setdefault(value, set()).add(rel)


def _scan_binary(path: Path, rel: str) -> list[PreScanFinding]:
    if not path.is_file():
        return []
    size = path.stat().st_size
    suffix = path.suffix.lower()
    if suffix not in BINARY_SUFFIXES and size < 1024:
        return []
    data = path.read_bytes()[:65536]
    if not data:
        return []
    findings: list[PreScanFinding] = []
    if b"\x00" in data[:4096] or suffix in BINARY_SUFFIXES:
        entropy = _entropy(data)
        severity = "medium" if suffix in BINARY_SUFFIXES or entropy >= 7.2 else "low"
        findings.append(
            PreScanFinding(
                "binary-or-high-entropy-file",
                "distribution_integrity",
                severity,
                rel,
                None,
                f"binary/high-entropy file present ({size} bytes, entropy {entropy:.2f})",
            )
        )
    return findings


def _scan_python(rel: str, text: str) -> list[PreScanFinding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    visitor = PythonIndicatorVisitor(rel)
    visitor.visit(tree)
    return visitor.findings


class PythonIndicatorVisitor(ast.NodeVisitor):
    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.depth = 0
        self.findings: list[PreScanFinding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if name:
            self._handle_call(node, name)
        self.generic_visit(node)

    def _handle_call(self, node: ast.Call, name: str) -> None:
        if self.depth == 0 and name in {
            "exec",
            "eval",
            "compile",
            "subprocess.run",
            "subprocess.Popen",
            "os.system",
            "requests.get",
            "requests.post",
            "httpx.get",
            "httpx.post",
            "urllib.request.urlopen",
        }:
            self.findings.append(
                PreScanFinding(
                    "top-level-side-effect",
                    "automatic_execution",
                    "high",
                    self.rel,
                    node.lineno,
                    f"top-level call to {name}",
                    name,
                )
            )
        call_rules = {
            "exec": ("obfuscation", "high", "dynamic code execution"),
            "eval": ("obfuscation", "high", "dynamic code execution"),
            "compile": ("obfuscation", "medium", "dynamic code compilation"),
            "marshal.loads": ("obfuscation", "high", "marshal loader"),
            "pickle.loads": ("obfuscation", "medium", "pickle loader"),
            "base64.b64decode": ("obfuscation", "medium", "base64 decoding"),
            "zlib.decompress": ("obfuscation", "medium", "zlib decompression"),
            "subprocess.run": ("execution", "medium", "subprocess execution"),
            "subprocess.Popen": ("execution", "medium", "subprocess execution"),
            "os.system": ("execution", "medium", "shell execution"),
            "tarfile.open": ("exfiltration", "low", "tar archive handling"),
            "zipfile.ZipFile": ("exfiltration", "low", "zip archive handling"),
            "shutil.make_archive": ("exfiltration", "medium", "archive staging"),
        }
        if name in call_rules:
            category, severity, detail = call_rules[name]
            self.findings.append(PreScanFinding(f"py-call-{name}", category, severity, self.rel, node.lineno, detail, name))


def _call_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = _call_name(func.value)
        return f"{parent}.{func.attr}" if parent else func.attr
    return None


def _scan_with_ast_grep(extract_dir: Path) -> list[PreScanFinding]:
    if shutil.which("ast-grep") is None:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as rule_file:
        rule_file.write(AST_GREP_RULES)
        rule_path = rule_file.name
    try:
        result = subprocess.run(
            ["ast-grep", "scan", "--rule", rule_path, "--json", str(extract_dir)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        Path(rule_path).unlink(missing_ok=True)
    if result.returncode not in {0, 1} or not result.stdout.strip():
        return []
    try:
        matches = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    findings: list[PreScanFinding] = []
    for match in matches:
        rule_id = match.get("ruleId") or "ast-grep"
        path = _relative_match_path(extract_dir, match.get("file") or "")
        line = (match.get("range") or {}).get("start", {}).get("line")
        line_number = line + 1 if isinstance(line, int) else None
        category, severity, detail = _ast_grep_rule_info(rule_id)
        findings.append(
            PreScanFinding(
                rule_id=f"ast-grep:{rule_id}",
                category=category,
                severity=severity,
                path=path,
                line=line_number,
                detail=detail,
                evidence=(match.get("lines") or match.get("text") or "").strip()[:240],
            )
        )
    return findings


def _ast_grep_rule_info(rule_id: str) -> tuple[str, str, str]:
    if rule_id == "py-dynamic-code-exec":
        return ("obfuscation", "high", "ast-grep matched dynamic code execution")
    if rule_id == "py-obfuscation-loader":
        return ("obfuscation", "medium", "ast-grep matched obfuscation/loader primitive")
    if rule_id == "py-process-execution":
        return ("execution", "medium", "ast-grep matched process execution")
    if rule_id == "py-network-upload":
        return ("exfiltration", "medium", "ast-grep matched network upload/request primitive")
    return ("unknown", "low", "ast-grep matched suspicious code pattern")


def _relative_match_path(root: Path, value: str) -> str:
    path = Path(value)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return value


def _select_paths(findings: list[PreScanFinding], by_path: dict[str, dict], max_files: int) -> list[str]:
    paths: list[str] = []
    for finding in sorted(findings, key=_finding_sort_key):
        if finding.path not in paths:
            paths.append(finding.path)
        if len(paths) >= max_files:
            return paths

    for rel in sorted(by_path, key=_fallback_path_score):
        if rel not in paths and _is_textish(rel):
            paths.append(rel)
        if len(paths) >= max_files:
            break
    return paths


def _build_focused_corpus(extract_dir: Path, paths: list[str], max_chars: int) -> str:
    parts: list[str] = []
    used = 0
    for rel in paths:
        text = _read_text(extract_dir / rel)
        if text is None:
            continue
        header = f"\n\n===== FILE: {rel} =====\n"
        remaining = max_chars - used - len(header)
        if remaining <= 0:
            break
        clipped = text[:remaining]
        parts.append(header + clipped)
        used += len(header) + len(clipped)
    return "".join(parts)


def _dedupe_findings(findings: list[PreScanFinding]) -> list[PreScanFinding]:
    seen: set[tuple[str, str, int | None, str | None]] = set()
    result: list[PreScanFinding] = []
    for finding in sorted(findings, key=_finding_sort_key):
        key = (finding.rule_id, finding.path, finding.line, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def _finding_sort_key(finding: PreScanFinding) -> tuple[int, str, int]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return (severity_rank.get(finding.severity, 9), finding.path, finding.line or 0)


def _fallback_path_score(rel: str) -> tuple[int, str]:
    path = Path(rel)
    lower_name = path.name.lower()
    if lower_name in HIGH_VALUE_NAMES or path.suffix.lower() == ".pth":
        return (0, rel.lower())
    if path.suffix.lower() in {".py", ".pyw"}:
        return (10, rel.lower())
    if path.suffix.lower() in TEXT_SUFFIXES:
        return (20, rel.lower())
    return (100, rel.lower())


def _is_textish(rel: str) -> bool:
    path = Path(rel)
    return path.name.lower() in HIGH_VALUE_NAMES or path.suffix.lower() in TEXT_SUFFIXES


def _extract_urls(text: str) -> list[str]:
    return [match.group(0).rstrip(".,;:") for match in URL_RE.finditer(text)]


def _extract_bare_hosts(text: str) -> list[str]:
    hosts: list[str] = []
    for match in HOST_RE.finditer(text):
        host = _normalize_host(match.group(0))
        if host and not _looks_like_filename(host) and _should_keep_bare_host(host):
            hosts.append(host)
    return hosts


def _normalize_host(host: str | None) -> str | None:
    if not host:
        return None
    host = host.strip().strip(".").lower()
    if not host or "/" in host or "_" in host:
        return None
    return host


def _is_suspicious_domain(host: str) -> bool:
    if _is_public_ip_literal(host):
        return True
    if host in KNOWN_BENIGN_DOMAINS:
        return False
    if any(host == suffix or host.endswith(f".{suffix}") for suffix in SUSPICIOUS_DOMAIN_SUFFIXES):
        return True
    labels = host.split(".")
    if len(labels) >= 3 and any(_looks_random_label(label) for label in labels[:-2]):
        return True
    return False


def _should_keep_bare_host(host: str) -> bool:
    if host in KNOWN_BENIGN_DOMAINS or _is_suspicious_domain(host):
        return True
    if host.startswith(("api.", "cdn.", "download.", "files.", "raw.")):
        return True
    if host.endswith((".cloud", ".zone", ".top", ".xyz", ".icu", ".click")):
        return True
    return False


def _should_ignore_host(host: str) -> bool:
    if host in IGNORED_INVENTORY_DOMAINS:
        return True
    if host in KNOWN_BENIGN_DOMAINS:
        return False
    if _is_private_or_local_host(host):
        return True
    return False


def _looks_like_filename(host: str) -> bool:
    labels = host.split(".")
    if labels[-1] in COMMON_CODE_SUFFIXES:
        return True
    suffix = Path(host).suffix.lower()
    return suffix in TEXT_SUFFIXES or suffix in BINARY_SUFFIXES or suffix in {".pyc", ".dist-info", ".egg-info"}


def _looks_random_label(label: str) -> bool:
    if len(label) < 16:
        return False
    digits = sum(ch.isdigit() for ch in label)
    hyphens = label.count("-")
    vowels = sum(ch in "aeiou" for ch in label.lower())
    return digits >= 5 or hyphens >= 3 or vowels <= max(1, len(label) // 8)


def _line_for_substring(text: str, value: str) -> int | None:
    index = text.find(value)
    if index < 0:
        return None
    return text.count("\n", 0, index) + 1


def _serialize_indicator_map(mapping: dict[str, set[str]], *, limit: int) -> list[dict]:
    rows = [
        {"value": value, "files": sorted(files)[:8], "file_count": len(files)}
        for value, files in sorted(mapping.items())
    ]
    return rows[:limit]


def _read_text(path: Path) -> str | None:
    if not path.exists() or not path.is_file() or path.stat().st_size > 512 * 1024:
        return None
    data = path.read_bytes()
    if b"\x00" in data[:4096]:
        return None
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return None


def _line_at(text: str, line: int) -> str:
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()[:240]
    return ""


def _decoded_base64_size(value: str) -> int | None:
    try:
        return len(base64.b64decode(value, validate=True))
    except (binascii.Error, ValueError):
        return None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _is_private_or_local_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )


def _is_private_or_local_host(value: str) -> bool:
    try:
        return _is_private_or_local_ip(value)
    except ValueError:
        return value in {"localhost"} or value.endswith(".local") or value.endswith(".internal")


def _is_public_ip_literal(value: str) -> bool:
    try:
        return not _is_private_or_local_ip(value)
    except ValueError:
        return False
