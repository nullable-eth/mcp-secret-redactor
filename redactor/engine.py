"""Redaction engine: exact values first, patterns second.

Exact values come from the cluster's own Secrets (see secrets.py). A value
that is in a Secret is replaced wherever it appears in a tool result, in its
common encodings, whatever the surrounding text looks like. That catches the
password in `env` output, an API key inside an app's config file, a
connection string in a log line: anything that matches a Secret.

Patterns cover what was never put in a Secret: credential-looking key/value
pairs, bearer tokens, URL userinfo, private keys and well-known token formats.
They are a second line, not a guarantee.
"""
from __future__ import annotations

import base64
import json
import math
import re
import threading
import urllib.parse
from dataclasses import dataclass

MIN_LEN = 8

# Keys whose values are credentials whatever they look like.
SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|pwd|secret|token|api[-_]?key|apikey|auth|credential|"
    r"private|cert|\.pem|\.key$|dsn|uri|url|connection|pgpass|cookie|session|salt|seed)",
    re.IGNORECASE)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def looks_secret(key: str, value: str) -> bool:
    """Is this Secret value worth redacting on sight?

    Secrets also hold ordinary values (usernames, host names, database names,
    ports). Masking "postgres" or "shared-pg-rw.databases.svc" everywhere would
    wreck every tool result, so a value qualifies if its key says it is a
    credential, or if it is long and random enough to be one.
    """
    if len(value) < MIN_LEN:
        return False
    if SENSITIVE_KEY.search(key):
        # A URL/URI key holds a secret only if it carries credentials.
        if re.search(r"(uri|url|dsn|connection)", key, re.I) and "://" in value:
            return bool(re.search(r"://[^/@\s:]+:[^/@\s]+@", value))
        return True
    if ORDINARY_SHAPE.match(value):
        return False
    return len(value) >= 16 and entropy(value) >= 3.5


# Values that are long and varied but are locations, not credentials: DNS
# names (optionally :port), e-mail addresses, file paths and URLs without
# userinfo. Only consulted for keys that do not name a credential.
ORDINARY_SHAPE = re.compile(
    r"^(?:"
    r"[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d{1,5})?"      # host.name[:port]
    r"|[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"  # e-mail
    r"|/[\w./-]*"                                     # /a/path
    r"|[a-z][a-z0-9+.-]*://[^@\s]*"                   # url without userinfo
    r")$")


def variants(value: str) -> set[str]:
    """The value as it may appear in text: raw, base64, URL- and JSON-escaped."""
    out = {value}
    out.add(base64.b64encode(value.encode()).decode())
    out.add(urllib.parse.quote(value, safe=""))
    out.add(json.dumps(value)[1:-1])
    # Multi-line values (certs, kubeconfigs, pgpass) show up line by line too.
    for line in value.splitlines():
        line = line.strip()
        if len(line) >= 24 or (":" in line and len(line) >= MIN_LEN and line.count(":") >= 3):
            out.add(line)
    return {v for v in out if len(v) >= MIN_LEN}


PATTERNS: list[tuple[re.Pattern, str]] = [
    # -----BEGIN ... PRIVATE KEY----- blocks
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[REDACTED:private-key]"),
    # user:password@ in URLs
    (re.compile(r"(?P<pre>[a-z][a-z0-9+.-]*://[^/@\s:]+:)(?P<secret>[^/@\s]+)(?P<post>@)", re.I), None),
    # Authorization headers
    (re.compile(r"(?P<pre>\b(?:bearer|basic)\s+)(?P<secret>[A-Za-z0-9._~+/=-]{12,})", re.I), None),
    # key = value / key: value / "key": "value", where the key ENDS in a
    # credential word ("GIT_TOKEN=", "password:"), so "secretName:",
    # "secretKeyRef:" and "max_tokens=" are left alone.
    (re.compile(
        r"(?P<pre>(?:^|[\s,{;&?\"'])[\w.-]*(?:pass(?:word|wd)?|pwd|secret|token|api[-_]?key|apikey|"
        r"access[-_]?key|client[-_]?secret)[\"']?\s*[:=]\s*[\"']?)"
        r"(?P<secret>[^\s\"',;&<>{}\[\]()]{6,})", re.I | re.M), None),
    # well-known token formats
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
     "[REDACTED:github-token]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
     "[REDACTED:jwt]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:aws-key]"),
]


@dataclass
class Stats:
    exact: int = 0
    pattern: int = 0


class Redactor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._regex: re.Pattern | None = None
        self._labels: dict[str, str] = {}
        self.count = 0

    def load(self, values: dict[str, str]) -> None:
        """values: secret value -> label (e.g. "ns/name.key")."""
        labels: dict[str, str] = {}
        for value, label in values.items():
            for v in variants(value):
                labels.setdefault(v, label)
        ordered = sorted(labels, key=len, reverse=True)       # longest match first
        regex = re.compile("|".join(re.escape(v) for v in ordered)) if ordered else None
        with self._lock:
            self._regex, self._labels, self.count = regex, labels, len(values)

    def text(self, s: str, stats: Stats) -> str:
        with self._lock:
            regex, labels = self._regex, self._labels
        if regex is not None:
            def sub(m: re.Match) -> str:
                stats.exact += 1
                return f"[REDACTED:{labels.get(m.group(0), 'secret')}]"
            s = regex.sub(sub, s)
        for pattern, fixed in PATTERNS:
            def psub(m: re.Match, fixed=fixed) -> str:
                if "REDACTED" in m.group(0):
                    return m.group(0)
                stats.pattern += 1
                if fixed:
                    return fixed
                return f"{m.group('pre')}[REDACTED]{m.groupdict().get('post') or ''}"
            s = pattern.sub(psub, s)
        return s

    def value(self, obj, stats: Stats):
        """Redact every string inside a JSON value (keys included)."""
        if isinstance(obj, str):
            return self.text(obj, stats)
        if isinstance(obj, list):
            return [self.value(v, stats) for v in obj]
        if isinstance(obj, dict):
            return {self.text(k, stats): self.value(v, stats) for k, v in obj.items()}
        return obj
