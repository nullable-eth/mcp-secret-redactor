"""Redaction engine: exact values first, patterns second.

Exact values come from the cluster's own Secrets (see secrets.py). One rule
decides which values are matched, with no guessing from what a value looks
like: every value of at least MIN_LEN characters is redacted, unless its key
is an ordinary one (by default user, username, host, hostname, port, dbname,
database; set with ORDINARY_KEYS). A matched value is replaced wherever it
appears in a tool result, in its common encodings: the password in `env`
output, an API key inside an app's config file, a webhook URL in a log line.

Over-masking is the safe failure: it shows up as a [REDACTED:...] marker in
output and is fixed by adding the key to ORDINARY_KEYS. A missed secret would
leak silently.

Patterns cover what was never put in a Secret: credential-looking key/value
pairs, bearer tokens, URL userinfo, private keys and well-known token formats.
They are a second line, not a guarantee.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass

MIN_LEN = 8          # shorter values (ports, short names) would mask ordinary text
LINE_MIN = 24        # lines of a multi-line value matched on their own
DEFAULT_ORDINARY_KEYS = "user,username,host,hostname,port,dbname,database"


def ordinary_keys(spec: str = DEFAULT_ORDINARY_KEYS) -> frozenset[str]:
    return frozenset(k.strip().lower() for k in spec.split(",") if k.strip())


def redactable(key: str, value: str, ordinary: frozenset[str]) -> bool:
    """The rule: long enough, and the key's last word is not an ordinary one.

    The last word of "unifi_username", "admin-user" or "auths.ghcr.io.username"
    is "username"/"user", so the ordinary list names words, not every key.
    """
    return len(value) >= MIN_LEN and re.split(r"[._-]", key.lower())[-1] not in ordinary


def variants(value: str) -> set[str]:
    """The value as it may appear in text: raw, base64, URL- and JSON-escaped,
    and each long line of a multi-line value (certs, kubeconfigs, pgpass)."""
    out = {value,
           base64.b64encode(value.encode()).decode(),
           urllib.parse.quote(value, safe=""),
           json.dumps(value)[1:-1]}
    out.update(line.strip() for line in value.splitlines() if len(line.strip()) >= LINE_MIN)
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
    # Ends on a lookahead, not \b: a base64url signature can end in "-", and
    # \b there backtracked and left the tail of the token in the result.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"),
     "[REDACTED:jwt]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:aws-key]"),
]


@dataclass
class Stats:
    exact: int = 0
    pattern: int = 0


class Redactor:
    """Holds (needle, marker) pairs, longest needle first, swapped atomically
    on reload. Matching is str.__contains__/str.replace per needle: plain C
    substring search, no regex, no lock."""

    def __init__(self) -> None:
        self._needles: tuple[tuple[str, str], ...] = ()
        self.count = 0

    def load(self, values: dict[str, str]) -> None:
        """values: secret value -> label (e.g. "ns/name.key")."""
        labels: dict[str, str] = {}
        for value, label in values.items():
            for v in variants(value):
                labels.setdefault(v, label)
        self._needles = tuple((v, f"[REDACTED:{labels[v]}]")
                              for v in sorted(labels, key=len, reverse=True))
        self.count = len(values)

    def text(self, s: str, stats: Stats) -> str:
        for needle, marker in self._needles:
            if needle in s:
                stats.exact += s.count(needle)
                s = s.replace(needle, marker)
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
