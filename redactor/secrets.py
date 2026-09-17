"""Loads the values to redact from the cluster's Secrets.

Lists every Secret this service account may read (cluster-wide by default),
keeps the values that look like credentials (engine.looks_secret), and
refreshes on an interval, so a new or rotated Secret is covered within a
minute without a restart. Values never leave this process: only their labels
("namespace/name.key") are ever logged.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time

from kubernetes import client, config

from .engine import MIN_LEN, Redactor, looks_secret

log = logging.getLogger("redactor.secrets")

SKIP_TYPES = {"helm.sh/release.v1"}      # huge compressed blobs, no credentials of their own


def _leaves(obj, prefix: str):
    """String leaves of a JSON/YAML-ish structure, with dotted key paths."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaves(v, f"{prefix}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _leaves(v, f"{prefix}[{i}]")
    elif isinstance(obj, str):
        yield prefix, obj


def collect(secrets) -> dict[str, str]:
    """value -> label, for every credential-looking value."""
    out: dict[str, str] = {}
    for s in secrets:
        if s.type in SKIP_TYPES:
            continue
        ns, name = s.metadata.namespace, s.metadata.name
        for key, b64 in (s.data or {}).items():
            try:
                value = base64.b64decode(b64).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue                         # binary: not something text output carries
            label = f"{ns}/{name}.{key}"
            if looks_secret(key, value):
                out.setdefault(value.strip(), label)
            # Structured values (dockerconfigjson, JSON credential files):
            # their inner credentials appear on their own in output.
            if value.lstrip().startswith(("{", "[")):
                try:
                    for path, leaf in _leaves(json.loads(value), key):
                        if looks_secret(path, leaf):
                            out.setdefault(leaf, f"{ns}/{name}.{path}")
                except ValueError:
                    pass
    return {v: l for v, l in out.items() if len(v) >= MIN_LEN}


class SecretSource:
    def __init__(self, redactor: Redactor, interval: int, namespaces: list[str]):
        self.redactor, self.interval, self.namespaces = redactor, interval, namespaces
        self.loaded_at = 0.0
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        self.api = client.CoreV1Api()

    def refresh(self) -> None:
        if self.namespaces:
            items = []
            for ns in self.namespaces:
                items += self.api.list_namespaced_secret(ns).items
        else:
            items = self.api.list_secret_for_all_namespaces().items
        values = collect(items)
        self.redactor.load(values)
        self.loaded_at = time.time()
        log.info("loaded %d credential values from %d secrets", len(values), len(items))

    def run(self) -> None:
        while True:
            time.sleep(self.interval)
            try:
                self.refresh()
            except Exception:
                log.exception("secret refresh failed; keeping the previous set")

    def start(self) -> None:
        self.refresh()                           # fail at startup, not silently later
        threading.Thread(target=self.run, daemon=True, name="secret-refresh").start()

    def fresh(self) -> bool:
        return time.time() - self.loaded_at < self.interval * 5


def from_env(redactor: Redactor) -> SecretSource:
    ns = [n.strip() for n in os.environ.get("SECRET_NAMESPACES", "").split(",") if n.strip()]
    return SecretSource(redactor, int(os.environ.get("REFRESH_SECONDS", "60")), ns)
