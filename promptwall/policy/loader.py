"""Loading, validating and hot-reloading policy files.

Policy is data, and this is the trust boundary around it. Every load is
all-or-nothing: if any file fails validation the previous bundle stays in
force, because running with half a policy is worse than running with a
stale one that at least somebody reviewed.
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from ..exceptions import PolicyNotFoundError, PolicyValidationError
from .schema import PolicyBundle, RedactionPack, SignaturePack, ToolPack

#: Rules shipped inside the package.
DEFAULT_RULES_DIR = Path(__file__).parent / "rules"

_FILES = {
    "signatures": "signatures.yaml",
    "tools": "tools.yaml",
    "redaction": "redaction.yaml",
}


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise PolicyNotFoundError(f"policy file not found: {path}", path=str(path)) from exc
    except OSError as exc:
        raise PolicyValidationError(f"cannot read {path}: {exc}", path=str(path)) from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PolicyValidationError(f"{path.name} is not valid YAML: {exc}", path=str(path)) from exc

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise PolicyValidationError(
            f"{path.name} must contain a mapping at the top level, got {type(data).__name__}",
            path=str(path),
        )
    return data


def compute_digest(paths: list[Path]) -> str:
    """Stable sha256 over the policy sources.

    Recorded on every verdict so an incident review can prove exactly which
    ruleset produced a decision, without trusting a mutable version string.
    """
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda p: p.name):
        digest.update(path.name.encode())
        digest.update(b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()[:16]


def load_bundle(rules_dir: str | Path | None = None, *, strict: bool = True) -> PolicyBundle:
    """Load and validate all three packs from ``rules_dir``.

    ``strict`` fails on a missing file. With ``strict=False`` a missing pack
    yields an empty one, which is only appropriate for tests.
    """
    directory = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
    if not directory.is_dir():
        raise PolicyNotFoundError(f"policy directory not found: {directory}", path=str(directory))

    paths = {key: directory / name for key, name in _FILES.items()}

    def _pack(key: str, model: type[BaseModel]) -> Any:
        path = paths[key]
        if not path.is_file():
            if strict:
                raise PolicyNotFoundError(
                    f"missing policy file {path.name} in {directory}", path=str(path)
                )
            return model()
        data = _read_yaml(path)
        try:
            return model.model_validate(data)
        except PolicyValidationError:
            raise
        except Exception as exc:
            raise PolicyValidationError(
                f"{path.name} failed validation: {exc}", path=str(path)
            ) from exc

    signatures = _pack("signatures", SignaturePack)
    tools = _pack("tools", ToolPack)
    redaction = _pack("redaction", RedactionPack)

    version_file = directory / "VERSION"
    version = version_file.read_text(encoding="utf-8").strip() if version_file.is_file() else "0"

    return PolicyBundle(
        version=version,
        signatures=signatures,
        tools=tools,
        redaction=redaction,
        digest=compute_digest([p for p in paths.values() if p.is_file()]),
    )


class PolicyStore:
    """Thread-safe holder for the active bundle, with atomic reload.

    The proxy reads policy on every request from many threads while an admin
    may reload it at any moment. Readers take a plain attribute read of an
    immutable bundle; the writer swaps the reference under a lock. No reader
    ever observes a partially-updated ruleset.
    """

    def __init__(self, rules_dir: str | Path | None = None, *, strict: bool = True) -> None:
        self._dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
        self._strict = strict
        self._lock = threading.Lock()
        self._bundle = load_bundle(self._dir, strict=strict)
        self._mtimes = self._current_mtimes()
        self._reload_count = 0
        self._last_error: str | None = None

    def _current_mtimes(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for name in (*_FILES.values(), "VERSION"):
            path = self._dir / name
            if path.is_file():
                out[name] = path.stat().st_mtime
        return out

    @property
    def bundle(self) -> PolicyBundle:
        return self._bundle

    @property
    def directory(self) -> Path:
        return self._dir

    def changed_on_disk(self) -> bool:
        return self._current_mtimes() != self._mtimes

    def reload(self, *, force: bool = False) -> bool:
        """Re-read policy. Returns True when the active bundle changed.

        A failed reload leaves the previous bundle in force and records the
        error rather than raising, so a typo in a YAML file cannot take the
        gateway down mid-flight. Callers that want the error should read
        ``last_error``.
        """
        with self._lock:
            if not force and not self.changed_on_disk():
                return False
            try:
                fresh = load_bundle(self._dir, strict=self._strict)
            except (PolicyValidationError, PolicyNotFoundError) as exc:
                self._last_error = str(exc)
                return False

            changed = fresh.digest != self._bundle.digest
            self._bundle = fresh
            self._mtimes = self._current_mtimes()
            self._last_error = None
            if changed:
                self._reload_count += 1
            return changed

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def status(self) -> dict[str, Any]:
        return {
            "directory": str(self._dir),
            "reloads": self._reload_count,
            "last_error": self._last_error,
            "stale": self.changed_on_disk(),
            **self._bundle.summary(),
        }


_store: PolicyStore | None = None
_store_lock = threading.Lock()


def get_store(rules_dir: str | Path | None = None) -> PolicyStore:
    """Process-wide policy store, created on first use."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = PolicyStore(rules_dir)
    return _store


def reset_store() -> None:
    """Drop the singleton. For tests and for a full config reload."""
    global _store
    with _store_lock:
        _store = None
