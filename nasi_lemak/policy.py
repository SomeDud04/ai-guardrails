"""Strict, bounded loader for one versioned startup policy file.

The policy is read exactly once while the application is constructed.  There is
no editor, hot reload, database policy management or client-supplied override.
An unavailable or invalid file is a configuration failure: the server stays
live but not ready instead of activating built-in defaults.

PyYAML is imported lazily so the dependency-free synthetic gateway keeps
working.  The HTTP server extra installs PyYAML at runtime.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .gateway import Policy

MAX_POLICY_FILE_BYTES = 32 * 1024
# The canonical document is a flat mapping with one list.  A small explicit
# collection-depth bound keeps a tiny but deeply nested file from reaching the
# recursive composer/constructor and raising RecursionError.
MAX_COLLECTION_DEPTH = 8

_REQUIRED_KEYS = frozenset(
    {"app_id", "version", "model", "token_budget", "deny_phrases"}
)
_OPTIONAL_KEYS = frozenset({"limits"})
_ALLOWED_KEYS = _REQUIRED_KEYS | _OPTIONAL_KEYS


class PolicyError(ValueError):
    """The policy file is missing, unreadable or not an allowed canonical form."""


def _policy_yaml() -> Any:
    try:
        import yaml
    except ImportError:
        raise PolicyError("policy loader dependency is unavailable") from None
    return yaml


def _read_policy_text(path: str | Path | None) -> str:
    if not isinstance(path, (str, Path)) or not str(path):
        raise PolicyError("policy file is not configured")
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_POLICY_FILE_BYTES + 1)
    except (OSError, TypeError, ValueError):
        raise PolicyError("policy file is unavailable") from None
    if len(data) > MAX_POLICY_FILE_BYTES:
        raise PolicyError("policy file is too large")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise PolicyError("policy file is not valid UTF-8") from None


def _reject_unsafe_yaml_events(yaml: Any, text: str) -> None:
    documents = 0
    depth = 0
    try:
        # Iterate the event stream instead of materializing a whole event list,
        # so a deeply nested document is rejected before composition.
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.DocumentStartEvent):
                documents += 1
            if isinstance(event, yaml.CollectionStartEvent):
                depth += 1
                if depth > MAX_COLLECTION_DEPTH:
                    raise PolicyError("policy collections are too deeply nested")
            elif isinstance(event, yaml.CollectionEndEvent):
                depth -= 1
            # Anchors, aliases and tags other than the standard YAML scalar/collection
            # tags are not part of the canonical configuration.
            if getattr(event, "anchor", None) is not None:
                raise PolicyError("policy anchors and aliases are not allowed")
            tag = getattr(event, "tag", None)
            if tag is not None and not tag.startswith("tag:yaml.org,2002:"):
                raise PolicyError("policy custom tags are not allowed")
    except PolicyError:
        raise
    except RecursionError:
        raise PolicyError("policy YAML is too deeply nested") from None
    except yaml.YAMLError:
        raise PolicyError("policy YAML is malformed") from None
    if documents != 1:
        raise PolicyError("policy must contain exactly one YAML document")


def _strict_load(yaml: Any, text: str) -> Any:
    class StrictSafeLoader(yaml.SafeLoader):
        def construct_mapping(self, node: Any, deep: bool = False) -> Any:
            if not isinstance(node, yaml.MappingNode):
                raise yaml.constructor.ConstructorError(
                    None, None, "expected a mapping", node.start_mark
                )
            mapping = super().construct_mapping(node, deep=deep)
            if len(mapping) != len(node.value):
                raise yaml.constructor.ConstructorError(
                    None, None, "duplicate key", node.start_mark
                )
            return mapping

    try:
        return yaml.load(text, Loader=StrictSafeLoader)
    except (yaml.YAMLError, RecursionError):
        raise PolicyError("policy YAML is invalid") from None


def load_policy(path: str | Path | None) -> Policy:
    """Read and validate one complete policy file.

    The returned object is immutable and its digest covers the app identity,
    version, public model alias, token budget, literal deny phrases and, when
    the optional ``limits`` mapping is present, that mapping in canonical order.
    Any failure raises :class:`PolicyError` with a fixed generic message; file
    contents and paths are never echoed.
    """
    text = _read_policy_text(path)
    yaml = _policy_yaml()
    _reject_unsafe_yaml_events(yaml, text)
    loaded = _strict_load(yaml, text)

    if (
        not isinstance(loaded, dict)
        or not _REQUIRED_KEYS <= set(loaded)
        or not set(loaded) <= _ALLOWED_KEYS
    ):
        raise PolicyError("policy keys are invalid")
    if not isinstance(loaded["deny_phrases"], list):
        raise PolicyError("policy deny phrases are invalid")
    if "limits" in loaded and not isinstance(loaded["limits"], dict):
        # ``limits:`` with a null or sequence value is not a flat mapping.
        raise PolicyError("policy limits are invalid")

    try:
        return Policy(
            version=loaded["version"],
            model=loaded["model"],
            token_budget=loaded["token_budget"],
            app_id=loaded["app_id"],
            deny_phrases=loaded["deny_phrases"],
            limits=loaded["limits"] if "limits" in loaded else None,
        )
    except (TypeError, ValueError):
        raise PolicyError("policy configuration is invalid") from None
