"""Operator-run diagnostic for the direct generation transport.

This is deliberately *not* a gateway entry point and does not apply input
screening, PII masking, output safety or audit. It accepts no arbitrary prompt
or file: only a fixed synthetic connectivity probe. Default invocation performs
a configuration check and makes no network call. Model IDs are metadata; probe
response content is never printed, returned or saved.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Mapping, Sequence

from .generation import (
    AUTH_BEARER,
    ENV_API_KEY,
    ENV_AUTH,
    ENV_MODEL,
    ENV_URL,
    GenerationClient,
    GenerationConfig,
    GenerationConfigError,
    GenerationError,
)

SUMMARY_KEYS = (
    "url_origin",
    "url_path",
    "upstream_model",
    "auth_mode",
    "api_key_configured",
    "allow_insecure_http",
    "timeout_seconds",
    "max_response_bytes",
    "ca_file_configured",
)


def _auth_mode(environ: Mapping[str, str]) -> str:
    return (environ.get(ENV_AUTH) or AUTH_BEARER).strip().lower()


def _check_config(environ: Mapping[str, str]) -> tuple[int, GenerationConfig | None]:
    missing = [name for name in (ENV_URL,) if not environ.get(name)]
    if _auth_mode(environ) == AUTH_BEARER and not environ.get(ENV_API_KEY):
        missing.append(ENV_API_KEY)
    if missing:
        print("config=incomplete missing=" + ",".join(missing))
        print("network=not_performed")
        return 2, None
    try:
        config = GenerationConfig.from_env(environ)
    except GenerationConfigError as exc:
        print(f"config=invalid reason={exc}")
        print("network=not_performed")
        return 2, None
    summary = config.safe_summary()
    print("config=valid")
    for key in SUMMARY_KEYS:
        print(f"{key}={summary[key]}")
    print("network=not_performed")
    return 0, config


def _load_for_network(environ: Mapping[str, str], *, require_model: bool) -> GenerationConfig | None:
    missing = [name for name in (ENV_URL,) if not environ.get(name)]
    if require_model and not environ.get(ENV_MODEL):
        missing.append(ENV_MODEL)
    if missing:
        print("config=incomplete missing=" + ",".join(missing))
        return None
    auth_mode = _auth_mode(environ)
    if auth_mode == AUTH_BEARER and not environ.get(ENV_API_KEY):
        try:
            key = getpass.getpass("Generation API key (input hidden, not saved): ").strip()
        except (EOFError, KeyboardInterrupt):
            key = ""
        if not key:
            print("config=incomplete missing=" + ENV_API_KEY)
            return None
    else:
        key = None
    try:
        return GenerationConfig.from_env(
            environ,
            api_key_override=key if key is not None and not environ.get(ENV_API_KEY) else None,
        )
    except GenerationConfigError as exc:
        print(f"config=invalid reason={exc}")
        return None


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    env = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(
        description="UNGUARDED direct generation diagnostic; not the gateway. No arbitrary prompts or files.",
    )
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--check-config", action="store_true", help="validate server-side configuration only (default)")
    actions.add_argument("--list-models", action="store_true", help="list upstream model IDs via GET /models (network call)")
    actions.add_argument("--probe", action="store_true", help="send one fixed synthetic prompt (network call)")
    args = parser.parse_args(argv)

    if not (args.list_models or args.probe):
        return _check_config(env)[0]

    config = _load_for_network(env, require_model=args.probe)
    if config is None:
        print("network=not_performed")
        return 2
    try:
        client = GenerationClient(config)
    except GenerationConfigError as exc:
        print(f"config=invalid reason={exc}")
        print("network=not_performed")
        return 2
    print("unguarded=yes gateway_entry_point=no")
    print(f"upstream_model={config.model or 'not_configured'}")

    if args.list_models:
        try:
            models = client.list_models()
        except GenerationError as exc:
            print(f"models_pass=no error={exc}")
            return 1
        print("models_pass=yes")
        for model_id in models:
            print(f"model_id={model_id}")
        return 0

    try:
        result = client.probe()
    except (GenerationConfigError, GenerationError) as exc:
        print(f"probe=fail error={exc}")
        return 1
    print("probe=pass")
    print(f"response_bytes={result['response_bytes']}")
    print("response_content=not_printed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
