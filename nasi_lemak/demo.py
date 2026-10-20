"""Synthetic-only demonstration; no listening server or remote model calls."""

import json
import tempfile
from pathlib import Path

from .gateway import make_demo_gateway


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="nasi-lemak-demo-", dir=Path(__file__).resolve().parents[1]) as directory:
        gateway, _, key = make_demo_gateway(Path(directory) / "audit.sqlite3")
        response = gateway.handle(
            "POST", "/v1/chat/completions",
            {"Authorization": "Bearer " + key},
            {"model": "pilot-local", "messages": [{"role": "user", "content": "Synthetic demo asks for a safe greeting."}]},
        )
        print(json.dumps({"status": response[0], "response": response[1]}, sort_keys=True))


if __name__ == "__main__":
    main()
