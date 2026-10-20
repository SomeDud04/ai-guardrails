"""Local synthetic operator-view fixture.

This is a deliberately non-production demo for a browser check on loopback.  It
uses explicit synthetic audit rows and an explicit synthetic operator key, binds
only 127.0.0.1, and never reads production environment variables or contacts a
real model, guard or audit service.

Usage::

    .\\.venv\\Scripts\\python.exe scripts/operator_demo.py --port 18789

The synthetic operator key is printed once at startup.  Do not reuse it.
Optional ``--reader-delay`` and ``--reader-unavailable`` switches exist only in
this fixture for caller browser race/outage checks; they are not runtime
configuration and no environment variable can enable them.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import sqlite3
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

import uvicorn

# Allow ``python scripts/operator_demo.py`` from a checkout without installation.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from nasi_lemak.audit import AuditError, SqliteAuditStore
from nasi_lemak.export import ExportAuditError, SqliteExportAuditLog
from nasi_lemak.gateway import Gateway, MemoryAdapters, Policy
from nasi_lemak.operator import SqliteAuditReader
from nasi_lemak.server import make_app

SYNTHETIC_OPERATOR_KEY = "synthetic-operator-key-not-for-any-real-use"
SYNTHETIC_CHAT_KEY = "synthetic-chat-key-not-for-any-real-use"
SYNTHETIC_APP = "synthetic-operator-demo"
SYNTHETIC_HOSTILE_METADATA = "<img src=x onerror=alert(1)>"
SYNTHETIC_FILLER_REQUESTS = 60
MAX_SYNTHETIC_READER_DELAY = 30.0


class _SyntheticDelayReader:
    """Loopback fixture wrapper; delays each page read by a bounded interval."""

    def __init__(self, reader: SqliteAuditReader, delay: float) -> None:
        self._reader = reader
        self._delay = delay

    def fetch_page(self, app_id, filters):
        time.sleep(self._delay)
        return self._reader.fetch_page(app_id, filters)

    def fetch_export(self, app_id, filters):
        time.sleep(self._delay)
        return self._reader.fetch_export(app_id, filters)

    def close(self) -> None:
        self._reader.close()


class _SyntheticUnavailableReader:
    """Loopback fixture wrapper; every read fails with a generic 503."""

    def fetch_page(self, app_id, filters):
        raise AuditError("synthetic reader unavailable")

    def fetch_export(self, app_id, filters):
        raise AuditError("synthetic reader unavailable")

    def close(self) -> None:
        pass


class _SyntheticUnavailableExportLog:
    """Loopback fixture wrapper; export audit writes fail closed."""

    def record(self, entry) -> None:
        raise ExportAuditError("synthetic export audit unavailable")

    def close(self) -> None:
        pass


def _seed(store: SqliteAuditStore, policy: Policy, db_path: Path) -> int:
    """Preserve the first known synthetic records, then add filler pages.

    The filler rows are deterministic enough for paging (more than 100 events,
    so the default 50-row page has a next page) and include one harmless HTML
    string in an allowlisted metadata column to exercise ``textContent``.
    """
    events = [
        ("req_demo_01", "request_started", "pending", None),
        ("req_demo_01", "request_completed", "allowed", None),
        ("req_demo_02", "request_started", "pending", None),
        ("req_demo_02", "request_blocked", "blocked", "POLICY_BLOCK"),
        ("req_demo_03", "request_started", "pending", None),
    ]
    for request_id, event_type, decision, code in events:
        if event_type == "request_started":
            store.record_initial(
                request_id, policy.app_id, policy.model, policy.version, policy.digest
            )
        else:
            store.record_terminal(
                request_id,
                event_type,
                decision,
                code,
                app_id=policy.app_id,
                model=policy.model,
                policy_version=policy.version,
                policy_digest=policy.digest,
            )

    now = time.time()
    rows = []
    # An unrelated application row proves the reader scope; it is never shown.
    rows.append(
        (
            "req_other_app",
            "request_started",
            now,
            "synthetic-other-app",
            policy.model,
            "synthetic-other.1",
            "0" * 64,
            "pending",
            None,
        )
    )
    # Harmless markup is rendered through textContent, never as HTML.
    rows.append(
        (
            "req_demo_markup",
            "request_started",
            now + 0.001,
            policy.app_id,
            policy.model,
            SYNTHETIC_HOSTILE_METADATA,
            policy.digest,
            "pending",
            None,
        )
    )
    for index in range(1, SYNTHETIC_FILLER_REQUESTS + 1):
        request_id = f"req_demo_fill_{index:02d}"
        started = now + index * 0.002
        rows.append(
            (
                request_id,
                "request_started",
                started,
                policy.app_id,
                policy.model,
                policy.version,
                policy.digest,
                "pending",
                None,
            )
        )
        rows.append(
            (
                request_id,
                "request_completed",
                started + 0.001,
                policy.app_id,
                policy.model,
                policy.version,
                policy.digest,
                "allowed",
                None,
            )
        )
    with closing(sqlite3.connect(str(db_path))) as db:
        try:
            db.execute("BEGIN")
            db.executemany(
                """
                INSERT INTO events(
                    request_id, event_type, timestamp, app_id, model,
                    policy_version, policy_digest, decision, error_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return len(events) + len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18789)
    parser.add_argument(
        "--reader-delay",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help=(
            "Synthetic per-page delay between 0 and "
            f"{MAX_SYNTHETIC_READER_DELAY:g} seconds (not runtime configuration)."
        ),
    )
    parser.add_argument(
        "--reader-unavailable",
        action="store_true",
        help="Make every synthetic event page read return a generic 503.",
    )
    parser.add_argument(
        "--export-audit-unavailable",
        action="store_true",
        help="Make the synthetic export audit write fail, so export returns 503.",
    )
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    if (
        not math.isfinite(args.reader_delay)
        or not 0.0 <= args.reader_delay <= MAX_SYNTHETIC_READER_DELAY
    ):
        parser.error(
            f"reader delay must be between 0 and {MAX_SYNTHETIC_READER_DELAY:g} seconds"
        )

    policy = Policy(
        app_id=SYNTHETIC_APP,
        version="synthetic-operator-demo.1",
        model="pilot-local",
        token_budget=256,
    )
    with tempfile.TemporaryDirectory(prefix="nasi-lemak-operator-demo-") as tmp:
        db_path = Path(tmp) / "synthetic-audit.sqlite3"
        export_path = Path(tmp) / "synthetic-export-audit.sqlite3"
        store = SqliteAuditStore(db_path)
        seeded = _seed(store, policy, db_path)

        if args.reader_unavailable:
            reader = _SyntheticUnavailableReader()
        else:
            reader = SqliteAuditReader(db_path)
            if args.reader_delay > 0:
                reader = _SyntheticDelayReader(reader, args.reader_delay)
        if args.export_audit_unavailable:
            export_log = _SyntheticUnavailableExportLog()
        else:
            export_log = SqliteExportAuditLog(export_path)

        gateway = Gateway(
            app_key=SYNTHETIC_CHAT_KEY,
            audit_store=store,
            adapters=MemoryAdapters(),
            policy=policy,
            app_id=policy.app_id,
        )
        # environ={} keeps the synthetic fixture from reading any process
        # environment, including *_FILE secret paths.
        app = make_app(
            gateway=gateway,
            operator_key_digest=hashlib.sha256(SYNTHETIC_OPERATOR_KEY.encode()).hexdigest(),
            operator_reader=reader,
            export_log=export_log,
            environ={},
        )
        print("Synthetic operator fixture; not production evidence.")
        print(f"Seeded {seeded} synthetic events; the default page shows 50.")
        print(
            "Exports use a separate synthetic export-audit file; "
            f"the default export matches {seeded - 1} scoped events."
        )
        if args.reader_delay > 0:
            print(f"Synthetic reader delay: {args.reader_delay:g}s per page.")
        if args.reader_unavailable:
            print("Synthetic reader outage: every event page returns 503.")
        if args.export_audit_unavailable:
            print("Synthetic export-audit outage: every export returns 503.")
        print(f"Open http://127.0.0.1:{args.port}/admin")
        print(f"Synthetic operator token: {SYNTHETIC_OPERATOR_KEY}")
        print("Press Ctrl+C to stop. The temporary audit file is deleted on exit.")
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=args.port,
            log_level="warning",
            access_log=False,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
