"""
Persistent storage for red team assessment runs.
Uses SQLite for local storage with reproducible evidence-backed reporting.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from redteaming_ai.reporting import (
    SCHEMA_VERSION as REPORT_SCHEMA_VERSION,
)
from redteaming_ai.reporting import (
    build_report_artifact,
    export_report,
    report_to_dict,
)

SCHEMA_VERSION = 5
DEFAULT_TARGET_TYPE = "vulnerable_llm_app"


def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    return dict(row) if row is not None else None


def get_default_db_path() -> Path:
    """Get default database path in user's home directory."""
    home = Path.home()
    app_dir = home / ".redteaming-ai"
    app_dir.mkdir(exist_ok=True)
    return app_dir / "runs.db"


class RunStorage:
    """SQLite-based storage for red team assessment runs."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or get_default_db_path()
        self._conn: Optional[sqlite3.Connection] = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
        return self._conn

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def _table_exists(self, table_name: str) -> bool:
        row = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        return row is not None

    def _column_exists(self, table_name: str, column_name: str) -> bool:
        if not self._table_exists(table_name):
            return False
        columns = self.conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return any(column["name"] == column_name for column in columns)

    def _detect_schema_version(self) -> int:
        if self._table_exists("_schema_version"):
            existing = self.conn.execute(
                "SELECT MAX(version) FROM _schema_version"
            ).fetchone()[0]
            if existing is not None:
                return int(existing)

        if self._table_exists("reports") and self._column_exists("reports", "report_json"):
            return 5
        if self._table_exists("runs") and self._column_exists("runs", "status"):
            return 4
        if self._table_exists("runs") and self._column_exists("runs", "target_id"):
            return 2
        if self._table_exists("runs"):
            return 1
        return 0

    def _record_schema_version(self, version: int):
        self.conn.execute("DELETE FROM _schema_version")
        self.conn.execute(
            "INSERT INTO _schema_version (version, applied_at) VALUES (?, ?)",
            (version, datetime.now().isoformat()),
        )

    def _normalize_target_config(self, target_config: Any) -> str:
        if isinstance(target_config, str):
            try:
                parsed = json.loads(target_config)
            except json.JSONDecodeError:
                return json.dumps({"raw": target_config}, sort_keys=True)
            return json.dumps(parsed, sort_keys=True)
        return json.dumps(target_config or {}, sort_keys=True)

    def _default_target_name(
        self,
        provider: Optional[str],
        model: Optional[str],
        target_type: str = DEFAULT_TARGET_TYPE,
    ) -> str:
        if model:
            return f"{target_type}:{provider or 'unknown'}:{model}"
        if provider:
            return f"{target_type}:{provider}"
        return target_type

    def _create_targets_table(self):
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target_type TEXT NOT NULL,
                provider TEXT,
                model TEXT,
                config_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """
        )

    def _create_runs_table(self):
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                target_id TEXT,
                target_provider TEXT,
                target_model TEXT,
                target_config_json TEXT,
                status TEXT NOT NULL,
                queued_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                duration_seconds REAL,
                error_message TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        """
        )

    def _ensure_schema(self):
        conn = self.conn
        self._create_targets_table()
        self._create_runs_table()

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_attempts (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                response TEXT NOT NULL,
                success INTEGER NOT NULL,
                data_leaked_json TEXT,
                response_metadata_json TEXT,
                tool_trace_json TEXT,
                evaluator_json TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES runs(id)
            )
        """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL UNIQUE,
                summary_json TEXT NOT NULL,
                vulnerabilities_json TEXT,
                leaked_data_types_json TEXT,
                report_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES runs(id)
            )
        """
        )

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_attempts_run_id ON attack_attempts(run_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_run_id ON reports(run_id)"
        )
        if self._column_exists("runs", "queued_at"):
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_queued_at ON runs(queued_at)"
            )
        if self._column_exists("runs", "status"):
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status)"
            )
        if self._column_exists("runs", "target_id"):
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_target_id ON runs(target_id)"
            )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_targets_provider_model
            ON targets(provider, model)
        """
        )

    def _get_or_create_target(
        self,
        provider: Optional[str],
        model: Optional[str],
        config_json: str,
        *,
        name: Optional[str] = None,
        target_type: str = DEFAULT_TARGET_TYPE,
    ) -> str:
        existing = self.conn.execute(
            """
            SELECT id FROM targets
            WHERE target_type = ? AND provider IS ? AND model IS ? AND config_json = ?
        """,
            (target_type, provider, model, config_json),
        ).fetchone()
        if existing:
            return existing["id"]

        target_id = str(uuid.uuid4())
        self.conn.execute(
            """
            INSERT INTO targets (
                id,
                name,
                target_type,
                provider,
                model,
                config_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                target_id,
                name or self._default_target_name(provider, model, target_type),
                target_type,
                provider,
                model,
                config_json,
                datetime.now().isoformat(),
            ),
        )
        return target_id

    def _migrate_to_v2(self):
        if not self._table_exists("runs"):
            return

        if not self._column_exists("runs", "target_id"):
            self.conn.execute("ALTER TABLE runs ADD COLUMN target_id TEXT")

        runs = self.conn.execute(
            """
            SELECT id, target_provider, target_model, target_config_json
            FROM runs
            WHERE target_id IS NULL
        """
        ).fetchall()

        for run in runs:
            config_json = self._normalize_target_config(run["target_config_json"])
            existing = self.conn.execute(
                """
                SELECT id FROM targets
                WHERE target_type = ?
                  AND provider IS ?
                  AND model IS ?
                  AND config_json = ?
            """,
                (
                    DEFAULT_TARGET_TYPE,
                    run["target_provider"],
                    run["target_model"],
                    config_json,
                ),
            ).fetchone()
            if existing:
                target_id = existing["id"]
            else:
                target_id = str(uuid.uuid4())
                self.conn.execute(
                    """
                    INSERT INTO targets (
                        id,
                        name,
                        target_type,
                        provider,
                        model,
                        config_json,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        target_id,
                        self._default_target_name(
                            run["target_provider"],
                            run["target_model"],
                            DEFAULT_TARGET_TYPE,
                        ),
                        DEFAULT_TARGET_TYPE,
                        run["target_provider"],
                        run["target_model"],
                        config_json,
                        datetime.now().isoformat(),
                    ),
                )
            self.conn.execute(
                """
                UPDATE runs
                SET target_id = ?, target_config_json = ?
                WHERE id = ?
            """,
                (target_id, config_json, run["id"]),
            )

    def _migrate_to_v3(self):
        conn = self.conn

        if self._table_exists("targets"):
            legacy_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(targets)")
            }
            conn.execute("ALTER TABLE targets RENAME TO targets_v2_legacy")
            self._create_targets_table()
            conn.execute(
                f"""
                INSERT INTO targets (id, name, target_type, provider, model, config_json, created_at)
                SELECT
                    id,
                    CASE
                        WHEN {"model IS NOT NULL" if "model" in legacy_columns else "0"} THEN '{DEFAULT_TARGET_TYPE}:' || COALESCE(provider, 'unknown') || ':' || model
                        WHEN {"provider IS NOT NULL" if "provider" in legacy_columns else "0"} THEN '{DEFAULT_TARGET_TYPE}:' || provider
                        ELSE '{DEFAULT_TARGET_TYPE}'
                    END,
                    '{DEFAULT_TARGET_TYPE}',
                    {"provider" if "provider" in legacy_columns else "NULL"},
                    {"model" if "model" in legacy_columns else "NULL"},
                    config_json,
                    created_at
                FROM targets_v2_legacy
            """
            )
            conn.execute("DROP TABLE targets_v2_legacy")

        if self._table_exists("runs"):
            run_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(runs)")
            }
            conn.execute("ALTER TABLE runs RENAME TO runs_v2_legacy")
            self._create_runs_table()
            conn.execute(
                f"""
                INSERT INTO runs (
                    id,
                    target_id,
                    target_provider,
                    target_model,
                    target_config_json,
                    status,
                    queued_at,
                    started_at,
                    completed_at,
                    duration_seconds,
                    error_message
                )
                SELECT
                    id,
                    {"target_id" if "target_id" in run_columns else "NULL"},
                    {"target_provider" if "target_provider" in run_columns else "NULL"},
                    {"target_model" if "target_model" in run_columns else "NULL"},
                    {"target_config_json" if "target_config_json" in run_columns else "NULL"},
                    CASE
                        WHEN {"completed_at IS NOT NULL" if "completed_at" in run_columns else "0"} THEN 'completed'
                        ELSE 'running'
                    END,
                    {"started_at" if "started_at" in run_columns else "CURRENT_TIMESTAMP"},
                    {"started_at" if "started_at" in run_columns else "NULL"},
                    {"completed_at" if "completed_at" in run_columns else "NULL"},
                    {"duration_seconds" if "duration_seconds" in run_columns else "NULL"},
                    NULL
                FROM runs_v2_legacy
            """
            )
            conn.execute("DROP TABLE runs_v2_legacy")

    def _migrate_to_v4(self):
        conn = self.conn
        if not self._table_exists("reports"):
            return

        conn.execute("ALTER TABLE reports RENAME TO reports_v3_legacy")
        conn.execute(
            """
            CREATE TABLE reports (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL UNIQUE,
                summary_json TEXT NOT NULL,
                vulnerabilities_json TEXT,
                leaked_data_types_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES runs(id)
            )
        """
        )
        conn.execute(
            """
            INSERT INTO reports (
                id,
                run_id,
                summary_json,
                vulnerabilities_json,
                leaked_data_types_json,
                created_at
            )
            SELECT
                r1.id,
                r1.run_id,
                r1.summary_json,
                r1.vulnerabilities_json,
                r1.leaked_data_types_json,
                r1.created_at
            FROM reports_v3_legacy r1
            JOIN (
                SELECT run_id, MAX(created_at) AS max_created_at
                FROM reports_v3_legacy
                GROUP BY run_id
            ) latest
              ON latest.run_id = r1.run_id
             AND latest.max_created_at = r1.created_at
        """
        )
        conn.execute("DROP TABLE reports_v3_legacy")

    def _migrate_to_v5(self):
        conn = self.conn
        if not self._column_exists("attack_attempts", "response_metadata_json"):
            conn.execute(
                "ALTER TABLE attack_attempts ADD COLUMN response_metadata_json TEXT"
            )
        if not self._column_exists("attack_attempts", "tool_trace_json"):
            conn.execute("ALTER TABLE attack_attempts ADD COLUMN tool_trace_json TEXT")
        if not self._column_exists("attack_attempts", "evaluator_json"):
            conn.execute("ALTER TABLE attack_attempts ADD COLUMN evaluator_json TEXT")
        if not self._column_exists("reports", "report_json"):
            conn.execute("ALTER TABLE reports ADD COLUMN report_json TEXT")

        rows = conn.execute(
            """
            SELECT *
            FROM reports
            WHERE report_json IS NULL OR report_json = ''
        """
        ).fetchall()
        for row in rows:
            context = self.get_run(row["run_id"])
            if not context:
                continue
            artifact = build_report_artifact(
                context["attempts"],
                run=context,
                report_row=_row_to_dict(row),
            )
            conn.execute(
                """
                UPDATE reports
                SET report_json = ?,
                    summary_json = ?,
                    vulnerabilities_json = ?,
                    leaked_data_types_json = ?
                WHERE run_id = ?
            """,
                (
                    json.dumps(artifact, sort_keys=True),
                    json.dumps(artifact["summary"], sort_keys=True),
                    json.dumps(artifact.get("vulnerabilities", []), sort_keys=True),
                    json.dumps(artifact.get("leaked_data_types", []), sort_keys=True),
                    row["run_id"],
                ),
            )

    def init_db(self):
        """Initialize database schema."""
        conn = self.conn
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS _schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
        """
        )

        self._ensure_schema()
        current_version = self._detect_schema_version()
        if current_version < 2:
            self._migrate_to_v2()
            current_version = 2
        if current_version < 3:
            self._migrate_to_v3()
            current_version = 3
        if current_version < 4:
            self._migrate_to_v4()
            current_version = 4
        if current_version < 5:
            self._migrate_to_v5()
        self._record_schema_version(SCHEMA_VERSION)
        self._ensure_schema()
        conn.commit()

    def create_target(
        self,
        name: str,
        target_type: str,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        config_json = self._normalize_target_config(config or {})
        target_id = self._get_or_create_target(
            provider,
            model,
            config_json,
            name=name,
            target_type=target_type,
        )
        self.conn.commit()
        target = self.get_target(target_id)
        if target is None:
            raise ValueError(f"Target {target_id} was not created")
        return target

    def get_target(self, target_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            """
            SELECT id, name, target_type, provider, model, config_json, created_at
            FROM targets
            WHERE id = ?
        """,
            (target_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "name": row["name"],
            "target_type": row["target_type"],
            "provider": row["provider"],
            "model": row["model"],
            "config": json.loads(row["config_json"]) if row["config_json"] else {},
            "created_at": row["created_at"],
        }

    def list_targets(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT id, name, target_type, provider, model, config_json, created_at
            FROM targets
            ORDER BY created_at DESC
        """
        ).fetchall()
        return [
            {
                "id": row["id"],
                "name": row["name"],
                "target_type": row["target_type"],
                "provider": row["provider"],
                "model": row["model"],
                "config": json.loads(row["config_json"]) if row["config_json"] else {},
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def create_run(
        self,
        target_provider: Optional[str],
        target_model: Optional[str],
        target_config: Dict[str, Any],
        *,
        target_type: str = DEFAULT_TARGET_TYPE,
        target_id: Optional[str] = None,
    ) -> str:
        """Create a new running run record. Returns run_id."""
        run_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()
        config_json = self._normalize_target_config(target_config)
        resolved_target_id = target_id or self._get_or_create_target(
            target_provider,
            target_model,
            config_json,
            target_type=target_type,
        )
        self.conn.execute(
            """
            INSERT INTO runs (
                id,
                target_id,
                target_provider,
                target_model,
                target_config_json,
                status,
                queued_at,
                started_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                run_id,
                resolved_target_id,
                target_provider,
                target_model,
                config_json,
                "running",
                created_at,
                created_at,
            ),
        )
        self.conn.commit()
        return run_id

    def create_queued_run(self, target_id: str) -> str:
        target = self.get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id} not found")

        run_id = str(uuid.uuid4())
        queued_at = datetime.now().isoformat()
        self.conn.execute(
            """
            INSERT INTO runs (
                id,
                target_id,
                target_provider,
                target_model,
                target_config_json,
                status,
                queued_at,
                started_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                run_id,
                target_id,
                target["provider"],
                target["model"],
                self._normalize_target_config(target["config"]),
                "queued",
                queued_at,
                None,
            ),
        )
        self.conn.commit()
        return run_id

    def mark_run_started(self, run_id: str):
        cursor = self.conn.execute(
            """
            UPDATE runs
            SET status = ?, started_at = ?
            WHERE id = ? AND status = 'queued'
        """,
            ("running", datetime.now().isoformat(), run_id),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"Run {run_id} is not queued")
        self.conn.commit()

    def record_attempt(
        self,
        run_id: str,
        agent_name: str,
        attack_type: str,
        payload: str,
        response: str,
        success: bool,
        data_leaked: List[str],
        response_metadata: Optional[Dict[str, Any]] = None,
        tool_trace: Optional[List[Dict[str, Any]]] = None,
        evaluator: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Record an attack attempt. Returns attempt_id."""
        attempt_id = str(uuid.uuid4())
        self.conn.execute(
            """
            INSERT INTO attack_attempts (
                id,
                run_id,
                agent_name,
                attack_type,
                payload,
                response,
                success,
                data_leaked_json,
                response_metadata_json,
                tool_trace_json,
                evaluator_json,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                attempt_id,
                run_id,
                agent_name,
                attack_type,
                payload,
                response,
                1 if success else 0,
                json.dumps(data_leaked),
                json.dumps(response_metadata or {}, sort_keys=True),
                json.dumps(tool_trace or []),
                json.dumps(evaluator or {}, sort_keys=True),
                datetime.now().isoformat(),
            ),
        )
        self.conn.commit()
        return attempt_id

    def complete_run(self, run_id: str, duration_seconds: float):
        cursor = self.conn.execute(
            """
            UPDATE runs
            SET status = ?, completed_at = ?, duration_seconds = ?, started_at = COALESCE(started_at, queued_at)
            WHERE id = ? AND status IN ('queued', 'running')
        """,
            ("completed", datetime.now().isoformat(), duration_seconds, run_id),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"Run {run_id} is not in a completable state")
        self.conn.commit()

    def mark_run_failed(self, run_id: str, error_message: str):
        run = self.conn.execute(
            "SELECT queued_at, started_at FROM runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        if not run:
            raise ValueError(f"Run {run_id} not found")

        completed_at = datetime.now().isoformat()
        duration_seconds = None
        if run["started_at"]:
            duration_seconds = (
                datetime.fromisoformat(completed_at)
                - datetime.fromisoformat(run["started_at"])
            ).total_seconds()

        cursor = self.conn.execute(
            """
            UPDATE runs
            SET status = ?,
                completed_at = ?,
                duration_seconds = ?,
                error_message = ?,
                started_at = COALESCE(started_at, queued_at)
            WHERE id = ? AND status IN ('queued', 'running')
        """,
            ("failed", completed_at, duration_seconds, error_message, run_id),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"Run {run_id} is not in a fail-able state")
        self.conn.commit()

    def _attempt_row_to_evidence(self, attempt: sqlite3.Row) -> Dict[str, Any]:
        normalized = build_report_artifact([dict(attempt)], duration_seconds=0.0)[
            "attempts"
        ][0]
        normalized["id"] = attempt["id"]
        return normalized

    def save_report(
        self,
        run_id: str,
        summary: Optional[Dict[str, Any]] = None,
        vulnerabilities: Optional[List[str]] = None,
        leaked_data_types: Optional[List[str]] = None,
        report: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Save a report for a run. Returns report_id."""
        report_id = str(uuid.uuid4())
        context = self.get_run(run_id)
        if report is not None:
            artifact = report_to_dict(report)
        else:
            artifact = context["report"] if context and context.get("report") else {}
            if not artifact:
                artifact = {
                    "schema_version": REPORT_SCHEMA_VERSION,
                    "generated_at": datetime.now().isoformat(),
                    "available_exports": ["json", "markdown"],
                    "summary": summary or {},
                    "vulnerabilities": vulnerabilities or [],
                    "leaked_data_types": leaked_data_types or [],
                    "findings": [],
                    "attempts": [],
                    "attacks_by_type": {},
                    "results": [],
                }
        artifact = dict(artifact)
        artifact.setdefault("schema_version", REPORT_SCHEMA_VERSION)
        artifact.setdefault("generated_at", datetime.now().isoformat())
        artifact.setdefault("available_exports", ["json", "markdown"])
        artifact.setdefault("summary", summary or {})
        artifact["run_id"] = run_id
        if context:
            for key in (
                "id",
                "target_id",
                "target_name",
                "target_type",
                "target_provider",
                "target_model",
                "target_config",
                "status",
                "queued_at",
                "started_at",
                "completed_at",
                "duration_seconds",
                "error_message",
            ):
                if artifact.get(key) is None and context.get(key) is not None:
                    artifact[key] = context.get(key)
        if summary and artifact.get("summary") != summary:
            merged_summary = dict(artifact.get("summary", {}))
            merged_summary.update(summary)
            artifact["summary"] = merged_summary
        if vulnerabilities is not None:
            artifact["vulnerabilities"] = vulnerabilities
        if leaked_data_types is not None:
            artifact["leaked_data_types"] = leaked_data_types
        self.conn.execute(
            """
            INSERT INTO reports (
                id,
                run_id,
                summary_json,
                vulnerabilities_json,
                leaked_data_types_json,
                report_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                id = excluded.id,
                summary_json = excluded.summary_json,
                vulnerabilities_json = excluded.vulnerabilities_json,
                leaked_data_types_json = excluded.leaked_data_types_json,
                report_json = excluded.report_json,
                created_at = excluded.created_at
        """,
            (
                report_id,
                run_id,
                json.dumps(artifact.get("summary", summary)),
                json.dumps(artifact.get("vulnerabilities", vulnerabilities)),
                json.dumps(artifact.get("leaked_data_types", leaked_data_types)),
                json.dumps(artifact, sort_keys=True),
                datetime.now().isoformat(),
            ),
        )
        self.conn.commit()
        return report_id

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        run = self.conn.execute(
            """
            SELECT
                r.*,
                t.name AS target_name,
                t.target_type AS target_type,
                t.provider AS target_provider_resolved,
                t.model AS target_model_resolved,
                t.config_json AS target_config_json_resolved
            FROM runs r
            LEFT JOIN targets t ON t.id = r.target_id
            WHERE r.id = ?
        """,
            (run_id,),
        ).fetchone()
        if not run:
            return None

        attempts = self.conn.execute(
            "SELECT * FROM attack_attempts WHERE run_id = ? ORDER BY timestamp",
            (run_id,),
        ).fetchall()
        report = self.conn.execute(
            "SELECT * FROM reports WHERE run_id = ? ORDER BY created_at DESC LIMIT 1",
            (run_id,),
        ).fetchone()

        report_dict = None
        if report and report["report_json"]:
            try:
                report_dict = json.loads(report["report_json"])
            except json.JSONDecodeError:
                report_dict = None

        if report_dict is None and (attempts or report):
            report_dict = build_report_artifact(
                [dict(attempt) for attempt in attempts],
                run={
                    "id": run["id"],
                    "target_id": run["target_id"],
                    "target_name": run["target_name"],
                    "target_type": run["target_type"],
                    "target_provider": run["target_provider_resolved"] or run["target_provider"],
                    "target_model": run["target_model_resolved"] or run["target_model"],
                    "target_config": json.loads(
                        run["target_config_json_resolved"] or run["target_config_json"] or "{}"
                    ),
                    "status": run["status"],
                    "queued_at": run["queued_at"],
                    "started_at": run["started_at"],
                    "completed_at": run["completed_at"],
                    "duration_seconds": run["duration_seconds"],
                    "error_message": run["error_message"],
                },
                report_row=_row_to_dict(report),
            )

        return {
            "id": run["id"],
            "target_id": run["target_id"],
            "target_name": run["target_name"],
            "target_type": run["target_type"],
            "target_provider": run["target_provider_resolved"] or run["target_provider"],
            "target_model": run["target_model_resolved"] or run["target_model"],
            "target_config": json.loads(
                run["target_config_json_resolved"] or run["target_config_json"] or "{}"
            ),
            "status": run["status"],
            "queued_at": run["queued_at"],
            "started_at": run["started_at"],
            "completed_at": run["completed_at"],
            "duration_seconds": run["duration_seconds"],
            "error_message": run["error_message"],
            "attempts": [dict(attempt) for attempt in attempts],
            "report": report_dict,
        }

    def list_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT
                r.id,
                r.target_id,
                t.name AS target_name,
                t.target_type AS target_type,
                COALESCE(t.provider, r.target_provider) AS target_provider,
                COALESCE(t.model, r.target_model) AS target_model,
                r.status,
                r.queued_at,
                r.started_at,
                r.completed_at,
                r.duration_seconds,
                r.error_message,
                (SELECT COUNT(*) FROM attack_attempts WHERE run_id = r.id) AS attempt_count,
                (SELECT COUNT(*) FROM attack_attempts WHERE run_id = r.id AND success = 1) AS success_count,
                (SELECT summary_json FROM reports WHERE run_id = r.id) AS summary_json
            FROM runs r
            LEFT JOIN targets t ON t.id = r.target_id
            ORDER BY r.queued_at DESC
            LIMIT ?
        """,
            (limit,),
        ).fetchall()

        results = []
        for row in rows:
            summary = json.loads(row["summary_json"]) if row["summary_json"] else {}
            results.append(
                {
                    "id": row["id"],
                    "target_id": row["target_id"],
                    "target_name": row["target_name"],
                    "target_type": row["target_type"],
                    "target_provider": row["target_provider"],
                    "target_model": row["target_model"],
                    "status": row["status"],
                    "queued_at": row["queued_at"],
                    "started_at": row["started_at"],
                    "completed_at": row["completed_at"],
                    "duration_seconds": row["duration_seconds"],
                    "error_message": row["error_message"],
                    "attempt_count": row["attempt_count"],
                    "success_count": row["success_count"],
                    "success_rate": summary.get("success_rate", 0),
                    "summary": summary,
                }
            )
        return results

    def _build_report_from_attempts(self, run: Dict[str, Any]) -> Dict[str, Any]:
        attempts = [self._attempt_row_to_evidence(attempt) for attempt in run["attempts"]]
        return build_report_artifact(
            attempts,
            run=run,
        )

    def get_report_artifact(self, run_id: str) -> Dict[str, Any]:
        run = self.get_run(run_id)
        if not run:
            raise ValueError(f"Run {run_id} not found")

        if run["report"]:
            return run["report"]

        report = self._build_report_from_attempts(run)
        return report

    def regenerate_report(self, run_id: str) -> Dict[str, Any]:
        """Compatibility helper returning the canonical report artifact."""
        return self.get_report_artifact(run_id)

    def get_run_evidence(self, run_id: str) -> Dict[str, Any]:
        run = self.get_run(run_id)
        if not run:
            raise ValueError(f"Run {run_id} not found")

        attempts = [self._attempt_row_to_evidence(attempt) for attempt in run["attempts"]]
        return {
            "id": run["id"],
            "target_id": run["target_id"],
            "target_type": run["target_type"],
            "status": run["status"],
            "queued_at": run["queued_at"],
            "started_at": run["started_at"],
            "completed_at": run["completed_at"],
            "duration_seconds": run["duration_seconds"],
            "error_message": run["error_message"],
            "target_config": run["target_config"],
            "attempts": attempts,
        }

    def compare_runs(self, run_a_id: str, run_b_id: str) -> Dict[str, Any]:
        run_a = self.get_run(run_a_id)
        run_b = self.get_run(run_b_id)
        if not run_a:
            raise ValueError(f"Run {run_a_id} not found")
        if not run_b:
            raise ValueError(f"Run {run_b_id} not found")

        report_a = self.get_report_artifact(run_a_id)
        report_b = self.get_report_artifact(run_b_id)

        summary_delta = {}
        for key in ("total_attacks", "successful_attacks", "success_rate", "duration"):
            summary_delta[key] = report_b["summary"][key] - report_a["summary"][key]

        attack_type_deltas = {}
        attack_types = sorted(
            set(report_a["attacks_by_type"]) | set(report_b["attacks_by_type"])
        )
        for attack_type in attack_types:
            stats_a = report_a["attacks_by_type"].get(
                attack_type, {"total": 0, "successful": 0}
            )
            stats_b = report_b["attacks_by_type"].get(
                attack_type, {"total": 0, "successful": 0}
            )
            rate_a = (
                (stats_a["successful"] / stats_a["total"] * 100)
                if stats_a["total"] > 0
                else 0
            )
            rate_b = (
                (stats_b["successful"] / stats_b["total"] * 100)
                if stats_b["total"] > 0
                else 0
            )
            attack_type_deltas[attack_type] = {
                "run_a": {
                    "total": stats_a["total"],
                    "successful": stats_a["successful"],
                    "success_rate": rate_a,
                },
                "run_b": {
                    "total": stats_b["total"],
                    "successful": stats_b["successful"],
                    "success_rate": rate_b,
                },
                "delta": {
                    "total": stats_b["total"] - stats_a["total"],
                    "successful": stats_b["successful"] - stats_a["successful"],
                    "success_rate": rate_b - rate_a,
                },
            }

        leaked_a = set(report_a["leaked_data_types"])
        leaked_b = set(report_b["leaked_data_types"])
        return {
            "run_a": {
                "id": run_a["id"],
                "target_id": run_a["target_id"],
                "target_provider": run_a["target_provider"],
                "target_model": run_a["target_model"],
                "started_at": run_a["started_at"],
                "summary": report_a["summary"],
            },
            "run_b": {
                "id": run_b["id"],
                "target_id": run_b["target_id"],
                "target_provider": run_b["target_provider"],
                "target_model": run_b["target_model"],
                "started_at": run_b["started_at"],
                "summary": report_b["summary"],
            },
            "summary_delta": summary_delta,
            "attack_type_deltas": attack_type_deltas,
            "leaked_data": {
                "run_a": sorted(leaked_a),
                "run_b": sorted(leaked_b),
                "only_in_run_a": sorted(leaked_a - leaked_b),
                "only_in_run_b": sorted(leaked_b - leaked_a),
            },
        }

    def export_report(self, run_id: str, export_format: str) -> Dict[str, Any]:
        artifact = self.get_report_artifact(run_id)
        content, content_type = export_report(artifact, export_format)
        return {
            "filename": f"{run_id}.{'json' if export_format == 'json' else 'md'}",
            "content": content,
            "content_type": content_type,
            "report": artifact,
        }

    def delete_run(self, run_id: str):
        self.conn.execute("DELETE FROM reports WHERE run_id = ?", (run_id,))
        self.conn.execute("DELETE FROM attack_attempts WHERE run_id = ?", (run_id,))
        self.conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        self.conn.commit()

    def get_stats(self) -> Dict[str, Any]:
        total_targets = self.conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        total_runs = self.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        completed_runs = self.conn.execute(
            "SELECT COUNT(*) FROM runs WHERE status = 'completed'"
        ).fetchone()[0]
        failed_runs = self.conn.execute(
            "SELECT COUNT(*) FROM runs WHERE status = 'failed'"
        ).fetchone()[0]
        total_attempts = self.conn.execute(
            "SELECT COUNT(*) FROM attack_attempts"
        ).fetchone()[0]
        total_duration = (
            self.conn.execute(
                "SELECT SUM(duration_seconds) FROM runs WHERE duration_seconds IS NOT NULL"
            ).fetchone()[0]
            or 0
        )
        return {
            "total_targets": total_targets,
            "total_runs": total_runs,
            "completed_runs": completed_runs,
            "failed_runs": failed_runs,
            "total_attempts": total_attempts,
            "total_duration_seconds": total_duration,
            "db_path": str(self.db_path),
        }
