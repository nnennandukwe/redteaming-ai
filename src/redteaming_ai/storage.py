"""
Persistent storage for red team assessment runs.
Uses SQLite for local storage with full reproducibility support.
"""

import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = 2


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
        existing = self.conn.execute(
            "SELECT MAX(version) FROM _schema_version"
        ).fetchone()[0]
        if existing is not None:
            return int(existing)
        if self._table_exists("runs"):
            return 1 if not self._column_exists("runs", "target_id") else 2
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

    def _ensure_schema(self):
        conn = self.conn
        conn.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                provider TEXT,
                model TEXT,
                config_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(provider, model, config_json)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                target_id TEXT,
                target_provider TEXT,
                target_model TEXT,
                target_config_json TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_seconds REAL,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS attack_attempts (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                response TEXT NOT NULL,
                success INTEGER NOT NULL,
                data_leaked_json TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES runs(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                vulnerabilities_json TEXT,
                leaked_data_types_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES runs(id)
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_attempts_run_id ON attack_attempts(run_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_reports_run_id ON reports(run_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at)
        """)

        if self._column_exists("runs", "target_id"):
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_runs_target_id ON runs(target_id)
            """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_targets_provider_model
            ON targets(provider, model)
        """)

    def _get_or_create_target(
        self, provider: Optional[str], model: Optional[str], config_json: str
    ) -> str:
        existing = self.conn.execute(
            """
            SELECT id FROM targets
            WHERE provider IS ? AND model IS ? AND config_json = ?
        """,
            (provider, model, config_json),
        ).fetchone()
        if existing:
            return existing["id"]

        target_id = str(uuid.uuid4())
        self.conn.execute(
            """
            INSERT INTO targets (id, provider, model, config_json, created_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (target_id, provider, model, config_json, datetime.now().isoformat()),
        )
        return target_id

    def _migrate_to_v2(self):
        conn = self.conn
        conn.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                provider TEXT,
                model TEXT,
                config_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(provider, model, config_json)
            )
        """)

        if not self._column_exists("runs", "target_id"):
            conn.execute("ALTER TABLE runs ADD COLUMN target_id TEXT")

        runs = conn.execute(
            """
            SELECT id, target_provider, target_model, target_config_json
            FROM runs
            WHERE target_id IS NULL
        """
        ).fetchall()

        for run in runs:
            config_json = self._normalize_target_config(run["target_config_json"])
            target_id = self._get_or_create_target(
                run["target_provider"],
                run["target_model"],
                config_json,
            )
            conn.execute(
                """
                UPDATE runs
                SET target_id = ?, target_config_json = ?
                WHERE id = ?
            """,
                (target_id, config_json, run["id"]),
            )

    def init_db(self):
        """Initialize database schema."""
        conn = self.conn

        conn.execute("""
            CREATE TABLE IF NOT EXISTS _schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
        """)
        self._ensure_schema()
        current_version = self._detect_schema_version()
        if current_version < 2:
            self._migrate_to_v2()
        self._record_schema_version(SCHEMA_VERSION)
        conn.commit()

    def create_run(
        self,
        target_provider: str,
        target_model: Optional[str],
        target_config: Dict[str, Any],
    ) -> str:
        """Create a new run record. Returns run_id."""
        run_id = str(uuid.uuid4())
        config_json = self._normalize_target_config(target_config)
        target_id = self._get_or_create_target(target_provider, target_model, config_json)
        conn = self.conn
        conn.execute(
            """
            INSERT INTO runs (
                id,
                target_id,
                target_provider,
                target_model,
                target_config_json,
                started_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                run_id,
                target_id,
                target_provider,
                target_model,
                config_json,
                datetime.now().isoformat(),
            ),
        )
        conn.commit()
        return run_id

    def record_attempt(
        self,
        run_id: str,
        agent_name: str,
        attack_type: str,
        payload: str,
        response: str,
        success: bool,
        data_leaked: List[str],
    ) -> str:
        """Record an attack attempt. Returns attempt_id."""
        attempt_id = str(uuid.uuid4())
        conn = self.conn
        conn.execute(
            """
            INSERT INTO attack_attempts
            (id, run_id, agent_name, attack_type, payload, response, success, data_leaked_json, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                datetime.now().isoformat(),
            ),
        )
        conn.commit()
        return attempt_id

    def complete_run(self, run_id: str, duration_seconds: float):
        """Mark run as completed with duration."""
        conn = self.conn
        conn.execute(
            """
            UPDATE runs SET completed_at = ?, duration_seconds = ? WHERE id = ?
        """,
            (datetime.now().isoformat(), duration_seconds, run_id),
        )
        conn.commit()

    def save_report(
        self,
        run_id: str,
        summary: Dict[str, Any],
        vulnerabilities: List[str],
        leaked_data_types: List[str],
    ) -> str:
        """Save a report for a run. Returns report_id."""
        report_id = str(uuid.uuid4())
        conn = self.conn
        conn.execute(
            """
            INSERT INTO reports (id, run_id, summary_json, vulnerabilities_json, leaked_data_types_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                report_id,
                run_id,
                json.dumps(summary),
                json.dumps(vulnerabilities),
                json.dumps(leaked_data_types),
                datetime.now().isoformat(),
            ),
        )
        conn.commit()
        return report_id

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Get a run with all its attempts."""
        conn = self.conn

        run = conn.execute(
            """
            SELECT
                r.*,
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

        attempts = conn.execute(
            "SELECT * FROM attack_attempts WHERE run_id = ? ORDER BY timestamp",
            (run_id,),
        ).fetchall()

        report = conn.execute(
            "SELECT * FROM reports WHERE run_id = ?", (run_id,)
        ).fetchone()

        return {
            "id": run["id"],
            "target_id": run["target_id"],
            "target_provider": run["target_provider_resolved"] or run["target_provider"],
            "target_model": run["target_model_resolved"] or run["target_model"],
            "target_config": json.loads(
                run["target_config_json_resolved"] or run["target_config_json"] or "{}"
            )
            if (run["target_config_json_resolved"] or run["target_config_json"])
            else {},
            "started_at": run["started_at"],
            "completed_at": run["completed_at"],
            "duration_seconds": run["duration_seconds"],
            "attempts": [dict(a) for a in attempts],
            "report": dict(report) if report else None,
        }

    def list_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        """List recent runs with summary info."""
        conn = self.conn
        runs = conn.execute(
            """
            SELECT r.id, r.target_id,
                   COALESCE(t.provider, r.target_provider) AS target_provider,
                   COALESCE(t.model, r.target_model) AS target_model,
                   r.started_at, r.completed_at, r.duration_seconds,
                   (SELECT COUNT(*) FROM attack_attempts WHERE run_id = r.id) as attempt_count,
                   (SELECT COUNT(*) FROM attack_attempts WHERE run_id = r.id AND success = 1) as success_count,
                   (SELECT summary_json FROM reports WHERE run_id = r.id) as summary_json
            FROM runs r
            LEFT JOIN targets t ON t.id = r.target_id
            ORDER BY r.started_at DESC
            LIMIT ?
        """,
            (limit,),
        ).fetchall()

        results = []
        for run in runs:
            summary = json.loads(run["summary_json"]) if run["summary_json"] else {}
            results.append(
                {
                    "id": run["id"],
                    "target_id": run["target_id"],
                    "target_provider": run["target_provider"],
                    "target_model": run["target_model"],
                    "started_at": run["started_at"],
                    "completed_at": run["completed_at"],
                    "duration_seconds": run["duration_seconds"],
                    "attempt_count": run["attempt_count"],
                    "success_count": run["success_count"],
                    "success_rate": summary.get("success_rate", 0),
                }
            )
        return results

    def regenerate_report(self, run_id: str) -> Dict[str, Any]:
        """Regenerate a report from stored attack attempts."""
        run = self.get_run(run_id)
        if not run:
            raise ValueError(f"Run {run_id} not found")

        attempts = run["attempts"]
        total_attacks = len(attempts)
        successful_attacks = sum(1 for a in attempts if a["success"])
        success_rate = (
            (successful_attacks / total_attacks * 100) if total_attacks > 0 else 0
        )

        all_leaked = set()
        attacks_by_type = {}

        for attempt in attempts:
            leaked = (
                json.loads(attempt["data_leaked_json"])
                if attempt["data_leaked_json"]
                else []
            )
            all_leaked.update(leaked)

            at = attempt["attack_type"]
            if at not in attacks_by_type:
                attacks_by_type[at] = {"total": 0, "successful": 0}
            attacks_by_type[at]["total"] += 1
            if attempt["success"]:
                attacks_by_type[at]["successful"] += 1

        return {
            "summary": {
                "total_attacks": total_attacks,
                "successful_attacks": successful_attacks,
                "success_rate": success_rate,
                "duration": run["duration_seconds"] or 0,
            },
            "attacks_by_type": attacks_by_type,
            "leaked_data_types": list(all_leaked),
            "results": [
                {
                    "agent_name": a["agent_name"],
                    "attack_type": a["attack_type"],
                    "payload": a["payload"],
                    "success": bool(a["success"]),
                    "data_leaked": json.loads(a["data_leaked_json"])
                    if a["data_leaked_json"]
                    else [],
                }
                for a in attempts
            ],
        }

    def compare_runs(self, run_a_id: str, run_b_id: str) -> Dict[str, Any]:
        """Compare two runs and return stable summary and delta data."""
        run_a = self.get_run(run_a_id)
        run_b = self.get_run(run_b_id)
        if not run_a:
            raise ValueError(f"Run {run_a_id} not found")
        if not run_b:
            raise ValueError(f"Run {run_b_id} not found")

        report_a = self.regenerate_report(run_a_id)
        report_b = self.regenerate_report(run_b_id)

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

    def delete_run(self, run_id: str):
        """Delete a run and all associated data."""
        conn = self.conn
        conn.execute("DELETE FROM reports WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM attack_attempts WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        conn.commit()

    def get_stats(self) -> Dict[str, Any]:
        """Get overall storage statistics."""
        conn = self.conn
        total_targets = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        total_runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        completed_runs = conn.execute(
            "SELECT COUNT(*) FROM runs WHERE completed_at IS NOT NULL"
        ).fetchone()[0]
        total_attempts = conn.execute(
            "SELECT COUNT(*) FROM attack_attempts"
        ).fetchone()[0]
        total_duration = (
            conn.execute(
                "SELECT SUM(duration_seconds) FROM runs WHERE duration_seconds IS NOT NULL"
            ).fetchone()[0]
            or 0
        )

        return {
            "total_targets": total_targets,
            "total_runs": total_runs,
            "completed_runs": completed_runs,
            "total_attempts": total_attempts,
            "total_duration_seconds": total_duration,
            "db_path": str(self.db_path),
        }
