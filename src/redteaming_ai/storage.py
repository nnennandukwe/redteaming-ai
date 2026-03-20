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

    def init_db(self):
        """Initialize database schema."""
        conn = self.conn

        conn.execute("""
            CREATE TABLE IF NOT EXISTS _schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                target_provider TEXT,
                target_model TEXT,
                target_config_json TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_seconds REAL
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

        existing = conn.execute("SELECT MAX(version) FROM _schema_version").fetchone()[
            0
        ]
        if not existing:
            conn.execute(
                "INSERT INTO _schema_version (version, applied_at) VALUES (1, ?)",
                (datetime.now().isoformat(),),
            )

        conn.commit()

    def create_run(
        self,
        target_provider: str,
        target_model: Optional[str],
        target_config: Dict[str, Any],
    ) -> str:
        """Create a new run record. Returns run_id."""
        run_id = str(uuid.uuid4())
        conn = self.conn
        conn.execute(
            """
            INSERT INTO runs (id, target_provider, target_model, target_config_json, started_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                run_id,
                target_provider,
                target_model,
                json.dumps(target_config),
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

        run = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
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
            "target_provider": run["target_provider"],
            "target_model": run["target_model"],
            "target_config": json.loads(run["target_config_json"])
            if run["target_config_json"]
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
            SELECT r.id, r.target_provider, r.target_model, r.started_at,
                   r.completed_at, r.duration_seconds,
                   (SELECT COUNT(*) FROM attack_attempts WHERE run_id = r.id) as attempt_count,
                   (SELECT COUNT(*) FROM attack_attempts WHERE run_id = r.id AND success = 1) as success_count,
                   (SELECT summary_json FROM reports WHERE run_id = r.id) as summary_json
            FROM runs r
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
            "total_runs": total_runs,
            "completed_runs": completed_runs,
            "total_attempts": total_attempts,
            "total_duration_seconds": total_duration,
            "db_path": str(self.db_path),
        }
