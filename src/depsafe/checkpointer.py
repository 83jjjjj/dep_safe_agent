from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class Trajectory:
    """
    Messages + VulnBudget 持久化器。

    存放位置：项目根目录 / trajectory.json
    恢复前提：validate_env() 通过（cwd == git repo root）
    """

    FILENAME = "trajectory.json"

    def __init__(self, root: Path | None = None):
        self.root = root or Path.cwd().resolve()
        self._path = self.root / self.FILENAME

    @staticmethod
    def validate_env() -> bool:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return False
            return result.stdout.strip() == str(Path.cwd().resolve())
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def save(self, messages: list[dict], vuln_budget_state: dict[str, Any]) -> None:
        data = {
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "vuln_budget": vuln_budget_state,
            "messages": messages,
        }
        self._path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def load(self) -> tuple[list[dict], dict[str, Any]] | None:
        """返回 (messages, vuln_budget_state)，文件不存在返回 None"""
        if not self._path.exists():
            return None
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return data.get("messages", []), data.get("vuln_budget", {})

    def exists(self) -> bool:
        return self._path.exists()

    def remove(self) -> None:
        """批次正常结束后清理，避免下次误恢复"""
        self._path.unlink(missing_ok=True)
