from __future__ import annotations

import json
import logging
import platform
import shutil
import sys
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("agent")

SUPPORTED_VERSIONS = {1}

"""
budget_state 统一结构约定：
{
    "token": {...},      # TokenBudget.to_dict()
    "cost": {...},       # CostBudget.to_dict()
    "step": {...},       # StepCounter.to_dict()
    "vuln": {...},       # VulnBudget.to_dict()  (仅主 Agent 使用)
}
SubAgent 的 budget_state 不包含 "vuln" 字段。
"""


class Trajectory:
    """追踪链路轨迹，用于断点恢复和审计观测"""

    CHECKPOINT_DIR = ".depsafe"
    CHECKPOINT_FILE = "checkpoint.json"
    ARCHIVE_DIR = "archives"

    def __init__(self, project_root: Path):
        self.project_root = project_root.resolve()
        self.dir = self.project_root / self.CHECKPOINT_DIR
        self.file = self.dir / self.CHECKPOINT_FILE
        self.archive_dir = self.dir / self.ARCHIVE_DIR

    def exists(self) -> bool:
        return self.file.exists()

    @staticmethod
    def validate_env(checkpoint: dict) -> bool:
        """检查 checkpoint 的环境指纹是否与当前运行时兼容"""
        saved = checkpoint.get("env", {})
        if not saved:
            # 旧版 checkpoint 没有 env 字段，保守拒绝
            logger.warning("Checkpoint missing 'env' fingerprint, refusing recovery.")
            return False
        if saved.get("system") != platform.system():
            logger.warning(f"OS mismatch: saved={saved.get('system')}, current={platform.system()}")
            return False
        current_py = f"{sys.version_info.major}.{sys.version_info.minor}"
        if saved.get("python") != current_py:
            logger.warning(f"Python version mismatch: saved={saved.get('python')}, current={current_py}")
            return False
        return True

    @staticmethod
    def build_env_fingerprint() -> dict:
        """构建当前环境指纹，save 时写入 checkpoint"""
        return {
            "system": platform.system(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "machine": platform.machine(),
        }

    def load(self) -> dict | None:
        if not self.file.exists():
            return None
        try:
            return json.loads(self.file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def save(self, messages: list[dict], budget_state: dict, status: str = "running", exit_reason: str | None = None):
        """保存检查点。status: running / completed / error"""
        self.dir.mkdir(parents=True, exist_ok=True)
        now = datetime.now().isoformat(timespec="seconds")
        created_at = now
        if self.file.exists():
            existing = self.load()
            if existing:
                created_at = existing.get("created_at", now)
        checkpoint = {
            "version": 1,
            "project_root": str(self.project_root),
            "created_at": created_at,
            "updated_at": now,
            "status": status,
            "exit_reason": exit_reason,
            "env": self.build_env_fingerprint(),
            "messages": messages,
            "budget_state": budget_state,
        }
        # 原子写入：先写临时文件再 rename，防止写一半断电导致文件损坏
        tmp = self.file.with_suffix(".tmp")
        tmp.write_text(json.dumps(checkpoint, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.rename(self.file)

    def archive(self) -> Path | None:
        """将当前检查点归档到 archives/ 目录"""
        if not self.file.exists():
            return None
        checkpoint = self.load()
        if checkpoint is None:
            return None
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        status = checkpoint.get("status", "unknown")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = f"checkpoint_{ts}_{status}.json"
        archive_path = self.archive_dir / archive_name
        shutil.copy2(self.file, archive_path)
        self.file.unlink()
        return archive_path

    def recover(self) -> tuple[bool, dict | None]:
        """
        尝试恢复轨迹。
        恢复策略：
        - 无检查点 → 重新开始
        - status == "running" → 断电恢复（进程被意外杀死）
        - status == "completed" / "error" → 归档后重新开始

        Returns:
            (resumed_messages, budget_state):
            - resumed_messages=True 表示消息历史已恢复到调用方
            （实际消息通过 load() 获取，避免在返回值中传递大列表）
            - budget_state 始终返回（无论消息是否恢复），调用方据此初始化 VulnBudget
            - 若不应恢复，返回 (False, None)
        """
        # 1. 文件存在且可读
        if not self.exists():
            return False, None
        checkpoint = self.load()
        if checkpoint is None:
            logger.warning("Checkpoint file corrupted or unreadable, starting fresh.")
            return False, None
        # 2. 版本兼容
        if checkpoint.get("version") not in SUPPORTED_VERSIONS:
            logger.warning(f"Incompatible checkpoint version {checkpoint.get('version')}, starting fresh.")
            return False, None
        # 3. 环境兼容
        if not self.validate_env(checkpoint):
            logger.warning("Environment validation failed, starting fresh.")
            return False, None
        # 4. 状态检查：非 running → 归档后重开
        status = checkpoint.get("status", "running")
        if status != "running":
            archived = self.archive()
            logger.info(
                f"Previous run ended: status='{status}', "
                f"reason={checkpoint.get('exit_reason')}. "
                f"Archived to {archived}. Starting fresh."
            )
            return False, None
        # 5. 提取数据
        messages = checkpoint.get("messages", [])
        budget_state = checkpoint.get("budget_state", {})
        if not messages:
            logger.info("Resumed budget only, no messages to restore.")
            return False, budget_state
        logger.info(f"Resumed from interrupted run: {len(messages)} messages.")
        return True, budget_state


class SubTrajectory:
    """
    SubAgent 只写审计日志。
    - 不做断点恢复，ROI较低，无状态函数调用重试容易而恢复复杂
    - 每次 run() 生成一个独立文件
    - 文件名包含父任务标识，便于关联
    """

    SUB_DIR = ".depsafe/sub_trajectories"

    def __init__(self, project_root: Path, sub_task_name: str):
        self.project_root = project_root.resolve()
        self.dir = project_root / self.SUB_DIR
        # 任务名拼入文件名，必须消毒路径分隔符（如 file_path="./app.py" 会引入 '/' 导致保存失败）
        self.sub_task_name = sub_task_name.replace("/", "-")

    def save(self, messages: list[dict], budget_state: dict, status: str = "completed", exit_reason: str | None = None):
        """保存 SubAgent 执行轨迹（覆盖写入，无需原子操作——丢了就丢了）"""
        self.dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.sub_task_name}_{ts}.json"
        filepath = self.dir / filename
        record = {
            "version": 1,
            "project_root": str(self.project_root),
            "sub_task_name": self.sub_task_name,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "status": status,
            "exit_reason": exit_reason,
            "messages": messages,
            "budget_state": budget_state,
        }
        filepath.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.debug(f"SubAgent trajectory saved: {filepath}")
