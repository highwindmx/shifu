"""数据模型：诊断结果与占用者信息。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class HeldProcess:
    """Restart Manager 识别出的占用进程。"""

    pid: int
    name: str
    app_type: int = 0
    restartable: bool = False
    start_time: float = 0.0
    exe: str = ""

    @property
    def type_label(self) -> str:
        return {
            0: "未知",
            1: "主窗口程序",
            2: "其他窗口程序",
            3: "服务",
            4: "资源管理器",
            5: "控制台程序",
            1000: "关键进程",
        }.get(self.app_type, f"类型 {self.app_type}")


@dataclass
class FileHolder:
    """通过句柄枚举识别出的持有文件句柄的进程。"""

    pid: int
    handle_value: int
    object_name: str
    win32_path: str
    process_name: str = ""


@dataclass
class Diagnosis:
    """单个路径的诊断结果。"""

    path: str
    exists: bool = False
    is_dir: bool = False
    kind: str = "UNKNOWN"
    kind_label: str = "未知"
    detail: str = ""
    error_code: int = 0
    attributes: int = 0
    processes: List[HeldProcess] = field(default_factory=list)
    holders: List[FileHolder] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

    def summary(self) -> str:
        head = f"{self.path}\n  判定: {self.kind_label}"
        if self.detail:
            head += f"\n  说明: {self.detail}"
        if self.processes:
            names = "、".join(f"{p.name}(PID {p.pid})" for p in self.processes[:5])
            head += f"\n  占用进程: {names}"
        if self.holders:
            head += f"\n  文件句柄: {len(self.holders)} 个"
        if self.suggestions:
            head += "\n  建议: " + "；".join(self.suggestions)
        return head


@dataclass
class ActionResult:
    """一次操作的结果。"""

    ok: bool
    message: str
    detail: str = ""
