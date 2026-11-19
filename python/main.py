"""释缚 - 解锁 Win11 被占用文件（GUI 入口，始终非提权）。

架构：GUI 不请求管理员权限，以便正常接收资源管理器 OLE 拖放（UIPI 只会
拦截低完整性 -> 高完整性的消息）。需要管理员权限的解锁操作通过命名管道
交给按需拉起的提权 helper（agent_main.py），用户点操作时弹一次 UAC。
"""
from __future__ import annotations

import os
import sys

# 允许从源码目录直接运行
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import winapi  # noqa: E402
from ui.main_window import run  # noqa: E402


def _parse_mode(argv: list[str]) -> str:
    """解析 --mode=xxx，返回 delete/unlock/rename，默认 delete。"""
    for a in argv:
        if a.startswith("--mode="):
            mode = a.split("=", 1)[1].strip().lower()
            if mode in ("delete", "unlock", "rename"):
                return mode
    return "delete"


def _collect_paths(argv: list[str]) -> list[str]:
    """收集命令行中的文件路径，过滤掉标志位。"""
    paths = []
    for a in argv:
        if a.startswith("-") and not os.path.exists(a):
            continue
        try:
            abs_p = os.path.abspath(a)
        except Exception:
            continue
        if os.path.exists(abs_p):
            paths.append(abs_p)
    return paths


def main() -> int:
    argv = sys.argv[1:]
    paths = _collect_paths(argv)
    mode = _parse_mode(argv)
    # 非提权运行是刻意设计：拖放必须在中等完整性下才能工作。
    # 旧版 Source 态 runas 自重启逻辑已移除，提权只发生在 helper。
    return run(paths, mode=mode)


if __name__ == "__main__":
    sys.exit(main())
