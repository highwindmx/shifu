"""策略层：L0~L4 解锁手段，统一返回 ActionResult。"""
from __future__ import annotations

import os
import time
from typing import List

from . import winapi
from .models import ActionResult, Diagnosis, FileHolder, HeldProcess


def l0_retry_delete(path: str, attempts: int = 3, delay: float = 0.4) -> ActionResult:
    """L0 只重试探测是否可删，绝不隐式删除（删除是独立的最终操作）。"""
    last = 0
    for i in range(attempts):
        ok, last = winapi.probe_delete(path)
        if ok:
            return ActionResult(True, "L0 重试探测", "瞬时占用已解除，文件现可删除/重命名")
        if i < attempts - 1:
            time.sleep(delay)
    return ActionResult(False, "L0 重试探测", f"仍不可删除 err={last}")


def _verify_unlock(path: str) -> tuple[bool, str]:
    """解锁后仅探测是否可删，绝不实际删除（删除是独立的最终操作）。"""
    ok, err = winapi.probe_delete(path)
    return ok, "解锁成功，文件现可删除/重命名" if ok else f"仍不可删除 err={err}"


def l1_end_processes(path: str, procs: List[HeldProcess], force: bool = False) -> ActionResult:
    """结束占用进程（跳过自身进程），然后探测解锁结果，不删除文件。"""
    logs = []
    all_ok = True
    for p in procs:
        if p.pid in winapi.self_pid_chain():
            logs.append(f"{p.name} (PID {p.pid}): 跳过（自身进程）")
            continue
        ok, msg = winapi.terminate_process(p.pid, force=force)
        logs.append(f"{p.name} (PID {p.pid}): {msg}")
        all_ok = all_ok and ok
    time.sleep(0.5)
    ok_probe, msg_probe = _verify_unlock(path)
    logs.append(f"解锁复验: {msg_probe}")
    return ActionResult(ok_probe, "L1 结束占用进程", "\n".join(logs))


def l2_fix_permissions(path: str) -> ActionResult:
    ok, msg = winapi.fix_permissions(path)
    return ActionResult(ok, "L2 权限修复", msg)


def l3_close_handles(path: str, holders: List[FileHolder]) -> ActionResult:
    """关闭文件句柄（跳过自身进程），然后探测解锁结果，不删除文件。"""
    logs = []
    all_ok = True
    for h in holders:
        if h.pid in winapi.self_pid_chain():
            logs.append(f"{h.process_name} PID {h.pid}: 跳过（自身进程）")
            continue
        ok, msg = winapi.close_remote_handle(h.pid, h.handle_value)
        logs.append(f"{h.process_name} PID {h.pid} 句柄 {h.handle_value}: {msg}")
        all_ok = all_ok and ok
    time.sleep(0.3)
    ok_probe, msg_probe = _verify_unlock(path)
    logs.append(f"解锁复验: {msg_probe}")
    return ActionResult(ok_probe, "L3 强制关闭句柄", "\n".join(logs))


def l4_schedule_delete(path: str) -> ActionResult:
    ok, msg = winapi.schedule_delete_on_reboot(path)
    return ActionResult(ok, "L4 重启后删除", msg)


def do_recycle(path: str) -> ActionResult:
    ok, msg = winapi.recycle_path(path)
    return ActionResult(ok, "移入回收站", msg)


def do_delete(path: str) -> ActionResult:
    """兼容旧 op 名：实际执行也改为移入回收站，不再永久删除。"""
    return do_recycle(path)


def do_rename(src: str, dst: str) -> ActionResult:
    ok, msg = winapi.rename_path(src, dst)
    return ActionResult(ok, "重命名", msg)


def deep_scan(path: str) -> List[FileHolder]:
    return winapi.find_file_holders(path)
