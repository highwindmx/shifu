"""释缚提权 helper（无窗口，onedir 打包，requireAdministrator）。

只做一件事：通过命名管道接收非提权 GUI 发来的 JSON 请求，调用 core 层执行
需要管理员权限的操作，把结果以 JSON 回传。自身不带 UI、不接受拖放，
因此完全绕开 UIPI —— 拖放由非提权 GUI 负责。

生命周期：GUI 拉起后常驻；GUI 进程退出则 watchdog 自动退出 helper。
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import __version__, ipc, winapi  # noqa: E402
from core import detector, strategies  # noqa: E402
from core.models import ActionResult, FileHolder, HeldProcess  # noqa: E402
from shell import menu as shell_menu  # noqa: E402


def _parse_args(argv: list[str]):
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--pipe-name", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--gui-pid", type=int, required=True)
    p.add_argument("--gui-exe", default="")
    ns, _ = p.parse_known_args(argv)
    return ns


def _proc_from_dict(d: dict) -> HeldProcess:
    return HeldProcess(
        pid=int(d.get("pid", 0)),
        name=d.get("name", ""),
        app_type=int(d.get("app_type", 0)),
        restartable=bool(d.get("restartable", False)),
        start_time=float(d.get("start_time", 0.0)),
        exe=d.get("exe", ""),
    )


def _holder_from_dict(d: dict) -> FileHolder:
    return FileHolder(
        pid=int(d.get("pid", 0)),
        handle_value=int(d.get("handle_value", 0)),
        object_name=d.get("object_name", ""),
        win32_path=d.get("win32_path", ""),
        process_name=d.get("process_name", ""),
    )


def _result_dict(r: ActionResult) -> dict:
    return {"ok": bool(r.ok), "message": r.message, "detail": r.detail}


def dispatch(op: str, args: dict):
    """按操作名把请求路由到 core 层。返回可 JSON 序列化的数据。"""
    if op == "ping":
        return {"pong": True, "version": __version__}
    if op == "is_admin":
        return {"admin": winapi.is_admin()}
    if op == "diagnose":
        d = detector.diagnose(args["path"])
        # dataclass → dict，供 GUI 重建 Diagnosis
        return {
            "path": d.path, "exists": d.exists, "is_dir": d.is_dir,
            "kind": d.kind, "kind_label": d.kind_label, "detail": d.detail,
            "error_code": d.error_code, "attributes": d.attributes,
            "processes": [vars(p) for p in d.processes],
            "holders": [vars(h) for h in d.holders],
            "suggestions": d.suggestions,
        }
    if op == "l0":
        return _result_dict(strategies.l0_retry_delete(args["path"]))
    if op == "l1":
        procs = [_proc_from_dict(p) for p in args.get("procs", [])]
        return _result_dict(strategies.l1_end_processes(args["path"], procs))
    if op == "l2":
        return _result_dict(strategies.l2_fix_permissions(args["path"]))
    if op == "l3":
        holders = [_holder_from_dict(h) for h in args.get("holders", [])]
        return _result_dict(strategies.l3_close_handles(args["path"], holders))
    if op == "l4":
        return _result_dict(strategies.l4_schedule_delete(args["path"]))
    if op == "deep_scan":
        hs = strategies.deep_scan(args["path"])
        return [vars(h) for h in hs if h.pid not in winapi.self_pid_chain()]
    if op == "delete":
        return _result_dict(strategies.do_delete(args["path"]))
    if op == "recycle":
        return _result_dict(strategies.do_recycle(args["path"]))
    if op == "install_menu":
        ok, msg = shell_menu.install_menu(args.get("gui_exe", ""))
        return {"ok": bool(ok), "message": "安装右键菜单", "detail": msg}
    if op == "uninstall_menu":
        ok, msg = shell_menu.uninstall_menu()
        return {"ok": bool(ok), "message": "卸载右键菜单", "detail": msg}
    if op == "rename":
        return _result_dict(strategies.do_rename(args["src"], args["dst"]))
    raise ValueError(f"未知操作：{op}")


def _watchdog(gui_pid: int, server: ipc.PipeServer, interval: float = 1.0):
    """GUI 退出后 helper 自动结束，避免提权进程残留。"""
    import psutil

    while not server._stop.is_set():
        if not psutil.pid_exists(gui_pid):
            server.stop()
            return
        time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    ns = _parse_args(argv)

    # 提权 helper 必须保护 GUI 进程与 GUI 的 exe 路径
    winapi.set_protected_pids([ns.gui_pid, os.getpid()])
    if ns.gui_exe:
        winapi.add_self_path(ns.gui_exe)
    winapi.enable_debug_privilege()

    try:
        server = ipc.PipeServer(ns.pipe_name, ns.token, dispatch)
    except ipc.AgentError as exc:
        # 管道都建不起来，写事件日志即可（GUI 会收到连接失败提示）
        print(f"[shifu agent] {exc}", file=sys.stderr)
        return 1

    wd = threading.Thread(
        target=_watchdog, args=(ns.gui_pid, server), daemon=True
    )
    wd.start()
    try:
        server.serve()
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
