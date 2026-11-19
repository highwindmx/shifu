"""命名管道 IPC：非提权 GUI <-> 提权 helper。

设计要点：
- 管道名与令牌均由 GUI 随机生成，经命令行传给 helper；每条请求都带令牌校验，
  防止本机其他进程冒充客户端。
- 管道 DACL 用 SDDL 限定为 SYSTEM / Administrators / 交互式用户（当前登录用户），
  中等完整性的 GUI 可以连接，其他用户不行。
- helper 用 onedir 打包：规避 onefile + ShellExecute(runas) 的
  "invalid originating onefile parent process" 校验错误。
- 启动 helper 前临时清理本进程的 _PYI_* 环境变量，避免 onedir bootloader
  误判自己是一次性解包子进程。
"""
from __future__ import annotations

import ctypes
import json
import os
import secrets
import sys
import threading
import time
from ctypes import byref, wintypes
from typing import Any, Optional

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
PIPE_ACCESS_DUPLEX = 0x3
PIPE_UNLIMITED_INSTANCES = 255
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_PIPE_CONNECTED = 535
ERROR_BROKEN_PIPE = 109
ERROR_SEM_TIMEOUT = 121
ERROR_FILE_NOT_FOUND = 2
NMPWAIT_WAIT_FOREVER = 0xFFFFFFFF
SW_HIDE = 0

# SDDL：SYSTEM + Builtin Admins + 交互式登录用户；拒绝其他用户
_PIPE_SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)"

kernel32.CreateNamedPipeW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
]
kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
kernel32.ConnectNamedPipe.restype = wintypes.BOOL
kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
kernel32.WaitNamedPipeW.restype = wintypes.BOOL
kernel32.ReadFile.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
kernel32.FlushFileBuffers.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), wintypes.LPVOID
]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
kernel32.LocalFree.argtypes = [wintypes.HANDLE]
kernel32.LocalFree.restype = wintypes.HANDLE


class AgentError(RuntimeError):
    """helper 不可用、令牌校验失败或操作返回失败。"""


def pipe_full_name(pipe_name: str) -> str:
    return "\\\\.\\pipe\\" + pipe_name


def new_credentials() -> tuple[str, str]:
    """生成随机管道名与令牌。"""
    return "shifu_agent_" + secrets.token_hex(12), secrets.token_hex(24)


def agent_script_or_exe() -> str:
    """helper 的可执行文件（打包态）或脚本路径（源码态）。

    打包态 helper 用 onedir，产物在 dist/shifu_agent/shifu_agent.exe；
    兼容旧布局 dist/shifu_agent.exe。
    """
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
        candidates = [
            os.path.join(base, "shifu_agent", "shifu_agent.exe"),
            os.path.join(base, "shifu_agent.exe"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return candidates[0]
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "agent_main.py"))


def launch_agent(pipe_name: str, token: str, gui_pid: int, gui_exe: str) -> None:
    """以 runas 启动提权 helper（唯一一次 UAC 弹窗）。"""
    agent = agent_script_or_exe()
    if getattr(sys, "frozen", False):
        exe, params = agent, f'"{agent}"'
    else:
        exe, params = sys.executable, f'"{agent}"'
    params += (
        f" --pipe-name={pipe_name} --token={token}"
        f" --gui-pid={int(gui_pid)} --gui-exe=\"{gui_exe}\""
    )
    if not os.path.exists(exe):
        raise AgentError(f"找不到提权组件：{exe}")
    if not os.path.exists(agent):
        raise AgentError(f"找不到 helper 脚本：{agent}")

    # ShellExecute 继承当前环境；临时移除 _PYI_* 避免 onedir bootloader 误判
    pyi_keys = [k for k in os.environ if k.startswith("_PYI_")]
    saved = {k: os.environ[k] for k in pyi_keys}
    for k in pyi_keys:
        del os.environ[k]
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, params, None, "open", SW_HIDE
        )
    finally:
        for k, v in saved.items():
            os.environ[k] = v
    if int(rc) <= 32:
        raise AgentError(f"无法启动提权组件（ShellExecute 返回 {rc}）——UAC 可能被拒绝")


def wait_agent(pipe_name: str, timeout: float = 90.0) -> bool:
    """等待 helper 创建管道（覆盖用户点 UAC 的等待时间）。"""
    full = pipe_full_name(pipe_name)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if kernel32.WaitNamedPipeW(full, 500):
            return True
        err = ctypes.get_last_error()
        if err not in (ERROR_SEM_TIMEOUT, ERROR_FILE_NOT_FOUND):
            return False
    return False


def _pipe_sa():
    """返回 (SECURITY_ATTRIBUTES, sd_ptr)；sd_ptr 需 LocalFree。"""
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(sa)
    sa.bInheritHandle = False
    sd = wintypes.LPVOID()
    if advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        _PIPE_SDDL, 1, byref(sd), None
    ):
        sa.lpSecurityDescriptor = sd
        return sa, sd
    return sa, None


def create_server_pipe(pipe_name: str):
    """helper 侧：创建命名管道，返回 (handle, sd_ptr)。"""
    sa, sd = _pipe_sa()
    h = kernel32.CreateNamedPipeW(
        pipe_full_name(pipe_name),
        PIPE_ACCESS_DUPLEX,
        0,  # PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
        PIPE_UNLIMITED_INSTANCES,
        65536, 65536, 0,
        byref(sa) if sa.lpSecurityDescriptor else None,
    )
    if h == INVALID_HANDLE_VALUE or not h:
        raise AgentError(f"创建命名管道失败，Win32 错误 {ctypes.get_last_error()}")
    return h, sd


def _send(handle, obj: dict) -> None:
    data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    written = wintypes.DWORD(0)
    if not kernel32.WriteFile(handle, data, len(data), byref(written), None):
        raise AgentError(f"管道写入失败，Win32 错误 {ctypes.get_last_error()}")


def _recv(handle, max_bytes: int = 8 * 1024 * 1024) -> dict:
    buf = bytearray()
    chunk = ctypes.create_string_buffer(8192)
    read = wintypes.DWORD(0)
    while len(buf) < max_bytes:
        if not kernel32.ReadFile(handle, chunk, len(chunk), byref(read), None):
            err = ctypes.get_last_error()
            raise AgentError(f"管道读取失败，Win32 错误 {err}")
        if read.value == 0:
            break
        buf.extend(chunk.raw[: read.value])
        idx = buf.find(b"\n")
        if idx >= 0:
            return json.loads(bytes(buf[:idx]).decode("utf-8"))
    raise AgentError("管道响应未按预期结束（缺少换行符）")


class PipeServer:
    """helper 侧：单线程循环接收请求，逐条处理。"""

    def __init__(self, pipe_name: str, token: str, dispatcher):
        self.pipe_name = pipe_name
        self.token = token
        self.dispatcher = dispatcher
        self.handle, self.sd = create_server_pipe(pipe_name)
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def serve(self):
        try:
            while not self._stop.is_set():
                if not kernel32.ConnectNamedPipe(self.handle, None):
                    if ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
                        raise AgentError(
                            f"ConnectNamedPipe 失败，Win32 错误 {ctypes.get_last_error()}"
                        )
                try:
                    req = _recv(self.handle)
                    if req.get("token") != self.token:
                        resp = {"ok": False, "error": "令牌校验失败"}
                    else:
                        try:
                            data = self.dispatcher(req.get("op"), req.get("args") or {})
                            resp = {"ok": True, "data": data}
                        except Exception as exc:  # noqa: BLE001
                            resp = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                    _send(self.handle, resp)
                    kernel32.FlushFileBuffers(self.handle)
                except AgentError:
                    pass
                finally:
                    kernel32.DisconnectNamedPipe(self.handle)
        finally:
            kernel32.CloseHandle(self.handle)
            if self.sd:
                kernel32.LocalFree(self.sd)


class AgentClient:
    """GUI 侧：线程安全地发送一条请求并读取响应。"""

    def __init__(self, pipe_name: str, token: str):
        self.full = pipe_full_name(pipe_name)
        self.token = token
        self._lock = threading.Lock()

    def call(self, op: str, **args) -> Any:
        with self._lock:
            h = kernel32.CreateFileW(
                self.full, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None
            )
            if h == INVALID_HANDLE_VALUE or not h:
                raise AgentError(
                    f"无法连接提权组件，Win32 错误 {ctypes.get_last_error()}"
                )
            try:
                _send(h, {"token": self.token, "op": op, "args": args})
                resp = _recv(h)
            finally:
                kernel32.CloseHandle(h)
        if not resp.get("ok"):
            raise AgentError(resp.get("error") or "helper 返回失败")
        return resp.get("data")
