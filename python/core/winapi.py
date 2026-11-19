"""Win32 API 封装：提权、Restart Manager、句柄枚举/关闭、权限修复、延迟删除。

只依赖 ctypes + 标准库，便于打包。所有对外函数尽量返回 (ok, info) 或结构化数据，
不把 Win32 错误码直接抛给 UI。
"""
from __future__ import annotations

import ctypes
import msvcrt
import os
import subprocess
import sys
import tempfile
import time
from ctypes import byref, wintypes

import psutil  # 模块顶层导入：避免在 RmStartSession 活动期间动态 import 触发堆损坏
from typing import List, Optional, Tuple

from .models import FileHolder, HeldProcess

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
rstrtmgr = ctypes.WinDLL("RstrtMgr", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

# ---------------------------------------------------------------- 常量
ERROR_SUCCESS = 0
ERROR_MORE_DATA = 234
ERROR_ACCESS_DENIED = 5
ERROR_SHARING_VIOLATION = 32
ERROR_LOCK_VIOLATION = 33
ERROR_FILE_NOT_FOUND = 2

CCH_RM_SESSION_KEY = 32
CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

DELETE_ACCESS = 0x00010000
SYNCHRONIZE = 0x00100000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
FILE_SHARE_DELETE = 0x4
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000

PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
DUPLICATE_SAME_ACCESS = 0x2
DUPLICATE_CLOSE_SOURCE = 0x1

TOKEN_ADJUST_PRIVILEGES = 0x20
TOKEN_QUERY = 0x8
TOKEN_ELEVATION_CLASS = 20  # TokenElevation
SE_PRIVILEGE_ENABLED = 0x2

SystemExtendedHandleInformation = 64
STATUS_SUCCESS = 0
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
ObjectNameInformation = 2

MOVEFILE_DELAY_UNTIL_REBOOT = 0x4

# 回收站（SHFileOperation）
FO_DELETE = 3
FOF_ALLOWUNDO = 0x0040
FOF_NOCONFIRMATION = 0x0010
FOF_NOERRORUI = 0x0400
FOF_SILENT = 0x0004
FOF_WANTNUKEWARNING = 0x4000
DRIVE_FIXED = 3

# ---------------------------------------------------------------- 结构体
class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class RM_UNIQUE_PROCESS(ctypes.Structure):
    # 实测原始内存为紧密 12 字节：DWORD + FILETIME，中间无 padding。
    _fields_ = [
        ("dwProcessId", wintypes.DWORD),
        ("ProcessStartTime", FILETIME),
    ]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
        ("strShortFileName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
        ("ApplicationType", ctypes.c_int),
        ("bRestartable", wintypes.BOOL),
        # 实测：RmGetList 在 x64 上按 668 字节写入本结构（末尾多写 8 字节）。
        # 原定义仅 660 字节，越界写会在解释器退出 GC 时触发 0xc0000374 堆损坏，
        # 表现为“拖入正在运行的 exe 后崩溃”。补 8 字节尾部占位消除越界。
        ("_tail_pad", wintypes.DWORD * 2),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


class OBJECT_NAME_INFORMATION(ctypes.Structure):
    _fields_ = [("Name", UNICODE_STRING)]


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_size_t),
        ("HandleValue", ctypes.c_size_t),
        ("GrantedAccess", wintypes.ULONG),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ("NumberOfHandles", ctypes.c_size_t),
        ("Reserved", ctypes.c_size_t),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
    ]


class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_ubyte * 6)]


class SHFILEOPSTRUCTW(ctypes.Structure):
    """SHFileOperationW 参数结构；x64 下由 ctypes 自动对齐。"""

    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", wintypes.WORD),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]


# ---------------------------------------------------------------- 函数原型
rstrtmgr.RmStartSession.argtypes = [
    ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.LPWSTR
]
rstrtmgr.RmStartSession.restype = wintypes.DWORD
rstrtmgr.RmRegisterResources.argtypes = [
    wintypes.DWORD,
    wintypes.UINT,
    ctypes.POINTER(wintypes.LPCWSTR),
    wintypes.UINT,
    ctypes.POINTER(RM_UNIQUE_PROCESS),
    wintypes.UINT,
    ctypes.POINTER(wintypes.LPCWSTR),
]
rstrtmgr.RmRegisterResources.restype = wintypes.DWORD
rstrtmgr.RmGetList.argtypes = [
    wintypes.DWORD,
    ctypes.POINTER(wintypes.UINT),
    ctypes.POINTER(wintypes.UINT),
    ctypes.POINTER(RM_PROCESS_INFO),
    ctypes.POINTER(wintypes.DWORD),
]
rstrtmgr.RmGetList.restype = wintypes.DWORD
rstrtmgr.RmEndSession.argtypes = [wintypes.DWORD]
rstrtmgr.RmEndSession.restype = wintypes.DWORD

kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.DuplicateHandle.argtypes = [
    wintypes.HANDLE,
    wintypes.HANDLE,
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.HANDLE),
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.DuplicateHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
kernel32.GetFileAttributesW.restype = wintypes.DWORD
kernel32.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
kernel32.SetFileAttributesW.restype = wintypes.BOOL
kernel32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
kernel32.QueryDosDeviceW.restype = wintypes.DWORD
kernel32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
kernel32.MoveFileExW.restype = wintypes.BOOL
kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
kernel32.GetDriveTypeW.restype = wintypes.UINT
shell32.SHFileOperationW.argtypes = [ctypes.POINTER(SHFILEOPSTRUCTW)]
shell32.SHFileOperationW.restype = ctypes.c_int
kernel32.GetCurrentProcess.restype = wintypes.HANDLE

advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.LookupPrivilegeValueW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)
]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE,
    wintypes.BOOL,
    ctypes.POINTER(TOKEN_PRIVILEGES),
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
advapi32.AllocateAndInitializeSid.argtypes = [
    ctypes.POINTER(SID_IDENTIFIER_AUTHORITY),
    wintypes.BYTE,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p),
]
advapi32.AllocateAndInitializeSid.restype = wintypes.BOOL
advapi32.CheckTokenMembership.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.BOOL),
]
advapi32.CheckTokenMembership.restype = wintypes.BOOL
advapi32.FreeSid.argtypes = [ctypes.c_void_p]
advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
advapi32.GetTokenInformation.restype = wintypes.BOOL

ntdll.NtQuerySystemInformation.argtypes = [
    ctypes.c_int, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)
]
ntdll.NtQuerySystemInformation.restype = ctypes.c_long
ntdll.NtQueryObject.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
]
ntdll.NtQueryObject.restype = ctypes.c_long

shell32.ShellExecuteW.argtypes = [
    wintypes.HWND,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    ctypes.c_int,
]
shell32.ShellExecuteW.restype = ctypes.c_void_p

# 拖放相关（提权进程接收来自资源管理器的拖放）
user32 = ctypes.WinDLL("user32", use_last_error=True)
WM_DROPFILES = 0x0233
WM_COPYDATA = 0x004A
WM_COPYGLOBALDATA = 0x0049
MSGFLT_ALLOW = 1

user32.ChangeWindowMessageFilterEx.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.DWORD, ctypes.c_void_p
]
user32.ChangeWindowMessageFilterEx.restype = wintypes.BOOL
user32.ChangeWindowMessageFilter.argtypes = [wintypes.UINT, wintypes.DWORD]
user32.ChangeWindowMessageFilter.restype = wintypes.BOOL
shell32.DragQueryFileW.argtypes = [
    wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT
]
shell32.DragQueryFileW.restype = wintypes.UINT
shell32.DragFinish.argtypes = [wintypes.HANDLE]
# DragAcceptFiles 在 shell32.dll（不是 user32）
shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
shell32.DragAcceptFiles.restype = None


def accept_native_files(hwnd: int) -> bool:
    """把窗口注册为原生文件拖放目标（Qt 在提权下 OLE 拖放失效，需此原生通道）。"""
    try:
        if not hwnd:
            return False
        shell32.DragAcceptFiles(wintypes.HWND(hwnd), True)
        return True
    except Exception:
        return False


def allow_drop_messages(hwnd: int) -> bool:
    """放行拖放消息，使提权进程能接收来自资源管理器的文件拖放。

    UIPI 会拦截低完整性进程（explorer.exe）向高完整性进程（提权后的本程序）
    发送的消息，导致 Qt 的 OLE 拖放失效。显式放行 WM_DROPFILES 等消息，
    配合 UI 层的原生事件过滤器处理 DragQueryFile。
    """
    ok_any = False
    for msg in (WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA):
        try:
            # 优先用带窗口句柄的版本（Vista+，粒度更细）
            if hwnd and user32.ChangeWindowMessageFilterEx(hwnd, msg, MSGFLT_ALLOW, None):
                ok_any = True
        except Exception:
            pass
        try:
            # 再用全局版本兜底（旧系统/Ex 失败时）
            if user32.ChangeWindowMessageFilter(msg, MSGFLT_ALLOW):
                ok_any = True
        except Exception:
            pass
    return ok_any


def drag_query_paths(hdrop: int) -> list[str]:
    """从 WM_DROPFILES 的 HDROP 句柄中取出所有文件路径。"""
    paths = []
    try:
        count = shell32.DragQueryFileW(wintypes.HANDLE(hdrop), 0xFFFFFFFF, None, 0)
        for i in range(count):
            buf = ctypes.create_unicode_buffer(32768)
            shell32.DragQueryFileW(wintypes.HANDLE(hdrop), i, buf, 32768)
            if buf.value:
                paths.append(buf.value)
    except Exception:
        pass
    finally:
        try:
            shell32.DragFinish(wintypes.HANDLE(hdrop))
        except Exception:
            pass
    return paths


# ---------------------------------------------------------------- 自身保护
# 双进程架构下，提权 helper 必须同时保护自己、自己的祖先、GUI 进程，
# 以及两个 exe 的路径（GUI 用 shifu.exe，helper 用 shifu_agent.exe）。
_PROTECTED_PIDS: set[int] = set()
_SELF_PATHS: set[str] = {os.path.realpath(os.path.abspath(sys.executable))}


def set_protected_pids(pids) -> None:
    """追加必须保护的 PID（helper 启动时把 GUI 进程 PID 传进来）。"""
    for p in pids:
        try:
            _PROTECTED_PIDS.add(int(p))
        except (TypeError, ValueError):
            pass


def add_self_path(path: str) -> None:
    """把另一个 exe 路径也视为“自身”（helper 里登记 GUI 的 exe 路径）。"""
    if path:
        _SELF_PATHS.add(os.path.realpath(os.path.abspath(path)))


def self_pid_chain() -> set[int]:
    """当前进程及其祖先 PID —— 绝不能结束/关句柄，否则程序自杀式退出。

    双进程下额外包含 GUI 进程（由 set_protected_pids 注入），
    避免 helper 结束掉正在等待结果的非提权 GUI。
    """
    pids = {os.getpid()} | set(_PROTECTED_PIDS)
    try:
        import psutil

        p = psutil.Process(os.getpid())
        for _ in range(8):  # 向上追溯几代，覆盖 bootloader / consent.exe
            p = p.parent()
            if p is None:
                break
            pids.add(p.pid)
    except Exception:
        pass
    return pids


def is_self_path(path: str) -> bool:
    """路径是否指向程序自身（含指向自身的 .lnk 快捷方式）。

    防止自删/自改导致运行中的程序异常。快捷方式内含 UTF-16LE 的目标路径，
    直接搜字节即可，不依赖 COM（打包环境无 pywin32）。
    helper 里 _SELF_PATHS 同时含 GUI exe 与 helper exe 两条路径。
    """
    try:
        target = os.path.realpath(os.path.abspath(path))
        for me in _SELF_PATHS:
            if target.lower() == me.lower():
                return True
            if target.lower().endswith(".lnk"):
                try:
                    with open(target, "rb") as f:
                        data = f.read().lower()
                    needles = []
                    for candidate in (me, os.path.basename(me)):
                        for enc in ("utf-16le", "mbcs", "ascii"):
                            try:
                                needles.append(candidate.encode(enc).lower())
                            except (UnicodeEncodeError, LookupError):
                                pass
                    if any(n and n in data for n in needles):
                        return True
                except Exception:
                    pass
    except Exception:
        pass
    return False


# ---------------------------------------------------------------- 通用工具
def _token_is_elevated() -> bool:
    """TokenElevation：判断当前令牌是否为提升的完整管理员令牌。"""
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY, byref(token)
    ):
        return False
    try:
        elev = wintypes.DWORD(0)
        ret = wintypes.DWORD(0)
        ok = advapi32.GetTokenInformation(
            token, TOKEN_ELEVATION_CLASS, byref(elev), ctypes.sizeof(elev), byref(ret)
        )
        return bool(ok and elev.value)
    finally:
        kernel32.CloseHandle(token)


def _in_admin_group() -> bool:
    """CheckTokenMembership：判断当前令牌是否属于 BUILTIN\\Administrators。"""
    # BUILTIN\Administrators = S-1-5-32-544
    #   SECURITY_NT_AUTHORITY        = {0,0,0,0,0,5}
    #   SECURITY_BUILTIN_DOMAIN_RID  = 0x20  (子授权 0)
    #   DOMAIN_ALIAS_RID_ADMINS      = 0x220 (子授权 1)
    nt_authority = SID_IDENTIFIER_AUTHORITY((0, 0, 0, 0, 0, 5))
    sid = ctypes.c_void_p()
    ok = advapi32.AllocateAndInitializeSid(
        byref(nt_authority), 2, 0x20, 0x220, 0, 0, 0, 0, 0, 0, byref(sid)
    )
    if not ok:
        return False
    try:
        member = wintypes.BOOL(False)
        result = advapi32.CheckTokenMembership(None, sid, byref(member))
        return bool(result and member.value)
    finally:
        advapi32.FreeSid(sid)


def is_admin() -> bool:
    """管理员判定：TokenElevation 为主，Administrators 组身份兜底（OR）。

    两者任一为真即视为已提权。TokenElevation 最贴合"能否改系统文件"，
    CheckTokenMembership 覆盖 UAC 已关闭等令牌形态，互为补充。
    """
    try:
        if _token_is_elevated():
            return True
    except Exception:
        pass
    try:
        return _in_admin_group()
    except Exception:
        return False


def ensure_admin() -> bool:
    """若非管理员，弹 UAC 重启本程序并返回 False（调用方应立即退出）。"""
    if is_admin():
        return True
    if getattr(sys, "frozen", False):
        exe = sys.executable
        args = subprocess.list2cmdline(sys.argv[1:])
    else:
        exe = sys.executable
        args = subprocess.list2cmdline([os.path.abspath(sys.argv[0])] + sys.argv[1:])
    try:
        shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
    except Exception:
        return False
    return False


def enable_debug_privilege() -> bool:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, byref(token)
    ):
        return False
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        return bool(
            advapi32.AdjustTokenPrivileges(
                token, False, byref(tp), ctypes.sizeof(tp), None, None
            )
        )
    finally:
        kernel32.CloseHandle(token)


def extended_path(path: str) -> str:
    """长路径支持：绝对路径加 \\\\?\\ 前缀。"""
    p = os.path.abspath(path).replace("/", "\\")
    if p.startswith("\\\\?\\"):
        return p
    return "\\\\?\\" + p


def filetime_to_ts(ft: FILETIME) -> float:
    try:
        raw = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
        return raw / 10_000_000.0 - 11644473600.0
    except Exception:
        return 0.0


def decode_output(data: bytes) -> str:
    for enc in ("utf-8", "gb18030", "mbcs"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", "replace")


# SHFileOperation / Win32 常见错误码 → 可读文本。
# System FormatMessage 在部分环境（无系统消息表 / 精简运行时）会返回空，
# 故以本地字典为主，系统翻译兜底。
_ERROR_TEXT = {
    5: "拒绝访问（权限不足）",
    32: "文件正在被其他程序使用（共享冲突）",
    33: "文件被锁定",
    87: "参数无效",
    1223: "操作已取消",
    0x71: "操作被取消或目标正在使用（Shell 错误 0x71）",
    0x4C7: "操作已取消（Shell 错误 0x4C7）",
}


def format_win_error(code: int) -> str:
    """把错误码翻译成可读中文；本地字典优先，系统 FormatMessage 兜底。"""
    if not code:
        return ""
    if code in _ERROR_TEXT:
        return _ERROR_TEXT[code]
    flags = 0x1000 | 0x0200  # FORMAT_MESSAGE_ALLOCATE_BUFFER | FROM_SYSTEM
    buf = ctypes.c_wchar_p()
    try:
        n = kernel32.FormatMessageW(
            flags, None, code, 0, ctypes.byref(buf), 0, None
        )
        if n and buf.value:
            text = buf.value.strip().rstrip("。\r\n")
            kernel32.LocalFree(buf)
            return text
    except Exception:  # noqa: BLE001
        pass
    return f"系统错误 {code}"


def get_process_name(pid: int) -> str:
    try:
        import psutil

        p = psutil.Process(pid)
        return p.name()
    except Exception:
        pass
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return f"PID {pid}"
    try:
        buf = ctypes.create_unicode_buffer(260)
        size = wintypes.DWORD(260)
        ok = kernel32.QueryFullProcessImageNameW(h, 0, buf, byref(size))
        return os.path.basename(buf.value) if ok else f"PID {pid}"
    except Exception:
        return f"PID {pid}"
    finally:
        kernel32.CloseHandle(h)


def get_file_attributes(path: str) -> int:
    attrs = kernel32.GetFileAttributesW(extended_path(path))
    return attrs if attrs != 0xFFFFFFFF else 0


def clear_readonly(path: str) -> Tuple[bool, str]:
    attrs = get_file_attributes(path)
    if not attrs or not (attrs & FILE_ATTRIBUTE_READONLY):
        return True, "无需处理"
    new_attrs = attrs & ~FILE_ATTRIBUTE_READONLY
    if not new_attrs:
        new_attrs = FILE_ATTRIBUTE_NORMAL
    ok = kernel32.SetFileAttributesW(extended_path(path), new_attrs)
    return bool(ok), "已去除只读属性" if ok else f"失败 err={ctypes.get_last_error()}"


# ---------------------------------------------------------------- L1 Restart Manager
def rm_query(paths: List[str]) -> Tuple[int, List[HeldProcess], int]:
    """返回 (错误码, 占用进程列表, rebootReasons)。错误码 0 表示成功。"""
    if not paths:
        return ERROR_SUCCESS, [], 0
    session = wintypes.DWORD()
    key = ctypes.create_unicode_buffer(CCH_RM_SESSION_KEY + 1)
    rc = rstrtmgr.RmStartSession(byref(session), 0, key)
    if rc != ERROR_SUCCESS:
        return rc, [], 0
    try:
        arr = (wintypes.LPCWSTR * len(paths))(*[str(p) for p in paths])
        rc = rstrtmgr.RmRegisterResources(
            session.value, len(paths), arr, 0, None, 0, None
        )
        if rc != ERROR_SUCCESS:
            return rc, [], 0

        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reboot = wintypes.DWORD(0)
        rc = rstrtmgr.RmGetList(
            session.value, byref(needed), byref(count), None, byref(reboot)
        )
        if rc not in (ERROR_SUCCESS, ERROR_MORE_DATA):
            return rc, [], reboot.value

        n = needed.value
        if n == 0:
            return ERROR_SUCCESS, [], reboot.value

        infos = (RM_PROCESS_INFO * n)()
        count = wintypes.UINT(n)
        rc = rstrtmgr.RmGetList(
            session.value, byref(needed), byref(count), infos, byref(reboot)
        )
        if rc != ERROR_SUCCESS:
            return rc, [], reboot.value

        result: List[HeldProcess] = []
        for i in range(count.value):
            info = infos[i]
            pid = info.Process.dwProcessId
            name = info.strAppName or info.strShortFileName or f"PID {pid}"
            start = filetime_to_ts(info.Process.ProcessStartTime)
            try:
                proc = psutil.Process(pid)
                exe = proc.exe()
                name = os.path.basename(exe) or name
                create = proc.create_time()
                # 启动时间不一致说明 PID 已被重用，丢弃
                if start and abs(create - start) > 5:
                    continue
            except Exception:
                exe = ""
            result.append(
                HeldProcess(
                    pid=pid,
                    name=name,
                    app_type=info.ApplicationType,
                    restartable=bool(info.bRestartable),
                    start_time=start,
                    exe=exe,
                )
            )
        return ERROR_SUCCESS, result, reboot.value
    finally:
        rstrtmgr.RmEndSession(session.value)


# ---------------------------------------------------------------- 句柄枚举
def _enum_system_handles() -> List[SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX]:
    length = 1 << 20
    for _ in range(20):
        buf = ctypes.create_string_buffer(length)
        ret = wintypes.ULONG(0)
        status = ntdll.NtQuerySystemInformation(
            SystemExtendedHandleInformation, buf, length, byref(ret)
        )
        if status == STATUS_SUCCESS:
            info = ctypes.cast(buf, ctypes.POINTER(SYSTEM_HANDLE_INFORMATION_EX)).contents
            n = int(info.NumberOfHandles)
            entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
            base = ctypes.addressof(buf) + SYSTEM_HANDLE_INFORMATION_EX.Handles.offset
            out = []
            for i in range(n):
                e = ctypes.cast(
                    base + i * entry_size, ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
                ).contents
                out.append(
                    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(
                        Object=e.Object,
                        UniqueProcessId=e.UniqueProcessId,
                        HandleValue=e.HandleValue,
                        GrantedAccess=e.GrantedAccess,
                        CreatorBackTraceIndex=e.CreatorBackTraceIndex,
                        ObjectTypeIndex=e.ObjectTypeIndex,
                        HandleAttributes=e.HandleAttributes,
                        Reserved=e.Reserved,
                    )
                )
            return out
        if status == STATUS_INFO_LENGTH_MISMATCH:
            length = max(length * 2, int(ret.value) + 0x10000)
            if length > (1 << 28):
                break
            continue
        break
    return []


def _get_file_type_index(handles: List[SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX]) -> Optional[int]:
    fd = None
    try:
        fd, tmp = tempfile.mkstemp(prefix="shifu_probe_")
        hval = msvcrt.get_osfhandle(fd)
        pid = os.getpid()
        for e in handles:
            if e.UniqueProcessId == pid and e.HandleValue == hval:
                return int(e.ObjectTypeIndex)
    except Exception:
        pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
            try:
                os.unlink(tmp)
            except Exception:
                pass
    return None


def _query_object_name(handle: wintypes.HANDLE) -> str:
    size = 0x400
    for _ in range(12):
        buf = ctypes.create_string_buffer(size)
        ret = wintypes.ULONG(0)
        status = ntdll.NtQueryObject(handle, ObjectNameInformation, buf, size, byref(ret))
        if status == STATUS_SUCCESS:
            info = ctypes.cast(buf, ctypes.POINTER(OBJECT_NAME_INFORMATION)).contents
            if info.Name.Buffer and info.Name.Length:
                return ctypes.wstring_at(info.Name.Buffer, info.Name.Length // 2)
            return ""
        if status == STATUS_INFO_LENGTH_MISMATCH:
            size = max(size * 2, int(ret.value) + 0x100)
            if size > (1 << 20):
                break
            continue
        break
    return ""


def _device_to_win32(dev_path: str) -> str:
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        buf = ctypes.create_unicode_buffer(1024)
        if kernel32.QueryDosDeviceW(f"{letter}:", buf, 1024):
            dev = buf.value
            if dev and dev_path.lower().startswith(dev.lower()):
                return f"{letter}:" + dev_path[len(dev) :]
    return dev_path


def find_file_holders(target: str) -> List[FileHolder]:
    """深度扫描：枚举所有进程的文件句柄，找出指向 target 的句柄。"""
    target_norm = os.path.abspath(target).replace("/", "\\").rstrip("\\").lower()
    long_norm = target_norm
    if not long_norm.startswith("\\\\?\\"):
        long_norm = "\\\\?\\" + long_norm

    handles = _enum_system_handles()
    file_type = _get_file_type_index(handles)
    if file_type is None:
        return []

    candidates: List[Tuple[int, int]] = []
    for e in handles:
        if int(e.ObjectTypeIndex) == file_type and e.HandleValue and e.UniqueProcessId:
            candidates.append((int(e.UniqueProcessId), int(e.HandleValue)))

    current = kernel32.GetCurrentProcess()
    own_pids = self_pid_chain()
    found: List[FileHolder] = []
    seen = set()
    for pid, hval in candidates:
        if (pid, hval) in seen:
            continue
        seen.add((pid, hval))
        if pid in own_pids:  # 跳过自身，避免复制/操作自己的句柄引发异常
            continue
        hproc = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        if not hproc:
            continue
        dup = wintypes.HANDLE()
        try:
            ok = kernel32.DuplicateHandle(
                hproc,
                wintypes.HANDLE(hval),
                current,
                byref(dup),
                0,
                False,
                DUPLICATE_SAME_ACCESS,
            )
            if not ok or not dup.value:
                continue
            name = _query_object_name(dup)
            if not name:
                continue
            win32 = _device_to_win32(name)
            w_norm = win32.replace("/", "\\").rstrip("\\").lower()
            if w_norm == target_norm or w_norm == long_norm:
                found.append(
                    FileHolder(
                        pid=pid,
                        handle_value=hval,
                        object_name=name,
                        win32_path=win32,
                        process_name=get_process_name(pid),
                    )
                )
        finally:
            if dup.value:
                kernel32.CloseHandle(dup)
            kernel32.CloseHandle(hproc)
    return found


def close_remote_handle(pid: int, handle_value: int) -> Tuple[bool, str]:
    """在目标进程中关闭指定句柄（DUPLICATE_CLOSE_SOURCE）。"""
    if pid in self_pid_chain():
        return False, f"拒绝关闭自身进程 PID {pid} 的句柄（会导致程序崩溃）"
    hproc = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
    if not hproc:
        return False, f"无法打开进程 PID {pid}（err={ctypes.get_last_error()}）"
    dup = wintypes.HANDLE()
    try:
        ok = kernel32.DuplicateHandle(
            hproc,
            wintypes.HANDLE(handle_value),
            kernel32.GetCurrentProcess(),
            byref(dup),
            0,
            False,
            DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
        )
        err = ctypes.get_last_error()
        if not ok and err == ERROR_ACCESS_DENIED:
            ok = kernel32.DuplicateHandle(
                hproc,
                wintypes.HANDLE(handle_value),
                None,
                None,
                0,
                False,
                DUPLICATE_CLOSE_SOURCE,
            )
            err = ctypes.get_last_error()
        return bool(ok), "已关闭" if ok else f"关闭失败 err={err}"
    finally:
        if dup.value:
            kernel32.CloseHandle(dup)
        kernel32.CloseHandle(hproc)


# ---------------------------------------------------------------- 探测与删除
def probe_delete(path: str) -> Tuple[bool, int]:
    """以 DELETE 权限尝试打开文件，不实际删除。返回 (是否可删, Win32 错误码)。"""
    h = kernel32.CreateFileW(
        extended_path(path),
        DELETE_ACCESS | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if h == INVALID_HANDLE_VALUE or not h:
        return False, ctypes.get_last_error()
    kernel32.CloseHandle(h)
    return True, 0


def terminate_process(pid: int, force: bool = False) -> Tuple[bool, str]:
    if pid in self_pid_chain():
        return False, f"拒绝结束自身进程 PID {pid}（会导致程序崩溃）"
    try:
        import psutil

        p = psutil.Process(pid)
        if force:
            p.kill()
        else:
            p.terminate()
        try:
            p.wait(timeout=3)
        except Exception:
            if not force:
                p.kill()
                p.wait(timeout=3)
        return True, "已结束进程"
    except Exception as exc:
        if force:
            # psutil 失败时退回 taskkill
            r = subprocess.run(
                ["taskkill", "/PID", str(pid), "/F"],
                capture_output=True,
                text=False,
            )
            return r.returncode == 0, decode_output(r.stdout + r.stderr).strip()
        return False, str(exc)


def fix_permissions(path: str) -> Tuple[bool, str]:
    """takeown + icacls 修复所有权与 ACL（管理员权限）。"""
    logs: List[str] = []
    is_dir = os.path.isdir(path)
    cmd_takeown = ["takeown", "/F", path]
    if is_dir:
        cmd_takeown += ["/R", "/D", "Y"]
    try:
        r = subprocess.run(cmd_takeown, capture_output=True)
        logs.append(f"takeown rc={r.returncode}: {decode_output(r.stdout + r.stderr).strip()[:200]}")
    except Exception as exc:
        logs.append(f"takeown 异常: {exc}")

    # S-1-5-32-544 = Administrators（用 SID 避免中英文系统组名差异）
    cmd_icacls = ["icacls", path, "/grant", "*S-1-5-32-544:F"]
    if is_dir:
        cmd_icacls += ["/T"]
    cmd_icacls += ["/C"]
    try:
        r = subprocess.run(cmd_icacls, capture_output=True)
        logs.append(f"icacls rc={r.returncode}: {decode_output(r.stdout + r.stderr).strip()[:200]}")
    except Exception as exc:
        logs.append(f"icacls 异常: {exc}")

    ok_ro, msg_ro = clear_readonly(path)
    logs.append(f"只读属性: {msg_ro}")
    ok_probe, err = probe_delete(path)
    return ok_probe, "\n".join(logs) + (f"\n复验 err={err}" if not ok_probe else "\n复验通过")


def schedule_delete_on_reboot(path: str) -> Tuple[bool, str]:
    """注册重启后删除（写 PendingFileRenameOperations，需管理员）。"""
    p = os.path.abspath(path)
    if len(p) > 260:
        p = extended_path(p)
    ok = kernel32.MoveFileExW(p, None, MOVEFILE_DELAY_UNTIL_REBOOT)
    return bool(ok), "已注册重启后删除，请重启系统" if ok else f"注册失败 err={ctypes.get_last_error()}"


def recycle_path(path: str) -> Tuple[bool, str]:
    """把文件/目录移入回收站（可还原），而非永久删除。

    前置检查：
    - 自身 exe / 指向自身的快捷方式一律拒绝；
    - 仅本地固定磁盘支持回收站（网络盘/可移动盘/U 盘多数直接永久删除），
      其他卷明确拒绝，避免「点删除却永久丢失」。

    SHFileOperationW 的 pFrom 必须以双 NUL 结尾；FOF_ALLOWUNDO 决定入回收站。
    """
    if is_self_path(path):
        return False, "拒绝删除程序自身（shifu.exe），会导致运行中的程序异常"
    p = os.path.abspath(path)
    if not os.path.exists(p):
        return False, "路径不存在，无需删除"

    drive = os.path.splitdrive(p)[0]
    if not drive:
        return False, f"无法判定磁盘类型，拒绝删除以避免永久丢失：{p}"
    dtype = kernel32.GetDriveTypeW(drive + os.sep)
    if dtype != DRIVE_FIXED:
        label = {0: "未知", 1: "无效", 2: "可移动", 4: "网络", 5: "光驱", 6: "内存盘"}.get(
            dtype, str(dtype)
        )
        return False, (
            f"该路径位于{label}磁盘（类型 {dtype}），不保证支持回收站；"
            "为避免永久删除已取消，请在资源管理器中手动删除。"
        )

    # 双 NUL 结尾的宽字符串
    buf = ctypes.create_unicode_buffer(p + "\0")
    op = SHFILEOPSTRUCTW(
        hwnd=None,
        wFunc=FO_DELETE,
        pFrom=ctypes.cast(buf, wintypes.LPCWSTR),
        pTo=None,
        fFlags=FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT,
        fAnyOperationsAborted=False,
        hNameMappings=None,
        lpszProgressTitle=None,
    )
    try:
        rc = shell32.SHFileOperationW(ctypes.byref(op))
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    if rc != 0 or op.fAnyOperationsAborted:
        text = format_win_error(rc) or "未知错误"
        hint = ""
        if (
            rc in (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION, 0x71)
            or "正在" in text or "锁定" in text or "占用" in text
        ):
            hint = "；目录/文件内可能有正在运行的程序锁着它，请先对路径执行「仅解锁」释放占用后重试"
        return False, (
            f"移入回收站失败：{text}（错误码 {rc}，"
            f"已中止={bool(op.fAnyOperationsAborted)}）{hint}"
        )
    return True, "已移入回收站（可从回收站还原）"


def rename_path(src: str, dst: str) -> Tuple[bool, str]:
    if is_self_path(src):
        return False, "拒绝重命名程序自身（shifu.exe），会导致运行中的程序异常"
    try:
        os.rename(extended_path(src), extended_path(dst))
        return True, "重命名成功"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
