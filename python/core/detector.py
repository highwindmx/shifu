"""诊断层：判断文件/文件夹为何无法删除或重命名。"""
from __future__ import annotations

import os
from typing import List

from . import winapi
from .models import Diagnosis

_KIND_LABELS = {
    "NOT_FOUND": "路径不存在",
    "NORMAL": "未发现明显锁定",
    "HANDLE_OCCUPIED": "被进程占用（句柄）",
    "PERMISSION": "权限不足",
    "READONLY": "只读属性",
    "CLOUD_PLACEHOLDER": "云同步占位文件",
    "LONG_PATH": "长路径",
    "UNKNOWN": "未知原因",
}


def diagnose(path: str) -> Diagnosis:
    """单路径诊断。"""
    p = os.path.abspath(path)
    d = Diagnosis(path=p)
    exists = os.path.exists(p)
    d.exists = exists
    if not exists:
        d.kind = "NOT_FOUND"
        d.kind_label = _KIND_LABELS["NOT_FOUND"]
        d.detail = "路径不存在或无法访问"
        return d

    d.is_dir = os.path.isdir(p)
    d.attributes = winapi.get_file_attributes(p)
    attrs = d.attributes

    # Restart Manager 识别占用进程（L1）
    rm_code, procs, reboot_reason = winapi.rm_query([p])
    d.processes = procs

    # CreateFile 探测删除权限
    can_delete, err = winapi.probe_delete(p)
    d.error_code = err
    d.detail = f"探测错误码: {err}" if err else "探测可删除"

    # 分类
    if attrs & (
        winapi.FILE_ATTRIBUTE_OFFLINE
        | winapi.FILE_ATTRIBUTE_RECALL_ON_OPEN
        | winapi.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    ):
        d.kind = "CLOUD_PLACEHOLDER"
        d.suggestions.append("先在资源管理器中取消 OneDrive 占位或暂停同步")
    elif procs:
        d.kind = "HANDLE_OCCUPIED"
        d.suggestions.append("L1: 结束占用进程后重试删除")
    elif err in (winapi.ERROR_SHARING_VIOLATION, winapi.ERROR_LOCK_VIOLATION):
        d.kind = "HANDLE_OCCUPIED"
        d.suggestions.append("L3: Restart Manager 未识别，需深度扫描并关闭句柄")
    elif err == winapi.ERROR_ACCESS_DENIED:
        if attrs & winapi.FILE_ATTRIBUTE_READONLY:
            d.kind = "READONLY"
            d.suggestions.append("L2: 去除只读属性 / 修复权限")
        else:
            d.kind = "PERMISSION"
            d.suggestions.append("L2: 取得所有权并赋予管理员完全控制")
    elif len(p) > 260:
        d.kind = "LONG_PATH"
        d.suggestions.append("使用 \\\\?\\ 前缀路径操作")
    elif can_delete:
        d.kind = "NORMAL"
        d.suggestions.append("可直接删除或重命名")
    else:
        d.kind = "UNKNOWN"
        d.suggestions.append("L3: 深度扫描句柄，或 L4: 重启后删除")

    if reboot_reason:
        d.detail += f"；RM 重启原因: {reboot_reason}"
    if rm_code not in (0,):
        d.detail += f"；RM 查询返回: {rm_code}"

    d.kind_label = _KIND_LABELS.get(d.kind, d.kind)
    if err == winapi.ERROR_ACCESS_DENIED and d.kind == "HANDLE_OCCUPIED":
        d.suggestions.append("L2: 同时检查 ACL 权限")
    return d


def diagnose_many(paths: List[str]) -> List[Diagnosis]:
    return [diagnose(p) for p in paths]
