r"""右键菜单注册与卸载（SubCommands 级联，位于第二层经典菜单）。

Win11 经典菜单（「显示更多选项」/ Shift+右键）支持微软官方 SubCommands
级联结构：

  HKCU\Software\Classes\*\shell\ShifuUnlock
      MUIVerb     = 释缚 · 解锁被占用文件
      SubCommands = ShifuUnlock.Unlock;ShifuUnlock.Rename;ShifuUnlock.Delete

子 verb 的实现放 CommandStore。微软文档示例在 HKLM（写 HKLM 需提权），
GUI 非提权，因此本模块的 install/uninstall 设计为**在提权 helper 中调用**。

手写注册表 verb（无论平级还是级联）按设计只出现在第二层经典菜单，
不会进入 Win11 第一层新式菜单——那需要 IExplorerCommand + 包身份。
"""
from __future__ import annotations

import os
import sys
import winreg

APP_NAME = "ShifuUnlock"
MENU_TEXT = "释缚 · 解锁被占用文件"

# (verb 名, 显示文本, mode)
MENU_ENTRIES = [
    ("ShifuUnlock.Unlock", "仅解锁", "unlock"),
    ("ShifuUnlock.Rename", "解锁并重命名", "rename"),
    ("ShifuUnlock.Delete", "解锁并删除（回收站）", "delete"),
]
SUBCOMMANDS = ";".join(verb for verb, _text, _mode in MENU_ENTRIES)

_SUBKEY_BASES = [
    r"Software\Classes\*\shell",           # 所有文件
    r"Software\Classes\Directory\shell",   # 文件夹
]

_COMMAND_STORE = r"Software\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell"

def _exe_path(gui_exe: str = "") -> str:
    """右键菜单要启动的 GUI 程序。

    提权 helper 里 sys.executable 是 shifu_agent.exe，sys.argv[0] 是 agent_main.py，
    都不能作为菜单目标——必须显式传入 GUI exe 路径。
    """
    target = gui_exe or sys.executable
    return f'"{target}"'


def _icon_value(gui_exe: str = "") -> str:
    target = gui_exe or sys.executable
    if getattr(sys, "frozen", False):
        return target
    ico = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "assets", "shifu.ico")
    )
    return ico if os.path.exists(ico) else sys.executable


def install_menu(gui_exe: str = "") -> tuple[bool, str]:
    """安装级联右键菜单。CommandStore 写 HKLM，需在提权进程中调用。"""
    exe = _exe_path(gui_exe)
    icon = _icon_value(gui_exe)
    try:
        uninstall_menu()  # 清旧版平级三项与旧级联结构

        # ① 父菜单：HKCU（MUIVerb + SubCommands），无需提权
        for base in _SUBKEY_BASES:
            parent = f"{base}\\{APP_NAME}"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, parent) as key:
                # SubCommands 级联的父键默认值必须留空，
                # 否则 Shell 用默认值而非 MUIVerb 作菜单文字。
                try:
                    winreg.DeleteValue(key, "")
                except FileNotFoundError:
                    pass
                winreg.SetValueEx(key, "MUIVerb", 0, winreg.REG_SZ, MENU_TEXT)
                winreg.SetValueEx(key, "SubCommands", 0, winreg.REG_SZ, SUBCOMMANDS)
                winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, icon)

        # ② 子 verb 实现：HKLM CommandStore（需提权）
        for verb, text, mode in MENU_ENTRIES:
            sub = f"{_COMMAND_STORE}\\{verb}"
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, sub) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, text)
                winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, icon)
                with winreg.CreateKey(key, "command") as cmd:
                    winreg.SetValueEx(
                        cmd, "", 0, winreg.REG_SZ, f'{exe} --mode={mode} "%1"'
                    )

        return True, (
            "级联右键菜单已安装：「释缚 · 解锁被占用文件」子菜单含三项。"
            "位于「显示更多选项」的经典菜单。"
        )
    except OSError as exc:
        return False, f"安装失败（CommandStore 需管理员权限）: {exc}"


def uninstall_menu() -> tuple[bool, str]:
    """卸载级联菜单。尝试清 HKLM，非提权时跳过该项并返回提示。"""
    notes = []
    for base in _SUBKEY_BASES:
        _delete_tree(winreg.HKEY_CURRENT_USER, f"{base}\\{APP_NAME}")
        # 旧版平级三项（ShifuUnlock.Unlock / .Rename / .Delete）
        for verb, _text, _mode in MENU_ENTRIES:
            suffix = verb.rsplit(".", 1)[-1]
            _delete_tree(winreg.HKEY_CURRENT_USER, f"{base}\\{APP_NAME}.{suffix}")

    # 旧版本安装时自动写入的经典菜单开关键，卸载时一并清除
    _delete_tree(
        winreg.HKEY_CURRENT_USER,
        r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
        r"\InprocServer32",
    )

    hklm_error = ""
    for verb, _text, _mode in MENU_ENTRIES:
        try:
            _delete_tree(winreg.HKEY_LOCAL_MACHINE, f"{_COMMAND_STORE}\\{verb}")
        except OSError as exc:
            hklm_error = str(exc)
    if hklm_error:
        notes.append(f"HKLM CommandStore 未清理（需提权）: {hklm_error}")
    if notes:
        return False, "；".join(notes)
    return True, "右键菜单已卸载（父菜单 + CommandStore 子项均清除）"


def _delete_tree(root, path: str) -> None:
    try:
        with winreg.OpenKey(root, path) as key:
            subkeys = []
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
        for sub in subkeys:
            _delete_tree(root, f"{path}\\{sub}")
        winreg.DeleteKey(root, path)
    except FileNotFoundError:
        pass
