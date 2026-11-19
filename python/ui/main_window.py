"""主界面（精简版）：路径 → 占用项 → 三种解锁操作 → 日志。

架构（双进程）：
- 本窗口始终非提权，使用 Qt 标准 OLE 拖放（中等完整性，收得到 explorer 的拖入）。
- 需要管理员权限的操作按需拉起提权 helper，通过命名管道 RPC 调用；
  UAC 只在第一次点执行操作时弹一次，helper 常驻到本窗口退出。
- 多文件按队列逐个处理：解锁 → 最终操作（解锁/重命名/删除）→ 下一个。
- 任何流程都跳过指向自身 exe / helper exe / 指向自身的快捷方式。
"""
from __future__ import annotations

import os
import sys
from typing import Callable, List, Optional

from PyQt6.QtCore import (
    QObject,
    QRunnable,
    QThreadPool,
    Qt,
    pyqtSignal,
)
from PyQt6.QtGui import QAction, QFont, QIcon, QMouseEvent, QDragEnterEvent, QDropEvent
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import __version__, detector, ipc, winapi
from core.models import ActionResult, Diagnosis, FileHolder
from shell import menu as shell_menu


# ---------------------------------------------------------------- 后台任务
class _WorkerSignals(QObject):
    result = pyqtSignal(object)
    error = pyqtSignal(str)


class _Worker(QRunnable):
    def __init__(self, fn: Callable, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = _WorkerSignals()

    def run(self):
        try:
            self.signals.result.emit(self.fn(*self.args, **self.kwargs))
        except Exception as exc:  # noqa: BLE001
            self.signals.error.emit(f"{type(exc).__name__}: {exc}")


class PathList(QListWidget):
    """路径列表：标准 Qt OLE 拖放（本窗口非提权，拖放通道天然可用）。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DropOnly)
        self.setToolTip("从资源管理器拖入路径，或点「添加路径」")

    def dragEnterEvent(self, event: QDragEnterEvent):  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event: QDropEvent):  # noqa: N802
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        paths = [p for p in paths if p]
        if paths:
            event.acceptProposedAction()
            self._on_paths_dropped(paths)
        else:
            super().dropEvent(event)

    def _on_paths_dropped(self, paths: List[str]):
        parent = self.window()
        cb = getattr(parent, "on_paths_dropped", None)
        if cb:
            cb(paths)

    def paths(self) -> List[str]:
        return [self.item(i).text() for i in range(self.count())]


MODE_LABELS = {
    "unlock": "仅解锁",
    "rename": "解锁并重命名",
    "delete": "解锁并删除（回收站）",
}

# 三个操作按钮固定配色：绿 / 黄 / 红（选中态只加粗边框，不再换色）
MODE_STYLES = {
    "unlock": ("background: #2E9E5B;", "color: white;", "border: 2px solid #1B6E3C;"),
    "rename": ("background: #E0A80A;", "color: #3A2A00;", "border: 2px solid #A87A00;"),
    "delete": ("background: #D64545;", "color: white;", "border: 2px solid #9E2B2B;"),
}


def _mode_button_style(key: str, selected: bool) -> str:
    bg, fg, border = MODE_STYLES[key]
    weight = "font-weight: bold;" if selected else ""
    edge = border if selected else "border: 2px solid transparent;"
    return (
        f"QPushButton {{ {bg} {fg} {edge} {weight} border-radius: 5px; padding: 6px; }}"
        "QPushButton:hover { opacity: 0.9; }"
    )


class MainWindow(QMainWindow):
    def __init__(self, initial_paths: Optional[List[str]] = None, mode: str = "delete"):
        super().__init__()
        self.mode = mode if mode in MODE_LABELS else "delete"
        self.setWindowTitle(f"释缚 · 解锁被占用文件  v{__version__}")
        self.resize(820, 660)
        self.setMinimumSize(700, 540)
        self.diagnoses: List[Diagnosis] = []
        self.holders: List[FileHolder] = []
        self.proc_checks = []
        self.holder_checks = []
        self.mode_buttons = {}
        self.pool = QThreadPool.globalInstance()

        # 提权 helper 客户端（懒启动：第一次点执行操作时才拉起）
        self._agent: Optional[ipc.AgentClient] = None
        self._agent_starting = False

        # 批处理状态
        self._queue: List[str] = []
        self._batch_mode = "delete"
        self._batch_total = 0
        self._batch_confirmed = False   # 危险操作本批次只确认一次
        self._rename_template = ""
        self._skip_self: List[str] = []

        self._build_ui()
        for p in initial_paths or []:
            if p and p not in self.path_list.paths():
                self.path_list.addItem(p)
        if self.path_list.count():
            self.run_diagnose()

    # ------------------------------------------------------------ 拖放注入
    def on_paths_dropped(self, paths: List[str]):
        added = 0
        for path in paths:
            if path and path not in self.path_list.paths():
                self.path_list.addItem(path)
                self.log_append(f"拖入：{path}")
                added += 1
        if added:
            self.run_diagnose()

    # ------------------------------------------------------------ UI 构建
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(8)

        # ① 路径
        root.addWidget(QLabel("<b>① 目标路径</b>（可多选，拖入或添加，自动诊断）"))
        path_row = QHBoxLayout()
        self.path_list = PathList()
        path_row.addWidget(self.path_list, 1)
        btn_col = QVBoxLayout()
        b_add = QPushButton("添加路径")
        b_add.clicked.connect(self.add_path)
        b_clear = QPushButton("清空")
        b_clear.clicked.connect(self.clear_paths)
        for b in (b_add, b_clear):
            btn_col.addWidget(b)
        btn_col.addStretch(1)
        path_row.addLayout(btn_col)
        root.addLayout(path_row, 2)

        # ② 占用项
        root.addWidget(QLabel("<b>② 占用项</b>（勾选后执行，L1 结束进程 / L3 关句柄）"))
        self.holder_area = QListWidget()
        self.holder_area.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        root.addWidget(self.holder_area, 2)

        # ③ 三种解锁操作
        root.addWidget(QLabel("<b>③ 解锁操作</b>（自动按诊断选择解锁手段，多文件逐个处理）"))
        ops = QHBoxLayout()
        for key in ("unlock", "rename", "delete"):
            b = QPushButton(MODE_LABELS[key])
            b.setMinimumHeight(40)
            b.setToolTip({
                "unlock": "解除占用，不删除，之后手动处理（绿色）",
                "rename": "解锁后重命名，多文件用模板+序号（黄色）",
                "delete": "解锁后移入回收站，可从回收站还原（红色）",
            }[key])
            b.clicked.connect(lambda _, k=key: self.exec_mode(k))
            self.mode_buttons[key] = b
            ops.addWidget(b)
        root.addLayout(ops)
        self._highlight_mode_button()

        # ④ 日志
        root.addWidget(QLabel("<b>④ 日志</b>"))
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont("Consolas", 9))
        root.addWidget(self.log, 3)

        menubar = self.menuBar()
        m = menubar.addMenu("设置")
        for text, slot in (
            ("安装右键菜单", self.install_menu),
            ("卸载右键菜单", self.uninstall_menu),
            ("权限状态", self.show_admin_status),
        ):
            a = QAction(text, self)
            a.triggered.connect(slot)
            m.addAction(a)
        a_about = QAction("关于", self)
        a_about.triggered.connect(
            lambda: QMessageBox.about(
                self, "关于释缚",
                f"释缚 v{__version__}\n解锁被占用文件，支持仅解锁 / 重命名 / 删除到回收站。\n\n"
                "界面非提权运行（保证拖放可用），解锁时按需拉起提权组件。\n"
                "⚠ 强制关闭句柄或结束进程可能导致目标程序异常，请确认后再执行。"
            )
        )
        m.addAction(a_about)

        self.setStyleSheet(
            """
            QWidget { font-family: 'Microsoft YaHei'; font-size: 10pt; }
            QPushButton { padding: 4px 8px; }
            QListWidget { alternate-background-color: #f7f7f7; }
            """
        )
        self.log_append(
            f"释缚 v{__version__} 启动（界面非提权，拖放通道：Qt 原生）。"
            "首次执行解锁操作时将弹一次 UAC。"
        )

    def _highlight_mode_button(self):
        for key, b in self.mode_buttons.items():
            b.setStyleSheet(_mode_button_style(key, key == self.mode))

    # ------------------------------------------------------------ 日志
    def log_append(self, text: str):
        self.log.append(text)
        self.log.ensureCursorVisible()

    @staticmethod
    def _fmt_result(r: ActionResult) -> str:
        mark = "✅" if r.ok else "❌"
        return f"{mark} 【{r.message}】{r.detail}"

    # ------------------------------------------------------------ 提权组件
    def _ensure_agent(self, on_ready: Callable[[], None]):
        """首次执行时拉起提权 helper；已就绪则立即回调。"""
        if self._agent is not None:
            on_ready()
            return
        if self._agent_starting:
            self.log_append("提权组件正在启动中，请稍候…")
            return
        self._agent_starting = True
        self.log_append("需要管理员权限，正在启动提权组件…请在 UAC 弹窗中点「是」")
        self._run_async(self._start_agent, lambda res: self._on_agent_ready(res, on_ready))

    def _start_agent(self) -> dict:
        try:
            name, token = ipc.new_credentials()
            ipc.launch_agent(name, token, os.getpid(), sys.executable)
            if not ipc.wait_agent(name, timeout=120.0):
                return {"ok": False, "error": "等待提权组件超时（可能未在 UAC 弹窗确认）"}
            client = ipc.AgentClient(name, token)
            ping = client.call("ping")
            return {"ok": True, "client": client, "ping": ping}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def _on_agent_ready(self, res: dict, on_ready: Callable[[], None]):
        self._agent_starting = False
        if not res.get("ok"):
            self.log_append(f"❌ 提权组件启动失败：{res.get('error')}")
            QMessageBox.warning(
                self, "无法提权",
                f"提权组件启动失败：{res.get('error')}\n\n"
                "L2/L3/L4 解锁与删除需要管理员权限，请检查 UAC 设置后重试。",
            )
            return
        self._agent = res["client"]
        ping = res.get("ping") or {}
        self.log_append(
            f"✅ 提权组件就绪（v{ping.get('version', '?')}，管理员权限已生效）"
        )
        on_ready()

    def _rpc_result(self, op: str, **args) -> ActionResult:
        """调用 helper 并把 JSON 结果还原成 ActionResult。"""
        d = self._agent.call(op, **args)
        return ActionResult(
            bool(d.get("ok")), d.get("message", ""), d.get("detail", "")
        )

    def _rpc_deep_scan(self, path: str) -> List[FileHolder]:
        data = self._agent.call("deep_scan", path=path)
        out = []
        for h in data:
            out.append(FileHolder(
                pid=int(h.get("pid", 0)),
                handle_value=int(h.get("handle_value", 0)),
                object_name=h.get("object_name", ""),
                win32_path=h.get("win32_path", ""),
                process_name=h.get("process_name", ""),
            ))
        return out

    # ------------------------------------------------------------ 路径
    def add_path(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "选择文件（可多选，也可直接拖入）")
        added = 0
        for path in paths:
            if path and path not in self.path_list.paths():
                self.path_list.addItem(path)
                added += 1
        if added:
            self.log_append(f"已添加 {added} 个路径")
            self.run_diagnose()

    def clear_paths(self):
        self.path_list.clear()
        self.diagnoses = []
        self.holders = []
        self.proc_checks = []
        self.holder_checks = []
        self._queue = []
        self.holder_area.clear()
        self.log_append("已清空路径列表。")

    def selected_paths(self) -> List[str]:
        rows = self.path_list.selectedItems()
        return [i.text() for i in rows] if rows else self.path_list.paths()

    # ------------------------------------------------------------ 诊断
    def run_diagnose(self):
        paths = self.path_list.paths()
        if not paths:
            return
        self.log_append(f"开始诊断 {len(paths)} 个路径…")
        self._run_async(lambda: detector.diagnose_many(paths), self._on_diagnose_done)

    def _on_diagnose_done(self, results: List[Diagnosis]):
        self.diagnoses = results
        for d in results:
            self.log_append(d.summary())
        self.log_append("诊断完成。")
        self._refresh_holders()

    def _diag_for(self, path: str) -> Optional[Diagnosis]:
        return next((d for d in self.diagnoses if d.path == path), None)

    def _refresh_holders(self):
        self.holder_area.clear()
        self.proc_checks = []
        self.holder_checks = []
        protected = winapi.self_pid_chain()
        seen = set()
        for d in self.diagnoses:
            for p in d.processes:
                if p.pid in seen or p.pid in protected:
                    continue
                seen.add(p.pid)
                cb = QCheckBox(f"[进程] {p.name}  PID {p.pid}  {p.type_label}")
                cb.setChecked(True)
                item = QListWidgetItem()
                self.holder_area.addItem(item)
                self.holder_area.setItemWidget(item, cb)
                self.proc_checks.append((cb, p))
            for h in self.holders:
                if h.pid in protected:
                    continue
                cb = QCheckBox(
                    f"[句柄] {h.process_name}  PID {h.pid}  句柄 {h.handle_value}  {h.win32_path}"
                )
                cb.setChecked(True)
                item = QListWidgetItem()
                self.holder_area.addItem(item)
                self.holder_area.setItemWidget(item, cb)
                self.holder_checks.append((cb, h))
        if not self.proc_checks and not self.holder_checks:
            self.holder_area.addItem("（未发现占用项）")

    # ------------------------------------------------------------ 批量执行
    def exec_mode(self, mode: str):
        """校验 → 建立队列 → 确保提权 → 逐个处理。"""
        raw = self.selected_paths()
        if not raw:
            QMessageBox.information(self, "提示", "请先添加或选择路径")
            return

        # 自身 exe / 指向自身的快捷方式：一律跳过，防自杀/自删
        self._skip_self = [p for p in raw if winapi.is_self_path(p)]
        paths = [p for p in raw if not winapi.is_self_path(p)]
        if self._skip_self:
            self.log_append(f"⏭ 跳过 {len(self._skip_self)} 个自身/自身快捷方式路径（防止自锁）")
        if not paths:
            QMessageBox.information(self, "无可处理路径", "所选路径均为程序自身，已全部跳过。")
            return

        # 批量重命名：一次性输入模板，{n} 为序号；不允许不同文件同名
        self._rename_template = ""
        if mode == "rename" and len(paths) > 1:
            template, ok = QInputDialog.getText(
                self, "批量重命名模板",
                f"共 {len(paths)} 个文件。输入新名称，用 {{n}} 代表序号（从 1 开始）：",
                text="new_{n}",
            )
            if not ok or not template.strip():
                return
            if "{n}" not in template:
                template = template + "_{n}"
            self._rename_template = template
            self.log_append(f"批量重命名模板：{template}")

        # 批量删除：一次性确认，列出全部文件
        if mode == "delete" and len(paths) > 1:
            listing = "\n".join(f"  • {p}" for p in paths[:12])
            if len(paths) > 12:
                listing += f"\n  … 另有 {len(paths) - 12} 个"
            if QMessageBox.question(
                self, "确认批量移入回收站",
                f"即将把 {len(paths)} 个文件移入回收站：\n{listing}\n\n"
                "移入后可从回收站还原；部分磁盘（网络盘/U 盘）不支持，将跳过。继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            ) != QMessageBox.StandardButton.Yes:
                return

        self._queue = list(paths)
        self._batch_mode = mode
        self._batch_total = len(paths)
        self._batch_confirmed = False
        self.log_append(f"===== {MODE_LABELS[mode]}：共 {self._batch_total} 个路径 =====")
        self._ensure_agent(lambda: self._process_next())

    def _process_next(self):
        if not self._queue:
            self.log_append("✅ 批量处理完成，正在重新诊断…")
            self._run_async(
                lambda: detector.diagnose_many(self.path_list.paths()), self._on_diagnose_done
            )
            return
        path = self._queue[0]
        done = self._batch_total - len(self._queue) + 1
        self.log_append(f"—— 进度 [{done}/{self._batch_total}] {path} ——")
        diag = self._diag_for(path)
        if diag is None:
            self._run_async(
                lambda: detector.diagnose(path),
                lambda d: self._exec_unlock(d, path),
            )
        else:
            self._exec_unlock(diag, path)

    def _exec_unlock(self, diag: Diagnosis, path: str):
        if diag.kind == "NOT_FOUND":
            self.log_append("路径不存在，跳过。")
            self._advance()
            return

        mode = self._batch_mode
        if diag.kind in ("PERMISSION", "READONLY"):
            self.log_append("诊断=权限问题，采用 L2 权限修复")
            self._run_async(
                lambda: self._rpc_result("l2", path=path),
                lambda r: self._on_unlock_done(r, path),
            )
        elif diag.kind == "HANDLE_OCCUPIED" and diag.processes:
            procs = [p for cb, p in self.proc_checks if cb.isChecked()] or diag.processes[:]
            procs = [p for p in procs if p.pid not in winapi.self_pid_chain()]
            if not procs:
                self.log_append("占用进程均为自身，跳过 L1，尝试深度扫描")
                self._deep_scan_then_unlock(path)
                return
            if not self._batch_confirmed:
                names = "、".join(f"{p.name}(PID {p.pid})" for p in procs)
                if QMessageBox.question(
                    self, "确认结束占用进程",
                    f"检测到占用进程：{names}\n\n结束这些进程后继续？（未保存数据可能丢失）\n"
                    "（选择「是」后本批次不再重复询问）",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                ) != QMessageBox.StandardButton.Yes:
                    self._advance()
                    return
                self._batch_confirmed = True
            self.log_append("诊断=进程占用，采用 L1 结束占用进程")
            proc_dicts = [vars(p) for p in procs]
            self._run_async(
                lambda: self._rpc_result("l1", path=path, procs=proc_dicts),
                lambda r: self._on_unlock_done(r, path),
            )
        elif diag.kind in ("HANDLE_OCCUPIED", "UNKNOWN", "LONG_PATH", "CLOUD_PLACEHOLDER"):
            self._deep_scan_then_unlock(path)
        else:
            self.log_append("未发现明显锁定，直接进入最终操作")
            self._finish_by_mode(path)

    def _deep_scan_then_unlock(self, path: str):
        self.log_append("RM 未识别占用者，先做 L3 深度扫描…")
        self._run_async(
            lambda: self._rpc_deep_scan(path),
            lambda hs: self._on_scan_then_unlock(hs, path),
        )

    def _on_scan_then_unlock(self, holders: List[FileHolder], path: str):
        self.holders = holders
        self._refresh_holders()
        protected = winapi.self_pid_chain()
        holders = [h for h in holders if h.pid not in protected]
        if not holders:
            self.log_append("深度扫描未发现外部文件句柄，尝试 L0 重试删除")
            self._run_async(
                lambda: self._rpc_result("l0", path=path),
                lambda r: self._on_unlock_done(r, path),
            )
            return
        checked = [h for cb, h in self.holder_checks if cb.isChecked()] or holders
        if not self._batch_confirmed:
            if QMessageBox.warning(
                self, "风险确认",
                f"发现 {len(checked)} 个外部文件句柄，强制关闭可能导致相关进程崩溃或数据丢失。\n\n"
                "继续？（选择「是」后本批次不再重复询问）",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            ) != QMessageBox.StandardButton.Yes:
                self._advance()
                return
            self._batch_confirmed = True
        self.log_append("采用 L3 关闭文件句柄")
        holder_dicts = [vars(h) for h in checked]
        self._run_async(
            lambda: self._rpc_result("l3", path=path, holders=holder_dicts),
            lambda r: self._on_unlock_done(r, path),
        )

    def _on_unlock_done(self, result: ActionResult, path: str):
        self.log_append(self._fmt_result(result))
        if not result.ok:
            self.log_append("⚠ 解锁未完全成功，仍尝试最终操作（可能被系统拒绝）；继续下一个。")
        self._finish_by_mode(path)

    def _finish_by_mode(self, path: str):
        mode = self._batch_mode
        if mode == "unlock":
            self.log_append(f"✅ 已解锁：{path}")
            self._advance()
            return
        if mode == "rename":
            if self._rename_template:
                idx = self._batch_total - len(self._queue) + 1
                name = self._rename_template.replace("{n}", str(idx))
                dst = os.path.join(os.path.dirname(path), name)
                if os.path.exists(dst):
                    self.log_append(f"❌ 目标已存在，跳过：{dst}")
                    self._advance()
                    return
                self.log_append(f"重命名：{path} → {dst}")
                self._run_async(
                    lambda: self._rpc_result("rename", src=path, dst=dst), self._on_final_done
                )
                return
            old = os.path.basename(path.rstrip("\\/"))
            new, ok = QInputDialog.getText(self, "解锁并重命名", "新名称：", text=old)
            if not ok or not new:
                self._advance()
                return
            dst = os.path.join(os.path.dirname(path), new)
            self._run_async(
                lambda: self._rpc_result("rename", src=path, dst=dst), self._on_final_done
            )
            return

        # delete：单文件再确认一次（多文件已在批次开始统一确认）
        if self._batch_total == 1:
            if QMessageBox.question(
                self, "确认移入回收站",
                f"解锁完成，确定把下面文件移入回收站（可还原）：\n{path}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            ) != QMessageBox.StandardButton.Yes:
                self._advance()
                return
        self._run_async(lambda: self._recycle(path), self._on_final_done)

    def _recycle(self, path: str) -> ActionResult:
        """非提权 GUI 直接移入回收站（与资源管理器同一完整性，最可靠）；
        失败时才回退到提权 helper（例如目标目录 ACL 只有管理员可写）。"""
        ok, msg = winapi.recycle_path(path)
        if ok:
            return ActionResult(True, "移入回收站", msg)
        if self._agent is not None:
            try:
                d = self._agent.call("recycle", path=path)
                r = ActionResult(
                    bool(d.get("ok")), d.get("message", ""), d.get("detail", "")
                )
                if r.ok:
                    return r
                return ActionResult(False, "移入回收站", f"{msg}；提权重试：{r.detail}")
            except Exception as exc:  # noqa: BLE001
                return ActionResult(False, "移入回收站", f"{msg}；提权重试失败：{exc}")
        return ActionResult(False, "移入回收站", msg)

    def _on_final_done(self, result: ActionResult):
        self.log_append(self._fmt_result(result))
        if not result.ok:
            # 最终操作失败必须让用户看见，不能只在日志里静默滚动
            QMessageBox.warning(
                self, "操作失败",
                f"{result.message}：{result.detail}\n\n"
                "处理建议：\n"
                "• 若提示占用/共享冲突：先对该路径执行「仅解锁」，再重试删除\n"
                "• 若权限不足：右键「以管理员身份运行」后重试\n"
                "• 网络盘 / U 盘不支持回收站，请直接手动删除",
            )
        self._advance()

    def _advance(self):
        if self._queue:
            self._queue.pop(0)
        self._process_next()

    # ------------------------------------------------------------ 异步封装
    def _run_async(self, fn: Callable, on_done: Callable, on_error: Optional[Callable] = None):
        worker = _Worker(fn)
        worker.signals.result.connect(on_done)
        worker.signals.error.connect(
            on_error or (lambda msg: self.log_append(
                f"❌ 异常：{msg}（若与提权组件通信失败，请重启程序）"
            ))
        )
        self.pool.start(worker)

    # ------------------------------------------------------------ 菜单动作
    def install_menu(self):
        """级联菜单的 CommandStore 在 HKLM，需提权 helper 写入。"""
        self._ensure_agent(lambda: self._do_menu_op("install"))

    def uninstall_menu(self):
        self._ensure_agent(lambda: self._do_menu_op("uninstall"))

    def _do_menu_op(self, which: str):
        try:
            if which == "install":
                d = self._agent.call("install_menu", gui_exe=sys.executable)
            else:
                d = self._agent.call("uninstall_menu")
            ok, msg = bool(d.get("ok")), d.get("detail", "")
            self.log_append(f"{'✅' if ok else '❌'} {msg}")
            QMessageBox.information(self, "右键菜单", msg)
        except Exception as exc:  # noqa: BLE001
            self.log_append(f"❌ 右键菜单操作失败：{exc}")
            QMessageBox.warning(self, "右键菜单", f"操作失败：{exc}")

    def show_admin_status(self):
        ready = "已就绪" if self._agent is not None else "未启动（首次执行解锁时拉起）"
        QMessageBox.information(
            self, "权限状态",
            f"界面进程：非提权（拖放通道正常）\n"
            f"提权组件：{ready}\n\n"
            "首次点解锁/重命名/删除时会弹一次 UAC，之后不再重复，"
            "组件随本窗口退出而结束。",
        )

    def closeEvent(self, event):  # noqa: N802
        # helper 的 watchdog 检测到 GUI 退出会自动结束，无需显式 IPC。
        super().closeEvent(event)


def _find_icon() -> str:
    candidates = []
    if getattr(sys, "frozen", False):
        candidates.append(os.path.join(getattr(sys, "_MEIPASS", ""), "assets", "shifu.ico"))
        candidates.append(os.path.join(os.path.dirname(sys.executable), "assets", "shifu.ico"))
    candidates.append(
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets", "shifu.ico"))
    )
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return ""


def run(initial_paths: Optional[List[str]] = None, mode: str = "delete") -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("释缚")
    icon_path = _find_icon()
    if icon_path:
        app.setWindowIcon(QIcon(icon_path))
    w = MainWindow(initial_paths, mode=mode)
    if icon_path:
        w.setWindowIcon(QIcon(icon_path))
    w.show()
    return app.exec()
