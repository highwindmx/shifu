using System.Text.Json;
using Shifu.Core;

namespace Shifu;

public partial class MainForm
{
    // ------------------------------------------------------------ 诊断
    private void RunDiagnose()
    {
        var paths = PathItems.ToList();
        if (paths.Count == 0) return;
        AppendLog($"开始诊断 {paths.Count} 个路径…");
        _ = RunAsync(() => Detector.DiagnoseMany(paths), results =>
        {
            _diagnoses.Clear();
            _diagnoses.AddRange(results);
            foreach (var d in results) AppendLog(d.Summary);
            AppendLog("诊断完成。");
            RefreshHolders();

            // 右键菜单 --mode= 启动：诊断完成后自动执行对应操作（危险步骤仍保留确认框）
            if (_autoExec && !_autoExecFired)
            {
                _autoExecFired = true;
                AppendLog($"右键菜单启动，自动执行：{ModeLabels[_mode]}");
                ExecMode(_mode);
            }
        });
    }

    private Diagnosis? DiagFor(string path) => _diagnoses.FirstOrDefault(d => d.Path == path);

    private void RefreshHolders()
    {
        _holderArea.Items.Clear();
        _procEntries.Clear();
        _holderEntries.Clear();
        var protectedPids = Win32.SelfPidChain();
        var seen = new HashSet<int>();
        foreach (var d in _diagnoses)
        {
            foreach (var p in d.Processes)
            {
                if (!seen.Add(p.Pid) || protectedPids.Contains(p.Pid)) continue;
                _holderArea.Items.Add($"[进程] {p.Name}  PID {p.Pid}  {p.TypeLabel}", true);
                _procEntries.Add(p);
            }
            foreach (var h in _holders)
            {
                if (protectedPids.Contains(h.Pid)) continue;
                _holderArea.Items.Add($"[句柄] {h.ProcessName}  PID {h.Pid}  句柄 {h.HandleValue}  {h.Win32Path}", true);
                _holderEntries.Add(h);
            }
        }
        if (_holderArea.Items.Count == 0) _holderArea.Items.Add("（未发现占用项）");
    }

    /// <summary>返回勾选的占用项；若一项都没勾，按 Python 版语义回退到全部。</summary>
    private (List<HeldProcess> procs, List<FileHolder> holders) CheckedEntries()
    {
        var procs = new List<HeldProcess>();
        var holders = new List<FileHolder>();
        var anyChecked = false;
        for (var i = 0; i < _holderArea.Items.Count; i++)
        {
            if (!_holderArea.GetItemChecked(i)) continue;
            anyChecked = true;
            if (i < _procEntries.Count) procs.Add(_procEntries[i]);
            else if (i - _procEntries.Count < _holderEntries.Count) holders.Add(_holderEntries[i - _procEntries.Count]);
        }
        if (!anyChecked) { procs = [.. _procEntries]; holders = [.. _holderEntries]; }
        return (procs, holders);
    }

    // ------------------------------------------------------------ 提权组件
    private bool EnsureAgent(Action onReady)
    {
        if (_agent is not null) { onReady(); return true; }
        if (_agentStarting) { AppendLog("提权组件正在启动中，请稍候…"); return false; }
        _agentStarting = true;
        AppendLog("需要管理员权限，正在启动提权组件…请在 UAC 弹窗中点「是」");
        _ = RunAsync(() =>
        {
            var (name, token) = Ipc.NewCredentials();
            Ipc.LaunchAgent(name, token, Environment.ProcessId,
                Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "shifu.exe"));
            if (!Ipc.WaitAgent(name)) return (false, (AgentClient?)null, "等待提权组件超时（可能未在 UAC 弹窗确认）");
            var client = new AgentClient(name, token);
            var ping = client.Call<Dictionary<string, JsonElement>>("ping");
            var ver = ping.TryGetValue("version", out var v) ? v.GetString() : "?";
            return (true, client, ver);
        }, res =>
        {
            _agentStarting = false;
            var (ok, client, info) = res;
            if (!ok || client is null)
            {
                AppendLog($"❌ 提权组件启动失败：{info}");
                MessageBox.Show(this, $"提权组件启动失败：{info}\n\nL2/L3/L4 解锁与删除需要管理员权限，请检查 UAC 设置后重试。",
                    "无法提权", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            _agent = client;
            AppendLog($"✅ 提权组件就绪（v{info}，管理员权限已生效）");
            onReady();
        });
        return true;
    }

    private ActionResult RpcResult(string op, Dictionary<string, object?>? args = null) =>
        _agent?.CallResult(op, args) ?? ActionResult.Fail(op, "提权组件未就绪");

    private List<FileHolder> RpcDeepScan(string path)
    {
        if (_agent is null) return [];
        return _agent.Call<List<FileHolder>>("deep_scan", new() { ["path"] = path }) ?? [];
    }

    // ------------------------------------------------------------ 批量执行
    private void ExecMode(string mode)
    {
        var raw = SelectedPaths();
        if (raw.Count == 0) { MessageBox.Show(this, "请先添加或选择路径", "提示"); return; }

        // 自身 exe / 指向自身的快捷方式一律跳过
        var skipSelf = raw.Where(Win32.IsSelfPath).ToList();
        var paths = raw.Where(p => !Win32.IsSelfPath(p)).ToList();
        if (skipSelf.Count > 0) AppendLog($"⏭ 跳过 {skipSelf.Count} 个自身/自身快捷方式路径（防止自锁）");
        if (paths.Count == 0) { MessageBox.Show(this, "所选路径均为程序自身，已全部跳过。", "无可处理路径"); return; }

        _renameTemplate = "";
        if (mode == "rename" && paths.Count > 1)
        {
            var (template, ok) = Prompt("批量重命名模板",
                $"共 {paths.Count} 个文件。输入新名称，用 {{n}} 代表序号（从 1 开始）：", "new_{n}");
            if (!ok || string.IsNullOrWhiteSpace(template)) return;
            if (!template.Contains("{n}")) template += "_{n}";
            _renameTemplate = template;
            AppendLog($"批量重命名模板：{template}");
        }

        if (mode == "delete" && paths.Count > 1)
        {
            var listing = string.Join("\n", paths.Take(12).Select(p => $"  • {p}"));
            if (paths.Count > 12) listing += $"\n  … 另有 {paths.Count - 12} 个";
            var answer = MessageBox.Show(this,
                $"即将把 {paths.Count} 个文件移入回收站：\n{listing}\n\n移入后可从回收站还原；部分磁盘（网络盘/U 盘）不支持，将跳过。继续？",
                "确认批量移入回收站", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes) return;
        }

        _queue.Clear();
        _queue.AddRange(paths);
        _batchMode = mode;
        _batchTotal = paths.Count;
        _batchConfirmed = false;
        HighlightModeButton();
        AppendLog($"===== {ModeLabels[mode]}：共 {_batchTotal} 个路径 =====");
        EnsureAgent(ProcessNext);
    }

    private void ProcessNext()
    {
        if (_queue.Count == 0)
        {
            AppendLog("✅ 批量处理完成，正在重新诊断…");
            _holders.Clear();
            RunDiagnose();
            return;
        }
        var path = _queue[0];
        var done = _batchTotal - _queue.Count + 1;
        AppendLog($"—— 进度 [{done}/{_batchTotal}] {path} ——");
        var diag = DiagFor(path);
        if (diag is null)
            _ = RunAsync(() => Detector.Diagnose(path), d => ExecUnlock(d!, path));
        else
            ExecUnlock(diag, path);
    }

    private void ExecUnlock(Diagnosis diag, string path)
    {
        if (diag.Kind == "NOT_FOUND") { AppendLog("路径不存在，跳过。"); Advance(); return; }

        if (diag.Kind is "PERMISSION" or "READONLY")
        {
            AppendLog("诊断=权限问题，采用 L2 权限修复");
            _ = RunAsync(() => RpcResult("l2", new() { ["path"] = path }), r => OnUnlockDone(r, path));
        }
        else if (diag.Kind == "HANDLE_OCCUPIED" && diag.Processes.Count > 0)
        {
            var own = Win32.SelfPidChain();
            var (checkedProcs, _) = CheckedEntries();
            var procs = (checkedProcs.Count > 0 ? checkedProcs : diag.Processes).Where(p => !own.Contains(p.Pid)).ToList();
            if (procs.Count == 0)
            {
                AppendLog("占用进程均为自身，跳过 L1，尝试深度扫描");
                DeepScanThenUnlock(path);
                return;
            }
            if (!_batchConfirmed)
            {
                var names = string.Join("、", procs.Select(p => $"{p.Name}(PID {p.Pid})"));
                var answer = MessageBox.Show(this,
                    $"检测到占用进程：{names}\n\n结束这些进程后继续？（未保存数据可能丢失）\n（选择「是」后本批次不再重复询问）",
                    "确认结束占用进程", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (answer != DialogResult.Yes) { Advance(); return; }
                _batchConfirmed = true;
            }
            AppendLog("诊断=进程占用，采用 L1 结束占用进程");
            var list = procs.Select(p => new Dictionary<string, object?>
            {
                ["pid"] = p.Pid, ["name"] = p.Name, ["app_type"] = p.AppType,
                ["restartable"] = p.Restartable, ["start_time"] = p.StartTime, ["exe"] = p.Exe,
            }).ToList();
            _ = RunAsync(() => RpcResult("l1", new() { ["path"] = path, ["procs"] = list }), r => OnUnlockDone(r, path));
        }
        else if (diag.Kind is "HANDLE_OCCUPIED" or "UNKNOWN" or "LONG_PATH" or "CLOUD_PLACEHOLDER")
        {
            DeepScanThenUnlock(path);
        }
        else
        {
            AppendLog("未发现明显锁定，直接进入最终操作");
            FinishByMode(path);
        }
    }

    private void DeepScanThenUnlock(string path)
    {
        AppendLog("RM 未识别占用者，先做 L3 深度扫描…");
        _ = RunAsync(() => RpcDeepScan(path), hs => OnScanThenUnlock(hs, path));
    }

    private void OnScanThenUnlock(List<FileHolder> holders, string path)
    {
        _holders.Clear();
        _holders.AddRange(holders);
        RefreshHolders();
        var own = Win32.SelfPidChain();
        var external = holders.Where(h => !own.Contains(h.Pid)).ToList();
        if (external.Count == 0)
        {
            AppendLog("深度扫描未发现外部文件句柄，尝试 L0 重试探测");
            _ = RunAsync(() => RpcResult("l0", new() { ["path"] = path }), r => OnUnlockDone(r, path));
            return;
        }
        var (_, checkedHolders) = CheckedEntries();
        var selected = checkedHolders.Count > 0 ? checkedHolders : external;
        if (!_batchConfirmed)
        {
            var answer = MessageBox.Show(this,
                $"发现 {selected.Count} 个外部文件句柄，强制关闭可能导致相关进程崩溃或数据丢失。\n\n继续？（选择「是」后本批次不再重复询问）",
                "风险确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes) { Advance(); return; }
            _batchConfirmed = true;
        }
        AppendLog("采用 L3 关闭文件句柄");
        var list = selected.Select(h => new Dictionary<string, object?>
        {
            ["pid"] = h.Pid, ["handle_value"] = h.HandleValue, ["object_name"] = h.ObjectName,
            ["win32_path"] = h.Win32Path, ["process_name"] = h.ProcessName,
        }).ToList();
        _ = RunAsync(() => RpcResult("l3", new() { ["path"] = path, ["holders"] = list }), r => OnUnlockDone(r, path));
    }

    private void OnUnlockDone(ActionResult result, string path)
    {
        AppendLog(FormatResult(result));
        if (!result.Ok) AppendLog("⚠ 解锁未完全成功，仍尝试最终操作（可能被系统拒绝）；继续下一个。");
        FinishByMode(path);
    }

    private void FinishByMode(string path)
    {
        if (_batchMode == "unlock") { AppendLog($"✅ 已解锁：{path}"); Advance(); return; }

        if (_batchMode == "rename")
        {
            if (!string.IsNullOrEmpty(_renameTemplate))
            {
                var idx = _batchTotal - _queue.Count + 1;
                var name = _renameTemplate.Replace("{n}", idx.ToString());
                var dst = Path.Combine(Path.GetDirectoryName(path) ?? "", name);
                if (File.Exists(dst) || Directory.Exists(dst)) { AppendLog($"❌ 目标已存在，跳过：{dst}"); Advance(); return; }
                AppendLog($"重命名：{path} → {dst}");
                _ = RunAsync(() => RpcResult("rename", new() { ["src"] = path, ["dst"] = dst }), OnFinalDone);
                return;
            }
            var old = Path.GetFileName(path.TrimEnd('\\', '/'));
            var (newName, ok) = Prompt("解锁并重命名", "新名称：", old);
            if (!ok || string.IsNullOrEmpty(newName)) { Advance(); return; }
            var dst2 = Path.Combine(Path.GetDirectoryName(path) ?? "", newName);
            _ = RunAsync(() => RpcResult("rename", new() { ["src"] = path, ["dst"] = dst2 }), OnFinalDone);
            return;
        }

        // delete：单文件再确认一次
        if (_batchTotal == 1)
        {
            var answer = MessageBox.Show(this, $"解锁完成，确定把下面文件移入回收站（可还原）：\n{path}",
                "确认移入回收站", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes) { Advance(); return; }
        }
        _ = RunAsync(() => Recycle(path), OnFinalDone);
    }

    private ActionResult Recycle(string path)
    {
        // 非提权 GUI 直接移入回收站（与资源管理器同一完整性，最可靠）；失败才回退提权 helper
        var (ok, msg) = Win32.RecyclePath(path);
        if (ok) return ActionResult.Success("移入回收站", msg);
        if (_agent is not null)
        {
            var r = RpcResult("recycle", new() { ["path"] = path });
            return r.Ok ? r : ActionResult.Fail("移入回收站", $"{msg}；提权重试：{r.Detail}");
        }
        return ActionResult.Fail("移入回收站", msg);
    }

    private void OnFinalDone(ActionResult result)
    {
        AppendLog(FormatResult(result));
        if (!result.Ok)
        {
            MessageBox.Show(this,
                $"{result.Message}：{result.Detail}\n\n处理建议：\n• 若提示占用/共享冲突：先对该路径执行「仅解锁」，再重试删除\n• 若权限不足：右键「以管理员身份运行」后重试\n• 网络盘 / U 盘不支持回收站，请直接手动删除",
                "操作失败", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        Advance();
    }

    private void Advance()
    {
        if (_queue.Count > 0) _queue.RemoveAt(0);
        ProcessNext();
    }

    // ------------------------------------------------------------ 异步封装
    private async Task RunAsync<T>(Func<T> work, Action<T> onDone)
    {
        try
        {
            var result = await Task.Run(work);
            if (IsHandleCreated) BeginInvoke(() => onDone(result));
            else onDone(result);
        }
        catch (Exception exc)
        {
            AppendLog($"❌ 异常：{exc.GetType().Name}: {exc.Message}（若与提权组件通信失败，请重启程序）");
        }
    }

    private (string, bool) Prompt(string title, string text, string defaultText)
    {
        using var form = new Form
        {
            Text = title, Width = 460, Height = 150, FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, MaximizeBox = false,
        };
        var label = new Label { Text = text, Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(10, 10, 10, 4) };
        var input = new TextBox { Text = defaultText, Dock = DockStyle.Top, Margin = new Padding(10) };
        var ok = new Button { Text = "确定", DialogResult = DialogResult.OK, Dock = DockStyle.Bottom };
        var cancel = new Button { Text = "取消", DialogResult = DialogResult.Cancel, Dock = DockStyle.Bottom };
        form.Controls.AddRange([input, label, ok, cancel]);
        form.AcceptButton = ok;
        form.CancelButton = cancel;
        var result = form.ShowDialog(this);
        return (input.Text, result == DialogResult.OK);
    }

    // ------------------------------------------------------------ 菜单动作
    private void InstallMenu()
    {
        if (!EnsureAgent(() => DoMenuOp(true))) return;
    }

    private void UninstallMenu()
    {
        if (!EnsureAgent(() => DoMenuOp(false))) return;
    }

    private void DoMenuOp(bool install)
    {
        try
        {
            var d = install
                ? _agent!.Call<Dictionary<string, JsonElement>>("install_menu", new() { ["gui_exe"] = Environment.ProcessPath ?? "" })
                : _agent!.Call<Dictionary<string, JsonElement>>("uninstall_menu");
            var ok = d.TryGetValue("ok", out var o) && o.GetBoolean();
            var msg = d.TryGetValue("detail", out var m) ? m.GetString() ?? "" : "";
            AppendLog($"{(ok ? "✅" : "❌")} {msg}");
            MessageBox.Show(this, msg, "右键菜单");
        }
        catch (Exception exc) { AppendLog($"❌ 右键菜单操作失败：{exc.Message}"); MessageBox.Show(this, $"操作失败：{exc.Message}", "右键菜单"); }
    }

    private void ShowAdminStatus()
    {
        var ready = _agent is not null ? "已就绪" : "未启动（首次执行解锁时拉起）";
        MessageBox.Show(this,
            $"界面进程：非提权（拖放通道正常）\n提权组件：{ready}\n\n首次点解锁/重命名/删除时会弹一次 UAC，之后不再重复，组件随本窗口退出而结束。",
            "权限状态");
    }

    private void ShowAbout()
    {
        MessageBox.Show(this,
            $"释缚 v{AppInfo.Version}\n解锁被占用文件，支持仅解锁 / 重命名 / 删除到回收站。\n\n界面非提权运行（保证拖放可用），解锁时按需拉起提权组件。\n⚠ 强制关闭句柄或结束进程可能导致目标程序异常，请确认后再执行。",
            "关于释缚");
    }
}
