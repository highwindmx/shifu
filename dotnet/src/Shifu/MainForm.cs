using Shifu.Core;

namespace Shifu;

/// <summary>
/// 主界面（四块：路径 → 占用项 → 三种操作 → 日志）。对应 Python ui/main_window.py。
/// GUI 始终非提权（OLE 拖放要求中等完整性）；需要管理员权限的操作懒拉起提权 helper。
/// </summary>
public partial class MainForm : Form
{
    private readonly string _mode;
    private readonly bool _autoExec;
    private bool _autoExecFired; // 自动执行只触发一次，避免批量结束后的重新诊断再次触发
    private readonly List<Diagnosis> _diagnoses = [];
    private readonly List<FileHolder> _holders = [];
    private readonly List<HeldProcess> _procEntries = [];
    private readonly List<FileHolder> _holderEntries = [];
    private readonly Dictionary<string, Button> _modeButtons = new();

    private AgentClient? _agent;
    private bool _agentStarting;

    private readonly List<string> _queue = [];
    private string _batchMode = "delete";
    private int _batchTotal;
    private bool _batchConfirmed;
    private string _renameTemplate = "";

    private static readonly Dictionary<string, string> ModeLabels = new()
    {
        ["unlock"] = "仅解锁",
        ["rename"] = "解锁并重命名",
        ["delete"] = "解锁并删除（回收站）",
    };

    // UI 控件
    private readonly ListBox _pathList = new();
    private readonly CheckedListBox _holderArea = new();
    private readonly RichTextBox _log = new();

    public MainForm(IReadOnlyList<string> initialPaths, string mode, bool autoExec = false)
    {
        _mode = ModeLabels.ContainsKey(mode) ? mode : "delete";
        _autoExec = autoExec;
        Text = $"释缚 · 解锁被占用文件  v{AppInfo.Version}";
        Size = new Size(820, 660);
        MinimumSize = new Size(700, 540);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Microsoft YaHei", 10f);

        BuildUi();

        foreach (var p in initialPaths)
            if (!string.IsNullOrEmpty(p) && !PathItems.Contains(p)) _pathList.Items.Add(p);

        AppendLog($"释缚 v{AppInfo.Version} 启动（界面非提权，拖放通道：OLE 原生）。首次执行解锁操作时将弹一次 UAC。");

        // 诊断推迟到 Shown：构造期句柄未创建，RunAsync 回调会落在后台线程访问 UI。
        // 右键菜单 --mode= 启动时，诊断完成后自动执行对应操作。
        Shown += (_, _) =>
        {
            if (_pathList.Items.Count > 0) RunDiagnose();
            else if (_autoExec) AppendLog("命令行未带有效路径，未自动执行操作。");
        };
    }

    private IEnumerable<string> PathItems => _pathList.Items.Cast<object>().Select(o => o.ToString() ?? "");

    // ------------------------------------------------------------ UI 构建
    private void BuildUi()
    {
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 5, ColumnCount = 1, Padding = new Padding(10) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));      // ① label
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 22));   // ① path row
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));      // ② label
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 25));   // ② holders
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 45));   // ③+④ 用嵌套

        root.Controls.Add(new Label { Text = "① 目标路径（可多选，拖入或添加，自动诊断）", AutoSize = true, Font = new Font(Font, FontStyle.Bold) });

        var pathRow = new Panel { Dock = DockStyle.Fill };
        _pathList.Dock = DockStyle.Left;
        _pathList.Width = 560;
        _pathList.SelectionMode = SelectionMode.MultiExtended;
        _pathList.AllowDrop = true;
        _pathList.DragEnter += PathList_DragEnter;
        _pathList.DragDrop += PathList_DragDrop;
        var pathBtns = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8, 0, 0, 0) };
        var addBtn = new Button { Text = "添加路径", Dock = DockStyle.Top, Height = 32 };
        addBtn.Click += (_, _) => AddPath();
        var clearBtn = new Button { Text = "清空", Dock = DockStyle.Top, Height = 32 };
        clearBtn.Click += (_, _) => ClearPaths();
        pathBtns.Controls.Add(clearBtn);
        pathBtns.Controls.Add(addBtn);
        pathRow.Controls.Add(pathBtns);
        pathRow.Controls.Add(_pathList);
        root.Controls.Add(pathRow);

        root.Controls.Add(new Label { Text = "② 占用项（勾选后执行，L1 结束进程 / L3 关句柄）", AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
        _holderArea.Dock = DockStyle.Fill;
        _holderArea.CheckOnClick = true;
        root.Controls.Add(_holderArea);

        // ③④ 嵌套面板
        var bottom = new Panel { Dock = DockStyle.Fill };
        var opsLabel = new Label { Text = "③ 解锁操作（自动按诊断选择手段，多文件逐个处理）", Dock = DockStyle.Top, AutoSize = true, Font = new Font(Font, FontStyle.Bold) };
        // 三个按钮三等分，随主窗口宽度伸缩
        var opsRow = new TableLayoutPanel
        {
            Dock = DockStyle.Top, Height = 52, ColumnCount = 3, RowCount = 1,
            Padding = new Padding(0, 4, 0, 4),
        };
        opsRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));
        opsRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        opsRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        opsRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
        var btnUnlock = MakeModeButton("unlock", "仅解锁", Color.FromArgb(0x2E, 0x9E, 0x5B), Color.White, Color.FromArgb(0x1B, 0x6E, 0x3C));
        var btnRename = MakeModeButton("rename", "解锁并重命名", Color.FromArgb(0xE0, 0xA8, 0x0A), Color.FromArgb(0x3A, 0x2A, 0x00), Color.FromArgb(0xA8, 0x7A, 0x00));
        var btnDelete = MakeModeButton("delete", "解锁并删除（回收站）", Color.FromArgb(0xD6, 0x45, 0x45), Color.White, Color.FromArgb(0x9E, 0x2B, 0x2B));
        opsRow.Controls.Add(btnUnlock, 0, 0);
        opsRow.Controls.Add(btnRename, 1, 0);
        opsRow.Controls.Add(btnDelete, 2, 0);
        foreach (var b in new[] { btnUnlock, btnRename, btnDelete })
        {
            b.Dock = DockStyle.Fill;
            b.Margin = new Padding(3, 0, 3, 0);
            _modeButtons[b.Tag as string ?? ""] = b;
        }
        var logLabel = new Label { Text = "④ 日志", Dock = DockStyle.Top, AutoSize = true, Font = new Font(Font, FontStyle.Bold) };
        _log.Dock = DockStyle.Fill;
        _log.ReadOnly = true;
        _log.Font = new Font("Consolas", 9f);
        _log.BackColor = Color.FromArgb(0xFA, 0xFA, 0xFA);
        bottom.Controls.Add(_log);
        bottom.Controls.Add(logLabel);
        bottom.Controls.Add(opsRow);
        bottom.Controls.Add(opsLabel);
        root.Controls.Add(bottom);

        Controls.Add(root);
        HighlightModeButton();

        // 菜单栏
        var menu = new MenuStrip();
        var settings = new ToolStripMenuItem("设置");
        settings.DropDownItems.Add("安装右键菜单", null, (_, _) => InstallMenu());
        settings.DropDownItems.Add("卸载右键菜单", null, (_, _) => UninstallMenu());
        settings.DropDownItems.Add("权限状态", null, (_, _) => ShowAdminStatus());
        settings.DropDownItems.Add(new ToolStripSeparator());
        settings.DropDownItems.Add("关于", null, (_, _) => ShowAbout());
        menu.Items.Add(settings);
        MainMenuStrip = menu;
        Controls.Add(menu);
    }

    private Button MakeModeButton(string key, string text, Color bg, Color fg, Color border)
    {
        var b = new Button
        {
            Text = text, TextAlign = ContentAlignment.MiddleCenter,
            BackColor = bg, ForeColor = fg, FlatStyle = FlatStyle.Flat,
            Tag = key, Height = 44, Font = new Font(Font, FontStyle.Bold),
        };
        b.FlatAppearance.BorderColor = border;
        b.FlatAppearance.BorderSize = 2;
        b.Click += (_, _) => ExecMode(key);
        return b;
    }

    private void HighlightModeButton()
    {
        foreach (var (key, b) in _modeButtons)
        {
            b.Font = new Font(Font, key == _batchMode ? FontStyle.Bold : FontStyle.Regular);
            b.FlatAppearance.BorderSize = key == _mode ? 3 : 2;
        }
    }

    // ------------------------------------------------------------ 拖放
    private void PathList_DragEnter(object? sender, DragEventArgs e)
    {
        e.Effect = e.Data?.GetDataPresent(DataFormats.FileDrop) == true ? DragDropEffects.Copy : DragDropEffects.None;
    }

    private void PathList_DragDrop(object? sender, DragEventArgs e)
    {
        if (e.Data?.GetData(DataFormats.FileDrop) is not string[] paths) return;
        var added = 0;
        foreach (var path in paths)
        {
            if (!string.IsNullOrEmpty(path) && !PathItems.Contains(path))
            {
                _pathList.Items.Add(path);
                AppendLog($"拖入：{path}");
                added++;
            }
        }
        if (added > 0) RunDiagnose();
    }

    // ------------------------------------------------------------ 日志
    private void AppendLog(string text)
    {
        if (_log.InvokeRequired) { _log.Invoke(() => AppendLog(text)); return; }
        _log.AppendText(text + Environment.NewLine);
        _log.ScrollToCaret();
    }

    private static string FormatResult(ActionResult r) => $"{(r.Ok ? "✅" : "❌")} 【{r.Message}】{r.Detail}";

    // ------------------------------------------------------------ 工具
    private void AddPath()
    {
        using var dlg = new OpenFileDialog { Multiselect = true, Title = "选择文件（可多选，也可直接拖入）" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        var added = 0;
        foreach (var path in dlg.FileNames)
            if (!PathItems.Contains(path)) { _pathList.Items.Add(path); added++; }
        if (added > 0) { AppendLog($"已添加 {added} 个路径"); RunDiagnose(); }
    }

    private void ClearPaths()
    {
        _pathList.Items.Clear();
        _diagnoses.Clear();
        _holders.Clear();
        _procEntries.Clear();
        _holderEntries.Clear();
        _queue.Clear();
        _holderArea.Items.Clear();
        AppendLog("已清空路径列表。");
    }

    private List<string> SelectedPaths()
    {
        if (_pathList.SelectedItems.Count > 0)
            return _pathList.SelectedItems.Cast<object>().Select(o => o.ToString() ?? "").ToList();
        return PathItems.ToList();
    }
}
