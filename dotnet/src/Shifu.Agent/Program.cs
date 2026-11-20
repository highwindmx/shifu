using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Shifu.Core;

// 释缚提权 helper（无窗口，requireAdministrator）。
// 只做一件事：通过命名管道接收非提权 GUI 的 JSON 请求，调用 Core 层执行
// 需要管理员权限的操作，结果以 JSON 回传。GUI 退出后 watchdog 自动结束本进程。

var (pipeName, token, guiPid, guiExe) = ParseArgs(args);

// 提权 helper 必须保护 GUI 进程与两个 exe 路径
Win32.SetProtectedPids([guiPid, Environment.ProcessId]);
if (!string.IsNullOrEmpty(guiExe)) Win32.AddSelfPath(guiExe);
Win32.EnableDebugPrivilege();

using var server = Ipc.CreateServer(pipeName);

// watchdog：GUI 退出后 helper 自动结束，避免提权进程残留
using var cts = new CancellationTokenSource();
_ = Task.Run(async () =>
{
    using var gui = TryGetProcess(guiPid);
    while (!cts.IsCancellationRequested)
    {
        if (gui is null || gui.HasExited) { cts.Cancel(); break; }
        await Task.Delay(1000, cts.Token).ContinueWith(_ => { }, TaskScheduler.Default);
    }
});

try
{
    while (!cts.IsCancellationRequested)
    {
        await server.WaitForConnectionAsync(cts.Token);
        Dictionary<string, JsonElement>? req = null;
        object resp;
        try
        {
            req = Ipc.ReadJson<Dictionary<string, JsonElement>>(server);
            var reqToken = req is not null && req.TryGetValue("token", out var t) ? t.GetString() : null;
            if (reqToken != token)
            {
                resp = new { ok = false, error = "令牌校验失败" };
            }
            else
            {
                var op = req is not null && req.TryGetValue("op", out var o) ? o.GetString() ?? "" : "";
                var argsEl = req is not null && req.TryGetValue("args", out var a) ? a : default;
                try
                {
                    var data = Dispatch(op, argsEl);
                    resp = new { ok = true, data };
                }
                catch (Exception exc)
                {
                    resp = new { ok = false, error = $"{exc.GetType().Name}: {exc.Message}" };
                }
            }
        }
        catch (Exception exc)
        {
            resp = new { ok = false, error = $"{exc.GetType().Name}: {exc.Message}" };
        }
        try { Ipc.WriteJson(server, resp); } catch { }
        if (server.IsConnected) server.Disconnect();
    }
}
catch (OperationCanceledException) { }
catch (IOException) { }
finally { cts.Cancel(); }

return 0;

// ---------------------------------------------------------------- 函数
static (string, string, int, string) ParseArgs(string[] argv)
{
    string pipe = "", token = "", guiExe = "";
    var guiPid = 0;
    for (var i = 0; i < argv.Length; i++)
    {
        var a = argv[i];
        string? Val()
        {
            if (a.Contains('=')) return a[(a.IndexOf('=') + 1)..];
            return i + 1 < argv.Length ? argv[++i] : null;
        }
        if (a.StartsWith("--pipe-name", StringComparison.Ordinal)) pipe = Val() ?? "";
        else if (a.StartsWith("--token", StringComparison.Ordinal)) token = Val() ?? "";
        else if (a.StartsWith("--gui-pid", StringComparison.Ordinal)) int.TryParse(Val(), out guiPid);
        else if (a.StartsWith("--gui-exe", StringComparison.Ordinal)) guiExe = Val() ?? "";
    }
    if (pipe.Length == 0 || token.Length == 0 || guiPid == 0)
    {
        Console.Error.WriteLine("用法: shifu-agent --pipe-name=... --token=... --gui-pid=... [--gui-exe=...]");
        Environment.Exit(1);
    }
    return (pipe, token, guiPid, guiExe);
}

static Process? TryGetProcess(int pid)
{
    try { return Process.GetProcessById(pid); } catch { return null; }
}

static object Dispatch(string op, JsonElement args)
{
    string? Str(string key) => args.ValueKind == JsonValueKind.Object && args.TryGetProperty(key, out var v) ? v.GetString() : null;

    switch (op)
    {
        case "ping": return new { pong = true, version = AppInfo.Version };
        case "is_admin": return new { admin = Win32.IsAdmin() };

        case "diagnose":
        {
            var d = Detector.Diagnose(Str("path") ?? "");
            return new
            {
                path = d.Path, exists = d.Exists, is_dir = d.IsDir,
                kind = d.Kind, kind_label = d.KindLabel, detail = d.Detail,
                error_code = d.ErrorCode, attributes = d.Attributes,
                processes = d.Processes, holders = d.Holders, suggestions = d.Suggestions,
            };
        }
        case "l0": return Strategies.L0RetryDelete(Str("path") ?? "");
        case "l2": return Strategies.L2FixPermissions(Str("path") ?? "");
        case "l3":
        {
            var holders = new List<FileHolder>();
            if (args.ValueKind == JsonValueKind.Object && args.TryGetProperty("holders", out var hs))
                foreach (var h in hs.EnumerateArray())
                    holders.Add(h.Deserialize<FileHolder>()!);
            return Strategies.L3CloseHandles(Str("path") ?? "", holders);
        }
        case "l1":
        {
            var procs = new List<HeldProcess>();
            if (args.ValueKind == JsonValueKind.Object && args.TryGetProperty("procs", out var ps))
                foreach (var p in ps.EnumerateArray())
                    procs.Add(p.Deserialize<HeldProcess>()!);
            return Strategies.L1EndProcesses(Str("path") ?? "", procs);
        }
        case "l4": return Strategies.L4ScheduleDelete(Str("path") ?? "");
        case "deep_scan":
        {
            var hs = Strategies.DeepScan(Str("path") ?? "");
            var own = Win32.SelfPidChain();
            return hs.Where(h => !own.Contains(h.Pid)).ToList();
        }
        case "recycle":
        case "delete": return Strategies.DoRecycle(Str("path") ?? "");
        case "rename": return Strategies.DoRename(Str("src") ?? "", Str("dst") ?? "");
        case "install_menu":
        {
            var (ok, msg) = ShellMenu.Install(Str("gui_exe") ?? "");
            return new { ok, message = "安装右键菜单", detail = msg };
        }
        case "uninstall_menu":
        {
            var (ok, msg) = ShellMenu.Uninstall();
            return new { ok, message = "卸载右键菜单", detail = msg };
        }
        default: throw new InvalidOperationException($"未知操作：{op}");
    }
}
