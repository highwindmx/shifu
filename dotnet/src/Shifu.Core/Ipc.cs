using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Shifu.Core;

/// <summary>
/// 命名管道 IPC：非提权 GUI &lt;-&gt; 提权 helper。对应 Python core/ipc.py。
/// 管道名与令牌由 GUI 随机生成，经命令行传给 helper；每条请求带令牌校验，
/// 防止本机其他进程冒充客户端。DACL 用 SDDL 限定 SYSTEM/Admins/交互用户。
/// </summary>
public static class Ipc
{
    public const string PipePrefix = @"\\.\pipe\";
    public const string PipeSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static (string name, string token) NewCredentials() =>
        ("shifu_agent_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant(),
         Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant());

    public static string PipeFullName(string name) => PipePrefix + name;

    /// <summary>定位提权 helper：dist/shifu-agent/shifu-agent.exe，源码态回退到项目输出目录。</summary>
    public static string FindAgentExe()
    {
        var baseDir = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(baseDir, "shifu-agent", "shifu-agent.exe"),
            Path.Combine(baseDir, "shifu-agent.exe"),
            Path.Combine(baseDir, "..", "..", "..", "shifu-agent", "shifu-agent.exe"),
        };
        foreach (var c in candidates)
        {
            var full = Path.GetFullPath(c);
            if (File.Exists(full)) return full;
        }
        return Path.GetFullPath(candidates[0]);
    }

    /// <summary>以 runas 启动提权 helper（唯一一次 UAC 弹窗）。</summary>
    public static void LaunchAgent(string pipeName, string token, int guiPid, string guiExe)
    {
        var agent = FindAgentExe();
        if (!File.Exists(agent)) throw new FileNotFoundException($"找不到提权组件：{agent}");
        var args = $"--pipe-name={pipeName} --token={token} --gui-pid={guiPid} --gui-exe=\"{guiExe}\"";
        var rc = ShellExecuteW(IntPtr.Zero, "runas", agent, args, null, 0); // SW_HIDE = 0
        if (rc.ToInt64() <= 32) throw new InvalidOperationException($"无法启动提权组件（ShellExecute 返回 {rc}）——UAC 可能被拒绝");
    }

    /// <summary>等待 helper 创建管道（覆盖用户点 UAC 的等待时间）。</summary>
    public static bool WaitAgent(string pipeName, int timeoutMs = 120_000)
    {
        var full = PipeFullName(pipeName);
        var deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (WaitNamedPipeW(full, 500)) return true;
            Thread.Sleep(100);
        }
        return false;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WaitNamedPipeW(string lpNamedPipeName, uint nTimeOut);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr ShellExecuteW(IntPtr hwnd, string lpOperation, string lpFile,
        string? lpParameters, string? lpDirectory, int nShowCmd);

    /// <summary>helper 侧：创建带 SDDL 的服务端管道。</summary>
    public static NamedPipeServerStream CreateServer(string name)
    {
        var security = new PipeSecurity();
        var sid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.AddAccessRule(new PipeAccessRule(admins, PipeAccessRights.FullControl, AccessControlType.Allow));
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        security.AddAccessRule(new PipeAccessRule(interactive, PipeAccessRights.FullControl, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.None, 65536, 65536, security);
    }

    /// <summary>读取一行 UTF-8 JSON（换行分帧，与 Python 版协议一致）。</summary>
    public static T? ReadJson<T>(Stream stream)
    {
        var buffer = new List<byte>();
        var chunk = new byte[8192];
        while (buffer.Count < 8 * 1024 * 1024)
        {
            var n = stream.Read(chunk, 0, chunk.Length);
            if (n == 0) break;
            for (var i = 0; i < n; i++)
            {
                if (chunk[i] == (byte)'\n')
                {
                    var json = Encoding.UTF8.GetString(buffer.ToArray(), 0, buffer.Count);
                    return JsonSerializer.Deserialize<T>(json, JsonOpts);
                }
                buffer.Add(chunk[i]);
            }
        }
        throw new IOException("管道响应未按预期结束（缺少换行符）");
    }

    public static void WriteJson(Stream stream, object obj)
    {
        var json = JsonSerializer.Serialize(obj, JsonOpts) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush();
    }
}

/// <summary>GUI 侧线程安全客户端：每条请求开一条管道连接，同步等待响应。</summary>
public sealed class AgentClient : IDisposable
{
    private readonly string _pipeName;
    private readonly string _token;
    private readonly object _lock = new();

    public AgentClient(string pipeName, string token)
    {
        _pipeName = pipeName;
        _token = token;
    }

    public T Call<T>(string op, Dictionary<string, object?>? args = null)
    {
        lock (_lock)
        {
            using var client = new NamedPipeClientStream(".", _pipeName,
                PipeDirection.InOut, PipeOptions.None);
            client.Connect(90_000);
            var req = new Dictionary<string, object?>
            {
                ["token"] = _token, ["op"] = op, ["args"] = args ?? new Dictionary<string, object?>(),
            };
            Ipc.WriteJson(client, req);
            var resp = Ipc.ReadJson<Dictionary<string, JsonElement>>(client)
                ?? throw new IOException("管道返回空响应");
            if (!resp.TryGetValue("ok", out var okEl) || !okEl.GetBoolean())
            {
                var err = resp.TryGetValue("error", out var errEl) ? errEl.GetString() : "helper 返回失败";
                throw new InvalidOperationException(err);
            }
            if (!resp.TryGetValue("data", out var dataEl)) throw new IOException("响应缺少 data");
            return dataEl.Deserialize<T>()!;
        }
    }

    /// <summary>无需返回值的调用，转成 ActionResult（helper 的 dispatch 统一用 {ok,message,detail}）。</summary>
    public ActionResult CallResult(string op, Dictionary<string, object?>? args = null)
    {
        try
        {
            var d = Call<Dictionary<string, JsonElement>>(op, args);
            var ok = d.TryGetValue("ok", out var okEl) && okEl.GetBoolean();
            var msg = d.TryGetValue("message", out var m) ? m.GetString() ?? "" : "";
            var detail = d.TryGetValue("detail", out var det) ? det.GetString() ?? "" : "";
            return new ActionResult { Ok = ok, Message = msg, Detail = detail };
        }
        catch (Exception exc) { return ActionResult.Fail(op, $"{exc.GetType().Name}: {exc.Message}"); }
    }

    public void Dispose() { }
}
