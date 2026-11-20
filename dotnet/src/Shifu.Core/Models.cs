using System.Text.Json.Serialization;

namespace Shifu.Core;

/// <summary>版本号：与 Python 版保持一致。</summary>
public static class AppInfo
{
    public const string Version = "1.0.0";
}

/// <summary>Restart Manager 识别出的占用进程。</summary>
public sealed class HeldProcess
{
    public int Pid { get; set; }
    public string Name { get; set; } = "";
    public int AppType { get; set; }
    public bool Restartable { get; set; }
    public double StartTime { get; set; }
    public string Exe { get; set; } = "";

    [JsonIgnore]
    public string TypeLabel => AppType switch
    {
        0 => "未知",
        1 => "主窗口程序",
        2 => "其他窗口程序",
        3 => "服务",
        4 => "资源管理器",
        5 => "控制台程序",
        1000 => "关键进程",
        _ => $"类型 {AppType}",
    };
}

/// <summary>通过句柄枚举识别出的持有文件句柄的进程。</summary>
public sealed class FileHolder
{
    public int Pid { get; set; }
    public long HandleValue { get; set; }
    public string ObjectName { get; set; } = "";
    public string Win32Path { get; set; } = "";
    public string ProcessName { get; set; } = "";
}

/// <summary>单个路径的诊断结果。</summary>
public sealed class Diagnosis
{
    public string Path { get; set; } = "";
    public bool Exists { get; set; }
    public bool IsDir { get; set; }
    public string Kind { get; set; } = "UNKNOWN";
    public string KindLabel { get; set; } = "未知原因";
    public string Detail { get; set; } = "";
    public int ErrorCode { get; set; }
    public int Attributes { get; set; }
    public List<HeldProcess> Processes { get; set; } = [];
    public List<FileHolder> Holders { get; set; } = [];
    public List<string> Suggestions { get; set; } = [];

    [JsonIgnore]
    public string Summary
    {
        get
        {
            var sb = new System.Text.StringBuilder();
            sb.Append(Path).Append("\n  判定: ").Append(KindLabel);
            if (Detail.Length > 0) sb.Append("\n  说明: ").Append(Detail);
            if (Processes.Count > 0)
            {
                var names = string.Join("、", Processes.Take(5).Select(p => $"{p.Name}(PID {p.Pid})"));
                sb.Append("\n  占用进程: ").Append(names);
            }
            if (Holders.Count > 0) sb.Append("\n  文件句柄: ").Append(Holders.Count).Append(" 个");
            if (Suggestions.Count > 0) sb.Append("\n  建议: ").Append(string.Join("；", Suggestions));
            return sb.ToString();
        }
    }
}

/// <summary>一次操作的结果。</summary>
public sealed class ActionResult
{
    public bool Ok { get; set; }
    public string Message { get; set; } = "";
    public string Detail { get; set; } = "";

    public static ActionResult Success(string message, string detail = "") =>
        new() { Ok = true, Message = message, Detail = detail };

    public static ActionResult Fail(string message, string detail = "") =>
        new() { Ok = false, Message = message, Detail = detail };
}
