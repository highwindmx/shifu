namespace Shifu.Core;

/// <summary>诊断层：判断文件/文件夹为何无法删除或重命名。对应 Python core/detector.py。</summary>
public static class Detector
{
    private static readonly Dictionary<string, string> KindLabels = new()
    {
        ["NOT_FOUND"] = "路径不存在",
        ["NORMAL"] = "未发现明显锁定",
        ["HANDLE_OCCUPIED"] = "被进程占用（句柄）",
        ["PERMISSION"] = "权限不足",
        ["READONLY"] = "只读属性",
        ["CLOUD_PLACEHOLDER"] = "云同步占位文件",
        ["LONG_PATH"] = "长路径",
        ["UNKNOWN"] = "未知原因",
    };

    /// <summary>目录递归诊断上限：被占用导致删不掉的通常是少数 exe/dll。</summary>
    private const int DirScanLimit = 400;

    private static List<string> CollectFilesForRm(string path)
    {
        var found = new List<string>();
        try
        {
            foreach (var file in EnumerateFilesSafe(path))
            {
                found.Add(file);
                if (found.Count >= DirScanLimit) break;
            }
        }
        catch { }
        return found;
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root)
    {
        // 用 BFS 队列 + 目录枚举原顺序，贴近 Python os.walk(topdown=True) 的遍历，
        // 使 RM 注册的文件子集尽量一致（影响占用进程列表的对拍结果）。
        var queue = new Queue<string>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            var dir = queue.Dequeue();
            string[] subDirs;
            string[] files;
            try
            {
                subDirs = Directory.GetDirectories(dir);
                files = Directory.GetFiles(dir);
            }
            catch { continue; }

            foreach (var d in subDirs)
            {
                var name = Path.GetFileName(d).ToLowerInvariant();
                if (name is "$recycle.bin" or "system volume information") continue;
                queue.Enqueue(d);
            }
            foreach (var f in files) yield return f;
        }
    }

    public static Diagnosis Diagnose(string path)
    {
        var p = Path.GetFullPath(path);
        var d = new Diagnosis { Path = p };
        var exists = File.Exists(p) || Directory.Exists(p);
        d.Exists = exists;
        if (!exists)
        {
            d.Kind = "NOT_FOUND";
            d.KindLabel = KindLabels["NOT_FOUND"];
            d.Detail = "路径不存在或无法访问";
            return d;
        }

        d.IsDir = Directory.Exists(p);
        d.Attributes = (int)Win32.GetFileAttributes(p);
        var attrs = (uint)d.Attributes;

        // Restart Manager：目录本身查不到占用者 → 递归注册其内部文件（限量）
        var rmTargets = new List<string> { p };
        if (d.IsDir)
        {
            var inner = CollectFilesForRm(p);
            if (inner.Count > 0) rmTargets = inner;
        }
        var (rmCode, procs, rebootReason) = Win32.RmQuery(rmTargets);
        d.Processes = procs;

        // CreateFile 探测删除权限
        var (canDelete, err) = Win32.ProbeDelete(p);
        d.ErrorCode = err;
        d.Detail = err != 0 ? $"探测错误码: {err}" : "探测可删除";

        if ((attrs & (Native.FILE_ATTRIBUTE_OFFLINE | Native.FILE_ATTRIBUTE_RECALL_ON_OPEN | Native.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)) != 0)
        {
            d.Kind = "CLOUD_PLACEHOLDER";
            d.Suggestions.Add("先在资源管理器中取消 OneDrive 占位或暂停同步");
        }
        else if (procs.Count > 0)
        {
            d.Kind = "HANDLE_OCCUPIED";
            d.Suggestions.Add("L1: 结束占用进程后重试删除");
        }
        else if (err is Native.ERROR_SHARING_VIOLATION or Native.ERROR_LOCK_VIOLATION)
        {
            d.Kind = "HANDLE_OCCUPIED";
            d.Suggestions.Add("L3: Restart Manager 未识别，需深度扫描并关闭句柄");
        }
        else if (err == Native.ERROR_ACCESS_DENIED)
        {
            if ((attrs & Native.FILE_ATTRIBUTE_READONLY) != 0)
            {
                d.Kind = "READONLY";
                d.Suggestions.Add("L2: 去除只读属性 / 修复权限");
            }
            else
            {
                d.Kind = "PERMISSION";
                d.Suggestions.Add("L2: 取得所有权并赋予管理员完全控制");
            }
        }
        else if (p.Length > 260)
        {
            d.Kind = "LONG_PATH";
            d.Suggestions.Add("使用 \\\\?\\ 前缀路径操作");
        }
        else if (canDelete)
        {
            d.Kind = "NORMAL";
            d.Suggestions.Add("可直接删除或重命名");
        }
        else
        {
            d.Kind = "UNKNOWN";
            d.Suggestions.Add("L3: 深度扫描句柄，或 L4: 重启后删除");
        }

        if (d.IsDir && rmTargets.Count > 1) d.Detail += $"（已递归扫描目录内 {rmTargets.Count} 个文件）";
        if (rebootReason != 0) d.Detail += $"；RM 重启原因: {rebootReason}";
        if (rmCode != 0) d.Detail += $"；RM 查询返回: {rmCode}";

        d.KindLabel = KindLabels.GetValueOrDefault(d.Kind, d.Kind);
        if (err == Native.ERROR_ACCESS_DENIED && d.Kind == "HANDLE_OCCUPIED")
            d.Suggestions.Add("L2: 同时检查 ACL 权限");
        return d;
    }

    public static List<Diagnosis> DiagnoseMany(IReadOnlyList<string> paths) => paths.Select(Diagnose).ToList();
}
