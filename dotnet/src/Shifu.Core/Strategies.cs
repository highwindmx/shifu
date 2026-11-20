namespace Shifu.Core;

/// <summary>L0~L4 解锁手段 + 最终操作，统一返回 ActionResult。对应 Python core/strategies.py。
/// 核心安全约束：解锁后只探测是否可删，绝不隐式删除；删除是独立的最终操作。</summary>
public static class Strategies
{
    public static ActionResult L0RetryDelete(string path, int attempts = 3, int delayMs = 400)
    {
        var last = 0;
        for (var i = 0; i < attempts; i++)
        {
            var (ok, err) = Win32.ProbeDelete(path);
            last = err;
            if (ok) return ActionResult.Success("L0 重试探测", "瞬时占用已解除，文件现可删除/重命名");
            if (i < attempts - 1) Thread.Sleep(delayMs);
        }
        return ActionResult.Fail("L0 重试探测", $"仍不可删除 err={last}");
    }

    private static (bool ok, string msg) VerifyUnlock(string path)
    {
        var (ok, err) = Win32.ProbeDelete(path);
        return (ok, ok ? "解锁成功，文件现可删除/重命名" : $"仍不可删除 err={err}");
    }

    public static ActionResult L1EndProcesses(string path, List<HeldProcess> procs, bool force = false)
    {
        var logs = new List<string>();
        var own = Win32.SelfPidChain();
        foreach (var p in procs)
        {
            if (own.Contains(p.Pid)) { logs.Add($"{p.Name} (PID {p.Pid}): 跳过（自身进程）"); continue; }
            var (_, msg) = Win32.TerminateProcess(p.Pid, force);
            logs.Add($"{p.Name} (PID {p.Pid}): {msg}");
        }
        Thread.Sleep(500);
        var (okProbe, msgProbe) = VerifyUnlock(path);
        logs.Add($"解锁复验: {msgProbe}");
        return new ActionResult { Ok = okProbe, Message = "L1 结束占用进程", Detail = string.Join("\n", logs) };
    }

    public static ActionResult L2FixPermissions(string path)
    {
        var (ok, msg) = Win32.FixPermissions(path);
        return new ActionResult { Ok = ok, Message = "L2 权限修复", Detail = msg };
    }

    public static ActionResult L3CloseHandles(string path, List<FileHolder> holders)
    {
        var logs = new List<string>();
        var own = Win32.SelfPidChain();
        foreach (var h in holders)
        {
            if (own.Contains(h.Pid)) { logs.Add($"{h.ProcessName} PID {h.Pid}: 跳过（自身进程）"); continue; }
            var (_, msg) = Win32.CloseRemoteHandle(h.Pid, h.HandleValue);
            logs.Add($"{h.ProcessName} PID {h.Pid} 句柄 {h.HandleValue}: {msg}");
        }
        Thread.Sleep(300);
        var (okProbe, msgProbe) = VerifyUnlock(path);
        logs.Add($"解锁复验: {msgProbe}");
        return new ActionResult { Ok = okProbe, Message = "L3 强制关闭句柄", Detail = string.Join("\n", logs) };
    }

    public static ActionResult L4ScheduleDelete(string path)
    {
        var (ok, msg) = Win32.ScheduleDeleteOnReboot(path);
        return new ActionResult { Ok = ok, Message = "L4 重启后删除", Detail = msg };
    }

    public static ActionResult DoRecycle(string path)
    {
        var (ok, msg) = Win32.RecyclePath(path);
        return new ActionResult { Ok = ok, Message = "移入回收站", Detail = msg };
    }

    public static ActionResult DoRename(string src, string dst)
    {
        var (ok, msg) = Win32.RenamePath(src, dst);
        return new ActionResult { Ok = ok, Message = "重命名", Detail = msg };
    }

    public static List<FileHolder> DeepScan(string path) => Win32.FindFileholders(path);
}
