using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Shifu.Core;

/// <summary>
/// Win32 API 高层封装：提权判定、Restart Manager、句柄枚举/关闭、权限修复、
/// 回收站删除、延迟删除、自身保护。对应 Python 版 core/winapi.py。
/// 所有对外方法返回 (ok, info) 或结构化数据，不把 Win32 错误码抛给 UI。
/// </summary>
public static class Win32
{
    private static readonly HashSet<int> ProtectedPids = [];
    private static readonly HashSet<string> SelfPaths = new(StringComparer.OrdinalIgnoreCase);

    static Win32()
    {
        var exe = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(exe)) SelfPaths.Add(Path.GetFullPath(exe));
    }

    // ---------------- 自身保护 ----------------
    public static void SetProtectedPids(IEnumerable<int> pids)
    {
        foreach (var p in pids) ProtectedPids.Add(p);
    }

    public static void AddSelfPath(string path)
    {
        if (!string.IsNullOrEmpty(path)) SelfPaths.Add(Path.GetFullPath(path));
    }

    /// <summary>当前进程 + 祖先链 + 注入的 GUI PID —— 绝不结束/关句柄。</summary>
    public static HashSet<int> SelfPidChain()
    {
        var pids = new HashSet<int>(ProtectedPids) { Environment.ProcessId };
        try
        {
            var cur = Process.GetCurrentProcess();
            for (var i = 0; i < 8; i++)
            {
                using var parent = ParentProcess.GetParent(cur);
                if (parent is null) break;
                pids.Add(parent.Id);
                cur = parent;
            }
        }
        catch { /* 祖先链获取失败不影响自身 PID 保护 */ }
        return pids;
    }

    /// <summary>路径是否指向程序自身（含指向自身的 .lnk 快捷方式）。</summary>
    public static bool IsSelfPath(string path)
    {
        try
        {
            var target = Path.GetFullPath(path);
            foreach (var me in SelfPaths)
            {
                if (string.Equals(target, me, StringComparison.OrdinalIgnoreCase)) return true;
                if (!target.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) continue;
                var data = File.ReadAllBytes(target);
                var lower = new byte[data.Length];
                for (var i = 0; i < data.Length; i++) lower[i] = ToLowerByte(data[i]);
                var candidates = new[] { me, Path.GetFileName(me) };
                foreach (var c in candidates)
                {
                    foreach (var enc in new[] { Encoding.Unicode, Encoding.Default, Encoding.ASCII })
                    {
                        try
                        {
                            var needle = enc.GetBytes(c);
                            for (var i = 0; i < needle.Length; i++) needle[i] = ToLowerByte(needle[i]);
                            if (Contains(lower, needle)) return true;
                        }
                        catch (EncoderFallbackException) { }
                        catch (ArgumentException) { }
                    }
                }
            }
        }
        catch { }
        return false;
    }

    private static byte ToLowerByte(byte b) => b >= (byte)'A' && b <= (byte)'Z' ? (byte)(b + 32) : b;

    private static bool Contains(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || needle.Length > haystack.Length) return false;
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { ok = false; break; }
            }
            if (ok) return true;
        }
        return false;
    }

    // ---------------- 通用工具 ----------------
    public static bool IsAdmin()
    {
        try { if (TokenIsElevated()) return true; } catch { }
        try { return InAdminGroup(); } catch { return false; }
    }

    private static bool TokenIsElevated()
    {
        if (!Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_QUERY, out var token)) return false;
        try
        {
            return Native.GetTokenInformation(token, Native.TOKEN_ELEVATION, out var elev, sizeof(uint), out _) && elev != 0;
        }
        finally { Native.CloseHandle(token); }
    }

    private static bool InAdminGroup()
    {
        // S-1-5-32-544
        var ntAuthority = new Native.SID_IDENTIFIER_AUTHORITY { Value = [0, 0, 0, 0, 0, 5] };
        if (!Native.AllocateAndInitializeSid(ref ntAuthority, 2, 0x20, 0x220, 0, 0, 0, 0, 0, 0, out var sid)) return false;
        try
        {
            return Native.CheckTokenMembership(IntPtr.Zero, sid, out var member) && member != 0;
        }
        finally { Native.FreeSid(sid); }
    }

    public static bool EnableDebugPrivilege()
    {
        if (!Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_ADJUST_PRIVILEGES | Native.TOKEN_QUERY, out var token)) return false;
        try
        {
            if (!Native.LookupPrivilegeValueW(null, "SeDebugPrivilege", out var luid)) return false;
            var tp = new Native.TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privilege1 = new Native.LUID_AND_ATTRIBUTES { Luid = luid, Attributes = Native.SE_PRIVILEGE_ENABLED },
            };
            return Native.AdjustTokenPrivileges(token, false, ref tp, (uint)Marshal.SizeOf<Native.TOKEN_PRIVILEGES>(), IntPtr.Zero, IntPtr.Zero);
        }
        finally { Native.CloseHandle(token); }
    }

    /// <summary>长路径支持：绝对路径加 \\?\ 前缀。</summary>
    public static string ExtendedPath(string path)
    {
        var p = Path.GetFullPath(path).Replace('/', '\\');
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) return p;
        return @"\\?\" + p;
    }

    private static readonly Dictionary<int, string> ErrorText = new()
    {
        [5] = "拒绝访问（权限不足）",
        [32] = "文件正在被其他程序使用（共享冲突）",
        [33] = "文件被锁定",
        [87] = "参数无效",
        [1223] = "操作已取消",
        [0x71] = "操作被取消或目标正在使用（Shell 错误 0x71）",
        [0x4C7] = "操作已取消（Shell 错误 0x4C7）",
    };

    public static string FormatWinError(int code)
    {
        if (code == 0) return "";
        if (ErrorText.TryGetValue(code, out var text)) return text;
        const uint flags = 0x1000 | 0x0200; // FORMAT_MESSAGE_ALLOCATE_BUFFER | FROM_SYSTEM
        try
        {
            var n = Native.FormatMessageW(flags, IntPtr.Zero, (uint)code, 0, out var buf, 0, IntPtr.Zero);
            if (n > 0 && buf != IntPtr.Zero)
            {
                var s = Marshal.PtrToStringUni(buf)?.Trim().TrimEnd('。', '\r', '\n') ?? "";
                Native.LocalFree(buf);
                if (s.Length > 0) return s;
            }
        }
        catch { }
        return $"系统错误 {code}";
    }

    public static string GetProcessName(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            var name = p.ProcessName;
            if (!string.IsNullOrEmpty(name)) return name;
        }
        catch { }
        var h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return $"PID {pid}";
        try
        {
            var buf = new char[260];
            uint size = 260;
            return Native.QueryFullProcessImageNameW(h, 0, buf, ref size)
                ? Path.GetFileName(new string(buf, 0, (int)size))
                : $"PID {pid}";
        }
        catch { return $"PID {pid}"; }
        finally { Native.CloseHandle(h); }
    }

    public static uint GetFileAttributes(string path)
    {
        var attrs = Native.GetFileAttributesW(ExtendedPath(path));
        return attrs == 0xFFFFFFFF ? 0 : attrs;
    }

    public static (bool ok, string msg) ClearReadonly(string path)
    {
        var attrs = GetFileAttributes(path);
        if (attrs == 0 || (attrs & Native.FILE_ATTRIBUTE_READONLY) == 0) return (true, "无需处理");
        var newAttrs = attrs & ~Native.FILE_ATTRIBUTE_READONLY;
        if (newAttrs == 0) newAttrs = 0x80; // FILE_ATTRIBUTE_NORMAL
        var ok = Native.SetFileAttributesW(ExtendedPath(path), newAttrs);
        return (ok, ok ? "已去除只读属性" : $"失败 err={Marshal.GetLastWin32Error()}");
    }

    // ---------------- L1 Restart Manager ----------------
    public static (uint code, List<HeldProcess> procs, uint rebootReason) RmQuery(IReadOnlyList<string> paths)
    {
        if (paths.Count == 0) return (Native.ERROR_SUCCESS, [], 0);
        var sessionKey = new char[Native.CCH_RM_SESSION_KEY + 1];
        var rc = Native.RmStartSession(out var session, 0, sessionKey);
        if (rc != Native.ERROR_SUCCESS) return (rc, [], 0);
        try
        {
            rc = Native.RmRegisterResources(session, (uint)paths.Count, paths.ToArray(), 0, IntPtr.Zero, 0);
            if (rc != Native.ERROR_SUCCESS) return (rc, [], 0);

            var needed = 0u;
            var count = 0u;
            var reboot = 0u;
            rc = Native.RmGetListQuery(session, out needed, out count, IntPtr.Zero, out reboot);
            if (rc != Native.ERROR_SUCCESS && rc != Native.ERROR_MORE_DATA) return (rc, [], reboot);
            if (needed == 0) return (Native.ERROR_SUCCESS, [], reboot);

            var infos = new Native.RM_PROCESS_INFO[needed];
            count = needed;
            rc = Native.RmGetListFill(session, ref needed, ref count, infos, out reboot);
            if (rc != Native.ERROR_SUCCESS) return (rc, [], reboot);

            var result = new List<HeldProcess>();
            for (var i = 0; i < count; i++)
            {
                var info = infos[i];
                var pid = (int)info.Process.dwProcessId;
                var name = !string.IsNullOrEmpty(info.strAppName) ? info.strAppName
                    : !string.IsNullOrEmpty(info.strShortFileName) ? info.strShortFileName
                    : $"PID {pid}";
                var start = FileTimeToUnix(info.Process.ProcessStartTime.Raw);
                string exe;
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    exe = proc.MainModule?.FileName ?? "";
                    if (!string.IsNullOrEmpty(exe)) name = Path.GetFileName(exe);
                    var create = new DateTimeOffset(proc.StartTime.ToUniversalTime()).ToUnixTimeSeconds();
                    if (start > 0 && Math.Abs(create - start) > 5) continue; // PID 重用
                }
                catch { exe = ""; }
                result.Add(new HeldProcess
                {
                    Pid = pid, Name = name, AppType = info.ApplicationType,
                    Restartable = info.bRestartable != 0, StartTime = start, Exe = exe,
                });
            }
            return (Native.ERROR_SUCCESS, result, reboot);
        }
        finally { Native.RmEndSession(session); }
    }

    private static double FileTimeToUnix(long raw) => raw == 0 ? 0 : raw / 10_000_000.0 - 11644473600.0;

    // ---------------- 句柄枚举 ----------------
    private static List<Native.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> EnumSystemHandles()
    {
        var length = 1 << 20;
        var entrySize = Marshal.SizeOf<Native.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
        var headerSize = Marshal.SizeOf<Native.SYSTEM_HANDLE_INFORMATION_EX>();
        for (var attempt = 0; attempt < 20; attempt++)
        {
            var buf = Marshal.AllocHGlobal(length);
            try
            {
                var status = Native.NtQuerySystemInformation(Native.SystemExtendedHandleInformation, buf, (uint)length, out var ret);
                if (status == 0)
                {
                    var n = (int)Marshal.ReadIntPtr(buf).ToInt64(); // NumberOfHandles (UIntPtr)
                    var outList = new List<Native.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(n);
                    for (var i = 0; i < n; i++)
                    {
                        var ptr = IntPtr.Add(buf, headerSize + i * entrySize);
                        outList.Add(Marshal.PtrToStructure<Native.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(ptr));
                    }
                    return outList;
                }
                if ((uint)status == Native.STATUS_INFO_LENGTH_MISMATCH)
                {
                    length = (int)Math.Max(length * 2L, ret + 0x10000);
                    if (length > (1 << 28)) break;
                    continue;
                }
                break;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        return [];
    }

    /// <summary>用一个临时文件句柄反查 File 类型的 ObjectTypeIndex。</summary>
    private static int? GetFileTypeIndex(List<Native.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> handles)
    {
        string? tmp = null;
        try
        {
            tmp = Path.Combine(Path.GetTempPath(), "shifu_probe_" + Guid.NewGuid().ToString("N"));
            using var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            var hval = fs.SafeFileHandle.DangerousGetHandle();
            var pid = Environment.ProcessId;
            foreach (var e in handles)
                if (e.UniqueProcessId.ToUInt64() == (ulong)pid && e.HandleValue.ToUInt64() == (ulong)hval.ToInt64())
                    return e.ObjectTypeIndex;
        }
        catch { }
        finally
        {
            try { if (tmp is not null) File.Delete(tmp); } catch { }
        }
        return null;
    }

    private static string QueryObjectName(IntPtr handle)
    {
        var size = 0x400;
        for (var attempt = 0; attempt < 12; attempt++)
        {
            var buf = Marshal.AllocHGlobal(size);
            try
            {
                var status = Native.NtQueryObject(handle, Native.ObjectNameInformation, buf, (uint)size, out var ret);
                if (status == 0)
                {
                    var info = Marshal.PtrToStructure<Native.OBJECT_NAME_INFORMATION>(buf);
                    if (info.Name.Buffer != IntPtr.Zero && info.Name.Length > 0)
                        return Marshal.PtrToStringUni(info.Name.Buffer, info.Name.Length / 2) ?? "";
                    return "";
                }
                if ((uint)status == Native.STATUS_INFO_LENGTH_MISMATCH)
                {
                    size = (int)Math.Max(size * 2L, ret + 0x100);
                    if (size > (1 << 20)) break;
                    continue;
                }
                break;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        return "";
    }

    private static string DeviceToWin32(string devPath)
    {
        for (var c = 'A'; c <= 'Z'; c++)
        {
            var buf = new char[1024];
            if (Native.QueryDosDeviceW($"{c}:", buf, 1024) == 0) continue;
            var dev = new string(buf).Split('\0')[0];
            if (dev.Length > 0 && devPath.StartsWith(dev, StringComparison.OrdinalIgnoreCase))
                return $"{c}:" + devPath[dev.Length..];
        }
        return devPath;
    }

    /// <summary>深度扫描：枚举所有进程文件句柄，找出指向 target 的句柄。</summary>
    public static List<FileHolder> FindFileholders(string target)
    {
        var targetNorm = Path.GetFullPath(target).Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();
        var longNorm = targetNorm.StartsWith(@"\\?\", StringComparison.Ordinal) ? targetNorm : @"\\?\" + targetNorm;

        var handles = EnumSystemHandles();
        var fileType = GetFileTypeIndex(handles);
        if (fileType is null) return [];

        var current = Native.GetCurrentProcess();
        var ownPids = SelfPidChain();
        var found = new List<FileHolder>();
        var seen = new HashSet<(ulong, ulong)>();
        foreach (var e in handles)
        {
            var pid = e.UniqueProcessId.ToUInt64();
            var hval = e.HandleValue.ToUInt64();
            if (e.ObjectTypeIndex != fileType.Value || hval == 0 || pid == 0) continue;
            if (!seen.Add((pid, hval))) continue;
            if (ownPids.Contains((int)pid)) continue;

            var hproc = Native.OpenProcess(Native.PROCESS_DUP_HANDLE, false, (int)pid);
            if (hproc == IntPtr.Zero) continue;
            IntPtr dup = IntPtr.Zero;
            try
            {
                if (!Native.DuplicateHandle(hproc, new IntPtr((long)hval), current, out dup, 0, false, Native.DUPLICATE_SAME_ACCESS)) continue;
                if (dup == IntPtr.Zero) continue;
                var name = QueryObjectName(dup);
                if (name.Length == 0) continue;
                var win32 = DeviceToWin32(name);
                var wNorm = win32.Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();
                if (wNorm == targetNorm || wNorm == longNorm)
                    found.Add(new FileHolder
                    {
                        Pid = (int)pid, HandleValue = (long)hval, ObjectName = name,
                        Win32Path = win32, ProcessName = GetProcessName((int)pid),
                    });
            }
            finally
            {
                if (dup != IntPtr.Zero) Native.CloseHandle(dup);
                Native.CloseHandle(hproc);
            }
        }
        return found;
    }

    public static (bool ok, string msg) CloseRemoteHandle(int pid, long handleValue)
    {
        if (SelfPidChain().Contains(pid)) return (false, $"拒绝关闭自身进程 PID {pid} 的句柄（会导致程序崩溃）");
        var hproc = Native.OpenProcess(Native.PROCESS_DUP_HANDLE, false, pid);
        if (hproc == IntPtr.Zero) return (false, $"无法打开进程 PID {pid}（err={Marshal.GetLastWin32Error()}）");
        IntPtr dup = IntPtr.Zero;
        try
        {
            var ok = Native.DuplicateHandle(hproc, new IntPtr(handleValue), Native.GetCurrentProcess(), out dup, 0, false,
                Native.DUPLICATE_SAME_ACCESS | Native.DUPLICATE_CLOSE_SOURCE);
            var err = Marshal.GetLastWin32Error();
            if (!ok && err == Native.ERROR_ACCESS_DENIED)
            {
                // 回退：目标进程为 hTargetProcessHandle 传 None 的变体（C# 里用 IntPtr.Zero 语义不同，
                // 这里按 Python 版重试：以 hproc 为 target 再关一次）
                ok = Native.DuplicateHandle(hproc, new IntPtr(handleValue), hproc, out _, 0, false, Native.DUPLICATE_CLOSE_SOURCE);
                err = Marshal.GetLastWin32Error();
            }
            return (ok, ok ? "已关闭" : $"关闭失败 err={err}");
        }
        finally
        {
            if (dup != IntPtr.Zero) Native.CloseHandle(dup);
            Native.CloseHandle(hproc);
        }
    }

    // ---------------- 探测与删除 ----------------
    /// <summary>以 DELETE 权限尝试打开文件，不实际删除。返回 (是否可删, Win32 错误码)。</summary>
    public static (bool ok, int err) ProbeDelete(string path)
    {
        var h = Native.CreateFileW(
            ExtendedPath(path), Native.DELETE_ACCESS | Native.SYNCHRONIZE,
            Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE,
            IntPtr.Zero, Native.OPEN_EXISTING,
            Native.FILE_FLAG_BACKUP_SEMANTICS | Native.FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == Native.INVALID_HANDLE_VALUE || h == IntPtr.Zero) return (false, Marshal.GetLastWin32Error());
        Native.CloseHandle(h);
        return (true, 0);
    }

    public static (bool ok, string msg) TerminateProcess(int pid, bool force = false)
    {
        if (SelfPidChain().Contains(pid)) return (false, $"拒绝结束自身进程 PID {pid}（会导致程序崩溃）");
        try
        {
            using var p = Process.GetProcessById(pid);
            if (force) p.Kill();
            else
            {
                p.CloseMainWindow();
                if (!p.WaitForExit(3000)) p.Kill();
            }
            p.WaitForExit(3000);
            return (true, "已结束进程");
        }
        catch (Exception exc)
        {
            if (force)
            {
                try
                {
                    var psi = new ProcessStartInfo("taskkill", $"/PID {pid} /F")
                    { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
                    using var proc = Process.Start(psi)!;
                    var output = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
                    proc.WaitForExit();
                    return (proc.ExitCode == 0, output.Trim());
                }
                catch (Exception e2) { return (false, e2.Message); }
            }
            return (false, exc.Message);
        }
    }

    public static (bool ok, string msg) FixPermissions(string path)
    {
        var isDir = Directory.Exists(path);
        var logs = new List<string>();
        var (takeOk, takeOut) = RunCmd("takeown", isDir ? $"/F \"{path}\" /R /D Y" : $"/F \"{path}\"");
        logs.Add($"takeown rc={(takeOk ? 0 : 1)}: {Trunc(takeOut)}");
        var icaclsArgs = isDir ? $"\"{path}\" /grant *S-1-5-32-544:F /T /C" : $"\"{path}\" /grant *S-1-5-32-544:F /C";
        var (_, icaclsOut) = RunCmd("icacls", icaclsArgs);
        logs.Add($"icacls: {Trunc(icaclsOut)}");
        var (_, roMsg) = ClearReadonly(path);
        logs.Add($"只读属性: {roMsg}");
        var (okProbe, err) = ProbeDelete(path);
        return (okProbe, string.Join("\n", logs) + (okProbe ? "\n复验通过" : $"\n复验 err={err}"));
    }

    private static (bool ok, string output) RunCmd(string exe, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true,
            };
            using var p = Process.Start(psi)!;
            var outText = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit();
            return (p.ExitCode == 0, outText.Trim());
        }
        catch (Exception exc) { return (false, exc.Message); }
    }

    private static string Trunc(string s) => s.Length > 200 ? s[..200] : s;

    public static (bool ok, string msg) ScheduleDeleteOnReboot(string path)
    {
        var p = Path.GetFullPath(path);
        if (p.Length > 260) p = ExtendedPath(p);
        var ok = Native.MoveFileExW(p, null, Native.MOVEFILE_DELAY_UNTIL_REBOOT);
        return (ok, ok ? "已注册重启后删除，请重启系统" : $"注册失败 err={Marshal.GetLastWin32Error()}");
    }

    /// <summary>把文件/目录移入回收站（可还原）。仅本地固定磁盘支持；自身路径拒绝。</summary>
    public static (bool ok, string msg) RecyclePath(string path)
    {
        if (IsSelfPath(path)) return (false, "拒绝删除程序自身（shifu.exe），会导致运行中的程序异常");
        var p = Path.GetFullPath(path);
        if (!File.Exists(p) && !Directory.Exists(p)) return (false, "路径不存在，无需删除");
        var drive = Path.GetPathRoot(p);
        if (string.IsNullOrEmpty(drive)) return (false, $"无法判定磁盘类型，拒绝删除以避免永久丢失：{p}");
        var dtype = Native.GetDriveTypeW(drive);
        if (dtype != Native.DRIVE_FIXED)
        {
            var label = dtype switch { 0 => "未知", 1 => "无效", 2 => "可移动", 4 => "网络", 5 => "光驱", 6 => "内存盘", _ => dtype.ToString() };
            return (false, $"该路径位于{label}磁盘（类型 {dtype}），不保证支持回收站；为避免永久删除已取消，请在资源管理器中手动删除。");
        }

        // SHFileOperationW 的 pFrom 必须双 NUL 结尾
        var op = new Native.SHFILEOPSTRUCTW
        {
            hwnd = IntPtr.Zero,
            wFunc = Native.FO_DELETE,
            pFrom = p + "\0", // MarshalAs LPWSTR 会再加一个终止符 → 双 NUL
            pTo = null,
            fFlags = Native.FOF_ALLOWUNDO | Native.FOF_NOCONFIRMATION | Native.FOF_NOERRORUI | Native.FOF_SILENT,
            fAnyOperationsAborted = 0,
            hNameMappings = IntPtr.Zero,
            lpszProgressTitle = null,
        };
        int rc;
        try { rc = Native.SHFileOperationW(ref op); }
        catch (Exception exc) { return (false, $"{exc.GetType().Name}: {exc.Message}"); }
        if (rc != 0 || op.fAnyOperationsAborted != 0)
        {
            var text = FormatWinError(rc) switch { "" => "未知错误", var t => t };
            var hint = "";
            if (rc is Native.ERROR_SHARING_VIOLATION or Native.ERROR_LOCK_VIOLATION or 0x71
                || text.Contains("正在") || text.Contains("锁定") || text.Contains("占用"))
                hint = "；目录/文件内可能有正在运行的程序锁着它，请先对路径执行「仅解锁」释放占用后重试";
            return (false, $"移入回收站失败：{text}（错误码 {rc}，已中止={op.fAnyOperationsAborted != 0}）{hint}");
        }
        return (true, "已移入回收站（可从回收站还原）");
    }

    public static (bool ok, string msg) RenamePath(string src, string dst)
    {
        if (IsSelfPath(src)) return (false, "拒绝重命名程序自身（shifu.exe），会导致运行中的程序异常");
        try
        {
            var d = Path.GetDirectoryName(dst);
            if (!string.IsNullOrEmpty(d) && !Directory.Exists(d)) Directory.CreateDirectory(d);
            File.Move(ExtendedPath(src), ExtendedPath(dst), false);
            return (true, "重命名成功");
        }
        catch (Exception exc) { return (false, $"{exc.GetType().Name}: {exc.Message}"); }
    }

    /// <summary>供 GUI 进程使用的原生拖放消息放行（GUI 非提权下通常不需要，保留兼容）。</summary>
    public static bool AllowDropMessages(IntPtr hwnd) => true;
}

/// <summary>通过 NtQueryInformationProcess 取父进程 PID（零 NuGet 依赖）。</summary>
internal static class ParentProcess
{
    private const int ProcessBasicInformation = 0;

    public static Process? GetParent(Process child)
    {
        try
        {
            var h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, child.Id);
            if (h == IntPtr.Zero) return null;
            try
            {
                var rc = Native.NtQueryInformationProcess(
                    h, ProcessBasicInformation, out var info,
                    (uint)Marshal.SizeOf<Native.PROCESS_BASIC_INFORMATION>(), out _);
                if (rc != 0) return null;
                var ppid = (int)info.InheritedFromUniqueProcessId.ToUInt64();
                return ppid > 0 ? Process.GetProcessById(ppid) : null;
            }
            finally { Native.CloseHandle(h); }
        }
        catch { return null; }
    }
}
