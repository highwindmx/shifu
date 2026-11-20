using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Shifu.Core;

/// <summary>
/// 右键菜单注册与卸载（SubCommands 级联，位于 Win11 第二层经典菜单）。
/// 父菜单 HKCU 免提权，子 verb 的 CommandStore 写 HKLM 需提权 —— install/uninstall
/// 由提权 helper 调用。手写注册表 verb 按设计只出现在第二层，不进第一层新式菜单。
/// 对应 Python shell/menu.py。
/// </summary>
public static class ShellMenu
{
    private const string AppName = "ShifuUnlock";
    private const string MenuText = "释缚 · 解锁被占用文件";

    private static readonly (string verb, string text, string mode)[] Entries =
    [
        ("ShifuUnlock.Unlock", "仅解锁", "unlock"),
        ("ShifuUnlock.Rename", "解锁并重命名", "rename"),
        ("ShifuUnlock.Delete", "解锁并删除（回收站）", "delete"),
    ];

    private static readonly string[] SubkeyBases =
    [
        @"Software\Classes\*\shell",
        @"Software\Classes\Directory\shell",
    ];

    private const string CommandStore = @"Software\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell";

    public static (bool ok, string msg) Install(string guiExe = "")
    {
        var exe = string.IsNullOrEmpty(guiExe) ? Environment.ProcessPath ?? "shifu.exe" : guiExe;
        // Shell 从单文件 exe 提取图标不可靠且会缓存旧状态；优先直接指向 .ico 文件。
        // ico 与 exe 同目录的 assets\ 下（build.bat 会复制），不存在时回退 exe。
        var ico = Path.Combine(Path.GetDirectoryName(exe) ?? "", "assets", "shifu.ico");
        var icon = File.Exists(ico) ? ico : exe;
        try
        {
            Uninstall(); // 清旧版结构

            foreach (var baseKey in SubkeyBases)
            {
                var parent = $"{baseKey}\\{AppName}";
                using var key = Registry.CurrentUser.CreateSubKey(parent);
                // SubCommands 父键的 (Default) 必须彻底删除，不能写成空字符串：
                // 只要该值存在（哪怕是 ""），Shell 就用它而非 MUIVerb/SubCommands，
                // 表现为子菜单不展开。Python 版用 DeleteValue 删除，这里对齐。
                key.DeleteValue("", false);
                key.SetValue("MUIVerb", MenuText, RegistryValueKind.String);
                key.SetValue("SubCommands", string.Join(";", Entries.Select(e => e.verb)), RegistryValueKind.String);
                key.SetValue("Icon", icon, RegistryValueKind.String);
            }

            foreach (var (verb, text, mode) in Entries)
            {
                var sub = $"{CommandStore}\\{verb}";
                using var key = Registry.LocalMachine.CreateSubKey(sub);
                key.SetValue("", text, RegistryValueKind.String);
                key.SetValue("Icon", icon, RegistryValueKind.String);
                using var cmd = key.CreateSubKey("command");
                cmd.SetValue("", $"\"{exe}\" --mode={mode} \"%1\"", RegistryValueKind.String);
            }

            RefreshShell();
            return (true, "级联右键菜单已安装：「释缚 · 解锁被占用文件」子菜单含三项。位于「显示更多选项」的经典菜单。");
        }
        catch (Exception exc) { return (false, $"安装失败（CommandStore 需管理员权限）: {exc.Message}"); }
    }

    public static (bool ok, string msg) Uninstall()
    {
        var notes = new List<string>();
        foreach (var baseKey in SubkeyBases)
        {
            DeleteTree(Registry.CurrentUser, $"{baseKey}\\{AppName}");
            foreach (var (verb, _, _) in Entries)
            {
                var suffix = verb.Split('.').Last();
                DeleteTree(Registry.CurrentUser, $"{baseKey}\\{AppName}.{suffix}");
            }
        }

        // 旧版经典菜单开关键
        DeleteTree(Registry.CurrentUser,
            @"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32");

        foreach (var (verb, _, _) in Entries)
        {
            try { DeleteTree(Registry.LocalMachine, $"{CommandStore}\\{verb}"); }
            catch (Exception exc) { notes.Add($"HKLM CommandStore 未清理（需提权）: {exc.Message}"); }
        }
        if (notes.Count > 0) return (false, string.Join("；", notes));
        RefreshShell();
        return (true, "右键菜单已卸载（父菜单 + CommandStore 子项均清除）");
    }

    /// <summary>通知 Explorer 资源类型/图标缓存已变更，立刻重读注册表菜单与图标。</summary>
    private static void RefreshShell()
    {
        try
        {
            SHChangeNotify(0x08000000, 0x0000, IntPtr.Zero, IntPtr.Zero); // SHCNE_ASSOCCHANGED / SHCNF_IDLIST
        }
        catch { }
    }

    [DllImport("shell32.dll")]
    private static extern void SHChangeNotify(int eventId, uint flags, IntPtr item1, IntPtr item2);

    private static void DeleteTree(RegistryKey root, string path)
    {
        try
        {
            using var key = root.OpenSubKey(path);
            if (key is null) return;
            foreach (var sub in key.GetSubKeyNames()) DeleteTree(root, $"{path}\\{sub}");
            root.DeleteSubKeyTree(path, false);
        }
        catch { }
    }
}
