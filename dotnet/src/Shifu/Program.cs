using Shifu.Core;

namespace Shifu;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();

        var paths = new List<string>();
        var mode = "delete";
        var autoExec = false; // 仅右键菜单等显式 --mode= 启动时自动执行，双击打开不自动动文件
        foreach (var a in args)
        {
            if (a.StartsWith("--mode=", StringComparison.Ordinal))
            {
                var m = a["--mode=".Length..].Trim().ToLowerInvariant();
                if (m is "delete" or "unlock" or "rename") { mode = m; autoExec = true; }
                continue;
            }
            if (a.StartsWith('-') && !File.Exists(a) && !Directory.Exists(a)) continue;
            try
            {
                var abs = Path.GetFullPath(a);
                if (File.Exists(abs) || Directory.Exists(abs)) paths.Add(abs);
            }
            catch { }
        }

        using var form = new MainForm(paths, mode, autoExec);
        // 图标已通过 csproj 的 ApplicationIcon 嵌入 exe，窗体自动采用，无需手动加载外部 ico
        Application.Run(form);
    }
}
