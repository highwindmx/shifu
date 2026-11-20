using System.Runtime.InteropServices;

namespace Shifu.Core;

/// <summary>
/// 手写 Win32 P/Invoke 声明 + 结构体。
/// 刻意不用 CsWin32：Python 版有 3 处针对 x64 实测内存布局的修正，
/// 生成器按官方元数据生成的布局会丢掉这些修正、重现堆损坏 bug：
///   1) RM_PROCESS_INFO 补 8 字节尾填充（x64 按 668 字节写入，官方 660）
///   2) RM_UNIQUE_PROCESS 紧密 12 字节（DWORD + FILETIME，无 padding）
///   3) SYSTEM_HANDLE_* 用显式 Size + 指针算术遍历，而非依赖 CLR 自动布局
/// </summary>
internal static class Native
{
    internal const string Kernel32 = "kernel32.dll";
    internal const string Advapi32 = "advapi32.dll";
    internal const string Ntdll = "ntdll.dll";
    internal const string RstrtMgr = "RstrtMgr.dll";
    internal const string Shell32 = "shell32.dll";

    // ---------------- 常量 ----------------
    internal const uint ERROR_SUCCESS = 0;
    internal const uint ERROR_MORE_DATA = 234;
    internal const int ERROR_ACCESS_DENIED = 5;
    internal const int ERROR_SHARING_VIOLATION = 32;
    internal const int ERROR_LOCK_VIOLATION = 33;

    internal const int CCH_RM_SESSION_KEY = 32;
    internal const int CCH_RM_MAX_APP_NAME = 255;
    internal const int CCH_RM_MAX_SVC_NAME = 63;

    internal static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    internal const uint DELETE_ACCESS = 0x00010000;
    internal const uint SYNCHRONIZE = 0x00100000;
    internal const uint FILE_SHARE_READ = 0x1;
    internal const uint FILE_SHARE_WRITE = 0x2;
    internal const uint FILE_SHARE_DELETE = 0x4;
    internal const uint OPEN_EXISTING = 3;
    internal const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    internal const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

    internal const uint FILE_ATTRIBUTE_READONLY = 0x1;
    internal const uint FILE_ATTRIBUTE_OFFLINE = 0x1000;
    internal const uint FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000;
    internal const uint FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000;

    internal const uint PROCESS_DUP_HANDLE = 0x0040;
    internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    internal const uint DUPLICATE_SAME_ACCESS = 0x2;
    internal const uint DUPLICATE_CLOSE_SOURCE = 0x1;

    internal const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
    internal const uint TOKEN_QUERY = 0x8;
    internal const int TOKEN_ELEVATION = 20;
    internal const uint SE_PRIVILEGE_ENABLED = 0x2;

    internal const int SystemExtendedHandleInformation = 64;
    internal const int ObjectNameInformation = 2;
    internal const uint STATUS_SUCCESS = 0;
    internal const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

    internal const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    internal const uint FO_DELETE = 3;
    internal const ushort FOF_ALLOWUNDO = 0x0040;
    internal const ushort FOF_NOCONFIRMATION = 0x0010;
    internal const ushort FOF_NOERRORUI = 0x0400;
    internal const ushort FOF_SILENT = 0x0004;
    internal const uint DRIVE_FIXED = 3;

    // ---------------- 结构体 ----------------
    [StructLayout(LayoutKind.Sequential)]
    internal struct FILETIME
    {
        internal uint dwLowDateTime;
        internal uint dwHighDateTime;
        internal readonly long Raw => ((long)dwHighDateTime << 32) | dwLowDateTime;
    }

    /// <summary>实测紧密 12 字节：DWORD + FILETIME，中间无 padding。</summary>
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct RM_UNIQUE_PROCESS
    {
        internal uint dwProcessId;
        internal FILETIME ProcessStartTime;
    }

    /// <summary>
    /// 实测：x64 下 RmGetList 按 668 字节写入。原生定义 660 字节，
    /// 越界写会在进程退出时触发 0xc0000374 堆损坏。补 8 字节尾占位。
    /// strAppName/strShortFileName 用 ByValTStr 精确匹配 WCHAR 数组。
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4, Size = 668)]
    internal struct RM_PROCESS_INFO
    {
        internal RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        internal string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        internal string strShortFileName;
        internal int ApplicationType;
        internal int bRestartable;
        // 余下至 Size=668 由 CLR 零填充，正是规避越界写的尾部占位
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        internal uint LowPart;
        internal int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID_AND_ATTRIBUTES
    {
        internal LUID Luid;
        internal uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        internal uint PrivilegeCount;
        internal LUID_AND_ATTRIBUTES Privilege1;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_IDENTIFIER_AUTHORITY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        internal byte[] Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        internal IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_NAME_INFORMATION
    {
        internal UNICODE_STRING Name;
    }

    /// <summary>SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX，x64 显式 32 字节。</summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        internal IntPtr Object;
        internal UIntPtr UniqueProcessId;
        internal UIntPtr HandleValue;
        internal uint GrantedAccess;
        internal ushort CreatorBackTraceIndex;
        internal ushort ObjectTypeIndex;
        internal uint HandleAttributes;
        internal uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    internal struct SYSTEM_HANDLE_INFORMATION_EX
    {
        internal UIntPtr NumberOfHandles;
        internal UIntPtr Reserved;
        // Handles[] 紧跟其后，用指针算术遍历（见 Win32.ExtractHandles）
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SHFILEOPSTRUCTW
    {
        internal IntPtr hwnd;
        internal uint wFunc;
        [MarshalAs(UnmanagedType.LPWStr)] internal string? pFrom;
        [MarshalAs(UnmanagedType.LPWStr)] internal string? pTo;
        internal ushort fFlags;
        internal int fAnyOperationsAborted;
        internal IntPtr hNameMappings;
        [MarshalAs(UnmanagedType.LPWStr)] internal string? lpszProgressTitle;
    }

    // ---------------- Restart Manager ----------------
    [DllImport(RstrtMgr, CharSet = CharSet.Unicode)]
    internal static extern uint RmStartSession(out uint pSessionHandle, uint dwSessionFlags, [Out] char[] strSessionKey);

    [DllImport(RstrtMgr, CharSet = CharSet.Unicode)]
    internal static extern uint RmRegisterResources(
        uint dwSessionHandle, uint nFiles,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr, SizeParamIndex = 1)] string[]? rgsFilename,
        uint nProcInfo, IntPtr rgProcInfo,
        uint nProcInfoUsed);

    [DllImport(RstrtMgr, EntryPoint = "RmGetList")]
    internal static extern uint RmGetListQuery(
        uint dwSessionHandle, out uint pnProcInfoNeeded, out uint pnProcInfo,
        IntPtr rgProcInfo, out uint lpdwRebootReasons);

    [DllImport(RstrtMgr, EntryPoint = "RmGetList")]
    internal static extern uint RmGetListFill(
        uint dwSessionHandle, ref uint pnProcInfoNeeded, ref uint pnProcInfo,
        [Out] RM_PROCESS_INFO[] rgProcInfo, out uint lpdwRebootReasons);

    [DllImport(RstrtMgr)]
    internal static extern uint RmEndSession(uint dwSessionHandle);

    // ---------------- kernel32 ----------------
    [DllImport(Kernel32, CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport(Kernel32, SetLastError = true)]
    internal static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [DllImport(Kernel32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DuplicateHandle(
        IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle,
        out IntPtr lpTargetHandle, uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport(Kernel32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr hObject);

    [DllImport(Kernel32, CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint GetFileAttributesW(string lpFileName);

    [DllImport(Kernel32, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetFileAttributesW(string lpFileName, uint dwFileAttributes);

    [DllImport(Kernel32, CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint QueryDosDeviceW(string lpDeviceName, [Out] char[] lpTargetPath, uint ucchMax);

    [DllImport(Kernel32, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool MoveFileExW(string lpExistingFileName, string? lpNewFileName, uint dwFlags);

    [DllImport(Kernel32, CharSet = CharSet.Unicode)]
    internal static extern uint GetDriveTypeW(string lpRootPathName);

    [DllImport(Kernel32)]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport(Kernel32, CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int FormatMessageW(
        uint dwFlags, IntPtr lpSource, uint dwMessageId, uint dwLanguageId,
        out IntPtr lpBuffer, uint nSize, IntPtr args);

    [DllImport(Kernel32)]
    internal static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport(Kernel32, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageNameW(
        IntPtr hProcess, uint dwFlags, [Out] char[] lpExeName, ref uint lpdwSize);

    // ---------------- advapi32 ----------------
    [DllImport(Advapi32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport(Advapi32, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LookupPrivilegeValueW(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport(Advapi32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport(Advapi32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AllocateAndInitializeSid(
        ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority, byte nSubAuthorityCount,
        uint dwSubAuthority0, uint dwSubAuthority1, uint dwSubAuthority2, uint dwSubAuthority3,
        uint dwSubAuthority4, uint dwSubAuthority5, uint dwSubAuthority6, uint dwSubAuthority7,
        out IntPtr pSid);

    [DllImport(Advapi32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CheckTokenMembership(IntPtr TokenHandle, IntPtr SidToCheck, [Out] out int IsMember);

    [DllImport(Advapi32)]
    internal static extern IntPtr FreeSid(IntPtr pSid);

    [DllImport(Advapi32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetTokenInformation(
        IntPtr TokenHandle, int TokenInformationClass, out uint TokenInformation,
        uint TokenInformationLength, out uint ReturnLength);

    // ---------------- ntdll（未文档化 API） ----------------
    [DllImport(Ntdll)]
    internal static extern int NtQuerySystemInformation(
        int SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);

    [DllImport(Ntdll)]
    internal static extern int NtQueryObject(
        IntPtr Handle, int ObjectInformationClass, IntPtr ObjectInformation,
        uint ObjectInformationLength, out uint ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        internal int ExitStatus;
        internal IntPtr PebBaseAddress;
        internal UIntPtr AffinityMask;
        internal int BasePriority;
        internal UIntPtr UniqueProcessId;
        internal UIntPtr InheritedFromUniqueProcessId; // 父 PID
    }

    [DllImport(Ntdll)]
    internal static extern int NtQueryInformationProcess(
        IntPtr ProcessHandle, int ProcessInformationClass, out PROCESS_BASIC_INFORMATION ProcessInformation,
        uint ProcessInformationLength, out uint ReturnLength);

    // ---------------- shell32 ----------------
    [DllImport(Shell32, CharSet = CharSet.Unicode)]
    internal static extern int SHFileOperationW(ref SHFILEOPSTRUCTW lpFileOp);

    [DllImport(Shell32, CharSet = CharSet.Unicode)]
    internal static extern IntPtr ShellExecuteW(
        IntPtr hwnd, string lpOperation, string lpFile, string? lpParameters,
        string? lpDirectory, int nShowCmd);
}
