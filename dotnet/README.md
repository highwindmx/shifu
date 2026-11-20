# 释缚（shifu）— .NET 版

Windows 11 下解锁被占用 / 权限异常的文件，使其可被删除或重命名。
本目录是 Python 版（`../python/`）的 .NET 10 移植，目标框架 `net10.0-windows`，
双进程架构与功能语义保持一致。

## 状态（阶段 0~4 已完成）

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| 0 | 双项目骨架（GUI / Agent）+ 数据模型 + manifest | ✅ |
| 1 | Win32 诊断核心（RM / CreateFile / 属性 / 句柄枚举） | ✅ |
| 2 | 提权 IPC（命名管道 + SDDL + 令牌 + watchdog） | ✅ |
| 3 | WinForms UI（四块界面 + OLE 拖放 + 批量 L0~L4） | ✅ |
| 4 | 右键菜单 + `dotnet publish` 单文件打包 | ✅ |

## 系统要求

- Windows 10 / 11（x64）
- 发布产物自包含，无需安装 .NET 运行时或 Python
- 管理员权限：首次执行解锁操作时弹一次 UAC（由提权 helper 获得）

## 构建

在 `dotnet/` 目录执行：

```bat
tools\build.bat
```

产物：

| 文件 | 说明 |
| --- | --- |
| `dist\shifu.exe` | GUI，非提权（`asInvoker`），单文件，OLE 拖放正常 |
| `dist\shifu-agent\shifu-agent.exe` | 提权 helper（`requireAdministrator`），单文件 |

> 两个 exe 必须保持上述相对位置：GUI 按此布局查找 helper。分发时复制整个 `dist\`。

源码运行（需 .NET 10 SDK）：

```bat
dotnet build Shifu.slnx
dotnet run --project src\Shifu\Shifu.csproj
```

## 架构

| 项目 | 作用 |
| --- | --- |
| `src/Shifu.Core` | 共享层：手写 Win32 P/Invoke（Native.cs）、Win32 封装、诊断、策略、IPC、右键菜单、数据模型 |
| `src/Shifu` | WinForms GUI，始终非提权，OLE 拖放 + 懒提权 |
| `src/Shifu.Agent` | 控制台提权 helper，命名管道 RPC + L0~L4 执行 + GUI watchdog |

双进程原因：GUI 必须非提权（中等完整性）才能接收资源管理器 OLE 拖放；
UIPI 会拦截低完整性 → 高完整性的消息。需要管理员权限的操作通过命名管道交给 helper。

## 为什么手写 P/Invoke 而不用 CsWin32

Python 版有 3 处针对 x64 实际内存布局的实测修正，CsWin32 按官方元数据生成的结构体会丢掉它们、重现堆损坏：

1. `RM_PROCESS_INFO` 补 8 字节尾填充（`Size=668`，官方 660，越界写触发 `0xc0000374` 崩溃）
2. `RM_UNIQUE_PROCESS` 紧密 12 字节（`Pack=4`，DWORD + FILETIME 无 padding）
3. 句柄结构用 `Marshal.PtrToStructure` + 指针算术遍历，而非依赖 CLR 自动布局

故 `Native.cs` 全部手写声明 + 显式 `StructLayout`，零 NuGet 依赖。

## 与 Python 版对拍结果

同一台机器、同一批路径，诊断层（`kind / error_code`）逐项对比：

| 路径 | Python | .NET | 结论 |
| --- | --- | --- | --- |
| `C:\Windows\notepad.exe` | `PERMISSION 5 0` | `PERMISSION 5 0` | ✅ 一致 |
| `README.md`（普通文件） | `NORMAL 0 0` | `NORMAL 0 0` | ✅ 一致 |
| 不存在的路径 | `NOT_FOUND 0 0` | `NOT_FOUND 0 0` | ✅ 一致 |
| `C:\Windows`（目录） | `HANDLE_OCCUPIED 5` | `HANDLE_OCCUPIED 5` | ✅ 判定一致；占用进程明细数因目录遍历/权限过滤实现差异而不同（43 vs 65），不影响功能 |

## 待你本机验证

- [ ] 从资源管理器拖入正在被占用的文件 → 自动诊断、占用项列出
- [ ] 点击三种操作按钮 → 首次弹一次 UAC、之后复用 helper
- [ ] 「仅解锁」后文件可删、程序自身不被结束/删除
- [ ] 删除到回收站可从回收站还原
- [ ] 设置 → 安装右键菜单 → 「显示更多选项」经典菜单出现级联子菜单
- [ ] 关闭 GUI 后 helper 自动退出（任务管理器确认无残留）

## 风险提示

- L1 结束进程、L3 强关句柄可能导致目标程序异常退出或数据丢失。
- L2 会修改文件所有权与 ACL，仅建议对自己有管理权限的文件使用。
- 请勿对系统关键文件（如 `C:\Windows` 下）随意使用。

## 许可证

[MIT](../LICENSE) © 2026 highwindmx

Powered by WorkBuddy
