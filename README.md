# 释缚（shifu）

Windows 11 下解锁被占用 / 权限异常的文件，使其可被删除或重命名。
Qt 桌面工具，GUI 非提权（保证资源管理器拖放可用），解锁时按需拉起提权 helper，
可集成资源管理器右键菜单。

## 功能特性

- **一键诊断**：Restart Manager 精确定位占用进程 + `CreateFile` 探测删除权限 + 文件属性检查，自动判定锁定类型（句柄占用 / 权限不足 / 只读 / 云占位 / 长路径）。
- **五级解锁手段（L0~L4）**：
  - L0 退避重试探测（只探测是否可删，绝不隐式删除）
  - L1 结束占用进程（先温和终止，失败再强杀）
  - L2 权限修复（`takeown` + `icacls` + 去只读）
  - L3 强制关闭文件句柄（枚举系统句柄，需手动勾选确认）
  - L4 注册重启后删除（`PendingFileRenameOperations`）
- **三种解锁操作**：仅解锁（绿）/ 解锁并重命名（黄）/ 解锁并删除到回收站（红），按钮固定配色，点击后自动按诊断结果选 L 层级。删除走 `SHFileOperationW + FOF_ALLOWUNDO`，**移入回收站可还原**；网络盘/可移动盘不支持回收站时明确拒绝，绝不静默永久删除。
- **精简界面**：只有四块——路径、占用项、三种解锁操作、日志；诊断结果直接写日志，占用进程/句柄集中在「占用项」区勾选。
- **右键菜单**：安装后在「显示更多选项」的经典菜单里出现**级联子菜单**「释缚 · 解锁被占用文件」，内含三项（仅解锁 / 解锁并重命名 / 解锁并删除到回收站）。用微软 `MUIVerb` + `SubCommands` + `CommandStore` 实现——父菜单写 HKCU，子 verb 写 HKLM（安装时由提权 helper 写入，会弹一次 UAC）。手写注册表 verb 按设计只在第二层；进第一层需 `IExplorerCommand` + 包身份——详见文末「右键菜单为何只有第二层」。
- **多文件批量处理**：可多选路径，逐个执行「解锁 → 最终操作 → 下一个」；批量重命名用模板 + `{n}` 序号避免重名；批量删除一次性确认并列出全部文件。
- **安全设计**：L1 结束进程、L3 强关句柄、删除均需二次确认；**解锁与删除彻底分离**——L1/L3 解锁后只探测是否可删，绝不隐式删除；任何情况下都不会结束/关句柄/删除程序自身（含指向自身的 .lnk 快捷方式），避免自杀式崩溃。

## 系统要求

- Windows 10 / 11（x64）
- 管理员权限（首次执行解锁操作时弹一次 UAC，由提权 helper 获得）
- 无需安装 Python（使用打包后的 exe）

## 环境配置（uv）

项目使用 [uv](https://docs.astral.sh/uv/) 管理依赖，Python 锁定 3.14：

在 `python/` 目录执行：

```bat
cd python
uv sync
```

这会在 `python/.venv` 并装好 PyQt6 / psutil / PyInstaller。

源码运行：

```bat
cd python
uv run python main.py
```

打包 exe（GUI 单文件 + helper 目录）：

```bat
tools\build.bat
```

产物：

| 文件 | 说明 |
| --- | --- |
| `python\dist\shifu.exe` | GUI，非提权，单文件无控制台 |
| `python\dist\shifu_agent\shifu_agent.exe` | 提权 helper，onedir，`requireAdministrator` |

> 两个 exe 必须放在上述相对位置：GUI 会按此布局查找 helper。
> 分发时把整个 `python\dist\` 目录一起复制。

> 双进程架构：GUI（`shifu.exe`）**不提权**，这样资源管理器的 OLE 拖放才不会被
> UIPI 拦截；需要管理员权限的操作在首次点击「解锁 / 重命名 / 删除」时，
> 由 GUI 通过 `ShellExecute(runas)` 拉起无窗口的提权 helper
> (`dist\shifu_agent\shifu_agent.exe`)，只弹一次 UAC，之后复用同一进程，
> GUI 退出时 helper 自动结束。两者通过随机命名的命名管道通信，令牌校验 +
> SDDL 限定用户。
>
> helper 用 **onedir + `requireAdministrator` 清单**打包（GUI 仍是 onefile 但不带清单）：
> 若把 helper 也打成 onefile，`ShellExecute(runas)` 会继承非提权环境变量，
> 触发 PyInstaller 6.22.1+ 的 `invalid originating onefile parent process (PID not found)`
> 校验错误。启动 helper 前 GUI 会临时清除本进程的 `_PYI_*` 环境变量。

## 使用说明对照表

界面从上到下只有四块：

| 区域 | 内容 |
| --- | --- |
| ① 目标路径 | 拖入或点「添加路径」（可多选），加入后自动诊断 |
| ② 占用项 | 列出占用进程 / 文件句柄（可勾选；自动诊断 + 解锁时的深度扫描补充，无需手动按钮） |
| ③ 解锁操作 | 三个按钮固定配色：仅解锁（绿）/ 解锁并重命名（黄）/ 解锁并删除到回收站（红）；选中项加粗描边 |
| ④ 日志 | 诊断判定、占用进程、建议、每步操作结果与批量进度 |

操作对照：

| 操作 | 说明 |
| --- | --- |
| 拖入路径 / 添加路径 | 文件或文件夹加入列表后**自动诊断**，结果写入日志 |
| 仅解锁 | 多选时逐个解锁；按诊断自动选 L2/L1/L3/L0，**不删除不重命名** |
| 解锁并重命名 | 单文件弹名称框；多文件弹一次模板框，`{n}` 为序号（如 `new_{n}` → `new_1`、`new_2`） |
| 解锁并删除（回收站） | 解锁后移入回收站（可还原）；多文件一次性列出全部并确认；网络盘/U 盘不支持时拒绝 |
| 右键菜单 → 三项 | 在「显示更多选项」中：仅解锁 / 解锁并重命名 / 解锁并删除到回收站 |
| 设置 → 安装/卸载右键菜单 | 集成或移除资源管理器右键入口 |
| 设置 → 权限状态 | 查看提权组件是否就绪 |

> 内部仍保留 L0~L4 五级手段，但不再暴露为按钮——点三个操作按钮时按诊断结果自动选择：
> 权限问题走 L2、进程占用走 L1（勾选优先）、RM 未识别走深扫 + L3、瞬时锁走 L0。
> L4（重启后删除）作为极端兜底保留在 `strategies.py` 中。

> 拖放说明：界面非提权运行（中等完整性），与资源管理器同等级，因此使用 Qt 标准 OLE
> 拖放即可，无需任何 UIPI 消息放行补丁。旧版「提权 + 原生 WM_DROPFILES 通道」方案
> 在 Win11 26H2 上实测失效，已废弃。若个别环境仍无法拖放，用「添加路径」按钮
> （支持多选）或右键菜单兜底。

> 自身保护：路径若指向 shifu.exe 自身或指向自身的 `.lnk` 快捷方式（按 UTF-16LE / ANSI
> 字节匹配名称），会跳过并记日志；自检进程链内的 PID 一律不结束、不关句柄。
> L0/L1/L3 解锁后都只做删除探测，不再隐式删除——修复了此前「点仅解锁却把文件删掉」的问题。
> 真正的删除只在点红色按钮后发生，且走回收站（`FOF_ALLOWUNDO`），非提权 GUI 优先执行、
> 失败才回退提权 helper，保证与资源管理器同一用户上下文、回收站可还原。

## 右键菜单为何只有第二层

Win11 有两套**互相独立**的右键菜单，"显示更多选项"不是皮肤切换，而是从第一层跳到另一套菜单：

| | 第一层（新式 / XAML 菜单） | 第二层（经典 / Win10 菜单） |
| --- | --- | --- |
| 渲染 | `Windows.UI.FileExplorer.dll` 中的 packaged COM 类 | 传统 `IContextMenu` + shell32 菜单 |
| 谁进得来 | 系统内置命令；`IExplorerCommand` + **包身份**（MSIX 或 sparse package）；`EnumSubCommands` 提供原生折叠 | 手写注册表 `shell\verb\command`；`IContextMenu` COM 扩展；`SubCommands` + `CommandStore` 级联 |
| 实例 | 火绒安全软件、File Locksmith（PowerToys）、OneDrive、新建 | 7-Zip、发送到、打开方式、以及所有手写注册表项 |
| 释缚现状 | ❌ 进不来（无包身份、未实现 COM） | ✅ 三项平级，无折叠箭头 |

关键结论：

1. **手写注册表 verb 按设计只会被收进第二层**，与 GUI 用什么框架无关。微软 Learn 原文：
   "Use Show more options only to inspect legacy context-menu extensions. A command registered through `windows.fileExplorerContextMenus` and implemented with `IExplorerCommand` appears in the Windows 11 context menu."
2. **火绒 / File Locksmith 在第一层**：它们是打包应用或带 sparse package，用 `IExplorerCommand` 注册，并用 `EnumSubCommands` 得到原生折叠箭头。注册表里搜不到它们的菜单文字——注册在 manifest 里。
3. **7-Zip / 发送到在第二层能折叠**：靠 `SubCommands` + `MUIVerb` + `CommandStore`（微软 [官方文档](https://learn.microsoft.com/zh-cn/windows/win32/shell/how-to--create-cascading-menus-with-the-subcommands-registry-entry)）或自实现 `IContextMenu` 的 `QueryContextMenu` 插入 popup。
4. 本项目现在也用 `MUIVerb + SubCommands + CommandStore` 做成**级联子菜单**（在第二层经典菜单里可正常折叠）；但仍不进第一层——因为手写 verb 无论平级还是级联都是 legacy 扩展，这是系统设计不是 bug。
5. `CLSID {86ca1aa0-...}` 空默认值技巧是社区 hack（让 explorer 建不出新式菜单而回退经典菜单），微软无文档承诺，26H2 上可能失效；本项目不依赖它。经典菜单按 Shift + 右键唤出即可。

要进第一层需要：原生 C++ COM DLL 实现 `IExplorerCommand`（含 `EnumSubCommands`）+ MSIX/sparse package 提供包身份 + manifest 注册 `windows.fileExplorerContextMenus`；Python/PyInstaller 无法直接充当该 COM 组件。本项目的第二层折叠用 `MUIVerb` + `SubCommands`（HKCU 父键）+ `CommandStore`（HKLM 子 verb，需提权）实现，无需 COM。

> 另注：微软也提供 `ExtendedSubCommandsKey`，可把子项直接挂在父键下、全程写 HKCU 免提权；本项目选 CommandStore 是为了贴合官方 `SubCommands` 示例，代价是安装菜单时要提权一次。

## 技术栈

- Python 3.14
- PyQt6（GUI + 图标渲染，标准 OLE 拖放）
- psutil（进程信息 + helper watchdog）
- ctypes 直调 Win32 API（Restart Manager、NtQuerySystemInformation、DuplicateHandle、MoveFileEx、命名管道 + SDDL 等，零第三方封装）
- PyInstaller（GUI onefile / helper onedir）

图标（`assets/shifu.ico`，绿底圆角白字"解"）由 `tools/make_icon.py` 生成，改动样式后可重跑：

```bat
uv run python tools/make_icon.py
```

## 目录结构

```
shifu/
├── python/
│   ├── main.py             GUI 入口：解析命令行路径 + 启动非提权 GUI
│   ├── agent_main.py       提权 helper：命名管道 RPC + L0~L4 执行
│   ├── core/
│   │   ├── winapi.py       Win32 API 封装（RM / 句柄 / 权限 / 延迟删除 / 自身保护）
│   │   ├── ipc.py          命名管道客户端/服务端 + helper 拉起
│   │   ├── detector.py     锁定类型诊断
│   │   ├── strategies.py   L0~L4 与删除/重命名
│   │   └── models.py       数据模型
│   ├── ui/
│   │   └── main_window.py  PyQt6 主界面（标准拖放 + 懒提权）
│   ├── shell/
│   │   └── menu.py         右键菜单注册/卸载
│   ├── assets/
│   │   └── shifu.ico       应用图标（绿底圆角白字"解"）
│   ├── shifu.spec          GUI 打包（onefile，不提权）
│   └── shifu_agent.spec    helper 打包（onedir，requireAdministrator）
├── tools/
│   ├── build.bat           PyInstaller 打包脚本
│   └── make_icon.py        图标生成脚本
├── README.md
└── LICENSE
```

## 风险提示

- L1 结束进程、L3 强关句柄可能导致目标程序异常退出或数据丢失，请先保存相关工作。
- L2 会修改文件所有权与 ACL，仅建议对自己有管理权限的文件使用。
- 请勿对系统关键文件（如 `C:\Windows` 下）随意使用，以免破坏系统。

## 许可证

[MIT](LICENSE) © 2026 highwindmx

Powered by WorkBuddy
