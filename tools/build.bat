@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0..\python"

echo [1/3] 构建 GUI（非提权 onefile）...
uv run python -m PyInstaller --clean --noconfirm shifu.spec
if errorlevel 1 goto :fail

echo [2/3] 构建提权 helper（onedir + requireAdministrator）...
uv run python -m PyInstaller --clean --noconfirm shifu_agent.spec
if errorlevel 1 goto :fail

echo [3/3] 复制图标资源到 dist 根目录...
if not exist "dist\assets" mkdir "dist\assets"
copy /Y "assets\shifu.ico" "dist\assets\shifu.ico" >nul

echo.
echo 构建完成：
echo   dist\shifu.exe                     GUI（非提权，拖放正常）
echo   dist\shifu_agent\shifu_agent.exe   提权 helper（点操作时弹一次 UAC）
echo.
echo 注意：若 exe 正被占用，PyInstaller 可能跳过覆盖但仍返回 0，
echo       请用文件时间戳确认产物已更新。
endlocal
exit /b 0

:fail
echo 构建失败。
endlocal
exit /b 1
