@echo off
setlocal
cd /d "%~dp0.."
set "DIST=%CD%\dist"
set "SLIM=%CD%\dist-slim"

echo [1/6] Clean dist and dist-slim...
if exist "%DIST%" rmdir /S /Q "%DIST%"
if exist "%SLIM%" rmdir /S /Q "%SLIM%"
mkdir "%DIST%"
mkdir "%SLIM%"

echo [2/6] Publish GUI - self-contained single file (111MB, runs anywhere)...
dotnet publish src\Shifu\Shifu.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -o "%DIST%"
if errorlevel 1 goto :fail

echo [3/6] Publish helper - self-contained single file (71MB)...
dotnet publish src\Shifu.Agent\Shifu.Agent.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -o "%DIST%\shifu-agent"
if errorlevel 1 goto :fail

echo [4/6] Publish GUI - framework-dependent single file (slim, needs .NET 10 Desktop Runtime)...
dotnet publish src\Shifu\Shifu.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:DebugType=none -o "%SLIM%"
if errorlevel 1 goto :fail

echo [5/6] Publish helper - framework-dependent single file (slim)...
dotnet publish src\Shifu.Agent\Shifu.Agent.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -p:DebugType=none -o "%SLIM%\shifu-agent"
if errorlevel 1 goto :fail

echo [6/6] Copy icon to both dist trees...
if not exist "%DIST%\assets" mkdir "%DIST%\assets"
if not exist "%SLIM%\assets" mkdir "%SLIM%\assets"
copy /Y "src\Shifu\assets\shifu.ico" "%DIST%\assets\shifu.ico" >nul
copy /Y "src\Shifu\assets\shifu.ico" "%SLIM%\assets\shifu.ico" >nul

echo.
echo Build done:
echo   %DIST%\shifu.exe                      GUI full   (self-contained, ~111MB)
echo   %DIST%\shifu-agent\shifu-agent.exe    helper full (self-contained, ~71MB)
echo   %SLIM%\shifu.exe                      GUI slim   (~300KB, requires .NET 10 Desktop Runtime)
echo   %SLIM%\shifu-agent\shifu-agent.exe    helper slim
echo.
echo Keep the two-exe relative layout in each tree; GUI locates helper by this path.
echo Slim build requires .NET 10 Desktop Runtime on the target machine.
endlocal
exit /b 0

:fail
echo Build FAILED.
endlocal
exit /b 1
