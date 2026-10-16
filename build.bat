@echo off
rem Builds ss.exe, ip.exe, ifconfig.exe into .\bin using MSVC (Visual Studio / Build Tools).
setlocal
cd /d "%~dp0"

where cl >nul 2>nul
if not errorlevel 1 goto build

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto novs
for /f "usebackq delims=" %%i in (`call "%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR goto novs
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul
where cl >nul 2>nul
if errorlevel 1 goto novs

:build
if not exist bin mkdir bin
if not exist build mkdir build
set CFLAGS=/nologo /O2 /Oi /GL /MT /W3 /utf-8 /std:c17 /DNDEBUG /Fo:build\
set LFLAGS=/link /LTCG /OPT:REF /OPT:ICF /INCREMENTAL:NO iphlpapi.lib ws2_32.lib
for %%t in (ss ip ifconfig) do (
    cl %CFLAGS% src\%%t.c src\common.c /Fe:bin\%%t.exe %LFLAGS% || exit /b 1
)
echo.
echo Built: bin\ss.exe bin\ip.exe bin\ifconfig.exe
exit /b 0

:novs
echo error: MSVC not found. Install "Visual Studio Build Tools" with the "Desktop development with C++" workload.
exit /b 1
