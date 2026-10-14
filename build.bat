@echo off
REM ===========================================================================
REM  Build Fusion Forensics Agent (MinGW-w64 / UCRT64, C++20).
REM  Requires g++ from MSYS2 ucrt64. Override MINGW_BIN if installed elsewhere.
REM ===========================================================================
setlocal
if "%MINGW_BIN%"=="" set "MINGW_BIN=C:\msys64\ucrt64\bin"
set "PATH=%MINGW_BIN%;%PATH%"

cd /d "%~dp0"
set "OUT=build\FusionForensics.exe"
if not exist build mkdir build

echo [1/2] Compiling resources (manifest)...
windres src\app.rc -O coff -o build\app_res.o
if errorlevel 1 goto :err

echo [2/2] Compiling and linking...
REM -Wno-unknown-pragmas: #pragma comment(lib) is MSVC-only (we link via -l below)
REM -Wno-cast-function-type: GetProcAddress casts are the standard Win32 idiom
REM -static: bake libstdc++/libgcc/winpthread into the exe (no MinGW DLLs needed)
g++ -std=c++20 -O2 -municode -mwindows -static -Wall -Wextra -Wno-unknown-pragmas -Wno-cast-function-type ^
    src\main.cpp src\scanner.cpp src\logger.cpp src\util.cpp src\report.cpp src\guids.cpp ^
    src\mod_prefetch.cpp src\mod_registry.cpp src\mod_persistence.cpp ^
    src\mod_filesystem.cpp src\mod_drivers.cpp src\mod_memory.cpp ^
    src\mod_environment.cpp src\mod_tools.cpp src\mod_lua.cpp ^
    build\app_res.o ^
    -o "%OUT%" ^
    -lbcrypt -lwintrust -lshell32 -lole32 -lcomdlg32 -lgdi32 -luser32 -ladvapi32 -lntdll
if errorlevel 1 goto :err

echo.
echo Done: %OUT%
echo Run as administrator (the manifest requests UAC automatically).
goto :eof

:err
echo.
echo BUILD FAILED.
exit /b 1
