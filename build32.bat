@echo off
REM ===========================================================================
REM  Build Fusion Forensics Agent - 32-bit x86 (MinGW-w64 MINGW32, C++20).
REM  Produces an x86 exe that runs on 32-bit Windows and on 64-bit via WOW64.
REM  Requires the i686 toolchain from MSYS2: pacman -S mingw-w64-i686-gcc
REM  Override MINGW32_BIN if installed elsewhere.
REM ===========================================================================
setlocal
if "%MINGW32_BIN%"=="" set "MINGW32_BIN=C:\msys64\mingw32\bin"
set "PATH=%MINGW32_BIN%;%PATH%"

cd /d "%~dp0"
set "OUT=build\FusionForensics32.exe"
if not exist build mkdir build

echo [1/2] Compiling resources (manifest, 32-bit)...
windres src\app.rc -O coff -o build\app_res32.o
if errorlevel 1 goto :err

echo [2/2] Compiling and linking (32-bit)...
REM -D_WIN32_WINNT=0x0A00: match the ucrt64 default Windows version so headers
REM expose Win8+ fields such as WINTRUST_CATALOG_INFO.hCatAdmin on mingw32 too.
g++ -std=c++20 -O2 -municode -mwindows -static -s ^
    -D_WIN32_WINNT=0x0A00 ^
    -fvisibility=hidden -fvisibility-inlines-hidden ^
    -ffunction-sections -fdata-sections ^
    -Wall -Wextra -Wno-unknown-pragmas -Wno-cast-function-type ^
    src\main.cpp src\scanner.cpp src\logger.cpp src\util.cpp src\report.cpp src\guids.cpp ^
    src\mod_prefetch.cpp src\mod_registry.cpp src\mod_persistence.cpp ^
    src\mod_filesystem.cpp src\mod_drivers.cpp src\mod_memory.cpp ^
    src\mod_deleted.cpp ^
    src\mod_environment.cpp src\mod_tools.cpp src\mod_lua.cpp ^
    build\app_res32.o ^
    -o "%OUT%" ^
    -Wl,--strip-all,--gc-sections ^
    -lbcrypt -lwintrust -lshell32 -lole32 -lcomdlg32 -lgdi32 -lgdiplus -luser32 -ladvapi32 -lntdll
if errorlevel 1 goto :err

echo.
echo Done: %OUT%
echo Run as administrator (the manifest requests UAC automatically).
goto :eof

:err
echo.
echo BUILD FAILED.
exit /b 1
