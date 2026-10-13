@echo off
REM ============================================================================
REM  Сборка Fusion Forensics Agent (MinGW-w64 / UCRT64, C++20).
REM  Требуется g++ из MSYS2 ucrt64. Укажите путь к bin в MINGW_BIN при необходимости.
REM ============================================================================
setlocal
if "%MINGW_BIN%"=="" set "MINGW_BIN=C:\msys64\ucrt64\bin"
set "PATH=%MINGW_BIN%;%PATH%"

set "OUT=build\FusionForensics.exe"
if not exist build mkdir build

echo [1/2] Компиляция ресурсов (манифест)...
windres src\app.rc -O coff -o build\app_res.o
if errorlevel 1 goto :err

echo [2/2] Компиляция и линковка...
g++ -std=c++20 -O2 -municode -mwindows -Wall -Wextra ^
    src\main.cpp src\scanner.cpp src\logger.cpp src\util.cpp src\report.cpp src\guids.cpp ^
    src\mod_prefetch.cpp src\mod_registry.cpp src\mod_persistence.cpp ^
    src\mod_filesystem.cpp src\mod_drivers.cpp src\mod_memory.cpp ^
    src\mod_environment.cpp ^
    build\app_res.o ^
    -o "%OUT%" ^
    -lbcrypt -lwintrust -lshell32 -lole32 -lcomdlg32 -lgdi32 -luser32 -ladvapi32 -lntdll
if errorlevel 1 goto :err

echo.
echo Готово: %OUT%
echo Запускайте от имени администратора (манифест запросит UAC автоматически).
goto :eof

:err
echo.
echo СБОРКА НЕ УДАЛАСЬ.
exit /b 1
