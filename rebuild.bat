@echo off
REM ===========================================================================
REM  rebuild.bat — пересборка «в один клик».
REM
REM  Агент запускается от администратора и держит свой .exe, поэтому обычный
REM  build.bat падает на линковке с "Permission denied". Этот скрипт:
REM    1) сам поднимает права через UAC (нужно, чтобы закрыть админский агент);
REM    2) завершает запущенный агент и ЖДЁТ, пока ОС освободит .exe;
REM    3) удаляет старый билд и собирает заново (build.bat);
REM    4) пишет весь вывод в build\rebuild.log и запускает свежий билд.
REM  Достаточно двойного клика по файлу (и одного «Да» в окне UAC).
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

REM --- Самоповышение прав: если не админ — перезапускаем себя через UAC -------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Требуются права администратора. Запрашиваю повышение через UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
if not exist "build" mkdir "build"
set "EXE=%~dp0build\FusionForensics.exe"
set "LOG=%~dp0build\rebuild.log"
echo rebuild %date% %time% > "%LOG%"

echo [1/4] Завершаю запущенный агент FusionForensics (если открыт)...
taskkill /IM FusionForensics.exe /F >> "%LOG%" 2>&1

echo [2/4] Жду, пока ОС освободит .exe...
set /a tries=0
:waitloop
if not exist "%EXE%" goto unlocked
del /f /q "%EXE%" >nul 2>&1
if not exist "%EXE%" goto unlocked
set /a tries+=1
if %tries% geq 25 (
    echo.
    echo ОШИБКА: .exe всё ещё заблокирован ^(агент не закрылся^). Закройте его вручную.
    echo Подробности: "%LOG%"
    pause
    exit /b 1
)
REM пауза ~0.5 с между попытками
ping -n 2 127.0.0.1 >nul
goto waitloop
:unlocked

if exist "build\app_res.o" del /f /q "build\app_res.o" >nul 2>&1

echo [3/4] Собираю новый билд...
call "%~dp0build.bat" >> "%LOG%" 2>&1
if errorlevel 1 (
    echo.
    echo ================= ПЕРЕСБОРКА НЕ УДАЛАСЬ =================
    echo Лог сборки: "%LOG%"
    echo --- последние строки ---
    powershell -NoProfile -Command "Get-Content -LiteralPath '%LOG%' -Tail 15"
    pause
    exit /b 1
)

echo [4/4] Готово. Запускаю свежий билд...
start "" "%EXE%"
echo.
echo ================= ПЕРЕСБОРКА ЗАВЕРШЕНА =================
echo Новый файл: %EXE%
echo Полный лог: "%LOG%"
REM окно закроется само через 3 секунды (без лишних нажатий)
timeout /t 3 >nul
