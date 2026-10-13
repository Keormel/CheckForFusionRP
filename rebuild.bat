@echo off
REM ===========================================================================
REM  rebuild.bat — удаляет старый билд и собирает новый «с нуля».
REM
REM  Сам запрашивает права администратора (UAC), потому что агент запускается
REM  от админа и держит exe — без повышения прав получить "Permission denied".
REM  Шаги: завершить агента -> удалить старый билд -> собрать заново (build.bat).
REM ===========================================================================
setlocal

REM --- Самоповышение прав: если не админ — перезапускаем себя через UAC -------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Требуются права администратора. Запрашиваю повышение прав через UAC...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

echo [1/3] Завершаю запущенный агент FusionForensics (если открыт)...
taskkill /IM FusionForensics.exe /F >nul 2>&1
REM Небольшая пауза, чтобы ОС успела освободить файл после закрытия процесса.
ping -n 2 127.0.0.1 >nul

echo [2/3] Удаляю старый билд...
if exist "build\FusionForensics.exe" del /f /q "build\FusionForensics.exe"
if exist "build\app_res.o"          del /f /q "build\app_res.o"

echo [3/3] Собираю новый билд...
call "%~dp0build.bat"
if errorlevel 1 (
    echo.
    echo ================= ПЕРЕСБОРКА НЕ УДАЛАСЬ =================
    pause
    exit /b 1
)

echo.
echo ================= ПЕРЕСБОРКА ЗАВЕРШЕНА =================
echo Новый файл: build\FusionForensics.exe
echo Запускайте от администратора (манифест сам поднимет UAC).
pause
