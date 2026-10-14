@echo off
REM ===========================================================================
REM  rebuild.bat — пересборка «в один клик».
REM  Двойной клик по файлу -> один раз «Да» в окне UAC -> готово.
REM
REM  Агент работает от администратора и держит свой .exe, поэтому обычный
REM  build.bat падает на линковке ("Permission denied"). Этот скрипт сам
REM  поднимает права, закрывает агент, ждёт разблокировки .exe, пересобирает
REM  и запускает свежий билд. Весь вывод дублируется в build\rebuild.log.
REM  Системные команды вызываются полным путём (%SystemRoot%\System32\...),
REM  чтобы не зависеть от PATH.
REM ===========================================================================
setlocal EnableExtensions
set "ROOT=%~dp0"
set "SYS=%SystemRoot%\System32"
cd /d "%ROOT%"

REM --- Самоповышение прав: если не админ — перезапуск через UAC ---------------
"%SYS%\net.exe" session >nul 2>&1
if %errorlevel% neq 0 (
    echo Требуются права администратора. Открываю запрос UAC — нажмите "Да"...
    "%SYS%\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%ROOT%"
if not exist "build" mkdir "build"
set "EXE=%ROOT%build\FusionForensics.exe"
set "LOG=%ROOT%build\rebuild.log"
echo rebuild %date% %time% > "%LOG%"

echo [1/4] Закрываю запущенный агент FusionForensics...
"%SYS%\taskkill.exe" /IM FusionForensics.exe /F >> "%LOG%" 2>&1

echo [2/4] Жду освобождения .exe...
set /a tries=0
:waitloop
if not exist "%EXE%" goto unlocked
del /f /q "%EXE%" >nul 2>&1
if not exist "%EXE%" goto unlocked
set /a tries+=1
if %tries% geq 25 (
    echo.
    echo ОШИБКА: .exe всё ещё заблокирован — агент не закрылся. Закройте его вручную.
    echo Лог: "%LOG%"
    echo.
    pause
    exit /b 1
)
"%SYS%\ping.exe" -n 2 127.0.0.1 >nul
goto waitloop
:unlocked

if exist "build\app_res.o" del /f /q "build\app_res.o" >nul 2>&1

echo [3/4] Собираю новый билд...
call "%ROOT%build.bat" >> "%LOG%" 2>&1
if errorlevel 1 (
    echo.
    echo ================= ПЕРЕСБОРКА НЕ УДАЛАСЬ =================
    echo --- последние строки лога ("%LOG%") ---
    "%SYS%\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Get-Content -LiteralPath '%LOG%' -Tail 15"
    echo.
    pause
    exit /b 1
)

echo [4/4] Готово. Запускаю свежий билд...
start "" "%EXE%"
echo.
echo ================= ПЕРЕСБОРКА ЗАВЕРШЕНА =================
for %%F in ("%EXE%") do echo Новый .exe: %%~tF   (%%~zF байт)
echo Полный лог: "%LOG%"
echo.
echo Окно можно закрыть.
pause
