# Fusion Forensics — Endpoint Telemetry Agent

Лёгкий агент сбора криминалистической телеметрии для серверов Garry's Mod
(Source Engine), построенный по принципу **поиска артефактов и следов присутствия
в ОС**, а не сигнатурного поиска в памяти.

**Философия:** агент собирает *факты*, не выносит вердикт. Решение «чист / не чист»
принимает сервер-парсер, сверяя телеметрию со своей базой хэшей, сигнатур и
паттернов. Клиент только защищает честность сбора (подпись отчёта) и фиксирует
условия сбора (права, отладчик).

> ⚠️ Запускать только на машинах, где у вас есть согласие игрока на проверку
> (screenshare/форензик). Это оборонительный инструмент античита, а не средство
> скрытного наблюдения.

---

## Что уже реализовано

| Уровень | Модуль | Файл | Статус |
|--------|--------|------|--------|
| GUI | Лаунчер, тёмно-фиолетовая тема, лог реального времени, статус-бар | `main.cpp` | ✅ |
| 1 | **Prefetch** (`*.pf`, распаковка MAM/XPRESS Huffman, SCCA v17–31) | `mod_prefetch.cpp` | ✅ |
| 1 | **Registry**: UserAssist (ROT13 + время/счётчик), AppCompatCache (факт наличия) | `mod_registry.cpp` | ✅ |
| 2 | **Memory**: `VirtualQueryEx`-обход, RWX / private-exec / код вне модулей, сигнатура MZ | `mod_memory.cpp` | ✅ |
| 3 | **Filesystem**: рекурсивный обход Temp/Downloads/garrysmod, SHA256, пометки расположения | `mod_filesystem.cpp` | ✅ |
| 3 | **Persistence**: Run/RunOnce (HKCU/HKLM/Wow64), Startup, Планировщик | `mod_persistence.cpp` | ✅ |
| 4 | **Drivers**: `NtQuerySystemInformation(SystemModuleInformation)` + проверка подписи | `mod_drivers.cpp` | ✅ |
| — | **Environment**: отладчик (IsDebuggerPresent/PEB), права, USBSTOR | `mod_environment.cpp` | ✅ |
| — | **Report**: единый JSON + SHA256-дайджест (основа подписи) | `report.cpp` | ✅ |

Инфраструктура: `util.*` (хэши через BCrypt, время, привилегии), `logger.*`
(потокобезопасный лог → GUI), `scanner.*` (оркестратор в фоновом потоке),
`model.h` (единая модель `Finding`).

---

## Сборка

Нужен **MSYS2 / MinGW-w64 (UCRT64)** с `g++` 13+ (проверено на 15.2.0, C++20).

```bat
REM из корня проекта; при нестандартном пути задайте MINGW_BIN
set MINGW_BIN=C:\msys64\ucrt64\bin
build.bat
```

Либо вручную (одной строкой):

```bat
set PATH=C:\msys64\ucrt64\bin;%PATH%
windres src\app.rc -O coff -o build\app_res.o
g++ -std=c++20 -O2 -municode -mwindows src\*.cpp build\app_res.o -o build\FusionForensics.exe ^
    -lbcrypt -lwintrust -lshell32 -lole32 -lcomdlg32 -lgdi32 -luser32 -ladvapi32 -lntdll
```

> `src\*.cpp` подхватит все модули, включая `guids.cpp` — он обязателен: в MinGW
> без него `FOLDERID_*` дают undefined reference.

Результат: `build\FusionForensics.exe`.

## Запуск

Манифест (`app.manifest`) запрашивает права администратора — Windows покажет UAC.
Без администратора агент работает, но Prefetch, ShimCache, список драйверов и
память `gmod.exe`/`hl2.exe` будут недоступны (модули честно вернут `status=skipped`).

Кнопки:
- **Запуск аудита системы** — все уровни (1–4).
- **Проверка процессов** — только память игры + окружение.
- **Быстрый скан** — Prefetch + реестр + автозагрузка (без хэширования ФС).
- **Экспорт отчёта** — сохраняет собранные факты в JSON (с SHA256-дайджестом).

---

## Лаунчер FusionRP#2

Отдельное нативное окно-оболочка (`launcher/`) в тёмно-фиолетовой теме с
собственной иконкой. Запускается **без прав администратора** и служит точкой
входа для игрока:

- **НАЧАТЬ ПРОВЕРКУ** — поднимает агент `FusionForensics.exe` с правами
  администратора (UAC через `ShellExecuteEx "runas"`).
- Пока агент работает, лаунчер показывает **анимацию прогресса** и следит за
  процессом агента; когда тот закрывается — **автоматически открывает свежий
  отчёт** `report_latest.json` (агент сохраняет его рядом с собой после каждого
  скана).
- **Открыть отчёт…** — ручной выбор любого `*.json` отчёта.

Сборка:

```bat
cd launcher
build_launcher.bat        REM -> launcher\out\FusionRP2.exe
```

Папка `launcher\out\` — готовый бандл: `FusionRP2.exe` + `FusionForensics.exe`
рядом (лаунчер также ищет агент в `..\build\` и `..\..\build\`).

Файлы лаунчера: `FusionRP2.cpp`, `launcher.manifest` (asInvoker + visual styles),
`launcher.rc` + `fusionrp2.ico`, `build_launcher.bat`.

---

## Формат отчёта (JSON)

```jsonc
{
  "schema": "forensics-agent/1",
  "host": "MAINPC", "user": "player", "collected_at": "2026-10-13T17:24:53Z",
  "elevated": false,
  "modules": [
    { "module": "prefetch", "status": "ok", "note": "parsed=312",
      "findings": [
        { "title": "GMOD.EXE", "severity": "INFO",
          "fields": { "executable": "GMOD.EXE", "run_count": "42",
                      "last_run": "2026-10-13T16:37:44Z", "pf_file": "GMOD.EXE-XXXX.pf" } }
      ] }
  ]
}
```

`severity` — только приоритет для внимания аналитика, **не** приговор. Сервер
принимает решение сам. SHA256-дайджест тела — основа криптоподписи при отправке.

---

## Дорожная карта (следующие шаги)

### Шаг A — серверная подпись и транспорт (приоритет)
Сейчас агент считает SHA256 отчёта. Нужно добавить асимметричную подпись, чтобы
читер не мог подменить отчёт:
1. На сервере — пара ключей Ed25519/ECDSA (P-256). Публичный зашит в агента.
2. Агент получает от сервера одноразовый **nonce** (против replay), кладёт его в
   отчёт, подписывает тело приватным *сессионным* ключом, выданным при хендшейке.
3. Транспорт — TLS + доп. подпись тела (HMAC/ECDSA) в заголовке. BCrypt уже
   подключён (`util.cpp`) — там же добавить `BCryptSignHash`.

### Шаг B — завершить Prefetch и Registry на сервере
- Перенести детальный разбор **AppCompatCache/ShimCache** на сервер (формат
  зависит от билда ОС: Win10 1709+ vs 11 24H2). Агент уже шлёт сырой блоб и размер.
- **Amcache.hve**: подключать куст через `RegLoadAppKeyW` и читать
  `Root\InventoryApplicationFile` → SHA1 + путь. Добавить как `mod_amcache.cpp`.

### Шаг C — усилить Memory Forensics (Уровень 2)
- **Проверка хуков**: читать первые 5–16 байт экспортируемых функций отрисовки
  (`Present`/`SwapBuffers`), сети (`send`/`recv`) и Lua (`lua_pcall`, `luaL_loadbuffer`)
  и сверять с «чистыми» байтами из образа на диске; `0xE9`/`0xFF25` в начале → хук.
  Базис уже есть: сопоставление регионов с модулями.
- **Ручной обход PEB** `Ldr.InLoadOrderModuleList` и сверка с Toolhelp —
  модуль, присутствующий в памяти, но отсутствующий в списке = «расслинкованный».
  Сейчас реализован обратный признак (код вне модулей); добавить прямой обход PEB
  через `NtQueryInformationProcess(ProcessBasicInformation)` → `ReadProcessMemory`.
- **Дамп подозрительного региона** (первые 4 КБ) в отчёт для анализа на сервере.

### Шаг D — Garry's Mod-специфика
- Распарсить `steamapps/libraryfolders.vdf`, чтобы находить установку GMod на
  любом диске (сейчас перебираем C:–H: по типовым путям).
- Снимать список подписанных на сервере аддонов и workshop-кэш (`.gma`), сверять
  с серверным манифестом.
- Дамп `garrysmod/data/` и Lua-кэша для сверки хэшей известных читов (Lmaobox-подобные
  скрипты, autorun-инъекторы).

### Шаг E — серверный парсер (отдельный сервис)
- Приём JSON → валидация подписи и nonce → нормализация.
- Сверка: хэши файлов/драйверов с базой известных читов; неподписанные драйверы;
  RWX-регионы; расположения в Temp; аномальные записи автозагрузки.
- Выдача админу агрегированного вердикта с весами и ссылками на конкретные факты.
- Хранение истории по SteamID для ретроспективы.

### Шаг F — эксплуатационное
- Подписать сам `.exe` (code signing) — иначе SmartScreen/антивирусы будут ругаться.
- Логи с ротацией, офлайн-режим (сохранить отчёт, отправить позже).
- CMake-проект и CI-сборка вместо `build.bat`.

---

## Структура

```
src/
  main.cpp              Win32 GUI (тёмно-фиолетовая тема) + точка входа
  scanner.{h,cpp}       оркестратор, фоновый поток, профили сканов
  logger.{h,cpp}        потокобезопасный лог → GUI
  model.h               Finding / ModuleResult / Severity
  report.{h,cpp}        сериализация JSON + SHA256-дайджест
  util.{h,cpp}          BCrypt-хэши, время, привилегии, JSON-escape
  guids.cpp             инстанцирование FOLDERID_* (нужно для MinGW)
  mod_prefetch.cpp      Уровень 1 — Prefetch
  mod_registry.cpp      Уровень 1 — UserAssist / ShimCache
  mod_memory.cpp        Уровень 2 — память процесса (только чтение)
  mod_filesystem.cpp    Уровень 3 — обход ФС + SHA256
  mod_persistence.cpp   Уровень 3 — автозагрузка
  mod_drivers.cpp       Уровень 4 — драйверы ядра + подписи
  mod_environment.cpp   окружение агента + USBSTOR
  app.manifest, app.rc  запрос прав администратора + DPI awareness
build.bat               сборка через MinGW/UCRT64
```
