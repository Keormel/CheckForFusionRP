// modules.h — публичный интерфейс всех модулей сбора телеметрии.
// Каждый модуль читает артефакты ОС и возвращает факты. Решений не принимает.
#pragma once
#include "model.h"
#include <cstdint>

namespace modules {

// Уровень 1 — артефакты выполнения.
ModuleResult ScanPrefetch(uint64_t sinceFileTime);   // 0 = без фильтра по времени
ModuleResult ScanRegistryArtifacts();                // UserAssist + AppCompatCache (наличие)

// Уровень 2 — память процессов (только чтение, детекция аномалий).
ModuleResult ScanProcessMemory(const std::vector<std::wstring>& targetNames);

// Уровень 3 — файловая система и автозагрузка.
ModuleResult ScanFilesystem(const std::vector<std::wstring>& roots);
ModuleResult ScanPersistence();                      // Run/RunOnce, Startup, задачи

// Уровень 4 — драйверы и окружение.
ModuleResult ScanDrivers();

// Самодиагностика окружения агента (телеметрия, не "защита").
ModuleResult ScanEnvironment();

// Сторонний инструментарий: читы, инъекторы, отладчики, редакторы памяти,
// AutoHotkey/AutoIt и прочие средства автоматизации (процессы, окна, файлы).
ModuleResult ScanCheatTools();

// Lua-читы Garry's Mod: autorun/data-скрипты (контент-анализ), бинарные модули.
ModuleResult ScanLuaCheats();

} // namespace modules
