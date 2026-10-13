// scanner.cpp
#include "scanner.h"
#include "modules.h"
#include "report.h"
#include "logger.h"
#include "util.h"
#include <windows.h>

Scanner::~Scanner() {
    stop_.store(true);
    if (worker_.joinable()) worker_.join();
}

void Scanner::StartAsync(ScanProfile profile, DoneCallback onDone) {
    if (running_.load()) return;
    if (worker_.joinable()) worker_.join();
    stop_.store(false);
    running_.store(true);
    worker_ = std::thread(&Scanner::Run, this, profile, std::move(onDone));
}

void Scanner::Run(ScanProfile profile, DoneCallback onDone) {
    auto& log = Logger::Instance();
    std::vector<ModuleResult> results;

    log.Info(L"================ НАЧАЛО АУДИТА ================");
    if (!util::IsElevated())
        log.Med(L"Агент запущен без прав администратора — часть артефактов ОС будет недоступна.");

    auto step = [&](const wchar_t* name, auto fn) {
        if (stop_.load()) return;
        log.Info(std::wstring(L"→ модуль: ") + name);
        results.push_back(fn());
    };

    // окно времени для prefetch: последние 24 часа
    uint64_t dayAgo = util::NowFileTime() - (uint64_t)24 * 3600 * 10'000'000ull;

    if (profile == ScanProfile::Full || profile == ScanProfile::Quick) {
        step(L"environment", [] { return modules::ScanEnvironment(); });
        step(L"prefetch",    [&] { return modules::ScanPrefetch(dayAgo); });
        step(L"registry",    [] { return modules::ScanRegistryArtifacts(); });
        step(L"persistence", [] { return modules::ScanPersistence(); });
    }
    if (profile == ScanProfile::Full) {
        step(L"filesystem", [] { return modules::ScanFilesystem({}); });
        step(L"drivers",    [] { return modules::ScanDrivers(); });
        step(L"memory",     [] { return modules::ScanProcessMemory({}); });
    }
    if (profile == ScanProfile::Processes) {
        step(L"environment", [] { return modules::ScanEnvironment(); });
        step(L"memory",      [] { return modules::ScanProcessMemory({}); });
    }

    int totalFindings = 0, highCount = 0;
    for (auto& m : results)
        for (auto& f : m.findings) { totalFindings++; if (f.severity == Severity::High) highCount++; }

    if (stop_.load())
        log.Med(L"Аудит остановлен пользователем.");
    log.Info(L"Итого фактов собрано: " + std::to_wstring(totalFindings) +
             L", приоритетных (HIGH): " + std::to_wstring(highCount));
    log.Info(L"================ КОНЕЦ АУДИТА ================");

    running_.store(false);
    if (onDone) onDone(std::move(results));
}
