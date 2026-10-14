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

std::vector<std::wstring> Scanner::ModulesFor(ScanProfile profile) {
    switch (profile) {
        case ScanProfile::Full:
            return { L"environment", L"prefetch", L"registry", L"persistence",
                     L"filesystem", L"deleted", L"lua", L"drivers", L"memory", L"tools" };
        case ScanProfile::Quick:
            return { L"environment", L"prefetch", L"registry", L"persistence",
                     L"deleted", L"lua", L"tools" };
        case ScanProfile::Processes:
            return { L"environment", L"memory", L"tools" };
    }
    return {};
}

void Scanner::StartAsync(ScanProfile profile, DoneCallback onDone, StepCallback onStep) {
    if (running_.load()) return;
    if (worker_.joinable()) worker_.join();
    stop_.store(false);
    running_.store(true);
    worker_ = std::thread(&Scanner::Run, this, profile, std::move(onDone), std::move(onStep));
}

static ModuleResult RunModule(const std::wstring& name, uint64_t prefetchSince) {
    if (name == L"environment") return modules::ScanEnvironment();
    if (name == L"prefetch")    return modules::ScanPrefetch(prefetchSince);
    if (name == L"registry")    return modules::ScanRegistryArtifacts();
    if (name == L"persistence") return modules::ScanPersistence();
    if (name == L"filesystem")  return modules::ScanFilesystem({});
    if (name == L"deleted")     return modules::ScanDeletedFiles(prefetchSince);
    if (name == L"drivers")     return modules::ScanDrivers();
    if (name == L"memory")      return modules::ScanProcessMemory({});
    if (name == L"tools")       return modules::ScanCheatTools();
    if (name == L"lua")         return modules::ScanLuaCheats();
    ModuleResult r; r.module = name; r.status = L"error"; r.note = L"неизвестный модуль";
    return r;
}

void Scanner::Run(ScanProfile profile, DoneCallback onDone, StepCallback onStep) {
    auto& log = Logger::Instance();
    std::vector<ModuleResult> results;

    log.Info(L"================ НАЧАЛО АУДИТА ================");
    if (!util::IsElevated())
        log.Med(L"Агент запущен без прав администратора — часть артефактов ОС будет недоступна.");

    // окно времени для prefetch: последние 24 часа
    uint64_t dayAgo = util::NowFileTime() - (uint64_t)24 * 3600 * 10'000'000ull;

    auto plan = ModulesFor(profile);
    for (size_t i = 0; i < plan.size() && !stop_.load(); i++) {
        StepEvent ev;
        ev.index = (int)i; ev.total = (int)plan.size(); ev.module = plan[i];
        if (onStep) onStep(ev);

        log.Info(L"[" + plan[i] + L"] запуск модуля " + std::to_wstring(i + 1) + L"/" +
                 std::to_wstring(plan.size()));
        ULONGLONG t0 = GetTickCount64();
        results.push_back(RunModule(plan[i], dayAgo));
        ULONGLONG ms = GetTickCount64() - t0;

        const auto& m = results.back();
        ev.finished = true;
        ev.status = m.status;
        ev.findings = (int)m.findings.size();
        for (auto& f : m.findings) {
            if (f.severity == Severity::High)   ev.high++;
            if (f.severity == Severity::Medium) ev.medium++;
            if (f.severity == Severity::Low)    ev.low++;
        }
        if (onStep) onStep(ev);

        wchar_t took[32];
        swprintf(took, 32, L"%.1f", ms / 1000.0);
        std::wstring summary = L"[" + plan[i] + L"] готово за " + took + L" с: статус " + m.status +
                               L", фактов " + std::to_wstring(ev.findings);
        if (ev.high)   summary += L", HIGH " + std::to_wstring(ev.high);
        if (ev.medium) summary += L", MEDIUM " + std::to_wstring(ev.medium);
        if (m.status == L"ok") log.Info(summary);
        else                   log.Med(summary);   // причину модуль уже записал сам
    }

    int totalFindings = 0, highCount = 0;
    for (auto& m : results)
        for (auto& f : m.findings) { totalFindings++; if (f.severity == Severity::High) highCount++; }

    if (stop_.load())
        log.Med(L"Аудит остановлен пользователем.");
    log.Info(L"Итого фактов собрано: " + std::to_wstring(totalFindings) +
             L", приоритетных (HIGH): " + std::to_wstring(highCount));
    log.Info(L"================ КОНЕЦ АУДИТА ================");

    // --- МИНИ-ОТЧЁТ: важные маркеры (HIGH/MEDIUM) одним блоком в самом низу -----
    // Дублируем сюда только важные строки, что уже прошли выше по журналу, чтобы
    // сразу после аудита было видно, какие проверки критичны/средние — не листая
    // весь лог. Исполняемые регионы без MZ (JIT-код LuaJIT) не тащим: они High по
    // форме, но это шум, и в журнал как маркеры они не выносились.
    {
        auto noisyExec = [](const Finding& f) {
            if (f.category != L"memory") return false;
            auto it = f.fields.find(L"mz_header");     // поле есть только у exec-региона
            return it != f.fields.end() && it->second != L"true";
        };
        std::vector<std::wstring> highs, meds;
        for (auto& m : results)
            for (auto& f : m.findings) {
                if (noisyExec(f)) continue;
                if (f.severity == Severity::High)
                    highs.push_back(L"[" + f.category + L"] " + f.title);
                else if (f.severity == Severity::Medium)
                    meds.push_back(L"[" + f.category + L"] " + f.title);
            }

        constexpr size_t kCap = 40;   // не более N строк на каждый уровень
        log.Info(L"──────────────── МИНИ-ОТЧЁТ ────────────────");
        if (highs.empty() && meds.empty()) {
            log.Info(L"Важных маркеров (HIGH/MEDIUM) не обнаружено — чисто.");
        } else {
            log.Info(L"Важные маркеры:  HIGH — " + std::to_wstring(highs.size()) +
                     L",  MEDIUM — " + std::to_wstring(meds.size()) + L".");
            for (size_t i = 0; i < highs.size() && i < kCap; i++) log.High(L"  ● " + highs[i]);
            if (highs.size() > kCap)
                log.High(L"  … и ещё HIGH: " + std::to_wstring(highs.size() - kCap));
            for (size_t i = 0; i < meds.size() && i < kCap; i++) log.Med(L"  ○ " + meds[i]);
            if (meds.size() > kCap)
                log.Med(L"  … и ещё MEDIUM: " + std::to_wstring(meds.size() - kCap));
        }
        log.Info(L"═════════════════════════════════════════════");
    }

    running_.store(false);
    if (onDone) onDone(std::move(results));
}
