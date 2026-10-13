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
                     L"filesystem", L"drivers", L"memory" };
        case ScanProfile::Quick:
            return { L"environment", L"prefetch", L"registry", L"persistence" };
        case ScanProfile::Processes:
            return { L"environment", L"memory" };
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
    if (name == L"drivers")     return modules::ScanDrivers();
    if (name == L"memory")      return modules::ScanProcessMemory({});
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

    // --- Итоговый мини-отчёт по маркерам HIGH / MEDIUM ------------------------
    // Собираем приоритетные строки из всех модулей в один блок в конце журнала,
    // чтобы ключевые маркеры (внедрения, следы выгрузки, конфиги, подозрительные
    // модули) были видны сразу, без прокрутки всего лога. Длинные списки
    // обрезаем, чтобы JIT-шум памяти не затопил отчёт.
    {
        std::vector<std::wstring> highs, meds;
        for (auto& m : results)
            for (auto& f : m.findings) {
                if (f.severity == Severity::High)
                    highs.push_back(L"[" + f.category + L"] " + f.title);
                else if (f.severity == Severity::Medium)
                    meds.push_back(L"[" + f.category + L"] " + f.title);
            }

        constexpr size_t kCap = 30;   // не более N строк на каждый уровень
        log.Info(L"──────────────── МИНИ-ОТЧЁТ ────────────────");
        if (highs.empty() && meds.empty()) {
            log.Info(L"Критичных (HIGH) и средних (MEDIUM) маркеров не обнаружено.");
        } else {
            log.Info(L"Маркеров: HIGH — " + std::to_wstring(highs.size()) +
                     L", MEDIUM — " + std::to_wstring(meds.size()) + L".");
            for (size_t i = 0; i < highs.size(); i++) {
                if (i >= kCap) { log.High(L"  … и ещё HIGH: " + std::to_wstring(highs.size() - kCap)); break; }
                log.High(L"  ● " + highs[i]);
            }
            for (size_t i = 0; i < meds.size(); i++) {
                if (i >= kCap) { log.Med(L"  … и ещё MEDIUM: " + std::to_wstring(meds.size() - kCap)); break; }
                log.Med(L"  ○ " + meds[i]);
            }
        }
        log.Info(L"─────────────────────────────────────────────");
    }

    log.Info(L"================ КОНЕЦ АУДИТА ================");

    running_.store(false);
    if (onDone) onDone(std::move(results));
}
