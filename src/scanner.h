// scanner.h — оркестратор сканирования. Запускает модули в фоновом потоке,
// стримит прогресс в Logger, по завершении отдаёт собранные ModuleResult.
#pragma once
#include "model.h"
#include <functional>
#include <string>
#include <vector>
#include <atomic>
#include <thread>

enum class ScanProfile {
    Full,       // все уровни
    Processes,  // только память процессов + окружение
    Quick,      // prefetch + persistence + registry (быстро, без хэшей FS)
};

// Событие прогресса по модулю (для GUI). Отдаётся дважды на модуль:
// при старте (finished=false) и по завершении (finished=true, со сводкой).
struct StepEvent {
    int index = 0;              // порядковый номер модуля в профиле (с 0)
    int total = 0;              // всего модулей в профиле
    std::wstring module;        // имя модуля ("prefetch", ...)
    bool finished = false;
    std::wstring status;        // "ok" / "skipped" / "error" (при finished)
    int findings = 0, high = 0, medium = 0, low = 0;
};

class Scanner {
public:
    using DoneCallback = std::function<void(std::vector<ModuleResult>)>;
    using StepCallback = std::function<void(const StepEvent&)>;

    ~Scanner();

    bool Running() const { return running_.load(); }

    // Список модулей профиля в порядке запуска.
    static std::vector<std::wstring> ModulesFor(ScanProfile profile);

    // Запускает скан в отдельном потоке. onStep/onDone вызываются из этого потока.
    void StartAsync(ScanProfile profile, DoneCallback onDone, StepCallback onStep = nullptr);
    void RequestStop() { stop_.store(true); }

private:
    void Run(ScanProfile profile, DoneCallback onDone, StepCallback onStep);

    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_{false};
};
