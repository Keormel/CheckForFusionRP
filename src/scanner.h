// scanner.h — оркестратор сканирования. Запускает модули в фоновом потоке,
// стримит прогресс в Logger, по завершении отдаёт собранные ModuleResult.
#pragma once
#include "model.h"
#include <functional>
#include <vector>
#include <atomic>
#include <thread>

enum class ScanProfile {
    Full,       // все уровни
    Processes,  // только память процессов + окружение
    Quick,      // prefetch + persistence + registry (быстро, без хэшей FS)
};

class Scanner {
public:
    using DoneCallback = std::function<void(std::vector<ModuleResult>)>;

    ~Scanner();

    bool Running() const { return running_.load(); }

    // Запускает скан в отдельном потоке. onDone вызывается из этого потока.
    void StartAsync(ScanProfile profile, DoneCallback onDone);
    void RequestStop() { stop_.store(true); }

private:
    void Run(ScanProfile profile, DoneCallback onDone);

    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_{false};
};
