// logger.h — потокобезопасный лог. Воркер-поток пишет строки,
// GUI-поток получает их через колбэк (реализован как PostMessage в gui.cpp).
#pragma once
#include <string>
#include <functional>
#include <mutex>
#include "model.h"

class Logger {
public:
    using Sink = std::function<void(Severity, const std::wstring&)>;

    static Logger& Instance();

    void SetSink(Sink sink);
    void Log(Severity sev, const std::wstring& msg);

    void Info(const std::wstring& m)  { Log(Severity::Info, m); }
    void Low(const std::wstring& m)   { Log(Severity::Low, m); }
    void Med(const std::wstring& m)   { Log(Severity::Medium, m); }
    void High(const std::wstring& m)  { Log(Severity::High, m); }

private:
    std::mutex mtx_;
    Sink sink_;
};
