// logger.cpp
#include "logger.h"

Logger& Logger::Instance() {
    static Logger inst;
    return inst;
}

void Logger::SetSink(Sink sink) {
    std::lock_guard<std::mutex> lk(mtx_);
    sink_ = std::move(sink);
}

void Logger::Log(Severity sev, const std::wstring& msg) {
    Sink s;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        s = sink_;
    }
    if (s) s(sev, msg);
}
