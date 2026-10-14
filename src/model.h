// model.h - единая модель факта (Finding). Агент НЕ выносит вердикт:
// severity здесь - это только приоритет для внимания аналитика, а не "бан".
#pragma once
#include <string>
#include <vector>
#include <map>

enum class Severity { Info, Low, Medium, High };

inline const wchar_t* SeverityName(Severity s) {
    switch (s) {
        case Severity::Info:   return L"INFO";
        case Severity::Low:    return L"LOW";
        case Severity::Medium: return L"MEDIUM";
        case Severity::High:   return L"HIGH";
    }
    return L"INFO";
}

// Один собранный факт. category = модуль ("prefetch","drivers",...).
// fields - произвольные пары ключ/значение (путь, хэш, время, счётчик и т.п.).
struct Finding {
    std::wstring category;
    std::wstring title;
    Severity     severity = Severity::Info;
    std::map<std::wstring, std::wstring> fields;

    Finding& set(const std::wstring& k, const std::wstring& v) { fields[k] = v; return *this; }
};

// Результат одного модуля сканирования.
struct ModuleResult {
    std::wstring module;          // имя модуля
    std::wstring status;          // "ok" / "skipped" / "error"
    std::wstring note;            // пояснение (напр. "требуются права администратора")
    std::vector<Finding> findings;
};
