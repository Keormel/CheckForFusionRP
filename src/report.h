// report.h — сериализация собранных фактов в JSON для отправки на сервер.
#pragma once
#include "model.h"
#include <string>
#include <vector>

namespace report {

// Собирает единый JSON-отчёт (UTF-8). Метаданные хоста + массив модулей.
std::string BuildJson(const std::vector<ModuleResult>& results);

// Пишет JSON в файл. true при успехе.
bool WriteToFile(const std::wstring& path, const std::string& json);

// Контрольная сумма тела отчёта (SHA256 hex) — основа для подписи на сервере.
std::wstring Digest(const std::string& json);

} // namespace report
