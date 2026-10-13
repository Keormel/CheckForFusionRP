// util.h — общие утилиты агента телеметрии: время, хэши, привилегии, строки.
#pragma once
#include <windows.h>
#include <shlobj.h>   // KNOWNFOLDERID / REFKNOWNFOLDERID
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace util {

// --- строки -----------------------------------------------------------------
std::wstring Widen(const std::string& s);
std::string  Narrow(const std::wstring& s);
std::wstring ToUpper(std::wstring s);
std::wstring Trim(const std::wstring& s);

// --- время ------------------------------------------------------------------
// FILETIME (100-нс интервалы с 1601) -> ISO-8601 UTC "YYYY-MM-DDTHH:MM:SSZ".
std::wstring FileTimeToIso(const FILETIME& ft);
std::wstring FileTimeToIso(uint64_t filetime100ns);
uint64_t     FileTimeToU64(const FILETIME& ft);
uint64_t     NowFileTime();                 // текущее время как FILETIME u64
std::wstring NowIso();

// --- файловая система -------------------------------------------------------
std::optional<std::vector<uint8_t>> ReadFileBytes(const std::wstring& path,
                                                  size_t maxBytes = 0);
std::optional<std::wstring> Sha256File(const std::wstring& path);   // hex, lower
std::optional<std::wstring> Sha256Bytes(const uint8_t* data, size_t len);
std::wstring ExpandEnv(const std::wstring& s);
std::wstring KnownFolder(REFKNOWNFOLDERID id);  // "" при ошибке

// --- привилегии / окружение -------------------------------------------------
bool IsElevated();
bool EnablePrivilege(const wchar_t* name);  // напр. SeDebugPrivilege

// JSON-экранирование одной строки (без кавычек по краям).
std::string JsonEscape(const std::wstring& s);

} // namespace util
