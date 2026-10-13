// mod_registry.cpp — Уровень 1: артефакты запуска из реестра.
//
// UserAssist: HKCU\...\Explorer\UserAssist\{GUID}\Count — имена значений
//   зашифрованы ROT13; содержат счётчик запусков и время последнего запуска
//   (структура UEME, FILETIME по смещению 0x3C в блоке 72 байта на Win7+).
// AppCompatCache (ShimCache): HKLM\SYSTEM\CurrentControlSet\Control\
//   Session Manager\AppCompatCache\AppCompatCache — бинарный блоб. Полный
//   разбор версионно-зависим; здесь фиксируем факт наличия и размер (сырой
//   блоб уходит на сервер для детального парсинга там).

#include "modules.h"
#include "util.h"
#include "logger.h"
#include <windows.h>
#include <string>
#include <vector>

namespace {

std::wstring Rot13(const std::wstring& in) {
    std::wstring o = in;
    for (auto& c : o) {
        if (c >= L'a' && c <= L'z') c = L'a' + (c - L'a' + 13) % 26;
        else if (c >= L'A' && c <= L'Z') c = L'A' + (c - L'A' + 13) % 26;
    }
    return o;
}

void ReadUserAssist(ModuleResult& r) {
    const wchar_t* base = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    HKEY root;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, base, 0, KEY_READ, &root) != ERROR_SUCCESS) return;

    DWORD gi = 0; wchar_t guid[256];
    for (;;) {
        DWORD glen = 256;
        if (RegEnumKeyExW(root, gi++, guid, &glen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

        std::wstring countPath = std::wstring(guid) + L"\\Count";
        HKEY k;
        if (RegOpenKeyExW(root, countPath.c_str(), 0, KEY_READ, &k) != ERROR_SUCCESS) continue;

        DWORD vi = 0; wchar_t name[2048]; BYTE data[4096];
        for (;;) {
            DWORD nlen = 2048, dlen = sizeof(data), type = 0;
            LONG rc = RegEnumValueW(k, vi++, name, &nlen, nullptr, &type, data, &dlen);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) break;

            std::wstring decoded = Rot13(name);
            uint32_t runCount = 0; uint64_t lastRun = 0;
            if (dlen >= 68) {                 // структура UEME Win7+ (72 байта)
                memcpy(&runCount, data + 4, 4);
                memcpy(&lastRun, data + 60, 8); // FILETIME по 0x3C
            }

            Finding f;
            f.category = L"userassist";
            f.title = decoded;
            f.severity = Severity::Info;
            f.set(L"name", decoded)
             .set(L"run_count", std::to_wstring(runCount))
             .set(L"last_run", util::FileTimeToIso(lastRun))
             .set(L"guid", guid);
            r.findings.push_back(std::move(f));
        }
        RegCloseKey(k);
    }
    RegCloseKey(root);
}

void ReadAppCompatCache(ModuleResult& r) {
    HKEY k;
    const wchar_t* path = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &k) != ERROR_SUCCESS) {
        Finding f; f.category = L"shimcache"; f.title = L"AppCompatCache";
        f.severity = Severity::Low;
        f.set(L"status", L"нет доступа (нужны права администратора)");
        r.findings.push_back(std::move(f));
        return;
    }
    DWORD type = 0, sz = 0;
    RegQueryValueExW(k, L"AppCompatCache", nullptr, &type, nullptr, &sz);
    Finding f; f.category = L"shimcache"; f.title = L"AppCompatCache";
    f.severity = Severity::Info;
    f.set(L"present", sz ? L"true" : L"false")
     .set(L"blob_size", std::to_wstring(sz))
     .set(L"note", L"сырой блоб парсится на сервере (формат зависит от версии ОС)");
    r.findings.push_back(std::move(f));
    RegCloseKey(k);
}

} // namespace

namespace modules {

ModuleResult ScanRegistryArtifacts() {
    ModuleResult r; r.module = L"registry"; r.status = L"ok";
    auto& log = Logger::Instance();
    ReadUserAssist(r);
    ReadAppCompatCache(r);
    log.Info(L"[registry] артефактов реестра (UserAssist+ShimCache): " +
             std::to_wstring((int)r.findings.size()));
    r.note = L"items=" + std::to_wstring((int)r.findings.size());
    return r;
}

} // namespace modules
