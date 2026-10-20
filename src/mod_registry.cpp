// mod_registry.cpp - Уровень 1: артефакты запуска из реестра.
//
// UserAssist: HKCU\...\Explorer\UserAssist\{GUID}\Count - имена значений
//   зашифрованы ROT13; содержат счётчик запусков, фокус и время последнего
//   запуска (структура UEME, 72 байта на Win7+). Пути вида "{KNOWNFOLDERID}\x.exe"
//   раскрываются в обычный путь; служебные записи UEME_CTL* пропускаются.
// AppCompatCache (ShimCache): HKLM\SYSTEM\CurrentControlSet\Control\Session
//   Manager\AppCompatCache\AppCompatCache - бинарный блоб. Разбираем формат
//   Windows 10/11 (заголовок 0x30/0x34, записи "10ts"): путь, время изменения
//   файла и позиция в кэше (0 = самая свежая запись). Для других форматов
//   фиксируем только наличие и размер. ShimCache пишется в реестр при
//   выключении ОС - записей текущего сеанса в нём ещё нет.

#include "modules.h"
#include "util.h"
#include "logger.h"
#include <windows.h>
#include <objbase.h>
#include <string>
#include <vector>
#include <cstring>

namespace {

std::wstring Rot13(const std::wstring& in) {
    std::wstring o = in;
    for (auto& c : o) {
        if (c >= L'a' && c <= L'z') c = L'a' + (c - L'a' + 13) % 26;
        else if (c >= L'A' && c <= L'Z') c = L'A' + (c - L'A' + 13) % 26;
    }
    return o;
}

// "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe" -> "C:\Windows\System32\cmd.exe"
std::wstring ResolveKnownFolderPath(const std::wstring& name) {
    if (name.size() < 39 || name[0] != L'{' || name[37] != L'}') return name;
    GUID id{};
    if (FAILED(CLSIDFromString(name.substr(0, 38).c_str(), &id))) return name;
    std::wstring base = util::KnownFolder(id);
    return base.empty() ? name : base + name.substr(38);
}

// Ключи UserAssist: какие GUID что означают.
const wchar_t* UserAssistKind(const std::wstring& guid) {
    std::wstring u = util::ToUpper(guid);
    if (u == L"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}") return L"executable";
    if (u == L"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}") return L"shortcut";
    return L"other";
}

void ReadUserAssist(ModuleResult& r, int& notable) {
    auto& log = Logger::Instance();
    const wchar_t* base = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    HKEY root;
    LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER, base, 0, KEY_READ, &root);
    if (rc != ERROR_SUCCESS) {
        log.Med(L"[registry] UserAssist недоступен (RegOpenKey HKCU\\...\\UserAssist вернул " +
                std::to_wstring(rc) + L") — "
                L"обычно это значит, что профиль пользователя заблокирован ОС или ключ отсутствует "
                L"(например, при запуске из-под SYSTEM вместо интерактивного пользователя).");
        return;
    }

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
            if (decoded.rfind(L"UEME_", 0) == 0) continue;   // служебные счётчики сеанса

            uint32_t runCount = 0, focusCount = 0, focusMs = 0; uint64_t lastRun = 0;
            if (dlen >= 68) {                 // структура UEME Win7+ (72 байта)
                memcpy(&runCount, data + 4, 4);
                memcpy(&focusCount, data + 8, 4);
                memcpy(&focusMs, data + 12, 4);
                memcpy(&lastRun, data + 60, 8); // FILETIME по 0x3C
            }

            std::wstring path = ResolveKnownFolderPath(decoded);
            std::wstring loc = util::LocationTag(path);

            Finding f;
            f.category = L"userassist";
            f.title = path;
            f.severity = util::IsNotableLocation(loc) ? Severity::Low : Severity::Info;
            if (f.severity == Severity::Low) notable++;
            f.set(L"name", decoded)
             .set(L"path", path)
             .set(L"location", loc)
             .set(L"kind", UserAssistKind(guid))
             .set(L"run_count", std::to_wstring(runCount))
             .set(L"focus_count", std::to_wstring(focusCount))
             .set(L"focus_time_sec", std::to_wstring(focusMs / 1000))
             .set(L"last_run", util::FileTimeToIso(lastRun))
             .set(L"guid", guid);
            r.findings.push_back(std::move(f));
        }
        RegCloseKey(k);
    }
    RegCloseKey(root);
}

template <typename T>
bool ReadAt(const std::vector<uint8_t>& b, size_t off, T& v) {
    if (off + sizeof(T) > b.size()) return false;
    memcpy(&v, b.data() + off, sizeof(T));
    return true;
}

// Формат Windows 10/11. Запись:
//   +0  "10ts"            +4  (не используется)   +8  размер данных записи
//   +12 длина пути (байт) +14 путь UTF-16
//   затем FILETIME изменения файла (8), размер доп. данных (4), доп. данные.
// Возвращает число разобранных записей или -1, если формат не распознан.
int ParseShimCacheWin10(const std::vector<uint8_t>& blob, ModuleResult& r, int& notable) {
    uint32_t hdr = 0;
    if (!ReadAt(blob, 0, hdr) || (hdr != 0x30 && hdr != 0x34)) return -1;

    int count = 0;
    size_t off = hdr;
    while (off + 14 <= blob.size()) {
        if (memcmp(blob.data() + off, "10ts", 4) != 0) break;
        uint32_t entrySize = 0; uint16_t pathLen = 0;
        ReadAt(blob, off + 8, entrySize);
        ReadAt(blob, off + 12, pathLen);
        size_t end = off + 12 + (size_t)entrySize;
        size_t p = off + 14;
        if (end > blob.size() || p + pathLen + 8 > end) break;

        std::wstring raw(pathLen / 2, L'\0');
        memcpy(raw.data(), blob.data() + p, (pathLen / 2) * 2);
        uint64_t modified = 0;
        ReadAt(blob, p + pathLen, modified);

        std::wstring path = util::ResolveDevicePath(raw);
        std::wstring loc = util::LocationTag(path);

        Finding f;
        f.category = L"shimcache";
        f.title = path;
        f.severity = util::IsNotableLocation(loc) ? Severity::Low : Severity::Info;
        if (f.severity == Severity::Low) notable++;
        f.set(L"path", path)
         .set(L"location", loc)
         .set(L"position", std::to_wstring(count))
         .set(L"file_modified", util::FileTimeToIso(modified));
        r.findings.push_back(std::move(f));

        count++;
        off = end;
    }
    return count;
}

void ReadAppCompatCache(ModuleResult& r, int& notable) {
    auto& log = Logger::Instance();
    HKEY k;
    const wchar_t* path = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &k) != ERROR_SUCCESS) {
        Finding f; f.category = L"shimcache"; f.title = L"AppCompatCache";
        f.severity = Severity::Low;
        f.set(L"status", L"нет доступа (нужны права администратора)");
        r.findings.push_back(std::move(f));
        log.Med(L"[registry] ShimCache: нет доступа (нужны права администратора)");
        return;
    }
    DWORD type = 0, sz = 0;
    RegQueryValueExW(k, L"AppCompatCache", nullptr, &type, nullptr, &sz);
    std::vector<uint8_t> blob(sz);
    if (sz && RegQueryValueExW(k, L"AppCompatCache", nullptr, &type, blob.data(), &sz) == ERROR_SUCCESS)
        blob.resize(sz);
    else
        blob.clear();
    RegCloseKey(k);

    int parsed = blob.empty() ? -1 : ParseShimCacheWin10(blob, r, notable);
    if (parsed >= 0) {
        log.Info(L"[registry] ShimCache: записей разобрано: " + std::to_wstring(parsed));
        return;
    }

    uint32_t hdr = 0; ReadAt(blob, 0, hdr);
    wchar_t hx[16]; swprintf(hx, 16, L"0x%X", hdr);
    Finding f; f.category = L"shimcache"; f.title = L"AppCompatCache";
    f.severity = Severity::Info;
    f.set(L"present", blob.empty() ? L"false" : L"true")
     .set(L"blob_size", std::to_wstring(blob.size()))
     .set(L"header", hx)
     .set(L"note", L"формат не распознан (не Windows 10/11) — разбор на сервере");
    r.findings.push_back(std::move(f));
    log.Med(std::wstring(L"[registry] ShimCache: формат с заголовком ") + hx + L" не поддерживается");
}

} // namespace

namespace modules {

ModuleResult ScanRegistryArtifacts() {
    ModuleResult r; r.module = L"registry"; r.status = L"ok";
    auto& log = Logger::Instance();

    int notableUa = 0, notableShim = 0;
    ReadUserAssist(r, notableUa);
    size_t uaCount = r.findings.size();
    log.Info(L"[registry] UserAssist: записей: " + std::to_wstring(uaCount));

    ReadAppCompatCache(r, notableShim);
    size_t shimCount = r.findings.size() - uaCount;

    if (notableUa + notableShim)
        log.Low(L"[registry] исполняемых из Temp/Загрузок: UserAssist " + std::to_wstring(notableUa) +
                L", ShimCache " + std::to_wstring(notableShim));
    r.note = L"userassist=" + std::to_wstring(uaCount) + L" shimcache=" + std::to_wstring(shimCount);
    return r;
}

} // namespace modules
