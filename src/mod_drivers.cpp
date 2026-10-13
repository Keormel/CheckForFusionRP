// mod_drivers.cpp — Уровень 4: аудит загруженных модулей ядра.
//
// NtQuerySystemInformation(SystemModuleInformation) отдаёт список всех
// загруженных драйверов (.sys) с базовым адресом, размером и путём. Для каждого
// проверяем цифровую подпись через WinVerifyTrust. Неподписанные / с необычным
// путём драйверы — приоритетная телеметрия для аналитика (но НЕ вердикт).
//
// Нужны права администратора для полноты данных о путях.

#include "modules.h"
#include "util.h"
#include "logger.h"
#include <windows.h>
#include <winternl.h>
#include <softpub.h>
#include <wintrust.h>
#include <mscat.h>
#include <vector>
#include <string>

#pragma comment(lib, "wintrust.lib")

namespace {

constexpr ULONG SystemModuleInformation = 11;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

typedef NTSTATUS (WINAPI *PFN_NQSI)(ULONG, PVOID, ULONG, PULONG);

// Путь в стиле ядра -> путь Win32 (приблизительно).
std::wstring NormalizeDriverPath(const std::string& raw) {
    std::wstring p = util::Widen(raw);
    wchar_t win[MAX_PATH]; GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring sysroot = win;
    size_t slash = sysroot.find_first_of(L"\\");
    std::wstring drive = sysroot.substr(0, 2); // "C:"

    if (p.rfind(L"\\SystemRoot\\", 0) == 0)
        return sysroot + p.substr(11);
    if (p.rfind(L"\\??\\", 0) == 0)
        return p.substr(4);
    if (p.rfind(L"\\Windows\\", 0) == 0)
        return drive + p;
    (void)slash;
    return p;
}

// Встроенная подпись Authenticode (внутри самого файла .sys).
bool VerifyEmbedded(const std::wstring& path) {
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG rc = WinVerifyTrust(nullptr, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);
    return rc == ERROR_SUCCESS;
}

// Каталожная подпись (.cat): большинство штатных драйверов Windows подписаны
// именно так, без встроенной подписи. Без этой проверки они ложно считались бы
// "untrusted". Хэшируем файл, ищем каталог по хэшу и проверяем его доверие.
bool VerifyCatalog(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    bool trusted = false;
    HCATADMIN hAdmin = nullptr;
    GUID drvAction = DRIVER_ACTION_VERIFY;
    if (CryptCATAdminAcquireContext(&hAdmin, &drvAction, 0)) {
        DWORD hashLen = 0;
        CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, nullptr, 0);
        if (hashLen > 0) {
            std::vector<BYTE> hash(hashLen);
            if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash.data(), 0)) {
                // хэш в виде HEX-строки для тега члена каталога
                static const wchar_t* hx = L"0123456789ABCDEF";
                std::wstring tag;
                tag.reserve(hashLen * 2);
                for (DWORD i = 0; i < hashLen; i++) {
                    tag.push_back(hx[hash[i] >> 4]);
                    tag.push_back(hx[hash[i] & 0xF]);
                }

                HCATINFO hCat = CryptCATAdminEnumCatalogFromHash(
                    hAdmin, hash.data(), hashLen, 0, nullptr);
                if (hCat) {
                    CATALOG_INFO ci{}; ci.cbStruct = sizeof(ci);
                    if (CryptCATCatalogInfoFromContext(hCat, &ci, 0)) {
                        WINTRUST_CATALOG_INFO wci{};
                        wci.cbStruct = sizeof(wci);
                        wci.pcwszCatalogFilePath = ci.wszCatalogFile;
                        wci.pcwszMemberTag = tag.c_str();
                        wci.pcwszMemberFilePath = path.c_str();
                        wci.hMemberFile = hFile;
                        wci.pbCalculatedFileHash = hash.data();
                        wci.cbCalculatedFileHash = hashLen;
                        wci.hCatAdmin = hAdmin;

                        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                        WINTRUST_DATA wd{};
                        wd.cbStruct = sizeof(wd);
                        wd.dwUIChoice = WTD_UI_NONE;
                        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
                        wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                        wd.pCatalog = &wci;
                        wd.dwStateAction = WTD_STATEACTION_VERIFY;
                        wd.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

                        trusted = (WinVerifyTrust(nullptr, &action, &wd) == ERROR_SUCCESS);
                        wd.dwStateAction = WTD_STATEACTION_CLOSE;
                        WinVerifyTrust(nullptr, &action, &wd);
                    }
                    CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
                }
            }
        }
        CryptCATAdminReleaseContext(hAdmin, 0);
    }
    CloseHandle(hFile);
    return trusted;
}

// Драйвер доверенный, если валидна встроенная ИЛИ каталожная подпись.
bool IsTrusted(const std::wstring& path) {
    if (path.empty()) return false;
    return VerifyEmbedded(path) || VerifyCatalog(path);
}

} // namespace

namespace modules {

ModuleResult ScanDrivers() {
    ModuleResult r; r.module = L"drivers"; r.status = L"ok";
    auto& log = Logger::Instance();

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    auto pNQSI = (PFN_NQSI)GetProcAddress(nt, "NtQuerySystemInformation");
    if (!pNQSI) { r.status = L"error"; r.note = L"NtQuerySystemInformation недоступна"; return r; }

    ULONG len = 0;
    pNQSI(SystemModuleInformation, nullptr, 0, &len);
    if (len == 0) { r.status = L"error"; r.note = L"нулевой размер буфера"; return r; }

    std::vector<uint8_t> buf(len + 0x4000);
    NTSTATUS st = pNQSI(SystemModuleInformation, buf.data(), (ULONG)buf.size(), &len);
    if (st != 0) { r.status = L"error"; r.note = L"NTSTATUS=0x" + std::to_wstring((unsigned)st); return r; }

    auto* mods = reinterpret_cast<RTL_PROCESS_MODULES*>(buf.data());
    log.Info(L"[drivers] проверка подписей " + std::to_wstring((unsigned)mods->NumberOfModules) +
             L" драйверов (встроенная + каталожная)…");
    int unsignedCnt = 0;
    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        if (i && i % 40 == 0)
            log.Info(L"[drivers] проверено " + std::to_wstring(i) + L"/" +
                     std::to_wstring((unsigned)mods->NumberOfModules) + L"…");
        const auto& m = mods->Modules[i];
        std::string full((const char*)m.FullPathName);
        std::string name = full.substr(m.OffsetToFileName < full.size() ? m.OffsetToFileName : 0);
        std::wstring path = NormalizeDriverPath(full);

        bool trusted = IsTrusted(path);
        if (!trusted) unsignedCnt++;

        Finding f;
        f.category = L"drivers";
        f.title = util::Widen(name);
        f.severity = trusted ? Severity::Info : Severity::Medium;
        f.set(L"driver", util::Widen(name))
         .set(L"path", path)
         .set(L"image_base", [&]{ wchar_t b[32]; swprintf(b,32,L"0x%p",m.ImageBase); return std::wstring(b); }())
         .set(L"image_size", std::to_wstring(m.ImageSize))
         .set(L"load_order", std::to_wstring(m.LoadOrderIndex))
         .set(L"signature", trusted ? L"trusted" : L"UNSIGNED_OR_UNTRUSTED")
         .set(L"sha256", util::Sha256File(path).value_or(L""));
        r.findings.push_back(std::move(f));
    }

    log.Info(L"[drivers] всего модулей ядра: " + std::to_wstring((int)mods->NumberOfModules) +
             L", без доверенной подписи: " + std::to_wstring(unsignedCnt));
    r.note = L"total=" + std::to_wstring((unsigned)mods->NumberOfModules) +
             L" untrusted=" + std::to_wstring(unsignedCnt);
    return r;
}

} // namespace modules
