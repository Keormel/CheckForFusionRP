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

// true, если подпись Authenticode валидна (цепочка доверия ОС).
bool IsTrusted(const std::wstring& path) {
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
    int unsignedCnt = 0;
    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
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
