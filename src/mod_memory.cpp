// mod_memory.cpp — Уровень 2: форензика памяти целевого процесса (только чтение).
//
// Что делаем (без вмешательства, без записи — исключительно детекция фактов):
//   1. Находим процесс игры (gmod.exe / hl2.exe) по снимку Toolhelp.
//   2. Открываем с минимальными правами: PROCESS_QUERY_INFORMATION|VM_READ.
//   3. Собираем диапазоны легитимно загруженных модулей (Module32).
//   4. VirtualQueryEx обходит всё адресное пространство и отмечает аномалии:
//        - исполняемые регионы с типом MEM_PRIVATE (частая форма инъекций/шеллкода);
//        - исполняемые регионы, не попадающие ни в один загруженный модуль
//          (кандидат на "несвязанный" / скрытый код);
//        - RWX-страницы (одновременно запись и исполнение) как отдельный признак.
//   5. Для подозрительных регионов читаем первые байты и фиксируем, начинается ли
//      регион с сигнатуры MZ (признак вручную спроецированного PE).
//   6. Отдельно проверяем КАЖДЫЙ загруженный модуль игры на цифровую подпись и
//      расположение — так ловится инъекция через LoadLibrary (такая DLL числится
//      обычным модулем и шагами 1–5 не отмечается). Неподписанный модуль из
//      пользовательской папки (Temp/Downloads/Desktop/AppData) = явный признак.
//   Явные признаки внедрения (спроецированный PE с MZ; неподписанный модуль из
//   пользовательской папки) пишутся в журнал строкой HIGH — остальные аномалии
//   остаются фактами в отчёте, чтобы не зашумлять журнал JIT-кодом LuaJIT.
//
// Это телеметрия: модуль НЕ модифицирует чужой процесс и НЕ выносит вердикт.
// Требуются права администратора (и SeDebugPrivilege) для открытия hl2.exe/gmod.exe.

#include "modules.h"
#include "util.h"
#include "logger.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <algorithm>

namespace {

struct ModRange { uintptr_t base; uintptr_t end; std::wstring name; std::wstring path; };

DWORD FindProcess(const std::vector<std::wstring>& names, std::wstring& matched) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring exe = util::ToUpper(pe.szExeFile);
            for (auto& n : names) {
                if (exe == util::ToUpper(n)) { pid = pe.th32ProcessID; matched = pe.szExeFile; break; }
            }
            if (pid) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

std::vector<ModRange> CollectModules(DWORD pid) {
    std::vector<ModRange> mods;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return mods;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            uintptr_t base = (uintptr_t)me.modBaseAddr;
            mods.push_back({ base, base + me.modBaseSize, me.szModule, me.szExePath });
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return mods;
}

bool InAnyModule(const std::vector<ModRange>& mods, uintptr_t addr) {
    for (auto& m : mods) if (addr >= m.base && addr < m.end) return true;
    return false;
}

bool IsExecutable(DWORD protect) {
    DWORD p = protect & 0xFF;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}
bool IsRwx(DWORD protect) {
    DWORD p = protect & 0xFF;
    return p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

std::wstring ProtName(DWORD p) {
    switch (p & 0xFF) {
        case PAGE_EXECUTE:           return L"X";
        case PAGE_EXECUTE_READ:      return L"RX";
        case PAGE_EXECUTE_READWRITE: return L"RWX";
        case PAGE_EXECUTE_WRITECOPY: return L"RWXc";
        case PAGE_READWRITE:         return L"RW";
        case PAGE_READONLY:          return L"R";
        default:                     return L"0x" + std::to_wstring(p);
    }
}

} // namespace

namespace modules {

ModuleResult ScanProcessMemory(const std::vector<std::wstring>& targetNames) {
    ModuleResult r; r.module = L"memory"; r.status = L"ok";
    auto& log = Logger::Instance();

    util::EnablePrivilege(L"SeDebugPrivilege");

    // Имена процессов Garry's Mod: 32-бит (hl2.exe), 64-бит (gmod_win64.exe /
    // hl2_win64.exe) и лаунчеры. Агент 64-битный и читает оба варианта
    // (TH32CS_SNAPMODULE32 подхватывает модули WOW64).
    std::vector<std::wstring> names = targetNames.empty()
        ? std::vector<std::wstring>{ L"gmod.exe", L"gmod_win64.exe",
                                     L"hl2.exe",  L"hl2_win64.exe", L"GarrysMod.exe" }
        : targetNames;

    std::wstring matched;
    DWORD pid = FindProcess(names, matched);
    if (!pid) {
        r.status = L"skipped";
        r.note = L"целевой процесс Garry's Mod (gmod_win64.exe/gmod.exe/hl2.exe) не запущен";
        log.Med(L"[memory] " + r.note);
        return r;
    }
    log.Info(L"[memory] цель: " + matched + L" (PID " + std::to_wstring(pid) + L")");

    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!proc) {
        r.status = L"error";
        r.note = L"OpenProcess не удалось (нужны права администратора/SeDebugPrivilege), err=" +
                 std::to_wstring(GetLastError());
        log.Med(L"[memory] " + r.note);
        return r;
    }

    auto mods = CollectModules(pid);
    log.Info(L"[memory] загруженных модулей (Toolhelp): " + std::to_wstring((int)mods.size()));

    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t maxA = (uintptr_t)si.lpMaximumApplicationAddress;

    int anomalies = 0, regions = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < maxA && VirtualQueryEx(proc, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        regions++;
        uintptr_t regBase = (uintptr_t)mbi.BaseAddress;
        uintptr_t next = regBase + mbi.RegionSize;
        if (next <= addr) break; // защита от зацикливания

        if (mbi.State == MEM_COMMIT && IsExecutable(mbi.Protect)) {
            bool rwx     = IsRwx(mbi.Protect);
            bool priv    = (mbi.Type == MEM_PRIVATE);
            bool unbacked= !InAnyModule(mods, regBase);

            if (rwx || priv || unbacked) {
                // читаем первые 2 байта для проверки сигнатуры MZ
                uint8_t head[2] = {0,0}; SIZE_T got = 0;
                ReadProcessMemory(proc, (LPCVOID)regBase, head, 2, &got);
                bool mz = (got == 2 && head[0] == 'M' && head[1] == 'Z');

                Severity sev = Severity::Low;
                if (rwx) sev = Severity::High;
                else if (priv && unbacked) sev = Severity::High;
                else if (unbacked) sev = Severity::Medium;

                std::wstring reasons;
                if (rwx)      reasons += L"RWX;";
                if (priv)     reasons += L"PRIVATE_EXEC;";
                if (unbacked) reasons += L"NOT_IN_MODULE;";
                if (mz)       reasons += L"MZ_HEADER;";

                Finding f;
                f.category = L"memory";
                wchar_t ab[32]; swprintf(ab, 32, L"0x%p", (void*)regBase);
                f.title = std::wstring(L"exec region ") + ab + L" [" + reasons + L"]";
                f.severity = sev;
                f.set(L"pid", std::to_wstring(pid))
                 .set(L"process", matched)
                 .set(L"base", ab)
                 .set(L"size", std::to_wstring((uint64_t)mbi.RegionSize))
                 .set(L"protect", ProtName(mbi.Protect))
                 .set(L"type", mbi.Type == MEM_PRIVATE ? L"PRIVATE" :
                              mbi.Type == MEM_IMAGE ? L"IMAGE" :
                              mbi.Type == MEM_MAPPED ? L"MAPPED" : L"?")
                 .set(L"in_module", unbacked ? L"false" : L"true")
                 .set(L"mz_header", mz ? L"true" : L"false")
                 .set(L"flags", reasons);
                r.findings.push_back(std::move(f));
                anomalies++;

                // Явная подсветка в журнале: регион с сигнатурой MZ вне модулей —
                // почти наверняка вручную спроецированный PE (инъекция чита).
                // JIT-регионы LuaJIT сюда не попадают — у них нет заголовка MZ.
                if (mz && (priv || unbacked)) {
                    log.High(L"[memory] ВНЕДРЕНИЕ в " + matched + L": спроецированный PE (MZ) по адресу " +
                             std::wstring(ab) + L" [" + reasons + L"]");
                }
            }
        }
        addr = next;
    }

    // --- Инъекция через LoadLibrary: такая DLL числится нормальным модулем -----
    // (MEM_IMAGE, "в модуле") и выше не отмечается. Проверяем КАЖДЫЙ загруженный
    // модуль на цифровую подпись и расположение: неподписанный модуль, тем более
    // из пользовательской папки (Temp/Downloads/Desktop/AppData), — признак
    // внедрённого чита. Модули из каталога Windows и из папки самой игры
    // пропускаем (ОС и файлы игры), чтобы не тратить время и не шуметь.
    int suspModules = 0;
    {
        wchar_t winBuf[MAX_PATH] = {};
        GetWindowsDirectoryW(winBuf, MAX_PATH);
        std::wstring winDir = util::ToUpper(winBuf);               // C:\WINDOWS
        std::wstring gameDir;
        if (!mods.empty()) {
            std::wstring exe = mods.front().path;
            size_t s = exe.find_last_of(L"\\/");
            if (s != std::wstring::npos) gameDir = util::ToUpper(exe.substr(0, s));
        }
        auto under = [](const std::wstring& up, const std::wstring& dir) {
            return !dir.empty() && up.compare(0, dir.size(), dir) == 0;
        };

        for (auto& m : mods) {
            if (m.path.empty()) continue;
            std::wstring up = util::ToUpper(m.path);
            if (under(up, winDir)) continue;      // модуль ОС
            if (under(up, gameDir)) continue;     // собственный файл игры

            bool trusted = util::IsFileSignatureTrusted(m.path);
            std::wstring loc = util::LocationTag(m.path);
            bool userDir = (loc == L"TEMP" || loc == L"DOWNLOADS" ||
                            loc == L"APPDATA" || loc == L"DESKTOP");

            Severity sev; std::wstring reason;
            if (!trusted && userDir) { sev = Severity::High;   reason = L"INJECTED_UNSIGNED_MODULE"; }
            else if (!trusted)       { sev = Severity::Medium; reason = L"UNSIGNED_MODULE"; }
            else if (userDir)        { sev = Severity::Medium; reason = L"MODULE_FROM_USER_DIR"; }
            else continue;                        // подписан и не из пользовательской папки

            Finding f;
            f.category = L"memory";
            f.title = L"loaded module " + m.name + L" [" + reason + L"]";
            f.severity = sev;
            wchar_t ab[32]; swprintf(ab, 32, L"0x%p", (void*)m.base);
            f.set(L"pid", std::to_wstring(pid))
             .set(L"process", matched)
             .set(L"module", m.name)
             .set(L"path", m.path)
             .set(L"base", ab)
             .set(L"location", loc)
             .set(L"signature", trusted ? L"trusted" : L"UNSIGNED_OR_UNTRUSTED")
             .set(L"flags", reason);
            r.findings.push_back(std::move(f));
            suspModules++;

            if (sev == Severity::High)
                log.High(L"[memory] ВНЕДРЕНИЕ в " + matched + L": загружен неподписанный модуль " +
                         m.name + L" из " + loc + L" — " + m.path);
            else
                log.Med(L"[memory] подозрительный модуль " + m.name + L" (" + reason + L"): " + m.path);
        }
    }

    CloseHandle(proc);
    log.Info(L"[memory] регионов просмотрено: " + std::to_wstring(regions) +
             L", аномальных исполняемых: " + std::to_wstring(anomalies) +
             L", подозрительных модулей: " + std::to_wstring(suspModules));
    r.note = L"pid=" + std::to_wstring(pid) + L" regions=" + std::to_wstring(regions) +
             L" anomalies=" + std::to_wstring(anomalies) +
             L" susp_modules=" + std::to_wstring(suspModules);
    return r;
}

} // namespace modules
