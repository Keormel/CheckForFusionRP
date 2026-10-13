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

struct ModRange { uintptr_t base; uintptr_t end; std::wstring name; };

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
            mods.push_back({ base, base + me.modBaseSize, me.szModule });
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
            }
        }
        addr = next;
    }

    CloseHandle(proc);
    log.Info(L"[memory] регионов просмотрено: " + std::to_wstring(regions) +
             L", аномальных исполняемых: " + std::to_wstring(anomalies));
    r.note = L"pid=" + std::to_wstring(pid) + L" regions=" + std::to_wstring(regions) +
             L" anomalies=" + std::to_wstring(anomalies);
    return r;
}

} // namespace modules
