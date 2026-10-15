// mod_memory.cpp - Уровень 2: форензика памяти целевого процесса (только чтение).
//
// Что делаем (без вмешательства, без записи - исключительно детекция фактов):
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
//      расположение - так ловится инъекция через LoadLibrary (такая DLL числится
//      обычным модулем и шагами 1-5 не отмечается). Неподписанный модуль из
//      пользовательской папки (Temp/Downloads/Desktop/AppData) = явный признак.
//   Явные признаки внедрения (спроецированный PE с MZ; неподписанный модуль из
//   пользовательской папки) пишутся в журнал строкой HIGH - остальные аномалии
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
#include <map>
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

// --- Журнал выгруженных модулей (x64) --------------------------------------
// ntdll ведёт кольцевой буфер последних выгрузок DLL (RtlGetUnloadEventTraceEx).
// Запись остаётся ПОСЛЕ FreeLibrary - именно это ловит чит, который внедрился,
// а затем «выгрузился кнопкой»: модуля уже нет в списке, но факт загрузки/
// выгрузки сохранён. Раскладка RTL_UNLOAD_EVENT_TRACE: указательные поля —
// нативной ширины (8 байт на x64, 4 на x86), поэтому используем PVOID/SIZE_T/ULONG,
// чтобы структура совпадала с ntdll той же разрядности, что и агент.
struct UnloadEntry {
    PVOID    BaseAddress;
    SIZE_T   SizeOfImage;
    ULONG    Sequence;
    ULONG    TimeDateStamp;
    ULONG    CheckSum;
    wchar_t  ImageName[32];   // усечено ntdll до 31 символа + 0
};
typedef void (NTAPI *RtlGetUnloadEventTraceEx_t)(PULONG*, PULONG*, PVOID*);

// Есть ли DLL с таким именем среди штатных (System32 / SysWOW64) - грубый
// фильтр: выгрузка системной библиотеки не интересна.
bool IsSystemDllName(const std::wstring& name) {
    if (name.empty()) return false;
    wchar_t sys[MAX_PATH] = {};
    if (GetSystemDirectoryW(sys, MAX_PATH)) {
        std::wstring p = std::wstring(sys) + L"\\" + name;
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    }
    wchar_t win[MAX_PATH] = {};
    if (GetWindowsDirectoryW(win, MAX_PATH)) {
        std::wstring p = std::wstring(win) + L"\\SysWOW64\\" + name;
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    }
    return false;
}

// --- Внешний чит: кто держит хэндл на процесс игры -------------------------
// Внешний чит - отдельный процесс, который читает/пишет память игры через
// хэндл, полученный OpenProcess. Берём системный список хэндлов
// (SystemExtendedHandleInformation), находим хэндлы ТИПА «процесс», чьё
// дублирование указывает на PID игры, и фиксируем владельца и его права:
// VM_WRITE/VM_OPERATION (запись памяти) - почти всегда чит (HIGH); VM_READ
// (чтение) - внешний ESP/аналитика (MEDIUM). Требуются права администратора
// (PROCESS_DUP_HANDLE на чужие процессы) - без них найдётся мало/ничего.
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)
#endif
struct SysHandleEx {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
};
struct SysHandleInfoEx {
    ULONG_PTR   NumberOfHandles;
    ULONG_PTR   Reserved;
    SysHandleEx Handles[1];
};
typedef LONG (NTAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
constexpr ULONG kSystemExtendedHandleInformation = 64;

void ScanExternalAccessors(DWORD gamePid, const std::wstring& gameName,
                           ModuleResult& r, Logger& log) {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    auto NtQSI = nt ? (NtQSI_t)(void*)GetProcAddress(nt, "NtQuerySystemInformation") : nullptr;
    if (!NtQSI) return;

    std::vector<uint8_t> buf(1u << 21);
    LONG st = 0;
    for (int tries = 0; tries < 8; tries++) {
        ULONG need = 0;
        st = NtQSI(kSystemExtendedHandleInformation, buf.data(), (ULONG)buf.size(), &need);
        if (st == STATUS_INFO_LENGTH_MISMATCH) { buf.resize(buf.size() * 2 + (1u << 20)); continue; }
        break;
    }
    if (st < 0) {
        log.Med(L"[memory] список системных хэндлов недоступен — внешние читы не проверены.");
        return;
    }

    auto* info = reinterpret_cast<SysHandleInfoEx*>(buf.data());
    ULONG_PTR cnt = info->NumberOfHandles;
    DWORD ourPid = GetCurrentProcessId();

    // ObjectTypeIndex «процесса» - по собственному хэндлу на себя.
    HANDLE selfH = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ourPid);
    USHORT procType = 0xFFFF;
    if (selfH)
        for (ULONG_PTR i = 0; i < cnt; i++) {
            auto& e = info->Handles[i];
            if (e.UniqueProcessId == ourPid && (HANDLE)e.HandleValue == selfH) {
                procType = e.ObjectTypeIndex; break;
            }
        }

    std::map<DWORD, DWORD> accessByPid;   // владелец -> ИЛИ прав доступа к игре
    HANDLE me = GetCurrentProcess();
    for (ULONG_PTR i = 0; i < cnt; i++) {
        auto& e = info->Handles[i];
        DWORD owner = (DWORD)e.UniqueProcessId;
        if (owner == gamePid || owner == ourPid || owner == 0 || owner == 4) continue;
        if (procType != 0xFFFF && e.ObjectTypeIndex != procType) continue;
        DWORD acc = e.GrantedAccess;
        if (!(acc & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                     PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION))) continue;

        HANDLE ownerH = OpenProcess(PROCESS_DUP_HANDLE, FALSE, owner);
        if (!ownerH) continue;
        HANDLE dup = nullptr;
        if (DuplicateHandle(ownerH, (HANDLE)e.HandleValue, me, &dup, 0, FALSE,
                            DUPLICATE_SAME_ACCESS) && dup) {
            if (GetProcessId(dup) == gamePid) accessByPid[owner] |= acc;
            CloseHandle(dup);
        }
        CloseHandle(ownerH);
    }
    if (selfH) CloseHandle(selfH);

    auto nameOf = [](DWORD pid, std::wstring& name) -> std::wstring {
        std::wstring path;
        HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (ph) {
            wchar_t b[MAX_PATH]; DWORD n = MAX_PATH;
            if (QueryFullProcessImageNameW(ph, 0, b, &n)) {
                path.assign(b, n);
                size_t s = path.find_last_of(L"\\/");
                name = (s == std::wstring::npos) ? path : path.substr(s + 1);
            }
            CloseHandle(ph);
        }
        return path;
    };

    int ext = 0;
    for (auto& [pid, acc] : accessByPid) {
        std::wstring name, path = nameOf(pid, name);
        std::wstring who = name.empty() ? L"PID " + std::to_wstring(pid) : name;
        bool write = (acc & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) != 0;
        bool read  = (acc & PROCESS_VM_READ) != 0;
        Severity sev = write ? Severity::High : read ? Severity::Medium : Severity::Low;

        std::wstring flags;
        if (acc & PROCESS_VM_READ)      flags += L"VM_READ;";
        if (acc & PROCESS_VM_WRITE)     flags += L"VM_WRITE;";
        if (acc & PROCESS_VM_OPERATION) flags += L"VM_OPERATION;";
        if (acc & (PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION)) flags += L"QUERY;";
        bool trusted = !path.empty() && util::IsFileSignatureTrusted(path);

        Finding f; f.category = L"memory";
        f.title = L"внешний доступ к " + gameName + L": " + who + L" [" + flags + L"]";
        f.severity = sev;
        f.set(L"kind", L"external_handle")
         .set(L"accessor_pid", std::to_wstring(pid))
         .set(L"accessor", name)
         .set(L"accessor_path", path)
         .set(L"target", gameName)
         .set(L"target_pid", std::to_wstring(gamePid))
         .set(L"access", flags)
         .set(L"signature", trusted ? L"trusted" : L"UNSIGNED_OR_UNTRUSTED");
        if (!path.empty()) f.set(L"sha256", util::Sha256File(path).value_or(L""));

        if (sev == Severity::High)
            log.High(L"[memory] ВНЕШНИЙ ЧИТ? " + who + L" держит хэндл на " + gameName +
                     L" с правом записи памяти [" + flags + L"]" + (path.empty() ? L"" : L" — " + path));
        else if (sev == Severity::Medium)
            log.Med(L"[memory] " + who + L" читает память " + gameName + L" [" + flags + L"]" +
                    (path.empty() ? L"" : L" — " + path));
        r.findings.push_back(std::move(f));
        ext++;
    }
    log.Info(L"[memory] внешних процессов с хэндлом на игру: " + std::to_wstring(ext) +
             (util::IsElevated() ? L"" : L" (без прав администратора список неполон)"));
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

    // Внешние читы: кто из других процессов держит хэндл на игру (чтение/запись
    // памяти). Делаем это ДО открытия памяти игры - работает, даже если саму
    // память прочитать не удалось.
    ScanExternalAccessors(pid, matched, r, log);

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

                // Явная подсветка в журнале: регион с сигнатурой MZ вне модулей -
                // почти наверняка вручную спроецированный PE (инъекция чита).
                // JIT-регионы LuaJIT сюда не попадают - у них нет заголовка MZ.
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
    // из пользовательской папки (Temp/Downloads/Desktop/AppData), - признак
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

    // --- Выгруженные модули: ловим «внедрился и выгрузился кнопкой» ------------
    // Читаем кольцевой журнал выгрузок из ntdll ЦЕЛЕВОГО процесса. ntdll
    // проецируется по одному адресу во всех процессах сессии, поэтому адреса
    // глобалов журнала совпадают с нашими - достаточно прочитать их remote.
    // Работает для 64-битной цели; у 32-битной (WOW64) журнал ведёт отдельная
    // 32-битная ntdll - честно помечаем это и не выдаём ложное «чисто».
    int unloaded = 0;
    {
        BOOL wow64 = FALSE;
        IsWow64Process(proc, &wow64);
        if (wow64) {
            log.Med(L"[memory] цель 32-битная (WOW64): журнал выгрузок 32-битной ntdll "
                    L"недоступен из 64-битного агента — выгруженные модули не проверены.");
        } else {
            HMODULE nt = GetModuleHandleW(L"ntdll.dll");
            auto fn = nt ? (RtlGetUnloadEventTraceEx_t)(void*)
                           GetProcAddress(nt, "RtlGetUnloadEventTraceEx") : nullptr;
            if (!fn) {
                log.Med(L"[memory] RtlGetUnloadEventTraceEx недоступна — журнал выгрузок пропущен.");
            } else {
                PULONG pElemSize = nullptr, pElemCount = nullptr; PVOID pTracePtr = nullptr;
                fn(&pElemSize, &pElemCount, &pTracePtr);
                ULONG elemSize = (pElemSize ? *pElemSize : 0);
                ULONG elemCount = (pElemCount ? *pElemCount : 0);

                // Базовый адрес массива лежит по адресу pTracePtr - но уже в ПАМЯТИ
                // целевого процесса (адрес в ntdll общий, значение - его собственное).
                void* remoteArray = nullptr; SIZE_T got = 0;
                if (pTracePtr && elemSize >= sizeof(UnloadEntry) && elemCount > 0 &&
                    elemCount <= 4096 && elemSize <= 4096 &&
                    ReadProcessMemory(proc, pTracePtr, &remoteArray, sizeof(remoteArray), &got) &&
                    got == sizeof(remoteArray) && remoteArray) {

                    std::vector<uint8_t> buf((size_t)elemSize * elemCount);
                    if (ReadProcessMemory(proc, remoteArray, buf.data(), buf.size(), &got) && got > 0) {
                        size_t have = got / elemSize;
                        for (size_t i = 0; i < have; i++) {
                            auto* e = reinterpret_cast<UnloadEntry*>(buf.data() + i * elemSize);
                            if (!e->BaseAddress || e->ImageName[0] == 0) continue;
                            wchar_t nmz[33] = {};
                            memcpy(nmz, e->ImageName, sizeof(e->ImageName));
                            nmz[32] = 0;
                            std::wstring name = nmz;
                            if (name.empty()) continue;

                            bool sysDll = IsSystemDllName(name);
                            // Был ли модуль с таким именем среди загруженных сейчас
                            // (перезагрузка штатной библиотеки - не интересно).
                            bool loadedNow = false;
                            for (auto& m : mods)
                                if (util::ToUpper(m.name) == util::ToUpper(name)) { loadedNow = true; break; }

                            Severity sev = (sysDll || loadedNow) ? Severity::Low : Severity::High;
                            std::wstring flag = (sev == Severity::High)
                                ? L"UNLOADED_UNKNOWN_MODULE" : L"UNLOADED_MODULE";

                            Finding f;
                            f.category = L"memory";
                            f.title = L"unloaded module " + name + L" [" + flag + L"]";
                            f.severity = sev;
                            wchar_t ab[32]; swprintf(ab, 32, L"0x%p", e->BaseAddress);
                            f.set(L"pid", std::to_wstring(pid))
                             .set(L"process", matched)
                             .set(L"module", name)
                             .set(L"former_base", ab)
                             .set(L"size", std::to_wstring((uint64_t)e->SizeOfImage))
                             .set(L"sequence", std::to_wstring(e->Sequence))
                             .set(L"in_system_dir", sysDll ? L"true" : L"false")
                             .set(L"flags", flag);
                            r.findings.push_back(std::move(f));
                            unloaded++;

                            if (sev == Severity::High)
                                log.High(L"[memory] СЛЕД ВНЕДРЕНИЯ в " + matched +
                                         L": модуль " + name + L" был загружен и затем ВЫГРУЖЕН "
                                         L"(former_base " + std::wstring(ab) +
                                         L") — не системная DLL, вероятно чит выгрузился кнопкой.");
                        }
                    }
                }
                log.Info(L"[memory] записей в журнале выгрузок (не системных): " +
                         std::to_wstring(unloaded));
            }
        }
    }

    CloseHandle(proc);
    log.Info(L"[memory] регионов просмотрено: " + std::to_wstring(regions) +
             L", аномальных исполняемых: " + std::to_wstring(anomalies) +
             L", подозрительных модулей: " + std::to_wstring(suspModules) +
             L", следов выгрузки: " + std::to_wstring(unloaded));
    r.note = L"pid=" + std::to_wstring(pid) + L" regions=" + std::to_wstring(regions) +
             L" anomalies=" + std::to_wstring(anomalies) +
             L" susp_modules=" + std::to_wstring(suspModules) +
             L" unloaded=" + std::to_wstring(unloaded);
    return r;
}

} // namespace modules
