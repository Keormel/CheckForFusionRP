// mod_tools.cpp - детект стороннего инструментария: читы, инъекторы, отладчики,
// редакторы памяти и средства автоматизации (AutoHotkey / AutoIt / макросы).
//
// Это телеметрия: модуль только ФИКСИРУЕТ факт присутствия инструмента и не
// выносит вердикт. Собираем из четырёх источников:
//   1. Запущенные процессы (снимок Toolhelp) - сверка имени exe с таблицей
//      известных инструментов и с набором имён интерпретаторов AutoHotkey/AutoIt.
//   2. Окна верхнего уровня (EnumWindows) - класс окна "AutoHotkey" (даже скрытое
//      окно скрипта) и заголовки известных инструментов (напр. "Cheat Engine").
//   3. Скомпилированные AHK-скрипты (Ahk2Exe → .exe): в PE остаётся RCDATA-ресурс
//      ">AUTOHOTKEY SCRIPT<". Проверяем его у exe пользовательских процессов -
//      так ловится переименованный/скомпилированный AHK-бот (например recoil).
//   4. Файлы автоматизации на диске (*.ahk, *.au3) в пользовательских папках
//      (Рабочий стол, Загрузки, Документы, автозагрузка, Temp) + факт установки
//      AutoHotkey (ассоциация .ahk / каталог в Program Files).
//
// Запускается без прав администратора (имена процессов и окна видны и так);
// путь к exe чужого процесса может быть недоступен - тогда остаётся только имя.

#include "modules.h"
#include "util.h"
#include "logger.h"
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <set>
#include <algorithm>

namespace {

// --- таблица известного инструментария -------------------------------------
// needle - различимая подстрока имени exe (в нижнем регистре). Короткие
// неоднозначные подстроки (напр. "ida") намеренно не используются.
struct ToolSig { const wchar_t* needle; Severity sev; const wchar_t* kind; };

const ToolSig kTools[] = {
    // Читы / редакторы памяти - высокий приоритет.
    { L"cheatengine",     Severity::High,   L"cheat_engine" },
    { L"artmoney",        Severity::High,   L"memory_editor" },
    { L"squalr",          Severity::High,   L"memory_editor" },
    { L"gameconqueror",   Severity::High,   L"memory_editor" },
    { L"reclass",         Severity::High,   L"memory_editor" },
    // Инъекторы DLL.
    { L"extremeinjector", Severity::High,   L"injector" },
    { L"xenos",           Severity::High,   L"injector" },
    { L"ghinjector",      Severity::High,   L"injector" },
    { L"injector",        Severity::High,   L"injector" },
    // Отладчики / дамперы.
    { L"x64dbg",          Severity::High,   L"debugger" },
    { L"x32dbg",          Severity::High,   L"debugger" },
    { L"x96dbg",          Severity::High,   L"debugger" },
    { L"ollydbg",         Severity::High,   L"debugger" },
    { L"scylla",          Severity::High,   L"dumper" },
    { L"megadumper",      Severity::High,   L"dumper" },
    // Средства реверса / анализа - дуальные, средний приоритет.
    { L"processhacker",   Severity::Medium, L"analysis" },
    { L"systeminformer",  Severity::Medium, L"analysis" },
    { L"windbg",          Severity::Medium, L"debugger" },
    { L"ida64",           Severity::Medium, L"re_tool" },
    { L"idaq",            Severity::Medium, L"re_tool" },
    { L"ghidra",          Severity::Medium, L"re_tool" },
    { L"frida",           Severity::Medium, L"re_tool" },
    { L"hxd",             Severity::Medium, L"hex_editor" },
    // Средства макросов (помимо AHK/AutoIt - те отдельной веткой).
    { L"tinytask",        Severity::Medium, L"macro" },
    { L"jitbit",          Severity::Medium, L"macro" },
    { L"macrorecorder",   Severity::Medium, L"macro" },
    { L"pulover",         Severity::Medium, L"macro" },
    // ПО периферии, через которое часто вешают макросы отдачи - контекст.
    { L"lghub",           Severity::Low,    L"peripheral_macro" },
    { L"rewasd",          Severity::Low,    L"peripheral_macro" },
    { L"razer synapse",   Severity::Low,    L"peripheral_macro" },
};

// Имя процесса - интерпретатор AutoHotkey / AutoIt?
bool IsAhkProcessName(const std::wstring& lower) {
    return lower.find(L"autohotkey") != std::wstring::npos ||
           lower.find(L"autoit")     != std::wstring::npos;
}

std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

// Полный путь к exe процесса (нужны минимальные права QUERY_LIMITED).
std::wstring ProcPath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return L"";
    wchar_t buf[MAX_PATH]; DWORD n = MAX_PATH;
    std::wstring r;
    if (QueryFullProcessImageNameW(h, 0, buf, &n)) r.assign(buf, n);
    CloseHandle(h);
    return r;
}

// В PE есть RCDATA-ресурс ">AUTOHOTKEY SCRIPT<" (признак сборки Ahk2Exe).
// Загружаем файл как данные (без исполнения) и ищем ресурс.
bool HasAhkResource(const std::wstring& path) {
    HMODULE h = LoadLibraryExW(path.c_str(), nullptr,
                               LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
    if (!h) return false;
    bool found = FindResourceW(h, L">AUTOHOTKEY SCRIPT<", RT_RCDATA) != nullptr;
    FreeLibrary(h);
    return found;
}

bool UnderDir(const std::wstring& pathUpper, const std::wstring& dirUpper) {
    return !dirUpper.empty() && pathUpper.compare(0, dirUpper.size(), dirUpper) == 0;
}

// --- процессы ---------------------------------------------------------------
void ScanProcesses(ModuleResult& r, Logger& log, int& tools, int& ahk) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    wchar_t winBuf[MAX_PATH] = {}; GetWindowsDirectoryW(winBuf, MAX_PATH);
    std::wstring winDir = util::ToUpper(winBuf);
    DWORD selfPid = GetCurrentProcessId();
    std::set<std::wstring> ahkChecked;

    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == selfPid) continue;
            std::wstring exe = pe.szExeFile;
            std::wstring low = Lower(exe);
            std::wstring path = ProcPath(pe.th32ProcessID);

            // 1) AutoHotkey / AutoIt по имени интерпретатора.
            if (IsAhkProcessName(low)) {
                Finding f; f.category = L"ahk";
                f.title = L"запущен интерпретатор автоматизации: " + exe;
                f.severity = Severity::High;
                f.set(L"source", L"process").set(L"kind", L"ahk_interpreter")
                 .set(L"process", exe).set(L"pid", std::to_wstring(pe.th32ProcessID))
                 .set(L"path", path);
                if (!path.empty()) f.set(L"sha256", util::Sha256File(path).value_or(L""));
                r.findings.push_back(std::move(f));
                log.High(L"[tools] AutoHotkey/AutoIt запущен: " + exe +
                         L" (PID " + std::to_wstring(pe.th32ProcessID) + L")" +
                         (path.empty() ? L"" : L" — " + path));
                ahk++;
                continue;
            }

            // 2) Известный сторонний инструмент по имени.
            bool matched = false;
            for (auto& t : kTools) {
                if (low.find(t.needle) == std::wstring::npos) continue;
                Finding f; f.category = L"tools";
                f.title = std::wstring(L"запущен инструмент (") + t.kind + L"): " + exe;
                f.severity = t.sev;
                f.set(L"source", L"process").set(L"kind", t.kind)
                 .set(L"process", exe).set(L"pid", std::to_wstring(pe.th32ProcessID))
                 .set(L"path", path);
                if (!path.empty()) f.set(L"sha256", util::Sha256File(path).value_or(L""));
                r.findings.push_back(std::move(f));
                std::wstring msg = L"[tools] обнаружен инструмент " + exe + L" (" +
                                   t.kind + L", PID " + std::to_wstring(pe.th32ProcessID) + L")";
                if (t.sev == Severity::High) log.High(msg);
                else if (t.sev == Severity::Medium) log.Med(msg);
                else log.Low(msg);
                tools++;
                matched = true;
                break;
            }
            if (matched) continue;

            // 3) Скомпилированный AHK-скрипт: только для exe вне каталога Windows
            //    (переименованный бот обычно лежит в пользовательской папке).
            if (!path.empty()) {
                std::wstring up = util::ToUpper(path);
                if (!UnderDir(up, winDir) && ahkChecked.insert(up).second &&
                    HasAhkResource(path)) {
                    Finding f; f.category = L"ahk";
                    f.title = L"скомпилированный AutoHotkey-скрипт: " + exe;
                    f.severity = Severity::High;
                    f.set(L"source", L"process").set(L"kind", L"ahk_compiled_exe")
                     .set(L"process", exe).set(L"pid", std::to_wstring(pe.th32ProcessID))
                     .set(L"path", path).set(L"location", util::LocationTag(path))
                     .set(L"sha256", util::Sha256File(path).value_or(L""));
                    r.findings.push_back(std::move(f));
                    log.High(L"[tools] скомпилированный AHK-скрипт запущен: " + exe + L" — " + path);
                    ahk++;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

// --- окна верхнего уровня ---------------------------------------------------
struct WinCtx { ModuleResult* r; Logger* log; int* ahk; int* tools; };

BOOL CALLBACK EnumWinProc(HWND hwnd, LPARAM lp) {
    auto* c = (WinCtx*)lp;
    wchar_t cls[128] = {}; GetClassNameW(hwnd, cls, 128);
    wchar_t ttl[256] = {}; GetWindowTextW(hwnd, ttl, 256);
    std::wstring className = cls, title = ttl, titleLow = Lower(title);

    DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);

    // Класс окна AutoHotkey (в т.ч. скрытого управляющего окна скрипта).
    if (className == L"AutoHotkey") {
        Finding f; f.category = L"ahk";
        f.title = L"окно AutoHotkey" + (title.empty() ? L"" : L": " + title);
        f.severity = Severity::High;
        f.set(L"source", L"window").set(L"kind", L"ahk_window")
         .set(L"window_class", className).set(L"window_title", title)
         .set(L"pid", std::to_wstring(pid));
        c->r->findings.push_back(std::move(f));
        c->log->High(L"[tools] окно AutoHotkey (class=AutoHotkey, PID " + std::to_wstring(pid) + L")");
        (*c->ahk)++;
        return TRUE;
    }

    // Заголовки известных инструментов (окно видно пользователю).
    if (!title.empty()) {
        struct { const wchar_t* needle; Severity sev; const wchar_t* kind; } wsig[] = {
            { L"cheat engine", Severity::High,   L"cheat_engine" },
            { L"reclass",      Severity::High,   L"memory_editor" },
            { L"artmoney",     Severity::High,   L"memory_editor" },
            { L"process hacker", Severity::Medium, L"analysis" },
        };
        for (auto& w : wsig) {
            if (titleLow.find(w.needle) == std::wstring::npos) continue;
            Finding f; f.category = L"tools";
            f.title = std::wstring(L"окно инструмента (") + w.kind + L"): " + title;
            f.severity = w.sev;
            f.set(L"source", L"window").set(L"kind", w.kind)
             .set(L"window_class", className).set(L"window_title", title)
             .set(L"pid", std::to_wstring(pid));
            c->r->findings.push_back(std::move(f));
            std::wstring msg = L"[tools] окно инструмента: \"" + title + L"\" (" + w.kind + L")";
            if (w.sev == Severity::High) c->log->High(msg); else c->log->Med(msg);
            (*c->tools)++;
            break;
        }
    }
    return TRUE;
}

// --- файлы автоматизации на диске ------------------------------------------
bool IsAutomationScript(const std::wstring& nameLower) {
    auto ends = [&](const wchar_t* ext) {
        size_t n = wcslen(ext);
        return nameLower.size() >= n && nameLower.compare(nameLower.size() - n, n, ext) == 0;
    };
    return ends(L".ahk") || ends(L".ah2") || ends(L".ahk1") || ends(L".au3");
}

void WalkForScripts(const std::wstring& root, const std::wstring& label,
                    ModuleResult& r, int& files, int& visited, int maxVisited, int maxFiles) {
    if (root.empty()) return;
    std::vector<std::wstring> stack{ root };
    while (!stack.empty() && visited < maxVisited && files < maxFiles) {
        std::wstring cur = stack.back(); stack.pop_back();
        visited++;
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW((cur + L"\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring nm = fd.cFileName;
            if (nm == L"." || nm == L"..") continue;
            std::wstring full = cur + L"\\" + nm;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue; // не ходим по симлинкам
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { stack.push_back(full); continue; }
            if (!IsAutomationScript(Lower(nm))) continue;

            ULARGE_INTEGER sz{}; sz.LowPart = fd.nFileSizeLow; sz.HighPart = fd.nFileSizeHigh;
            Finding f; f.category = L"ahk";
            f.title = L"скрипт автоматизации: " + nm + L" (" + label + L")";
            f.severity = Severity::Medium;
            f.set(L"source", L"file").set(L"kind", L"automation_script")
             .set(L"location_label", label).set(L"path", full)
             .set(L"size", std::to_wstring(sz.QuadPart))
             .set(L"modified", util::FileTimeToIso(fd.ftLastWriteTime))
             .set(L"sha256", util::Sha256File(full).value_or(L""));
            r.findings.push_back(std::move(f));
            files++;
            if (files >= maxFiles) break;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
}

// Установлен ли AutoHotkey (ассоциация .ahk или каталог в Program Files).
void CheckAhkInstalled(ModuleResult& r, Logger& log) {
    bool assoc = false;
    HKEY k;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L".ahk", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        assoc = true; RegCloseKey(k);
    }
    std::wstring pf = util::ExpandEnv(L"%ProgramFiles%\\AutoHotkey");
    std::wstring pfx = util::ExpandEnv(L"%ProgramFiles(x86)%\\AutoHotkey");
    bool dir = GetFileAttributesW(pf.c_str())  != INVALID_FILE_ATTRIBUTES ||
               GetFileAttributesW(pfx.c_str()) != INVALID_FILE_ATTRIBUTES;
    if (!assoc && !dir) return;

    Finding f; f.category = L"ahk";
    f.title = L"AutoHotkey установлен в системе";
    f.severity = Severity::Low;
    f.set(L"source", L"install").set(L"kind", L"ahk_installed")
     .set(L"file_association", assoc ? L"true" : L"false")
     .set(L"program_files_dir", dir ? L"true" : L"false");
    r.findings.push_back(std::move(f));
    log.Low(L"[tools] AutoHotkey установлен (ассоциация .ahk/каталог в Program Files)");
}

} // namespace

namespace modules {

ModuleResult ScanCheatTools() {
    ModuleResult r; r.module = L"tools"; r.status = L"ok";
    auto& log = Logger::Instance();

    int tools = 0, ahk = 0;

    // 1-3) процессы (имя / скомпилированный AHK).
    ScanProcesses(r, log, tools, ahk);

    // 2) окна верхнего уровня.
    WinCtx ctx{ &r, &log, &ahk, &tools };
    EnumWindows(EnumWinProc, (LPARAM)&ctx);

    // 4) файлы *.ahk / *.au3 в пользовательских папках + факт установки.
    int files = 0, visited = 0;
    constexpr int kMaxVisited = 8000, kMaxFiles = 500;
    struct Root { REFKNOWNFOLDERID id; const wchar_t* label; };
    const Root roots[] = {
        { FOLDERID_Desktop,       L"Рабочий стол" },
        { FOLDERID_Downloads,     L"Загрузки" },
        { FOLDERID_Documents,     L"Документы" },
        { FOLDERID_Startup,       L"Автозагрузка (user)" },
        { FOLDERID_CommonStartup, L"Автозагрузка (common)" },
    };
    for (auto& rt : roots)
        WalkForScripts(util::KnownFolder(rt.id), rt.label, r, files, visited, kMaxVisited, kMaxFiles);
    WalkForScripts(util::ExpandEnv(L"%TEMP%"), L"Temp", r, files, visited, kMaxVisited, kMaxFiles);

    CheckAhkInstalled(r, log);

    log.Info(L"[tools] инструментов: " + std::to_wstring(tools) +
             L", признаков AutoHotkey/AutoIt: " + std::to_wstring(ahk) +
             L", скриптов на диске: " + std::to_wstring(files));
    r.note = L"tools=" + std::to_wstring(tools) + L" ahk=" + std::to_wstring(ahk) +
             L" scripts=" + std::to_wstring(files);
    return r;
}

} // namespace modules
