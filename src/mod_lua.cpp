// mod_lua.cpp — форензика Lua-читов Garry's Mod + бинарных Lua-модулей.
//
// Читы GMod почти всегда приходят как Lua: скрипт в autorun (выполняется сам при
// загрузке), загрузчик в data/, обфусцированный RunString/CompileString-блоб,
// либо нативный модуль в lua/bin (gmcl_*/gmsv_*.dll — путь внутренних читов).
//
// Что делаем (телеметрия, без вердикта):
//   1. Находим установку(и) GarrysMod: через SteamPath в реестре + разбор
//      steamapps/libraryfolders.vdf, плюс типовые пути C:–H: как запасной вариант.
//   2. Инвентаризируем и хэшируем Lua-файлы высокосигнальных мест:
//        garrysmod/lua/autorun/** (client/server), garrysmod/data/**, корень
//        garrysmod/*, а также каталоги МЕНЮ-стейта (главное меню — отдельная
//        Lua-песочница): garrysmod/lua/{menu,includes,derma,vgui}/**. Штатное
//        меню-Lua лежит в VPK, поэтому файлы на диске здесь — оверрайды/инъекции.
//   3. Контент-анализ каждого такого файла: ищем паттерны читов — сильные слова
//      (aimbot/wallhack/triggerbot/norecoil…), генерацию кода (RunString/
//      CompileString), сетевой exfil (http.Fetch/Post, sockets), хуки боевого
//      цикла (CreateMove/CalcView) и обфускацию (мини-строки, \x-блобы).
//   4. Бинарные Lua-модули garrysmod/lua/bin/*.dll: подпись + хэш + расположение.
//
// Решение «чит/не чит» принимает сервер по хэшам и сигнатурам — агент собирает.

#include "modules.h"
#include "util.h"
#include "logger.h"
#include <windows.h>
#include <string>
#include <vector>
#include <set>
#include <algorithm>

namespace {

constexpr uint64_t kMaxScanBytes = 4ull << 20;   // контент-скан не более 4 МБ файла
constexpr int kMaxFiles          = 4000;          // общий предохранитель на инвентарь
constexpr int kMaxScanFiles      = 2500;          // сколько файлов разбираем по содержимому
constexpr int kMaxDirs           = 20000;         // предел обхода каталогов

std::string LowerAscii(const uint8_t* p, size_t n) {
    std::string s; s.resize(n);
    for (size_t i = 0; i < n; i++) {
        char c = (char)p[i];
        s[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    return s;
}

bool Has(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

// --- поиск установки Garry's Mod -------------------------------------------
std::wstring RegStr(HKEY root, const wchar_t* sub, const wchar_t* val) {
    HKEY k; std::wstring r;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) == ERROR_SUCCESS) {
        wchar_t buf[MAX_PATH]; DWORD cb = sizeof(buf), type = 0;
        if (RegQueryValueExW(k, val, nullptr, &type, (BYTE*)buf, &cb) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            r.assign(buf, cb / sizeof(wchar_t));
            if (!r.empty() && r.back() == L'\0') r.pop_back();
        }
        RegCloseKey(k);
    }
    return r;
}

// Собираем корни библиотек Steam: SteamPath + пути из libraryfolders.vdf.
std::vector<std::wstring> SteamLibraries() {
    std::set<std::wstring> libs;
    std::wstring steam = RegStr(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", L"SteamPath");
    if (steam.empty())
        steam = RegStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Valve\\Steam", L"InstallPath");
    std::replace(steam.begin(), steam.end(), L'/', L'\\');
    if (!steam.empty()) {
        libs.insert(steam);
        // libraryfolders.vdf — текст; достаём все значения "path".
        std::wstring vdf = steam + L"\\steamapps\\libraryfolders.vdf";
        auto bytes = util::ReadFileBytes(vdf, 1u << 20);
        if (bytes) {
            std::string s((const char*)bytes->data(), bytes->size());
            size_t pos = 0;
            while ((pos = s.find("\"path\"", pos)) != std::string::npos) {
                size_t q1 = s.find('"', pos + 6);
                size_t q2 = (q1 == std::string::npos) ? std::string::npos : s.find('"', q1 + 1);
                if (q1 == std::string::npos || q2 == std::string::npos) break;
                std::string raw = s.substr(q1 + 1, q2 - q1 - 1);
                std::string path; path.reserve(raw.size());
                for (size_t i = 0; i < raw.size(); i++) {      // "\\" -> "\"
                    if (raw[i] == '\\' && i + 1 < raw.size() && raw[i + 1] == '\\') { path += '\\'; i++; }
                    else path += raw[i];
                }
                libs.insert(util::Widen(path));
                pos = q2 + 1;
            }
        }
    }
    return { libs.begin(), libs.end() };
}

std::vector<std::wstring> FindGmodDirs() {
    std::set<std::wstring> found;
    auto consider = [&](const std::wstring& garrysmod) {
        if (GetFileAttributesW(garrysmod.c_str()) != INVALID_FILE_ATTRIBUTES)
            found.insert(garrysmod);
    };
    for (auto& lib : SteamLibraries())
        consider(lib + L"\\steamapps\\common\\GarrysMod\\garrysmod");
    // Запасные типовые пути (на случай, если реестр/VDF недоступны).
    const wchar_t* libDirs[] = { L"SteamLibrary", L"Steam" };
    for (wchar_t d = L'C'; d <= L'H'; d++)
        for (auto* lib : libDirs)
            consider(std::wstring(1, d) + L":\\" + lib +
                     L"\\steamapps\\common\\GarrysMod\\garrysmod");
    consider(L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\GarrysMod\\garrysmod");
    return { found.begin(), found.end() };
}

// --- контент-анализ одного Lua/текстового файла ----------------------------
// Заполняет severity/флаги по найденным паттернам.
void ScanContent(const std::wstring& path, Severity& sev, std::wstring& matched, Finding& f) {
    auto bytes = util::ReadFileBytes(path, kMaxScanBytes);
    if (!bytes || bytes->empty()) return;
    std::string low = LowerAscii(bytes->data(), bytes->size());

    static const char* kStrong[] = {
        "aimbot", "aim_bot", "triggerbot", "trigger_bot", "wallhack", "silentaim",
        "silent_aim", "norecoil", "no_recoil", "killaura", "autoshoot", "chams",
        "bhop_script", "wallbang", "backtrack"
    };
    static const char* kExec[] = { "runstringex", "runstring", "compilestring", "compilefile" };
    static const char* kNet[]  = { "http.fetch", "http.post", "http.get", "sockets.tcp", "websocket" };
    static const char* kHook[] = { "createmove", "calcview", "predrawhud",
                                   "renderscreenspaceeffects", "renderscene" };

    std::vector<std::wstring> tags;
    bool strong = false, exec = false, net = false, hook = false;
    for (auto* k : kStrong) if (Has(low, k)) { strong = true; tags.push_back(util::Widen(k)); }
    for (auto* k : kExec)   if (Has(low, k)) { exec = true;   tags.push_back(util::Widen(k)); break; }
    for (auto* k : kNet)    if (Has(low, k)) { net = true;    tags.push_back(util::Widen(k)); }
    for (auto* k : kHook)   if (Has(low, k)) { hook = true;   tags.push_back(util::Widen(k)); break; }

    // Обфускация: очень длинная строка (минификация) или много \x-эскейпов.
    size_t maxLine = 0, cur = 0, hexEsc = 0;
    for (size_t i = 0; i < low.size(); i++) {
        if (low[i] == '\n') { maxLine = std::max(maxLine, cur); cur = 0; }
        else cur++;
        if (low[i] == '\\' && i + 1 < low.size() && low[i + 1] == 'x') hexEsc++;
    }
    maxLine = std::max(maxLine, cur);
    bool obf = maxLine > 3000 || hexEsc > 60;
    if (obf) tags.push_back(L"obfuscated");

    if (strong)                       sev = Severity::High;
    else if (exec && (net || obf))    sev = Severity::High;
    else if (exec || net || obf)      sev = std::max(sev, Severity::Medium);
    else if (hook)                    sev = std::max(sev, Severity::Low);

    for (size_t i = 0; i < tags.size(); i++) matched += (i ? L"," : L"") + tags[i];
    f.set(L"max_line", std::to_wstring((uint64_t)maxLine));
    if (hexEsc) f.set(L"hex_escapes", std::to_wstring((uint64_t)hexEsc));
}

bool IsLuaLike(const std::wstring& nameLower) {
    auto ends = [&](const wchar_t* e) {
        size_t n = wcslen(e);
        return nameLower.size() >= n && nameLower.compare(nameLower.size() - n, n, e) == 0;
    };
    return ends(L".lua") || ends(L".txt") || ends(L".json") || ends(L".dat");
}

std::wstring LowerW(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

// Обходим каталог, инвентаризируем Lua-подобные файлы с контент-анализом.
void WalkLua(const std::wstring& root, const std::wstring& kind, ModuleResult& r,
             Logger& log, int& files, int& scanned, int& dirs) {
    if (root.empty() || GetFileAttributesW(root.c_str()) == INVALID_FILE_ATTRIBUTES) return;
    std::vector<std::wstring> stack{ root };
    while (!stack.empty() && files < kMaxFiles && dirs < kMaxDirs) {
        std::wstring cur = stack.back(); stack.pop_back();
        dirs++;
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW((cur + L"\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring nm = fd.cFileName;
            if (nm == L"." || nm == L"..") continue;
            std::wstring full = cur + L"\\" + nm;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { stack.push_back(full); continue; }
            if (!IsLuaLike(LowerW(nm))) continue;

            uint64_t size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            Finding f; f.category = L"lua"; f.title = nm;
            f.severity = (kind == L"autorun") ? Severity::Low : Severity::Info;
            f.set(L"kind", kind).set(L"path", full)
             .set(L"size", std::to_wstring(size))
             .set(L"modified", util::FileTimeToIso(fd.ftLastWriteTime))
             .set(L"location", util::LocationTag(full));
            if (size <= kMaxScanBytes)
                f.set(L"sha256", util::Sha256File(full).value_or(L""));

            std::wstring matched;
            if (scanned < kMaxScanFiles && size <= kMaxScanBytes) {
                ScanContent(full, f.severity, matched, f);
                scanned++;
            }
            if (!matched.empty()) f.set(L"patterns", matched);

            if (f.severity == Severity::High)
                log.High(L"[lua] подозрительный скрипт (" + matched + L"): " + full);
            else if (f.severity == Severity::Medium)
                log.Med(L"[lua] скрипт с признаками чита (" + matched + L"): " + full);

            r.findings.push_back(std::move(f));
            files++;
        } while (FindNextFileW(h, &fd) && files < kMaxFiles);
        FindClose(h);
    }
}

// Бинарные Lua-модули garrysmod/lua/bin/*.dll — путь внутренних читов.
void ScanBinModules(const std::wstring& gmod, ModuleResult& r, Logger& log, int& mods) {
    std::wstring bin = gmod + L"\\lua\\bin";
    if (GetFileAttributesW(bin.c_str()) == INVALID_FILE_ATTRIBUTES) return;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((bin + L"\\*.dll").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring full = bin + L"\\" + fd.cFileName;
        bool trusted = util::IsFileSignatureTrusted(full);
        Finding f; f.category = L"lua";
        f.title = L"бинарный Lua-модуль: " + std::wstring(fd.cFileName);
        f.severity = trusted ? Severity::Low : Severity::Medium;
        f.set(L"kind", L"binary_module").set(L"path", full)
         .set(L"signature", trusted ? L"trusted" : L"UNSIGNED_OR_UNTRUSTED")
         .set(L"modified", util::FileTimeToIso(fd.ftLastWriteTime))
         .set(L"sha256", util::Sha256File(full).value_or(L""));
        if (!trusted)
            log.Med(L"[lua] неподписанный бинарный Lua-модуль: " + full);
        r.findings.push_back(std::move(f));
        mods++;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

} // namespace

namespace modules {

ModuleResult ScanLuaCheats() {
    ModuleResult r; r.module = L"lua"; r.status = L"ok";
    auto& log = Logger::Instance();

    auto gmods = FindGmodDirs();
    if (gmods.empty()) {
        r.status = L"skipped";
        r.note = L"установка Garry's Mod не найдена (Steam/libraryfolders.vdf/типовые пути)";
        log.Med(L"[lua] " + r.note);
        return r;
    }

    int files = 0, scanned = 0, dirs = 0, mods = 0;
    for (auto& gmod : gmods) {
        log.Info(L"[lua] установка GMod: " + gmod);
        WalkLua(gmod + L"\\lua\\autorun", L"autorun", r, log, files, scanned, dirs);
        WalkLua(gmod + L"\\data",         L"data",    r, log, files, scanned, dirs);

        // Меню-стейт GMod (главное меню) — отдельная Lua-песочница, грузится до
        // захода на сервер и переживает смену серверов; серверный антифишинг её
        // не видит, поэтому лоадеры/спуферы часто сидят именно здесь. Штатные
        // скрипты игра держит в VPK, а на диске эти каталоги — место оверрайдов
        // и инъекций: инвентаризируем с хэшем (для серверной сверки с эталоном)
        // и тем же контент-анализом (RunString+http, обфускация, cheat-слова).
        for (auto* sub : { L"\\lua\\menu", L"\\lua\\includes",
                           L"\\lua\\derma", L"\\lua\\vgui" }) {
            std::wstring kind = std::wstring(L"menu:") + (wcsrchr(sub, L'\\') + 1);
            WalkLua(gmod + sub, kind, r, log, files, scanned, dirs);
        }
        // Корень garrysmod/ — только верхний уровень (без спуска в lua/materials/…).
        {
            WIN32_FIND_DATAW fd{};
            HANDLE h = FindFirstFileW((gmod + L"\\*").c_str(), &fd);
            if (h != INVALID_HANDLE_VALUE) {
                do {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    std::wstring nm = fd.cFileName;
                    if (!IsLuaLike(LowerW(nm))) continue;
                    std::wstring full = gmod + L"\\" + nm;
                    uint64_t size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                    Finding f; f.category = L"lua"; f.title = nm;
                    f.severity = Severity::Low;
                    f.set(L"kind", L"gmod_root").set(L"path", full)
                     .set(L"size", std::to_wstring(size))
                     .set(L"modified", util::FileTimeToIso(fd.ftLastWriteTime));
                    if (size <= kMaxScanBytes) f.set(L"sha256", util::Sha256File(full).value_or(L""));
                    std::wstring matched;
                    if (scanned < kMaxScanFiles && size <= kMaxScanBytes) {
                        ScanContent(full, f.severity, matched, f); scanned++;
                        if (!matched.empty()) f.set(L"patterns", matched);
                    }
                    if (f.severity == Severity::High)
                        log.High(L"[lua] подозрительный файл в корне garrysmod (" + matched + L"): " + full);
                    r.findings.push_back(std::move(f));
                    files++;
                } while (FindNextFileW(h, &fd) && files < kMaxFiles);
                FindClose(h);
            }
        }
        ScanBinModules(gmod, r, log, mods);
    }

    log.Info(L"[lua] Lua-файлов: " + std::to_wstring(files) +
             L" (разобрано " + std::to_wstring(scanned) + L"), бинарных модулей: " +
             std::to_wstring(mods));
    r.note = L"gmod_dirs=" + std::to_wstring((int)gmods.size()) +
             L" files=" + std::to_wstring(files) + L" scanned=" + std::to_wstring(scanned) +
             L" bin_modules=" + std::to_wstring(mods);
    return r;
}

} // namespace modules
