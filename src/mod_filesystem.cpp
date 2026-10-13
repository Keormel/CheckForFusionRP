// mod_filesystem.cpp — Уровень 3: обход директорий и расчёт хэшей.
//
// Рекурсивно обходит заданные корни (по умолчанию: Temp, Downloads, папки
// garrysmod/{lua,data,cache} относительно обнаруженной установки Steam/GMod).
// Для каждого файла интересующих расширений считает SHA256 и выставляет пометку
// расположения. Сервер сверяет хэши со своей базой — агент только собирает.

#include "modules.h"
#include "util.h"
#include "logger.h"
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <algorithm>

namespace {

const wchar_t* kExts[] = { L".exe", L".dll", L".sys", L".lua", L".dat", L".bin", L".gma",
                           L".txt", L".cfg", L".ini", L".json", L".cfg", L".vdf" };
constexpr uint64_t kMaxHashSize = 32ull << 20;   // не хэшируем файлы > 32 МБ
constexpr int kMaxFiles = 12000;                 // общий предохранитель
constexpr int kMaxPerRoot = 4000;                // чтобы один каталог (Temp) не занял весь лимит
constexpr int kProgressEvery = 250;              // как часто сообщать прогресс в лог

// Расширения, типичные для конфигов (в т.ч. конфигов читов).
bool IsConfigExt(const std::wstring& name) {
    size_t dot = name.rfind(L'.');
    if (dot == std::wstring::npos) return false;
    std::wstring ext = util::ToUpper(name.substr(dot));
    return ext == L".CFG" || ext == L".INI" || ext == L".JSON" ||
           ext == L".DAT" || ext == L".TXT" || ext == L".LUA" || ext == L".VDF";
}

// Сильные маркеры читов в пути/имени: такие слова почти не встречаются в
// легитимных файлах. Возвращает найденное слово или пустую строку.
std::wstring CheatMarker(const std::wstring& path) {
    static const wchar_t* kMarkers[] = {
        L"CHEAT", L"ЧИТ", L"HACK", L"AIMBOT", L"AIM BOT", L"WALLHACK", L"ESP",
        L"TRIGGERBOT", L"INJECT", L"INJECTOR", L"EXPLOIT", L"BYPASS", L"SPOOFER",
        L"UNLOCKER", L"NORECOIL", L"SILENTAIM", L"LMAOBOX", L"FATALITY", L"RECOIL",
        L"MENU_CONFIG", L"HACKMENU", L"GMODHACK", L"GMODCHEAT"
    };
    std::wstring u = util::ToUpper(path);
    for (auto* m : kMarkers)
        if (u.find(m) != std::wstring::npos) return m;
    return L"";
}

bool InterestingExt(const std::wstring& name) {
    size_t dot = name.rfind(L'.');
    if (dot == std::wstring::npos) return false;
    std::wstring ext = util::ToUpper(name.substr(dot));
    for (auto* e : kExts) if (ext == util::ToUpper(e)) return true;
    return false;
}

void WalkRoot(const std::wstring& root, ModuleResult& r, int& fileCount) {
    auto& log = Logger::Instance();
    int rootCount = 0;
    std::vector<std::wstring> stack{ root };
    while (!stack.empty() && fileCount < kMaxFiles && rootCount < kMaxPerRoot) {
        std::wstring cur = stack.back(); stack.pop_back();
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW((cur + L"\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring nm = fd.cFileName;
            if (nm == L"." || nm == L"..") continue;
            std::wstring full = cur + L"\\" + nm;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue; // не ходим по симлинкам
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { stack.push_back(full); continue; }
            if (!InterestingExt(nm)) continue;

            uint64_t size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            std::wstring loc = util::LocationTag(full);
            std::wstring marker = CheatMarker(full);
            bool cfg = IsConfigExt(nm);

            Finding f;
            f.category = L"filesystem";
            f.title = nm;
            // По умолчанию модуль просто собирает факты (Info) — вердикт за сервером.
            // Но файл с явным маркером чита подсвечиваем сразу, а конфиг в Documents
            // помечаем Low, чтобы он не потерялся среди прочих файлов.
            f.severity = Severity::Info;
            if (!marker.empty())                          f.severity = Severity::High;
            else if (cfg && (loc == L"DOCUMENTS" || loc == L"APPDATA")) f.severity = Severity::Low;

            f.set(L"path", full)
             .set(L"size", std::to_wstring(size))
             .set(L"modified", util::FileTimeToIso(fd.ftLastWriteTime))
             .set(L"created", util::FileTimeToIso(fd.ftCreationTime))
             .set(L"location", loc);
            if (cfg) f.set(L"kind", L"config");
            if (!marker.empty()) f.set(L"cheat_marker", marker);
            if (size <= kMaxHashSize)
                f.set(L"sha256", util::Sha256File(full).value_or(L""));
            else
                f.set(L"sha256", L"(skipped: too large)");
            r.findings.push_back(std::move(f));

            if (!marker.empty())
                log.High(L"[filesystem] возможный файл/конфиг чита: " + full +
                         L"  (маркер: " + marker + L")");
            else if (f.severity == Severity::Low)
                log.Info(L"[filesystem] конфиг в " + loc + L": " + full);

            fileCount++;
            rootCount++;
            if (fileCount % kProgressEvery == 0)
                log.Info(L"[filesystem] захэшировано файлов: " + std::to_wstring(fileCount) + L"…");
        } while (FindNextFileW(h, &fd) && fileCount < kMaxFiles && rootCount < kMaxPerRoot);
        FindClose(h);
    }
    if (rootCount >= kMaxPerRoot)
        log.Med(L"[filesystem] достигнут лимит на каталог (" + std::to_wstring(kMaxPerRoot) +
                L"), часть файлов в «" + root + L"» пропущена.");
}

// Пытаемся найти установку Garry's Mod по стандартным путям Steam.
void AddGmodRoots(std::vector<std::wstring>& roots) {
    std::vector<std::wstring> candidates = {
        L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\GarrysMod\\garrysmod",
        L"C:\\Program Files\\Steam\\steamapps\\common\\GarrysMod\\garrysmod",
    };
    // диски C:..H: — типичные раскладки библиотеки Steam (SteamLibrary и Steam)
    const wchar_t* libDirs[] = { L"SteamLibrary", L"Steam" };
    for (wchar_t d = L'C'; d <= L'H'; d++)
        for (auto* lib : libDirs) {
            std::wstring p = std::wstring(1, d) + L":\\" + lib +
                             L"\\steamapps\\common\\GarrysMod\\garrysmod";
            candidates.push_back(p);
        }
    for (auto& c : candidates)
        if (GetFileAttributesW(c.c_str()) != INVALID_FILE_ATTRIBUTES) {
            for (auto* sub : { L"\\lua", L"\\data", L"\\cache", L"\\addons", L"\\download" }) {
                std::wstring full = c + sub;
                if (GetFileAttributesW(full.c_str()) != INVALID_FILE_ATTRIBUTES) roots.push_back(full);
            }
        }
}

} // namespace

namespace modules {

ModuleResult ScanFilesystem(const std::vector<std::wstring>& extraRoots) {
    ModuleResult r; r.module = L"filesystem"; r.status = L"ok";
    auto& log = Logger::Instance();

    std::vector<std::wstring> roots;
    std::wstring temp = util::ExpandEnv(L"%LOCALAPPDATA%\\Temp");
    if (GetFileAttributesW(temp.c_str()) != INVALID_FILE_ATTRIBUTES) roots.push_back(temp);
    std::wstring dl = util::KnownFolder(FOLDERID_Downloads);
    if (!dl.empty()) roots.push_back(dl);
    // Папка «Документы» — туда читы чаще всего кладут свои конфиги (учитывается
    // и перенаправление в OneDrive: KnownFolder возвращает фактический путь).
    std::wstring docs = util::KnownFolder(FOLDERID_Documents);
    if (!docs.empty()) roots.push_back(docs);
    std::wstring saved = util::KnownFolder(FOLDERID_SavedGames);
    if (!saved.empty()) roots.push_back(saved);
    AddGmodRoots(roots);
    for (auto& e : extraRoots)
        if (GetFileAttributesW(e.c_str()) != INVALID_FILE_ATTRIBUTES) roots.push_back(e);

    int fileCount = 0;
    for (auto& root : roots) {
        log.Info(L"[filesystem] обход: " + root);
        WalkRoot(root, r, fileCount);
    }
    if (roots.empty()) { r.status = L"skipped"; r.note = L"не найдено ни одного корня для обхода"; }

    log.Info(L"[filesystem] файлов захэшировано: " + std::to_wstring(fileCount) +
             (fileCount >= kMaxFiles ? L" (достигнут лимит)" : L""));
    r.note = L"files=" + std::to_wstring(fileCount);
    return r;
}

} // namespace modules
