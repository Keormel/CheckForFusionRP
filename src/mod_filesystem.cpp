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

const wchar_t* kExts[] = { L".exe", L".dll", L".sys", L".lua", L".dat", L".bin", L".gma", L".txt", L".cfg" };
constexpr uint64_t kMaxHashSize = 64ull << 20;   // не хэшируем файлы > 64 МБ
constexpr int kMaxFiles = 20000;                 // предохранитель

bool InterestingExt(const std::wstring& name) {
    size_t dot = name.rfind(L'.');
    if (dot == std::wstring::npos) return false;
    std::wstring ext = util::ToUpper(name.substr(dot));
    for (auto* e : kExts) if (ext == util::ToUpper(e)) return true;
    return false;
}

std::wstring LocationTag(const std::wstring& path) {
    std::wstring u = util::ToUpper(path);
    if (u.find(L"\\TEMP\\") != std::wstring::npos || u.find(L"\\TMP\\") != std::wstring::npos) return L"TEMP";
    if (u.find(L"\\DOWNLOADS\\") != std::wstring::npos) return L"DOWNLOADS";
    if (u.find(L"\\GARRYSMOD\\LUA\\") != std::wstring::npos) return L"GMOD_LUA";
    if (u.find(L"\\GARRYSMOD\\DATA\\") != std::wstring::npos) return L"GMOD_DATA";
    if (u.find(L"\\GARRYSMOD\\CACHE\\") != std::wstring::npos) return L"GMOD_CACHE";
    if (u.find(L"\\APPDATA\\") != std::wstring::npos) return L"APPDATA";
    if (u.find(L"\\DESKTOP\\") != std::wstring::npos) return L"DESKTOP";
    return L"OTHER";
}

void WalkRoot(const std::wstring& root, ModuleResult& r, int& fileCount) {
    std::vector<std::wstring> stack{ root };
    while (!stack.empty() && fileCount < kMaxFiles) {
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
            Finding f;
            f.category = L"filesystem";
            f.title = nm;
            f.severity = Severity::Info;
            f.set(L"path", full)
             .set(L"size", std::to_wstring(size))
             .set(L"modified", util::FileTimeToIso(fd.ftLastWriteTime))
             .set(L"created", util::FileTimeToIso(fd.ftCreationTime))
             .set(L"location", LocationTag(full));
            if (size <= kMaxHashSize)
                f.set(L"sha256", util::Sha256File(full).value_or(L""));
            else
                f.set(L"sha256", L"(skipped: too large)");
            r.findings.push_back(std::move(f));
            fileCount++;
        } while (FindNextFileW(h, &fd) && fileCount < kMaxFiles);
        FindClose(h);
    }
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
