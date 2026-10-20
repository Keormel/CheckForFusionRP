// mod_persistence.cpp - Уровень 3: точки автозагрузки (persistence).
//
// Собираем: HKCU/HKLM ...\CurrentVersion\Run и RunOnce (в т.ч. Wow6432Node),
// папки Startup (пользователя и общую), а также XML-файлы Планировщика заданий
// в C:\Windows\System32\Tasks (имя задачи = относительный путь).
// Для каждого записанного исполняемого считаем SHA256, если удаётся извлечь путь.

#include "modules.h"
#include "util.h"
#include "logger.h"
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>

namespace {

// Достаём путь к .exe из строки команды автозагрузки (убираем кавычки/аргументы).
std::wstring ExtractImagePath(const std::wstring& cmd) {
    std::wstring s = util::Trim(cmd);
    if (s.empty()) return s;
    std::wstring path;
    if (s[0] == L'"') {
        size_t end = s.find(L'"', 1);
        path = (end == std::wstring::npos) ? s.substr(1) : s.substr(1, end - 1);
    } else {
        size_t sp = s.find(L' ');
        path = (sp == std::wstring::npos) ? s : s.substr(0, sp);
    }
    return util::ExpandEnv(path);
}

// Возвращает true, если ключ удалось открыть (даже пустой), false - если ОС
// отказала (нет ключа / нет прав). Причину вызывающий агрегирует и логирует.
bool ReadRunKey(HKEY root, const wchar_t* subkey, const std::wstring& label,
                REGSAM extra, ModuleResult& r) {
    HKEY k;
    LONG rc = RegOpenKeyExW(root, subkey, 0, KEY_READ | extra, &k);
    if (rc != ERROR_SUCCESS) return false;

    DWORD idx = 0;
    wchar_t name[16384]; BYTE data[32768];
    for (;;) {
        DWORD nlen = 16384, dlen = sizeof(data), type = 0;
        LONG rc = RegEnumValueW(k, idx++, name, &nlen, nullptr, &type, data, &dlen);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) break;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

        std::wstring cmd((wchar_t*)data, (dlen / sizeof(wchar_t)));
        if (!cmd.empty() && cmd.back() == L'\0') cmd.pop_back();
        std::wstring img = ExtractImagePath(cmd);

        Finding f;
        f.category = L"persistence";
        f.title = std::wstring(name) + L" (" + label + L")";
        f.severity = Severity::Low;
        f.set(L"source", label)
         .set(L"value_name", name)
         .set(L"command", cmd)
         .set(L"image_path", img)
         .set(L"exists", (GetFileAttributesW(img.c_str()) != INVALID_FILE_ATTRIBUTES) ? L"true" : L"false");
        if (GetFileAttributesW(img.c_str()) != INVALID_FILE_ATTRIBUTES)
            f.set(L"sha256", util::Sha256File(img).value_or(L""));
        r.findings.push_back(std::move(f));
    }
    RegCloseKey(k);
    return true;
}

// Возвращает причину сбоя или пустую строку, если папка обработана.
std::wstring ReadStartupFolder(const std::wstring& dir, const std::wstring& label, ModuleResult& r) {
    if (dir.empty())
        return label + L": путь не определён (SHGetKnownFolderPath вернул пусто)";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return L"";  // просто пусто
        return label + L": папка " + dir + L" недоступна (err=" + std::to_wstring(e) + L")";
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        Finding f;
        f.category = L"persistence";
        f.title = std::wstring(fd.cFileName) + L" (" + label + L")";
        f.severity = Severity::Low;
        f.set(L"source", label)
         .set(L"path", full)
         .set(L"sha256", util::Sha256File(full).value_or(L""));
        r.findings.push_back(std::move(f));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return L"";
}

void ReadScheduledTasks(ModuleResult& r) {
    wchar_t win[MAX_PATH]; GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring base = std::wstring(win) + L"\\System32\\Tasks";

    std::vector<std::wstring> stack{ base };
    int count = 0;
    while (!stack.empty() && count < 2000) {
        std::wstring cur = stack.back(); stack.pop_back();
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW((cur + L"\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring nm = fd.cFileName;
            if (nm == L"." || nm == L"..") continue;
            std::wstring full = cur + L"\\" + nm;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { stack.push_back(full); continue; }

            auto bytes = util::ReadFileBytes(full, 1u << 20);
            std::wstring content = bytes ? util::Widen(std::string((char*)bytes->data(), bytes->size())) : L"";
            // грубое извлечение <Command> из XML задачи
            std::wstring img;
            size_t p = content.find(L"<Command>");
            if (p != std::wstring::npos) {
                size_t e = content.find(L"</Command>", p);
                if (e != std::wstring::npos) img = util::ExpandEnv(util::Trim(content.substr(p + 9, e - p - 9)));
            }

            Finding f;
            f.category = L"persistence";
            f.title = L"task: " + full.substr(base.size());
            f.severity = Severity::Info;
            f.set(L"source", L"scheduled_task")
             .set(L"task_path", full.substr(base.size()))
             .set(L"command", img);
            if (!img.empty() && GetFileAttributesW(img.c_str()) != INVALID_FILE_ATTRIBUTES) {
                f.set(L"sha256", util::Sha256File(img).value_or(L""));
                f.severity = Severity::Low;
            }
            r.findings.push_back(std::move(f));
            count++;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
}

} // namespace

namespace modules {

ModuleResult ScanPersistence() {
    ModuleResult r; r.module = L"persistence"; r.status = L"ok";
    auto& log = Logger::Instance();

    const wchar_t* run     = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const wchar_t* runOnce = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";

    // Собираем все недоступные источники: HKCU\Run существует всегда, а вот
    // HKLM\Run без прав админа отдаст ERROR_ACCESS_DENIED. Молча пропустить -
    // значит соврать «автозагрузка пуста», поэтому пишем сводку в журнал.
    std::vector<std::wstring> missing;
    auto tryKey = [&](HKEY root, const wchar_t* sub, const std::wstring& lbl, REGSAM w) {
        if (!ReadRunKey(root, sub, lbl, w, r)) missing.push_back(lbl);
    };
    tryKey(HKEY_CURRENT_USER,  run,     L"HKCU\\Run",             0);
    tryKey(HKEY_CURRENT_USER,  runOnce, L"HKCU\\RunOnce",         0);
    tryKey(HKEY_LOCAL_MACHINE, run,     L"HKLM\\Run",             0);
    tryKey(HKEY_LOCAL_MACHINE, runOnce, L"HKLM\\RunOnce",         0);
    tryKey(HKEY_LOCAL_MACHINE, run,     L"HKLM\\Run (Wow64)",     KEY_WOW64_32KEY);
    tryKey(HKEY_LOCAL_MACHINE, runOnce, L"HKLM\\RunOnce (Wow64)", KEY_WOW64_32KEY);

    auto suA = ReadStartupFolder(util::KnownFolder(FOLDERID_Startup),       L"Startup (user)",   r);
    auto suC = ReadStartupFolder(util::KnownFolder(FOLDERID_CommonStartup), L"Startup (common)", r);
    if (!suA.empty()) missing.push_back(suA);
    if (!suC.empty()) missing.push_back(suC);

    ReadScheduledTasks(r);

    if (!missing.empty()) {
        std::wstring list;
        for (size_t i = 0; i < missing.size(); i++) { if (i) list += L"; "; list += missing[i]; }
        log.Med(L"[persistence] недоступные источники (" + std::to_wstring((int)missing.size()) +
                L"): " + list +
                (util::IsElevated() ? L" — ключи/папки отсутствуют или заблокированы ОС."
                                    : L" — большинство HKLM-ключей читается только администратором; "
                                      L"запустите агент с правами администратора."));
    }

    log.Info(L"[persistence] точек автозагрузки собрано: " + std::to_wstring((int)r.findings.size()));
    r.note = L"items=" + std::to_wstring((int)r.findings.size()) +
             (missing.empty() ? L""
                              : L" missing=" + std::to_wstring((int)missing.size()));
    return r;
}

} // namespace modules
