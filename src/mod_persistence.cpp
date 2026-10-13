// mod_persistence.cpp — Уровень 3: точки автозагрузки (persistence).
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

void ReadRunKey(HKEY root, const wchar_t* subkey, const std::wstring& label,
                REGSAM extra, ModuleResult& r) {
    HKEY k;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | extra, &k) != ERROR_SUCCESS) return;

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
}

void ReadStartupFolder(const std::wstring& dir, const std::wstring& label, ModuleResult& r) {
    if (dir.empty()) return;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
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

    ReadRunKey(HKEY_CURRENT_USER,  run,     L"HKCU\\Run",     0, r);
    ReadRunKey(HKEY_CURRENT_USER,  runOnce, L"HKCU\\RunOnce", 0, r);
    ReadRunKey(HKEY_LOCAL_MACHINE, run,     L"HKLM\\Run",     0, r);
    ReadRunKey(HKEY_LOCAL_MACHINE, runOnce, L"HKLM\\RunOnce", 0, r);
    ReadRunKey(HKEY_LOCAL_MACHINE, run,     L"HKLM\\Run (Wow64)",     KEY_WOW64_32KEY, r);
    ReadRunKey(HKEY_LOCAL_MACHINE, runOnce, L"HKLM\\RunOnce (Wow64)", KEY_WOW64_32KEY, r);

    ReadStartupFolder(util::KnownFolder(FOLDERID_Startup),       L"Startup (user)",   r);
    ReadStartupFolder(util::KnownFolder(FOLDERID_CommonStartup), L"Startup (common)", r);

    ReadScheduledTasks(r);

    log.Info(L"[persistence] точек автозагрузки собрано: " + std::to_wstring((int)r.findings.size()));
    r.note = L"items=" + std::to_wstring((int)r.findings.size());
    return r;
}

} // namespace modules
