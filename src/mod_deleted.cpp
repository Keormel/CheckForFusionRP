// mod_deleted.cpp - Уровень 3: недавно удалённые файлы (только чтение).
//
// Зачем: чит часто живёт недолго - внедрился, поработал и файл СТЁРТ (в т.ч.
// shift-delete мимо корзины или программно). На момент скана файла уже нет, но
// NTFS хранит след, переживающий удаление, - ровно как журнал выгрузок ntdll
// переживает FreeLibrary (см. mod_memory.cpp). Берём два таких источника:
//
//   1. USN Journal (\$Extend\$UsnJrnl:$J) - журнал изменений NTFS. На каждое
//      удаление пишется запись USN_RECORD с флагом USN_REASON_FILE_DELETE и
//      (в финальной записи) USN_REASON_CLOSE: имя файла, время, ссылки MFT.
//      Запись остаётся после того, как сам файл стёрт. Полный путь родителя
//      восстанавливаем best-effort через OpenFileById (если каталог ещё жив).
//   2. Корзина (\$Recycle.Bin\<SID>\$I*) - для удалений «в корзину»: из $I-файла
//      читаем оригинальный путь, размер и время удаления. Читеры обычно удаляют
//      мимо корзины, поэтому это дополнение к USN, а не замена.
//
// Окно времени привязано к СЕССИИ игры: берём удаления с момента запуска
// gmod/hl2 (минус небольшой запас). Игра не запущена - откат на переданное
// окно (последние сутки). Severity повышаем для cheat-подобных расширений
// (.dll/.exe/.asi/.lua/.ahk/.sys...), имён (aim/esp/cheat/inject...) и удалений
// из пользовательских папок (Temp/Downloads/Desktop/AppData). Обычные удаления
// остаются фактами низкого приоритета - модуль НЕ выносит вердикт.
//
// Ограничения (честно, чтобы отчёт не врал):
//   - только NTFS; на FAT/exFAT журнала нет - том пропускаем;
//   - USN кольцевой: при большой активности старые удаления вытесняются;
//   - хранится имя и ссылка MFT, но НЕ содержимое - восстановить файл нельзя;
//   - журнал может быть выключен/очищен (fsutil usn deletejournal) - тогда
//     источник пуст, это отмечается, но не считается «чисто».
// Требуются права администратора (открытие тома \\.\X: и чужих $Recycle.Bin).

#include "modules.h"
#include "util.h"
#include "logger.h"
#include <windows.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <set>
#include <cstdint>
#include <cstring>

namespace {

constexpr uint64_t k100nsPerSec = 10'000'000ull;
constexpr size_t   kMaxFindings = 1500;   // защита от разрастания отчёта

// --- эвристики cheat-подобности --------------------------------------------
// Исполняемые/скриптовые расширения - то, чем бывает чит и его загрузчик.
bool IsCheatExt(const std::wstring& extLower) {
    static const wchar_t* exts[] = {
        L"dll", L"exe", L"asi", L"sys", L"lua", L"ahk", L"au3",
        L"bin", L"so", L"dylib", L"vbs", L"bat", L"cmd", L"ps1", L"scr", L"dat"
    };
    for (auto* e : exts) if (extLower == e) return true;
    return false;
}
// Характерные подстроки в именах читов (имя уже в нижнем регистре).
bool HasCheatKeyword(const std::wstring& nameLower) {
    static const wchar_t* kw[] = {
        L"aim", L"esp", L"cheat", L"hack", L"inject", L"wallhack", L"trigger",
        L"bypass", L"spoof", L"exploit", L"loader", L"menu", L"unlock", L"fusion",
        L"gmod", L"lmaobox", L"hvh", L"norecoil", L"macro"
    };
    for (auto* k : kw) if (nameLower.find(k) != std::wstring::npos) return true;
    return false;
}

std::wstring LeafName(const std::wstring& path) {
    size_t s = path.find_last_of(L"\\/");
    return (s == std::wstring::npos) ? path : path.substr(s + 1);
}
std::wstring ExtLower(const std::wstring& leaf) {
    size_t d = leaf.find_last_of(L'.');
    if (d == std::wstring::npos || d + 1 >= leaf.size()) return L"";
    std::wstring e = leaf.substr(d + 1);
    for (auto& c : e) c = (wchar_t)towlower(c);
    return e;
}

// Присвоить severity по пути/имени. loc - util::LocationTag полного пути (или "").
Severity Rank(const std::wstring& leaf, const std::wstring& loc, std::wstring& why) {
    std::wstring nameLower = leaf;
    for (auto& c : nameLower) c = (wchar_t)towlower(c);
    std::wstring ext = ExtLower(leaf);
    bool execExt = IsCheatExt(ext);
    bool kw      = HasCheatKeyword(nameLower);
    bool userDir = (loc == L"TEMP" || loc == L"DOWNLOADS" ||
                    loc == L"APPDATA" || loc == L"DESKTOP");

    why.clear();
    if (execExt) why += L"EXEC_EXT;";
    if (kw)      why += L"CHEAT_NAME;";
    if (userDir) why += L"USER_DIR;";

    if ((execExt || kw) && userDir) return Severity::High;
    if (execExt || kw)              return Severity::Medium;
    if (userDir)                    return Severity::Low;
    return Severity::Info;
}

// --- сессия игры: с какого момента смотреть удаления -----------------------
DWORD FindGameProcess(std::wstring& name) {
    static const wchar_t* names[] = {
        L"GMOD.EXE", L"GMOD_WIN64.EXE", L"HL2.EXE", L"HL2_WIN64.EXE", L"GARRYSMOD.EXE"
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring up = util::ToUpper(pe.szExeFile);
            for (auto* n : names)
                if (up == n) { pid = pe.th32ProcessID; name = pe.szExeFile; break; }
            if (pid) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// Момент старта сессии: время создания процесса игры минус 5-минутный запас
// (чтобы поймать «сбросил файл → запустил → удалил» на границе). Нет игры - 0.
uint64_t SessionSince(std::wstring& gameName) {
    DWORD pid = FindGameProcess(gameName);
    if (!pid) return 0;
    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!ph) return 0;
    FILETIME c{}, e{}, k{}, u{};
    uint64_t since = 0;
    if (GetProcessTimes(ph, &c, &e, &k, &u)) {
        since = util::FileTimeToU64(c);
        uint64_t slack = 5 * 60 * k100nsPerSec;
        since = (since > slack) ? since - slack : 0;
    }
    CloseHandle(ph);
    return since;
}

// --- восстановление пути каталога по ссылке MFT родителя --------------------
std::wstring ResolveParentPath(HANDLE vol, DWORDLONG parentRef) {
    if (!parentRef) return L"";
    FILE_ID_DESCRIPTOR fid{};
    fid.dwSize = sizeof(fid);
    fid.Type = FileIdType;
    fid.FileId.QuadPart = (LONGLONG)parentRef;
    HANDLE h = OpenFileById(vol, &fid, FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, FILE_FLAG_BACKUP_SEMANTICS);
    if (h == INVALID_HANDLE_VALUE || !h) return L"";
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD n = GetFinalPathNameByHandleW(h, buf, MAX_PATH * 2, FILE_NAME_NORMALIZED);
    CloseHandle(h);
    if (n == 0 || n >= MAX_PATH * 2) return L"";
    std::wstring p = buf;
    if (p.rfind(L"\\\\?\\", 0) == 0) p = p.substr(4);   // убрать префикс вида backslash-backslash-?
    return p;
}

std::wstring ReasonFlags(DWORD reason) {
    std::wstring s;
    if (reason & USN_REASON_FILE_DELETE)    s += L"FILE_DELETE;";
    if (reason & USN_REASON_RENAME_OLD_NAME) s += L"RENAME_OLD_NAME;";
    if (reason & USN_REASON_CLOSE)          s += L"CLOSE;";
    return s;
}

// --- USN Journal одного NTFS-тома ------------------------------------------
// Возвращает число добавленных фактов; обновляет счётчики.
int ScanVolumeUsn(const std::wstring& root /* "C:\\" */, uint64_t since,
                  ModuleResult& r, Logger& log, int& totalDeletes, bool& journalOk) {
    wchar_t letter = root[0];
    std::wstring dev = std::wstring(L"\\\\.\\") + letter + L":";
    HANDLE vol = CreateFileW(dev.c_str(), GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_EXISTING, 0, nullptr);
    if (vol == INVALID_HANDLE_VALUE) {
        log.Med(std::wstring(L"[deleted] том ") + letter + L": недоступен (нужны права администратора)");
        return 0;
    }

    USN_JOURNAL_DATA jd{};
    DWORD br = 0;
    if (!DeviceIoControl(vol, FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                         &jd, sizeof(jd), &br, nullptr)) {
        DWORD e = GetLastError();
        log.Med(std::wstring(L"[deleted] USN-журнал на ") + letter + L": недоступен (err=" +
                std::to_wstring(e) + L") — возможно отключён (fsutil usn)");
        CloseHandle(vol);
        return 0;
    }
    journalOk = true;

    READ_USN_JOURNAL_DATA rd{};
    rd.StartUsn = jd.LowestValidUsn;
    rd.ReasonMask = USN_REASON_FILE_DELETE | USN_REASON_CLOSE;
    rd.ReturnOnlyOnClose = 0;
    rd.Timeout = 0;
    rd.BytesToWaitFor = 0;
    rd.UsnJournalID = jd.UsnJournalID;

    std::vector<uint8_t> buf(64 * 1024);
    std::set<DWORDLONG> seen;        // дедуп по ссылке файла (несколько записей на удаление)
    int added = 0;
    uint64_t guard = 0, kGuard = 50'000'000ull;   // жёсткий предел итераций

    while (DeviceIoControl(vol, FSCTL_READ_USN_JOURNAL, &rd, sizeof(rd),
                           buf.data(), (DWORD)buf.size(), &br, nullptr)) {
        if (br <= sizeof(USN)) break;             // только «следующий USN» - конец
        USN nextUsn = *reinterpret_cast<USN*>(buf.data());
        DWORD off = sizeof(USN);
        while (off + sizeof(USN_RECORD) <= br) {
            auto* rec = reinterpret_cast<USN_RECORD*>(buf.data() + off);
            if (rec->RecordLength == 0) break;

            bool isDelete = (rec->Reason & USN_REASON_FILE_DELETE) &&
                            (rec->Reason & USN_REASON_CLOSE);
            bool isDir = (rec->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            uint64_t ts = (uint64_t)rec->TimeStamp.QuadPart;

            if (isDelete && !isDir && ts >= since) {
                std::wstring leaf((wchar_t*)((uint8_t*)rec + rec->FileNameOffset),
                                  rec->FileNameLength / sizeof(wchar_t));
                if (!leaf.empty() && seen.insert(rec->FileReferenceNumber).second) {
                    totalDeletes++;
                    std::wstring parent = ResolveParentPath(vol, rec->ParentFileReferenceNumber);
                    std::wstring full = parent.empty() ? L"" :
                        (parent.back() == L'\\' ? parent + leaf : parent + L"\\" + leaf);
                    std::wstring loc = full.empty() ? L"" : util::LocationTag(full);

                    std::wstring why;
                    Severity sev = Rank(leaf, loc, why);

                    if (added < (int)kMaxFindings || sev >= Severity::Medium) {
                        Finding f;
                        f.category = L"deleted";
                        f.title = L"удалён " + leaf + (why.empty() ? L"" : L" [" + why + L"]");
                        f.severity = sev;
                        f.set(L"source", L"usn_journal")
                         .set(L"volume", std::wstring(1, letter) + L":")
                         .set(L"name", leaf)
                         .set(L"path", full)
                         .set(L"parent", parent)
                         .set(L"location", loc)
                         .set(L"deleted_time", util::FileTimeToIso(ts))
                         .set(L"reason", ReasonFlags(rec->Reason))
                         .set(L"file_ref", std::to_wstring((uint64_t)rec->FileReferenceNumber))
                         .set(L"flags", why);
                        r.findings.push_back(std::move(f));
                        added++;

                        if (sev == Severity::High)
                            log.High(L"[deleted] УДАЛЁН cheat-подобный файл: " +
                                     (full.empty() ? leaf : full) + L" [" + why + L"] (" +
                                     util::FileTimeToIso(ts) + L")");
                        else if (sev == Severity::Medium)
                            log.Med(L"[deleted] удалён " + (full.empty() ? leaf : full) +
                                    L" [" + why + L"]");
                    }
                }
            }
            off += rec->RecordLength;
            if (++guard > kGuard) break;
        }
        if (nextUsn == rd.StartUsn || guard > kGuard) break;
        rd.StartUsn = nextUsn;
    }

    CloseHandle(vol);
    return added;
}

// --- Корзина одного тома ($Recycle.Bin\<SID>\$I*) --------------------------
// $I-файл: [0..7] версия (1 - до Win10, 2 - Win10+), [8..15] размер,
// [16..23] время удаления (FILETIME). Далее путь: версия 1 - фиксированные
// 260 wchar; версия 2 - [24..27] длина в символах (вкл. \0), затем UTF-16.
void ParseRecycleI(const std::vector<uint8_t>& d, std::wstring& origPath, uint64_t& delTime) {
    origPath.clear(); delTime = 0;
    if (d.size() < 24) return;
    int64_t ver = 0;  memcpy(&ver, d.data(), 8);
    memcpy(&delTime, d.data() + 16, 8);
    if (ver == 1) {
        const wchar_t* p = (const wchar_t*)(d.data() + 24);
        size_t maxc = (d.size() - 24) / sizeof(wchar_t);
        for (size_t i = 0; i < maxc && i < 260 && p[i]; i++) origPath.push_back(p[i]);
    } else {
        if (d.size() < 28) return;
        uint32_t len = 0; memcpy(&len, d.data() + 24, 4);
        if (len == 0 || len > 32768) return;
        const wchar_t* p = (const wchar_t*)(d.data() + 28);
        size_t avail = (d.size() - 28) / sizeof(wchar_t);
        for (size_t i = 0; i + 1 < len && i < avail && p[i]; i++) origPath.push_back(p[i]);
    }
}

int ScanVolumeRecycleBin(const std::wstring& root, uint64_t since,
                         ModuleResult& r, Logger& log, int& totalRecycle) {
    std::wstring binRoot = root + L"$Recycle.Bin\\";
    WIN32_FIND_DATAW sid{};
    HANDLE hs = FindFirstFileW((binRoot + L"*").c_str(), &sid);
    if (hs == INVALID_HANDLE_VALUE) return 0;
    int added = 0;
    do {
        if (!(sid.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (sid.cFileName[0] == L'.') continue;
        std::wstring sidDir = binRoot + sid.cFileName + L"\\";

        WIN32_FIND_DATAW fi{};
        HANDLE hf = FindFirstFileW((sidDir + L"$I*").c_str(), &fi);
        if (hf == INVALID_HANDLE_VALUE) continue;
        do {
            if (fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            auto bytes = util::ReadFileBytes(sidDir + fi.cFileName, 1 << 16);
            if (!bytes) continue;

            std::wstring orig; uint64_t del = 0;
            ParseRecycleI(*bytes, orig, del);
            if (orig.empty() || del < since) continue;

            totalRecycle++;
            std::wstring leaf = LeafName(orig);
            std::wstring loc = util::LocationTag(orig);
            std::wstring why;
            Severity sev = Rank(leaf, loc, why);

            Finding f;
            f.category = L"deleted";
            f.title = L"в корзине " + leaf + (why.empty() ? L"" : L" [" + why + L"]");
            f.severity = sev;
            f.set(L"source", L"recycle_bin")
             .set(L"volume", std::wstring(1, root[0]) + L":")
             .set(L"name", leaf)
             .set(L"path", orig)
             .set(L"location", loc)
             .set(L"deleted_time", util::FileTimeToIso(del))
             .set(L"flags", why);
            r.findings.push_back(std::move(f));
            added++;

            if (sev == Severity::High)
                log.High(L"[deleted] в корзине cheat-подобный файл: " + orig +
                         L" [" + why + L"] (" + util::FileTimeToIso(del) + L")");
            else if (sev == Severity::Medium)
                log.Med(L"[deleted] в корзине " + orig + L" [" + why + L"]");
        } while (FindNextFileW(hf, &fi));
        FindClose(hf);
    } while (FindNextFileW(hs, &sid));
    FindClose(hs);
    return added;
}

} // namespace

namespace modules {

ModuleResult ScanDeletedFiles(uint64_t sinceFallback) {
    ModuleResult r; r.module = L"deleted"; r.status = L"ok";
    auto& log = Logger::Instance();

    // Окно: сессия игры, иначе переданный откат (последние сутки).
    std::wstring gameName;
    uint64_t sessSince = SessionSince(gameName);
    uint64_t since = sessSince ? sessSince : sinceFallback;
    if (sessSince)
        log.Info(L"[deleted] окно привязано к сессии " + gameName + L": удаления с " +
                 util::FileTimeToIso(sessSince));
    else
        log.Info(L"[deleted] игра не запущена — окно: удаления за последние сутки");

    if (!util::IsElevated())
        log.Med(L"[deleted] без прав администратора список удалений будет неполным "
                L"(том \\\\.\\C: и чужие $Recycle.Bin недоступны).");

    int usnAdded = 0, binAdded = 0, totalDeletes = 0, totalRecycle = 0;
    bool anyJournal = false;

    DWORD mask = GetLogicalDrives();
    int ntfsVols = 0;
    for (int i = 0; i < 26; i++) {
        if (!(mask & (1u << i))) continue;
        wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
        if (GetDriveTypeW(root) != DRIVE_FIXED) continue;
        wchar_t fs[16] = {};
        if (!GetVolumeInformationW(root, nullptr, 0, nullptr, nullptr, nullptr, fs, 16)) continue;
        if (_wcsicmp(fs, L"NTFS") != 0) continue;   // USN/$Recycle.Bin - только NTFS
        ntfsVols++;

        bool jok = false;
        usnAdded += ScanVolumeUsn(root, since, r, log, totalDeletes, jok);
        if (jok) anyJournal = true;
        binAdded += ScanVolumeRecycleBin(root, since, r, log, totalRecycle);
    }

    if (ntfsVols == 0) {
        r.status = L"skipped";
        r.note = L"NTFS-томов не найдено — источники удалений недоступны";
        log.Med(L"[deleted] " + r.note);
        return r;
    }
    if (!anyJournal)
        log.Med(L"[deleted] USN-журнал недоступен ни на одном томе — "
                L"отсутствие записей НЕ означает «чисто».");

    if ((int)r.findings.size() >= (int)kMaxFindings)
        log.Med(L"[deleted] показаны не все удаления: достигнут предел " +
                std::to_wstring((int)kMaxFindings) +
                L" фактов (cheat-подобные показаны все).");

    log.Info(L"[deleted] удалений в окне: USN=" + std::to_wstring(totalDeletes) +
             L", корзина=" + std::to_wstring(totalRecycle) +
             L"; фактов в отчёте: " + std::to_wstring((int)r.findings.size()));
    r.note = L"ntfs_vols=" + std::to_wstring(ntfsVols) +
             L" usn_deletes=" + std::to_wstring(totalDeletes) +
             L" recycle=" + std::to_wstring(totalRecycle) +
             L" findings=" + std::to_wstring((int)r.findings.size()) +
             (anyJournal ? L"" : L" journal=UNAVAILABLE");
    return r;
}

} // namespace modules
