// mod_prefetch.cpp - Уровень 1: парсер Windows Prefetch (*.pf).
//
// Формат:
//   Win8.1+ файлы сжаты контейнером "MAM\x04" (XPRESS Huffman). Распаковываем
//   документированным RtlDecompressBufferEx (COMPRESSION_FORMAT_XPRESS_HUFF).
//   Далее - заголовок SCCA (сигнатура "SCCA"), версия определяет раскладку
//   полей: имя exe (UTF-16), счётчик запусков, массив времён последних запусков.
//
// Факты, которые собираем на каждый .pf:
//   executable, run_count, last_run (ISO), все last_run_times, pf_modified,
//   и пометка расположения (TEMP/DOWNLOADS/APPDATA...) - как признак для анализа.
//
// Требуются права администратора: каталог C:\Windows\Prefetch закрыт для
// обычного пользователя. При отсутствии прав модуль честно отдаёт status=skipped.

#include "modules.h"
#include "util.h"
#include "logger.h"
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

namespace {

// RtlDecompressBufferEx / RtlGetCompressionWorkSpaceSize из ntdll.
typedef NTSTATUS (WINAPI *PFN_WSS)(USHORT, PULONG, PULONG);
// RtlDecompressBufferEx: 7 параметров (Format, Dst, DstSize, Src, SrcSize, FinalSize, WorkSpace).
typedef NTSTATUS (WINAPI *PFN_DECOMP)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID);

constexpr USHORT XPRESS_HUFF = 4; // COMPRESSION_FORMAT_XPRESS_HUFFMAN

bool DecompressMam(const std::vector<uint8_t>& raw, std::vector<uint8_t>& out) {
    if (raw.size() < 8) return false;
    // "MAM" + байт формата; байт 3 = формат, биты старшего нибла = флаг CRC.
    if (memcmp(raw.data(), "MAM", 3) != 0) return false;
    uint32_t outSize;
    memcpy(&outSize, raw.data() + 4, 4);          // несжатый размер
    if (outSize == 0 || outSize > (64u << 20)) return false;

    static PFN_WSS    pWss    = nullptr;
    static PFN_DECOMP pDecomp = nullptr;
    if (!pDecomp) {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        pWss    = (PFN_WSS)GetProcAddress(nt, "RtlGetCompressionWorkSpaceSize");
        pDecomp = (PFN_DECOMP)GetProcAddress(nt, "RtlDecompressBufferEx");
    }
    if (!pDecomp || !pWss) return false;

    ULONG wsCompress = 0, wsFragment = 0;
    if (pWss(XPRESS_HUFF, &wsCompress, &wsFragment) != 0) return false;

    std::vector<uint8_t> ws(wsFragment);
    out.assign(outSize, 0);
    ULONG finalSize = 0;
    // полезная нагрузка начинается после 8-байтового заголовка MAM
    NTSTATUS st = pDecomp(XPRESS_HUFF, out.data(), outSize,
                          (PUCHAR)raw.data() + 8, (ULONG)(raw.size() - 8),
                          &finalSize, ws.data());
    if (st != 0) return false;
    out.resize(finalSize);
    return true;
}

// --- SCCA ------------------------------------------------------------------
// Смещения внутри несжатого .pf. Значения выверены по версиям формата.
struct Layout {
    uint32_t lastRunOffset;   // массив FILETIME последних запусков
    uint32_t lastRunSlots;    // сколько слотов (1 или 8)
    uint32_t runCountOffsets[2]; // где лежит счётчик (пробуем по очереди)
};

bool LayoutForVersion(uint32_t ver, Layout& L) {
    switch (ver) {
        case 17: L = {0x78, 1, {0x90, 0}};        return true; // XP/2003
        case 23: L = {0x80, 1, {0x98, 0}};        return true; // Vista/7
        case 26: L = {0x80, 8, {0xD0, 0}};        return true; // 8.1
        case 30: L = {0x80, 8, {0xD0, 0xC8}};     return true; // 10
        case 31: L = {0x80, 8, {0xC8, 0xD0}};     return true; // 11 24H2+
        default: return false;
    }
}

template <typename T>
bool Read(const std::vector<uint8_t>& b, size_t off, T& v) {
    if (off + sizeof(T) > b.size()) return false;
    memcpy(&v, b.data() + off, sizeof(T));
    return true;
}

// Имя исполняемого - UTF-16 по смещению 0x10, до 60 wchar.
std::wstring ReadExeName(const std::vector<uint8_t>& b) {
    constexpr size_t off = 0x10, maxChars = 60;
    std::wstring s;
    for (size_t i = 0; i < maxChars; i++) {
        uint16_t c;
        if (!Read(b, off + i * 2, c) || c == 0) break;
        s.push_back((wchar_t)c);
    }
    return s;
}

// Секция имён файлов: все файлы, к которым процесс обращался в первые ~10 с
// после запуска (сам exe, его DLL, данные). Смещение/размер секции лежат в
// заголовке по 0x64/0x68 - одинаково для версий 17-31. Строки UTF-16, каждая
// завершается нулём, пути в нотации "\VOLUME{...}\..." или "\DEVICE\...".
std::vector<std::wstring> ReadFilenameStrings(const std::vector<uint8_t>& b) {
    std::vector<std::wstring> out;
    uint32_t off = 0, size = 0;
    if (!Read(b, 0x64, off) || !Read(b, 0x68, size)) return out;
    if (off == 0 || size == 0 || (uint64_t)off + size > b.size()) return out;

    std::wstring cur;
    for (uint32_t i = 0; i + 1 < size; i += 2) {
        uint16_t c;
        memcpy(&c, b.data() + off + i, 2);
        if (c == 0) {
            if (!cur.empty()) out.push_back(std::move(cur));
            cur.clear();
        } else {
            cur.push_back((wchar_t)c);
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

// Полный путь исполняемого: строка из секции имён, чьё последнее звено
// совпадает с именем exe из заголовка (оно обрезается до 29 символов).
std::wstring FindExePath(const std::vector<std::wstring>& files, const std::wstring& exe) {
    if (exe.empty()) return L"";
    std::wstring want = util::ToUpper(exe);
    for (auto& f : files) {
        std::wstring u = util::ToUpper(f);
        size_t slash = u.find_last_of(L'\\');
        std::wstring name = (slash == std::wstring::npos) ? u : u.substr(slash + 1);
        if (name == want || (want.size() >= 29 && name.rfind(want, 0) == 0)) return f;
    }
    return L"";
}

} // namespace

namespace modules {

ModuleResult ScanPrefetch(uint64_t sinceFileTime) {
    ModuleResult r; r.module = L"prefetch"; r.status = L"ok";
    auto& log = Logger::Instance();

    std::wstring win; wchar_t wbuf[MAX_PATH];
    GetWindowsDirectoryW(wbuf, MAX_PATH); win = wbuf;
    std::wstring dir = win + L"\\Prefetch\\";

    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"*.pf").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        r.status = L"skipped";
        r.note = (e == ERROR_ACCESS_DENIED)
            ? L"нет доступа к C:\\Windows\\Prefetch (нужны права администратора)"
            : L"каталог Prefetch недоступен (возможно, Prefetch отключён)";
        log.Med(L"[prefetch] " + r.note);
        return r;
    }

    int parsed = 0, failed = 0, withPath = 0, notable = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring full = dir + fd.cFileName;

        auto bytes = util::ReadFileBytes(full);
        if (!bytes) { failed++; continue; }

        std::vector<uint8_t> data;
        if (bytes->size() >= 3 && memcmp(bytes->data(), "MAM", 3) == 0) {
            if (!DecompressMam(*bytes, data)) { failed++; continue; }
        } else {
            data = std::move(*bytes); // уже несжатый (старые ОС)
        }

        uint32_t version = 0;
        if (!Read(data, 0, version) || data.size() < 0x84) { failed++; continue; }
        if (memcmp(data.data() + 4, "SCCA", 4) != 0) { failed++; continue; }

        Layout L;
        if (!LayoutForVersion(version, L)) { failed++; continue; }

        std::wstring exe = ReadExeName(data);

        uint32_t runCount = 0;
        for (uint32_t off : L.runCountOffsets) {
            if (off == 0) break;
            uint32_t v;
            if (Read(data, off, v) && v > 0 && v < 100000) { runCount = v; break; }
        }

        std::vector<uint64_t> runs;
        uint64_t newest = 0;
        for (uint32_t i = 0; i < L.lastRunSlots; i++) {
            uint64_t ft;
            if (!Read(data, L.lastRunOffset + i * 8, ft)) break;
            if (ft != 0) { runs.push_back(ft); if (ft > newest) newest = ft; }
        }

        // модификация самого .pf = приблизительное время последнего запуска (fallback)
        uint64_t pfMod = util::FileTimeToU64(fd.ftLastWriteTime);
        uint64_t effective = newest ? newest : pfMod;

        parsed++;
        if (sinceFileTime && effective < sinceFileTime) { continue; } // вне окна времени

        Finding f;
        f.category = L"prefetch";
        f.title = exe.empty() ? std::wstring(fd.cFileName) : exe;
        f.severity = Severity::Info;
        f.set(L"pf_file", fd.cFileName)
         .set(L"executable", exe)
         .set(L"version", std::to_wstring(version))
         .set(L"run_count", std::to_wstring(runCount))
         .set(L"last_run", util::FileTimeToIso(newest))
         .set(L"pf_modified", util::FileTimeToIso(pfMod));

        std::wstring allRuns;
        for (size_t i = 0; i < runs.size(); i++) {
            if (i) allRuns += L";";
            allRuns += util::FileTimeToIso(runs[i]);
        }
        f.set(L"last_run_times", allRuns);

        auto files = ReadFilenameStrings(data);
        std::wstring devPath = FindExePath(files, exe);
        std::wstring path = devPath.empty() ? L"" : util::ResolveDevicePath(devPath);
        std::wstring loc = path.empty() ? L"" : util::LocationTag(path);
        f.set(L"path", path)
         .set(L"device_path", devPath)
         .set(L"location", loc)
         .set(L"files_referenced", std::to_wstring(files.size()));
        if (util::IsNotableLocation(loc)) { f.severity = Severity::Low; notable++; }
        if (!path.empty()) withPath++;

        r.findings.push_back(std::move(f));
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    log.Info(L"[prefetch] разобрано .pf: " + std::to_wstring(parsed) +
             L", в окне времени: " + std::to_wstring((int)r.findings.size()) +
             L", ошибок парсинга: " + std::to_wstring(failed));
    log.Info(L"[prefetch] полный путь восстановлен: " + std::to_wstring(withPath) + L"/" +
             std::to_wstring((int)r.findings.size()));
    if (notable)
        log.Low(L"[prefetch] запусков из Temp/Загрузок: " + std::to_wstring(notable));
    r.note = L"parsed=" + std::to_wstring(parsed) + L" in_window=" +
             std::to_wstring((int)r.findings.size()) + L" with_path=" + std::to_wstring(withPath);
    return r;
}

} // namespace modules
