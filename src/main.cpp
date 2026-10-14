// main.cpp — лаунчер агента телеметрии: Win32 GUI в тёмно-фиолетовой теме.
//
// Чистый Win32 + GDI, без внешних зависимостей. Раскладка:
//   шапка (бренд + статус прав) / боковая панель (действия + статусы модулей) /
//   карточки-сводка, прогресс, цветной журнал (RichEdit) / статус-бар.
// Всё масштабируется под DPI монитора (PerMonitorV2 из манифеста), отрисовка
// идёт через внеэкранный буфер — без мерцания. Сканирование идёт в фоновом
// потоке; строки лога, прогресс и результат приходят через PostMessage.

#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <richedit.h>
#include <algorithm>
#include <string>
#include <vector>
#include <memory>
#include "logger.h"
#include "scanner.h"
#include "report.h"
#include "util.h"

#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

// ---- палитра (Deep Purple) -------------------------------------------------
namespace clr {
    const COLORREF kBg       = RGB(15, 12, 24);   // фон контента
    const COLORREF kSurface  = RGB(23, 18, 37);   // шапка, боковая панель, статус-бар
    const COLORREF kCard     = RGB(29, 23, 47);   // карточки, кнопки
    const COLORREF kCardHi   = RGB(40, 32, 64);   // карточка при наведении / активная строка
    const COLORREF kLogBg    = RGB(12, 9, 20);    // фон журнала
    const COLORREF kBorder   = RGB(52, 42, 84);
    const COLORREF kAccent   = RGB(132, 94, 230); // фиолетовый акцент
    const COLORREF kAccentHi = RGB(158, 124, 245);
    const COLORREF kAccentDn = RGB(104, 72, 190);
    const COLORREF kText     = RGB(234, 230, 246);
    const COLORREF kTextDim  = RGB(158, 148, 190);
    const COLORREF kTextMute = RGB(102, 94, 134);
    const COLORREF kHigh     = RGB(242, 110, 140);
    const COLORREF kMed      = RGB(240, 184, 96);
    const COLORREF kLow      = RGB(120, 162, 246);
    const COLORREF kOk       = RGB(96, 212, 150);
}

// Иконки из Segoe MDL2 Assets (есть в Windows 10/11).
namespace glyph {
    const wchar_t* kOpen    = L"";   // OpenFile
    const wchar_t* kAudit   = L"";
    const wchar_t* kProcess = L"";
    const wchar_t* kQuick   = L"";
    const wchar_t* kSave    = L"";
    const wchar_t* kStop    = L"";
    const wchar_t* kShield  = L"";
    const wchar_t* kWarn    = L"";
}

enum {
    IDC_BTN_FULL = 1001, IDC_BTN_PROC, IDC_BTN_QUICK, IDC_BTN_EXPORT, IDC_BTN_OPEN, IDC_BTN_STOP,
    IDC_LOG = 1010, IDC_VIEWER = 1011
};
#define WM_APP_LOG  (WM_APP + 1)
#define WM_APP_DONE (WM_APP + 2)
#define WM_APP_STEP (WM_APP + 3)
constexpr UINT_PTR kAnimTimer = 1;

// ---- состояние модулей в боковой панели ------------------------------------
enum class ModState { Idle, Pending, Running, Ok, Skipped, Error, Cancelled };

struct ModRow {
    const wchar_t* id;
    const wchar_t* label;
    ModState st = ModState::Idle;
    int findings = 0, high = 0, medium = 0, low = 0;
    RECT rc{};   // область строки на экране — для клика-фильтра (заполняется при отрисовке)
};

// Структурированная запись журнала: храним все строки, чтобы перерисовывать
// журнал под активный фильтр (по важности и/или по модулю).
struct LogEntry {
    Severity     sev = Severity::Info;
    std::wstring mod;            // id модуля или пусто
    std::wstring text;           // текст сообщения (без префикса [module])
    std::wstring time;           // местное время HH:MM:SS
    std::wstring saved;          // строка для «Сохранить журнал» (дата+метка+модуль+текст)
    bool         divider = false;
    std::wstring dividerTitle;
};

// Фильтр журнала по важности. All — показывать всё (включая INFO и разделители).
enum class SevFilter { All, High, Medium, Low };

struct ButtonInfo {
    int id;
    const wchar_t* icon;
    const wchar_t* title;
    const wchar_t* subtitle;   // nullptr — однострочная кнопка
    bool primary;
    bool danger;
};

static const ButtonInfo kButtons[] = {
    { IDC_BTN_FULL,   glyph::kAudit,   L"Полный аудит",       L"Все уровни 1–4",                 true,  false },
    { IDC_BTN_PROC,   glyph::kProcess, L"Проверка процессов", L"Память игры и окружение",        false, false },
    { IDC_BTN_QUICK,  glyph::kQuick,   L"Быстрый скан",       L"Prefetch, реестр, автозагрузка", false, false },
    { IDC_BTN_EXPORT, glyph::kSave,    L"Экспорт отчёта",     L"JSON + SHA256-дайджест",         false, false },
    { IDC_BTN_OPEN,   glyph::kOpen,    L"Удалённые файлы",    L"Из последнего скана",            false, false },
    { IDC_BTN_STOP,   glyph::kStop,    L"Остановить",         nullptr,                           false, true  },
};
constexpr int kButtonCount = (int)(sizeof(kButtons) / sizeof(kButtons[0]));

// ---- глобальное состояние GUI ---------------------------------------------
struct AppState {
    HWND hwnd = nullptr, log = nullptr;
    HWND viewer = nullptr;          // встроенный вьюер отчёта (RichEdit)
    bool inReport = false;          // показан вьюер вместо карточек/журнала
    std::wstring reportName;        // имя открытого файла отчёта / подпись вьюера
    std::wstring viewerTitle = L"ОТЧЁТ ФОРЕНЗИКИ";  // заголовок шапки вьюера
    HWND buttons[kButtonCount] = {};
    UINT dpi = 96;
    HFONT fTitle = nullptr, fUi = nullptr, fSmall = nullptr, fLabel = nullptr,
          fNum = nullptr, fMono = nullptr, fIcon = nullptr, fIconBig = nullptr;
    Scanner scanner;
    std::vector<ModuleResult> lastResults;
    std::wstring status = L"Готов. Выберите тип проверки.";
    HWND hoverBtn = nullptr;
    WNDPROC btnProc = nullptr;   // исходная оконная процедура BUTTON
    WNDPROC logProc = nullptr;   // исходная оконная процедура RichEdit
    std::vector<LogEntry> entries;        // полный журнал (для фильтрации и сохранения)
    SevFilter sevFilter = SevFilter::All; // активный фильтр по важности
    std::wstring modFilter;               // активный фильтр по модулю (id) или пусто
    RECT rcSevChip[3]{};                  // кликабельные метки HIGH/MEDIUM/LOW в шапке журнала
    RECT rcSevReset{};                    // кнопка «Сбросить фильтр» в шапке журнала
    RECT rcModReset{};                    // кнопка «Сбросить фильтр» под списком модулей

    std::vector<ModRow> rows = {
        { L"environment", L"Окружение" },
        { L"prefetch",    L"Prefetch" },
        { L"registry",    L"Реестр" },
        { L"persistence", L"Автозагрузка" },
        { L"filesystem",  L"Файловая система" },
        { L"deleted",     L"Удалённые файлы" },
        { L"lua",         L"Lua-читы GMod" },
        { L"drivers",     L"Драйверы ядра" },
        { L"memory",      L"Память игры" },
        { L"tools",       L"Читы и макросы" },
    };
    int stepDone = 0, stepTotal = 0;
    std::wstring stepLabel;
    ULONGLONG scanStart = 0, scanElapsed = 0;
    bool stopping = false;
    bool hasRun = false;
    int anim = 0;

    // вычисляемая раскладка
    RECT rcHeader{}, rcSidebar{}, rcModules{}, rcCards[4]{}, rcProgress{}, rcLogCard{}, rcStatus{};
    RECT rcViewer{}, rcViewerHdr{};   // область встроенного вьюера отчёта
};
static AppState g;

// ---- DPI -------------------------------------------------------------------
static int S(int v) { return MulDiv(v, (int)g.dpi, 96); }

static UINT DpiForWindow(HWND hwnd) {
    using Fn = UINT (WINAPI*)(HWND);
    static Fn fn = (Fn)GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow");
    if (fn && hwnd) return fn(hwnd);
    HDC dc = GetDC(nullptr);
    UINT d = (UINT)GetDeviceCaps(dc, LOGPIXELSY);
    ReleaseDC(nullptr, dc);
    return d;
}

// ---- шрифты ----------------------------------------------------------------
static bool FontInstalled(const wchar_t* face) {
    LOGFONTW lf{}; lf.lfCharSet = DEFAULT_CHARSET;
    lstrcpynW(lf.lfFaceName, face, LF_FACESIZE);
    bool found = false;
    HDC dc = GetDC(nullptr);
    EnumFontFamiliesExW(dc, &lf, [](const LOGFONTW*, const TEXTMETRICW*, DWORD, LPARAM p) -> int {
        *(bool*)p = true; return 0;
    }, (LPARAM)&found, 0);
    ReleaseDC(nullptr, dc);
    return found;
}

static HFONT MakeFont(int px, int weight, const wchar_t* face) {
    return CreateFontW(-S(px), 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE, face);
}

static void DestroyFonts() {
    for (HFONT* f : { &g.fTitle, &g.fUi, &g.fSmall, &g.fLabel, &g.fNum, &g.fMono, &g.fIcon, &g.fIconBig })
        if (*f) { DeleteObject(*f); *f = nullptr; }
}

static void CreateFonts() {
    DestroyFonts();
    static const wchar_t* mono = FontInstalled(L"Cascadia Mono") ? L"Cascadia Mono" : L"Consolas";
    g.fTitle   = MakeFont(18, FW_BOLD,     L"Segoe UI");
    g.fUi      = MakeFont(14, FW_SEMIBOLD, L"Segoe UI");
    g.fSmall   = MakeFont(12, FW_NORMAL,   L"Segoe UI");
    g.fLabel   = MakeFont(11, FW_BOLD,     L"Segoe UI");
    g.fNum     = MakeFont(28, FW_SEMIBOLD, L"Segoe UI");
    g.fMono    = MakeFont(13, FW_NORMAL,   mono);
    g.fIcon    = MakeFont(15, FW_NORMAL,   L"Segoe MDL2 Assets");
    g.fIconBig = MakeFont(18, FW_NORMAL,   L"Segoe MDL2 Assets");
}

// ---- примитивы рисования ---------------------------------------------------
static void FillRectColor(HDC dc, const RECT& rc, COLORREF c) {
    HBRUSH b = CreateSolidBrush(c);
    FillRect(dc, &rc, b);
    DeleteObject(b);
}

static void RoundBox(HDC dc, const RECT& rc, int radius, COLORREF fill, COLORREF border) {
    HBRUSH b = CreateSolidBrush(fill);
    HPEN p = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ ob = SelectObject(dc, b), op = SelectObject(dc, p);
    RoundRect(dc, rc.left, rc.top, rc.right, rc.bottom, radius, radius);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(b); DeleteObject(p);
}

static void Dot(HDC dc, int cx, int cy, int r, COLORREF c) {
    RECT rc{ cx - r, cy - r, cx + r + 1, cy + r + 1 };
    RoundBox(dc, rc, r * 2 + 1, c, c);
}

static void Text(HDC dc, const std::wstring& s, RECT rc, HFONT f, COLORREF c, UINT flags) {
    HGDIOBJ of = SelectObject(dc, f);
    SetTextColor(dc, c);
    DrawTextW(dc, s.c_str(), -1, &rc, flags | DT_NOPREFIX);
    SelectObject(dc, of);
}

static int TextWidth(HDC dc, const std::wstring& s, HFONT f) {
    HGDIOBJ of = SelectObject(dc, f);
    SIZE sz{}; GetTextExtentPoint32W(dc, s.c_str(), (int)s.size(), &sz);
    SelectObject(dc, of);
    return sz.cx;
}

// Двойная буферизация: рисуем в память, затем одним BitBlt на экран.
struct BufferedDC {
    HDC target, mem; HBITMAP bmp; HGDIOBJ old; RECT rc;
    BufferedDC(HDC dc, const RECT& r) : target(dc), rc(r) {
        mem = CreateCompatibleDC(dc);
        bmp = CreateCompatibleBitmap(dc, r.right - r.left, r.bottom - r.top);
        old = SelectObject(mem, bmp);
        SetWindowOrgEx(mem, r.left, r.top, nullptr);
        SetBkMode(mem, TRANSPARENT);
    }
    ~BufferedDC() {
        SetWindowOrgEx(mem, 0, 0, nullptr);
        BitBlt(target, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, mem, 0, 0, SRCCOPY);
        SelectObject(mem, old); DeleteObject(bmp); DeleteDC(mem);
    }
};

// ---- журнал (RichEdit с цветом по важности) --------------------------------
static COLORREF SeverityColor(Severity s) {
    switch (s) {
        case Severity::High:   return clr::kHigh;
        case Severity::Medium: return clr::kMed;
        case Severity::Low:    return clr::kLow;
        default:               return clr::kTextMute;
    }
}

// Строка журнала на экране — колонки фиксированной ширины (моноширинный шрифт):
//   14:02:11  HIGH    memory      текст сообщения, перенос строки
//                                 выравнивается по колонке текста
// Метка важности для INFO не выводится — так заметнее то, что важно.
constexpr int kTimeCol = 10;          // "14:02:11" + 2 пробела
constexpr int kTagCol  = 8;           // "MEDIUM" + 2 пробела
constexpr int kModCol  = 13;          // "environment" + 2 пробела
constexpr int kMaxLogLines = 5000;    // старые строки отбрасываются

static std::wstring Pad(std::wstring s, int width) {
    if ((int)s.size() < width) s.resize(width, L' ');
    return s;
}

static std::wstring LocalTime(bool withDate) {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t b[32];
    if (withDate)
        swprintf(b, 32, L"%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond);
    else
        swprintf(b, 32, L"%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
    return b;
}

// Модули пишут "[prefetch] текст" — выносим имя модуля в отдельную колонку.
static void SplitModule(const std::wstring& msg, std::wstring& mod, std::wstring& text) {
    mod.clear(); text = msg;
    if (msg.size() < 3 || msg[0] != L'[') return;
    size_t e = msg.find(L']');
    if (e == std::wstring::npos || e < 2 || e > (size_t)kModCol) return;
    std::wstring m = msg.substr(1, e - 1);
    for (wchar_t c : m) if (!((c >= L'a' && c <= L'z') || c == L'_')) return;
    mod = m;
    text = util::Trim(msg.substr(e + 1));
}

// "======== НАЧАЛО АУДИТА ========" -> заголовок раздела.
static bool IsDivider(const std::wstring& msg, std::wstring& title) {
    if (msg.size() < 4 || msg.compare(0, 3, L"===") != 0) return false;
    size_t b = msg.find_first_not_of(L"= "), e = msg.find_last_not_of(L"= ");
    title = (b == std::wstring::npos) ? L"" : msg.substr(b, e - b + 1);
    return true;
}

static void LogWrite(const std::wstring& text, COLORREF color, bool bold = false) {
    int len = GetWindowTextLengthW(g.log);   // может быть больше реального — RichEdit обрежет до конца
    CHARRANGE cr{ len, len };
    SendMessageW(g.log, EM_EXSETSEL, 0, (LPARAM)&cr);
    CHARFORMAT2W cf{}; cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR | CFM_BOLD;
    cf.crTextColor = color;
    cf.dwEffects = bold ? CFE_BOLD : 0;
    SendMessageW(g.log, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(g.log, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
}

// На время дописывания: без перерисовки, с сохранением выделения пользователя и
// позиции прокрутки. Вниз журнал прокручивается, только если пользователь и так
// был внизу — иначе можно спокойно читать старые строки во время скана.
struct LogAppendScope {
    CHARRANGE sel{};
    POINT scroll{};
    bool atBottom = true;
    bool trimmed = false;

    LogAppendScope() {
        SCROLLINFO si{};
        si.cbSize = sizeof(si);
        si.fMask = SIF_ALL;
        if (GetScrollInfo(g.log, SB_VERT, &si) && si.nMax > 0 && si.nPage > 0)
            atBottom = si.nPos + (int)si.nPage >= si.nMax - 2;
        SendMessageW(g.log, EM_EXGETSEL, 0, (LPARAM)&sel);
        SendMessageW(g.log, EM_GETSCROLLPOS, 0, (LPARAM)&scroll);
        SendMessageW(g.log, WM_SETREDRAW, FALSE, 0);
    }
    ~LogAppendScope() {
        int lines = (int)SendMessageW(g.log, EM_GETLINECOUNT, 0, 0);
        if (lines > kMaxLogLines + 500) {
            LONG cut = (LONG)SendMessageW(g.log, EM_LINEINDEX, lines - kMaxLogLines, 0);
            CHARRANGE head{ 0, cut };
            SendMessageW(g.log, EM_EXSETSEL, 0, (LPARAM)&head);
            SendMessageW(g.log, EM_REPLACESEL, FALSE, (LPARAM)L"");
            trimmed = true;
        }
        if (!trimmed) SendMessageW(g.log, EM_EXSETSEL, 0, (LPARAM)&sel);
        SendMessageW(g.log, WM_SETREDRAW, TRUE, 0);
        if (atBottom) SendMessageW(g.log, WM_VSCROLL, SB_BOTTOM, 0);
        else if (!trimmed) SendMessageW(g.log, EM_SETSCROLLPOS, 0, (LPARAM)&scroll);
        InvalidateRect(g.log, nullptr, TRUE);
    }
};

// Проходит ли запись активный фильтр (по важности и по модулю).
static bool EntryPassesFilter(const LogEntry& e) {
    if (g.sevFilter == SevFilter::All && g.modFilter.empty()) return true;
    if (e.divider) return false;   // разделители — только в полном виде
    if (g.sevFilter != SevFilter::All) {
        Severity want = g.sevFilter == SevFilter::High   ? Severity::High
                      : g.sevFilter == SevFilter::Medium ? Severity::Medium : Severity::Low;
        if (e.sev != want) return false;
    }
    if (!g.modFilter.empty() && e.mod != g.modFilter) return false;
    return true;
}

// Отрисовать одну запись в RichEdit (в конец). Прокрутку/перерисовку
// контролирует вызывающий (LogAppendScope при дописывании, или RebuildLog).
static void WriteEntryToLog(const LogEntry& e) {
    bool empty = GetWindowTextLengthW(g.log) == 0;
    if (e.divider) {
        std::wstring line = L"── " + e.dividerTitle + L" ";
        line.resize(std::max<size_t>(line.size(), 48), L'─');
        LogWrite((empty ? L"" : L"\r\n") + line + L"\r\n", clr::kAccentHi, true);
        return;
    }
    LogWrite(Pad(e.time, kTimeCol), clr::kTextMute);
    if (e.sev == Severity::Info) LogWrite(Pad(L"", kTagCol), clr::kTextMute);
    else                         LogWrite(Pad(SeverityName(e.sev), kTagCol), SeverityColor(e.sev), true);
    LogWrite(Pad(e.mod, kModCol), clr::kAccentHi);

    COLORREF body = e.sev == Severity::High   ? clr::kHigh
                  : e.sev == Severity::Medium ? clr::kMed
                  : e.sev == Severity::Low    ? clr::kText : clr::kTextDim;
    LogWrite(e.text + L"\r\n", body);
}

static void AppendLog(Severity sev, const std::wstring& msg) {
    std::wstring mod, text, title;
    SplitModule(msg, mod, text);

    LogEntry e;
    e.sev  = sev;
    e.time = LocalTime(false);
    e.saved = LocalTime(true) + L"  " + Pad(SeverityName(sev), kTagCol) + Pad(mod, kModCol) + text;
    if (IsDivider(msg, title)) { e.divider = true; e.dividerTitle = title; }
    else                       { e.mod = mod; e.text = text; }

    g.entries.push_back(std::move(e));
    if ((int)g.entries.size() > kMaxLogLines + 500)
        g.entries.erase(g.entries.begin(), g.entries.end() - kMaxLogLines);

    if (!EntryPassesFilter(g.entries.back())) return;   // при активном фильтре не дописываем
    LogAppendScope scope;
    WriteEntryToLog(g.entries.back());
}

// Висячий отступ: перенесённая часть длинной строки встаёт под колонку текста,
// а не под время. Не трогает шрифт и цвета — безопасно вызывать после записи
// цветных строк (в отличие от WM_SETFONT, который сбрасывает цвета на чёрный).
static void ApplyLogParaFormat() {
    HDC dc = GetDC(nullptr);
    HGDIOBJ of = SelectObject(dc, g.fMono);
    SIZE ch{}; GetTextExtentPoint32W(dc, L"0", 1, &ch);
    int sysDpi = GetDeviceCaps(dc, LOGPIXELSX);
    SelectObject(dc, of);
    ReleaseDC(nullptr, dc);

    PARAFORMAT2 pf{}; pf.cbSize = sizeof(pf);
    pf.dwMask = PFM_STARTINDENT | PFM_OFFSET | PFM_SPACEAFTER;
    pf.dxStartIndent = 0;
    pf.dxOffset = MulDiv(ch.cx * (kTimeCol + kTagCol + kModCol), 1440, sysDpi);
    pf.dySpaceAfter = 40;   // 2 pt воздуха между строками
    CHARRANGE sel{}, all{ 0, -1 };
    SendMessageW(g.log, EM_EXGETSEL, 0, (LPARAM)&sel);
    SendMessageW(g.log, EM_EXSETSEL, 0, (LPARAM)&all);
    SendMessageW(g.log, EM_SETPARAFORMAT, 0, (LPARAM)&pf);
    SendMessageW(g.log, EM_EXSETSEL, 0, (LPARAM)&sel);
}

static void ApplyLogFont() {
    SendMessageW(g.log, WM_SETFONT, (WPARAM)g.fMono, TRUE);
    // WM_SETFONT меняет только формат по умолчанию — переносим размер на уже
    // записанный текст, не трогая цвета строк.
    CHARFORMAT2W cf{}; cf.cbSize = sizeof(cf);
    SendMessageW(g.log, EM_GETCHARFORMAT, SCF_DEFAULT, (LPARAM)&cf);
    cf.dwMask = CFM_FACE | CFM_SIZE | CFM_CHARSET;
    SendMessageW(g.log, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    ApplyLogParaFormat();
}

static void Invalidate(const RECT& rc);   // объявление ниже

// Полностью перерисовать журнал из g.entries под текущий фильтр.
static void RebuildLog() {
    SendMessageW(g.log, WM_SETREDRAW, FALSE, 0);
    SetWindowTextW(g.log, L"");
    for (auto& e : g.entries)
        if (EntryPassesFilter(e)) WriteEntryToLog(e);
    ApplyLogParaFormat();   // только отступы — цвета строк не трогаем
    CHARRANGE top{ 0, 0 };
    SendMessageW(g.log, EM_EXSETSEL, 0, (LPARAM)&top);
    SendMessageW(g.log, WM_VSCROLL, SB_TOP, 0);
    SendMessageW(g.log, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g.log, nullptr, TRUE);
}

// Переключить фильтр по важности (повторный клик по активной метке — сброс).
static void ToggleSevFilter(SevFilter f) {
    g.sevFilter = (g.sevFilter == f) ? SevFilter::All : f;
    RebuildLog();
    Invalidate(g.rcLogCard);
}

// Переключить фильтр по модулю (повторный клик по активному модулю — сброс).
static void ToggleModFilter(const std::wstring& id) {
    g.modFilter = (g.modFilter == id) ? std::wstring() : id;
    RebuildLog();
    Invalidate(g.rcLogCard);
    Invalidate(g.rcSidebar);
}

// Сбросить все фильтры (без перерисовки журнала — вызывается перед очисткой).
static void ResetFilters() {
    g.sevFilter = SevFilter::All;
    g.modFilter.clear();
}

// ---- меню журнала (ПКМ): копировать / выделить всё / сохранить / очистить --
enum { IDM_LOG_COPY = 3001, IDM_LOG_SELALL, IDM_LOG_SAVE, IDM_LOG_CLEAR, IDM_LOG_RESET };

static void SaveLogToFile() {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t path[MAX_PATH];
    swprintf(path, MAX_PATH, L"journal_%04u%02u%02u_%02u%02u%02u.txt",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g.hwnd;
    ofn.lpstrFilter = L"Текстовый файл\0*.txt\0Все файлы\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;

    std::wstring all;
    for (auto& e : g.entries) { all += e.saved; all += L"\r\n"; }
    std::string utf8 = "\xEF\xBB\xBF" + util::Narrow(all);
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD w = 0;
    bool ok = h != INVALID_HANDLE_VALUE &&
              WriteFile(h, utf8.data(), (DWORD)utf8.size(), &w, nullptr) && w == utf8.size();
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    AppendLog(ok ? Severity::Info : Severity::High,
              ok ? std::wstring(L"Журнал сохранён: ") + path : L"Не удалось сохранить журнал.");
}

static void ShowLogMenu(LPARAM lp) {
    POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
    if (lp == -1) {   // вызов с клавиатуры (Shift+F10 / клавиша меню)
        RECT r; GetWindowRect(g.log, &r);
        pt = { r.left + S(12), r.top + S(12) };
    }
    CHARRANGE sel{};
    SendMessageW(g.log, EM_EXGETSEL, 0, (LPARAM)&sel);

    bool filtered = g.sevFilter != SevFilter::All || !g.modFilter.empty();
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING | (sel.cpMax > sel.cpMin ? 0 : MF_GRAYED), IDM_LOG_COPY, L"Копировать\tCtrl+C");
    AppendMenuW(m, MF_STRING, IDM_LOG_SELALL, L"Выделить всё\tCtrl+A");
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING | (filtered ? 0 : MF_GRAYED), IDM_LOG_RESET, L"Показать все (сбросить фильтр)");
    AppendMenuW(m, MF_STRING | (g.entries.empty() ? MF_GRAYED : 0), IDM_LOG_SAVE, L"Сохранить журнал…");
    AppendMenuW(m, MF_STRING, IDM_LOG_CLEAR, L"Очистить журнал");
    int cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g.hwnd, nullptr);
    DestroyMenu(m);

    switch (cmd) {
    case IDM_LOG_COPY:
        SendMessageW(g.log, WM_COPY, 0, 0);
        break;
    case IDM_LOG_SELALL: {
        CHARRANGE all{ 0, -1 };
        SendMessageW(g.log, EM_EXSETSEL, 0, (LPARAM)&all);
        SetFocus(g.log);
        break;
    }
    case IDM_LOG_SAVE:
        SaveLogToFile();
        break;
    case IDM_LOG_RESET:
        ResetFilters();
        RebuildLog();
        Invalidate(g.rcLogCard);
        Invalidate(g.rcSidebar);
        break;
    case IDM_LOG_CLEAR:
        g.entries.clear();
        ResetFilters();
        SetWindowTextW(g.log, L"");
        ApplyLogFont();   // вернуть отступы пустому документу
        Invalidate(g.rcLogCard);
        Invalidate(g.rcSidebar);
        break;
    }
}

// ---- тёмная тема системных элементов (заголовок окна, полосы прокрутки) ----
static void ApplyDarkChrome(HWND hwnd) {
    if (HMODULE dwm = LoadLibraryW(L"dwmapi.dll")) {
        using Fn = HRESULT (WINAPI*)(HWND, DWORD, LPCVOID, DWORD);
        if (auto set = (Fn)GetProcAddress(dwm, "DwmSetWindowAttribute")) {
            BOOL dark = TRUE;
            set(hwnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &dark, sizeof(dark));
            COLORREF caption = clr::kSurface;
            set(hwnd, 35 /*DWMWA_CAPTION_COLOR, Win11*/, &caption, sizeof(caption));
        }
    }
}

static void ApplyDarkScrollbars(HWND ctl) {
    if (HMODULE ux = LoadLibraryW(L"uxtheme.dll")) {
        using Fn = HRESULT (WINAPI*)(HWND, LPCWSTR, LPCWSTR);
        if (auto set = (Fn)GetProcAddress(ux, "SetWindowTheme"))
            set(ctl, L"DarkMode_Explorer", nullptr);
    }
}

// ---- helpers ---------------------------------------------------------------
static void Invalidate(const RECT& rc) { InvalidateRect(g.hwnd, &rc, FALSE); }

static void SetStatus(const std::wstring& s) {
    g.status = s;
    Invalidate(g.rcStatus);
}

// Каталог, где лежит сам агент (рядом лаунчер ищет report_latest.json).
static std::wstring AgentDir() {
    wchar_t buf[MAX_PATH]; GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring p = buf;
    size_t s = p.find_last_of(L"\\/");
    return (s == std::wstring::npos) ? L"." : p.substr(0, s);
}

static HWND Button(int id) {
    for (int i = 0; i < kButtonCount; i++) if (kButtons[i].id == id) return g.buttons[i];
    return nullptr;
}

static void UpdateButtons() {
    bool running = g.scanner.Running();
    EnableWindow(Button(IDC_BTN_FULL),   !running);
    EnableWindow(Button(IDC_BTN_PROC),   !running);
    EnableWindow(Button(IDC_BTN_QUICK),  !running);
    EnableWindow(Button(IDC_BTN_EXPORT), !running && !g.lastResults.empty());
    EnableWindow(Button(IDC_BTN_OPEN),   !running);
    EnableWindow(Button(IDC_BTN_STOP),   running && !g.stopping);
}

static ModRow* FindRow(const std::wstring& id) {
    for (auto& r : g.rows) if (id == r.id) return &r;
    return nullptr;
}

struct Totals { int findings = 0, high = 0, medium = 0, low = 0, ok = 0, ran = 0; };
static Totals ComputeTotals() {
    Totals t;
    for (auto& r : g.rows) {
        t.findings += r.findings; t.high += r.high; t.medium += r.medium; t.low += r.low;
        if (r.st == ModState::Ok) t.ok++;
        if (r.st == ModState::Ok || r.st == ModState::Skipped || r.st == ModState::Error) t.ran++;
    }
    return t;
}

static std::wstring FormatElapsed(ULONGLONG ms) {
    wchar_t b[32];
    swprintf(b, 32, L"%02llu:%02llu", ms / 60000, (ms / 1000) % 60);
    return b;
}

// ---- подписка Logger -> GUI (из воркер-потока) -----------------------------
static void InstallLogSink() {
    Logger::Instance().SetSink([](Severity sev, const std::wstring& msg) {
        auto* copy = new std::wstring(msg);
        if (!PostMessageW(g.hwnd, WM_APP_LOG, (WPARAM)sev, (LPARAM)copy))
            delete copy;
    });
}

// ---- запуск скана ----------------------------------------------------------
static void ShowReportView(bool on);   // определена ниже (вьюер отчёта)

static void StartScan(ScanProfile profile, const wchar_t* label) {
    if (g.scanner.Running()) return;
    if (g.inReport) ShowReportView(false);   // вернуться к журналу на время скана

    // Каждая новая проверка — журнал с чистого листа: старые события стираются,
    // новый аудит пишется заново. Так лог всегда относится к текущему скану.
    g.entries.clear();
    ResetFilters();
    SetWindowTextW(g.log, L"");
    ApplyLogFont();   // вернуть отступы/шрифт пустому документу

    auto plan = Scanner::ModulesFor(profile);
    for (auto& r : g.rows) {
        r = ModRow{ r.id, r.label };
        for (auto& id : plan) if (id == r.id) r.st = ModState::Pending;
    }
    g.stepDone = 0; g.stepTotal = (int)plan.size();
    g.stepLabel = L"Подготовка…";
    g.scanStart = GetTickCount64(); g.scanElapsed = 0;
    g.stopping = false; g.hasRun = true;

    g.scanner.StartAsync(profile,
        [](std::vector<ModuleResult> res) {
            auto* heap = new std::vector<ModuleResult>(std::move(res));
            if (!PostMessageW(g.hwnd, WM_APP_DONE, 0, (LPARAM)heap))
                delete heap;
        },
        [](const StepEvent& ev) {
            auto* heap = new StepEvent(ev);
            if (!PostMessageW(g.hwnd, WM_APP_STEP, 0, (LPARAM)heap))
                delete heap;
        });

    UpdateButtons();
    SetTimer(g.hwnd, kAnimTimer, 40, nullptr);
    SetStatus(std::wstring(L"Выполняется: ") + label + L"…");
    InvalidateRect(g.hwnd, nullptr, FALSE);
}

static void StopScan() {
    if (!g.scanner.Running() || g.stopping) return;
    g.stopping = true;
    g.scanner.RequestStop();
    UpdateButtons();
    SetStatus(L"Остановка после завершения текущего модуля…");
}

static void ExportReport() {
    if (g.lastResults.empty()) { AppendLog(Severity::Medium, L"Нет данных для экспорта — сначала выполните аудит."); return; }
    std::string json = report::BuildJson(g.lastResults);
    std::wstring digest = report::Digest(json);

    wchar_t path[MAX_PATH] = L"forensics_report.json";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g.hwnd;
    ofn.lpstrFilter = L"JSON отчёт\0*.json\0Все файлы\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"json";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;

    if (report::WriteToFile(path, json)) {
        AppendLog(Severity::Info, std::wstring(L"Отчёт сохранён: ") + path);
        AppendLog(Severity::Info, L"SHA256 отчёта: " + digest);
        SetStatus(L"Отчёт экспортирован.");
    } else {
        AppendLog(Severity::High, L"Не удалось записать файл отчёта.");
    }
}

// ---- встроенный вьюер отчёта ----------------------------------------------
// Индекс цвета строки отчёта в таблице цветов RTF (см. ViewerFill):
// 1=текст, 2=HIGH, 3=MEDIUM, 4=LOW, 5=OK, 6=акцент(module), 7=тускло.
static int ReportLineColorIdx(const std::wstring& ln) {
    auto has = [&](const wchar_t* s) { return ln.find(s) != std::wstring::npos; };
    if (has(L"\"HIGH\"")   || has(L"[HIGH]"))   return 2;
    if (has(L"\"MEDIUM\"") || has(L"[MEDIUM]")) return 3;
    if (has(L"\"LOW\"")    || has(L"[LOW]"))    return 4;
    if (has(L"\"status\"")) {
        if (has(L"error"))   return 2;
        if (has(L"skipped")) return 3;
        if (has(L"\"ok\""))  return 5;
    }
    if (has(L"\"module\"")) return 6;
    if (has(L"\"title\"") || has(L"\"severity\"") || has(L"\"note\"")) return 1;
    return 7;
}

// Экранирование строки в тело RTF: спецсимволы RTF и не-ASCII как \uN? .
static void RtfAppendEscaped(std::string& out, const std::wstring& ln) {
    for (wchar_t wc : ln) {
        unsigned c = (unsigned)wc;
        if (wc == L'\\' || wc == L'{' || wc == L'}') { out += '\\'; out += (char)c; }
        else if (c >= 0x20 && c < 0x80)              { out += (char)c; }
        else { out += "\\u"; out += std::to_string((int)(short)wc); out += '?'; }
    }
}

// Заполнение вьюера отчётом одним потоком RTF (EM_STREAMIN).
// Раньше отчёт вставлялся построчно, и каждый шаг звал GetWindowTextLengthW —
// это O(n²); на большом отчёте (скан Documents даёт тысячи строк JSON) UI
// «вис намертво» и окно показывало «не отвечает». Теперь формируем весь RTF и
// отдаём его RichEdit одним вызовом: разбор идёт внутри контрола, линейно.
static void ViewerFill(const std::wstring& text) {
    auto rgb = [](COLORREF c) {
        return "\\red"   + std::to_string(GetRValue(c)) +
               "\\green" + std::to_string(GetGValue(c)) +
               "\\blue"  + std::to_string(GetBValue(c)) + ";";
    };
    std::string rtf;
    rtf.reserve(text.size() * 2 + 256);
    rtf  = "{\\rtf1\\ansi\\ansicpg1251\\deff0{\\fonttbl{\\f0\\fmodern Consolas;}}{\\colortbl;";
    rtf += rgb(clr::kText);       // 1
    rtf += rgb(clr::kHigh);       // 2
    rtf += rgb(clr::kMed);        // 3
    rtf += rgb(clr::kLow);        // 4
    rtf += rgb(clr::kOk);         // 5
    rtf += rgb(clr::kAccentHi);   // 6
    rtf += rgb(clr::kTextDim);    // 7
    rtf += "}\\pard\\f0\\fs20 ";

    size_t i = 0;
    while (i <= text.size()) {
        size_t e = text.find(L'\n', i);
        size_t len = (e == std::wstring::npos ? text.size() : e) - i;
        std::wstring ln = text.substr(i, len);
        if (!ln.empty() && ln.back() == L'\r') ln.pop_back();
        rtf += "\\cf" + std::to_string(ReportLineColorIdx(ln)) + " ";
        RtfAppendEscaped(rtf, ln);
        rtf += "\\par\n";
        if (e == std::wstring::npos) break;
        i = e + 1;
    }
    rtf += "}";

    struct Ctx { const std::string* s; size_t pos; } ctx{ &rtf, 0 };
    EDITSTREAM es{};
    es.dwCookie = (DWORD_PTR)&ctx;
    es.pfnCallback = (EDITSTREAMCALLBACK) +[](DWORD_PTR cookie, LPBYTE buf, LONG cb, LONG* pcb) -> DWORD {
        auto* c = (Ctx*)cookie;
        size_t left = c->s->size() - c->pos;
        LONG n = ((size_t)cb < left) ? cb : (LONG)left;
        memcpy(buf, c->s->data() + c->pos, (size_t)n);
        c->pos += (size_t)n;
        *pcb = n;
        return 0;
    };

    SendMessageW(g.viewer, WM_SETREDRAW, FALSE, 0);
    SendMessageW(g.viewer, EM_STREAMIN, SF_RTF, (LPARAM)&es);
    CHARRANGE top{ 0, 0 };
    SendMessageW(g.viewer, EM_EXSETSEL, 0, (LPARAM)&top);
    SendMessageW(g.viewer, WM_VSCROLL, SB_TOP, 0);
    SendMessageW(g.viewer, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g.viewer, nullptr, TRUE);
}

// Переключение между основным видом (карточки/журнал) и вьюером отчёта.
static void ShowReportView(bool on) {
    g.inReport = on;
    ShowWindow(g.viewer, on ? SW_SHOW : SW_HIDE);
    ShowWindow(g.log,    on ? SW_HIDE : SW_SHOW);
    InvalidateRect(g.hwnd, nullptr, FALSE);
}

// Открыть во встроенном вьюере список удалённых файлов из последнего скана
// (факты категории "deleted": USN Journal + Корзина). Самые важные — сверху.
static void OpenDeletedFiles() {
    if (g.lastResults.empty()) {
        AppendLog(Severity::Medium, L"Нет данных — сначала выполните аудит "
                  L"(модуль «Удалённые файлы» входит в полный и быстрый скан).");
        SetStatus(L"Сначала выполните скан.");
        return;
    }

    std::vector<const Finding*> items;
    for (const auto& m : g.lastResults)
        for (const auto& f : m.findings)
            if (f.category == L"deleted") items.push_back(&f);
    std::stable_sort(items.begin(), items.end(),
        [](const Finding* a, const Finding* b) { return a->severity > b->severity; });

    auto fld = [](const Finding* f, const wchar_t* k) -> std::wstring {
        auto it = f->fields.find(k);
        return it == f->fields.end() ? std::wstring() : it->second;
    };

    int nHigh = 0, nMed = 0, nLow = 0;
    for (auto* f : items) {
        if (f->severity == Severity::High)        nHigh++;
        else if (f->severity == Severity::Medium) nMed++;
        else if (f->severity == Severity::Low)    nLow++;
    }

    std::wstring t;
    t += L"Удалённые файлы за последнюю сессию (USN Journal + Корзина).\n";
    t += L"Всего: " + std::to_wstring((int)items.size()) +
         L"    HIGH: " + std::to_wstring(nHigh) +
         L"    MEDIUM: " + std::to_wstring(nMed) +
         L"    LOW: " + std::to_wstring(nLow) + L"\n";
    t += L"------------------------------------------------------------\n\n";

    if (items.empty()) {
        t += L"В последнем скане удалённых файлов в окне времени не найдено.\n";
        t += L"Проверьте, что скан запускался от администратора, а тома — NTFS\n";
        t += L"(на FAT/exFAT журнала удалений нет).\n";
    }
    for (auto* f : items) {
        std::wstring name = fld(f, L"name"); if (name.empty()) name = f->title;
        std::wstring path = fld(f, L"path"), vol = fld(f, L"volume");
        std::wstring when = fld(f, L"deleted_time"), reason = fld(f, L"reason");
        std::wstring flags = fld(f, L"flags"), loc = fld(f, L"location");
        bool recycle = (fld(f, L"source") == L"recycle_bin");

        t += L"[" + std::wstring(SeverityName(f->severity)) + L"] " + name + L"\n";
        if (!when.empty()) t += L"    удалён:   " + when + L"\n";
        t += L"    путь:     " +
             (path.empty() ? (vol.empty() ? std::wstring(L"(каталог не восстановлен)")
                                          : vol + L"  (каталог не восстановлен)")
                           : path) + L"\n";
        std::wstring srcLine = L"    источник: " +
            std::wstring(recycle ? L"Корзина" : L"USN Journal");
        if (!reason.empty()) srcLine += L"    причина: " + reason;
        t += srcLine + L"\n";
        if (!loc.empty())   t += L"    зона:     " + loc + L"\n";
        if (!flags.empty()) t += L"    признаки: " + flags + L"\n";
        t += L"\n";
    }

    g.viewerTitle = L"УДАЛЁННЫЕ ФАЙЛЫ";
    g.reportName  = L"последний скан";
    ViewerFill(t);
    ShowReportView(true);
    SetStatus(L"Удалённые файлы: " + std::to_wstring((int)items.size()) +
              L" (HIGH " + std::to_wstring(nHigh) + L"). Кнопка «Закрыть» — назад.");
}

// ---- раскладка -------------------------------------------------------------
static int ButtonHeight(const ButtonInfo& b) { return b.subtitle ? S(52) : S(40); }

static void LayoutControls(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    const int headerH = S(64), statusH = S(30), sideW = S(272), pad = S(20);

    g.rcHeader  = { 0, 0, rc.right, headerH };
    g.rcStatus  = { 0, rc.bottom - statusH, rc.right, rc.bottom };
    g.rcSidebar = { 0, headerH, sideW, g.rcStatus.top };

    // боковая панель: заголовок «Действия», кнопки, заголовок «Модули», строки
    int x = S(16), w = sideW - S(32);
    int y = headerH + S(16) + S(22);
    for (int i = 0; i < kButtonCount; i++) {
        int h = ButtonHeight(kButtons[i]);
        if (kButtons[i].danger) y += S(4);
        MoveWindow(g.buttons[i], x, y, w, h, TRUE);
        y += h + S(6);
    }
    y += S(12);
    g.rcModules = { x, y, x + w, y + S(22) + (int)g.rows.size() * S(28) };

    // основная область: карточки, прогресс, журнал
    int mx = sideW + pad, mr = rc.right - pad;
    int cy = headerH + pad, ch = S(92), gap = S(12);
    int cw = (mr - mx - gap * 3) / 4;
    for (int i = 0; i < 4; i++)
        g.rcCards[i] = { mx + i * (cw + gap), cy, mx + i * (cw + gap) + cw, cy + ch };
    g.rcProgress = { mx, cy + ch + S(16), mr, cy + ch + S(16) + S(40) };
    g.rcLogCard  = { mx, g.rcProgress.bottom + S(12), mr, g.rcStatus.top - pad };

    int inset = S(14);
    MoveWindow(g.log, g.rcLogCard.left + inset, g.rcLogCard.top + S(40),
               g.rcLogCard.right - g.rcLogCard.left - inset - S(4),
               g.rcLogCard.bottom - g.rcLogCard.top - S(40) - S(8), TRUE);

    // вьюер отчёта занимает всю основную область (под шапкой с заголовком)
    g.rcViewer    = { mx, cy, mr, g.rcStatus.top - pad };
    g.rcViewerHdr = { g.rcViewer.left, g.rcViewer.top, g.rcViewer.right, g.rcViewer.top + S(34) };
    MoveWindow(g.viewer, g.rcViewer.left + inset, g.rcViewerHdr.bottom + S(6),
               g.rcViewer.right - g.rcViewer.left - inset - S(4),
               g.rcViewer.bottom - g.rcViewerHdr.bottom - S(6) - S(8), TRUE);
}

// ---- отрисовка owner-draw кнопки -------------------------------------------
static void DrawButton(LPDRAWITEMSTRUCT di) {
    const ButtonInfo* info = nullptr;
    for (auto& b : kButtons) if ((int)di->CtlID == b.id) info = &b;
    if (!info) return;

    bool pressed  = (di->itemState & ODS_SELECTED) != 0;
    bool disabled = (di->itemState & ODS_DISABLED) != 0;
    bool hover    = (di->hwndItem == g.hoverBtn) && !disabled;

    BufferedDC buf(di->hDC, di->rcItem);
    HDC dc = buf.mem;
    RECT rc = di->rcItem;
    FillRectColor(dc, rc, clr::kSurface);

    COLORREF fill = clr::kCard, border = clr::kBorder, text = clr::kText,
             sub = clr::kTextDim, icon = clr::kAccentHi, iconBg = clr::kCardHi;
    if (info->primary) {
        fill = pressed ? clr::kAccentDn : hover ? clr::kAccentHi : clr::kAccent;
        border = fill; text = RGB(255, 255, 255); sub = RGB(230, 220, 255);
        icon = RGB(255, 255, 255); iconBg = pressed ? clr::kAccent : clr::kAccentDn;
    } else if (info->danger) {
        fill = pressed ? RGB(70, 30, 48) : hover ? RGB(58, 28, 44) : clr::kSurface;
        border = clr::kHigh; text = clr::kHigh; icon = clr::kHigh;
    } else {
        if (hover)   { fill = clr::kCardHi; border = clr::kAccent; }
        if (pressed) { fill = clr::kBorder; }
    }
    if (disabled) {
        fill = info->danger ? clr::kSurface : clr::kCard;
        border = clr::kBorder; text = sub = icon = clr::kTextMute; iconBg = clr::kCard;
    }

    RECT box = rc; InflateRect(&box, -1, -1);
    RoundBox(dc, box, S(12), fill, border);

    // Кнопка «Удалённые файлы» во время просмотра работает как «Закрыть».
    const wchar_t* btnTitle = info->title;
    const wchar_t* btnSub   = info->subtitle;
    if (info->id == IDC_BTN_OPEN && g.inReport) {
        btnTitle = L"Закрыть";
        btnSub   = L"Вернуться к журналу";
    }

    int h = rc.bottom - rc.top;
    if (info->subtitle) {
        int is = S(32);
        RECT ib{ rc.left + S(10), rc.top + (h - is) / 2, rc.left + S(10) + is, rc.top + (h + is) / 2 };
        RoundBox(dc, ib, S(8), iconBg, iconBg);
        Text(dc, info->icon, ib, g.fIcon, icon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        int tx = ib.right + S(12);
        RECT t1{ tx, rc.top + S(8), rc.right - S(8), rc.top + h / 2 + S(2) };
        RECT t2{ tx, rc.top + h / 2 + S(1), rc.right - S(8), rc.bottom - S(6) };
        Text(dc, btnTitle, t1, g.fUi, text, DT_LEFT | DT_BOTTOM | DT_SINGLELINE | DT_END_ELLIPSIS);
        Text(dc, btnSub, t2, g.fSmall, sub, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS);
    } else {
        std::wstring title = btnTitle;
        int tw = TextWidth(dc, title, g.fUi) + S(26);
        int sx = rc.left + (rc.right - rc.left - tw) / 2;
        RECT ir{ sx, rc.top, sx + S(18), rc.bottom };
        Text(dc, info->icon, ir, g.fIcon, icon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        RECT tr{ sx + S(26), rc.top, rc.right, rc.bottom };
        Text(dc, title, tr, g.fUi, text, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
}

// ---- отрисовка окна --------------------------------------------------------
static void PaintHeader(HDC dc) {
    const RECT& h = g.rcHeader;
    FillRectColor(dc, h, clr::kSurface);
    RECT line{ h.left, h.bottom - 1, h.right, h.bottom };
    FillRectColor(dc, line, clr::kBorder);

    // логотип-марка
    int ls = S(36), ly = (h.bottom - ls) / 2;
    RECT logo{ S(18), ly, S(18) + ls, ly + ls };
    RoundBox(dc, logo, S(10), clr::kAccent, clr::kAccentHi);
    Text(dc, glyph::kShield, logo, g.fIconBig, RGB(255, 255, 255), DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    int tx = logo.right + S(14);
    RECT t1{ tx, h.top + S(11), h.right / 2, h.top + S(36) };
    Text(dc, L"FUSION · FORENSICS", t1, g.fTitle, clr::kText, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    RECT t2{ tx, h.top + S(35), h.right / 2, h.top + S(54) };
    Text(dc, L"Endpoint Telemetry Agent · Garry's Mod", t2, g.fSmall, clr::kTextDim, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    // бейдж прав справа
    bool elevated = util::IsElevated();
    std::wstring badge = elevated ? L"Администратор" : L"Без прав администратора";
    COLORREF bc = elevated ? clr::kOk : clr::kMed;
    int bw = TextWidth(dc, badge, g.fSmall) + S(46), bh = S(28);
    RECT b{ h.right - S(20) - bw, (h.bottom - bh) / 2, h.right - S(20), (h.bottom + bh) / 2 };
    RoundBox(dc, b, bh, clr::kCard, bc);
    RECT bi{ b.left + S(12), b.top, b.left + S(30), b.bottom };
    Text(dc, elevated ? glyph::kShield : glyph::kWarn, bi, g.fIcon, bc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT bt{ b.left + S(34), b.top, b.right - S(10), b.bottom };
    Text(dc, badge, bt, g.fSmall, bc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

static void SectionLabel(HDC dc, const wchar_t* s, int x, int y, int w) {
    RECT r{ x, y, x + w, y + S(18) };
    Text(dc, s, r, g.fLabel, clr::kTextMute, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

static void PaintSidebar(HDC dc) {
    const RECT& s = g.rcSidebar;
    FillRectColor(dc, s, clr::kSurface);
    RECT line{ s.right - 1, s.top, s.right, s.bottom };
    FillRectColor(dc, line, clr::kBorder);

    int x = S(16), w = s.right - S(32);
    SectionLabel(dc, L"ДЕЙСТВИЯ", x + S(4), s.top + S(16), w);

    const RECT& m = g.rcModules;
    SectionLabel(dc, L"МОДУЛИ", m.left + S(4), m.top, w);

    int rowH = S(28), y = m.top + S(22);
    for (auto& r : g.rows) {
        RECT row{ m.left, y, m.right, y + rowH - S(2) };
        r.rc = row;   // для клика-фильтра по модулю
        bool activeFilter = (g.modFilter == r.id);
        if (activeFilter)
            RoundBox(dc, row, S(8), clr::kCardHi, clr::kAccent);
        else if (r.st == ModState::Running)
            RoundBox(dc, row, S(8), clr::kCardHi, clr::kCardHi);

        COLORREF dot = clr::kTextMute, label = clr::kTextDim, right = clr::kTextMute;
        std::wstring rtext;
        switch (r.st) {
            case ModState::Idle:      label = clr::kTextMute; rtext = L"—"; break;
            case ModState::Pending:   dot = clr::kBorder; rtext = L"ожидание"; break;
            case ModState::Running:   dot = (g.anim / 8) % 2 ? clr::kAccentHi : clr::kAccent;
                                      label = clr::kText; right = clr::kAccentHi;
                                      rtext = std::wstring(L"идёт") + std::wstring(1 + (g.anim / 8) % 3, L'.'); break;
            case ModState::Ok:        dot = clr::kOk; label = clr::kText;
                                      right = r.high ? clr::kHigh : r.medium ? clr::kMed : clr::kTextDim;
                                      rtext = std::to_wstring(r.findings); break;
            case ModState::Skipped:   dot = clr::kMed; right = clr::kMed; rtext = L"пропущен"; break;
            case ModState::Error:     dot = clr::kHigh; right = clr::kHigh; rtext = L"ошибка"; break;
            case ModState::Cancelled: rtext = L"отменён"; break;
        }
        if (activeFilter) label = clr::kText;
        int cy = (row.top + row.bottom) / 2;
        if (r.st == ModState::Idle) {
            RECT ring{ row.left + S(10), cy - S(4), row.left + S(19), cy + S(5) };
            RoundBox(dc, ring, S(9), clr::kSurface, clr::kBorder);
        } else {
            Dot(dc, row.left + S(14), cy, S(4), dot);
        }
        RECT lt{ row.left + S(28), row.top, row.right - S(70), row.bottom };
        Text(dc, r.label, lt, g.fUi, label, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        RECT rt{ row.right - S(80), row.top, row.right - S(10), row.bottom };
        Text(dc, rtext, rt, g.fSmall, right, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        y += rowH;
    }

    // Кнопка «Сбросить фильтр» под списком модулей — видна, когда фильтр активен.
    bool anyFilter = g.sevFilter != SevFilter::All || !g.modFilter.empty();
    g.rcModReset = RECT{};
    if (anyFilter && !g.inReport) {
        RECT b{ m.left, y + S(6), m.right, y + S(6) + S(26) };
        g.rcModReset = b;
        RoundBox(dc, b, S(8), clr::kCard, clr::kAccent);
        Text(dc, L"✕ Сбросить фильтр", b, g.fSmall, clr::kAccentHi,
             DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
}

static void PaintCard(HDC dc, const RECT& rc, const wchar_t* label, const std::wstring& value,
                      const std::wstring& caption, COLORREF accent, bool highlight) {
    RoundBox(dc, rc, S(14), clr::kCard, highlight ? accent : clr::kBorder);
    RECT stripe{ rc.left + S(1), rc.top + S(14), rc.left + S(4), rc.bottom - S(14) };
    FillRectColor(dc, stripe, accent);

    int x = rc.left + S(18), r = rc.right - S(12);
    Dot(dc, x + S(3), rc.top + S(22), S(3), accent);
    RECT lt{ x + S(14), rc.top + S(12), r, rc.top + S(32) };
    Text(dc, label, lt, g.fSmall, clr::kTextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    RECT vt{ x, rc.top + S(30), r, rc.top + S(66) };
    Text(dc, value, vt, g.fNum, highlight ? accent : clr::kText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT ct{ x, rc.top + S(64), r, rc.bottom - S(8) };
    Text(dc, caption, ct, g.fSmall, clr::kTextMute, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

static void PaintCards(HDC dc) {
    Totals t = ComputeTotals();
    std::wstring dash = L"—";
    bool any = g.hasRun;
    PaintCard(dc, g.rcCards[0], L"Собрано фактов", any ? std::to_wstring(t.findings) : dash,
              L"всего по всем модулям", clr::kAccentHi, false);
    PaintCard(dc, g.rcCards[1], L"Высокий приоритет", any ? std::to_wstring(t.high) : dash,
              L"проверить в первую очередь", clr::kHigh, t.high > 0);
    PaintCard(dc, g.rcCards[2], L"Средний приоритет", any ? std::to_wstring(t.medium) : dash,
              L"стоит просмотреть", clr::kMed, t.medium > 0);
    PaintCard(dc, g.rcCards[3], L"Модули", any ? std::to_wstring(t.ok) + L" / " + std::to_wstring(g.stepTotal) : dash,
              L"завершены успешно", clr::kOk, false);
}

static void PaintProgress(HDC dc) {
    const RECT& p = g.rcProgress;
    FillRectColor(dc, p, clr::kBg);
    bool running = g.scanner.Running();

    std::wstring left, right;
    if (running) {
        left = g.stepLabel;
        right = FormatElapsed(GetTickCount64() - g.scanStart);
    } else if (g.hasRun) {
        left = g.stopping ? L"Проверка остановлена" : L"Проверка завершена";
        right = L"за " + FormatElapsed(g.scanElapsed);
    } else {
        left = L"Ожидание запуска";
    }
    RECT lt{ p.left, p.top, p.right, p.top + S(22) };
    Text(dc, left, lt, g.fUi, running ? clr::kText : clr::kTextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    Text(dc, right, lt, g.fSmall, clr::kTextMute, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

    RECT track{ p.left, p.top + S(30), p.right, p.top + S(36) };
    RoundBox(dc, track, S(6), clr::kCard, clr::kCard);

    int width = track.right - track.left;
    double frac = 0;
    if (g.stepTotal > 0) {
        frac = (double)g.stepDone / g.stepTotal;
        if (running && g.stepDone < g.stepTotal) frac += 0.5 / g.stepTotal;
    }
    if (!running && g.hasRun && !g.stopping) frac = 1.0;
    int fw = (int)(width * frac);
    if (fw > 0) {
        RECT fill{ track.left, track.top, track.left + fw, track.bottom };
        RoundBox(dc, fill, S(6), clr::kAccent, clr::kAccent);
        if (running) {
            // бегущий блик по заполненной части — показывает, что работа идёт
            int seg = S(60), span = fw + seg;
            int pos = track.left - seg + (g.anim * S(6)) % (span > 0 ? span : 1);
            RECT sh{ std::max<int>(pos, (int)track.left), track.top,
                     std::min<int>(pos + seg, (int)fill.right), track.bottom };
            if (sh.right > sh.left) RoundBox(dc, sh, S(6), clr::kAccentHi, clr::kAccentHi);
        }
    }
}

static void PaintLogCard(HDC dc) {
    const RECT& c = g.rcLogCard;
    RoundBox(dc, c, S(14), clr::kLogBg, clr::kBorder);
    RECT title{ c.left + S(16), c.top + S(8), c.right - S(16), c.top + S(34) };

    // заголовок + текущий фильтр в подписи (видно, что журнал отфильтрован)
    std::wstring caption = L"Журнал событий";
    if (g.sevFilter != SevFilter::All)
        caption += std::wstring(L" · ") + (g.sevFilter == SevFilter::High   ? L"HIGH"
                                         : g.sevFilter == SevFilter::Medium ? L"MEDIUM" : L"LOW");
    if (!g.modFilter.empty()) {
        std::wstring ml = g.modFilter;
        for (auto& r : g.rows) if (g.modFilter == r.id) { ml = r.label; break; }
        caption += L" · " + ml;
    }
    Text(dc, caption, title, g.fUi, clr::kText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    // Кликабельные метки важности справа: клик фильтрует журнал, активная —
    // подсвечена «таблеткой». Строки INFO идут без метки.
    struct { const wchar_t* n; COLORREF c; SevFilter f; } legend[] = {
        { L"HIGH",   clr::kHigh, SevFilter::High   },
        { L"MEDIUM", clr::kMed,  SevFilter::Medium },
        { L"LOW",    clr::kLow,  SevFilter::Low    } };
    int x = title.right;
    for (int i = 2; i >= 0; i--) {
        int tw = TextWidth(dc, legend[i].n, g.fSmall);
        bool active = g.sevFilter == legend[i].f;
        RECT chip{ x - tw - S(20), title.top + S(1), x + S(2), title.bottom - S(1) };
        g.rcSevChip[i] = chip;   // для хит-теста клика
        if (active) RoundBox(dc, chip, (chip.bottom - chip.top), clr::kCardHi, legend[i].c);
        RECT lr{ x - tw, title.top, x, title.bottom };
        Text(dc, legend[i].n, lr, g.fSmall, active ? legend[i].c : clr::kTextDim,
             DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        Dot(dc, x - tw - S(8), (title.top + title.bottom) / 2, S(3), legend[i].c);
        x -= tw + S(28);
    }

    // Кнопка «Сбросить фильтр» слева от меток — видна, когда фильтр активен.
    bool anyFilter = g.sevFilter != SevFilter::All || !g.modFilter.empty();
    g.rcSevReset = RECT{};
    if (anyFilter) {
        std::wstring t = L"✕ Сбросить фильтр";
        int tw = TextWidth(dc, t, g.fSmall);
        RECT rb{ x - tw - S(20), title.top + S(1), x - S(6), title.bottom - S(1) };
        g.rcSevReset = rb;
        RoundBox(dc, rb, rb.bottom - rb.top, clr::kCard, clr::kAccent);
        Text(dc, t, rb, g.fSmall, clr::kAccentHi, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        x = rb.left - S(6);
    }

    // подсказка между заголовком и легендой (обрезается, если места мало)
    int capW = TextWidth(dc, caption, g.fUi);
    RECT hint{ title.left + capW + S(14), title.top, x, title.bottom };
    if (hint.right > hint.left)
        Text(dc, L"клик по метке/модулю — фильтр · ПКМ — меню", hint, g.fSmall, clr::kTextMute,
             DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    RECT line{ c.left + S(1), c.top + S(38), c.right - S(1), c.top + S(39) };
    FillRectColor(dc, line, clr::kBorder);
}

static void PaintStatus(HDC dc) {
    const RECT& s = g.rcStatus;
    FillRectColor(dc, s, clr::kSurface);
    RECT line{ s.left, s.top, s.right, s.top + 1 };
    FillRectColor(dc, line, clr::kBorder);
    bool running = g.scanner.Running();
    Dot(dc, s.left + S(18), (s.top + s.bottom) / 2, S(3), running ? clr::kAccentHi : clr::kOk);
    std::wstring hint = L"severity — приоритет для аналитика, не вердикт";
    int hw = TextWidth(dc, hint, g.fSmall);
    RECT ht{ s.right - S(16) - hw, s.top, s.right - S(16), s.bottom };
    Text(dc, hint, ht, g.fSmall, clr::kTextMute, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    RECT t{ s.left + S(30), s.top, ht.left - S(24), s.bottom };
    Text(dc, g.status, t, g.fSmall, running ? clr::kText : clr::kTextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

// Шапка встроенного вьюера отчёта: заголовок, имя файла, легенда важности.
static void PaintViewerHeader(HDC dc) {
    const RECT& v = g.rcViewer;
    RoundBox(dc, v, S(14), clr::kLogBg, clr::kBorder);
    RECT title{ v.left + S(16), v.top + S(8), v.right - S(16), v.top + S(32) };
    Text(dc, g.viewerTitle, title, g.fUi, clr::kText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    int nameX = title.left + TextWidth(dc, g.viewerTitle, g.fUi) + S(14);

    // легенда важности справа
    struct { const wchar_t* n; COLORREF c; } legend[] = {
        { L"HIGH", clr::kHigh }, { L"MEDIUM", clr::kMed }, { L"LOW", clr::kLow } };
    int x = v.right - S(16);
    for (int i = 2; i >= 0; i--) {
        int tw = TextWidth(dc, legend[i].n, g.fSmall);
        RECT lr{ x - tw, title.top, x, title.bottom };
        Text(dc, legend[i].n, lr, g.fSmall, clr::kTextDim, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        Dot(dc, x - tw - S(8), (title.top + title.bottom) / 2, S(3), legend[i].c);
        x -= tw + S(24);
    }

    // имя файла между заголовком и легендой
    RECT nm{ nameX, title.top, x - S(12), title.bottom };
    if (nm.right > nm.left)
        Text(dc, g.reportName, nm, g.fSmall, clr::kTextMute,
             DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

    RECT line{ v.left + S(1), g.rcViewerHdr.bottom, v.right - S(1), g.rcViewerHdr.bottom + 1 };
    FillRectColor(dc, line, clr::kBorder);
}

static void PaintWindow(HWND hwnd) {
    PAINTSTRUCT ps; HDC screen = BeginPaint(hwnd, &ps);
    RECT rc; GetClientRect(hwnd, &rc);
    if (rc.right > 0 && rc.bottom > 0) {
        BufferedDC buf(screen, rc);
        HDC dc = buf.mem;
        FillRectColor(dc, rc, clr::kBg);
        PaintHeader(dc);
        PaintSidebar(dc);
        if (g.inReport) {
            PaintViewerHeader(dc);
        } else {
            PaintCards(dc);
            PaintProgress(dc);
            PaintLogCard(dc);
        }
        PaintStatus(dc);
    }
    EndPaint(hwnd, &ps);
}

// ---- кнопки: подкласс для наведения и курсора-руки -------------------------
static LRESULT CALLBACK ButtonSubclass(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_MOUSEMOVE:
        if (g.hoverBtn != h) {
            HWND old = g.hoverBtn; g.hoverBtn = h;
            if (old) InvalidateRect(old, nullptr, FALSE);
            InvalidateRect(h, nullptr, FALSE);
            TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, h, 0 };
            TrackMouseEvent(&tme);
        }
        break;
    case WM_MOUSELEAVE:
        if (g.hoverBtn == h) { g.hoverBtn = nullptr; InvalidateRect(h, nullptr, FALSE); }
        break;
    case WM_SETCURSOR:
        if (IsWindowEnabled(h)) { SetCursor(LoadCursor(nullptr, IDC_HAND)); return TRUE; }
        break;
    case WM_ERASEBKGND:
        return 1;
    case WM_LBUTTONDBLCLK:   // двойной клик = обычное нажатие, без "залипания"
        msg = WM_LBUTTONDOWN;
        break;
    }
    return CallWindowProcW(g.btnProc, h, msg, wp, lp);
}

// Журнал: своё контекстное меню вместо стандартного поведения RichEdit.
static LRESULT CALLBACK LogSubclass(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_CONTEXTMENU) { ShowLogMenu(lp); return 0; }
    return CallWindowProcW(g.logProc, h, msg, wp, lp);
}

static HWND MakeButton(HWND parent, int id) {
    HWND b = CreateWindowExW(0, L"BUTTON", L"",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        0, 0, 10, 10, parent, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
    g.btnProc = (WNDPROC)SetWindowLongPtrW(b, GWLP_WNDPROC, (LONG_PTR)ButtonSubclass);
    return b;
}

// ---- оконная процедура -----------------------------------------------------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g.hwnd = hwnd;
        g.dpi = DpiForWindow(hwnd);
        CreateFonts();
        ApplyDarkChrome(hwnd);

        for (int i = 0; i < kButtonCount; i++) {
            g.buttons[i] = MakeButton(hwnd, kButtons[i].id);
            SetWindowTextW(g.buttons[i], kButtons[i].title);   // для экранного диктора
        }

        LoadLibraryW(L"Msftedit.dll");
        g.log = CreateWindowExW(0, MSFTEDIT_CLASS, L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)IDC_LOG, GetModuleHandleW(nullptr), nullptr);
        SendMessageW(g.log, EM_SETBKGNDCOLOR, 0, (LPARAM)clr::kLogBg);
        SendMessageW(g.log, EM_EXLIMITTEXT, 0, (LPARAM)(16 * 1024 * 1024));
        g.logProc = (WNDPROC)SetWindowLongPtrW(g.log, GWLP_WNDPROC, (LONG_PTR)LogSubclass);
        ApplyLogFont();
        ApplyDarkScrollbars(g.log);

        // встроенный вьюер отчёта (скрыт, пока не открыли отчёт)
        g.viewer = CreateWindowExW(0, MSFTEDIT_CLASS, L"",
            WS_CHILD | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY |
            ES_AUTOVSCROLL | ES_AUTOHSCROLL,
            0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)IDC_VIEWER, GetModuleHandleW(nullptr), nullptr);
        SendMessageW(g.viewer, EM_SETBKGNDCOLOR, 0, (LPARAM)clr::kLogBg);
        SendMessageW(g.viewer, WM_SETFONT, (WPARAM)g.fMono, TRUE);
        SendMessageW(g.viewer, EM_SETTARGETDEVICE, 0, 1);   // без переноса строк
        SendMessageW(g.viewer, EM_EXLIMITTEXT, 0, (LPARAM)(64 * 1024 * 1024));
        ApplyDarkScrollbars(g.viewer);

        UpdateButtons();
        LayoutControls(hwnd);
        AppendLog(Severity::Info, L"Агент готов. Рекомендуется запуск от имени администратора.");
        if (!util::IsElevated())
            AppendLog(Severity::Medium, L"Внимание: нет прав администратора — Prefetch/ShimCache/драйверы будут недоступны.");
        return 0;
    }

    case WM_SIZE:
        LayoutControls(hwnd);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;

    case WM_DPICHANGED: {
        g.dpi = HIWORD(wp);
        CreateFonts();
        ApplyLogFont();
        RebuildLog();   // WM_SETFONT в ApplyLogFont сбрасывает цвета — восстановим из g.entries
        const RECT* r = (const RECT*)lp;
        SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        LayoutControls(hwnd);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_GETMINMAXINFO: {
        auto* mmi = (MINMAXINFO*)lp;
        mmi->ptMinTrackSize.x = S(960);
        mmi->ptMinTrackSize.y = S(760);
        return 0;
    }

    case WM_ERASEBKGND:
        return 1; // фон рисуем в WM_PAINT

    case WM_PAINT:
        PaintWindow(hwnd);
        return 0;

    case WM_DRAWITEM:
        DrawButton((LPDRAWITEMSTRUCT)lp);
        return TRUE;

    case WM_MOUSEWHEEL: {
        // Колесо мыши должно прокручивать журнал (и вьюер отчёта), даже когда
        // фокус на кнопке. По умолчанию WM_MOUSEWHEEL уходит окну с фокусом;
        // DefWindowProc кнопки пробрасывает его сюда, в родителя, а мы — в
        // видимый прокручиваемый контрол. Без этого прокрутка «не работала».
        HWND target = g.inReport ? g.viewer : g.log;
        if (target && IsWindowVisible(target))
            return SendMessageW(target, WM_MOUSEWHEEL, wp, lp);
        break;
    }

    case WM_LBUTTONDOWN: {
        // Клик по метке важности или строке модуля — переключить фильтр журнала.
        // В режиме вьюера отчёта журнал скрыт — фильтры не трогаем.
        if (!g.inReport) {
            POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            // Кнопки «Сбросить фильтр» (в шапке журнала и под модулями) — вернуть
            // исходный журнал (сбрасывают оба фильтра сразу).
            if (PtInRect(&g.rcSevReset, pt) || PtInRect(&g.rcModReset, pt)) {
                ResetFilters();
                RebuildLog();
                Invalidate(g.rcLogCard);
                Invalidate(g.rcSidebar);
                return 0;
            }
            for (int i = 0; i < 3; i++)
                if (PtInRect(&g.rcSevChip[i], pt)) {
                    ToggleSevFilter(i == 0 ? SevFilter::High : i == 1 ? SevFilter::Medium : SevFilter::Low);
                    return 0;
                }
            for (auto& r : g.rows)
                if (PtInRect(&r.rc, pt)) { ToggleModFilter(r.id); return 0; }
        }
        break;
    }

    case WM_SETCURSOR:
        // Рука над кликабельными метками важности и строками модулей.
        if ((HWND)wp == hwnd && !g.inReport) {
            POINT pt; GetCursorPos(&pt); ScreenToClient(hwnd, &pt);
            if (PtInRect(&g.rcSevReset, pt) || PtInRect(&g.rcModReset, pt)) {
                SetCursor(LoadCursor(nullptr, IDC_HAND)); return TRUE;
            }
            for (auto& rc : g.rcSevChip)
                if (PtInRect(&rc, pt)) { SetCursor(LoadCursor(nullptr, IDC_HAND)); return TRUE; }
            for (auto& r : g.rows)
                if (PtInRect(&r.rc, pt)) { SetCursor(LoadCursor(nullptr, IDC_HAND)); return TRUE; }
        }
        break;

    case WM_TIMER:
        if (wp == kAnimTimer) {
            g.anim++;
            Invalidate(g.rcProgress);
            Invalidate(g.rcModules);
        }
        return 0;

    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDC_BTN_FULL)   StartScan(ScanProfile::Full,      L"полный аудит системы");
        if (id == IDC_BTN_PROC)   StartScan(ScanProfile::Processes, L"проверка процессов");
        if (id == IDC_BTN_QUICK)  StartScan(ScanProfile::Quick,     L"быстрый скан");
        if (id == IDC_BTN_EXPORT) ExportReport();
        if (id == IDC_BTN_OPEN)   { if (g.inReport) ShowReportView(false); else OpenDeletedFiles(); }
        if (id == IDC_BTN_STOP)   StopScan();
        return 0;
    }

    case WM_APP_LOG: {
        std::unique_ptr<std::wstring> m((std::wstring*)lp);
        AppendLog((Severity)wp, *m);
        return 0;
    }

    case WM_APP_STEP: {
        std::unique_ptr<StepEvent> ev((StepEvent*)lp);
        ModRow* row = FindRow(ev->module);
        if (row) {
            if (!ev->finished) {
                row->st = ModState::Running;
                g.stepLabel = L"Модуль " + std::to_wstring(ev->index + 1) + L" из " +
                              std::to_wstring(ev->total) + L" · " + row->label;
            } else {
                row->st = ev->status == L"ok" ? ModState::Ok
                        : ev->status == L"skipped" ? ModState::Skipped : ModState::Error;
                row->findings = ev->findings; row->high = ev->high;
                row->medium = ev->medium; row->low = ev->low;
                g.stepDone = ev->index + 1;
            }
        }
        Invalidate(g.rcModules);
        Invalidate(g.rcProgress);
        for (auto& c : g.rcCards) Invalidate(c);
        return 0;
    }

    case WM_APP_DONE: {
        std::unique_ptr<std::vector<ModuleResult>> res((std::vector<ModuleResult>*)lp);
        g.lastResults = std::move(*res);
        KillTimer(hwnd, kAnimTimer);
        g.scanElapsed = GetTickCount64() - g.scanStart;
        for (auto& r : g.rows)
            if (r.st == ModState::Pending || r.st == ModState::Running) r.st = ModState::Cancelled;
        Totals t = ComputeTotals();

        // Авто-сохранение отчёта рядом с агентом — лаунчер откроет его сам.
        std::string json = report::BuildJson(g.lastResults);
        std::wstring autoPath = AgentDir() + L"\\report_latest.json";
        if (report::WriteToFile(autoPath, json))
            AppendLog(Severity::Info, L"Отчёт автоматически сохранён: " + autoPath);

        SetStatus((g.stopping ? L"Остановлено. " : L"Готово. ") + std::wstring(L"Собрано фактов: ") +
                  std::to_wstring(t.findings) + L", HIGH: " + std::to_wstring(t.high) +
                  L", MEDIUM: " + std::to_wstring(t.medium) + L". Можно экспортировать отчёт.");
        UpdateButtons();
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_DESTROY:
        KillTimer(hwnd, kAnimTimer);
        g.scanner.RequestStop();
        Logger::Instance().SetSink(nullptr);
        DestroyFonts();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    InstallLogSink();

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"FusionForensicsWnd";
    // Иконка из ресурсов (ID 1): заголовок окна, панель задач, Alt-Tab.
    wc.hIcon   = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED);
    wc.hIconSm = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(1), IMAGE_ICON,
                                   GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED);
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName,
        L"Fusion Forensics — Endpoint Telemetry Agent",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 1480, 960,
        nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    // Размер под DPI монитора и центрирование в рабочей области.
    MONITORINFO mi{};
    mi.cbSize = sizeof(mi);
    GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mi);
    const RECT& wa = mi.rcWork;
    int w = std::min<int>(S(1120), wa.right - wa.left);
    int h = std::min<int>(S(820),  wa.bottom - wa.top);
    SetWindowPos(hwnd, nullptr, wa.left + (wa.right - wa.left - w) / 2,
                 wa.top + (wa.bottom - wa.top - h) / 2, w, h, SWP_NOZORDER);

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
