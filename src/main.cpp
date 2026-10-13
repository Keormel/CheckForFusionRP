// main.cpp — лаунчер агента телеметрии: Win32 GUI в тёмно-фиолетовой теме.
//
// Чистый Win32 + GDI, без внешних зависимостей. Owner-draw кнопки, лог-консоль
// реального времени (read-only EDIT), статус-бар. Сканирование идёт в фоновом
// потоке; строки лога и результат приходят в GUI-поток через PostMessage.

#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
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
    const COLORREF kBg       = RGB(18, 14, 30);   // фон окна
    const COLORREF kPanel    = RGB(28, 22, 46);   // левая панель
    const COLORREF kLogBg    = RGB(14, 10, 24);   // фон лога
    const COLORREF kAccent   = RGB(124, 92, 196); // фиолетовый акцент
    const COLORREF kAccentHi = RGB(158, 124, 232);// акцент при наведении
    const COLORREF kAccentDn = RGB(96, 68, 158);  // акцент при нажатии
    const COLORREF kText     = RGB(224, 219, 240);
    const COLORREF kTextDim  = RGB(150, 140, 180);
    const COLORREF kHigh     = RGB(236, 120, 150); // HIGH в логе
    const COLORREF kMed      = RGB(230, 190, 120); // MEDIUM
    const COLORREF kBorder   = RGB(72, 56, 120);
}

enum {
    IDC_BTN_FULL = 1001, IDC_BTN_PROC, IDC_BTN_QUICK, IDC_BTN_EXPORT,
    IDC_LOG = 1010
};
#define WM_APP_LOG  (WM_APP + 1)
#define WM_APP_DONE (WM_APP + 2)

// ---- глобальное состояние GUI ---------------------------------------------
struct AppState {
    HWND hwnd = nullptr, log = nullptr;
    HWND btnFull = nullptr, btnProc = nullptr, btnQuick = nullptr, btnExport = nullptr;
    HFONT fontUi = nullptr, fontMono = nullptr, fontTitle = nullptr;
    HBRUSH brLogBg = nullptr, brPanel = nullptr;
    Scanner scanner;
    std::vector<ModuleResult> lastResults;
    std::wstring status = L"Готов. Запустите аудит.";
    HWND hoverBtn = nullptr;
};
static AppState g;

// ---- helpers ---------------------------------------------------------------
static void AppendLog(Severity sev, const std::wstring& line) {
    const wchar_t* tag = SeverityName(sev);
    std::wstring ts = util::NowIso();
    std::wstring full = L"[" + ts.substr(11, 8) + L"] " + tag + L"  " + line + L"\r\n";
    int len = GetWindowTextLengthW(g.log);
    SendMessageW(g.log, EM_SETSEL, len, len);
    SendMessageW(g.log, EM_REPLACESEL, FALSE, (LPARAM)full.c_str());
    SendMessageW(g.log, EM_SCROLLCARET, 0, 0);
}

static void SetStatus(const std::wstring& s) {
    g.status = s;
    RECT rc; GetClientRect(g.hwnd, &rc);
    RECT bar{ 0, rc.bottom - 30, rc.right, rc.bottom };
    InvalidateRect(g.hwnd, &bar, FALSE);
}

// Каталог, где лежит сам агент (рядом лаунчер ищет report_latest.json).
static std::wstring AgentDir() {
    wchar_t buf[MAX_PATH]; GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring p = buf;
    size_t s = p.find_last_of(L"\\/");
    return (s == std::wstring::npos) ? L"." : p.substr(0, s);
}

static void EnableButtons(bool en) {
    EnableWindow(g.btnFull, en);
    EnableWindow(g.btnProc, en);
    EnableWindow(g.btnQuick, en);
    EnableWindow(g.btnExport, en && !g.lastResults.empty());
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
static void StartScan(ScanProfile profile, const wchar_t* label) {
    if (g.scanner.Running()) return;
    EnableButtons(false);
    SetStatus(std::wstring(L"Выполняется: ") + label + L"…");
    g.scanner.StartAsync(profile, [](std::vector<ModuleResult> res) {
        auto* heap = new std::vector<ModuleResult>(std::move(res));
        if (!PostMessageW(g.hwnd, WM_APP_DONE, 0, (LPARAM)heap))
            delete heap;
    });
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

// ---- отрисовка owner-draw кнопки -------------------------------------------
static void DrawButton(LPDRAWITEMSTRUCT di) {
    bool pressed = (di->itemState & ODS_SELECTED) != 0;
    bool disabled = (di->itemState & ODS_DISABLED) != 0;
    bool hover = (di->hwndItem == g.hoverBtn);

    COLORREF fill = clr::kAccent;
    if (disabled)      fill = RGB(54, 46, 78);
    else if (pressed)  fill = clr::kAccentDn;
    else if (hover)    fill = clr::kAccentHi;

    HDC dc = di->hDC;
    RECT rc = di->rcItem;

    HBRUSH bg = CreateSolidBrush(clr::kPanel);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);

    HBRUSH br = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, disabled ? clr::kBorder : clr::kAccentHi);
    HGDIOBJ ob = SelectObject(dc, br);
    HGDIOBJ op = SelectObject(dc, pen);
    RoundRect(dc, rc.left, rc.top, rc.right, rc.bottom, 14, 14);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(br); DeleteObject(pen);

    wchar_t txt[128]; GetWindowTextW(di->hwndItem, txt, 128);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, disabled ? clr::kTextDim : clr::kText);
    HGDIOBJ of = SelectObject(dc, g.fontUi);
    if (pressed) OffsetRect(&rc, 1, 1);
    DrawTextW(dc, txt, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, of);
}

// ---- отрисовка фона/заголовка/статус-бара ----------------------------------
static void PaintWindow(HWND hwnd) {
    PAINTSTRUCT ps; HDC dc = BeginPaint(hwnd, &ps);
    RECT rc; GetClientRect(hwnd, &rc);

    HBRUSH bg = CreateSolidBrush(clr::kBg);
    FillRect(dc, &rc, bg); DeleteObject(bg);

    // левая панель
    RECT panel{ 0, 0, 250, rc.bottom - 30 };
    FillRect(dc, &panel, g.brPanel);
    HPEN sep = CreatePen(PS_SOLID, 1, clr::kBorder);
    HGDIOBJ op = SelectObject(dc, sep);
    MoveToEx(dc, 250, 0, nullptr); LineTo(dc, 250, rc.bottom - 30);
    SelectObject(dc, op); DeleteObject(sep);

    // заголовок
    SetBkMode(dc, TRANSPARENT);
    HGDIOBJ of = SelectObject(dc, g.fontTitle);
    SetTextColor(dc, clr::kAccentHi);
    RECT t{ 20, 22, 250, 60 };
    DrawTextW(dc, L"FUSION · FORENSICS", -1, &t, DT_LEFT | DT_SINGLELINE);
    SelectObject(dc, g.fontUi);
    SetTextColor(dc, clr::kTextDim);
    RECT s{ 20, 58, 250, 82 };
    DrawTextW(dc, L"Endpoint Telemetry Agent", -1, &s, DT_LEFT | DT_SINGLELINE);

    RECT hint{ 20, rc.bottom - 100, 240, rc.bottom - 40 };
    DrawTextW(dc,
        L"Агент собирает факты и\r\nтелеметрию. Вердикт о\r\nнарушении выносит сервер.",
        -1, &hint, DT_LEFT | DT_WORDBREAK);
    SelectObject(dc, of);

    // статус-бар
    RECT bar{ 0, rc.bottom - 30, rc.right, rc.bottom };
    HBRUSH bb = CreateSolidBrush(clr::kPanel);
    FillRect(dc, &bar, bb); DeleteObject(bb);
    HPEN tp = CreatePen(PS_SOLID, 1, clr::kBorder);
    HGDIOBJ op2 = SelectObject(dc, tp);
    MoveToEx(dc, 0, rc.bottom - 30, nullptr); LineTo(dc, rc.right, rc.bottom - 30);
    SelectObject(dc, op2); DeleteObject(tp);

    of = SelectObject(dc, g.fontUi);
    SetTextColor(dc, g.scanner.Running() ? clr::kAccentHi : clr::kTextDim);
    RECT st{ 12, rc.bottom - 28, rc.right - 12, rc.bottom - 4 };
    DrawTextW(dc, g.status.c_str(), -1, &st, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, of);

    EndPaint(hwnd, &ps);
}

// ---- создание контролов ----------------------------------------------------
static HWND MakeButton(HWND parent, int id, const wchar_t* text, int y) {
    return CreateWindowExW(0, L"BUTTON", text,
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        20, y, 210, 46, parent, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
}

static void LayoutControls(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int logX = 262, logY = 20;
    MoveWindow(g.log, logX, logY, rc.right - logX - 14, rc.bottom - 30 - logY - 14, TRUE);
}

// ---- оконная процедура -----------------------------------------------------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g.hwnd = hwnd;
        g.fontUi    = CreateFontW(-16, 0,0,0, FW_SEMIBOLD, 0,0,0, DEFAULT_CHARSET,
                                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                  DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g.fontTitle = CreateFontW(-24, 0,0,0, FW_BOLD, 0,0,0, DEFAULT_CHARSET,
                                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                  DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI Semibold");
        g.fontMono  = CreateFontW(-14, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET,
                                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                  FIXED_PITCH | FF_MODERN, L"Cascadia Mono");
        g.brLogBg = CreateSolidBrush(clr::kLogBg);
        g.brPanel = CreateSolidBrush(clr::kPanel);

        g.btnFull   = MakeButton(hwnd, IDC_BTN_FULL,   L"Запуск аудита системы", 100);
        g.btnProc   = MakeButton(hwnd, IDC_BTN_PROC,   L"Проверка процессов",    156);
        g.btnQuick  = MakeButton(hwnd, IDC_BTN_QUICK,  L"Быстрый скан",          212);
        g.btnExport = MakeButton(hwnd, IDC_BTN_EXPORT, L"Экспорт отчёта",        268);

        g.log = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)IDC_LOG, GetModuleHandleW(nullptr), nullptr);
        SendMessageW(g.log, WM_SETFONT, (WPARAM)g.fontMono, TRUE);
        // снимаем стандартный лимит текста EDIT (~30 КБ), иначе лог перестаёт дополняться
        SendMessageW(g.log, EM_SETLIMITTEXT, (WPARAM)(8 * 1024 * 1024), 0);

        EnableButtons(true);
        LayoutControls(hwnd);
        AppendLog(Severity::Info, L"Агент готов. Рекомендуется запуск от имени администратора.");
        if (!util::IsElevated())
            AppendLog(Severity::Medium, L"Внимание: нет прав администратора — Prefetch/ShimCache/драйверы будут недоступны.");
        return 0;
    }

    case WM_SIZE:
        LayoutControls(hwnd);
        return 0;

    case WM_GETMINMAXINFO: {
        auto* mmi = (MINMAXINFO*)lp;
        mmi->ptMinTrackSize.x = 720;
        mmi->ptMinTrackSize.y = 480;
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

    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetBkColor(dc, clr::kLogBg);
        SetTextColor(dc, clr::kText);
        return (LRESULT)g.brLogBg;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDC_BTN_FULL)   StartScan(ScanProfile::Full,      L"полный аудит системы");
        if (id == IDC_BTN_PROC)   StartScan(ScanProfile::Processes, L"проверка процессов");
        if (id == IDC_BTN_QUICK)  StartScan(ScanProfile::Quick,     L"быстрый скан");
        if (id == IDC_BTN_EXPORT) ExportReport();
        return 0;
    }

    // наведение мыши на кнопки -> подсветка
    case WM_MOUSEMOVE: {
        POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        HWND over = ChildWindowFromPoint(hwnd, pt);
        HWND newHover = nullptr;
        if (over == g.btnFull || over == g.btnProc || over == g.btnQuick || over == g.btnExport)
            newHover = over;
        if (newHover != g.hoverBtn) {
            HWND old = g.hoverBtn; g.hoverBtn = newHover;
            if (old) InvalidateRect(old, nullptr, TRUE);
            if (newHover) InvalidateRect(newHover, nullptr, TRUE);
            TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        if (g.hoverBtn) { HWND old = g.hoverBtn; g.hoverBtn = nullptr; InvalidateRect(old, nullptr, TRUE); }
        return 0;

    case WM_APP_LOG: {
        std::unique_ptr<std::wstring> msg((std::wstring*)lp);
        AppendLog((Severity)wp, *msg);
        return 0;
    }

    case WM_APP_DONE: {
        std::unique_ptr<std::vector<ModuleResult>> res((std::vector<ModuleResult>*)lp);
        g.lastResults = std::move(*res);
        EnableButtons(true);
        int findings = 0;
        for (auto& m : g.lastResults) findings += (int)m.findings.size();

        // Авто-сохранение отчёта рядом с агентом — лаунчер откроет его сам.
        std::string json = report::BuildJson(g.lastResults);
        std::wstring autoPath = AgentDir() + L"\\report_latest.json";
        if (report::WriteToFile(autoPath, json))
            AppendLog(Severity::Info, L"Отчёт автоматически сохранён: " + autoPath);

        SetStatus(L"Готово. Собрано фактов: " + std::to_wstring(findings) + L". Можно экспортировать отчёт.");
        return 0;
    }

    case WM_DESTROY:
        g.scanner.RequestStop();
        Logger::Instance().SetSink(nullptr);
        if (g.fontUi) DeleteObject(g.fontUi);
        if (g.fontMono) DeleteObject(g.fontMono);
        if (g.fontTitle) DeleteObject(g.fontTitle);
        if (g.brLogBg) DeleteObject(g.brLogBg);
        if (g.brPanel) DeleteObject(g.brPanel);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    SetProcessDPIAware();
    InstallLogSink();

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"FusionForensicsWnd";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName,
        L"Fusion Forensics — Endpoint Telemetry Agent",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 940, 640,
        nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
