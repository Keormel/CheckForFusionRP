// mod_environment.cpp - самодиагностика окружения агента (телеметрия).
//
// Это НЕ "защита от аналитика", а факты о среде, в которой агент работал:
//   - запущен ли под отладчиком (IsDebuggerPresent / PEB.BeingDebugged);
//   - есть ли права администратора (полнота сбора зависит от этого);
//   - USB-носители, подключавшиеся к системе (USBSTOR) - артефакт HID-макросов.
// Сервер учитывает это при оценке полноты и достоверности отчёта.

#include "modules.h"
#include "util.h"
#include "logger.h"
#include <windows.h>
#include <winternl.h>
#include <string>

namespace {

void ReadUsbStor(ModuleResult& r) {
    HKEY k;
    const wchar_t* path = L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &k) != ERROR_SUCCESS) return;
    DWORD i = 0; wchar_t dev[512];
    for (;;) {
        DWORD len = 512;
        if (RegEnumKeyExW(k, i++, dev, &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        Finding f; f.category = L"usb"; f.title = dev; f.severity = Severity::Info;
        f.set(L"device", dev).set(L"source", L"USBSTOR");
        r.findings.push_back(std::move(f));
    }
    RegCloseKey(k);
}

} // namespace

namespace modules {

ModuleResult ScanEnvironment() {
    ModuleResult r; r.module = L"environment"; r.status = L"ok";
    auto& log = Logger::Instance();

    bool dbg = IsDebuggerPresent();
    BOOL remoteDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDbg);
    bool peb = NtCurrentTeb()->ProcessEnvironmentBlock->BeingDebugged;
    bool elevated = util::IsElevated();

    Finding f; f.category = L"environment"; f.title = L"agent runtime";
    f.severity = (dbg || remoteDbg || peb) ? Severity::Medium : Severity::Info;
    f.set(L"debugger_present", dbg ? L"true" : L"false")
     .set(L"remote_debugger", remoteDbg ? L"true" : L"false")
     .set(L"peb_being_debugged", peb ? L"true" : L"false")
     .set(L"elevated", elevated ? L"true" : L"false")
     .set(L"collected_at", util::NowIso());
    r.findings.push_back(std::move(f));

    ReadUsbStor(r);

    if (!elevated) r.note = L"агент без прав администратора — часть артефактов недоступна";
    log.Info(std::wstring(L"[environment] debugger=") + (dbg ? L"yes" : L"no") +
             L" elevated=" + (elevated ? L"yes" : L"no") +
             L" usb_devices=" + std::to_wstring((int)r.findings.size() - 1));
    return r;
}

} // namespace modules
