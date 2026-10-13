// util.cpp
#include "util.h"
#include <bcrypt.h>
#include <shlobj.h>
#include <algorithm>
#include <cstdio>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace util {

std::wstring Widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

std::string Narrow(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string a(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), a.data(), n, nullptr, nullptr);
    return a;
}

std::wstring ToUpper(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towupper(c);
    return s;
}

std::wstring Trim(const std::wstring& s) {
    size_t b = s.find_first_not_of(L" \t\r\n");
    if (b == std::wstring::npos) return {};
    size_t e = s.find_last_not_of(L" \t\r\n");
    return s.substr(b, e - b + 1);
}

uint64_t FileTimeToU64(const FILETIME& ft) {
    return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

std::wstring FileTimeToIso(uint64_t v) {
    if (v == 0) return L"";
    FILETIME ft; ft.dwLowDateTime = (DWORD)(v & 0xFFFFFFFF); ft.dwHighDateTime = (DWORD)(v >> 32);
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) return L"";
    wchar_t buf[32];
    swprintf(buf, 32, L"%04u-%02u-%02uT%02u:%02u:%02uZ",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::wstring FileTimeToIso(const FILETIME& ft) { return FileTimeToIso(FileTimeToU64(ft)); }

uint64_t NowFileTime() {
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    return FileTimeToU64(ft);
}

std::wstring NowIso() { return FileTimeToIso(NowFileTime()); }

std::optional<std::vector<uint8_t>> ReadFileBytes(const std::wstring& path, size_t maxBytes) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::nullopt;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return std::nullopt; }
    size_t total = (size_t)sz.QuadPart;
    if (maxBytes && total > maxBytes) total = maxBytes;
    std::vector<uint8_t> buf(total);
    size_t done = 0;
    while (done < total) {
        DWORD toRead = (DWORD)std::min<size_t>(1u << 20, total - done);
        DWORD got = 0;
        if (!ReadFile(h, buf.data() + done, toRead, &got, nullptr) || got == 0) break;
        done += got;
    }
    CloseHandle(h);
    buf.resize(done);
    return buf;
}

static std::wstring HexLower(const uint8_t* d, size_t n) {
    static const wchar_t* k = L"0123456789abcdef";
    std::wstring s; s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s.push_back(k[d[i] >> 4]); s.push_back(k[d[i] & 0xF]); }
    return s;
}

std::optional<std::wstring> Sha256Bytes(const uint8_t* data, size_t len) {
    BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return std::nullopt;
    std::optional<std::wstring> result;
    DWORD hashLen = 0, cb = 0;
    uint8_t digest[32];
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cb, 0) == 0 &&
        hashLen == sizeof(digest) &&
        BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0) == 0 &&
            BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
            result = HexLower(digest, sizeof(digest));
        }
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return result;
}

std::optional<std::wstring> Sha256File(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::nullopt;

    BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) { CloseHandle(h); return std::nullopt; }
    std::optional<std::wstring> result;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        std::vector<uint8_t> buf(1u << 20);
        DWORD got = 0; bool ok = true;
        while (ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr) && got > 0) {
            if (BCryptHashData(hash, buf.data(), got, 0) != 0) { ok = false; break; }
        }
        if (ok) {
            uint8_t digest[32];
            if (BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0)
                result = HexLower(digest, sizeof(digest));
        }
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(h);
    return result;
}

std::wstring ExpandEnv(const std::wstring& s) {
    DWORD n = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
    if (!n) return s;
    std::wstring out(n, L'\0');
    ExpandEnvironmentStringsW(s.c_str(), out.data(), n);
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

std::wstring KnownFolder(REFKNOWNFOLDERID id) {
    PWSTR p = nullptr;
    std::wstring r;
    if (SHGetKnownFolderPath(id, 0, nullptr, &p) == S_OK && p) r = p;
    if (p) CoTaskMemFree(p);
    return r;
}

bool IsElevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el{}; DWORD cb = 0;
    bool ok = GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &cb) && el.TokenIsElevated;
    CloseHandle(tok);
    return ok;
}

bool EnablePrivilege(const wchar_t* name) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    LUID luid{};
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, name, &luid)) {
        TOKEN_PRIVILEGES tp{}; tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
             GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(tok);
    return ok;
}

std::string JsonEscape(const std::wstring& ws) {
    std::string s = Narrow(ws);
    std::string o; o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b";  break;
            case '\f': o += "\\f";  break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) { char b[8]; snprintf(b, 8, "\\u%04x", c); o += b; }
                else o += (char)c;
        }
    }
    return o;
}

} // namespace util
