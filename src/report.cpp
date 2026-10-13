// report.cpp
#include "report.h"
#include "util.h"
#include <windows.h>
#include <sstream>

namespace report {

static std::string Q(const std::wstring& s) { return "\"" + util::JsonEscape(s) + "\""; }

static std::wstring HostName() {
    wchar_t buf[256]; DWORD n = 256;
    if (GetComputerNameW(buf, &n)) return buf;
    return L"";
}
static std::wstring UserName_() {
    wchar_t buf[256]; DWORD n = 256;
    if (GetUserNameW(buf, &n)) return buf;
    return L"";
}

std::string BuildJson(const std::vector<ModuleResult>& results) {
    std::ostringstream o;
    o << "{\n";
    o << "  \"schema\": \"forensics-agent/1\",\n";
    o << "  \"host\": " << Q(HostName()) << ",\n";
    o << "  \"user\": " << Q(UserName_()) << ",\n";
    o << "  \"collected_at\": " << Q(util::NowIso()) << ",\n";
    o << "  \"elevated\": " << (util::IsElevated() ? "true" : "false") << ",\n";
    o << "  \"modules\": [\n";

    for (size_t mi = 0; mi < results.size(); mi++) {
        const auto& m = results[mi];
        o << "    {\n";
        o << "      \"module\": " << Q(m.module) << ",\n";
        o << "      \"status\": " << Q(m.status) << ",\n";
        o << "      \"note\": " << Q(m.note) << ",\n";
        o << "      \"findings\": [\n";
        for (size_t fi = 0; fi < m.findings.size(); fi++) {
            const auto& f = m.findings[fi];
            o << "        {\n";
            o << "          \"title\": " << Q(f.title) << ",\n";
            o << "          \"severity\": " << Q(SeverityName(f.severity)) << ",\n";
            o << "          \"fields\": {";
            size_t k = 0;
            for (const auto& [key, val] : f.fields) {
                o << (k ? ", " : " ") << Q(key) << ": " << Q(val);
                k++;
            }
            o << " }\n";
            o << "        }" << (fi + 1 < m.findings.size() ? "," : "") << "\n";
        }
        o << "      ]\n";
        o << "    }" << (mi + 1 < results.size() ? "," : "") << "\n";
    }
    o << "  ]\n";
    o << "}\n";
    return o.str();
}

bool WriteToFile(const std::wstring& path, const std::string& json) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    // UTF-8 BOM для корректного открытия в редакторах
    const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
    DWORD w = 0;
    WriteFile(h, bom, 3, &w, nullptr);
    bool ok = WriteFile(h, json.data(), (DWORD)json.size(), &w, nullptr) && w == json.size();
    CloseHandle(h);
    return ok;
}

std::wstring Digest(const std::string& json) {
    return util::Sha256Bytes((const uint8_t*)json.data(), json.size()).value_or(L"");
}

} // namespace report
