#include "stdafx.h"

#include "StringsSearchHistory.h"
#include "ReportUtil.h"

#include <shlobj.h>

#include <algorithm>
#include <cwctype>
#include <string_view>

static uint64_t NowUnixMs() {
    FILETIME ft = {};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ui = {};
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    uint64_t t100ns = ui.QuadPart;
    static const uint64_t kUnixEpoch100ns = 116444736000000000ULL;
    if (t100ns <= kUnixEpoch100ns) {
        return 0;
    }
    return (t100ns - kUnixEpoch100ns) / 10000ULL;
}

static std::wstring EscapeIniField(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t ch : s) {
        switch (ch) {
            case L'\\': out += L"\\\\"; break;
            case L'\t': out += L"\\t"; break;
            case L'\r': out += L"\\r"; break;
            case L'\n': out += L"\\n"; break;
            default: out.push_back(ch); break;
        }
    }
    return out;
}

static std::wstring UnescapeIniField(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        wchar_t ch = s[i];
        if (ch != L'\\' || (i + 1) >= s.size()) {
            out.push_back(ch);
            continue;
        }
        wchar_t n = s[i + 1];
        switch (n) {
            case L'\\': out.push_back(L'\\'); ++i; break;
            case L't': out.push_back(L'\t'); ++i; break;
            case L'r': out.push_back(L'\r'); ++i; break;
            case L'n': out.push_back(L'\n'); ++i; break;
            default: out.push_back(ch); break;
        }
    }
    return out;
}

static std::vector<std::wstring> SplitTabs(const std::wstring& s) {
    std::vector<std::wstring> parts;
    size_t start = 0;
    while (start <= s.size()) {
        size_t pos = s.find(L'\t', start);
        if (pos == std::wstring::npos) {
            parts.push_back(s.substr(start));
            break;
        }
        parts.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return parts;
}

std::wstring StringsSearchHistory::NormalizeQuery(const std::wstring& q) {
    std::wstring out;
    out.reserve(q.size());
    bool inSpace = true;
    for (wchar_t ch : q) {
        if (iswspace(ch)) {
            inSpace = true;
            continue;
        }
        if (inSpace && !out.empty()) {
            out.push_back(L' ');
        }
        inSpace = false;
        out.push_back(static_cast<wchar_t>(towlower(ch)));
    }
    return out;
}

std::wstring StringsSearchHistory::MakeKey(const StringsSearchHistoryEntry& e) {
    std::wstring qn = NormalizeQuery(e.query);
    std::wstring k;
    k.reserve(qn.size() + 32);
    k += std::to_wstring(static_cast<int>(e.mode));
    k += L'|';
    k += qn;
    k += L'|';
    k += std::to_wstring(e.typeFilter);
    k += L'|';
    k += std::to_wstring(e.minLen);
    k += L'|';
    k += (e.unique ? L"1" : L"0");
    return k;
}

void StringsSearchHistory::TrimToLimit() {
    const size_t kMax = 200;
    if (entries_.size() <= kMax) {
        return;
    }
    std::stable_sort(entries_.begin(), entries_.end(), [](const auto& a, const auto& b) {
        if (a.pinned != b.pinned) return a.pinned > b.pinned;
        return a.lastUsedMs > b.lastUsedMs;
    });
    size_t keepPinned = 0;
    while (keepPinned < entries_.size() && entries_[keepPinned].pinned) {
        ++keepPinned;
    }
    if (keepPinned >= kMax) {
        entries_.resize(keepPinned);
        return;
    }
    entries_.resize(kMax);
}

bool StringsSearchHistory::Load() {
    iniPath_ = GetPeInfoSettingsIniPath();
    entries_.clear();
    if (iniPath_.empty()) {
        return false;
    }

    const wchar_t* sec = L"StringsHistory";
    int count = GetPrivateProfileIntW(sec, L"Count", 0, iniPath_.c_str());
    if (count <= 0) {
        return true;
    }

    wchar_t buf[8192] = {};
    for (int i = 0; i < count; ++i) {
        std::wstring key = L"E" + std::to_wstring(i);
        DWORD n = GetPrivateProfileStringW(sec, key.c_str(), L"", buf, static_cast<DWORD>(std::size(buf)), iniPath_.c_str());
        if (n == 0) {
            continue;
        }
        std::wstring line(buf, buf + n);
        auto parts = SplitTabs(line);
        if (parts.size() < 8) {
            continue;
        }
        StringsSearchHistoryEntry e;
        e.mode = (parts[0] == L"1") ? StringsSearchMode::Regex : StringsSearchMode::Plain;
        try {
            e.typeFilter = std::stoi(parts[1]);
            e.minLen = std::stoi(parts[2]);
            e.unique = (parts[3] == L"1");
            e.pinned = (parts[4] == L"1");
            e.useCount = static_cast<uint32_t>(std::stoul(parts[5]));
            e.lastUsedMs = std::stoull(parts[6]);
        } catch (...) {
            continue;
        }
        e.query = UnescapeIniField(parts[7]);
        if (e.query.size() > 256) {
            e.query.resize(256);
        }
        entries_.push_back(std::move(e));
    }
    TrimToLimit();
    return true;
}

bool StringsSearchHistory::Save() const {
    if (iniPath_.empty()) {
        return false;
    }
    const wchar_t* sec = L"StringsHistory";
    WritePrivateProfileStringW(sec, nullptr, nullptr, iniPath_.c_str());
    WritePrivateProfileStringW(sec, L"Count", std::to_wstring(entries_.size()).c_str(), iniPath_.c_str());

    for (size_t i = 0; i < entries_.size(); ++i) {
        const auto& e = entries_[i];
        std::wstring line;
        line.reserve(512);
        line += std::to_wstring(static_cast<int>(e.mode));
        line.push_back(L'\t');
        line += std::to_wstring(e.typeFilter);
        line.push_back(L'\t');
        line += std::to_wstring(e.minLen);
        line.push_back(L'\t');
        line += (e.unique ? L"1" : L"0");
        line.push_back(L'\t');
        line += (e.pinned ? L"1" : L"0");
        line.push_back(L'\t');
        line += std::to_wstring(e.useCount);
        line.push_back(L'\t');
        line += std::to_wstring(e.lastUsedMs);
        line.push_back(L'\t');
        line += EscapeIniField(e.query);

        std::wstring key = L"E" + std::to_wstring(i);
        WritePrivateProfileStringW(sec, key.c_str(), line.c_str(), iniPath_.c_str());
    }
    return true;
}

void StringsSearchHistory::Record(const StringsSearchHistoryEntry& e) {
    if (iniPath_.empty()) {
        iniPath_ = GetPeInfoSettingsIniPath();
    }
    if (e.query.size() < 2) {
        return;
    }
    StringsSearchHistoryEntry ne = e;
    if (ne.query.size() > 256) {
        ne.query.resize(256);
    }
    ne.lastUsedMs = NowUnixMs();

    std::wstring key = MakeKey(ne);
    for (auto& it : entries_) {
        if (MakeKey(it) == key) {
            it.query = ne.query;
            it.useCount = it.useCount + 1;
            it.lastUsedMs = ne.lastUsedMs;
            it.typeFilter = ne.typeFilter;
            it.minLen = ne.minLen;
            it.unique = ne.unique;
            it.mode = ne.mode;
            TrimToLimit();
            return;
        }
    }
    ne.useCount = 1;
    entries_.push_back(std::move(ne));
    TrimToLimit();
}

bool StringsSearchHistory::SetPinned(const StringsSearchHistoryEntry& e, bool pinned) {
    std::wstring key = MakeKey(e);
    for (auto& it : entries_) {
        if (MakeKey(it) == key) {
            it.pinned = pinned;
            it.lastUsedMs = NowUnixMs();
            return true;
        }
    }
    return false;
}

bool StringsSearchHistory::Delete(const StringsSearchHistoryEntry& e) {
    std::wstring key = MakeKey(e);
    auto it = std::remove_if(entries_.begin(), entries_.end(), [&](const auto& v) { return MakeKey(v) == key; });
    if (it == entries_.end()) {
        return false;
    }
    entries_.erase(it, entries_.end());
    return true;
}

void StringsSearchHistory::Clear(bool includePinned) {
    if (includePinned) {
        entries_.clear();
        return;
    }
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(), [](const auto& e) { return !e.pinned; }), entries_.end());
}

std::vector<StringsSearchHistoryEntry> StringsSearchHistory::ListForDisplay() const {
    std::vector<StringsSearchHistoryEntry> out = entries_;
    std::stable_sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a.pinned != b.pinned) return a.pinned > b.pinned;
        return a.lastUsedMs > b.lastUsedMs;
    });
    return out;
}
