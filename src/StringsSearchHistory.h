#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class StringsSearchMode {
    Plain = 0,
    Regex = 1
};

struct StringsSearchHistoryEntry {
    StringsSearchMode mode = StringsSearchMode::Plain;
    std::wstring query;
    int typeFilter = 0;
    int minLen = 5;
    bool unique = true;
    bool pinned = false;
    uint32_t useCount = 0;
    uint64_t lastUsedMs = 0;
};

class StringsSearchHistory {
public:
    bool Load();
    bool Save() const;

    void Record(const StringsSearchHistoryEntry& e);
    bool SetPinned(const StringsSearchHistoryEntry& e, bool pinned);
    bool Delete(const StringsSearchHistoryEntry& e);
    void Clear(bool includePinned);

    std::vector<StringsSearchHistoryEntry> ListForDisplay() const;

private:
    static std::wstring NormalizeQuery(const std::wstring& q);
    static std::wstring MakeKey(const StringsSearchHistoryEntry& e);

    void TrimToLimit();

    std::wstring iniPath_;
    std::vector<StringsSearchHistoryEntry> entries_;
};
