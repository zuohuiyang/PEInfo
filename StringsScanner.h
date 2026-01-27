#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

enum class StringsHitType {
    Ascii,
    Utf16Le
};

struct StringsHit {
    StringsHitType type = StringsHitType::Ascii;
    uint64_t fileOffset = 0;
    std::wstring text;
};

struct StringsScanOptions {
    int minLen = 4;
    int maxLen = 4096;
    bool scanAscii = true;
    bool scanUtf16Le = true;
};

bool ScanStringsFromFile(const std::wstring& filePath,
                         const StringsScanOptions& opt,
                         std::vector<StringsHit>& outHits,
                         std::wstring& error,
                         std::atomic<bool>* cancel = nullptr,
                         const std::function<void(uint64_t processed, uint64_t total)>& progress = {});

