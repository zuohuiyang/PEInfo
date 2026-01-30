#include "stdafx.h"

#include "StringsScanner.h"

#include <algorithm>

static bool IsAsciiPrintable(uint8_t b) {
    return (b >= 0x20 && b <= 0x7E);
}

static void AppendAsciiHitIfNeeded(const StringsScanOptions& opt,
                                   std::vector<StringsHit>& outHits,
                                   uint64_t startOffset,
                                   const std::string& bytes) {
    if (bytes.size() < static_cast<size_t>(opt.minLen)) {
        return;
    }
    StringsHit hit;
    hit.type = StringsHitType::Ascii;
    hit.fileOffset = startOffset;
    hit.text.assign(bytes.begin(), bytes.end());
    if (hit.text.size() > static_cast<size_t>(opt.maxLen)) {
        hit.text.resize(static_cast<size_t>(opt.maxLen));
    }
    outHits.push_back(std::move(hit));
}

static void AppendUtf16HitIfNeeded(const StringsScanOptions& opt,
                                   std::vector<StringsHit>& outHits,
                                   uint64_t startOffset,
                                   const std::wstring& w) {
    if (w.size() < static_cast<size_t>(opt.minLen)) {
        return;
    }
    StringsHit hit;
    hit.type = StringsHitType::Utf16Le;
    hit.fileOffset = startOffset;
    hit.text = w;
    if (hit.text.size() > static_cast<size_t>(opt.maxLen)) {
        hit.text.resize(static_cast<size_t>(opt.maxLen));
    }
    outHits.push_back(std::move(hit));
}

static bool GetFileSize64(HANDLE h, uint64_t& outSize) {
    LARGE_INTEGER li = {};
    if (!GetFileSizeEx(h, &li)) {
        return false;
    }
    if (li.QuadPart < 0) {
        return false;
    }
    outSize = static_cast<uint64_t>(li.QuadPart);
    return true;
}

static bool SeekFile64(HANDLE h, uint64_t offset) {
    LARGE_INTEGER li = {};
    li.QuadPart = static_cast<LONGLONG>(offset);
    return SetFilePointerEx(h, li, nullptr, FILE_BEGIN) != 0;
}

static bool ScanAsciiStream(HANDLE h,
                            uint64_t total,
                            const StringsScanOptions& opt,
                            std::vector<StringsHit>& outHits,
                            std::wstring& error,
                            std::atomic<bool>* cancel,
                            const std::function<void(uint64_t processed, uint64_t total)>& progress,
                            bool* truncated) {
    const DWORD kBlock = 1u << 20;
    std::vector<uint8_t> buf(kBlock);
    uint64_t fileOffset = 0;
    uint64_t lastProgressReport = 0;

    std::string cur;
    cur.reserve(static_cast<size_t>(std::min<uint64_t>(total, 256)));
    uint64_t curStart = 0;
    bool inRun = false;

    while (fileOffset < total) {
        if (cancel && cancel->load()) {
            error = L"\u5df2\u53d6\u6d88";
            return false;
        }
        if (opt.maxHits > 0 && outHits.size() >= opt.maxHits) {
            if (truncated) {
                *truncated = true;
            }
            return true;
        }
        DWORD toRead = static_cast<DWORD>(std::min<uint64_t>(kBlock, total - fileOffset));
        DWORD read = 0;
        if (!ReadFile(h, buf.data(), toRead, &read, nullptr)) {
            error = L"\u8bfb\u53d6\u5931\u8d25";
            return false;
        }
        if (read == 0) {
            break;
        }

        for (DWORD i = 0; i < read; ++i) {
            uint8_t b = buf[i];
            if (IsAsciiPrintable(b)) {
                if (!inRun) {
                    inRun = true;
                    curStart = fileOffset + i;
                    cur.clear();
                }
                cur.push_back(static_cast<char>(b));
                if (cur.size() >= static_cast<size_t>(opt.maxLen)) {
                    AppendAsciiHitIfNeeded(opt, outHits, curStart, cur);
                    inRun = false;
                    cur.clear();
                }
            } else {
                if (inRun) {
                    AppendAsciiHitIfNeeded(opt, outHits, curStart, cur);
                    inRun = false;
                    cur.clear();
                }
            }
            if (opt.maxHits > 0 && outHits.size() >= opt.maxHits) {
                if (truncated) {
                    *truncated = true;
                }
                return true;
            }
        }

        fileOffset += read;
        if (progress && (fileOffset - lastProgressReport) >= (4ull << 20)) {
            lastProgressReport = fileOffset;
            progress(fileOffset, total);
        }
    }

    if (inRun) {
        AppendAsciiHitIfNeeded(opt, outHits, curStart, cur);
        if (opt.maxHits > 0 && outHits.size() >= opt.maxHits) {
            if (truncated) {
                *truncated = true;
            }
            return true;
        }
    }

    if (progress) {
        progress(total, total);
    }
    return true;
}

static bool ScanUtf16LeStream(HANDLE h,
                              uint64_t total,
                              const StringsScanOptions& opt,
                              std::vector<StringsHit>& outHits,
                              std::wstring& error,
                              std::atomic<bool>* cancel,
                              const std::function<void(uint64_t processed, uint64_t total)>& progress,
                              bool* truncated) {
    const DWORD kBlock = 1u << 20;
    std::vector<uint8_t> buf(kBlock + 1);
    uint64_t fileOffset = 0;
    uint64_t lastProgressReport = 0;

    std::wstring cur;
    cur.reserve(256);
    uint64_t curStart = 0;
    bool inRun = false;
    bool haveCarry = false;
    uint8_t carry = 0;

    while (fileOffset < total) {
        if (cancel && cancel->load()) {
            error = L"\u5df2\u53d6\u6d88";
            return false;
        }
        if (opt.maxHits > 0 && outHits.size() >= opt.maxHits) {
            if (truncated) {
                *truncated = true;
            }
            return true;
        }
        DWORD toRead = static_cast<DWORD>(std::min<uint64_t>(kBlock, total - fileOffset));
        DWORD read = 0;
        if (!ReadFile(h, buf.data(), toRead, &read, nullptr)) {
            error = L"\u8bfb\u53d6\u5931\u8d25";
            return false;
        }
        if (read == 0) {
            break;
        }

        DWORD i = 0;
        if (haveCarry) {
            uint8_t lo = carry;
            uint8_t hi = buf[0];
            if (hi == 0x00 && IsAsciiPrintable(lo)) {
                if (!inRun) {
                    inRun = true;
                    curStart = fileOffset - 1;
                    cur.clear();
                }
                cur.push_back(static_cast<wchar_t>(lo));
                if (cur.size() >= static_cast<size_t>(opt.maxLen)) {
                    AppendUtf16HitIfNeeded(opt, outHits, curStart, cur);
                    inRun = false;
                    cur.clear();
                }
            } else {
                if (inRun) {
                    AppendUtf16HitIfNeeded(opt, outHits, curStart, cur);
                    inRun = false;
                    cur.clear();
                }
            }
            haveCarry = false;
            i = 1;
            if (opt.maxHits > 0 && outHits.size() >= opt.maxHits) {
                if (truncated) {
                    *truncated = true;
                }
                return true;
            }
        }

        while (i + 1 < read) {
            uint8_t lo = buf[i];
            uint8_t hi = buf[i + 1];
            if (hi == 0x00 && IsAsciiPrintable(lo)) {
                if (!inRun) {
                    inRun = true;
                    curStart = fileOffset + i;
                    cur.clear();
                }
                cur.push_back(static_cast<wchar_t>(lo));
                if (cur.size() >= static_cast<size_t>(opt.maxLen)) {
                    AppendUtf16HitIfNeeded(opt, outHits, curStart, cur);
                    inRun = false;
                    cur.clear();
                }
            } else {
                if (inRun) {
                    AppendUtf16HitIfNeeded(opt, outHits, curStart, cur);
                    inRun = false;
                    cur.clear();
                }
            }
            i += 2;
            if (opt.maxHits > 0 && outHits.size() >= opt.maxHits) {
                if (truncated) {
                    *truncated = true;
                }
                return true;
            }
        }

        if (i < read) {
            carry = buf[i];
            haveCarry = true;
        }

        fileOffset += read;
        if (progress && (fileOffset - lastProgressReport) >= (4ull << 20)) {
            lastProgressReport = fileOffset;
            progress(fileOffset, total);
        }
    }

    if (inRun) {
        AppendUtf16HitIfNeeded(opt, outHits, curStart, cur);
        if (opt.maxHits > 0 && outHits.size() >= opt.maxHits) {
            if (truncated) {
                *truncated = true;
            }
            return true;
        }
    }

    if (progress) {
        progress(total, total);
    }
    return true;
}

bool ScanStringsFromFile(const std::wstring& filePath,
                         const StringsScanOptions& opt,
                         std::vector<StringsHit>& outHits,
                         std::wstring& error,
                         std::atomic<bool>* cancel,
                         const std::function<void(uint64_t processed, uint64_t total)>& progress,
                         bool* truncated) {
    outHits.clear();
    error.clear();
    if (truncated) {
        *truncated = false;
    }

    if (opt.minLen < 1) {
        error = L"\u53c2\u6570\u9519\u8bef";
        return false;
    }

    HANDLE h = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        error = L"\u6253\u5f00\u6587\u4ef6\u5931\u8d25";
        return false;
    }
    uint64_t total = 0;
    if (!GetFileSize64(h, total)) {
        CloseHandle(h);
        error = L"\u83b7\u53d6\u6587\u4ef6\u5927\u5c0f\u5931\u8d25";
        return false;
    }

    bool ok = true;
    if (opt.scanAscii) {
        if (!SeekFile64(h, 0)) {
            CloseHandle(h);
            error = L"\u8bfb\u53d6\u5931\u8d25";
            return false;
        }
        ok = ScanAsciiStream(h, total, opt, outHits, error, cancel, progress, truncated);
        if (!ok) {
            CloseHandle(h);
            return false;
        }
        if (truncated && *truncated) {
            CloseHandle(h);
            std::stable_sort(outHits.begin(), outHits.end(), [](const StringsHit& a, const StringsHit& b) { return a.fileOffset < b.fileOffset; });
            return true;
        }
    }

    if (opt.scanUtf16Le) {
        if (!SeekFile64(h, 0)) {
            CloseHandle(h);
            error = L"\u8bfb\u53d6\u5931\u8d25";
            return false;
        }
        ok = ScanUtf16LeStream(h, total, opt, outHits, error, cancel, progress, truncated);
        if (!ok) {
            CloseHandle(h);
            return false;
        }
    }

    CloseHandle(h);
    std::stable_sort(outHits.begin(), outHits.end(), [](const StringsHit& a, const StringsHit& b) { return a.fileOffset < b.fileOffset; });
    return true;
}
