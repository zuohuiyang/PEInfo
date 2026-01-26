#include "stdafx.h"
#include "ReportUtil.h"

#include <fstream>
#include <iomanip>
#include <sstream>

std::wstring ToWStringUtf8BestEffort(const std::string& s) {
    if (s.empty()) {
        return L"";
    }

    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    UINT codePage = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (needed == 0) {
        codePage = CP_ACP;
        flags = 0;
        needed = MultiByteToWideChar(codePage, flags, s.data(), static_cast<int>(s.size()), nullptr, 0);
    }
    if (needed <= 0) {
        return L"";
    }

    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(codePage, flags, s.data(), static_cast<int>(s.size()), out.data(), needed);
    return out;
}

static std::wstring FileTimeToStringUtc(const FILETIME& ft) {
    SYSTEMTIME st = {};
    if (!FileTimeToSystemTime(&ft, &st)) {
        return L"";
    }
    wchar_t buf[64] = {};
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::wstring FormatCoffTime(DWORD timeDateStamp, ReportTimeFormat mode) {
    if (mode == ReportTimeFormat::Raw) {
        std::wostringstream oss;
        oss << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << timeDateStamp;
        return oss.str();
    }

    ULONGLONG t = static_cast<ULONGLONG>(timeDateStamp);
    ULONGLONG ft64 = (t + 11644473600ULL) * 10000000ULL;
    FILETIME ft = {};
    ft.dwLowDateTime = static_cast<DWORD>(ft64 & 0xFFFFFFFFu);
    ft.dwHighDateTime = static_cast<DWORD>(ft64 >> 32);

    if (mode == ReportTimeFormat::Utc) {
        return FileTimeToStringUtc(ft) + L"Z";
    }

    FILETIME localFt = {};
    if (!FileTimeToLocalFileTime(&ft, &localFt)) {
        return L"";
    }
    return FileTimeToStringUtc(localFt);
}

std::wstring HexU32(DWORD v, int width) {
    std::wostringstream oss;
    oss << L"0x" << std::hex << std::setw(width) << std::setfill(L'0') << v << std::dec;
    return oss.str();
}

std::wstring HexU64(ULONGLONG v, int width) {
    std::wostringstream oss;
    oss << L"0x" << std::hex << std::setw(width) << std::setfill(L'0') << v << std::dec;
    return oss.str();
}

std::wstring CoffMachineToName(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386: return L"I386";
        case IMAGE_FILE_MACHINE_AMD64: return L"AMD64";
        case IMAGE_FILE_MACHINE_ARM: return L"ARM";
        case IMAGE_FILE_MACHINE_ARM64: return L"ARM64";
        case IMAGE_FILE_MACHINE_IA64: return L"IA64";
    }
    return L"Unknown";
}

std::string WStringToUtf8(const std::wstring& w) {
    if (w.empty()) {
        return {};
    }
    int needed = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

bool WriteAllBytes(const std::wstring& path, const std::string& bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        return false;
    }
    if (!bytes.empty()) {
        f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    return static_cast<bool>(f);
}

