#pragma once

#include <string>

struct PdbFileInfo {
    GUID guid;
    DWORD age;
    std::wstring filePath;
    std::wstring fileName;
};

bool ReadPdbFileInfo(const std::wstring& filePath, PdbFileInfo& outInfo, std::wstring& outError);

