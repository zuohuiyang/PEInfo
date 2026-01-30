#pragma once

#include "PEParser.h"

#include <optional>
#include <string>

struct PEPdbInfo {
    bool hasRsds;
    GUID guid;
    DWORD age;
    std::string pdbPath;
};

std::optional<PEPdbInfo> ExtractPdbInfo(const PEParser& parser);
std::string FormatGuidLower(const GUID& guid);

