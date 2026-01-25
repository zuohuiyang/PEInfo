#pragma once

#include "PEParser.h"

#include <map>
#include <optional>
#include <string>
#include <vector>

struct PEResourceNameOrId {
    bool isString = false;
    WORD id = 0;
    std::wstring name;
};

struct PEResourceItem {
    PEResourceNameOrId type;
    PEResourceNameOrId name;
    WORD language = 0;
    std::wstring languageName;
    DWORD dataRva = 0;
    DWORD size = 0;
    DWORD codePage = 0;
    DWORD rawOffset = 0;
};

struct PEResourceTypeStats {
    bool isString = false;
    WORD typeId = 0;
    std::wstring typeName;
    uint32_t items = 0;
    uint64_t totalBytes = 0;
};

struct PEResourceSummary {
    bool present = false;
    uint32_t typeCount = 0;
    uint32_t itemCount = 0;
    uint64_t totalBytes = 0;
    std::vector<PEResourceTypeStats> types;
};

std::wstring PEResourceTypeName(WORD typeId);
std::wstring PEResourceLanguageName(WORD langId);

bool EnumerateResources(const PEParser& parser, std::vector<PEResourceItem>& items, std::wstring& error);
PEResourceSummary BuildResourceSummary(const std::vector<PEResourceItem>& items);
bool ReadResourceBytes(const PEParser& parser, const PEResourceItem& item, std::vector<BYTE>& bytes);

struct PEVersionInfo {
    std::wstring fileVersion;
    std::wstring productVersion;
    DWORD fileFlags = 0;
    DWORD fileOS = 0;
    DWORD fileType = 0;
    DWORD fileSubType = 0;
    std::map<std::wstring, std::wstring> strings;
};

std::optional<PEVersionInfo> TryParseVersionInfo(const std::vector<PEResourceItem>& items, const PEParser& parser);

struct PEManifestInfo {
    bool present = false;
    std::wstring encoding;
    uint32_t size = 0;
    std::wstring text;
    std::wstring requestedExecutionLevel;
    std::optional<bool> uiAccess;
};

std::optional<PEManifestInfo> TryParseManifest(const std::vector<PEResourceItem>& items, const PEParser& parser, bool includeText);

struct PEIconImageInfo {
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t bitCount = 0;
    uint32_t bytesInRes = 0;
    uint32_t iconId = 0;
};

struct PEIconGroupInfo {
    PEResourceNameOrId name;
    WORD language = 0;
    std::vector<PEIconImageInfo> images;
};

std::vector<PEIconGroupInfo> TryParseIconGroups(const std::vector<PEResourceItem>& items, const PEParser& parser);
