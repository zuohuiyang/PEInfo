#include "stdafx.h"
#include "PEDebugInfo.h"

#include <cstring>
#include <sstream>

static std::string ReadCStringBestEffort(const BYTE* data, size_t maxSize) {
    if (data == nullptr || maxSize == 0) {
        return {};
    }
    size_t len = strnlen(reinterpret_cast<const char*>(data), maxSize);
    return std::string(reinterpret_cast<const char*>(data), len);
}

std::string FormatGuidLower(const GUID& guid) {
    std::ostringstream oss;
    oss << std::hex << std::nouppercase;
    oss << std::setw(8) << std::setfill('0') << guid.Data1 << "-";
    oss << std::setw(4) << std::setfill('0') << guid.Data2 << "-";
    oss << std::setw(4) << std::setfill('0') << guid.Data3 << "-";
    oss << std::setw(2) << std::setfill('0') << static_cast<unsigned>(guid.Data4[0]);
    oss << std::setw(2) << std::setfill('0') << static_cast<unsigned>(guid.Data4[1]);
    oss << "-";
    for (int i = 2; i < 8; ++i) {
        oss << std::setw(2) << std::setfill('0') << static_cast<unsigned>(guid.Data4[i]);
    }
    return oss.str();
}

std::optional<PEPdbInfo> ExtractPdbInfo(const PEParser& parser) {
    DWORD dirRva = 0;
    DWORD dirSize = 0;
    if (!parser.GetDebugDirectory(dirRva, dirSize)) {
        return std::nullopt;
    }

    DWORD dirOffset = parser.RVAToFileOffsetPublic(dirRva);
    if (dirOffset == 0) {
        return std::nullopt;
    }

    if (dirSize < sizeof(IMAGE_DEBUG_DIRECTORY)) {
        return std::nullopt;
    }

    DWORD count = dirSize / static_cast<DWORD>(sizeof(IMAGE_DEBUG_DIRECTORY));
    for (DWORD i = 0; i < count; ++i) {
        const DWORD entryOffset = dirOffset + i * static_cast<DWORD>(sizeof(IMAGE_DEBUG_DIRECTORY));
        IMAGE_DEBUG_DIRECTORY entry = {};
        if (!parser.ReadBytes(entryOffset, &entry, sizeof(entry))) {
            return std::nullopt;
        }

        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData == 0) {
            continue;
        }

        DWORD dataOffset = entry.PointerToRawData;
        if (dataOffset == 0 && entry.AddressOfRawData != 0) {
            dataOffset = parser.RVAToFileOffsetPublic(entry.AddressOfRawData);
        }
        if (dataOffset == 0) {
            continue;
        }

        const DWORD minSize = 4 + 16 + 4;
        if (entry.SizeOfData < minSize) {
            continue;
        }

        std::vector<BYTE> buf(entry.SizeOfData);
        if (!parser.ReadBytes(dataOffset, buf.data(), buf.size())) {
            return std::nullopt;
        }

        if (std::memcmp(buf.data(), "RSDS", 4) != 0) {
            continue;
        }

        GUID guid = {};
        std::memcpy(&guid, buf.data() + 4, sizeof(guid));
        DWORD age = 0;
        std::memcpy(&age, buf.data() + 4 + sizeof(guid), sizeof(age));
        std::string pdbPath = ReadCStringBestEffort(buf.data() + 4 + sizeof(guid) + sizeof(age),
                                                    buf.size() - (4 + sizeof(guid) + sizeof(age)));

        PEPdbInfo info = {};
        info.hasRsds = true;
        info.guid = guid;
        info.age = age;
        info.pdbPath = std::move(pdbPath);
        return info;
    }

    return std::nullopt;
}
