#include "stdafx.h"
#include "PEResource.h"

#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <unordered_map>

namespace {

constexpr size_t kMaxResourceNameLen = 1024;
constexpr size_t kMaxResourceItems = 200000;
constexpr int kMaxResourceDepth = 16;

template <typename T>
bool ReadStruct(const PEParser& parser, DWORD fileOffset, T& out) {
    return parser.ReadBytes(fileOffset, &out, sizeof(T));
}

bool ReadResourceNameString(const PEParser& parser, DWORD rootFileOffset, DWORD relStringOffset, std::wstring& out, std::wstring& error) {
    WORD len = 0;
    if (!parser.ReadBytes(rootFileOffset + relStringOffset, &len, sizeof(len))) {
        error = L"Failed to read resource name length";
        return false;
    }
    if (len > kMaxResourceNameLen) {
        error = L"Resource name too long";
        return false;
    }
    std::wstring s;
    s.resize(len);
    if (len > 0) {
        if (!parser.ReadBytes(rootFileOffset + relStringOffset + sizeof(len), s.data(), static_cast<size_t>(len) * sizeof(wchar_t))) {
            error = L"Failed to read resource name string";
            return false;
        }
    }
    out = std::move(s);
    return true;
}

struct ResourcePathEntry {
    PEResourceNameOrId id;
};

bool ParseDirectory(const PEParser& parser,
                    DWORD rootFileOffset,
                    DWORD resourceRva,
                    DWORD dirRelOffset,
                    int depth,
                    std::vector<ResourcePathEntry>& path,
                    std::vector<PEResourceItem>& items,
                    std::wstring& error) {
    if (depth > kMaxResourceDepth) {
        error = L"Resource directory too deep";
        return false;
    }
    if (items.size() > kMaxResourceItems) {
        error = L"Too many resource items";
        return false;
    }

    IMAGE_RESOURCE_DIRECTORY dir = {};
    if (!ReadStruct(parser, rootFileOffset + dirRelOffset, dir)) {
        error = L"Failed to read IMAGE_RESOURCE_DIRECTORY";
        return false;
    }

    DWORD entryCount = static_cast<DWORD>(dir.NumberOfNamedEntries) + static_cast<DWORD>(dir.NumberOfIdEntries);
    DWORD entriesOffset = rootFileOffset + dirRelOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);

    for (DWORD i = 0; i < entryCount; ++i) {
        IMAGE_RESOURCE_DIRECTORY_ENTRY e = {};
        if (!ReadStruct(parser, entriesOffset + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), e)) {
            error = L"Failed to read IMAGE_RESOURCE_DIRECTORY_ENTRY";
            return false;
        }

        PEResourceNameOrId entryId;
        if (e.NameIsString) {
            entryId.isString = true;
            DWORD rel = e.NameOffset;
            if (!ReadResourceNameString(parser, rootFileOffset, rel, entryId.name, error)) {
                return false;
            }
        } else {
            entryId.isString = false;
            entryId.id = e.Id;
        }

        DWORD childRelOffset = e.OffsetToData & 0x7FFFFFFF;
        if (e.DataIsDirectory) {
            path.push_back({entryId});
            if (!ParseDirectory(parser, rootFileOffset, resourceRva, childRelOffset, depth + 1, path, items, error)) {
                return false;
            }
            path.pop_back();
            continue;
        }

        IMAGE_RESOURCE_DATA_ENTRY de = {};
        if (!ReadStruct(parser, rootFileOffset + childRelOffset, de)) {
            error = L"Failed to read IMAGE_RESOURCE_DATA_ENTRY";
            return false;
        }

        PEResourceItem item;
        if (!path.empty()) {
            item.type = path[0].id;
            if (!item.type.isString && item.type.id != 0) {
                item.type.name = PEResourceTypeName(item.type.id);
            }
        } else {
            item.type = entryId;
            if (!item.type.isString && item.type.id != 0) {
                item.type.name = PEResourceTypeName(item.type.id);
            }
        }

        if (path.size() >= 2) {
            item.name = path[1].id;
        } else if (path.size() == 1) {
            item.name = entryId;
        }

        if (path.size() >= 3) {
            item.language = path[2].id.id;
        } else if (path.size() == 2) {
            item.language = entryId.id;
        }
        item.languageName = PEResourceLanguageName(item.language);

        item.dataRva = de.OffsetToData;
        item.size = de.Size;
        item.codePage = de.CodePage;
        item.rawOffset = parser.RVAToFileOffsetPublic(de.OffsetToData);

        items.push_back(std::move(item));
    }

    return true;
}

} // namespace

std::wstring PEResourceTypeName(WORD typeId) {
    switch (typeId) {
        case 1: return L"RT_CURSOR";
        case 2: return L"RT_BITMAP";
        case 3: return L"RT_ICON";
        case 4: return L"RT_MENU";
        case 5: return L"RT_DIALOG";
        case 6: return L"RT_STRING";
        case 7: return L"RT_FONTDIR";
        case 8: return L"RT_FONT";
        case 9: return L"RT_ACCELERATOR";
        case 10: return L"RT_RCDATA";
        case 11: return L"RT_MESSAGETABLE";
        case 12: return L"RT_GROUP_CURSOR";
        case 14: return L"RT_GROUP_ICON";
        case 16: return L"RT_VERSION";
        case 17: return L"RT_DLGINCLUDE";
        case 19: return L"RT_PLUGPLAY";
        case 20: return L"RT_VXD";
        case 21: return L"RT_ANICURSOR";
        case 22: return L"RT_ANIICON";
        case 23: return L"RT_HTML";
        case 24: return L"RT_MANIFEST";
    }
    return L"";
}

std::wstring PEResourceLanguageName(WORD langId) {
    if (langId == 0) {
        return L"";
    }
    wchar_t name[LOCALE_NAME_MAX_LENGTH] = {};
    LCID lcid = MAKELCID(langId, SORT_DEFAULT);
    if (LCIDToLocaleName(lcid, name, LOCALE_NAME_MAX_LENGTH, 0) <= 0) {
        return L"";
    }
    return name;
}

bool EnumerateResources(const PEParser& parser, std::vector<PEResourceItem>& items, std::wstring& error) {
    items.clear();
    error.clear();

    DWORD rva = 0;
    DWORD size = 0;
    if (!parser.GetResourceDirectory(rva, size)) {
        return true;
    }

    DWORD rootFileOffset = parser.RVAToFileOffsetPublic(rva);
    if (rootFileOffset == 0) {
        error = L"Failed to map resource directory RVA to file offset";
        return false;
    }

    std::vector<ResourcePathEntry> path;
    if (!ParseDirectory(parser, rootFileOffset, rva, 0, 0, path, items, error)) {
        return false;
    }

    return true;
}

PEResourceSummary BuildResourceSummary(const std::vector<PEResourceItem>& items) {
    PEResourceSummary s;
    s.present = !items.empty();
    s.itemCount = static_cast<uint32_t>(items.size());

    struct Accum {
        bool isString = false;
        WORD id = 0;
        uint32_t items = 0;
        uint64_t bytes = 0;
        std::wstring name;
    };

    std::unordered_map<std::wstring, Accum> map;
    for (const auto& it : items) {
        std::wstring key;
        if (it.type.isString) {
            key = L"S:" + it.type.name;
        } else {
            key = L"I:" + std::to_wstring(it.type.id);
        }

        auto& a = map[key];
        if (a.items == 0) {
            a.isString = it.type.isString;
            a.id = it.type.isString ? 0 : it.type.id;
            a.name = it.type.name;
        }
        a.items += 1;
        a.bytes += it.size;
        s.totalBytes += it.size;
    }

    s.typeCount = static_cast<uint32_t>(map.size());
    s.types.reserve(map.size());
    for (auto& kv : map) {
        PEResourceTypeStats ts;
        ts.isString = kv.second.isString;
        ts.typeId = kv.second.id;
        ts.typeName = std::move(kv.second.name);
        ts.items = kv.second.items;
        ts.totalBytes = kv.second.bytes;
        s.types.push_back(std::move(ts));
    }

    std::sort(s.types.begin(), s.types.end(), [](const PEResourceTypeStats& a, const PEResourceTypeStats& b) {
        if (a.items != b.items) return a.items > b.items;
        if (a.isString != b.isString) return a.isString < b.isString;
        if (!a.isString && a.typeId != b.typeId) return a.typeId < b.typeId;
        return a.typeName < b.typeName;
    });

    return s;
}

bool ReadResourceBytes(const PEParser& parser, const PEResourceItem& item, std::vector<BYTE>& bytes) {
    bytes.clear();
    if (item.size == 0) {
        return true;
    }
    if (item.rawOffset == 0) {
        return false;
    }
    bytes.resize(item.size);
    return parser.ReadBytes(item.rawOffset, bytes.data(), bytes.size());
}

namespace {

std::optional<std::vector<BYTE>> TryLoadResourceByType(const std::vector<PEResourceItem>& items, const PEParser& parser, WORD typeId, PEResourceItem* picked) {
    for (const auto& it : items) {
        if (it.type.isString) {
            continue;
        }
        if (it.type.id != typeId) {
            continue;
        }
        std::vector<BYTE> bytes;
        if (!ReadResourceBytes(parser, it, bytes)) {
            continue;
        }
        if (picked != nullptr) {
            *picked = it;
        }
        return bytes;
    }
    return std::nullopt;
}

bool ReadWordAt(const std::vector<BYTE>& data, size_t pos, WORD& out) {
    if (pos + sizeof(WORD) > data.size()) {
        return false;
    }
    out = *reinterpret_cast<const WORD*>(data.data() + pos);
    return true;
}

size_t Align4(size_t v) {
    return (v + 3) & ~static_cast<size_t>(3);
}

bool ReadNullTerminatedWideString(const std::vector<BYTE>& data, size_t pos, std::wstring& out, size_t& bytesRead) {
    out.clear();
    bytesRead = 0;
    if (pos >= data.size()) {
        return false;
    }
    size_t i = pos;
    while (i + sizeof(wchar_t) <= data.size()) {
        wchar_t ch = *reinterpret_cast<const wchar_t*>(data.data() + i);
        i += sizeof(wchar_t);
        if (ch == L'\0') {
            bytesRead = i - pos;
            return true;
        }
        out.push_back(ch);
        if (out.size() > 4096) {
            return false;
        }
    }
    return false;
}

std::wstring FormatVersion(DWORD ms, DWORD ls) {
    std::wostringstream oss;
    oss << HIWORD(ms) << L"." << LOWORD(ms) << L"." << HIWORD(ls) << L"." << LOWORD(ls);
    return oss.str();
}

bool ParseVersionBlock(const std::vector<BYTE>& data, size_t blockOffset, PEVersionInfo& out) {
    WORD wLength = 0;
    WORD wValueLength = 0;
    WORD wType = 0;
    if (!ReadWordAt(data, blockOffset + 0, wLength) || !ReadWordAt(data, blockOffset + 2, wValueLength) || !ReadWordAt(data, blockOffset + 4, wType)) {
        return false;
    }
    if (wLength < 6) {
        return false;
    }
    size_t end = blockOffset + wLength;
    if (end > data.size()) {
        return false;
    }

    std::wstring key;
    size_t keyBytes = 0;
    if (!ReadNullTerminatedWideString(data, blockOffset + 6, key, keyBytes)) {
        return false;
    }

    size_t pos = blockOffset + 6 + keyBytes;
    pos = Align4(pos);
    if (pos > end) {
        return false;
    }

    size_t valueSizeBytes = 0;
    if (wValueLength > 0) {
        if (wType == 1) {
            valueSizeBytes = static_cast<size_t>(wValueLength) * sizeof(wchar_t);
        } else {
            valueSizeBytes = static_cast<size_t>(wValueLength);
        }
    }

    size_t valueOffset = pos;
    size_t childrenOffset = Align4(valueOffset + valueSizeBytes);
    if (childrenOffset > end) {
        childrenOffset = end;
    }

    if (key == L"VS_VERSION_INFO" && wType == 0 && valueSizeBytes >= sizeof(VS_FIXEDFILEINFO) && valueOffset + sizeof(VS_FIXEDFILEINFO) <= end) {
        const auto* ffi = reinterpret_cast<const VS_FIXEDFILEINFO*>(data.data() + valueOffset);
        if (ffi->dwSignature == 0xFEEF04BD) {
            out.fileVersion = FormatVersion(ffi->dwFileVersionMS, ffi->dwFileVersionLS);
            out.productVersion = FormatVersion(ffi->dwProductVersionMS, ffi->dwProductVersionLS);
            out.fileFlags = ffi->dwFileFlags;
            out.fileOS = ffi->dwFileOS;
            out.fileType = ffi->dwFileType;
            out.fileSubType = ffi->dwFileSubtype;
        }
    }

    if (wType == 1 && wValueLength > 0 && valueOffset + valueSizeBytes <= end) {
        std::wstring value;
        value.assign(reinterpret_cast<const wchar_t*>(data.data() + valueOffset), wValueLength);
        while (!value.empty() && value.back() == L'\0') {
            value.pop_back();
        }
        if (!key.empty() && !value.empty()) {
            out.strings[key] = value;
        }
    }

    size_t child = childrenOffset;
    while (child + 6 <= end) {
        WORD childLen = 0;
        if (!ReadWordAt(data, child, childLen)) {
            break;
        }
        if (childLen == 0) {
            break;
        }
        if (child + childLen > end) {
            break;
        }
        ParseVersionBlock(data, child, out);
        child = Align4(child + childLen);
    }

    return true;
}

std::wstring DecodeUtf8ToWide(const BYTE* data, size_t size) {
    if (size == 0) {
        return L"";
    }
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char*>(data), static_cast<int>(size), nullptr, 0);
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (needed <= 0) {
        flags = 0;
        needed = MultiByteToWideChar(CP_UTF8, flags, reinterpret_cast<const char*>(data), static_cast<int>(size), nullptr, 0);
    }
    if (needed <= 0) {
        std::wstring w;
        w.reserve(size);
        for (size_t i = 0; i < size; ++i) {
            w.push_back(static_cast<wchar_t>(data[i]));
        }
        return w;
    }
    std::wstring out;
    out.resize(static_cast<size_t>(needed));
    MultiByteToWideChar(CP_UTF8, flags, reinterpret_cast<const char*>(data), static_cast<int>(size), out.data(), needed);
    return out;
}

std::optional<std::wstring> ExtractManifestAttr(const std::wstring& text, const std::wstring& key, size_t startPos) {
    std::wstring needleDouble = key + L"=\"";
    std::wstring needleSingle = key + L"='";

    size_t p = text.find(needleDouble, startPos);
    wchar_t quote = L'"';
    if (p != std::wstring::npos) {
        p += needleDouble.size();
    } else {
        p = text.find(needleSingle, startPos);
        if (p == std::wstring::npos) {
            return std::nullopt;
        }
        quote = L'\'';
        p += needleSingle.size();
    }

    size_t end = text.find(quote, p);
    if (end == std::wstring::npos || end <= p) {
        return std::nullopt;
    }
    return text.substr(p, end - p);
}

} // namespace

std::optional<PEVersionInfo> TryParseVersionInfo(const std::vector<PEResourceItem>& items, const PEParser& parser) {
    PEResourceItem picked;
    auto bytesOpt = TryLoadResourceByType(items, parser, 16, &picked);
    if (!bytesOpt.has_value()) {
        return std::nullopt;
    }
    PEVersionInfo vi;
    if (!ParseVersionBlock(*bytesOpt, 0, vi)) {
        return std::nullopt;
    }
    if (vi.fileVersion.empty() && vi.productVersion.empty() && vi.strings.empty()) {
        return std::nullopt;
    }
    return vi;
}

std::optional<PEManifestInfo> TryParseManifest(const std::vector<PEResourceItem>& items, const PEParser& parser, bool includeText) {
    PEResourceItem picked;
    auto bytesOpt = TryLoadResourceByType(items, parser, 24, &picked);
    if (!bytesOpt.has_value()) {
        return std::nullopt;
    }

    const auto& bytes = *bytesOpt;
    PEManifestInfo mi;
    mi.present = true;
    mi.size = static_cast<uint32_t>(bytes.size());

    const BYTE* p = bytes.data();
    size_t n = bytes.size();

    if (n >= 2 && p[0] == 0xFF && p[1] == 0xFE) {
        mi.encoding = L"utf-16le";
        size_t off = 2;
        size_t wbytes = (n - off) & ~static_cast<size_t>(1);
        mi.text.assign(reinterpret_cast<const wchar_t*>(p + off), wbytes / sizeof(wchar_t));
    } else if (n >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) {
        mi.encoding = L"utf-8";
        mi.text = DecodeUtf8ToWide(p + 3, n - 3);
    } else if (n >= 2 && p[0] == '<' && p[1] == 0) {
        mi.encoding = L"utf-16le";
        size_t wbytes = n & ~static_cast<size_t>(1);
        mi.text.assign(reinterpret_cast<const wchar_t*>(p), wbytes / sizeof(wchar_t));
    } else {
        mi.encoding = L"utf-8";
        mi.text = DecodeUtf8ToWide(p, n);
    }

    size_t searchPos = mi.text.find(L"requestedExecutionLevel");
    if (searchPos != std::wstring::npos) {
        auto level = ExtractManifestAttr(mi.text, L"level", searchPos);
        if (level.has_value()) {
            mi.requestedExecutionLevel = *level;
        }
        auto uiAccess = ExtractManifestAttr(mi.text, L"uiAccess", searchPos);
        if (uiAccess.has_value()) {
            std::wstring v = *uiAccess;
            std::transform(v.begin(), v.end(), v.begin(), [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
            if (v == L"true") {
                mi.uiAccess = true;
            } else if (v == L"false") {
                mi.uiAccess = false;
            }
        }
    }

    if (!includeText) {
        mi.text.clear();
    }

    return mi;
}

std::vector<PEIconGroupInfo> TryParseIconGroups(const std::vector<PEResourceItem>& items, const PEParser& parser) {
    std::vector<PEIconGroupInfo> out;

#pragma pack(push, 2)
    struct GRPICONDIR {
        WORD idReserved;
        WORD idType;
        WORD idCount;
    };
    struct GRPICONDIRENTRY {
        BYTE bWidth;
        BYTE bHeight;
        BYTE bColorCount;
        BYTE bReserved;
        WORD wPlanes;
        WORD wBitCount;
        DWORD dwBytesInRes;
        WORD nID;
    };
#pragma pack(pop)

    for (const auto& it : items) {
        if (it.type.isString || it.type.id != 14) {
            continue;
        }
        std::vector<BYTE> bytes;
        if (!ReadResourceBytes(parser, it, bytes)) {
            continue;
        }
        if (bytes.size() < sizeof(GRPICONDIR)) {
            continue;
        }
        const auto* hdr = reinterpret_cast<const GRPICONDIR*>(bytes.data());
        if (hdr->idType != 1 || hdr->idCount == 0) {
            continue;
        }
        size_t need = sizeof(GRPICONDIR) + static_cast<size_t>(hdr->idCount) * sizeof(GRPICONDIRENTRY);
        if (bytes.size() < need) {
            continue;
        }
        PEIconGroupInfo gi;
        gi.name = it.name;
        gi.language = it.language;
        gi.images.reserve(hdr->idCount);

        const auto* ents = reinterpret_cast<const GRPICONDIRENTRY*>(bytes.data() + sizeof(GRPICONDIR));
        for (WORD i = 0; i < hdr->idCount; ++i) {
            PEIconImageInfo img;
            img.width = (ents[i].bWidth == 0) ? 256u : static_cast<uint32_t>(ents[i].bWidth);
            img.height = (ents[i].bHeight == 0) ? 256u : static_cast<uint32_t>(ents[i].bHeight);
            img.bitCount = ents[i].wBitCount;
            img.bytesInRes = ents[i].dwBytesInRes;
            img.iconId = ents[i].nID;
            gi.images.push_back(std::move(img));
        }

        out.push_back(std::move(gi));
    }

    return out;
}
