#include "stdafx.h"
#include "PdbFileInfo.h"

#include <algorithm>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <vector>

static std::wstring Basename(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

static bool ReadFileToBuffer(const std::wstring& filePath, std::vector<uint8_t>& out, std::wstring& outError) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        outError = L"\u65e0\u6cd5\u6253\u5f00\u6587\u4ef6";
        return false;
    }
    std::streampos pos = file.tellg();
    if (pos <= 0) {
        outError = L"\u6587\u4ef6\u5927\u5c0f\u5f02\u5e38";
        return false;
    }
    size_t size = static_cast<size_t>(pos);
    file.seekg(0, std::ios::beg);
    out.resize(size);
    if (!file.read(reinterpret_cast<char*>(out.data()), size)) {
        outError = L"\u65e0\u6cd5\u8bfb\u53d6\u6587\u4ef6";
        return false;
    }
    return true;
}

static bool StartsWith(const char* s, size_t sLen, const char* prefix, size_t prefixLen) {
    if (sLen < prefixLen) {
        return false;
    }
    return std::memcmp(s, prefix, prefixLen) == 0;
}

static bool ReadAt(const std::vector<uint8_t>& file, size_t offset, void* dst, size_t size) {
    if (offset > file.size() || file.size() - offset < size) {
        return false;
    }
    std::memcpy(dst, file.data() + offset, size);
    return true;
}

static bool ReadStreamBytes(const std::vector<uint8_t>& file,
                            uint32_t blockSize,
                            const std::vector<uint32_t>& blocks,
                            size_t streamOffset,
                            void* dst,
                            size_t dstSize) {
    if (dstSize == 0) {
        return true;
    }
    if (blockSize == 0) {
        return false;
    }
    size_t startBlock = streamOffset / blockSize;
    size_t blockOffset = streamOffset % blockSize;
    size_t remaining = dstSize;
    uint8_t* out = reinterpret_cast<uint8_t*>(dst);

    if (startBlock >= blocks.size()) {
        return false;
    }

    size_t blockIndex = startBlock;
    while (remaining > 0) {
        if (blockIndex >= blocks.size()) {
            return false;
        }
        uint32_t fileBlock = blocks[blockIndex];
        size_t fileOffset = static_cast<size_t>(fileBlock) * blockSize;
        size_t space = static_cast<size_t>(blockSize) - blockOffset;
        size_t copySize = remaining < space ? remaining : space;
        if (!ReadAt(file, fileOffset + blockOffset, out, copySize)) {
            return false;
        }
        out += copySize;
        remaining -= copySize;
        ++blockIndex;
        blockOffset = 0;
    }
    return true;
}

bool ReadPdbFileInfo(const std::wstring& filePath, PdbFileInfo& outInfo, std::wstring& outError) {
    outError.clear();

    std::vector<uint8_t> file;
    if (!ReadFileToBuffer(filePath, file, outError)) {
        return false;
    }

    struct SuperBlock {
        char magic[32];
        uint32_t blockSize;
        uint32_t freeBlockMapBlock;
        uint32_t numBlocks;
        uint32_t numDirectoryBytes;
        uint32_t unknown;
        uint32_t blockMapAddr;
    };

    SuperBlock sb = {};
    if (!ReadAt(file, 0, &sb, sizeof(sb))) {
        outError = L"\u6587\u4ef6\u8fc7\u5c0f";
        return false;
    }

    static const char kMsf7Magic[] = "Microsoft C/C++ MSF 7.00";
    if (!StartsWith(sb.magic, sizeof(sb.magic), kMsf7Magic, sizeof(kMsf7Magic) - 1)) {
        outError = L"\u4e0d\u662f\u652f\u6301\u7684 PDB \u683c\u5f0f\uff08\u975e MSF 7.00\uff09";
        return false;
    }

    if (sb.blockSize < 512 || sb.blockSize > (1u << 20)) {
        outError = L"\u574f\u7684 PDB\uff08blockSize \u5f02\u5e38\uff09";
        return false;
    }

    uint64_t expectedSize = static_cast<uint64_t>(sb.blockSize) * static_cast<uint64_t>(sb.numBlocks);
    if (expectedSize == 0 || expectedSize > file.size()) {
        outError = L"\u574f\u7684 PDB\uff08\u6587\u4ef6\u4e0e\u5757\u5143\u6570\u636e\u4e0d\u4e00\u81f4\uff09";
        return false;
    }

    if (sb.blockMapAddr == 0 || sb.blockMapAddr >= sb.numBlocks) {
        outError = L"\u574f\u7684 PDB\uff08directory block map \u5f02\u5e38\uff09";
        return false;
    }

    uint32_t dirBytes = sb.numDirectoryBytes;
    uint32_t dirBlockCount = (dirBytes + sb.blockSize - 1) / sb.blockSize;
    if (dirBlockCount == 0) {
        outError = L"\u574f\u7684 PDB\uff08directory \u4e3a\u7a7a\uff09";
        return false;
    }

    std::vector<uint32_t> dirBlocks(dirBlockCount, 0);
    size_t blockMapOffset = static_cast<size_t>(sb.blockMapAddr) * sb.blockSize;
    size_t entriesAvailable = sb.blockSize / sizeof(uint32_t);
    if (dirBlockCount > entriesAvailable) {
        outError = L"\u6682\u4e0d\u652f\u6301\u7684 PDB\uff08directory \u8fc7\u5927\uff09";
        return false;
    }
    if (!ReadAt(file, blockMapOffset, dirBlocks.data(), dirBlockCount * sizeof(uint32_t))) {
        outError = L"\u574f\u7684 PDB\uff08\u65e0\u6cd5\u8bfb\u53d6 directory block map\uff09";
        return false;
    }
    for (uint32_t b : dirBlocks) {
        if (b >= sb.numBlocks) {
            outError = L"\u574f\u7684 PDB\uff08directory block \u8d8a\u754c\uff09";
            return false;
        }
    }

    std::vector<uint8_t> directory(dirBlockCount * sb.blockSize);
    for (uint32_t i = 0; i < dirBlockCount; ++i) {
        size_t srcOffset = static_cast<size_t>(dirBlocks[i]) * sb.blockSize;
        size_t dstOffset = static_cast<size_t>(i) * sb.blockSize;
        if (!ReadAt(file, srcOffset, directory.data() + dstOffset, sb.blockSize)) {
            outError = L"\u574f\u7684 PDB\uff08\u65e0\u6cd5\u8bfb\u53d6 directory\uff09";
            return false;
        }
    }
    directory.resize(dirBytes);

    size_t cursor = 0;
    auto readU32 = [&](uint32_t& v) -> bool {
        if (cursor + sizeof(uint32_t) > directory.size()) {
            return false;
        }
        std::memcpy(&v, directory.data() + cursor, sizeof(uint32_t));
        cursor += sizeof(uint32_t);
        return true;
    };

    uint32_t numStreams = 0;
    if (!readU32(numStreams) || numStreams == 0) {
        outError = L"\u574f\u7684 PDB\uff08stream \u5217\u8868\u5f02\u5e38\uff09";
        return false;
    }

    std::vector<uint32_t> streamSizes(numStreams, 0);
    for (uint32_t i = 0; i < numStreams; ++i) {
        if (!readU32(streamSizes[i])) {
            outError = L"\u574f\u7684 PDB\uff08stream size \u8bfb\u53d6\u5931\u8d25\uff09";
            return false;
        }
    }

    std::vector<std::vector<uint32_t>> streamBlocks;
    streamBlocks.resize(numStreams);
    for (uint32_t i = 0; i < numStreams; ++i) {
        uint32_t size = streamSizes[i];
        if (size == 0xFFFFFFFFu) {
            continue;
        }
        uint32_t blocksNeeded = (size + sb.blockSize - 1) / sb.blockSize;
        streamBlocks[i].resize(blocksNeeded);
        size_t bytesNeeded = static_cast<size_t>(blocksNeeded) * sizeof(uint32_t);
        if (cursor + bytesNeeded > directory.size()) {
            outError = L"\u574f\u7684 PDB\uff08stream block \u8bfb\u53d6\u8d8a\u754c\uff09";
            return false;
        }
        std::memcpy(streamBlocks[i].data(), directory.data() + cursor, bytesNeeded);
        cursor += bytesNeeded;
        for (uint32_t b : streamBlocks[i]) {
            if (b >= sb.numBlocks) {
                outError = L"\u574f\u7684 PDB\uff08stream block \u8d8a\u754c\uff09";
                return false;
            }
        }
    }

    if (numStreams <= 1 || streamSizes[1] == 0xFFFFFFFFu || streamSizes[1] < (4 + 4 + 4 + sizeof(GUID))) {
        outError = L"PDB \u7ed3\u6784\u5f02\u5e38\uff08\u65e0\u6cd5\u5b9a\u4f4d PDB Info Stream\uff09";
        return false;
    }

    struct PdbInfoHeader {
        uint32_t version;
        uint32_t signature;
        uint32_t age;
        GUID guid;
    };

    PdbInfoHeader hdr = {};
    if (!ReadStreamBytes(file, sb.blockSize, streamBlocks[1], 0, &hdr, sizeof(hdr))) {
        outError = L"PDB \u89e3\u6790\u5931\u8d25\uff08\u8bfb\u53d6 PDB Info Stream \u5931\u8d25\uff09";
        return false;
    }

    outInfo.guid = hdr.guid;
    outInfo.age = hdr.age;
    outInfo.filePath = filePath;
    outInfo.fileName = Basename(filePath);
    return true;
}
