#include "stdafx.h"
#include "PEParser.h"
#include <sstream>

PEParser::PEParser()
    : m_dosHeader(nullptr),
      m_ntHeaders32(nullptr),
      m_ntHeaders64(nullptr),
      m_isPE32Plus(false),
      m_sectionHeaders(nullptr),
      m_isValidPE(false) {
}

PEParser::~PEParser() {
    UnloadFile();
}

bool PEParser::LoadFile(const std::wstring& filePath) {
    UnloadFile();
    
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        m_lastError = L"Failed to open file: " + filePath;
        return false;
    }

    std::streampos pos = file.tellg();
    size_t fileSize = static_cast<size_t>(pos);
    file.seekg(0, std::ios::beg);

    m_fileData.resize(fileSize);
    if (!file.read(reinterpret_cast<char*>(m_fileData.data()), fileSize)) {
        m_lastError = L"Failed to read file";
        return false;
    }

    return ParsePE();
}

void PEParser::UnloadFile() {
    m_fileData.clear();
    m_dosHeader = nullptr;
    m_ntHeaders32 = nullptr;
    m_ntHeaders64 = nullptr;
    m_isPE32Plus = false;
    m_sectionHeaders = nullptr;
    m_isValidPE = false;
    m_imports.clear();
    m_delayImports.clear();
    m_exports.clear();
    m_lastError.clear();
}

bool PEParser::ParsePE() {
    if (m_fileData.size() < sizeof(IMAGE_DOS_HEADER)) {
        m_lastError = L"File too small, not a valid PE file";
        return false;
    }

    m_dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_fileData.data());
    if (m_dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        m_lastError = L"Invalid DOS signature";
        return false;
    }

    DWORD ntOffset = static_cast<DWORD>(m_dosHeader->e_lfanew);
    if (ntOffset > m_fileData.size()) {
        m_lastError = L"Invalid e_lfanew";
        return false;
    }

    if (m_fileData.size() < static_cast<size_t>(ntOffset) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD)) {
        m_lastError = L"File too small, does not contain complete PE header";
        return false;
    }

    const BYTE* ntBase = m_fileData.data() + ntOffset;
    DWORD signature = *reinterpret_cast<const DWORD*>(ntBase);
    if (signature != IMAGE_NT_SIGNATURE) {
        m_lastError = L"Invalid PE signature";
        return false;
    }

    const IMAGE_FILE_HEADER* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + sizeof(DWORD));
    WORD optionalMagic = *reinterpret_cast<const WORD*>(ntBase + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    m_isPE32Plus = (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if (!m_isPE32Plus && optionalMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        m_lastError = L"Unknown PE optional header magic";
        return false;
    }

    size_t ntHeadersSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + static_cast<size_t>(fileHeader->SizeOfOptionalHeader);
    if (m_fileData.size() < static_cast<size_t>(ntOffset) + ntHeadersSize) {
        m_lastError = L"File too small, does not contain complete optional header";
        return false;
    }

    if (m_isPE32Plus) {
        m_ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_fileData.data() + ntOffset);
        m_ntHeaders32 = nullptr;
    } else {
        m_ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(m_fileData.data() + ntOffset);
        m_ntHeaders64 = nullptr;
    }

    const BYTE* sectionBase = ntBase + ntHeadersSize;
    size_t sectionHeadersBytes = static_cast<size_t>(fileHeader->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (m_fileData.size() < static_cast<size_t>(ntOffset) + ntHeadersSize + sectionHeadersBytes) {
        m_lastError = L"File too small, does not contain complete section headers";
        return false;
    }

    m_sectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(const_cast<BYTE*>(sectionBase));

    // Fill header information
    m_headerInfo.is32Bit = (fileHeader->Machine == IMAGE_FILE_MACHINE_I386);
    m_headerInfo.is64Bit = (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64);
    m_headerInfo.machine = fileHeader->Machine;
    m_headerInfo.numberOfSections = fileHeader->NumberOfSections;
    m_headerInfo.timeDateStamp = fileHeader->TimeDateStamp;

    DWORD subsystemValue = 0;
    if (m_isPE32Plus) {
        m_headerInfo.sizeOfImage = m_ntHeaders64->OptionalHeader.SizeOfImage;
        m_headerInfo.entryPoint = m_ntHeaders64->OptionalHeader.AddressOfEntryPoint;
        m_headerInfo.imageBase = m_ntHeaders64->OptionalHeader.ImageBase;
        subsystemValue = m_ntHeaders64->OptionalHeader.Subsystem;
    } else {
        m_headerInfo.sizeOfImage = m_ntHeaders32->OptionalHeader.SizeOfImage;
        m_headerInfo.entryPoint = m_ntHeaders32->OptionalHeader.AddressOfEntryPoint;
        m_headerInfo.imageBase = m_ntHeaders32->OptionalHeader.ImageBase;
        subsystemValue = m_ntHeaders32->OptionalHeader.Subsystem;
    }
    
    // Get subsystem string
    switch (subsystemValue) {
        case IMAGE_SUBSYSTEM_NATIVE: m_headerInfo.subsystem = "Native"; break;
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: m_headerInfo.subsystem = "Windows GUI"; break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: m_headerInfo.subsystem = "Windows Console"; break;
        default: m_headerInfo.subsystem = "Unknown"; break;
    }

    ParseImports();
    ParseDelayImports();
    ParseExports();

    m_isValidPE = true;
    return true;
}

bool PEParser::ParseImports() {
    m_imports.clear();

    IMAGE_DATA_DIRECTORY dir = {};
    if (m_isPE32Plus) {
        dir = m_ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    } else {
        dir = m_ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }

    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return true; // No import table
    }

    return ParseImportTable(dir.VirtualAddress, dir.Size);
}

bool PEParser::ParseImportTable(DWORD importTableRVA, DWORD importTableSize) {
    (void)importTableSize;
    DWORD offset = RVAToFileOffset(importTableRVA);
    if (offset == 0) {
        m_lastError = L"Failed to convert import table RVA to file offset";
        return false;
    }

    DWORD currentOffset = offset;
    
    while (true) {
        IMAGE_IMPORT_DESCRIPTOR importDesc;
        if (!ReadMemory(currentOffset, &importDesc, sizeof(importDesc))) {
            m_lastError = L"Failed to read import descriptor";
            return false;
        }

        if (importDesc.Name == 0) {
            break; // End of import descriptors
        }

        std::string dllName;
        std::vector<PEImportFunction> functions;
        
        if (!ParseImportDescriptor(currentOffset, dllName, functions)) {
            return false;
        }

        PEImportDLL importDLL;
        importDLL.dllName = dllName;
        importDLL.functions = functions;
        m_imports.push_back(importDLL);

        currentOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    return true;
}

bool PEParser::ParseImportDescriptor(DWORD descriptorFileOffset, std::string& dllName, std::vector<PEImportFunction>& functions) {
    functions.clear();

    IMAGE_IMPORT_DESCRIPTOR importDesc;
    if (!ReadMemory(descriptorFileOffset, &importDesc, sizeof(importDesc))) {
        m_lastError = L"Failed to read import descriptor";
        return false;
    }

    // Get DLL name
    DWORD nameOffset = RVAToFileOffset(importDesc.Name);
    dllName = ReadString(nameOffset);
    if (dllName.empty() && importDesc.Name != 0) {
        m_lastError = L"Failed to read DLL name";
        return false;
    }

    // Parse functions
    DWORD thunkRVA = importDesc.OriginalFirstThunk ? importDesc.OriginalFirstThunk : importDesc.FirstThunk;
    DWORD thunkOffset = RVAToFileOffset(thunkRVA);
    
    if (thunkOffset == 0) {
        m_lastError = L"Failed to convert thunk RVA to file offset";
        return false;
    }

    DWORD currentThunkOffset = thunkOffset;
    ULONGLONG currentThunkRva = thunkRVA;
    
    while (true) {
        PEImportFunction func = {};
        func.rva = static_cast<DWORD>(currentThunkRva);

        if (m_isPE32Plus) {
            ULONGLONG thunkData = 0;
            if (!ReadMemory(currentThunkOffset, &thunkData, sizeof(thunkData))) {
                m_lastError = L"Failed to read thunk data";
                return false;
            }
            if (thunkData == 0) {
                break;
            }

            if (IMAGE_SNAP_BY_ORDINAL64(thunkData)) {
                func.isOrdinal = true;
                func.ordinal = static_cast<DWORD>(IMAGE_ORDINAL64(thunkData));
                func.name = "Ordinal: " + std::to_string(func.ordinal);
            } else {
                DWORD importByNameRva = static_cast<DWORD>(thunkData);
                DWORD importByNameOffset = RVAToFileOffset(importByNameRva);
                if (importByNameOffset == 0) {
                    m_lastError = L"Failed to convert name RVA to file offset";
                    return false;
                }
                func.isOrdinal = false;
                func.ordinal = 0;
                func.name = ReadString(importByNameOffset + 2);
                if (func.name.empty()) {
                    m_lastError = L"Failed to read function name";
                    return false;
                }
            }

            functions.push_back(func);
            currentThunkOffset += sizeof(ULONGLONG);
            currentThunkRva += sizeof(ULONGLONG);
        } else {
            DWORD thunkData = 0;
            if (!ReadMemory(currentThunkOffset, &thunkData, sizeof(thunkData))) {
                m_lastError = L"Failed to read thunk data";
                return false;
            }
            if (thunkData == 0) {
                break;
            }

            if (IMAGE_SNAP_BY_ORDINAL32(thunkData)) {
                func.isOrdinal = true;
                func.ordinal = static_cast<DWORD>(IMAGE_ORDINAL32(thunkData));
                func.name = "Ordinal: " + std::to_string(func.ordinal);
            } else {
                DWORD importByNameOffset = RVAToFileOffset(thunkData);
                if (importByNameOffset == 0) {
                    m_lastError = L"Failed to convert name RVA to file offset";
                    return false;
                }
                func.isOrdinal = false;
                func.ordinal = 0;
                func.name = ReadString(importByNameOffset + 2);
                if (func.name.empty()) {
                    m_lastError = L"Failed to read function name";
                    return false;
                }
            }

            functions.push_back(func);
            currentThunkOffset += sizeof(DWORD);
            currentThunkRva += sizeof(DWORD);
        }
    }

    return true;
}

DWORD PEParser::DelayAddrToRva(DWORD delayAddr, DWORD delayAttrs) const {
    if ((delayAttrs & 1u) != 0u) {
        return delayAddr;
    }

    if (delayAddr == 0) {
        return 0;
    }

    ULONGLONG base = m_headerInfo.imageBase;
    if (delayAddr < base) {
        return 0;
    }

    return static_cast<DWORD>(static_cast<ULONGLONG>(delayAddr) - base);
}

bool PEParser::ParseDelayImports() {
    m_delayImports.clear();

    IMAGE_DATA_DIRECTORY dir = {};
    if (m_isPE32Plus) {
        dir = m_ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    } else {
        dir = m_ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    }

    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return true;
    }

    DWORD tableOffset = RVAToFileOffset(dir.VirtualAddress);
    if (tableOffset == 0) {
        m_lastError = L"Failed to convert delay import table RVA to file offset";
        return false;
    }

    struct DelayDescriptor {
        DWORD grAttrs;
        DWORD szName;
        DWORD phmod;
        DWORD pIAT;
        DWORD pINT;
        DWORD pBoundIAT;
        DWORD pUnloadIAT;
        DWORD dwTimeStamp;
    };

    DWORD currentOffset = tableOffset;
    while (true) {
        DelayDescriptor desc = {};
        if (!ReadMemory(currentOffset, &desc, sizeof(desc))) {
            m_lastError = L"Failed to read delay import descriptor";
            return false;
        }

        if (desc.grAttrs == 0 && desc.szName == 0 && desc.pIAT == 0 && desc.pINT == 0) {
            break;
        }

        DWORD nameRva = DelayAddrToRva(desc.szName, desc.grAttrs);
        std::string dllName = ReadString(RVAToFileOffset(nameRva));
        if (dllName.empty() && nameRva != 0) {
            m_lastError = L"Failed to read delay import DLL name";
            return false;
        }

        DWORD thunkAddr = desc.pINT ? desc.pINT : desc.pIAT;
        DWORD thunkRva = DelayAddrToRva(thunkAddr, desc.grAttrs);
        DWORD thunkOffset = RVAToFileOffset(thunkRva);
        if (thunkOffset == 0) {
            m_lastError = L"Failed to convert delay import thunk RVA to file offset";
            return false;
        }

        std::vector<PEImportFunction> functions;
        DWORD currentThunkOffset = thunkOffset;
        while (true) {
            PEImportFunction func = {};

            if (m_isPE32Plus) {
                ULONGLONG thunkData = 0;
                if (!ReadMemory(currentThunkOffset, &thunkData, sizeof(thunkData))) {
                    m_lastError = L"Failed to read delay import thunk data";
                    return false;
                }
                if (thunkData == 0) {
                    break;
                }

                if (IMAGE_SNAP_BY_ORDINAL64(thunkData)) {
                    func.isOrdinal = true;
                    func.ordinal = static_cast<DWORD>(IMAGE_ORDINAL64(thunkData));
                    func.name = "Ordinal: " + std::to_string(func.ordinal);
                } else {
                    ULONGLONG addr = thunkData;
                    DWORD nameRva2 = (desc.grAttrs & 1u) ? static_cast<DWORD>(addr) : static_cast<DWORD>(addr - m_headerInfo.imageBase);
                    DWORD nameOffset2 = RVAToFileOffset(nameRva2);
                    if (nameOffset2 == 0) {
                        m_lastError = L"Failed to convert delay import name RVA to file offset";
                        return false;
                    }
                    func.isOrdinal = false;
                    func.ordinal = 0;
                    func.name = ReadString(nameOffset2 + 2);
                    if (func.name.empty()) {
                        m_lastError = L"Failed to read delay import function name";
                        return false;
                    }
                }

                functions.push_back(func);
                currentThunkOffset += sizeof(ULONGLONG);
            } else {
                DWORD thunkData = 0;
                if (!ReadMemory(currentThunkOffset, &thunkData, sizeof(thunkData))) {
                    m_lastError = L"Failed to read delay import thunk data";
                    return false;
                }
                if (thunkData == 0) {
                    break;
                }

                if (IMAGE_SNAP_BY_ORDINAL32(thunkData)) {
                    func.isOrdinal = true;
                    func.ordinal = static_cast<DWORD>(IMAGE_ORDINAL32(thunkData));
                    func.name = "Ordinal: " + std::to_string(func.ordinal);
                } else {
                    DWORD nameRva2 = DelayAddrToRva(thunkData, desc.grAttrs);
                    DWORD nameOffset2 = RVAToFileOffset(nameRva2);
                    if (nameOffset2 == 0) {
                        m_lastError = L"Failed to convert delay import name RVA to file offset";
                        return false;
                    }
                    func.isOrdinal = false;
                    func.ordinal = 0;
                    func.name = ReadString(nameOffset2 + 2);
                    if (func.name.empty()) {
                        m_lastError = L"Failed to read delay import function name";
                        return false;
                    }
                }

                functions.push_back(func);
                currentThunkOffset += sizeof(DWORD);
            }
        }

        PEImportDLL d = {};
        d.dllName = dllName;
        d.functions = std::move(functions);
        m_delayImports.push_back(std::move(d));

        currentOffset += sizeof(DelayDescriptor);
    }

    return true;
}

bool PEParser::ParseExports() {
    m_exports.clear();

    IMAGE_DATA_DIRECTORY dir = {};
    if (m_isPE32Plus) {
        dir = m_ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else {
        dir = m_ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return true;
    }

    DWORD exportOffset = RVAToFileOffset(dir.VirtualAddress);
    if (exportOffset == 0) {
        m_lastError = L"Failed to convert export table RVA to file offset";
        return false;
    }

    IMAGE_EXPORT_DIRECTORY exp = {};
    if (!ReadMemory(exportOffset, &exp, sizeof(exp))) {
        m_lastError = L"Failed to read export directory";
        return false;
    }

    if (exp.NumberOfFunctions == 0) {
        return true;
    }

    DWORD functionsOffset = RVAToFileOffset(exp.AddressOfFunctions);
    if (functionsOffset == 0) {
        m_lastError = L"Failed to convert export address table RVA to file offset";
        return false;
    }

    std::vector<DWORD> functionRvas(exp.NumberOfFunctions);
    if (!ReadMemory(functionsOffset, functionRvas.data(), functionRvas.size() * sizeof(DWORD))) {
        m_lastError = L"Failed to read export address table";
        return false;
    }

    m_exports.resize(exp.NumberOfFunctions);
    for (DWORD i = 0; i < exp.NumberOfFunctions; ++i) {
        m_exports[i].ordinal = exp.Base + i;
        m_exports[i].rva = functionRvas[i];
        m_exports[i].hasName = false;
        m_exports[i].name.clear();
    }

    if (exp.NumberOfNames == 0) {
        return true;
    }

    DWORD namesOffset = RVAToFileOffset(exp.AddressOfNames);
    DWORD ordinalsOffset = RVAToFileOffset(exp.AddressOfNameOrdinals);
    if (namesOffset == 0 || ordinalsOffset == 0) {
        m_lastError = L"Failed to convert export name tables RVA to file offset";
        return false;
    }

    std::vector<DWORD> nameRvas(exp.NumberOfNames);
    std::vector<WORD> nameOrdinals(exp.NumberOfNames);
    if (!ReadMemory(namesOffset, nameRvas.data(), nameRvas.size() * sizeof(DWORD))) {
        m_lastError = L"Failed to read export name table";
        return false;
    }
    if (!ReadMemory(ordinalsOffset, nameOrdinals.data(), nameOrdinals.size() * sizeof(WORD))) {
        m_lastError = L"Failed to read export ordinal table";
        return false;
    }

    for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
        WORD idx = nameOrdinals[i];
        if (idx >= m_exports.size()) {
            continue;
        }
        std::string name = ReadString(RVAToFileOffset(nameRvas[i]));
        if (!name.empty()) {
            m_exports[idx].name = std::move(name);
            m_exports[idx].hasName = true;
        }
    }

    return true;
}

DWORD PEParser::RVAToFileOffset(DWORD rva) const {
    if (m_fileData.empty() || m_sectionHeaders == nullptr) {
        return 0;
    }

    DWORD sizeOfHeaders = 0;
    if (m_isPE32Plus && m_ntHeaders64 != nullptr) {
        sizeOfHeaders = m_ntHeaders64->OptionalHeader.SizeOfHeaders;
    } else if (!m_isPE32Plus && m_ntHeaders32 != nullptr) {
        sizeOfHeaders = m_ntHeaders32->OptionalHeader.SizeOfHeaders;
    }

    if (sizeOfHeaders != 0 && rva < sizeOfHeaders) {
        return rva;
    }

    // Find the section containing this RVA
    for (DWORD i = 0; i < m_headerInfo.numberOfSections; i++) {
        PIMAGE_SECTION_HEADER section = &m_sectionHeaders[i];
        
        if (rva >= section->VirtualAddress && 
            rva < section->VirtualAddress + section->Misc.VirtualSize) {
            
            DWORD offset = rva - section->VirtualAddress;
            return section->PointerToRawData + offset;
        }
    }

    return 0;
}

bool PEParser::ReadMemory(DWORD offset, void* buffer, size_t size) {
    if (offset + size > m_fileData.size()) {
        return false;
    }

    memcpy(buffer, m_fileData.data() + offset, size);
    return true;
}

std::string PEParser::ReadString(DWORD offset) {
    if (offset >= m_fileData.size()) {
        return "";
    }

    std::string result;
    const char* str = reinterpret_cast<const char*>(m_fileData.data() + offset);
    
    // Find null terminator
    size_t maxLen = m_fileData.size() - offset;
    size_t len = strnlen(str, maxLen);
    
    if (len == maxLen) {
        return ""; // No null terminator found
    }

    return std::string(str, len);
}

std::vector<PESectionInfo> PEParser::GetSectionsInfo() const {
    std::vector<PESectionInfo> out;
    if (!m_isValidPE || m_sectionHeaders == nullptr) {
        return out;
    }

    out.reserve(m_headerInfo.numberOfSections);
    for (DWORD i = 0; i < m_headerInfo.numberOfSections; ++i) {
        const IMAGE_SECTION_HEADER& s = m_sectionHeaders[i];
        const char* namePtr = reinterpret_cast<const char*>(s.Name);
        size_t nameLen = strnlen(namePtr, 8);

        PESectionInfo si = {};
        si.name = std::string(namePtr, nameLen);
        si.virtualAddress = s.VirtualAddress;
        si.virtualSize = s.Misc.VirtualSize;
        si.rawAddress = s.PointerToRawData;
        si.rawSize = s.SizeOfRawData;
        si.characteristics = s.Characteristics;
        out.push_back(std::move(si));
    }

    return out;
}

DWORD PEParser::RVAToFileOffsetPublic(DWORD rva) const {
    return RVAToFileOffset(rva);
}

bool PEParser::ReadBytes(DWORD offset, void* buffer, size_t size) const {
    if (buffer == nullptr) {
        return false;
    }
    if (static_cast<size_t>(offset) + size > m_fileData.size()) {
        return false;
    }
    memcpy(buffer, m_fileData.data() + offset, size);
    return true;
}

bool PEParser::GetDebugDirectory(DWORD& rva, DWORD& size) const {
    rva = 0;
    size = 0;
    if (!m_isValidPE) {
        return false;
    }

    IMAGE_DATA_DIRECTORY dir = {};
    if (m_isPE32Plus && m_ntHeaders64 != nullptr) {
        dir = m_ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    } else if (!m_isPE32Plus && m_ntHeaders32 != nullptr) {
        dir = m_ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    } else {
        return false;
    }

    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return false;
    }

    rva = dir.VirtualAddress;
    size = dir.Size;
    return true;
}

bool PEParser::GetSecurityDirectory(DWORD& fileOffset, DWORD& size) const {
    fileOffset = 0;
    size = 0;
    if (!m_isValidPE) {
        return false;
    }

    IMAGE_DATA_DIRECTORY dir = {};
    if (m_isPE32Plus && m_ntHeaders64 != nullptr) {
        dir = m_ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else if (!m_isPE32Plus && m_ntHeaders32 != nullptr) {
        dir = m_ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else {
        return false;
    }

    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return false;
    }

    fileOffset = dir.VirtualAddress;
    size = dir.Size;
    return true;
}
