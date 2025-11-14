#include "stdafx.h"
#include "PEParser.h"
#include <sstream>

PEParser::PEParser() : m_dosHeader(nullptr), m_ntHeaders(nullptr), m_sectionHeaders(nullptr), m_isValidPE(false) {
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
    m_ntHeaders = nullptr;
    m_sectionHeaders = nullptr;
    m_isValidPE = false;
    m_imports.clear();
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

    if (m_fileData.size() < m_dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        m_lastError = L"File too small, does not contain complete PE header";
        return false;
    }

    m_ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(m_fileData.data() + m_dosHeader->e_lfanew);
    if (m_ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        m_lastError = L"Invalid PE signature";
        return false;
    }

    m_sectionHeaders = IMAGE_FIRST_SECTION(m_ntHeaders);

    // Fill header information
    m_headerInfo.is32Bit = (m_ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386);
    m_headerInfo.is64Bit = (m_ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    m_headerInfo.machine = m_ntHeaders->FileHeader.Machine;
    m_headerInfo.numberOfSections = m_ntHeaders->FileHeader.NumberOfSections;
    m_headerInfo.timeDateStamp = m_ntHeaders->FileHeader.TimeDateStamp;
    m_headerInfo.sizeOfImage = m_ntHeaders->OptionalHeader.SizeOfImage;
    m_headerInfo.entryPoint = m_ntHeaders->OptionalHeader.AddressOfEntryPoint;
    m_headerInfo.imageBase = static_cast<DWORD>(m_ntHeaders->OptionalHeader.ImageBase);
    
    // Get subsystem string
    switch (m_ntHeaders->OptionalHeader.Subsystem) {
        case IMAGE_SUBSYSTEM_NATIVE: m_headerInfo.subsystem = "Native"; break;
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: m_headerInfo.subsystem = "Windows GUI"; break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: m_headerInfo.subsystem = "Windows Console"; break;
        default: m_headerInfo.subsystem = "Unknown"; break;
    }

    // Parse imports
    ParseImports();

    m_isValidPE = true;
    return true;
}

bool PEParser::ParseImports() {
    m_imports.clear();

    DWORD importTableRVA = 0;
    DWORD importTableSize = 0;

    if (m_headerInfo.is32Bit) {
        importTableRVA = m_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importTableSize = m_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        // For 64-bit PE files, we would need to use IMAGE_NT_HEADERS64
        // For now, we'll handle 32-bit files only
        m_lastError = L"64-bit PE files not yet supported";
        return false;
    }

    if (importTableRVA == 0 || importTableSize == 0) {
        return true; // No import table
    }

    return ParseImportTable(importTableRVA, importTableSize);
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

bool PEParser::ParseImportDescriptor(DWORD descriptorRVA, std::string& dllName, std::vector<PEImportFunction>& functions) {
    functions.clear();

    IMAGE_IMPORT_DESCRIPTOR importDesc;
    if (!ReadMemory(RVAToFileOffset(descriptorRVA), &importDesc, sizeof(importDesc))) {
        m_lastError = L"Failed to read import descriptor";
        return false;
    }

    // Get DLL name
    dllName = ReadString(RVAToFileOffset(importDesc.Name));
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
    
    while (true) {
        DWORD thunkData;
        if (!ReadMemory(currentThunkOffset, &thunkData, sizeof(thunkData))) {
            m_lastError = L"Failed to read thunk data";
            return false;
        }

        if (thunkData == 0) {
            break; // End of thunks
        }

        PEImportFunction func;
        
        if (IMAGE_SNAP_BY_ORDINAL(thunkData)) {
            // Import by ordinal
            func.isOrdinal = true;
            func.ordinal = IMAGE_ORDINAL(thunkData);
            func.name = "Ordinal: " + std::to_string(func.ordinal);
        } else {
            // Import by name
            func.isOrdinal = false;
            func.ordinal = 0;
            
            DWORD nameOffset = RVAToFileOffset(thunkData);
            if (nameOffset == 0) {
                m_lastError = L"Failed to convert name RVA to file offset";
                return false;
            }

            // Skip hint (2 bytes)
            func.name = ReadString(nameOffset + 2);
            if (func.name.empty()) {
                m_lastError = L"Failed to read function name";
                return false;
            }
        }

        func.rva = currentThunkOffset;
        functions.push_back(func);
        currentThunkOffset += sizeof(DWORD);
    }

    return true;
}

DWORD PEParser::RVAToFileOffset(DWORD rva) {
    // Find the section containing this RVA
    for (WORD i = 0; i < m_ntHeaders->FileHeader.NumberOfSections; i++) {
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