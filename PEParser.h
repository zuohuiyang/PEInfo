#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <memory>

struct PEImportFunction {
    std::string name;
    DWORD ordinal;
    DWORD rva;
    bool isOrdinal;
};

struct PEImportDLL {
    std::string dllName;
    std::vector<PEImportFunction> functions;
};

struct PEHeaderInfo {
    bool is32Bit;
    bool is64Bit;
    WORD machine;
    DWORD numberOfSections;
    DWORD timeDateStamp;
    DWORD sizeOfImage;
    DWORD entryPoint;
    DWORD imageBase;
    std::string subsystem;
};

class PEParser {
public:
    PEParser();
    ~PEParser();

    bool LoadFile(const std::wstring& filePath);
    void UnloadFile();
    
    bool IsValidPE() const { return m_isValidPE; }
    const PEHeaderInfo& GetHeaderInfo() const { return m_headerInfo; }
    const std::vector<PEImportDLL>& GetImports() const { return m_imports; }
    std::wstring GetLastError() const { return m_lastError; }

private:
    bool ParsePE();
    bool ParseImports();
    bool ParseImportTable(DWORD importTableRVA, DWORD importTableSize);
    std::string GetDLLName(DWORD nameRVA);
    bool ParseImportDescriptor(DWORD descriptorRVA, std::string& dllName, std::vector<PEImportFunction>& functions);
    DWORD RVAToFileOffset(DWORD rva);
    bool ReadMemory(DWORD offset, void* buffer, size_t size);
    std::string ReadString(DWORD offset);

private:
    std::vector<BYTE> m_fileData;
    PIMAGE_DOS_HEADER m_dosHeader;
    PIMAGE_NT_HEADERS m_ntHeaders;
    PIMAGE_SECTION_HEADER m_sectionHeaders;
    bool m_isValidPE;
    PEHeaderInfo m_headerInfo;
    std::vector<PEImportDLL> m_imports;
    std::wstring m_lastError;
};