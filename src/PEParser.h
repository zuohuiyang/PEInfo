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

struct PEExportFunction {
    std::string name;
    DWORD ordinal;
    DWORD rva;
    bool hasName;
};

struct PEHeaderInfo {
    bool is32Bit;
    bool is64Bit;
    WORD machine;
    DWORD numberOfSections;
    DWORD timeDateStamp;
    DWORD sizeOfImage;
    DWORD entryPoint;
    ULONGLONG imageBase;
    std::string subsystem;
};

struct PESectionInfo {
    std::string name;
    DWORD virtualAddress;
    DWORD virtualSize;
    DWORD rawAddress;
    DWORD rawSize;
    DWORD characteristics;
};

class PEParser {
public:
    PEParser();
    ~PEParser();

    bool LoadFile(const std::wstring& filePath);
    void UnloadFile();
    
    bool IsValidPE() const { return m_isValidPE; }
    bool IsPE32Plus() const { return m_isPE32Plus; }
    const PEHeaderInfo& GetHeaderInfo() const { return m_headerInfo; }
    std::vector<PESectionInfo> GetSectionsInfo() const;
    const std::vector<PEImportDLL>& GetImports() const { return m_imports; }
    const std::vector<PEImportDLL>& GetDelayImports() const { return m_delayImports; }
    const std::vector<PEExportFunction>& GetExports() const { return m_exports; }
    std::wstring GetLastError() const { return m_lastError; }
    DWORD RVAToFileOffsetPublic(DWORD rva) const;
    bool ReadBytes(DWORD offset, void* buffer, size_t size) const;
    bool GetDebugDirectory(DWORD& rva, DWORD& size) const;
    bool GetResourceDirectory(DWORD& rva, DWORD& size) const;
    bool GetSecurityDirectory(DWORD& fileOffset, DWORD& size) const;

private:
    bool ParsePE();
    bool ParseImports();
    bool ParseDelayImports();
    bool ParseExports();
    bool ParseImportTable(DWORD importTableRVA, DWORD importTableSize);
    bool ParseImportDescriptor(DWORD descriptorFileOffset, std::string& dllName, std::vector<PEImportFunction>& functions);
    DWORD RVAToFileOffset(DWORD rva) const;
    DWORD DelayAddrToRva(DWORD delayAddr, DWORD delayAttrs) const;
    bool ReadMemory(DWORD offset, void* buffer, size_t size);
    std::string ReadString(DWORD offset);

private:
    std::vector<BYTE> m_fileData;
    PIMAGE_DOS_HEADER m_dosHeader;
    PIMAGE_NT_HEADERS32 m_ntHeaders32;
    PIMAGE_NT_HEADERS64 m_ntHeaders64;
    bool m_isPE32Plus;
    PIMAGE_SECTION_HEADER m_sectionHeaders;
    bool m_isValidPE;
    PEHeaderInfo m_headerInfo;
    std::vector<PEImportDLL> m_imports;
    std::vector<PEImportDLL> m_delayImports;
    std::vector<PEExportFunction> m_exports;
    std::wstring m_lastError;
};
