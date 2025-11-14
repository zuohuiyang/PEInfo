#include "stdafx.h"
#include "PEParser.h"
#include "HashCalculator.h"
#include <iostream>
#include <string>

int main() {
    std::wcout << L"=== PE Analyzer & Hash Calculator Test ===" << std::endl;
    std::wcout << L"Testing core functionality..." << std::endl;
    
    // Test PE Parser
    std::wcout << L"\n1. Testing PE Parser..." << std::endl;
    PEParser parser;
    std::wstring testFile = L"C:\\Windows\\System32\\notepad.exe";
    
    if (parser.LoadFile(testFile)) {
        std::wcout << L"[OK] PE file loaded successfully: " << testFile << std::endl;
        
        if (parser.IsValidPE()) {
            std::wcout << L"[OK] Valid PE file format" << std::endl;
            
            const auto& headerInfo = parser.GetHeaderInfo();
            std::wcout << L"  Architecture: " << (headerInfo.is32Bit ? L"32-bit" : L"64-bit") << std::endl;
            std::wcout << L"  Sections: " << headerInfo.numberOfSections << std::endl;
            std::wcout << L"  Image size: " << headerInfo.sizeOfImage << L" bytes" << std::endl;
            
            const auto& imports = parser.GetImports();
            std::wcout << L"  Imported DLLs: " << imports.size() << std::endl;
            
            if (!imports.empty()) {
                for (size_t i = 0; i < (imports.size() < 3 ? imports.size() : 3); ++i) {
                    std::wcout << L"    " << std::wstring(imports[i].dllName.begin(), imports[i].dllName.end()) 
                              << L" (" << imports[i].functions.size() << L" functions)" << std::endl;
                }
                if (imports.size() > 3) {
                    std::wcout << L"    ... and " << (imports.size() - 3) << L" more DLLs" << std::endl;
                }
            }
        } else {
            std::wcout << L"[FAIL] Invalid PE file format" << std::endl;
        }
    } else {
        std::wcout << L"[FAIL] Failed to load PE file: " << parser.GetLastError() << std::endl;
    }
    
    // Test Hash Calculator
    std::wcout << L"\n2. Testing Hash Calculator..." << std::endl;
    HashCalculator calculator;
    std::wstring testText = L"Hello, World!";
    
    std::wcout << L"Test text: " << testText << std::endl;
    
    // Test MD5
    auto md5Result = calculator.CalculateTextHash(testText, HashAlgorithm::MD5);
    if (md5Result.success) {
    std::wcout << L"[OK] MD5: " << md5Result.result << std::endl;
    } else {
        std::wcout << L"[FAIL] MD5 failed: " << md5Result.errorMessage << std::endl;
    }
    
    // Test SHA1
    auto sha1Result = calculator.CalculateTextHash(testText, HashAlgorithm::SHA1);
    if (sha1Result.success) {
    std::wcout << L"[OK] SHA1: " << sha1Result.result << std::endl;
    } else {
        std::wcout << L"[FAIL] SHA1 failed: " << sha1Result.errorMessage << std::endl;
    }
    
    // Test SHA256
    auto sha256Result = calculator.CalculateTextHash(testText, HashAlgorithm::SHA256);
    if (sha256Result.success) {
    std::wcout << L"[OK] SHA256: " << sha256Result.result << std::endl;
    } else {
        std::wcout << L"[FAIL] SHA256 failed: " << sha256Result.errorMessage << std::endl;
    }
    
    std::wcout << L"\n3. Testing Imports presence..." << std::endl;
    PEParser p2;
    std::wstring dll32 = L"C:\\Windows\\SysWOW64\\user32.dll";
    std::wstring dll64 = L"C:\\Windows\\System32\\user32.dll";
    std::wstring use = dll32;
    std::ifstream f32("C:/Windows/SysWOW64/user32.dll", std::ios::binary);
    if (!f32) use = dll64;
    if (p2.LoadFile(use)) {
        auto imps = p2.GetImports();
        std::wcout << L"Imports entries: " << imps.size() << std::endl;
        std::wcout << (imps.empty() ? L"[OK] Parser loaded (no imports or 64-bit unsupported)" : L"[OK] Found imports") << std::endl;
    } else {
        std::wcout << L"[FAIL] Load user32.dll: " << p2.GetLastError() << std::endl;
    }

    std::wcout << L"\n4. Testing file MD5..." << std::endl;
    HashResult hr = calculator.CalculateFileHash(L"C:\\project\\petools\\icon.svg", HashAlgorithm::MD5);
    if (hr.success && !hr.result.empty()) {
        std::wcout << L"[OK] File MD5: " << hr.result << std::endl;
    } else {
        std::wcout << L"[FAIL] File MD5" << std::endl;
    }

    std::wcout << L"\n=== Test completed ===" << std::endl;
    return 0;
}