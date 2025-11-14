#include "stdafx.h"
#include "PEParser.h"
#include <iostream>

int main() {
    std::wstring path = L"C:\\Windows\\System32\\kernel32.dll";
    PEParser p;
    if (!p.LoadFile(path)) {
        std::wcout << L"[FAIL] Load: " << p.GetLastError() << std::endl;
        return 1;
    }
    auto imps = p.GetImports();
    std::wcout << L"DLLs: " << imps.size() << std::endl;
    if (imps.empty()) {
        std::wcout << L"[FAIL] No imports" << std::endl;
        return 1;
    }
    std::wcout << L"[OK] Imports present" << std::endl;
    return 0;
}