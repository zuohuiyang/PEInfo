#include "stdafx.h"
#include "HashCalculator.h"
#include <iostream>
#include <fstream>

int main() {
    std::wstring path = L"C:\\project\\petools\\icon.svg";
    std::ifstream f("C:/project/petools/icon.svg", std::ios::binary);
    if (!f) {
        std::cout << "[FAIL] icon.svg missing" << std::endl;
        return 1;
    }
    HashCalculator hc;
    auto r = hc.CalculateFileHash(path, HashAlgorithm::MD5);
    if (!r.success || r.result.empty()) {
        std::cout << "[FAIL] MD5 file hash" << std::endl;
        return 1;
    }
    std::wcout << L"[OK] MD5: " << r.result << std::endl;
    return 0;
}