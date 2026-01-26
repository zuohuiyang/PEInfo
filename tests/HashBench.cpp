#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include "../HashCalculator.h"

static std::vector<unsigned char> ReadAll(const std::wstring& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    std::streamsize size = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<unsigned char> data(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(data.data()), size)) return {};
    return data;
}

static ALG_ID AlgOf(HashAlgorithm a) {
    switch (a) {
        case HashAlgorithm::MD5: return CALG_MD5;
        case HashAlgorithm::SHA1: return CALG_SHA1;
        case HashAlgorithm::SHA256: return CALG_SHA_256;
        default: return CALG_MD5;
    }
}

static std::wstring Hex(const std::vector<unsigned char>& bytes) {
    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0');
    for (unsigned char b : bytes) {
        ss << std::setw(2) << static_cast<unsigned int>(b);
    }
    return ss.str();
}

static std::wstring CryptoHashMem(const std::vector<unsigned char>& data, HashAlgorithm a) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return L"";
    if (!CryptCreateHash(hProv, AlgOf(a), 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return L"";
    }
    if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return L"";
    }
    DWORD len = 0, dlen = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&len), &dlen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return L"";
    }
    std::vector<unsigned char> hv(len);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hv.data(), &len, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return L"";
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return Hex(hv);
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::wcout << L"usage: HashBench <file>\\n";
        return 1;
    }
    std::wstring path = argv[1];
    HashCalculator calc;
    calc.SetChunkSize(4u << 20);
    auto r1 = calc.CalculateFileHash(path, HashAlgorithm::SHA256);
    if (!r1.success) {
        std::wcout << L"streaming sha256 failed: " << r1.errorMessage << L"\\n";
        return 2;
    }
    auto mem = ReadAll(path);
    if (mem.empty()) {
        std::wcout << L"read-all failed\\n";
        return 3;
    }
    auto r2 = CryptoHashMem(mem, HashAlgorithm::SHA256);
    if (r1.result != r2) {
        std::wcout << L"mismatch\\n" << r1.result << L"\\n" << r2 << L"\\n";
        return 4;
    }
    std::wcout << L"ok sha256 " << r1.result << L" time=" << r1.calculationTime << L"s\\n";
    return 0;
}
