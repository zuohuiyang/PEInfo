#include "stdafx.h"
#include "HashCalculator.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>

HashCalculator::HashCalculator() {
}

HashCalculator::~HashCalculator() {
}

HashResult HashCalculator::CalculateFileHash(const std::wstring& filePath, HashAlgorithm algorithm) {
    std::vector<BYTE> fileData = ReadFileData(filePath);
    if (fileData.empty()) {
        HashResult result;
        result.success = false;
        result.algorithm = GetAlgorithmName(algorithm);
        result.errorMessage = L"Failed to read file";
        return result;
    }

    return PerformHash(fileData, algorithm);
}

std::vector<HashResult> HashCalculator::CalculateFileHashes(const std::wstring& filePath, const std::vector<HashAlgorithm>& algorithms) {
    std::vector<BYTE> fileData = ReadFileData(filePath);
    std::vector<HashResult> results;

    if (fileData.empty()) {
        for (const auto& alg : algorithms) {
            HashResult result;
            result.success = false;
            result.algorithm = GetAlgorithmName(alg);
            result.errorMessage = L"Failed to read file";
            results.push_back(result);
        }
        return results;
    }

    for (const auto& alg : algorithms) {
        results.push_back(PerformHash(fileData, alg));
    }

    return results;
}

HashResult HashCalculator::CalculateTextHash(const std::wstring& text, HashAlgorithm algorithm) {
    std::vector<BYTE> textData = StringToBytes(text);
    return PerformHash(textData, algorithm);
}

std::vector<HashResult> HashCalculator::CalculateTextHashes(const std::wstring& text, const std::vector<HashAlgorithm>& algorithms) {
    std::vector<BYTE> textData = StringToBytes(text);
    std::vector<HashResult> results;

    for (const auto& alg : algorithms) {
        results.push_back(PerformHash(textData, alg));
    }

    return results;
}

bool HashCalculator::IsHashAlgorithmSupported(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::MD5:
        case HashAlgorithm::SHA1:
        case HashAlgorithm::SHA256:
            return true;
        default:
            return false;
    }
}

std::wstring HashCalculator::GetAlgorithmName(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::MD5: return L"MD5";
        case HashAlgorithm::SHA1: return L"SHA1";
        case HashAlgorithm::SHA256: return L"SHA256";
        default: return L"Unknown";
    }
}

void HashCalculator::ClearResults() {
    m_lastResults.clear();
}

HashResult HashCalculator::PerformHash(const std::vector<BYTE>& data, HashAlgorithm algorithm) {
    HashResult result;
    result.algorithm = GetAlgorithmName(algorithm);
    
    auto start = std::chrono::high_resolution_clock::now();

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    // Acquire cryptographic provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        result.success = false;
        result.errorMessage = L"Failed to acquire cryptographic context";
        return result;
    }

    // Create hash object
    ALG_ID algId = GetCryptoAPIAlgId(algorithm);
    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        result.success = false;
        result.errorMessage = L"Failed to create hash object";
        return result;
    }

    // Hash the data
    if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        result.success = false;
        result.errorMessage = L"Failed to hash data";
        return result;
    }

    // Get hash size
    DWORD hashLen = 0;
    DWORD dataLen = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &dataLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        result.success = false;
        result.errorMessage = L"Failed to get hash size";
        return result;
    }

    // Get hash value
    std::vector<BYTE> hashData(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashData.data(), &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        result.success = false;
        result.errorMessage = L"Failed to get hash value";
        return result;
    }

    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;
    result.calculationTime = diff.count();

    result.success = true;
    result.result = BytesToHexString(hashData);

    return result;
}

ALG_ID HashCalculator::GetCryptoAPIAlgId(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::MD5: return CALG_MD5;
        case HashAlgorithm::SHA1: return CALG_SHA1;
        case HashAlgorithm::SHA256: return CALG_SHA_256;
        default: return CALG_MD5;
    }
}

std::wstring HashCalculator::BytesToHexString(const std::vector<BYTE>& bytes) {
    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0');
    
    for (BYTE b : bytes) {
        ss << std::setw(2) << static_cast<unsigned int>(b);
    }
    
    return ss.str();
}

std::vector<BYTE> HashCalculator::StringToBytes(const std::wstring& str) {
    std::vector<BYTE> result;
    
    // Convert wide string to multi-byte string
    int size = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size > 0) {
        std::vector<char> buffer(size);
        WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, buffer.data(), size, nullptr, nullptr);
        result.assign(buffer.begin(), buffer.end() - 1); // Exclude null terminator
    }
    
    return result;
}

std::vector<BYTE> HashCalculator::ReadFileData(const std::wstring& filePath) {
    std::vector<BYTE> data;
    
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return data;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    data.resize(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        data.clear();
    }

    return data;
}

// Test function
void TestHashCalculation() {
    std::wcout << L"=== Hash Calculation Test ===" << std::endl;
    
    HashCalculator calculator;
    std::wstring testText = L"Hello, World!";
    
    std::wcout << L"Test text: " << testText << std::endl;
    
    // Test MD5
    auto md5Result = calculator.CalculateTextHash(testText, HashAlgorithm::MD5);
    if (md5Result.success) {
        std::wcout << L"MD5:    " << md5Result.result << L" (" << md5Result.calculationTime << L" seconds)" << std::endl;
    } else {
        std::wcout << L"MD5 failed: " << md5Result.errorMessage << std::endl;
    }
    
    // Test SHA1
    auto sha1Result = calculator.CalculateTextHash(testText, HashAlgorithm::SHA1);
    if (sha1Result.success) {
        std::wcout << L"SHA1:   " << sha1Result.result << L" (" << sha1Result.calculationTime << L" seconds)" << std::endl;
    } else {
        std::wcout << L"SHA1 failed: " << sha1Result.errorMessage << std::endl;
    }
    
    // Test SHA256
    auto sha256Result = calculator.CalculateTextHash(testText, HashAlgorithm::SHA256);
    if (sha256Result.success) {
        std::wcout << L"SHA256: " << sha256Result.result << L" (" << sha256Result.calculationTime << L" seconds)" << std::endl;
    } else {
        std::wcout << L"SHA256 failed: " << sha256Result.errorMessage << std::endl;
    }
    
    std::wcout << std::endl;
}