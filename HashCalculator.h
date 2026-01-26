#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <chrono>
#include <functional>
#include <atomic>

#pragma comment(lib, "advapi32.lib")

enum class HashAlgorithm {
    MD5,
    SHA1,
    SHA256
};

struct HashResult {
    bool success;
    std::wstring result;
    std::wstring algorithm;
    double calculationTime;
    std::wstring errorMessage;
};

class HashCalculator {
public:
    HashCalculator();
    ~HashCalculator();

    void SetChunkSize(size_t bytes);
    void SetProgressCallback(std::function<void(uint64_t, uint64_t)> cb);
    void SetCancelFlag(std::atomic<bool>* flag);

    // File hashing
    HashResult CalculateFileHash(const std::wstring& filePath, HashAlgorithm algorithm);
    std::vector<HashResult> CalculateFileHashes(const std::wstring& filePath, const std::vector<HashAlgorithm>& algorithms);
    
    // Text hashing
    HashResult CalculateTextHash(const std::wstring& text, HashAlgorithm algorithm);
    std::vector<HashResult> CalculateTextHashes(const std::wstring& text, const std::vector<HashAlgorithm>& algorithms);

    // Utility functions
    bool IsHashAlgorithmSupported(HashAlgorithm algorithm);
    std::wstring GetAlgorithmName(HashAlgorithm algorithm);
    void ClearResults();

private:
    // Core hashing function
    HashResult PerformHash(const std::vector<BYTE>& data, HashAlgorithm algorithm);
    ALG_ID GetCryptoAPIAlgId(HashAlgorithm algorithm);
    std::wstring BytesToHexString(const std::vector<BYTE>& bytes);
    std::vector<BYTE> StringToBytes(const std::wstring& str);
    std::vector<BYTE> ReadFileData(const std::wstring& filePath);
    HashResult HashFileStream(const std::wstring& filePath, HashAlgorithm algorithm);

private:
    std::vector<HashResult> m_lastResults;
    size_t m_chunkSize = (1u << 20);
    std::function<void(uint64_t, uint64_t)> m_progress;
    std::atomic<bool>* m_cancel = nullptr;
};
