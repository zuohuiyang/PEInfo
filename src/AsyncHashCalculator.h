#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <chrono>

#pragma comment(lib, "advapi32.lib")

enum class HashAlgorithm;
struct HashResult;

class AsyncHashCalculator {
public:
    AsyncHashCalculator();
    ~AsyncHashCalculator();

    void SetChunkSize(size_t bytes);
    void SetProgressCallback(std::function<void(uint64_t, uint64_t)> cb);
    void SetCancelFlag(std::atomic<bool>* flag);
    HashResult CalculateFileHash(const std::wstring& filePath, HashAlgorithm algorithm);

private:
    ALG_ID GetCryptoAPIAlgId(HashAlgorithm algorithm);
    std::wstring BytesToHexString(const std::vector<BYTE>& bytes);

private:
    size_t m_chunkSize = (1u << 20);
    std::function<void(uint64_t, uint64_t)> m_progress;
    std::atomic<bool>* m_cancel = nullptr;
};
