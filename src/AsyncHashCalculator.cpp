#include "stdafx.h"
#include "AsyncHashCalculator.h"
#include "HashCalculator.h"
#include <iomanip>
#include <sstream>

AsyncHashCalculator::AsyncHashCalculator() {
}

AsyncHashCalculator::~AsyncHashCalculator() {
}

void AsyncHashCalculator::SetChunkSize(size_t bytes) {
    m_chunkSize = bytes == 0 ? (1u << 20) : bytes;
}

void AsyncHashCalculator::SetProgressCallback(std::function<void(uint64_t, uint64_t)> cb) {
    m_progress = std::move(cb);
}

void AsyncHashCalculator::SetCancelFlag(std::atomic<bool>* flag) {
    m_cancel = flag;
}

ALG_ID AsyncHashCalculator::GetCryptoAPIAlgId(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::MD5: return CALG_MD5;
        case HashAlgorithm::SHA1: return CALG_SHA1;
        case HashAlgorithm::SHA256: return CALG_SHA_256;
        default: return CALG_MD5;
    }
}

std::wstring AsyncHashCalculator::BytesToHexString(const std::vector<BYTE>& bytes) {
    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0');
    for (BYTE b : bytes) {
        ss << std::setw(2) << static_cast<unsigned int>(b);
    }
    return ss.str();
}

struct ReadCtx {
    OVERLAPPED ov{};
    std::vector<BYTE> buf;
    uint64_t offset = 0;
};

HashResult AsyncHashCalculator::CalculateFileHash(const std::wstring& filePath, HashAlgorithm algorithm) {
    HashResult result;
    result.algorithm = HashCalculator().GetAlgorithmName(algorithm);
    auto start = std::chrono::high_resolution_clock::now();

    HANDLE hFile = CreateFileW(filePath.c_str(),
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_DELETE,
                               nullptr,
                               OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN,
                               nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        result.success = false;
        result.errorMessage = L"Failed to open file";
        return result;
    }

    LARGE_INTEGER li = {};
    uint64_t totalBytes = 0;
    if (GetFileSizeEx(hFile, &li)) {
        totalBytes = static_cast<uint64_t>(li.QuadPart);
    }

    HANDLE hIocp = CreateIoCompletionPort(hFile, NULL, reinterpret_cast<ULONG_PTR>(hFile), 0);
    if (!hIocp) {
        CloseHandle(hFile);
        result.success = false;
        result.errorMessage = L"Failed to create IOCP";
        return result;
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hIocp);
        CloseHandle(hFile);
        result.success = false;
        result.errorMessage = L"Failed to acquire cryptographic context";
        return result;
    }
    ALG_ID algId = GetCryptoAPIAlgId(algorithm);
    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hIocp);
        CloseHandle(hFile);
        result.success = false;
        result.errorMessage = L"Failed to create hash object";
        return result;
    }

    const size_t kChunk = m_chunkSize;
    const int kInFlight = 4;
    uint64_t nextOffset = 0;
    int inflight = 0;
    uint64_t processed = 0;

    std::vector<std::unique_ptr<ReadCtx>> pool;
    pool.reserve(kInFlight);
    for (int i = 0; i < kInFlight && nextOffset < totalBytes; ++i) {
        auto ctx = std::make_unique<ReadCtx>();
        ctx->buf.resize(static_cast<size_t>(kChunk));
        ctx->offset = nextOffset;
        ctx->ov.Offset = static_cast<DWORD>(nextOffset & 0xFFFFFFFF);
        ctx->ov.OffsetHigh = static_cast<DWORD>((nextOffset >> 32) & 0xFFFFFFFF);
        BOOL ok = ReadFile(hFile, ctx->buf.data(), static_cast<DWORD>(kChunk), NULL, &ctx->ov);
        if (!ok && GetLastError() != ERROR_IO_PENDING) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hIocp);
            CloseHandle(hFile);
            result.success = false;
            result.errorMessage = L"Failed to read file";
            return result;
        }
        inflight++;
        pool.push_back(std::move(ctx));
        nextOffset += kChunk;
    }

    while (inflight > 0) {
        if (m_cancel && m_cancel->load()) {
            CancelIoEx(hFile, NULL);
        }
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        LPOVERLAPPED pov = nullptr;
        BOOL ok = GetQueuedCompletionStatus(hIocp, &bytes, &key, &pov, INFINITE);
        if (!ok) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hIocp);
            CloseHandle(hFile);
            result.success = false;
            result.errorMessage = L"IOCP failure";
            return result;
        }
        ReadCtx* ctx = nullptr;
        for (auto& c : pool) {
            if (&c->ov == pov) {
                ctx = c.get();
                break;
            }
        }
        if (!ctx) {
            continue;
        }
        if (bytes > 0) {
            if (!CryptHashData(hHash, ctx->buf.data(), bytes, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                CloseHandle(hIocp);
                CloseHandle(hFile);
                result.success = false;
                result.errorMessage = L"Failed to hash data";
                return result;
            }
            processed += bytes;
            if (m_progress) {
                m_progress(totalBytes, processed);
            }
        }
        inflight--;
        if (nextOffset < totalBytes) {
            ctx->offset = nextOffset;
            ctx->ov.Offset = static_cast<DWORD>(nextOffset & 0xFFFFFFFF);
            ctx->ov.OffsetHigh = static_cast<DWORD>((nextOffset >> 32) & 0xFFFFFFFF);
            BOOL rok = ReadFile(hFile, ctx->buf.data(), static_cast<DWORD>(kChunk), NULL, &ctx->ov);
            if (!rok && GetLastError() != ERROR_IO_PENDING) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                CloseHandle(hIocp);
                CloseHandle(hFile);
                result.success = false;
                result.errorMessage = L"Failed to read file";
                return result;
            }
            inflight++;
            nextOffset += kChunk;
        }
    }

    DWORD hashLen = 0;
    DWORD dataLen = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &dataLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hIocp);
        CloseHandle(hFile);
        result.success = false;
        result.errorMessage = L"Failed to get hash size";
        return result;
    }
    std::vector<BYTE> hashData(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashData.data(), &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hIocp);
        CloseHandle(hFile);
        result.success = false;
        result.errorMessage = L"Failed to get hash value";
        return result;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hIocp);
    CloseHandle(hFile);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end - start;
    result.calculationTime = diff.count();
    result.success = true;
    result.result = BytesToHexString(hashData);
    return result;
}
