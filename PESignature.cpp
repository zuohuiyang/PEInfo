#include "stdafx.h"
#include "PESignature.h"

#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

#include <iomanip>
#include <sstream>
#include <vector>

static std::wstring BytesToHexUpper(const BYTE* data, DWORD size) {
    std::wostringstream oss;
    oss << std::hex << std::uppercase << std::setfill(L'0');
    for (DWORD i = 0; i < size; ++i) {
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return oss.str();
}

static std::wstring FileTimeToLocalString(const FILETIME& ft) {
    FILETIME localFt = {};
    if (!FileTimeToLocalFileTime(&ft, &localFt)) {
        return L"";
    }

    SYSTEMTIME st = {};
    if (!FileTimeToSystemTime(&localFt, &st)) {
        return L"";
    }

    wchar_t buf[64] = {};
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::wstring GetCertName(PCCERT_CONTEXT ctx, DWORD flags) {
    if (ctx == nullptr) {
        return L"";
    }

    DWORD len = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, nullptr, 0);
    if (len <= 1) {
        return L"";
    }

    std::wstring out(static_cast<size_t>(len), L'\0');
    CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, out.data(), len);
    if (!out.empty() && out.back() == L'\0') {
        out.pop_back();
    }
    return out;
}

static std::wstring GetThumbprintSha1(PCCERT_CONTEXT ctx) {
    if (ctx == nullptr) {
        return L"";
    }

    DWORD cb = 0;
    if (!CertGetCertificateContextProperty(ctx, CERT_SHA1_HASH_PROP_ID, nullptr, &cb) || cb == 0) {
        return L"";
    }

    std::vector<BYTE> buf(cb);
    if (!CertGetCertificateContextProperty(ctx, CERT_SHA1_HASH_PROP_ID, buf.data(), &cb)) {
        return L"";
    }

    return BytesToHexUpper(buf.data(), cb);
}

static bool FillSignerInfoFromStateData(HANDLE stateData, PESignerInfo& out) {
    if (stateData == nullptr) {
        return false;
    }

    CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(stateData);
    if (provData == nullptr) {
        return false;
    }

    CRYPT_PROVIDER_SGNR* provSigner = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
    if (provSigner == nullptr) {
        return false;
    }

    CRYPT_PROVIDER_CERT* provCert = WTHelperGetProvCertFromChain(provSigner, 0);
    if (provCert == nullptr || provCert->pCert == nullptr) {
        return false;
    }

    PCCERT_CONTEXT ctx = provCert->pCert;
    out.subject = GetCertName(ctx, 0);
    out.issuer = GetCertName(ctx, CERT_NAME_ISSUER_FLAG);
    out.sha1Thumbprint = GetThumbprintSha1(ctx);
    out.notBefore = FileTimeToLocalString(ctx->pCertInfo->NotBefore);
    out.notAfter = FileTimeToLocalString(ctx->pCertInfo->NotAfter);

    CRYPT_PROVIDER_SGNR* counterSigner = WTHelperGetProvSignerFromChain(provData, 0, TRUE, 0);
    if (counterSigner != nullptr) {
        out.timestamp = FileTimeToLocalString(counterSigner->sftVerifyAsOf);
    }

    return true;
}

static PESignatureVerifyStatus MapWinVerifyTrustStatus(LONG status) {
    if (status == ERROR_SUCCESS) {
        return PESignatureVerifyStatus::Valid;
    }
    if (status == TRUST_E_NOSIGNATURE) {
        return PESignatureVerifyStatus::NotSigned;
    }
    if (status == TRUST_E_SUBJECT_NOT_TRUSTED || status == TRUST_E_BAD_DIGEST || status == TRUST_E_EXPLICIT_DISTRUST ||
        status == CERT_E_REVOKED || status == CERT_E_UNTRUSTEDROOT || status == CERT_E_CHAINING) {
        return PESignatureVerifyStatus::Invalid;
    }
    return PESignatureVerifyStatus::Error;
}

static bool FindCatalogForFileShaAlg(const std::wstring& filePath, const wchar_t* hashAlg, std::wstring& catalogPathOut, std::wstring& memberTagOut) {
    catalogPathOut.clear();
    memberTagOut.clear();

    HMODULE hWintrust = GetModuleHandleW(L"wintrust.dll");
    if (hWintrust == nullptr) {
        return false;
    }

    using AcquireContext2Fn = BOOL(WINAPI*)(HCATADMIN*, const GUID*, PCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD);
    using CalcHash2Fn = BOOL(WINAPI*)(HCATADMIN, HANDLE, DWORD, BYTE*, DWORD);

    auto pAcquireContext2 = reinterpret_cast<AcquireContext2Fn>(GetProcAddress(hWintrust, "CryptCATAdminAcquireContext2"));
    auto pCalcHash2 = reinterpret_cast<CalcHash2Fn>(GetProcAddress(hWintrust, "CryptCATAdminCalcHashFromFileHandle2"));

    HCATADMIN hCatAdmin = nullptr;
    static const GUID kDriverActionVerify = {0xF750E6C3u, 0x38EEu, 0x11D1u, {0x85u, 0xE5u, 0x00u, 0xC0u, 0x4Fu, 0xC2u, 0x95u, 0xEEu}};
    const GUID* subsystemGuid = &kDriverActionVerify;
    BOOL acquired = FALSE;
    if (pAcquireContext2 != nullptr && hashAlg != nullptr) {
        acquired = pAcquireContext2(&hCatAdmin, subsystemGuid, hashAlg, nullptr, 0);
    }
    if (!acquired) {
        if (!CryptCATAdminAcquireContext(&hCatAdmin, subsystemGuid, 0)) {
            return false;
        }
    }

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    DWORD hashSize = 0;
    bool hashOk = false;
    if (pCalcHash2 != nullptr && hashAlg != nullptr && acquired) {
        if (!pCalcHash2(hCatAdmin, hFile, hashSize, nullptr, 0) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            hashOk = true;
        }
    } else {
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, nullptr, 0) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            hashOk = true;
        }
    }
    if (!hashOk || hashSize == 0) {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    std::vector<BYTE> hashBuf(hashSize);
    if (pCalcHash2 != nullptr && hashAlg != nullptr && acquired) {
        if (!pCalcHash2(hCatAdmin, hFile, hashSize, hashBuf.data(), 0)) {
            CloseHandle(hFile);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }
    } else {
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hashBuf.data(), 0)) {
            CloseHandle(hFile);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }
    }

    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashBuf.data(), hashSize, 0, nullptr);
    if (hCatInfo == nullptr) {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    CATALOG_INFO ci = {};
    ci.cbStruct = sizeof(ci);
    if (!CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0)) {
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    catalogPathOut = ci.wszCatalogFile;
    memberTagOut = BytesToHexUpper(hashBuf.data(), hashSize);

    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    CloseHandle(hFile);
    CryptCATAdminReleaseContext(hCatAdmin, 0);
    return true;
}

static bool FindCatalogForFile(const std::wstring& filePath, std::wstring& catalogPathOut, std::wstring& memberTagOut) {
    if (FindCatalogForFileShaAlg(filePath, L"SHA256", catalogPathOut, memberTagOut)) {
        return true;
    }
    if (FindCatalogForFileShaAlg(filePath, L"SHA1", catalogPathOut, memberTagOut)) {
        return true;
    }
    return FindCatalogForFileShaAlg(filePath, nullptr, catalogPathOut, memberTagOut);
}

PESignaturePresence DetectSignaturePresence(const std::wstring& filePath, const PEParser& parser) {
    PESignaturePresence p = {};
    DWORD secOff = 0;
    DWORD secSize = 0;
    p.hasEmbedded = parser.GetSecurityDirectory(secOff, secSize);

    std::wstring catPath;
    std::wstring memberTag;
    p.hasCatalog = FindCatalogForFile(filePath, catPath, memberTag);
    return p;
}

PESignatureVerifyResult VerifyEmbeddedSignature(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA wtData = {};
    wtData.cbStruct = sizeof(wtData);
    wtData.dwUIChoice = WTD_UI_NONE;
    wtData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtData.dwUnionChoice = WTD_CHOICE_FILE;
    wtData.pFile = &fileInfo;
    wtData.dwStateAction = WTD_STATEACTION_VERIFY;
    wtData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &action, &wtData);

    PESignatureVerifyResult r = {};
    r.winVerifyTrustStatus = status;
    r.status = MapWinVerifyTrustStatus(status);
    FillSignerInfoFromStateData(wtData.hWVTStateData, r.signer);

    wtData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wtData);
    return r;
}

PESignatureVerifyResult VerifyCatalogSignature(const std::wstring& filePath) {
    PESignatureVerifyResult r = {};
    r.winVerifyTrustStatus = TRUST_E_NOSIGNATURE;
    r.status = PESignatureVerifyStatus::NotSigned;

    std::wstring catalogPath;
    std::wstring memberTag;
    if (!FindCatalogForFile(filePath, catalogPath, memberTag)) {
        return r;
    }
    r.catalogPath = catalogPath;

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        r.status = PESignatureVerifyStatus::Error;
        r.winVerifyTrustStatus = HRESULT_FROM_WIN32(GetLastError());
        return r;
    }

    WINTRUST_CATALOG_INFO catInfo = {};
    catInfo.cbStruct = sizeof(catInfo);
    catInfo.pcwszCatalogFilePath = catalogPath.c_str();
    catInfo.pcwszMemberFilePath = filePath.c_str();
    catInfo.pcwszMemberTag = memberTag.c_str();
    catInfo.hMemberFile = hFile;

    WINTRUST_DATA wtData = {};
    wtData.cbStruct = sizeof(wtData);
    wtData.dwUIChoice = WTD_UI_NONE;
    wtData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtData.dwUnionChoice = WTD_CHOICE_CATALOG;
    wtData.pCatalog = &catInfo;
    wtData.dwStateAction = WTD_STATEACTION_VERIFY;
    wtData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &action, &wtData);
    r.winVerifyTrustStatus = status;
    r.status = MapWinVerifyTrustStatus(status);
    FillSignerInfoFromStateData(wtData.hWVTStateData, r.signer);

    wtData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wtData);
    CloseHandle(hFile);
    return r;
}
