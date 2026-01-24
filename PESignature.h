#pragma once

#include "PEParser.h"

#include <string>

enum class PESignatureVerifyStatus {
    Valid,
    NotSigned,
    Invalid,
    Error
};

struct PESignaturePresence {
    bool hasEmbedded;
    bool hasCatalog;
};

struct PESignerInfo {
    std::wstring subject;
    std::wstring issuer;
    std::wstring sha1Thumbprint;
    std::wstring notBefore;
    std::wstring notAfter;
    std::wstring timestamp;
};

struct PESignatureVerifyResult {
    PESignatureVerifyStatus status;
    LONG winVerifyTrustStatus;
    PESignerInfo signer;
    std::wstring catalogPath;
};

PESignaturePresence DetectSignaturePresence(const std::wstring& filePath, const PEParser& parser);
PESignatureVerifyResult VerifyEmbeddedSignature(const std::wstring& filePath);
PESignatureVerifyResult VerifyCatalogSignature(const std::wstring& filePath);

