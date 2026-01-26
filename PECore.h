#pragma once

#include "HashCalculator.h"
#include "PEDebugInfo.h"
#include "PEParser.h"
#include "PESignature.h"
#include "ReportTypes.h"

#include <optional>
#include <string>
#include <vector>
#include <functional>
#include <atomic>

enum class SignatureSource {
    Auto,
    Embedded,
    Catalog,
    Both
};

struct PEAnalysisOptions {
    bool computePdb = true;
    bool computeSignaturePresence = true;
    bool verifySignature = false;
    SignatureSource sigSource = SignatureSource::Auto;
    bool computeHashes = false;
    std::vector<HashAlgorithm> hashAlgorithms;
    ReportTimeFormat timeFormat = ReportTimeFormat::Local;
    std::function<void(uint64_t, uint64_t)> hashProgress;
    std::atomic<bool>* hashCancel = nullptr;
};

struct PEAnalysisResult {
    std::wstring filePath;
    PEParser parser;
    std::optional<PEPdbInfo> pdb;

    PESignaturePresence signaturePresence = {};
    bool signaturePresenceReady = false;

    std::optional<PESignatureVerifyResult> embeddedVerify;
    std::optional<PESignatureVerifyResult> catalogVerify;

    std::vector<HashResult> hashes;
    std::optional<HashResult> reportHash;

    int verifyExitCode = 0;
};

bool AnalyzePeFile(const std::wstring& filePath, const PEAnalysisOptions& opt, PEAnalysisResult& out, std::wstring& error);

