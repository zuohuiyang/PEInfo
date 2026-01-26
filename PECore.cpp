#include "stdafx.h"
#include "PECore.h"

#include <wintrust.h>

static int ComputeVerifyExitCode(SignatureSource source,
                                 bool presenceReady,
                                 const PESignaturePresence& presence,
                                 const std::optional<PESignatureVerifyResult>& embeddedVerify,
                                 const std::optional<PESignatureVerifyResult>& catalogVerify) {
    if (!presenceReady) {
        return 4;
    }

    bool anyPresent = false;
    bool anyValid = false;
    bool anyInvalid = false;

    auto consider = [&](const std::optional<PESignatureVerifyResult>& vr) {
        if (!vr.has_value()) {
            return;
        }
        if (vr->status == PESignatureVerifyStatus::NotSigned) {
            anyPresent = anyPresent || false;
            return;
        }
        anyPresent = true;
        if (vr->status == PESignatureVerifyStatus::Valid) {
            anyValid = true;
        } else {
            anyInvalid = true;
        }
    };

    if (source == SignatureSource::Embedded) {
        consider(embeddedVerify);
    } else if (source == SignatureSource::Catalog) {
        consider(catalogVerify);
    } else if (source == SignatureSource::Both) {
        consider(embeddedVerify);
        consider(catalogVerify);
    } else {
        if (embeddedVerify.has_value()) {
            consider(embeddedVerify);
        } else {
            consider(catalogVerify);
        }
    }

    if (!presence.hasEmbedded && !presence.hasCatalog) {
        return 4;
    }
    if (anyValid) {
        return 0;
    }
    if (!anyPresent) {
        return 4;
    }
    if (anyInvalid) {
        return 3;
    }
    return 3;
}

static SignatureSource MapAutoSource(const PESignaturePresence& presence) {
    if (!presence.hasEmbedded && presence.hasCatalog) {
        return SignatureSource::Catalog;
    }
    return SignatureSource::Embedded;
}

bool AnalyzePeFile(const std::wstring& filePath, const PEAnalysisOptions& opt, PEAnalysisResult& out, std::wstring& error) {
    out = {};
    out.filePath = filePath;

    if (!out.parser.LoadFile(filePath)) {
        error = out.parser.GetLastError();
        return false;
    }

    if (opt.computePdb) {
        out.pdb = ExtractPdbInfo(out.parser);
    }

    if (opt.computeSignaturePresence || opt.verifySignature) {
        out.signaturePresence = DetectSignaturePresence(filePath, out.parser);
        out.signaturePresenceReady = true;
    }

    if (opt.verifySignature) {
        SignatureSource effectiveSource = opt.sigSource;
        bool doEmbedded = (effectiveSource == SignatureSource::Embedded || effectiveSource == SignatureSource::Both || effectiveSource == SignatureSource::Auto);
        bool doCatalog = (effectiveSource == SignatureSource::Catalog || effectiveSource == SignatureSource::Both);
        if (effectiveSource == SignatureSource::Auto) {
            doCatalog = false;
        }

        if (doEmbedded && out.signaturePresence.hasEmbedded) {
            out.embeddedVerify = VerifyEmbeddedSignature(filePath);
        } else if (doEmbedded) {
            out.embeddedVerify = PESignatureVerifyResult{PESignatureVerifyStatus::NotSigned, TRUST_E_NOSIGNATURE, {}, {}};
        }

        if (doCatalog && out.signaturePresence.hasCatalog) {
            out.catalogVerify = VerifyCatalogSignature(filePath);
        } else if (doCatalog) {
            out.catalogVerify = PESignatureVerifyResult{PESignatureVerifyStatus::NotSigned, TRUST_E_NOSIGNATURE, {}, {}};
        }

        if (effectiveSource == SignatureSource::Auto) {
            SignatureSource mapped = MapAutoSource(out.signaturePresence);
            if (mapped == SignatureSource::Catalog && out.signaturePresence.hasCatalog) {
                out.catalogVerify = VerifyCatalogSignature(filePath);
            }
        }

        out.verifyExitCode = ComputeVerifyExitCode(effectiveSource, out.signaturePresenceReady, out.signaturePresence, out.embeddedVerify, out.catalogVerify);
    }

    if (opt.computeHashes) {
        HashCalculator calc;
        calc.SetChunkSize(4u << 20);
        if (opt.hashCancel) {
            calc.SetCancelFlag(opt.hashCancel);
        }
        if (opt.hashProgress) {
            calc.SetProgressCallback(opt.hashProgress);
        }
        std::vector<HashAlgorithm> algs = opt.hashAlgorithms;
        if (algs.empty()) {
            algs = {HashAlgorithm::SHA256};
        }
        out.hashes = calc.CalculateFileHashes(filePath, algs);
        for (const auto& r : out.hashes) {
            if (r.success && r.algorithm == L"SHA256") {
                out.reportHash = r;
                break;
            }
        }
        if (!out.reportHash.has_value()) {
            for (const auto& r : out.hashes) {
                if (r.success) {
                    out.reportHash = r;
                    break;
                }
            }
        }
        for (const auto& r : out.hashes) {
            if (!r.success) {
                error = r.errorMessage.empty() ? L"Hash calculation failed" : r.errorMessage;
                return false;
            }
        }
    }

    return true;
}

