#pragma once

#include "ReportTypes.h"

#include "HashCalculator.h"
#include "PEDebugInfo.h"
#include "PEParser.h"
#include "PESignature.h"

#include <optional>
#include <string>

std::wstring BuildTextReport(const ReportOptions& opt,
                             const std::wstring& filePath,
                             const PEParser& parser,
                             const std::optional<PEPdbInfo>& pdbOpt,
                             const PESignaturePresence* sigPresence,
                             const std::optional<PESignatureVerifyResult>& embedded,
                             const std::optional<PESignatureVerifyResult>& catalog,
                             const std::optional<HashResult>& hashResult,
                             size_t importMaxPerDll = 50,
                             size_t maxExports = 500);

