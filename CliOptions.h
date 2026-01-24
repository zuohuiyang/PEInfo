#pragma once

#include "HashCalculator.h"

#include <optional>
#include <string>

enum class CliOutputFormat {
    Text,
    Json
};

enum class CliTimeFormat {
    Local,
    Utc,
    Raw
};

enum class CliSigSource {
    Auto,
    Embedded,
    Catalog,
    Both
};

struct CliOptions {
    std::wstring filePath;
    bool showSummary;
    bool showSections;
    bool showImports;
    bool showExports;
    bool showPdb;
    bool showSignature;
    bool verifySignature;
    bool importsAll;
    bool quiet;
    CliSigSource sigSource;
    CliTimeFormat timeFormat;
    CliOutputFormat outputFormat;
    std::optional<HashAlgorithm> hashAlg;
    std::optional<std::wstring> outPath;
};

struct CliParseResult {
    bool ok;
    bool showHelp;
    int exitCode;
    std::wstring error;
    CliOptions options;
};

std::wstring BuildUsageText();
CliParseResult ParseCliArgs(int argc, wchar_t* argv[]);

