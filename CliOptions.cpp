#include "stdafx.h"
#include "CliOptions.h"

#include <algorithm>
#include <cwctype>
#include <sstream>

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return s;
}

static std::optional<HashAlgorithm> ParseHashAlgorithm(const std::wstring& alg) {
    std::wstring a = ToLower(alg);
    if (a == L"md5") {
        return HashAlgorithm::MD5;
    }
    if (a == L"sha1") {
        return HashAlgorithm::SHA1;
    }
    if (a == L"sha256") {
        return HashAlgorithm::SHA256;
    }
    return std::nullopt;
}

static std::optional<CliOutputFormat> ParseOutputFormat(const std::wstring& s) {
    std::wstring v = ToLower(s);
    if (v == L"text") {
        return CliOutputFormat::Text;
    }
    if (v == L"json") {
        return CliOutputFormat::Json;
    }
    return std::nullopt;
}

static std::optional<CliTimeFormat> ParseTimeFormat(const std::wstring& s) {
    std::wstring v = ToLower(s);
    if (v == L"local") {
        return CliTimeFormat::Local;
    }
    if (v == L"utc") {
        return CliTimeFormat::Utc;
    }
    if (v == L"raw") {
        return CliTimeFormat::Raw;
    }
    return std::nullopt;
}

static std::optional<CliSigSource> ParseSigSource(const std::wstring& s) {
    std::wstring v = ToLower(s);
    if (v == L"auto") {
        return CliSigSource::Auto;
    }
    if (v == L"embedded") {
        return CliSigSource::Embedded;
    }
    if (v == L"catalog") {
        return CliSigSource::Catalog;
    }
    if (v == L"both") {
        return CliSigSource::Both;
    }
    return std::nullopt;
}

std::wstring BuildUsageText() {
    std::wostringstream oss;
    oss << L"Usage:\n";
    oss << L"  PEInfo.exe <file> [options]\n\n";
    oss << L"Options:\n";
    oss << L"  --help, -h, /?            Show help\n";
    oss << L"  --summary                 Print PE summary (default)\n";
    oss << L"  --no-summary              Disable PE summary\n";
    oss << L"  --sections                Print section table summary\n";
    oss << L"  --imports                 Print import DLL/function summary (includes delay-load)\n";
    oss << L"  --imports-all             Print all import functions (no truncation)\n";
    oss << L"  --exports                 Print export summary\n";
    oss << L"  --pdb                     Print PDB (CodeView RSDS) info if present\n";
    oss << L"  --sig                     Print signature presence and signer info\n";
    oss << L"  --verify                  Verify signature (use exit code)\n";
    oss << L"  --sig-source <src>        auto|embedded|catalog|both (default: auto)\n";
    oss << L"  --hash <alg>              Calculate file hash: md5|sha1|sha256\n";
    oss << L"  --time <mode>             local|utc|raw (default: local)\n";
    oss << L"  --format <fmt>            text|json (default: text)\n";
    oss << L"  --out <path>              Write output to file (UTF-8)\n";
    oss << L"  --quiet                   Minimal output (best with --format json)\n";
    oss << L"  --all                     summary+sections+imports+exports+pdb+sig\n";
    return oss.str();
}

static CliOptions DefaultOptions() {
    CliOptions o = {};
    o.showSummary = true;
    o.showSections = false;
    o.showImports = false;
    o.showExports = false;
    o.showPdb = false;
    o.showSignature = false;
    o.verifySignature = false;
    o.importsAll = false;
    o.quiet = false;
    o.sigSource = CliSigSource::Auto;
    o.timeFormat = CliTimeFormat::Local;
    o.outputFormat = CliOutputFormat::Text;
    return o;
}

CliParseResult ParseCliArgs(int argc, wchar_t* argv[]) {
    CliParseResult r = {};
    r.ok = false;
    r.showHelp = false;
    r.exitCode = 2;
    r.options = DefaultOptions();

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i] ? argv[i] : L"";
        if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            r.ok = true;
            r.showHelp = true;
            r.exitCode = 0;
            return r;
        }

        if (arg == L"--summary") {
            r.options.showSummary = true;
            continue;
        }
        if (arg == L"--no-summary") {
            r.options.showSummary = false;
            continue;
        }
        if (arg == L"--sections") {
            r.options.showSections = true;
            continue;
        }
        if (arg == L"--imports") {
            r.options.showImports = true;
            continue;
        }
        if (arg == L"--imports-all") {
            r.options.showImports = true;
            r.options.importsAll = true;
            continue;
        }
        if (arg == L"--exports") {
            r.options.showExports = true;
            continue;
        }
        if (arg == L"--pdb") {
            r.options.showPdb = true;
            continue;
        }
        if (arg == L"--sig") {
            r.options.showSignature = true;
            continue;
        }
        if (arg == L"--verify") {
            r.options.showSignature = true;
            r.options.verifySignature = true;
            continue;
        }
        if (arg == L"--sig-source") {
            if (i + 1 >= argc) {
                r.error = L"Missing value for --sig-source (auto|embedded|catalog|both)";
                return r;
            }
            std::wstring v = argv[++i] ? argv[i] : L"";
            auto parsed = ParseSigSource(v);
            if (!parsed.has_value()) {
                r.error = L"Unsupported sig source: " + v;
                return r;
            }
            r.options.sigSource = *parsed;
            continue;
        }
        if (arg == L"--hash") {
            if (i + 1 >= argc) {
                r.error = L"Missing value for --hash (md5|sha1|sha256)";
                return r;
            }
            std::wstring alg = argv[++i] ? argv[i] : L"";
            r.options.hashAlg = ParseHashAlgorithm(alg);
            if (!r.options.hashAlg.has_value()) {
                r.error = L"Unsupported hash algorithm: " + alg;
                return r;
            }
            continue;
        }
        if (arg == L"--time") {
            if (i + 1 >= argc) {
                r.error = L"Missing value for --time (local|utc|raw)";
                return r;
            }
            std::wstring v = argv[++i] ? argv[i] : L"";
            auto parsed = ParseTimeFormat(v);
            if (!parsed.has_value()) {
                r.error = L"Unsupported time mode: " + v;
                return r;
            }
            r.options.timeFormat = *parsed;
            continue;
        }
        if (arg == L"--format") {
            if (i + 1 >= argc) {
                r.error = L"Missing value for --format (text|json)";
                return r;
            }
            std::wstring v = argv[++i] ? argv[i] : L"";
            auto parsed = ParseOutputFormat(v);
            if (!parsed.has_value()) {
                r.error = L"Unsupported format: " + v;
                return r;
            }
            r.options.outputFormat = *parsed;
            continue;
        }
        if (arg == L"--out") {
            if (i + 1 >= argc) {
                r.error = L"Missing value for --out";
                return r;
            }
            std::wstring v = argv[++i] ? argv[i] : L"";
            r.options.outPath = v;
            continue;
        }
        if (arg == L"--quiet") {
            r.options.quiet = true;
            continue;
        }
        if (arg == L"--all") {
            r.options.showSummary = true;
            r.options.showSections = true;
            r.options.showImports = true;
            r.options.showExports = true;
            r.options.showPdb = true;
            r.options.showSignature = true;
            continue;
        }

        if (!arg.empty() && arg.size() >= 2 && arg[0] == L'-' && arg[1] == L'-') {
            r.error = L"Unknown option: " + arg;
            return r;
        }

        if (!r.options.filePath.empty()) {
            r.error = L"Only one <file> argument is supported";
            return r;
        }
        r.options.filePath = arg;
    }

    if (r.options.filePath.empty()) {
        r.error = L"Missing <file> argument";
        return r;
    }

    r.ok = true;
    r.exitCode = 0;
    return r;
}

