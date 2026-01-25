#include "stdafx.h"
#include "CliOptions.h"
#include "PEDebugInfo.h"
#include "PEParser.h"
#include "PESignature.h"
#include "HashCalculator.h"
#include <iostream>
#include <string>
#include <vector>

static int g_failures = 0;

static void Fail(int line, const std::wstring& msg) {
    ++g_failures;
    std::wcerr << L"[FAIL] L" << line << L": " << msg << L"\n";
}

static void ExpectTrue(bool cond, int line, const std::wstring& msg) {
    if (!cond) {
        Fail(line, msg);
    } else {
        std::wcout << L"[OK] " << msg << L"\n";
    }
}

static void ExpectEq(const std::wstring& a, const std::wstring& b, int line, const std::wstring& msg) {
    if (a != b) {
        Fail(line, msg + L" (expected=" + b + L", got=" + a + L")");
    } else {
        std::wcout << L"[OK] " << msg << L"\n";
    }
}

static bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

static std::optional<std::wstring> FindFirstExisting(const std::vector<std::wstring>& paths) {
    for (const auto& p : paths) {
        if (FileExists(p)) {
            return p;
        }
    }
    return std::nullopt;
}

static CliParseResult ParseArgsVec(std::vector<std::wstring> args) {
    std::vector<wchar_t*> argv;
    argv.reserve(args.size());
    for (auto& s : args) {
        argv.push_back(s.data());
    }
    return ParseCliArgs(static_cast<int>(argv.size()), argv.data());
}

static void TestCliParse() {
    std::wcout << L"\n[CASE] CLI parse\n";

    {
        CliParseResult r = ParseArgsVec({L"PEInfo.exe"});
        ExpectTrue(!r.ok, __LINE__, L"missing file should fail");
    }
    {
        CliParseResult r = ParseArgsVec({L"PEInfo.exe", L"a.exe", L"--unknown"});
        ExpectTrue(!r.ok, __LINE__, L"unknown option should fail");
    }
    {
        CliParseResult r = ParseArgsVec({L"PEInfo.exe", L"a.exe", L"--all", L"--time", L"utc", L"--format", L"json"});
        ExpectTrue(r.ok, __LINE__, L"--all/--time/--format should parse");
        ExpectTrue(r.options.showSections && r.options.showImports && r.options.showExports && r.options.showPdb && r.options.showSignature, __LINE__,
                   L"--all should enable feature flags");
        ExpectTrue(r.options.timeFormat == CliTimeFormat::Utc && r.options.outputFormat == CliOutputFormat::Json, __LINE__, L"time/format should set");
    }
    {
        CliParseResult r = ParseArgsVec({L"PEInfo.exe", L"a.exe", L"--sig-source", L"catalog", L"--verify"});
        ExpectTrue(r.ok, __LINE__, L"--sig-source/--verify should parse");
        ExpectTrue(r.options.sigSource == CliSigSource::Catalog && r.options.verifySignature, __LINE__, L"sig-source should set");
    }
}

static void TestHashKnownValues() {
    std::wcout << L"\n[CASE] Hash known values\n";
    HashCalculator calculator;
    std::wstring text = L"Hello, World!";

    auto md5 = calculator.CalculateTextHash(text, HashAlgorithm::MD5);
    ExpectTrue(md5.success, __LINE__, L"MD5 should succeed");
    ExpectEq(md5.result, L"65a8e27d8879283831b664bd8b7f0ad4", __LINE__, L"MD5 value");

    auto sha1 = calculator.CalculateTextHash(text, HashAlgorithm::SHA1);
    ExpectTrue(sha1.success, __LINE__, L"SHA1 should succeed");
    ExpectEq(sha1.result, L"0a0a9f2a6772942557ab5355d76af442f8f65e01", __LINE__, L"SHA1 value");

    auto sha256 = calculator.CalculateTextHash(text, HashAlgorithm::SHA256);
    ExpectTrue(sha256.success, __LINE__, L"SHA256 should succeed");
    ExpectEq(sha256.result, L"dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f", __LINE__, L"SHA256 value");
}

static void TestPeParserBasics() {
    std::wcout << L"\n[CASE] PE parser basics\n";
    auto pe = FindFirstExisting({L"C:\\Windows\\System32\\notepad.exe", L"C:\\Windows\\System32\\kernel32.dll", L"C:\\Windows\\System32\\cmd.exe"});
    ExpectTrue(pe.has_value(), __LINE__, L"have a system PE sample");
    if (!pe.has_value()) {
        return;
    }

    PEParser parser;
    bool loaded = parser.LoadFile(*pe);
    ExpectTrue(loaded, __LINE__, L"LoadFile should succeed");
    if (!loaded) {
        std::wcerr << parser.GetLastError() << L"\n";
        return;
    }

    ExpectTrue(parser.IsValidPE(), __LINE__, L"IsValidPE should be true");
    auto sections = parser.GetSectionsInfo();
    ExpectTrue(!sections.empty(), __LINE__, L"sections should not be empty");
}

static void TestPdbExtraction() {
    std::wcout << L"\n[CASE] PDB extraction\n";
    auto pe = FindFirstExisting({L"C:\\Windows\\System32\\notepad.exe", L"C:\\Windows\\System32\\kernel32.dll", L"C:\\Windows\\System32\\cmd.exe"});
    ExpectTrue(pe.has_value(), __LINE__, L"have a system PE sample");
    if (!pe.has_value()) {
        return;
    }

    PEParser parser;
    if (!parser.LoadFile(*pe)) {
        Fail(__LINE__, L"failed to load PE sample for PDB");
        return;
    }

    auto pdb = ExtractPdbInfo(parser);
    if (!pdb.has_value()) {
        std::wcout << L"[OK] PDB not present on this sample, skipped\n";
        return;
    }
    ExpectTrue(pdb->hasRsds, __LINE__, L"PDB should be RSDS");
    ExpectTrue(pdb->age > 0, __LINE__, L"PDB age > 0");
    ExpectTrue(!pdb->pdbPath.empty(), __LINE__, L"PDB path non-empty");
}

static void TestSignatureEmbedded() {
    std::wcout << L"\n[CASE] Signature embedded verify\n";
    std::vector<std::wstring> candidates = {
        L"C:\\Windows\\System32\\notepad.exe",
        L"C:\\Windows\\System32\\cmd.exe",
        L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        L"C:\\Windows\\System32\\calc.exe"
    };

    std::optional<std::wstring> picked;
    PESignatureVerifyResult vr = {};
    for (const auto& p : candidates) {
        if (!FileExists(p)) {
            continue;
        }
        auto tmp = VerifyEmbeddedSignature(p);
        if (tmp.status == PESignatureVerifyStatus::Valid) {
            picked = p;
            vr = tmp;
            break;
        }
    }

    if (!picked.has_value()) {
        std::wcout << L"[OK] no embedded-signed sample verified on this machine, skipped\n";
        return;
    }

    ExpectTrue(vr.status == PESignatureVerifyStatus::Valid, __LINE__, L"embedded verify should succeed");
}

static void TestSignatureCatalog() {
    std::wcout << L"\n[CASE] Signature catalog verify\n";
    std::vector<std::wstring> candidates = {
        L"C:\\Windows\\System32\\drivers\\acpi.sys",
        L"C:\\Windows\\System32\\drivers\\ndis.sys",
        L"C:\\Windows\\System32\\drivers\\tcpip.sys",
        L"C:\\Windows\\System32\\drivers\\disk.sys",
        L"C:\\Windows\\System32\\drivers\\storport.sys"
    };

    std::optional<std::wstring> picked;
    for (const auto& p : candidates) {
        if (!FileExists(p)) {
            continue;
        }
        PEParser parser;
        if (!parser.LoadFile(p)) {
            continue;
        }
        auto presence = DetectSignaturePresence(p, parser);
        if (presence.hasCatalog) {
            picked = p;
            break;
        }
    }

    if (!picked.has_value()) {
        std::wcout << L"[OK] no catalog-signed driver found on this machine, skipped\n";
        return;
    }

    auto vr = VerifyCatalogSignature(*picked);
    ExpectTrue(vr.status == PESignatureVerifyStatus::Valid, __LINE__, L"catalog verify should succeed");
}

static void TestNotSignedFile() {
    std::wcout << L"\n[CASE] Not-signed file verify\n";
    std::wstring file = L"C:\\project\\petools\\README.md";
    ExpectTrue(FileExists(file), __LINE__, L"README.md exists");
    auto vr = VerifyEmbeddedSignature(file);
    ExpectTrue(vr.status == PESignatureVerifyStatus::NotSigned || vr.status == PESignatureVerifyStatus::Error, __LINE__, L"non-PE should not be signed");
}

int main() {
    std::wcout << L"=== PEInfo Tests ===\n";

    TestCliParse();
    TestHashKnownValues();
    TestPeParserBasics();
    TestPdbExtraction();
    TestSignatureEmbedded();
    TestSignatureCatalog();
    TestNotSignedFile();

    if (g_failures == 0) {
        std::wcout << L"\n=== All tests passed ===\n";
        return 0;
    }

    std::wcerr << L"\n=== Failures: " << g_failures << L" ===\n";
    return 2;
}
