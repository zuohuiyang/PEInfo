#include "stdafx.h"
#include "CliOptions.h"
#include "PECore.h"
#include "ReportJsonWriter.h"
#include "ReportTextWriter.h"
#include "ReportUtil.h"

#include <iostream>
#include <string>
#include <vector>

namespace {

static ReportTimeFormat MapTimeFormat(CliTimeFormat t) {
    switch (t) {
        case CliTimeFormat::Local: return ReportTimeFormat::Local;
        case CliTimeFormat::Utc: return ReportTimeFormat::Utc;
        case CliTimeFormat::Raw: return ReportTimeFormat::Raw;
    }
    return ReportTimeFormat::Local;
}

static SignatureSource MapSigSource(CliSigSource s) {
    switch (s) {
        case CliSigSource::Auto: return SignatureSource::Auto;
        case CliSigSource::Embedded: return SignatureSource::Embedded;
        case CliSigSource::Catalog: return SignatureSource::Catalog;
        case CliSigSource::Both: return SignatureSource::Both;
    }
    return SignatureSource::Auto;
}

static ReportOptions MakeReportOptions(const CliOptions& opt) {
    ReportOptions ro;
    ro.showSummary = opt.showSummary;
    ro.showSections = opt.showSections;
    ro.showImports = opt.showImports;
    ro.showExports = opt.showExports;
    ro.showResources = opt.showResources;
    ro.resourcesAll = opt.resourcesAll;
    ro.showPdb = opt.showPdb;
    ro.showSignature = opt.showSignature;
    ro.importsAll = opt.importsAll;
    ro.quiet = opt.quiet;
    ro.timeFormat = MapTimeFormat(opt.timeFormat);
    return ro;
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    CliParseResult parsed = ParseCliArgs(argc, argv);
    if (!parsed.ok) {
        if (!parsed.error.empty()) {
            std::wcerr << parsed.error << L"\n\n";
        }
        std::wcout << BuildUsageText();
        return parsed.exitCode;
    }
    if (parsed.showHelp) {
        std::wcout << BuildUsageText();
        return parsed.exitCode;
    }

    const CliOptions& opt = parsed.options;
    size_t importMaxPerDll = opt.importsAll ? 0 : 50;

    PEAnalysisOptions aopt;
    aopt.computePdb = opt.showPdb;
    aopt.computeSignaturePresence = (opt.showSignature || opt.verifySignature);
    aopt.verifySignature = opt.verifySignature;
    aopt.sigSource = MapSigSource(opt.sigSource);
    aopt.computeHashes = opt.hashAlg.has_value();
    if (opt.hashAlg.has_value()) {
        aopt.hashAlgorithms = {*opt.hashAlg};
    }
    aopt.timeFormat = MapTimeFormat(opt.timeFormat);

    PEAnalysisResult ar;
    std::wstring analysisError;
    if (!AnalyzePeFile(opt.filePath, aopt, ar, analysisError)) {
        std::wcerr << analysisError << L"\n";
        return 1;
    }

    int exitCode = opt.verifySignature ? ar.verifyExitCode : 0;

    if (opt.outputFormat == CliOutputFormat::Json) {
        ReportOptions ropt = MakeReportOptions(opt);
        std::string json = BuildJsonReport(ropt,
                                           ar.filePath,
                                           ar.parser,
                                           ar.pdb,
                                           ar.signaturePresenceReady ? &ar.signaturePresence : nullptr,
                                           &ar.embeddedVerify,
                                           &ar.catalogVerify,
                                           opt.hashAlg.has_value() ? &ar.reportHash : nullptr);
        json.push_back('\n');
        if (opt.outPath.has_value()) {
            if (!WriteAllBytes(*opt.outPath, json)) {
                std::wcerr << L"Failed to write output file: " << *opt.outPath << L"\n";
                return 1;
            }
        } else {
            std::cout.write(json.data(), static_cast<std::streamsize>(json.size()));
        }
        return exitCode;
    }

    if (opt.quiet) {
        std::wostringstream out;
        out << opt.filePath;
        if (opt.showSignature && ar.signaturePresenceReady) {
            std::wstring presence;
            if (ar.signaturePresence.hasEmbedded && ar.signaturePresence.hasCatalog) presence = L"both";
            else if (ar.signaturePresence.hasEmbedded) presence = L"embedded";
            else if (ar.signaturePresence.hasCatalog) presence = L"catalog";
            else presence = L"none";
            out << L"  sig=" << presence;
        }
        if (opt.verifySignature) {
            out << L"  verify_exit=" << exitCode;
        }
        if (ar.reportHash.has_value()) {
            out << L"  " << ar.reportHash->algorithm << L"=" << ar.reportHash->result;
        }
        out << L"\n";

        std::string utf8 = WStringToUtf8(out.str());
        if (opt.outPath.has_value()) {
            if (!WriteAllBytes(*opt.outPath, utf8)) {
                std::wcerr << L"Failed to write output file: " << *opt.outPath << L"\n";
                return 1;
            }
        } else {
            std::wcout << out.str();
        }
        return exitCode;
    }

    ReportOptions ropt = MakeReportOptions(opt);
    ropt.quiet = false;
    std::wstring report = BuildTextReport(ropt,
                                          ar.filePath,
                                          ar.parser,
                                          ar.pdb,
                                          ar.signaturePresenceReady ? &ar.signaturePresence : nullptr,
                                          ar.embeddedVerify,
                                          ar.catalogVerify,
                                          ar.reportHash,
                                          importMaxPerDll,
                                          500);

    if (opt.outPath.has_value()) {
        std::string utf8 = WStringToUtf8(report);
        if (!WriteAllBytes(*opt.outPath, utf8)) {
            std::wcerr << L"Failed to write output file: " << *opt.outPath << L"\n";
            return 1;
        }
    } else {
        std::wcout << report;
    }

    return exitCode;
}
