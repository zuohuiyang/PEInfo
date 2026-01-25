#include "stdafx.h"
#include "ReportJsonWriter.h"
#include "ReportUtil.h"

#include <iomanip>
#include <sstream>

namespace {

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char ch : s) {
        switch (ch) {
            case '\"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch < 0x20) {
                    char buf[7] = {};
                    sprintf_s(buf, "\\u%04x", static_cast<unsigned>(ch));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(ch));
                }
        }
    }
    return out;
}

std::string JsonQuoteUtf8(const std::string& s) {
    return std::string("\"") + JsonEscape(s) + "\"";
}

std::string JsonQuoteWide(const std::wstring& w) {
    return JsonQuoteUtf8(WStringToUtf8(w));
}

std::wstring VerifyStatusToStringWide(PESignatureVerifyStatus s) {
    switch (s) {
        case PESignatureVerifyStatus::Valid: return L"Valid";
        case PESignatureVerifyStatus::NotSigned: return L"NotSigned";
        case PESignatureVerifyStatus::Invalid: return L"Invalid";
        case PESignatureVerifyStatus::Error: return L"Error";
    }
    return L"Unknown";
}

} // namespace

std::string BuildJsonReport(const ReportOptions& opt,
                            const std::wstring& filePath,
                            const PEParser& parser,
                            const std::optional<PEPdbInfo>& pdbOpt,
                            const PESignaturePresence* sigPresence,
                            const std::optional<PESignatureVerifyResult>* embedded,
                            const std::optional<PESignatureVerifyResult>* catalog,
                            const std::optional<HashResult>* hashResult) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"file\":" << JsonQuoteWide(filePath);

    if (opt.showSummary) {
        const auto& h = parser.GetHeaderInfo();
        oss << ",\"summary\":{";
        oss << "\"bitness\":" << JsonQuoteUtf8(h.is64Bit ? "x64" : (h.is32Bit ? "x86" : "unknown"));
        {
            std::ostringstream t;
            t << "0x" << std::hex << std::setw(4) << std::setfill('0') << h.machine;
            oss << ",\"machine\":" << JsonQuoteUtf8(t.str());
        }
        oss << ",\"sections\":" << h.numberOfSections;
        {
            std::ostringstream raw;
            raw << "0x" << std::hex << std::setw(8) << std::setfill('0') << h.timeDateStamp;
            oss << ",\"timeDateStamp\":{";
            oss << "\"raw\":" << JsonQuoteUtf8(raw.str());
            if (opt.timeFormat != ReportTimeFormat::Raw) {
                oss << ",\"human\":" << JsonQuoteWide(FormatCoffTime(h.timeDateStamp, opt.timeFormat));
            }
            oss << "}";
        }
        oss << ",\"sizeOfImage\":" << h.sizeOfImage;
        oss << ",\"entryPointRva\":" << h.entryPoint;
        {
            std::ostringstream base;
            base << "0x" << std::hex << std::setw(16) << std::setfill('0') << h.imageBase;
            oss << ",\"imageBase\":" << JsonQuoteUtf8(base.str());
        }
        oss << ",\"subsystem\":" << JsonQuoteUtf8(h.subsystem);
        oss << "}";
    }

    if (opt.showSections) {
        auto sections = parser.GetSectionsInfo();
        oss << ",\"sections\":[";
        for (size_t i = 0; i < sections.size(); ++i) {
            const auto& s = sections[i];
            if (i) oss << ",";
            oss << "{";
            oss << "\"name\":" << JsonQuoteUtf8(s.name);
            oss << ",\"rva\":" << s.virtualAddress;
            oss << ",\"virtualSize\":" << s.virtualSize;
            oss << ",\"rawOffset\":" << s.rawAddress;
            oss << ",\"rawSize\":" << s.rawSize;
            oss << ",\"characteristics\":" << s.characteristics;
            oss << "}";
        }
        oss << "]";
    }

    if (opt.showImports) {
        auto writeDlls = [&](const char* key, const std::vector<PEImportDLL>& dlls) {
            oss << ",\"" << key << "\":[";
            for (size_t i = 0; i < dlls.size(); ++i) {
                const auto& d = dlls[i];
                if (i) oss << ",";
                oss << "{";
                oss << "\"dll\":" << JsonQuoteUtf8(d.dllName);
                oss << ",\"count\":" << d.functions.size();
                if (opt.importsAll) {
                    oss << ",\"functions\":[";
                    for (size_t j = 0; j < d.functions.size(); ++j) {
                        if (j) oss << ",";
                        oss << JsonQuoteUtf8(d.functions[j].name);
                    }
                    oss << "]";
                }
                oss << "}";
            }
            oss << "]";
        };
        writeDlls("imports", parser.GetImports());
        writeDlls("delayImports", parser.GetDelayImports());
    }

    if (opt.showExports) {
        const auto& exports = parser.GetExports();
        oss << ",\"exports\":[";
        for (size_t i = 0; i < exports.size(); ++i) {
            const auto& e = exports[i];
            if (i) oss << ",";
            oss << "{";
            oss << "\"ordinal\":" << e.ordinal;
            oss << ",\"rva\":" << e.rva;
            oss << ",\"name\":" << JsonQuoteUtf8(e.hasName ? e.name : std::string());
            oss << "}";
        }
        oss << "]";
    }

    if (opt.showPdb) {
        if (pdbOpt.has_value() && pdbOpt->hasRsds) {
            oss << ",\"pdb\":{";
            oss << "\"guid\":" << JsonQuoteUtf8(FormatGuidLower(pdbOpt->guid));
            oss << ",\"age\":" << pdbOpt->age;
            oss << ",\"path\":" << JsonQuoteUtf8(pdbOpt->pdbPath);
            oss << "}";
        } else {
            oss << ",\"pdb\":null";
        }
    }

    if (opt.showSignature && sigPresence != nullptr) {
        oss << ",\"signature\":{";
        std::string presence;
        if (sigPresence->hasEmbedded && sigPresence->hasCatalog) {
            presence = "both";
        } else if (sigPresence->hasEmbedded) {
            presence = "embedded";
        } else if (sigPresence->hasCatalog) {
            presence = "catalog";
        } else {
            presence = "none";
        }
        oss << "\"presence\":" << JsonQuoteUtf8(presence);

        auto writeVerify = [&](const char* key, const std::optional<PESignatureVerifyResult>* vr) {
            if (vr == nullptr || !vr->has_value()) {
                return;
            }
            oss << ",\"" << key << "\":{";
            oss << "\"status\":" << JsonQuoteWide(VerifyStatusToStringWide((*vr)->status));
            {
                std::ostringstream hs;
                hs << "0x" << std::hex << (*vr)->winVerifyTrustStatus;
                oss << ",\"statusCode\":" << JsonQuoteUtf8(hs.str());
            }
            if (!(*vr)->catalogPath.empty()) {
                oss << ",\"catalogFile\":" << JsonQuoteWide((*vr)->catalogPath);
            }
            const PESignerInfo& si = (*vr)->signer;
            if (!si.subject.empty()) oss << ",\"subject\":" << JsonQuoteWide(si.subject);
            if (!si.issuer.empty()) oss << ",\"issuer\":" << JsonQuoteWide(si.issuer);
            if (!si.sha1Thumbprint.empty()) oss << ",\"thumbprintSha1\":" << JsonQuoteWide(si.sha1Thumbprint);
            if (!si.notBefore.empty()) oss << ",\"notBefore\":" << JsonQuoteWide(si.notBefore);
            if (!si.notAfter.empty()) oss << ",\"notAfter\":" << JsonQuoteWide(si.notAfter);
            if (!si.timestamp.empty()) oss << ",\"timestamp\":" << JsonQuoteWide(si.timestamp);
            oss << "}";
        };

        writeVerify("embedded", embedded);
        writeVerify("catalog", catalog);
        oss << "}";
    }

    if (hashResult != nullptr && hashResult->has_value()) {
        oss << ",\"hash\":{";
        oss << "\"algorithm\":" << JsonQuoteWide(hashResult->value().algorithm);
        oss << ",\"value\":" << JsonQuoteWide(hashResult->value().result);
        oss << ",\"ms\":" << hashResult->value().calculationTime;
        oss << "}";
    }

    oss << "}";
    return oss.str();
}

