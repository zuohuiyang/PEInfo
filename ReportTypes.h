#pragma once

#include <string>

enum class ReportTimeFormat {
    Local,
    Utc,
    Raw
};

struct ReportOptions {
    bool showSummary = true;
    bool showSections = true;
    bool showImports = true;
    bool showExports = true;
    bool showPdb = true;
    bool showSignature = true;
    bool importsAll = true;
    bool quiet = false;
    ReportTimeFormat timeFormat = ReportTimeFormat::Local;
};

