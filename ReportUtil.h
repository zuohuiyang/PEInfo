#pragma once

#include "ReportTypes.h"

#include <string>

std::wstring ToWStringUtf8BestEffort(const std::string& s);
std::string WStringToUtf8(const std::wstring& w);
std::wstring FormatCoffTime(DWORD timeDateStamp, ReportTimeFormat mode);

std::wstring HexU32(DWORD v, int width);
std::wstring HexU64(ULONGLONG v, int width);

bool WriteAllBytes(const std::wstring& path, const std::string& bytes);

