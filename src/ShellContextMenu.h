#pragma once

#include <string>

bool IsPeInfoShellContextMenuInstalled();
bool InstallPeInfoShellContextMenuForCurrentUser(const std::wstring& guiExePath, std::wstring& error);
bool UninstallPeInfoShellContextMenuForCurrentUser(std::wstring& error);

