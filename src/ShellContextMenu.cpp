#include "stdafx.h"

#include "ShellContextMenu.h"

#include <shlobj.h>

#include <array>

static const wchar_t* kMenuKeyName = L"PEInfoGUI";

static std::wstring BuildBaseKeyPathForExt(const wchar_t* ext) {
    if (wcscmp(ext, L"*") == 0) {
        std::wstring path = L"Software\\Classes\\*\\shell\\";
        path += kMenuKeyName;
        return path;
    }
    std::wstring path = L"Software\\Classes\\SystemFileAssociations\\";
    path += ext;
    path += L"\\shell\\";
    path += kMenuKeyName;
    return path;
}

static bool SetRegSzValue(HKEY key, const wchar_t* valueName, const std::wstring& value, std::wstring& error) {
    const BYTE* data = reinterpret_cast<const BYTE*>(value.c_str());
    DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    LSTATUS st = RegSetValueExW(key, valueName, 0, REG_SZ, data, bytes);
    if (st != ERROR_SUCCESS) {
        error = L"\u5199\u5165\u6ce8\u518c\u8868\u5931\u8d25";
        return false;
    }
    return true;
}

static bool CreateKeyAndSetValues(const std::wstring& keyPath,
                                  const std::wstring& displayName,
                                  const std::wstring& iconPath,
                                  const std::wstring& command,
                                  std::wstring& error) {
    HKEY key = nullptr;
    DWORD disp = 0;
    LSTATUS st = RegCreateKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, &disp);
    if (st != ERROR_SUCCESS) {
        error = L"\u521b\u5efa\u6ce8\u518c\u8868\u9879\u5931\u8d25";
        return false;
    }
    bool ok = SetRegSzValue(key, L"MUIVerb", displayName, error) && SetRegSzValue(key, L"Icon", iconPath, error);
    RegCloseKey(key);
    if (!ok) {
        return false;
    }

    std::wstring cmdKeyPath = keyPath + L"\\command";
    HKEY cmdKey = nullptr;
    st = RegCreateKeyExW(HKEY_CURRENT_USER, cmdKeyPath.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &cmdKey, &disp);
    if (st != ERROR_SUCCESS) {
        error = L"\u521b\u5efa\u6ce8\u518c\u8868\u547d\u4ee4\u9879\u5931\u8d25";
        return false;
    }
    ok = SetRegSzValue(cmdKey, nullptr, command, error);
    RegCloseKey(cmdKey);
    return ok;
}

static bool DeleteTreeIfExists(const std::wstring& keyPath, std::wstring& error) {
    LSTATUS st = RegDeleteTreeW(HKEY_CURRENT_USER, keyPath.c_str());
    if (st == ERROR_FILE_NOT_FOUND) {
        return true;
    }
    if (st != ERROR_SUCCESS) {
        error = L"\u5220\u9664\u6ce8\u518c\u8868\u9879\u5931\u8d25";
        return false;
    }
    return true;
}

static void NotifyAssocChanged() {
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
}

bool IsPeInfoShellContextMenuInstalled() {
    std::wstring keyPath = BuildBaseKeyPathForExt(L"*");
    HKEY key = nullptr;
    LSTATUS st = RegOpenKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0, KEY_READ, &key);
    if (st != ERROR_SUCCESS) {
        return false;
    }
    RegCloseKey(key);
    return true;
}

bool InstallPeInfoShellContextMenuForCurrentUser(const std::wstring& guiExePath, std::wstring& error) {
    const std::array<const wchar_t*, 1> exts = {L"*"};
    std::wstring displayName = L"\u7528 PEInfo \u6253\u5f00";
    std::wstring iconPath = guiExePath;
    std::wstring command = L"\"";
    command += guiExePath;
    command += L"\" \"%1\"";

    for (const wchar_t* ext : exts) {
        std::wstring keyPath = BuildBaseKeyPathForExt(ext);
        if (!CreateKeyAndSetValues(keyPath, displayName, iconPath, command, error)) {
            return false;
        }
    }
    NotifyAssocChanged();
    return true;
}

bool UninstallPeInfoShellContextMenuForCurrentUser(std::wstring& error) {
    const std::array<const wchar_t*, 1> exts = {L"*"};
    for (const wchar_t* ext : exts) {
        std::wstring keyPath = BuildBaseKeyPathForExt(ext);
        if (!DeleteTreeIfExists(keyPath, error)) {
            return false;
        }
    }
    
    // Also try to cleanup old specific extensions if they exist
    const std::array<const wchar_t*, 8> oldExts = {L".exe", L".dll", L".sys", L".ocx", L".node", L".cpl", L".scr", L".efi"};
    for (const wchar_t* ext : oldExts) {
        std::wstring keyPath = L"Software\\Classes\\SystemFileAssociations\\";
        keyPath += ext;
        keyPath += L"\\shell\\";
        keyPath += kMenuKeyName;
        DeleteTreeIfExists(keyPath, error); // Ignore errors for cleanup
    }

    NotifyAssocChanged();
    return true;
}
