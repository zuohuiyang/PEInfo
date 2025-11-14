// 简化版本 - 用于验证代码结构和基本功能
// 这个版本不包含GUI，只包含核心功能测试

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

// 简单的哈希计算测试
std::string CalculateMD5(const std::string& input) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return "Error: Cannot acquire context";
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "Error: Cannot create hash";
    }

    std::vector<BYTE> data(input.begin(), input.end());
    if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "Error: Hash failed";
    }

    DWORD hashLen = 0;
    DWORD dataLen = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &dataLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "Error: Cannot get hash size";
    }

    std::vector<BYTE> hashData(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashData.data(), &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "Error: Cannot get hash value";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    // 转换为十六进制字符串
    std::string result;
    for (BYTE byte : hashData) {
        char hex[3];
        sprintf_s(hex, "%02x", byte);
        result += hex;
    }
    
    return result;
}

// 简单的PE文件检测测试
bool IsPEFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // 检查DOS头
    WORD dosSignature;
    file.read(reinterpret_cast<char*>(&dosSignature), sizeof(dosSignature));
    if (dosSignature != 0x5A4D) { // "MZ"
        return false;
    }

    // 检查PE签名位置
    file.seekg(0x3C);
    DWORD peOffset;
    file.read(reinterpret_cast<char*>(&peOffset), sizeof(peOffset));

    // 检查PE签名
    file.seekg(peOffset);
    DWORD peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));
    
    return peSignature == 0x00004550; // "PE\0\0"
}

int main() {
    std::cout << "PE Analyzer & Hash Calculator - 功能测试\n";
    std::cout << "========================================\n\n";

    // 测试哈希计算
    std::cout << "1. 哈希计算测试:\n";
    std::string testText = "Hello, World!";
    std::string md5Result = CalculateMD5(testText);
    std::cout << "   文本: " << testText << "\n";
    std::cout << "   MD5:  " << md5Result << "\n\n";

    // 测试PE文件检测
    std::cout << "2. PE文件检测测试:\n";
    std::string testFiles[] = {
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Windows\\explorer.exe"
    };

    for (const auto& file : testFiles) {
        bool isPE = IsPEFile(file);
        std::cout << "   文件: " << file << "\n";
        std::cout << "   结果: " << (isPE ? "是PE文件" : "不是PE文件") << "\n\n";
    }

    std::cout << "测试完成！\n";
    std::cout << "按回车键退出...";
    std::cin.get();

    return 0;
}