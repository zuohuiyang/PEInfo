# PEInfo

## 项目概述

PEInfo 是一个 Windows C++ 工具，提供 PE 文件信息查看（含导入/导出/延迟加载、PDB 信息、时间戳可读化、数字签名检测/验证）与文件哈希计算能力。项目采用模块化架构，核心解析与哈希逻辑可复用，符合 C++17 标准。

## 🎯 核心功能

### 1. PE文件分析器
- ✅ **文件加载**：支持拖放操作和文件选择对话框
- ✅ **PE结构解析**：完整解析DOS头、PE头、导入表
- ✅ **树形显示**：使用树形控件清晰展示PE结构
- ✅ **详细信息**：显示DLL名称、函数名、序号、RVA
- ✅ **PDB 信息**：解析 Debug Directory（RSDS GUID + Age + PDB Path）
- ✅ **时间戳可读化**：TimeDateStamp 支持 raw/utc/local 三种展示
- ✅ **数字签名**：可识别并验证嵌入式签名/编录(Catalog)签名，打印签名者与指纹等信息
- ✅ **Unicode支持**：支持Unicode文件路径

### 2. 哈希计算器  
- ✅ **多种算法**：支持MD5、SHA1、SHA256（使用Windows CryptoAPI）
- ✅ **输入模式**：支持文本输入和文件选择
- ✅ **性能优化**：显示计算时间和性能指标
- ✅ **操作控制**：提供计算和清除按钮
- ✅ **大文件支持**：分块处理大文件

## 🛠 技术规格

### 编译要求
- **编译器**：Visual Studio 2019/2022
- **C++标准**：C++17
- **目标平台**：32位 (x86)
- **运行时链接**：静态链接 (/MT)
- **Windows版本**：Windows 7及以上

### 项目结构
```
petools/
├── PEInfo.sln              # Visual Studio解决方案
├── PEAnalyzer.vcxproj      # 项目文件（已配置C++17, Win32, /MT）
├── CliMain.cpp             # 命令行入口
├── CliOptions.h/cpp        # 命令行参数解析（可测试）
├── PEParser.h/cpp          # PE文件解析模块
├── PEDebugInfo.h/cpp       # Debug Directory / PDB 解析
├── PESignature.h/cpp       # 数字签名检测/验证（embedded/catalog）
├── HashCalculator.h/cpp    # 哈希计算模块  
├── PEAnalyzer.h/cpp        # 主GUI应用程序
├── stdafx.h/cpp            # 预编译头文件
├── PEAnalyzer.rc           # 资源文件
├── build.bat               # 编译脚本
└── test_simple.cpp         # 核心功能测试程序（由 test_build 工程构建运行）
```

## 📦 编译说明

### 方法1：Visual Studio IDE
1. 打开 `PEInfo.sln` 文件
2. 选择 `Release` 配置和 `x86` 平台  
3. 点击 `生成` -> `生成解决方案`

### 方法2：命令行编译
1. 打开 "Visual Studio 开发人员命令提示符"
2. 导航到项目目录
3. 运行：`msbuild PEInfo.sln /p:Configuration=Release /p:Platform=Win32`

### 方法3：使用编译脚本
1. 打开 "Visual Studio 开发人员命令提示符"
2. 运行：`build.bat`

⚠️ **注意**：需要安装 Visual Studio 2022（MSVC v143）与 Windows 10/11 SDK。

## 🧰 命令行用法（CLI）

### 常用示例
- 概要信息（默认含概要）：
  - `PEInfo.exe C:\Windows\System32\notepad.exe`
- 指定时间戳展示：
  - `PEInfo.exe a.exe --summary --time utc`
- 输出 PDB（如存在）：
  - `PEInfo.exe a.exe --pdb`
- 输出并验证签名（自动选择 embedded/cat）：
  - `PEInfo.exe a.sys --sig --verify --sig-source auto`
- 生成 JSON 报告并写文件：
  - `PEInfo.exe a.exe --all --format json --out report.json`

### 退出码（与 --verify 相关）
- `0`：成功（解析成功；若指定 `--verify` 则验证也成功）
- `3`：签名验证失败
- `4`：未签名

## 🧪 测试验证

### PE分析测试
- 测试文件：`C:\Windows\System32\notepad.exe`
- 验证导入表显示正确性
- 检查DLL和函数信息完整性

### 哈希计算测试
测试文本：`Hello, World!`
- **MD5**: `65a8e27d8879283831b664bd8b7f0ad4`
- **SHA1**: `0a0a9f2a6772942557ab5355d76af442f8f65e01`  
- **SHA256**: `dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f`

## 🔧 技术特点

### 架构设计
- **模块化**：PE解析、哈希计算、GUI完全分离
- **异常安全**：完善的错误处理和异常捕获
- **内存管理**：RAII模式和智能指针使用
- **性能优化**：高效的算法和数据结构

### 用户界面
- **Win32 API**：原生Windows应用程序
- **标签页设计**：PE分析和哈希计算分离
- **树形控件**：层次化显示PE结构
- **拖放支持**：文件拖放操作

### 安全特性
- **输入验证**：文件路径和类型验证
- **边界检查**：防止缓冲区溢出
- **异常处理**：优雅处理各种错误情况
- **Unicode支持**：正确处理国际字符

## 📚 相关文档

- [编译指南](COMPILATION_GUIDE.md) - 详细的编译步骤和故障排除
- [功能总结](FEATURES_SUMMARY.md) - 完整的技术规格和实现细节
- [项目文件说明](PROJECT_FILES.md) - 各文件功能说明

## 🎯 开发状态

✅ **已完成**：
- 核心PE解析模块
- 哈希计算模块  
- GUI框架和基本控件
- 项目配置和编译脚本
- 完整的文档和说明

⚠️ **待测试**：
- 完整GUI功能验证
- 实际PE文件测试
- 性能基准测试
- 兼容性验证

## 🔍 故障排除

如果编译遇到问题：
1. 检查Visual Studio是否正确安装C++工作负载
2. 确认Windows SDK已安装
3. 验证项目属性中的平台工具集设置
4. 检查是否有中文路径或特殊字符问题

## 📞 技术支持

如有编译或功能问题，请提供：
- Visual Studio版本
- 具体的错误信息  
- 操作系统版本
- 测试用的PE文件（如需要）

---

**版本**: v1.0.0  
**开发环境**: Visual Studio 2022 + Windows SDK  
**最后更新**: 2024年
