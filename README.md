# PEInfo

## 免责声明（重要）

本项目为纯 vibe coding 产物，生成的代码基本未系统审阅/未逐行检查；不保证正确性、安全性与可维护性。仅供学习与参考使用，使用风险自担。尤其在分析来自不可信来源的 PE 文件时，建议在隔离环境/沙箱中运行。

## 项目概述

PEInfo 是一个 Windows C++ 图形界面（GUI）工具，用于分析单个 PE 文件并展示/导出结构化报告：导入/导出（含 Delay-Import）、PDB（RSDS）、时间戳展示、数字签名检测/验证，以及文件哈希（MD5/SHA1/SHA256）。核心解析与哈希逻辑模块化，可复用，符合 C++17 标准。

## 🎯 核心功能

### 1. PE 文件分析
- ✅ **概要信息**：位数/Machine/Sections/SizeOfImage/EntryPointRVA/ImageBase/Subsystem
- ✅ **Sections**：节表摘要
- ✅ **Imports / Delay-Imports**：按 DLL 汇总并列出 API（支持截断/不截断）
- ✅ **Exports**：导出函数列表
- ✅ **PDB 信息**：解析 Debug Directory（RSDS GUID + Age + PDB Path）
- ✅ **时间戳展示**：TimeDateStamp 支持 raw/utc/local 三种展示
- ✅ **数字签名**：检测 embedded / catalog 签名并可验证（`--verify`），输出 signer/thumbprint 等信息
- ✅ **文件哈希**：MD5/SHA1/SHA256（Windows CryptoAPI），支持显示耗时
- ✅ **输出格式**：text/json，支持导出到文件（UTF-8）

## 🛠 技术规格

### 编译要求
- **编译器**：Visual Studio 2019/2022
- **C++标准**：C++17
- **目标平台**：Win32 / x64
- **运行时链接**：静态链接 (/MT)
- **Windows版本**：Windows 7及以上

### 项目结构
```
petools/
├── PEInfo.sln                  # Visual Studio 解决方案
├── PEInfoGui.vcxproj           # GUI 项目（输出 PEInfo.exe）
├── src/                        # 源码（PE 解析/报告/哈希/签名/GUI）
├── res/                        # 资源文件（manifest 等）
├── scripts/                    # 构建/打包脚本
├── docs/                       # 设计与开发文档
└── README.md
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
1. 直接运行：`scripts\build.bat`
2. 可选参数：`scripts\build.bat x64 Release`

#### 产物路径（固定）
- 可执行文件：`dist\<Platform>\<Configuration>\PEInfo.exe`
- 调试符号（如存在）：`dist\<Platform>\<Configuration>\PEInfo.pdb`
- 压缩包：`dist\PEInfo_<Platform>_<Configuration>.zip`（例如：`dist\PEInfo_x64_Release.zip`、`dist\PEInfo_Win32_Release.zip`）

⚠️ **注意**：需要安装 Visual Studio 2022（MSVC v143）与 Windows 10/11 SDK。

## 🧩 资源管理器右键菜单

PEInfo 支持在程序内一键安装/卸载右键菜单项，便于从资源管理器直接对 PE 文件打开分析界面。

### 安装
1. 运行 `PEInfo.exe`
2. 点击顶部的 **设置**
3. 勾选：`在资源管理器右键菜单中添加“用 PEInfo 打开”`

### 卸载
1. 运行 `PEInfo.exe`
2. 点击顶部的 **设置**
3. 取消勾选同一选项

### 说明
- 默认仅对当前用户生效（写入 HKCU），不需要管理员权限
- 支持的扩展名：`.exe`、`.dll`、`.sys`、`.ocx`、`.node`、`.cpl`、`.scr`、`.efi`
- Windows 11 下自定义项通常出现在“显示更多选项”（经典右键菜单）中
  - 若未立即生效，可重启资源管理器或重新登录

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
- **模块化**：PE解析、哈希计算、签名验证等核心逻辑与GUI分离（可复用）
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

- [工程设计总结](docs/ENGINEERING_SUMMARY.md) - 本地开发与编译/验证要点

## 🎯 开发状态

✅ **已完成**：
- 核心PE解析模块
- 哈希计算模块  
- 项目配置和编译脚本
- 完整的文档和说明

⚠️ **待测试**：
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

## 📄 License

见 LICENSE。
