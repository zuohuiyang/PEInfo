# PE Analyzer & Hash Calculator - 编译指南

## 当前状态

项目代码已经完成，但由于当前环境中没有安装Visual Studio或任何C++编译器，无法直接编译测试。

## 系统要求

- Windows 7 或更高版本
- Visual Studio 2019/2022（支持C++17）
- Windows SDK

## 编译方法

### 方法1：使用Visual Studio IDE

1. 打开 `PEAnalyzer.sln` 文件
2. 选择 `Release` 配置和 `x86` 平台
3. 点击 `生成` -> `生成解决方案`

### 方法2：使用Visual Studio开发人员命令提示符

1. 打开 "Visual Studio 开发人员命令提示符"
2. 导航到项目目录
3. 运行以下命令：
   ```
   msbuild PEAnalyzer.sln /p:Configuration=Release /p:Platform=Win32
   ```

### 方法3：使用build.bat脚本

1. 打开 "Visual Studio 开发人员命令提示符"
2. 导航到项目目录
3. 运行：
   ```
   build.bat
   ```

## 项目结构

```
PEAnalyzer/
├── PEAnalyzer.sln          # Visual Studio解决方案文件
├── PEAnalyzer.vcxproj      # 项目文件（配置：C++17, Win32, /MT）
├── stdafx.h/cpp            # 预编译头文件
├── PEParser.h/cpp          # PE文件解析模块
├── HashCalculator.h/cpp    # 哈希计算模块
├── PEAnalyzer.h/cpp        # 主GUI应用程序
├── PEAnalyzer.rc           # 资源文件
├── resource.h               # 资源定义
├── build.bat                # 编译脚本
└── test_core.cpp            # 核心功能测试程序
```

## 核心功能验证

项目包含以下核心功能：

### 1. PE文件分析
- 解析DOS头和PE头
- 读取导入表信息
- 显示DLL名称、函数名、序号、RVA
- 支持拖放和文件选择

### 2. 哈希计算
- 支持MD5、SHA1、SHA256算法
- 支持文件和文本输入
- 显示计算时间和结果
- 支持清除和重新计算

### 3. GUI界面
- 基于Win32 API的图形界面
- 标签页设计（PE分析 + 哈希计算）
- 树形控件显示PE结构
- 支持Unicode文件路径

## 测试建议

编译成功后，建议进行以下测试：

1. **PE分析测试**：
   - 打开 `C:\Windows\System32\notepad.exe`
   - 验证导入表显示正确
   - 检查DLL和函数信息

2. **哈希计算测试**：
   - 测试文本："Hello, World!"
   - 预期MD5: `65a8e27d8879283831b664bd8b7f0ad4`
   - 预期SHA1: `0a0a9f2a6772942557ab5355d76af442f8f65e01`
   - 预期SHA256: `dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f`

3. **文件哈希测试**：
   - 选择任意文本文件
   - 验证计算结果与已知工具一致

## 注意事项

- 确保使用32位编译（x86）
- 静态链接运行时库（/MT）
- 需要管理员权限访问某些系统文件
- 支持Windows 7及以上版本

## 故障排除

如果编译遇到问题：

1. 检查Visual Studio是否正确安装C++工作负载
2. 确认Windows SDK已安装
3. 验证项目属性中的平台工具集设置
4. 检查是否有中文路径或特殊字符问题

## 联系方式

如有编译或功能问题，请提供：
- Visual Studio版本
- 具体的错误信息
- 操作系统版本
- 测试用的PE文件（如需要）