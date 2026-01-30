# 工程设计总结（本地开发与编译）

## 编译环境
- 操作系统：Windows 10/11，DPI=100%
- 编译工具：Visual Studio 2022（MSVC v143，MSBuild≥17.0）
- VS 环境脚本：`C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat`
- Windows SDK：10.x（已在 VS 工作负载中安装）

## 项目结构与目标
- 解决方案：`PEInfo.sln`
- 主程序：`PEInfo.exe`（GUI 工具，Win32 / x64 构建）

## 构建与打包
- 构建脚本：`build.bat`
  - 32位发布版：`./build.bat Win32 Release`
  - 64位发布版：`./build.bat x64 Release`
- 打包产物：`dist\PEInfo_x86_Release.zip`、`dist\PEInfo_x64_Release.zip`

## 运行与验证
- 启动 GUI：运行生成的 `PEInfo.exe`
  - 可通过“打开文件”选择 PE 文件，或把文件拖放到窗口中打开分析

## 当前功能（GUI）
- 概要信息：位数/Machine/Sections/SizeOfImage/EntryPointRVA/ImageBase/Subsystem
- Sections：节表摘要
- Imports / Delay-Imports：按 DLL 汇总并列出 API（支持截断/不截断）
- Exports：导出函数列表
- PDB 信息：解析 Debug Directory（RSDS GUID + Age + PDB Path）
- 数字签名：检测 embedded / catalog 并可验证，展示 signer/thumbprint 等信息
- 文件哈希：MD5/SHA1/SHA256（Windows CryptoAPI）

## 开发注意事项
- 编码：UTF-8；界面文本中文；Win32 原生控件
- 警告：当前可能出现 `C4100` 未使用参数警告（不影响功能）
- 资源：仅保留 `ui_vtabs_*` 设计图，历史图已清理

## 后续扩展建议
- 算法扩展：`CRC32/RIPEMD160` 等
- 64位 PE 解析：引入 `IMAGE_NT_HEADERS64` 与对应字段映射
