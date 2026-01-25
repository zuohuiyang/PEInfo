# 工程设计总结（本地开发与编译）

## 编译环境
- 操作系统：Windows 10/11，DPI=100%
- 编译工具：Visual Studio 2022（MSVC v143，MSBuild≥17.0）
- VS 环境脚本：`C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat`
- Windows SDK：10.x（已在 VS 工作负载中安装）

## 项目结构与目标
- 解决方案：`PEInfo.sln`
- 主程序：`PEInfo.exe`（命令行工具，Win32 / x64 构建）
- 测试工程：`test_build\PEAnalyzerTest.vcxproj`（控制台测试）

## 构建与打包
- 构建脚本：`build.bat`
  - 32位发布版：`./build.bat Win32 Release`
  - 64位发布版：`./build.bat x64 Release`
- 打包产物：`dist\PEInfo_x86_Release.zip`、`dist\PEInfo_x64_Release.zip`

## 运行与验证
- 启动 CLI：`./Release/PEInfo.exe --help`
- 示例：`./Release/PEInfo.exe C:\Windows\System32\notepad.exe --all`
- 测试执行：`./test_build/Release/PEAnalyzerTest.exe`
  - 覆盖：PE 解析基础、文本与文件哈希、导入解析健壮性

## 当前功能（CLI）
- 输出：`--format text|json`，可用 `--out <path>` 写 UTF-8 文件
- 分析项：`--summary/--sections/--imports/--imports-all/--exports/--pdb/--sig/--verify`
- 校验：`--verify` 会用退出码反映签名验证结果（通过/失败/未签名）
- 哈希：`--hash md5|sha1|sha256`

## 开发注意事项
- 编码：UTF-8；界面文本中文；Win32 原生控件
- 警告：当前可能出现 `C4100` 未使用参数警告（不影响功能）
- 资源：仅保留 `ui_vtabs_*` 设计图，历史图已清理

## 后续扩展建议
- 算法扩展：`CRC32/RIPEMD160` 等
- 64位 PE 解析：引入 `IMAGE_NT_HEADERS64` 与对应字段映射
