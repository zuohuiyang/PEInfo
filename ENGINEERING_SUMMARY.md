# 工程设计总结（本地开发与编译）

## 编译环境
- 操作系统：Windows 10/11，DPI=100%
- 编译工具：Visual Studio 2022（MSVC v143，MSBuild≥17.0）
- VS 环境脚本：`C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat`
- Windows SDK：10.x（已在 VS 工作负载中安装）

## 项目结构与目标
- 解决方案：`PEInfo.sln`
- 主程序：`PEInfo.exe`（Win32/x86，支持 x64 构建）
- 测试工程：`test_build\PEAnalyzerTest.vcxproj`（控制台测试）
- 资源与设计图：`docs/images/`（已保留当前方案图：`ui_vtabs_*`）

## 构建与打包
- 构建脚本：`build.bat`
  - 32位发布版：`./build.bat Win32 Release`
  - 64位发布版：`./build.bat x64 Release`
- 打包产物：`dist\PEInfo_x86_Release.zip`、`dist\PEInfo_x64_Release.zip`

## 运行与验证
- 启动应用：`./Release/PEInfo.exe`
- 测试执行：`./test_build/Release/PEAnalyzerTest.exe`
  - 覆盖：PE 解析基础、文本与文件哈希、导入解析健壮性
- 截图采集（用于界面确认）：
  - 在应用界面按 `F12`，生成 BMP 截图到 `artifacts/`：
    - `ui_main.bmp`、`ui_pe.bmp`、`ui_imports.bmp`、`ui_hash.bmp`

## 当前界面与功能
- 布局：顶部 Path 工具栏；左侧导航（`PE Info/Imports/Hash`）；右侧卡片内容区
- PE Info：`Entry Point(RVA/RAW)`、`EP Section`、`First Bytes`、`Linker Info.`、`SubSystem`、`MD5/Notice`
- Imports：搜索栏 + 双列表框（左：DLLs；右：APIs），支持关键字过滤与联动
- Hash：多算法勾选（`MD5/SHA1/SHA256`），支持文本或文件批量计算，结果逐行输出

## 开发注意事项
- 编码：UTF-8；界面文本中文；Win32 原生控件
- 警告：当前可能出现 `C4100` 未使用参数警告（不影响功能）
- 资源：仅保留 `ui_vtabs_*` 设计图，历史图已清理

## 后续扩展建议
- 算法扩展：`CRC32/RIPEMD160` 等
- 导入表增强：API 搜索高亮、分页加载
- 64位 PE 解析：引入 `IMAGE_NT_HEADERS64` 与对应字段映射
