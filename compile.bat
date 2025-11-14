@echo off
cd /d "C:\project\petools"

echo 设置VS2022环境...
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"

echo 编译资源文件...
rc.exe /fo Release\PEAnalyzer.res PEAnalyzer.rc

echo 编译PEAnalyzer.cpp...
cl.exe /c /std:c++17 /MT /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "UNICODE" /D "_UNICODE" /EHsc /nologo /Fo"Release\\" /Fd"Release\\vc143.pdb" /Zi PEAnalyzer.cpp

echo 链接可执行文件...
link.exe /OUT:"Release\PEAnalyzer.exe" /INCREMENTAL:NO /NOLOGO /MANIFEST /MANIFESTUAC:"level='asInvoker' uiAccess='false'" /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /LTCG:incremental /DYNAMICBASE /NXCOMPAT /MACHINE:X86 Release\stdafx.obj Release\PEParser.obj Release\HashCalculator.obj Release\PEAnalyzer.obj Release\PEAnalyzer.res kernel32.lib user32.lib gdi32.lib comctl32.lib shell32.lib advapi32.lib

echo 编译完成！
pause