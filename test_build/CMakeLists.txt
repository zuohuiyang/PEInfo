cmake_minimum_required(VERSION 3.16)
project(PEAnalyzerTest VERSION 1.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置编译选项
if(MSVC)
    add_compile_options(/W3 /EHsc)
    add_compile_options($<$<CONFIG:Release>:/O2>)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# 定义测试源文件
set(TEST_SOURCE_FILES
    ../stdafx.cpp
    ../test_simple.cpp
    ../CliOptions.cpp
    ../PEParser.cpp
    ../PEDebugInfo.cpp
    ../PESignature.cpp
    ../HashCalculator.cpp
)

# 定义头文件
set(HEADER_FILES
    ../stdafx.h
    ../targetver.h
    ../CliOptions.h
    ../PEParser.h
    ../PEDebugInfo.h
    ../PESignature.h
    ../HashCalculator.h
)

# 创建测试可执行文件
add_executable(PEAnalyzerTest ${TEST_SOURCE_FILES} ${HEADER_FILES})

# 链接库
target_link_libraries(PEAnalyzerTest
    PRIVATE
        kernel32
        user32
        gdi32
        comctl32
        shell32
        advapi32
        wintrust
        crypt32
)

# 设置子系统
set_target_properties(PEAnalyzerTest PROPERTIES
    LINK_FLAGS "/SUBSYSTEM:CONSOLE"
)
