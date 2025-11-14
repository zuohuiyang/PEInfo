cmake_minimum_required(VERSION 3.16)
project(PEAnalyzer VERSION 1.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置32位编译
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "64-bit compiler detected, forcing 32-bit compilation")
    set(CMAKE_GENERATOR_PLATFORM Win32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:IA32")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:IA32")
endif()

# 设置编译选项
if(MSVC)
    add_compile_options(/W3 /EHsc)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/MT /O2)
    else()
        add_compile_options(/MTd /Od)
    endif()
endif()

# 定义资源文件 (暂时禁用)
# set(RESOURCE_FILES
#     PEAnalyzer.rc
# )

# 定义源文件
set(SOURCE_FILES
    stdafx.cpp
    PEAnalyzer.cpp
    PEParser.cpp
    HashCalculator.cpp
)

# 定义头文件
set(HEADER_FILES
    stdafx.h
    targetver.h
    resource.h
    PEAnalyzer.h
    PEParser.h
    HashCalculator.h
)

# 创建可执行文件
add_executable(${PROJECT_NAME} WIN32 ${SOURCE_FILES} ${HEADER_FILES})

# 链接库
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        kernel32
        user32
        gdi32
        comctl32
        shell32
        advapi32
)

# 设置子系统
set_target_properties(${PROJECT_NAME} PROPERTIES
    LINK_FLAGS "/SUBSYSTEM:WINDOWS"
)

# 安装规则
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

install(FILES README.md
    DESTINATION doc
)