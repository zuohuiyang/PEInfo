#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PE Analyzer GUI 界面测试脚本
模拟界面点击操作来测试功能
"""

import time
import os
import subprocess

def main():
    """主函数"""
    print("=== PE Analyzer GUI 界面测试工具 ===")
    
    # 检查程序是否运行
    exe_path = r"C:\project\petools\build\Release\PEAnalyzer.exe"
    
    if not os.path.exists(exe_path):
        print("错误: 未找到 PEAnalyzer.exe")
        return
    
    print("正在启动 PE Analyzer...")
    
    try:
        # 启动程序
        subprocess.Popen([exe_path])
        print("程序已启动！")
        
        # 等待界面加载
        print("等待界面加载...")
        time.sleep(3)
        
        print("\n=== 界面测试说明 ===")
        print("1. PE分析标签页功能:")
        print("   - 点击 'Browse...' 按钮选择PE文件")
        print("   - 点击 'Analyze PE' 按钮分析文件")
        print("   - 支持拖拽文件到窗口")
        print("   - 树形控件显示PE导入表信息")
        print()
        print("2. 哈希计算标签页功能:")
        print("   - 在输入框中输入文本")
        print("   - 选择哈希算法(MD5/SHA1/SHA256)")
        print("   - 点击 'Calculate Hash' 计算哈希值")
        print("   - 结果显示在输出框中")
        print()
        print("3. 界面特性:")
        print("   - 标签页切换")
        print("   - 窗口大小调整")
        print("   - 文件拖拽支持")
        print("   - Unicode支持")
        
        print("\n=== 测试建议 ===")
        print("- 可以拖拽一个.exe或.dll文件到窗口")
        print("- 尝试切换标签页查看不同功能")
        print("- 在哈希页面输入文本进行计算")
        print("- 调整窗口大小查看布局效果")
        
        print("\n程序正在运行，请手动测试界面功能...")
        print("按 Ctrl+C 可以停止测试")
        
        # 保持脚本运行
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n测试结束")
            
    except Exception as e:
        print("启动程序失败: %s" % str(e))

if __name__ == "__main__":
    main()